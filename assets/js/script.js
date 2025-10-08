// script.js
// Tercera verción para trabajar con la API de VirusTotalv3.
// Manego de errores y uso de buenas practicas basadas en python y js, asi como manejo del DOM
// https://docs.virustotal.com/reference/overview

let apiKey = "";
const inputApi = document.getElementById("apiKey");
const btnGuardar = document.getElementById("guardarApi");
const btnAnalizar = document.getElementById("btnAnalizar");
const divResultados = document.getElementById("resultados");
const txtEntrada = document.getElementById("iocList");
const msgApi = document.getElementById("keyMsg");

// Guardar la API Key en memoria solo esta sesion a tarves de msgApl
btnGuardar.addEventListener("click", () => {
  const key = inputApi.value.trim();
  if (!key) {
    msgApi.textContent = "La clave está vacía. Intenta de nuevo.";
    return;
  }
  apiKey = key;
  msgApi.textContent = "Clave está guardada en memoria. Ahora puedes analizar.";
  inputApi.value = "";
});

// Detectar tipo de indicador con expresiones regulares, dando por hecho que sino es ninguna es dominio
function obtenerTipo(valor) {
  if (/^https?:\/\//i.test(valor)) return "url";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(valor)) return "ip";
  if (/^[0-9a-f]{32,64}$/i.test(valor)) return "file";
  return "domain";
}

// Crear URL para VirusTotal v3
function crearUrl(tipo, valor) {
  switch (tipo) {
    case "url":
      const b64 = btoa(valor).replace(/=+$/, "");
      return `https://www.virustotal.com/api/v3/urls/${b64}`;
    case "file":
      return `https://www.virustotal.com/api/v3/files/${valor}`;
    case "ip":
      return `https://www.virustotal.com/api/v3/ip_addresses/${valor}`;
    default:
      return `https://www.virustotal.com/api/v3/domains/${valor}`;
  }
}


// Extraer categoría principal de amenaza, falata afirnar parte de hashes
function obtenerCategoria(attr) {
  try {
    const pop = attr.popular_threat_classification;
    if (pop?.popular_threat_category?.length > 0)
      return pop.popular_threat_category[0].id;

    const resultados = attr.last_analysis_results || {};
    for (const r of Object.values(resultados)) {
      if (r.category === "malicious" || r.category === "suspicious")
        return r.result || "Sospechosa";
    }
  } catch (err) {
    console.warn("No se pudo extraer la categoría:", err);
  }
  return "Desconocida";
}


// Resumen de los vendors tipo x de x
function resumenReportes(stats) {
  if (!stats) return "Sin reportes";
  const malos = stats.malicious || 0;
  const total = Object.values(stats).reduce((a, b) => a + (b || 0), 0);
  return `${malos} de ${total}`;
}

// Formatear salida según el tipo
function mostrarDatos(tipo, valor, data) {
  const attr = data?.data?.attributes || {};
  const stats = attr.last_analysis_stats || {};
  const cat = obtenerCategoria(attr);
  let salida = "";

  if (tipo === "file") {
    const nombre = attr.names?.[0] || attr.name || "Desconocido";
    const firmado = attr.signer ? "Sí" : "No";
    salida = `Hash: ${valor}\nNombre: ${nombre}\nReportes: ${resumenReportes(stats)}\nCategoría: ${cat}\nFirmado: ${firmado}`;
  } else if (tipo === "ip") {
    salida = `IP: ${valor}\nPaís: ${attr.country || "Desconocido"}\nReportes: ${resumenReportes(stats)}\nAS: ${attr.as_owner || "N/A"}`;
  } else if (tipo === "domain" || tipo === "url") {
    const categorias = attr.categories ? Object.values(attr.categories).join(", ") : "Desconocida";
    salida = `${tipo.toUpperCase()}: ${valor}\nCategorías: ${categorias}\nReportes: ${resumenReportes(stats)}`;
  }
  return salida;
}

// Consultar VirusTotal vía proxy o local
async function consultarVT(url) {
  if (!apiKey) return { error: true, mensaje: "No hay API Key" };

  try {

    //Pruebas para local host
    /*
    const resp = await fetch(url, {
      headers: { "x-apikey": apiKey }
    }); */
    
    // Proxy
    const proxy = `/api/virustotal?url=${encodeURIComponent(url)}&apikey=${apiKey}`;
    const resp = await fetch(proxy);

    if (resp.status === 401 || resp.status === 403)
      return { error: true, mensaje: "API Key inválida o sin permisos" };
    if (resp.status === 429)
      return { error: true, mensaje: "Límite de peticiones alcanzado" };
    if (!resp.ok)
      return { error: true, mensaje: `Error HTTP ${resp.status}` };

    return { error: false, data: await resp.json() };
  } catch (err) {
    return { error: true, mensaje: err.message };
  }
}

// Escape de HTML para mostrar resultados correctamente
function escapeHtml(t) {
  return t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// Mandar los resultados al div mediante la manipulación del DOM REF: https://www.freecodecamp.org/espanol/news/el-dom-de-javascript-un-tutorial-practico/
function mostrarResultados(datos) {
    const contenedor = document.getElementById('resultados');
    contenedor.innerHTML = '';
  
    datos.forEach(item => {
      const div = document.createElement('div');
      div.classList.add('resultado');
  
      div.innerHTML = `
        <h3>${item.hash || 'Sin hash'}</h3>
        <p><strong>Nombre:</strong> ${item.nombre || 'Desconocido'}</p>
        <p><strong>Reportes:</strong> ${item.reportes || 'N/A'}</p>
        <p><strong>Categoría de amenaza:</strong> ${item.categoria || 'No clasificada'}</p>
        <p><strong>Firmado:</strong> ${item.firmado || 'No'}</p>
      `;
  
      contenedor.appendChild(div);
    });
  }


// Botón analizar maneja los posibles errores de usuaria
btnAnalizar.addEventListener("click", async () => {
  divResultados.innerHTML = "";
  const lineas = txtEntrada.value.split("\n").map(l => l.trim()).filter(Boolean);

  if (!apiKey) {
    divResultados.innerHTML = `<div class="error">Primero guarda tu API Key.</div>`;
    return;
  }
  if (lineas.length === 0) {
    divResultados.innerHTML = `<div class="error">Ingresa los indicadores a analizar.</div>`;
    return;
  }

  btnAnalizar.disabled = true;
  btnAnalizar.textContent = "Analizando...";

  for (const linea of lineas) {
    const tipo = obtenerTipo(linea);
    const url = crearUrl(tipo, linea);

    const bloque = document.createElement("div");
    bloque.className = "resultado";
    bloque.textContent = `${linea}\nConsultando...`;
    divResultados.appendChild(bloque);

    const resp = await consultarVT(url);

    if (resp.error) {
      bloque.innerHTML = `<div class="error">X ${resp.mensaje}</div>`;
      if (resp.mensaje.includes("inválida") || resp.mensaje.includes("Límite"))
        break;
      continue;
    }

    const texto = mostrarDatos(tipo, linea, resp.data);
    bloque.innerHTML = `<pre>${escapeHtml(texto)}</pre>`;
  }

  btnAnalizar.disabled = false;
  btnAnalizar.textContent = "Analizar";
});
