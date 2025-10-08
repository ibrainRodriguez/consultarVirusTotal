// /api/virustotal.js
export default async function handler(req, res) {
    const { url, apikey } = req.query;
    
    if (!url || !apikey) {
      return res.status(400).json({ error: "Falta URL o API key" });
    }
  
    try {
      const response = await fetch(url, {
        headers: { "x-apikey": apikey }
      });
  
      const data = await response.json();
      res.status(response.status).json(data);
    } catch (err) {
      res.status(500).json({
        error: "Error al consultar VirusTotal",
        details: err.message
      });
    }
}  