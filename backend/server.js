require("dotenv").config();
const express = require("express");
const cors = require("cors");
const axios = require("axios");
const mongoose = require("mongoose");
const Submission = require("./models/Submission");

const app = express();
app.use(cors());
app.use(express.json());

// Connect to MongoDB Atlas
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("Connected to MongoDB Atlas Audit Trail"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Route 1: Scan and Log
app.post("/api/triage", async (req, res) => {
  try {
    const { url } = req.body;

    const pythonRequest = axios.post("http://localhost:5000/analyze", { url });
    const vtUrlId = Buffer.from(url).toString("base64url").replace(/=/g, "");
    const vtRequest = axios
      .get(`https://www.virustotal.com/api/v3/urls/${vtUrlId}`, {
        headers: { "x-apikey": process.env.VIRUSTOTAL_API_KEY },
      })
      .catch((err) => null);

    const [pythonResponse, vtResponse] = await Promise.all([
      pythonRequest,
      vtRequest,
    ]);

    let vtMaliciousCount = 0;
    if (vtResponse && vtResponse.data) {
      vtMaliciousCount =
        vtResponse.data.data.attributes.last_analysis_stats.malicious;
    }

    // --- NEW: Save the Audit Trail to MongoDB ---
    const newScan = new Submission({
      url: url,
      ai_risk_score: pythonResponse.data.risk_score,
      vt_malicious_flags: vtMaliciousCount,
    });
    await newScan.save();

    res.json({
      url: url,
      ai_risk_score: pythonResponse.data.risk_score,
      ai_features: pythonResponse.data.features,
      vt_malicious_flags: vtMaliciousCount,
    });
  } catch (error) {
    console.error("Gateway Error:", error.message);
    res.status(500).json({ error: "Failed to triage URL" });
  }
});

// Route 2: Fetch Scan History for the Dashboard
app.get("/api/history", async (req, res) => {
  try {
    // Fetch the 10 most recent scans
    const history = await Submission.find().sort({ timestamp: -1 }).limit(10);
    res.json(history);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch history" });
  }
});

app.listen(3000, () => console.log("Node Gateway running on port 3000"));
