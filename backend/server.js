require("dotenv").config();
const express = require("express");
const cors = require("cors");
const axios = require("axios");
const mongoose = require("mongoose");
let Submission;
try {
  Submission = require("./models/Submission");
} catch (e) {
  Submission = null;
}

const app = express();
app.use(cors());
app.use(express.json());

// In-memory fallback store if MongoDB Atlas is offline or not configured
let inMemoryHistory = [];
let isMongoConnected = false;

// Connect to MongoDB Atlas (Graceful Fallback)
if (process.env.MONGO_URI) {
  mongoose
    .connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 3000 })
    .then(() => {
      isMongoConnected = true;
      console.log("Connected to MongoDB Atlas Audit Trail");
    })
    .catch((err) => {
      console.warn("MongoDB connection warning (falling back to memory store):", err.message);
    });
} else {
  console.log("No MONGO_URI provided in .env - utilizing in-memory audit trail fallback.");
}

// Fallback Node.js Feature Extraction (mirrors Python Random Forest heuristic)
function fallbackExtractFeatures(url) {
  const suspicious_words = ['login', 'verify', 'update', 'secure', 'account'];
  const hasAt = url.includes('@') ? 1 : 0;
  const hasIp = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url) ? 1 : 0;
  const dotCount = (url.match(/\./g) || []).length;
  const hasSuspiciousWords = suspicious_words.some(w => url.toLowerCase().includes(w)) ? 1 : 0;
  const isMalicious = (hasAt === 1) || (hasIp === 1 && hasSuspiciousWords === 1) || (dotCount >= 4 && hasSuspiciousWords === 1);

  return {
    risk_score: isMalicious ? 1 : 0,
    features: {
      "Length": url.length,
      "Has '@'": hasAt,
      "Has IP": hasIp,
      "Dot Count": dotCount,
      "Suspicious Words": hasSuspiciousWords
    }
  };
}

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.json({
    status: "online",
    gateway: "Deloitte SOC Triage Gateway v3.2",
    mongo_connected: isMongoConnected,
    timestamp: new Date().toISOString()
  });
});

// Route 1: Scan and Log
app.post("/api/triage", async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) {
      return res.status(400).json({ error: "Missing required 'url' parameter" });
    }

    // 1. Python ML Engine Analysis with fallback
    const pythonRequest = axios
      .post("http://localhost:5000/analyze", { url }, { timeout: 2500 })
      .then(resp => resp.data)
      .catch((err) => {
        console.warn("[Gateway] Python ML engine offline - utilizing Node.js heuristic classifier fallback.");
        return fallbackExtractFeatures(url);
      });

    // 2. VirusTotal Global Intelligence
    let vtRequest = Promise.resolve(null);
    if (process.env.VIRUSTOTAL_API_KEY) {
      const vtUrlId = Buffer.from(url).toString("base64url").replace(/=/g, "");
      vtRequest = axios
        .get(`https://www.virustotal.com/api/v3/urls/${vtUrlId}`, {
          headers: { "x-apikey": process.env.VIRUSTOTAL_API_KEY },
          timeout: 4000
        })
        .catch(() => null);
    }

    const [pythonData, vtResponse] = await Promise.all([
      pythonRequest,
      vtRequest,
    ]);

    let vtMaliciousCount = 0;
    if (vtResponse && vtResponse.data && vtResponse.data.data) {
      vtMaliciousCount =
        vtResponse.data.data.attributes.last_analysis_stats.malicious || 0;
    }

    const scanRecord = {
      _id: `scan-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
      url: url,
      ai_risk_score: pythonData.risk_score,
      vt_malicious_flags: vtMaliciousCount,
      timestamp: new Date()
    };

    // Save to MongoDB if connected, otherwise save to in-memory store
    if (isMongoConnected && Submission) {
      try {
        const newScan = new Submission({
          url: url,
          ai_risk_score: pythonData.risk_score,
          vt_malicious_flags: vtMaliciousCount,
        });
        await newScan.save();
      } catch (dbErr) {
        console.warn("Error saving to MongoDB, using memory store:", dbErr.message);
        inMemoryHistory.unshift(scanRecord);
      }
    } else {
      inMemoryHistory.unshift(scanRecord);
      if (inMemoryHistory.length > 50) inMemoryHistory.pop();
    }

    res.json({
      url: url,
      ai_risk_score: pythonData.risk_score,
      ai_features: pythonData.features,
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
    if (isMongoConnected && Submission) {
      const history = await Submission.find().sort({ timestamp: -1 }).limit(20);
      return res.json(history);
    }
    // Return in-memory history if Mongo isn't connected
    res.json(inMemoryHistory);
  } catch (error) {
    console.error("History fetch error:", error.message);
    res.json(inMemoryHistory);
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Deloitte SOC Node Gateway running on port ${PORT}`));
