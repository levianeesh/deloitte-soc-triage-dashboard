const mongoose = require("mongoose");

const submissionSchema = new mongoose.Schema({
  url: { type: String, required: true },
  ai_risk_score: { type: Number, required: true },
  vt_malicious_flags: { type: Number, required: true },
  timestamp: { type: Date, default: Date.now },
});

module.exports = mongoose.model("Submission", submissionSchema);
