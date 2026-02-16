const mongoose = require('mongoose');

const replySchema = new mongoose.Schema({
  name: { type: String, required: true },
  message: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const reportSchema = new mongoose.Schema({
  reporterUsername: { type: String, required: true },
  reporterIp: { type: String, required: true },
  reporterFingerprint: { type: String, required: true },
  reportedAt: { type: Date, default: Date.now }
});

const reviewSchema = new mongoose.Schema({
  name: { type: String, required: true },
  message: { type: String, required: true },
  replies: [replySchema],
  reports: [reportSchema],
  createdAt: { type: Date, default: Date.now }
});

// NO PRE-SAVE HOOK - auto-delete logic moved to server.js

module.exports = mongoose.model('Review', reviewSchema);