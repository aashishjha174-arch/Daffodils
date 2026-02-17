require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
const https = require('https'); // Added for IPv4 fix

// Brevo API
const SibApiV3Sdk = require('@getbrevo/brevo');

const Review = require('./models/review');
const User = require('./models/user');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected successfully"))
  .catch(err => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  });

// ────────────────────────────────────────────────
// Brevo API Configuration with IPv4 fix
// ────────────────────────────────────────────────
console.log("[DEBUG] Email credentials check:");
console.log("[DEBUG] EMAIL_USER exists:", !!process.env.EMAIL_USER);
console.log("[DEBUG] ADMIN_EMAIL exists:", !!process.env.ADMIN_EMAIL);
console.log("[DEBUG] BREVO_API_KEY exists:", !!process.env.BREVO_API_KEY);

// Initialize Brevo API with IPv4 preference
let apiInstance;
try {
  // Create custom agent to force IPv4
  const httpsAgent = new https.Agent({
    family: 4,  // Force IPv4
    keepAlive: true,
    timeout: 10000
  });

  // Configure Brevo API client
  const defaultClient = SibApiV3Sdk.ApiClient.instance;
  defaultClient.basePath = 'https://api.brevo.com/v3';
  defaultClient.defaultHeaders = { 
    'api-key': process.env.BREVO_API_KEY,
    'Content-Type': 'application/json'
  };

  // Override the request method to use IPv4 agent
  const originalRequest = defaultClient.callApi;
  defaultClient.callApi = function(path, httpMethod, pathParams, queryParams, headerParams, formParams, bodyParam, authNames, contentTypes, accepts, returnType, callback) {
    const options = {
      agent: httpsAgent
    };
    return originalRequest.call(this, path, httpMethod, pathParams, queryParams, headerParams, formParams, bodyParam, authNames, contentTypes, accepts, returnType, callback, options);
  };

  apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();
  console.log("[DEBUG] Brevo API initialized successfully with IPv4 force");
} catch (err) {
  console.error("[DEBUG] Brevo initialization error:", err);
}

// Simple auth middleware
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: "No token provided" });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = JSON.parse(Buffer.from(token, 'base64').toString('utf-8'));
    if (!decoded.username) throw new Error("Invalid token format");

    req.user = { username: decoded.username };
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: "Invalid or expired token" });
  }
};

// ────────────────────────────────────────────────
// Groq Moderation Check
// ────────────────────────────────────────────────
async function checkReviewToxicity(message) {
  const apiKey = process.env.GROQ_API_KEY;

  if (!apiKey) {
    console.warn("[MODERATION] No GROQ_API_KEY – skipping");
    return { isSafe: true, reason: "No key", score: 0 };
  }

  const badWords = [
    'fuck', 'fucking', 'fucked', 'fucker', 'motherfucker',
    'madar', 'madarchod', 'madarchut', 'maachikne',
    'bhen', 'bhenchod', 'behenchod', 'bh****d',
    'randi', 'r@ndi', 'randibaaz',
    'chutiya', 'chut', 'ch***ya',
    'beti', 'betichod', 'b@stard',
    'kill', 'marne', 'marau', 'maar', 'mar',
  ];

  const lowerMessage = message.toLowerCase();
  for (const word of badWords) {
    if (lowerMessage.includes(word)) {
      console.log("[MODERATION] Blocked by keyword:", word);
      return { isSafe: false, reason: "Contains extreme abusive language", score: 9 };
    }
  }

  try {
    const response = await axios.post(
      'https://api.groq.com/openai/v1/chat/completions',
      {
        model: 'llama-3.3-70b-versatile',
        messages: [
          {
            role: 'system',
            content: `You are a chill moderator for a Class 10 farewell memory site (Daffodils Batch 2082).
We want to keep it fun, emotional, and teenage-friendly.

Rules:
- SAFE: happy memories, jokes, light teasing, likes/dislikes, normal banter, mild naughty words (like "stupid", "idiot", "shit", "asshole" in casual/funny way), suggestions, nostalgia, love/hate for teachers/subjects in funny way, mild swearing if not hateful.
- UNSAFE (block): very heavy abuse (fuck, madarchod, betichod, randi, chutiya level), threats to kill/harm, serious bullying, hate speech, anything really mean-spirited or ruins the vibe.

Be lenient — allow most teenage complaints, jokes, and light swearing. Only block if it's clearly aggressive, hateful, or uses extreme swear words.

Respond ONLY with JSON:
{
  "isSafe": true or false,
  "reason": "one short sentence why",
  "toxicityScore": number 0–10 (keep most under 5 unless really bad)
}`
          },
          {
            role: 'user',
            content: `Review: "${message}"`
          }
        ],
        temperature: 0.3,
        max_tokens: 150
      },
      {
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json'
        }
      }
    );

    const content = response.data.choices[0].message.content.trim();
    let result;

    try {
      result = JSON.parse(content);
    } catch (e) {
      console.error("[MODERATION] Groq JSON parse error:", content);
      return { isSafe: true, reason: "Parse error", score: 0 };
    }

    console.log("[MODERATION] Groq judgment:", result);

    return {
      isSafe: result.isSafe !== false,
      reason: result.reason || "No reason",
      score: result.toxicityScore || 0
    };
  } catch (error) {
    console.error("[MODERATION] Groq API error:", error?.response?.data || error.message);
    return { isSafe: true, reason: "API error – allowed", score: 0 };
  }
}

// ────────────────────────────────────────────────
// Email Alert for Blocked Reviews
// ────────────────────────────────────────────────
async function sendAdminAlert(username, blockedReview, checkResult) {
  console.log("[DEBUG] ===== SEND ADMIN ALERT CALLED =====");
  console.log("[DEBUG] Username:", username);
  console.log("[DEBUG] Blocked Review:", blockedReview);
  
  if (!process.env.ADMIN_EMAIL || !process.env.EMAIL_USER || !process.env.BREVO_API_KEY) {
    console.warn("[EMAIL] Credentials missing – skipping alert");
    console.log("[DEBUG] Missing:", {
      adminEmail: !process.env.ADMIN_EMAIL,
      emailUser: !process.env.EMAIL_USER,
      brevoKey: !process.env.BREVO_API_KEY
    });
    return;
  }

  try {
    let sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
    
    sendSmtpEmail.sender = { 
      name: "Daffodils 2082", 
      email: process.env.EMAIL_USER 
    };
    sendSmtpEmail.to = [{ 
      email: process.env.ADMIN_EMAIL,
      name: "Admin"
    }];
    sendSmtpEmail.subject = `⚠️ Blocked Review by ${username}`;
    sendSmtpEmail.htmlContent = `
      <h2 style="color:#d32f2f;">⚠️ Blocked Inappropriate Review</h2>
      <p><strong>Username:</strong> ${username}</p>
      <p><strong>Time:</strong> ${new Date().toLocaleString('en-US', { timeZone: 'Asia/Kathmandu' })}</p>
      <p><strong>Review text:</strong></p>
      <blockquote style="border-left:4px solid #d32f2f; padding-left:15px; margin:10px 0;">${blockedReview}</blockquote>
      <h3>Groq Judgment:</h3>
      <ul>
        <li><strong>Safe?</strong> ${checkResult.isSafe ? 'Yes' : 'No'}</li>
        <li><strong>Score:</strong> ${checkResult.score}/10</li>
        <li><strong>Reason:</strong> ${checkResult.reason}</li>
      </ul>
      <p style="color:#555;">Review was NOT posted.</p>
    `;
    
    console.log("[DEBUG] Attempting to send email via Brevo...");
    const data = await apiInstance.sendTransacEmail(sendSmtpEmail);
    console.log(`[EMAIL] Admin alert sent for ${username}`, data);
  } catch (err) {
    console.error("[EMAIL] Failed to send:", err.response?.body || err.message);
    console.error("[EMAIL] Full error:", err);
  }
}

// ────────────────────────────────────────────────
// REPORT REVIEW + AUTO-DELETE
// ────────────────────────────────────────────────
app.post('/report-review', authMiddleware, async (req, res) => {
  const { reviewId } = req.body;

  if (!reviewId) {
    return res.status(400).json({ success: false, message: "Review ID required" });
  }

  const reporterUsername = req.user.username;
  const reporterIp = req.ip || req.connection.remoteAddress || 'unknown';
  const userAgent = req.headers['user-agent'] || 'unknown';
  const reporterFingerprint = crypto
    .createHash('md5')
    .update(userAgent + reporterIp)
    .digest('hex');

  try {
    const review = await Review.findById(reviewId);
    if (!review) {
      return res.status(404).json({ success: false, message: "Review not found" });
    }

    const alreadyReported = review.reports.some(r =>
      r.reporterUsername === reporterUsername &&
      r.reporterIp === reporterIp &&
      r.reporterFingerprint === reporterFingerprint
    );

    if (alreadyReported) {
      return res.status(400).json({ success: false, message: "You already reported this review" });
    }

    review.reports.push({
      reporterUsername,
      reporterIp,
      reporterFingerprint,
      reportedAt: new Date()
    });

    await review.save();

    const uniqueReporters = new Set();
    review.reports.forEach(report => {
      const key = `${report.reporterUsername}|${report.reporterIp}|${report.reporterFingerprint}`;
      uniqueReporters.add(key);
    });

    if (uniqueReporters.size >= 3) {
      console.log(`[AUTO-DELETE] Review ${reviewId} deleted – ${uniqueReporters.size} unique reports`);
      const reviewName = review.name;
      const reviewMessage = review.message;
      await Review.findByIdAndDelete(reviewId);
      await sendAdminAlertForReport(reporterUsername, reviewName, reviewMessage + " [AUTO-DELETED]", reviewId);
      return res.json({ success: true, message: "Review removed due to multiple reports." });
    }

    await sendAdminAlertForReport(reporterUsername, review.name, review.message, reviewId);
    res.json({ success: true, message: "Report sent to admin. Thank you!" });
  } catch (err) {
    console.error("Report error:", err);
    res.status(500).json({ success: false, message: "Failed to report" });
  }
});

// Email for reports
async function sendAdminAlertForReport(reporter, uploader, reviewText, reviewId) {
  if (!process.env.ADMIN_EMAIL || !process.env.EMAIL_USER || !process.env.BREVO_API_KEY) {
    console.warn("[REPORT EMAIL] Credentials missing");
    return;
  }

  try {
    let sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
    
    sendSmtpEmail.sender = { 
      name: "Daffodils 2082", 
      email: process.env.EMAIL_USER 
    };
    sendSmtpEmail.to = [{ 
      email: process.env.ADMIN_EMAIL 
    }];
    sendSmtpEmail.subject = `🚩 Review Reported by ${reporter}`;
    sendSmtpEmail.htmlContent = `
      <h2 style="color:#d32f2f;">🚩 Review Reported</h2>
      <p><strong>Reported by:</strong> ${reporter}</p>
      <p><strong>Review by:</strong> ${uploader}</p>
      <p><strong>Review ID:</strong> ${reviewId}</p>
      <p><strong>Review text:</strong></p>
      <blockquote style="border-left:4px solid #d32f2f; padding-left:15px; margin:10px 0;">${reviewText}</blockquote>
    `;
    
    const data = await apiInstance.sendTransacEmail(sendSmtpEmail);
    console.log(`[REPORT EMAIL] Sent for review ${reviewId}`, data);
  } catch (err) {
    console.error("[REPORT EMAIL] Failed:", err.response?.body || err.message);
  }
}

// ────────────────────────────────────────────────
// TEST ENDPOINTS - UPDATED to check BREVO_API_KEY
// ────────────────────────────────────────────────

app.get('/test-moderation/:message', async (req, res) => {
  const result = await checkReviewToxicity(req.params.message);
  res.json({
    message: req.params.message,
    moderationResult: result
  });
});

app.get('/test-email', async (req, res) => {
  console.log("[TEST] Testing email functionality with Brevo");
  
  try {
    let sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
    
    sendSmtpEmail.sender = { 
      name: "Daffodils Test", 
      email: process.env.EMAIL_USER 
    };
    sendSmtpEmail.to = [{ 
      email: process.env.ADMIN_EMAIL 
    }];
    sendSmtpEmail.subject = "Test Email from Daffodils";
    sendSmtpEmail.htmlContent = `
      <h1>✅ Test Email</h1>
      <p>If you receive this, Brevo is working perfectly!</p>
      <p>Time: ${new Date().toLocaleString('en-US', { timeZone: 'Asia/Kathmandu' })}</p>
    `;
    
    const data = await apiInstance.sendTransacEmail(sendSmtpEmail);
    console.log("[TEST] Email sent successfully:", data);
    res.send("✅ Email sent successfully! Check your inbox.");
  } catch (err) {
    console.error("[TEST] Email failed:", err.response?.body || err.message);
    res.status(500).send("❌ Email failed: " + JSON.stringify(err.response?.body || err.message));
  }
});

app.get('/test-groq', async (req, res) => {
  const result = await checkReviewToxicity("This is a test message");
  res.json({
    groqKeyExists: !!process.env.GROQ_API_KEY,
    moderationResult: result
  });
});

// UPDATED test-env endpoint to show BREVO_API_KEY
app.get('/test-env', (req, res) => {
  res.json({
    EMAIL_USER_exists: !!process.env.EMAIL_USER,
    ADMIN_EMAIL_exists: !!process.env.ADMIN_EMAIL,
    BREVO_API_KEY_exists: !!process.env.BREVO_API_KEY,  // NOW INCLUDED!
    GROQ_API_KEY_exists: !!process.env.GROQ_API_KEY,
    MONGO_URI_exists: !!process.env.MONGO_URI
  });
});

// ────────────────────────────────────────────────
// SIGNUP
// ────────────────────────────────────────────────
app.post('/signup', async (req, res) => {
  const { username } = req.body;

  if (!username || typeof username !== 'string' || username.trim().length < 3) {
    return res.status(400).json({ success: false, message: "Username must be at least 3 characters" });
  }

  const cleanUsername = username.trim().toLowerCase();

  if (!/^[a-zA-Z0-9_.-]+$/.test(cleanUsername)) {
    return res.status(400).json({ success: false, message: "Username can only contain letters, numbers, underscores, dots and hyphens" });
  }

  try {
    const existing = await User.findOne({ username: cleanUsername });
    if (existing) {
      return res.status(409).json({ success: false, message: "Username already taken" });
    }

    const newUser = new User({ username: cleanUsername });
    await newUser.save();

    const payload = { username: newUser.username };
    const token = Buffer.from(JSON.stringify(payload)).toString('base64');

    return res.json({
      success: true,
      username: newUser.username,
      token
    });
  } catch (err) {
    console.error("Signup error:", err);
    if (err.code === 11000) {
      return res.status(409).json({ success: false, message: "Username already taken" });
    }
    return res.status(500).json({ success: false, message: "Server error during signup – try again" });
  }
});

// ────────────────────────────────────────────────
// LOGIN
// ────────────────────────────────────────────────
app.post('/login', async (req, res) => {
  const { username } = req.body;

  if (!username || typeof username !== 'string') {
    return res.status(400).json({ success: false, message: "Username required" });
  }

  const cleanUsername = username.trim().toLowerCase();

  try {
    const user = await User.findOne({ username: cleanUsername });
    if (!user) {
      return res.status(404).json({ success: false, message: "Username not found" });
    }

    const payload = { username: user.username };
    const token = Buffer.from(JSON.stringify(payload)).toString('base64');

    return res.json({
      success: true,
      username: user.username,
      token
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ success: false, message: "Server error during login" });
  }
});

// ────────────────────────────────────────────────
// REVIEWS
// ────────────────────────────────────────────────
app.get('/reviews', async (req, res) => {
  try {
    const reviews = await Review.find().sort({ createdAt: -1 }).lean();
    res.json(reviews);
  } catch (err) {
    console.error("Get reviews error:", err);
    res.status(500).json({ success: false, message: "Could not fetch reviews" });
  }
});

app.post('/reviews', authMiddleware, async (req, res) => {
  const { message } = req.body;

  if (!message || typeof message !== 'string' || message.trim().length === 0) {
    return res.status(400).json({ success: false, message: "Message cannot be empty" });
  }

  const trimmedMessage = message.trim();
  const check = await checkReviewToxicity(trimmedMessage);

  console.log("[MODERATION] Final check result:", check);

  if (!check.isSafe || check.score >= 5) {
    await sendAdminAlert(req.user.username, trimmedMessage, check);
    return res.status(403).json({
      success: false,
      message: "blocked_toxic",
      warning: `Your review appears to contain negative content. Please keep your words kind.`
    });
  }

  try {
    const review = new Review({
      name: req.user.username,
      message: trimmedMessage
    });
    await review.save();
    res.json({ success: true, message: "Review submitted!" });
  } catch (err) {
    console.error("Post review error:", err);
    res.status(500).json({ success: false, message: "Failed to submit review" });
  }
});

// Health check
app.get('/ping', (req, res) => {
  res.status(200).send('pong');
});

// ────────────────────────────────────────────────
// REPLY & DELETE
// ────────────────────────────────────────────────
app.post('/reviews/:id/reply', async (req, res) => {
  const { name, message } = req.body;

  if (!name || !message || !name.trim() || !message.trim()) {
    return res.status(400).json({ success: false, message: "Name and message required" });
  }

  try {
    const review = await Review.findById(req.params.id);
    if (!review) {
      return res.status(404).json({ success: false, message: "Review not found" });
    }

    review.replies.push({
      name: name.trim(),
      message: message.trim()
    });

    await review.save();
    res.json({ success: true, message: "Reply added!" });
  } catch (err) {
    console.error("Reply error:", err);
    res.status(500).json({ success: false, message: "Failed to add reply" });
  }
});

app.delete('/reviews/:id', async (req, res) => {
  try {
    const deleted = await Review.findByIdAndDelete(req.params.id);
    if (!deleted) {
      return res.status(404).json({ success: false, message: "Review not found" });
    }
    res.json({ success: true, message: "Review deleted" });
  } catch (err) {
    console.error("Delete error:", err);
    res.status(500).json({ success: false, message: "Failed to delete review" });
  }
});

// Admin data viewer
app.get('/admin/data', async (req, res) => {
  try {
    const users = await User.find().lean();
    const reviews = await Review.find().lean();
    
    const formatNepalTime = (date) => {
      return new Date(date).toLocaleString('en-US', { 
        timeZone: 'Asia/Kathmandu',
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: true
      });
    };
    
    let html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Daffodils Data Viewer</title>
      <style>
        body { font-family: Arial; background: #111; color: #fff; padding: 20px; }
        h1 { color: #d4af37; }
        h2 { color: #c2f3f3; margin-top: 30px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 30px; }
        th { background: #d4af37; color: #000; padding: 12px; text-align: left; }
        td { background: #222; padding: 12px; border-bottom: 1px solid #333; vertical-align: top; }
        .container { max-width: 1400px; margin: 0 auto; }
        .note { color: #ffaa00; margin-bottom: 10px; font-style: italic; }
        .badge {
          display: inline-block;
          padding: 3px 8px;
          border-radius: 12px;
          font-size: 12px;
          font-weight: bold;
        }
        .badge-reply { background: #2a5f2a; color: #fff; }
        .badge-report { background: #8b0000; color: #fff; }
        .message-cell { max-width: 400px; word-wrap: break-word; }
        .replies-section { margin-top: 5px; padding: 8px; background: #333; border-radius: 5px; }
        .reply-item { margin-bottom: 5px; border-left: 2px solid #d4af37; padding-left: 8px; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>📊 Daffodils Database Viewer</h1>
        <div class="note">⏰ All times in Nepal Time (UTC+5:45)</div>
        
        <h2>👥 Users (${users.length})</h2>
        <table>
          <tr><th>Username</th><th>Created At</th></tr>
          ${users.map(u => `<tr><td>${u.username}</td><td>${formatNepalTime(u.createdAt)}</td></tr>`).join('')}
        </table>
        
        <h2>💬 Reviews (${reviews.length})</h2>
        <table>
          <tr><th>User</th><th>Message</th><th>Replies</th><th>Reports</th><th>Date</th></tr>
          ${reviews.map(r => `<tr>
            <td>${r.name}</td>
            <td>${r.message.substring(0, 100)}${r.message.length > 100 ? '...' : ''}</td>
            <td>${r.replies?.length || 0}</td>
            <td>${r.reports?.length || 0}</td>
            <td>${formatNepalTime(r.createdAt)}</td>
          </tr>`).join('')}
        </table>
      </div>
    </body>
    </html>
    `;
    
    res.send(html);
  } catch (err) {
    console.error('Admin data error:', err);
    res.status(500).send('Error loading data');
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
