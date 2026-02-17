require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const axios = require('axios');
const nodemailer = require('nodemailer');
const crypto = require('crypto'); // for fingerprint

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
// Groq Moderation Check – Relaxed for class memories
// ────────────────────────────────────────────────
async function checkReviewToxicity(message) {
  const apiKey = process.env.GROQ_API_KEY;

  if (!apiKey) {
    console.warn("[MODERATION] No GROQ_API_KEY – skipping");
    return { isSafe: true, reason: "No key", score: 0 };
  }

  // Keyword blacklist for extreme abuses (instant block)
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

  // AI check – very lenient prompt
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
// Email Alert for Blocked Reviews - FIXED with port 2525
// ────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 2525,  // CRITICAL FIX: Using port 2525 instead of default SMTP ports
  secure: false, // Port 2525 uses TLS, not SSL
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false // Helps with connection issues
  }
});

async function sendAdminAlert(username, blockedReview, checkResult) {
  const adminEmail = process.env.ADMIN_EMAIL;

  if (!adminEmail || !process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.warn("[EMAIL] Credentials missing – skipping alert");
    return;
  }

  const mailOptions = {
    from: `"Daffodils 2082 Alert" <${process.env.EMAIL_USER}>`,
    to: adminEmail,
    subject: `⚠️ Blocked Inappropriate Review by ${username}`,
    text: `
Blocked Review Attempt
---------------------
Username: ${username}
Time: ${new Date().toLocaleString('en-US', { timeZone: 'Asia/Kathmandu' })}
Review: "${blockedReview}"

Groq Result:
- Safe: ${checkResult.isSafe ? 'Yes' : 'No'}
- Score: ${checkResult.score}/10
- Reason: ${checkResult.reason}

Review was NOT posted.
    `,
    html: `
      <h2 style="color:#d32f2f;">⚠️ Blocked Inappropriate Review</h2>
      <p><strong>Username:</strong> ${username}</p>
      <p><strong>Time:</strong> ${new Date().toLocaleString('en-US', { timeZone: 'Asia/Kathmandu' })}</p>
      <p><strong>Review text:</strong></p>
      <blockquote style="border-left:4px solid #d32f2f; padding-left:15px; margin:10px 0;">${blockedReview}</blockquote>
      <h3>Groq Judgment:</h3>
      <ul>
        <li><strong>Safe?</strong> ${checkResult.isSafe ? 'Yes' : 'No'}</li>
        <li><strong>Score (0-10):</strong> ${checkResult.score}</li>
        <li><strong>Reason:</strong> ${checkResult.reason}</li>
      </ul>
      <p style="color:#555;">Review was NOT posted.</p>
      <hr>
      <small>Daffodils Public School – Batch 2082 Memorial</small>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`[EMAIL] Admin alert sent for ${username}`);
  } catch (err) {
    console.error("[EMAIL] Failed to send:", err.message);
  }
}

// ────────────────────────────────────────────────
// REPORT REVIEW + AUTO-DELETE ON 3 UNIQUE REPORTS
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

    // Prevent duplicate reports from same user/device
    const alreadyReported = review.reports.some(r =>
      r.reporterUsername === reporterUsername &&
      r.reporterIp === reporterIp &&
      r.reporterFingerprint === reporterFingerprint
    );

    if (alreadyReported) {
      return res.status(400).json({ success: false, message: "You already reported this review" });
    }

    // Add report
    review.reports.push({
      reporterUsername,
      reporterIp,
      reporterFingerprint,
      reportedAt: new Date()
    });

    await review.save();

    // AUTO-DELETE CHECK - Check if 3+ unique reports
    const uniqueReporters = new Set();
    review.reports.forEach(report => {
      const key = `${report.reporterUsername}|${report.reporterIp}|${report.reporterFingerprint}`;
      uniqueReporters.add(key);
    });

    if (uniqueReporters.size >= 3) {
      console.log(`[AUTO-DELETE] Review ${reviewId} deleted – ${uniqueReporters.size} unique reports`);
      
      // Store info before deletion
      const reviewName = review.name;
      const reviewMessage = review.message;
      
      // Delete the review
      await Review.findByIdAndDelete(reviewId);
      
      // Send email about auto-delete
      await sendAdminAlertForReport(
        reporterUsername, 
        reviewName, 
        reviewMessage + "\n\n[This review was AUTO-DELETED due to 3+ reports]", 
        reviewId
      );
      
      return res.json({ 
        success: true, 
        message: "Review has been removed due to multiple reports." 
      });
    }

    // Send email to admin about the report
    await sendAdminAlertForReport(reporterUsername, review.name, review.message, reviewId);

    res.json({ success: true, message: "Report sent to admin. Thank you!" });
  } catch (err) {
    console.error("Report error:", err);
    res.status(500).json({ success: false, message: "Failed to report" });
  }
});

// Email for reports - FIXED with same transporter
async function sendAdminAlertForReport(reporter, uploader, reviewText, reviewId) {
  const adminEmail = process.env.ADMIN_EMAIL;

  if (!adminEmail || !process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.warn("[REPORT EMAIL] Credentials missing");
    return;
  }

  const mailOptions = {
    from: `"Daffodils 2082 Report" <${process.env.EMAIL_USER}>`,
    to: adminEmail,
    subject: `🚩 Review Reported by ${reporter}`,
    text: `
Review Reported!
----------------
Reported by: ${reporter}
Review by: ${uploader}
Review ID: ${reviewId}
Review text: "${reviewText}"

Action needed: Please review and delete if inappropriate.
    `,
    html: `
      <h2 style="color:#d32f2f;">🚩 Review Reported</h2>
      <p><strong>Reported by:</strong> ${reporter}</p>
      <p><strong>Review by:</strong> ${uploader}</p>
      <p><strong>Review ID:</strong> ${reviewId}</p>
      <p><strong>Review text:</strong></p>
      <blockquote style="border-left:4px solid #d32f2f; padding-left:15px; margin:10px 0;">${reviewText}</blockquote>
      <p style="color:#555;">Please review and take action if needed.</p>
      <hr>
      <small>Daffodils Public School – Batch 2082 Memorial</small>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`[REPORT EMAIL] Sent for review ${reviewId}`);
  } catch (err) {
    console.error("[REPORT EMAIL] Failed:", err.message);
  }
}

// ────────────────────────────────────────────────
// SIGNUP – passwordless
// ────────────────────────────────────────────────
app.post('/signup', async (req, res) => {
  const { username } = req.body;

  if (!username || typeof username !== 'string' || username.trim().length < 3) {
    return res.status(400).json({ success: false, message: "Username must be at least 3 characters" });
  }

  const cleanUsername = username.trim().toLowerCase();

  // Optional: extra validation (match your schema regex)
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

    // Handle MongoDB duplicate key error specifically
    if (err.code === 11000) { // duplicate key
      return res.status(409).json({ success: false, message: "Username already taken" });
    }

    // Other errors (validation, DB crash, etc.)
    return res.status(500).json({ success: false, message: "Server error during signup – try again" });
  }
});

// ────────────────────────────────────────────────
// LOGIN – passwordless
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
// GET REVIEWS
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

// ────────────────────────────────────────────────
// POST REVIEW – WITH Groq MODERATION + EMAIL ALERT
// ────────────────────────────────────────────────
app.post('/reviews', authMiddleware, async (req, res) => {
  const { message } = req.body;

  if (!message || typeof message !== 'string' || message.trim().length === 0) {
    return res.status(400).json({ success: false, message: "Message cannot be empty" });
  }

  const trimmedMessage = message.trim();

  // Run Groq moderation
  const check = await checkReviewToxicity(trimmedMessage);

  console.log("[MODERATION] Final check result:", check);

  // Block if flagged or high score
  if (!check.isSafe || check.score >= 5) {
    await sendAdminAlert(req.user.username, trimmedMessage, check);

    return res.status(403).json({
      success: false,
      message: "blocked_toxic",
      warning: `Your review appears to contain negative, aggressive or controversial content.

This is a memorial space for Class 10 – Batch 2082.
Please keep your words kind, positive or constructive.

We appreciate suggestions and happy memories.
Thank you for helping maintain peace and harmony here.

— Daffodils Public School 2082`
    });
  }

  // Safe – save
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

// Ultra-light health check for uptime monitors
app.get('/ping', (req, res) => {
  res.status(200).send('pong');
});

// ────────────────────────────────────────────────
// REPLY & DELETE
// ────────────────────────────────────────────────
app.post('/reviews/:id/reply', async (req, res) => {
  const { name, message } = req.body;

  if (!name || !message || !name.trim() || !message.trim()) {
    return res.status(400).json({ success: false, message: "Name and message required for reply" });
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
    console.error("Delete review error:", err);
    res.status(500).json({ success: false, message: "Failed to delete review" });
  }
});

// Admin data viewer
app.get('/admin/data', async (req, res) => {
  try {
    const users = await User.find().lean();
    const reviews = await Review.find().lean();
    
    // Helper function for Nepal time
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
        .message-cell {
          max-width: 400px;
          word-wrap: break-word;
          white-space: pre-wrap;
        }
        .replies-section {
          margin-top: 5px;
          padding: 8px;
          background: #333;
          border-radius: 5px;
          font-size: 0.9em;
        }
        .reply-item {
          margin-bottom: 5px;
          border-left: 2px solid #d4af37;
          padding-left: 8px;
        }
        .view-toggle {
          cursor: pointer;
          color: #d4af37;
          text-decoration: underline;
          margin-left: 5px;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>📊 Daffodils Database Viewer</h1>
        <div class="note">⏰ All times are in Nepal Time (UTC+5:45)</div>
        
        <h2>👥 Users (${users.length})</h2>
        <table>
          <tr>
            <th>Username</th>
            <th>Created At (Nepal Time)</th>
          </tr>
          ${users.map(u => `
            <tr>
              <td><strong>${u.username}</strong></td>
              <td>${formatNepalTime(u.createdAt)}</td>
            </tr>
          `).join('')}
        </table>
        
        <h2>💬 Reviews (${reviews.length})</h2>
        <table>
          <tr>
            <th>User</th>
            <th>Message</th>
            <th>Replies</th>
            <th>Reports</th>
            <th>Date (Nepal Time)</th>
          </tr>
          ${reviews.map(r => {
            const repliesList = r.replies?.map(rep => 
              `<div class="reply-item">
                <strong>${rep.name}</strong> (${formatNepalTime(rep.createdAt)}): 
                <span>${rep.message}</span>
              </div>`
            ).join('') || 'No replies';
            
            return `
            <tr>
              <td><strong>${r.name}</strong></td>
              <td class="message-cell">
                <div class="full-message">${r.message}</div>
                ${r.message.length > 100 ? 
                  `<span class="view-toggle" onclick="this.previousElementSibling.classList.toggle('full-message')">Show less</span>` 
                  : ''}
              </td>
              <td>
                <span class="badge badge-reply">${r.replies?.length || 0}</span>
                ${r.replies?.length > 0 ? 
                  `<div class="replies-section">${repliesList}</div>` 
                  : ''}
              </td>
              <td><span class="badge badge-report">${r.reports?.length || 0}</span></td>
              <td>${formatNepalTime(r.createdAt)}</td>
            </tr>
          `}).join('')}
        </table>
      </div>
      
      <script>
        document.querySelectorAll('.view-toggle').forEach(btn => {
          btn.addEventListener('click', function() {
            const msgDiv = this.previousElementSibling;
            if (msgDiv.classList.contains('full-message')) {
              msgDiv.classList.remove('full-message');
              this.textContent = 'Show less';
            } else {
              msgDiv.classList.add('full-message');
              this.textContent = 'Show full';
            }
          });
        });
      </script>
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
