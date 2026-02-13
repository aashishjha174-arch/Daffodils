// server.js
const mongoose = require('mongoose');
const express = require('express');
const cors = require('cors');
const Review = require('./models/review');

const app = express();
app.use(cors());
app.use(express.json());

// Connect to MongoDB
mongoose.connect(
  'mongodb+srv://testuser:Test12345@cluster0.lxhz3yk.mongodb.net/Aashish123?retryWrites=true&w=majority',
  { useNewUrlParser: true, useUnifiedTopology: true }
)
.then(() => console.log("MongoDB connected"))
.catch(err => console.log(err));

// --- Routes ---

// Get all reviews
app.get('/reviews', async (req, res) => {
  const reviews = await Review.find().sort({ createdAt: -1 });
  res.json(reviews);
});

// Post a new review
app.post('/reviews', async (req, res) => {
  const { name, message } = req.body;
  const review = new Review({ name, message });
  await review.save();
  res.json({ success: true, message: "Review submitted!" });
});

// Post a reply to a review
app.post('/reviews/:id/reply', async (req, res) => {
  const { id } = req.params;
  const { name, message } = req.body;

  const review = await Review.findById(id);
  if (!review) return res.status(404).json({ success: false, message: "Review not found" });

  review.replies.push({ name, message });
  await review.save();

  res.json({ success: true, message: "Reply added!" });
});

// Delete a review
app.delete('/reviews/:id', async (req, res) => {
  const { id } = req.params;
  await Review.findByIdAndDelete(id);
  res.json({ success: true });
});

// Dynamic port for Render
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
