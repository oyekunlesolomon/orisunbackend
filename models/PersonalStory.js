const mongoose = require('mongoose');

const personalStorySchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  isPublic: { type: Boolean, default: false },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  date: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('PersonalStory', personalStorySchema); 