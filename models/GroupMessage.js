const mongoose = require('mongoose');

const groupMessageSchema = new mongoose.Schema({
  group: { type: mongoose.Schema.Types.ObjectId, ref: 'Group', required: true },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text: String,
  fileUrl: String,
  timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model('GroupMessage', groupMessageSchema); 