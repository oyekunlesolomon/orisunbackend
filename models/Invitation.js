const mongoose = require('mongoose');

const invitationSchema = new mongoose.Schema({
  inviter: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  inviteeEmail: { type: String, required: true },
  relationship: { type: String, required: true },
  token: { type: String, required: true, unique: true },
  status: { type: String, enum: ['pending', 'accepted', 'expired'], default: 'pending' },
  createdAt: { type: Date, default: Date.now, expires: '7d' } // auto-expire after 7 days
});

module.exports = mongoose.model('Invitation', invitationSchema); 