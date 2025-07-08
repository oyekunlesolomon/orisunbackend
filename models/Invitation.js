const mongoose = require('mongoose');

const invitationSchema = new mongoose.Schema({
  inviter: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  inviteeEmail: { type: String, required: true },
  relationship: { type: String }, // Not required for group invites
  group: { type: mongoose.Schema.Types.ObjectId, ref: 'Group' }, // Optional, for group invites
  type: { type: String, enum: ['relative', 'group'], default: 'relative' },
  token: { type: String, required: true, unique: true },
  status: { type: String, enum: ['pending', 'accepted', 'expired'], default: 'pending' },
  createdAt: { type: Date, default: Date.now, expires: '7d' } // auto-expire after 7 days
});

module.exports = mongoose.model('Invitation', invitationSchema); 