const mongoose = require('mongoose');

const familypediaSchema = new mongoose.Schema({
  title: { type: String, required: true },
  details: { type: String, required: true },
  date: { type: Date },
  familyId: { type: String, required: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  updatedAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('Familypedia', familypediaSchema); 