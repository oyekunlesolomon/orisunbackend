const mongoose = require('mongoose');

const personSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  surname: { type: String, required: true },
  maidenName: String,
  email: { type: String, unique: true, sparse: true },
  gender: { type: String, enum: ['male', 'female', 'other'] },
  dob: Date,
  avatar: String, // URL or file path
  parents: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Person' }],
  spouses: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Person' }],
  children: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Person' }],
  siblings: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Person' }],
  online: { type: Boolean, default: false },
  // Pending relationships for unregistered users
  pendingRelationships: [{
    type: {
      type: String,
      enum: ['spouse', 'child', 'parent', 'sibling'],
      required: true
    },
    email: String, // email of the unregistered user
    tempId: String // optional temp identifier
  }],
}, { timestamps: true });

const Person = mongoose.model('Person', personSchema, 'people');
module.exports = Person; 