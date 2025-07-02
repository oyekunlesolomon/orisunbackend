const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  firstName: { type: String, required: true },
  surname: { type: String, required: true },
  person: { type: mongoose.Schema.Types.ObjectId, ref: 'Person', required: true },
  relatives: {
    type: [Object],
    default: [],
  },
});

const User = mongoose.model('User', userSchema);
module.exports = User; 