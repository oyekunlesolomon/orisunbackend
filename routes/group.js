const express = require('express');
const router = express.Router();
const Group = require('../models/Group');
const GroupMessage = require('../models/GroupMessage');
const User = require('../models/User');

// Middleware for authentication
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Unauthorized' });
  const jwt = require('jsonwebtoken');
  const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Forbidden' });
    req.user = user;
    next();
  });
};

// Create group
router.post('/', authenticate, async (req, res) => {
  const { name, members } = req.body;
  if (!name || !Array.isArray(members) || members.length === 0) {
    return res.status(400).json({ message: 'Name and members are required.' });
  }
  const group = new Group({ name, members, createdBy: req.user.id });
  await group.save();
  res.status(201).json(group);
});

// Get all groups for user
router.get('/', authenticate, async (req, res) => {
  const groups = await Group.find({ members: req.user.id });
  res.json(groups);
});

// Get group messages
router.get('/:groupId/messages', authenticate, async (req, res) => {
  const messages = await GroupMessage.find({ group: req.params.groupId }).sort({ timestamp: 1 });
  res.json(messages);
});

// Send group message
router.post('/:groupId/messages', authenticate, async (req, res) => {
  const { text, fileUrl } = req.body;
  const message = new GroupMessage({
    group: req.params.groupId,
    sender: req.user.id,
    text,
    fileUrl
  });
  await message.save();
  res.status(201).json(message);
});

module.exports = router; 