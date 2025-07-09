const express = require('express');
const router = express.Router();
const Group = require('../models/Group');
const GroupMessage = require('../models/GroupMessage');
const User = require('../models/User');
const Invitation = require('../models/Invitation');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

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

// Helper to send group invitation email
async function sendGroupInviteEmail(to, inviterName, groupName, inviteLink) {
  // Use your SMTP config here
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
  const mailOptions = {
    from: process.env.SMTP_FROM || 'no-reply@orisun.com',
    to,
    subject: `Group Invitation: ${groupName}`,
    html: `<p>Hello,</p>
      <p>${inviterName} has invited you to join the group <b>${groupName}</b> on Orisun Family App.</p>
      <p>Click <a href="${inviteLink}">here</a> to accept the invitation.</p>
      <p>If you did not expect this invitation, you can ignore this email.</p>`
  };
  await transporter.sendMail(mailOptions);
}

// Create group with invitations
router.post('/', authenticate, async (req, res) => {
  const { name, members } = req.body;
  if (!name || !Array.isArray(members) || members.length === 0) {
    return res.status(400).json({ message: 'Name and members are required.' });
  }
  // Only add creator as member initially
  const group = new Group({ name, members: [req.user.id], createdBy: req.user.id });
  await group.save();

  // Invite each member (except creator)
  const inviterUser = await User.findById(req.user.id);
  for (const memberId of members) {
    if (memberId === req.user.id) continue;
    const inviteeUser = await User.findById(memberId);
    if (!inviteeUser) continue;
    const token = crypto.randomBytes(24).toString('hex');
    const invitation = new Invitation({
      inviter: req.user.id,
      inviteeEmail: inviteeUser.email,
      group: group._id,
      type: 'group',
      token,
      status: 'pending',
    });
    await invitation.save();
    const inviteLink = `http://localhost:3000/group-invite?token=${token}`;
    await sendGroupInviteEmail(inviteeUser.email, `${inviterUser.firstName} ${inviterUser.surname}`, name, inviteLink);
  }
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

// Accept group invitation
router.post('/invite-accept', authenticate, async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ message: 'Token required.' });
  const invitation = await Invitation.findOne({ token, type: 'group', status: 'pending' });
  if (!invitation) return res.status(404).json({ message: 'Invitation not found or already accepted.' });
  // Add user to group
  const group = await Group.findById(invitation.group);
  if (!group) return res.status(404).json({ message: 'Group not found.' });
  if (!group.members.includes(req.user.id)) {
    group.members.push(req.user.id);
    await group.save();
  }
  invitation.status = 'accepted';
  await invitation.save();
  res.json({ success: true, group });
});

// Get pending group invitations for the current user
router.get('/pending-invites', authenticate, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(401).json({ message: 'User not found' });
  const invites = await Invitation.find({ inviteeEmail: user.email, type: 'group', status: 'pending' }).populate('group inviter');
  res.json(invites);
});

module.exports = router; 