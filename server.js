// Load environment variables
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { Server } = require('socket.io');
const groupRoutes = require('./routes/group');
const User = require('./models/User');
const Person = require('./models/Person');
const Invitation = require('./models/Invitation');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const Familypedia = require('./models/Familypedia');
const PersonalStory = require('./models/PersonalStory');

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());

// MongoDB Connection
const MONGO_URI = process.env.MONGO_URI;
mongoose
  .connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB Atlas'))
  .catch((err) => console.error('MongoDB connection error:', err.message));

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// Middleware for authentication
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).send({ message: 'Unauthorized' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).send({ message: 'Forbidden' });
    req.user = user;
    next();
  });
};

// Define the User Schema
// const userSchema = new mongoose.Schema({ ... });
// const User = mongoose.model('User', userSchema);

// Helper function for responses
const sendResponse = (res, statusCode, message, data = {}) => {
  res.status(statusCode).send({ message, ...data });
};

// Helper to send invitation email
async function sendInvitationEmail(to, inviterName, relationship, inviteLink) {
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
    subject: `You've been invited to join Orisun Family App!`,
    html: `<p>Hello,</p>
      <p>${inviterName} has added you as their <b>${relationship}</b> on Orisun Family App.</p>
      <p>Click <a href="${inviteLink}">here</a> to register and connect your family tree.</p>
      <p>If you did not expect this invitation, you can ignore this email.</p>`
  };
  await transporter.sendMail(mailOptions);
}

// Authentication Endpoints
app.post('/api/register', async (req, res) => {
  try {
    const { firstName, surname, email, password, country, gender, invite } = req.body;
    if (!firstName || !surname || !email || !password || !country) {
      return sendResponse(res, 400, 'All fields are required.');
    }
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return sendResponse(res, 400, 'User already exists.');
    }
    // Check for existing Person with the same email
    let person = await Person.findOne({ email });
    if (person) {
      // Update the person with any new info (optional, e.g. firstName, surname, gender)
      person.firstName = firstName;
      person.surname = surname;
      if (gender) person.gender = gender;
      await person.save();
    } else {
      person = new Person({
        firstName,
        surname,
        email,
        gender,
      });
      await person.save();
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    // Create the User document, referencing the Person
    const user = new User({
      email,
      password: hashedPassword,
      firstName,
      surname,
      person: person._id,
      relatives: [],
    });
    await user.save();

    // If registering via invite, update both users' relatives
    if (invite) {
      const invitation = await Invitation.findOne({ token: invite, inviteeEmail: email, status: 'pending' });
      if (invitation) {
        // Mark invitation as accepted
        invitation.status = 'accepted';
        await invitation.save();
        // Add inviter to invitee's relatives
        const inviterUser = await User.findById(invitation.inviter).populate('person');
        if (inviterUser) {
          // Only push if all required fields are present
          if (inviterUser.person?.firstName && inviterUser.person?.surname && invitation.relationship) {
            user.relatives.push({
              name: inviterUser.person.firstName,
              surname: inviterUser.person.surname,
              email: inviterUser.email,
              relationship: invitation.relationship,
              gender: inviterUser.person.gender || '',
            });
          }
          if (firstName && surname && invitation.relationship) {
            inviterUser.relatives.push({
              name: firstName,
              surname: surname,
              email: email,
              relationship: getInverseRelationship(invitation.relationship),
              gender: gender,
            });
          }
          await user.save();
          await inviterUser.save();
        }
      }
    }

    const token = jwt.sign({ id: user._id.toString() }, JWT_SECRET, { expiresIn: '1h' });
    const inviteLink = `${process.env.FRONTEND_URL || 'https://orisun-frontend.vercel.app'}/register?invite=${token}`;
    await sendInvitationEmail(email, inviterName, relationship, inviteLink);
    sendResponse(res, 201, 'Registration successful!', {
      token,
      user: { id: user._id.toString(), firstName, surname, email, gender: person.gender },
    });
  } catch (error) {
    console.error('Error during registration:', error.message);
    sendResponse(res, 500, 'Internal server error');
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return sendResponse(res, 400, 'Email and password are required.');
    }
    const user = await User.findOne({ email });
    if (!user) {
      return sendResponse(res, 404, 'User not found.');
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return sendResponse(res, 400, 'Invalid credentials.');
    }
    const token = jwt.sign({ id: user._id.toString() }, JWT_SECRET, { expiresIn: '1h' });
    sendResponse(res, 200, 'Login successful!', {
      token,
      user: { id: user._id.toString(), firstName: user.firstName, surname: user.surname, email: user.email },
    });
  } catch (error) {
    console.error('Error during login:', error.message);
    sendResponse(res, 500, 'Internal server error');
  }
});

// Profile Management Endpoints
app.get('/api/profile', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).populate({ path: 'person', model: 'Person', collection: 'people' });
    if (!user) {
      return sendResponse(res, 404, 'User not found.');
    }
    sendResponse(res, 200, 'Profile fetched successfully.', { user });
  } catch (error) {
    console.error('Error fetching profile:', error.message);
    sendResponse(res, 500, 'Internal server error');
  }
});

app.put('/api/profile', authenticate, async (req, res) => {
  try {
    const updates = req.body;
    const user = await User.findByIdAndUpdate(req.user.id, updates, { new: true });
    if (!user) return sendResponse(res, 404, 'User not found.');
    sendResponse(res, 200, 'Profile updated successfully.', { user });
  } catch (error) {
    console.error('Error updating profile:', error.message);
    sendResponse(res, 500, 'Internal server error');
  }
});

// Add Relative Endpoint
app.post('/api/add-relative', authenticate, async (req, res) => {
  try {
    const { name, surname, maidenName, email, relationship, gender, dob, parentName } = req.body;
    if (!name || !surname || !relationship) {
      return sendResponse(res, 400, 'Name, surname, and relationship are required.');
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return sendResponse(res, 404, 'User not found.');
    }

    // Check if the email is already a user
    const existingUser = await User.findOne({ email });
    if (!existingUser && email) {
      // Generate unique token
      const token = crypto.randomBytes(32).toString('hex');
      // Create invitation
      await Invitation.create({
        inviter: user._id,
        inviteeEmail: email,
        relationship,
        token,
      });
      // Always populate person for inviter to get full name
      const inviterWithPerson = await User.findById(user._id).populate('person');
      const inviterName = inviterWithPerson.person ? `${inviterWithPerson.person.firstName} ${inviterWithPerson.person.surname}` : inviterWithPerson.email;
      const inviteLink = `${process.env.FRONTEND_URL || 'https://orisun-frontend.vercel.app'}/register?invite=${token}`;
      await sendInvitationEmail(email, inviterName, relationship, inviteLink);
    }

    // Only push if all required fields are present
    if (name && surname && relationship) {
      const relative = { name, surname, maidenName, email, relationship, gender, dob, parentName };
      user.relatives.push(relative);
    }

    await user.save();
    sendResponse(res, 201, 'Relative added successfully!', { relative: { name, surname, maidenName, email, relationship, gender, dob, parentName } });
  } catch (error) {
    console.error('Error adding relative:', error.message);
    sendResponse(res, 500, 'Internal server error');
  }
});

// Edit Relative Endpoint
app.post('/api/edit-relative', authenticate, async (req, res) => {
  try {
    const { index, ...updatedRelative } = req.body;

    const user = await User.findById(req.user.id);
    if (!user) {
      return sendResponse(res, 404, 'User not found.');
    }

    if (index === undefined || !user.relatives[index]) {
      return sendResponse(res, 400, 'Invalid relative index.');
    }

    user.relatives[index] = { ...user.relatives[index], ...updatedRelative };

    await user.save();
    sendResponse(res, 200, 'Relative updated successfully.', { relative: user.relatives[index] });
  } catch (error) {
    console.error('Error editing relative:', error.message);
    sendResponse(res, 500, 'Internal server error');
  }
});

// Delete Relative Endpoint
app.delete('/api/delete-relative', authenticate, async (req, res) => {
  try {
    const { index } = req.body;

    const user = await User.findById(req.user.id);
    if (!user) {
      return sendResponse(res, 404, 'User not found.');
    }

    if (index === undefined || !user.relatives[index]) {
      return sendResponse(res, 400, 'Invalid relative index.');
    }

    user.relatives.splice(index, 1);

    await user.save();
    sendResponse(res, 200, 'Relative deleted successfully.');
  } catch (error) {
    console.error('Error deleting relative:', error.message);
    sendResponse(res, 500, 'Internal server error');
  }
});

// Relatives Endpoint
app.get('/api/relatives', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).lean();
    if (!user) {
      return sendResponse(res, 404, 'User not found.');
    }
    sendResponse(res, 200, 'Relatives retrieved successfully.', { relatives: user.relatives || [] });
  } catch (error) {
    console.error('Error fetching relatives:', error.message);
    sendResponse(res, 500, 'Internal server error');
  }
});

// Family Tree Endpoint
app.get('/api/family-tree', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).populate('person').lean();
    if (!user) {
      return sendResponse(res, 404, 'User not found.');
    }

    let firstName = '';
    let surname = '';
    if (user.person) {
      firstName = user.person.firstName || '';
      surname = user.person.surname || '';
    } else {
      firstName = user.firstName || '';
      surname = user.surname || '';
    }
    const tree = {
      name: `${firstName} ${surname}`.trim(),
      children: (user.relatives || []).map((relative) => ({
        name: `${relative.name} ${relative.surname}`,
        relationship: relative.relationship,
        gender: relative.gender,
      })),
    };

    sendResponse(res, 200, 'Family tree retrieved successfully.', { tree });
  } catch (error) {
    console.error('Error retrieving family tree:', error.message);
    sendResponse(res, 500, 'Internal server error');
  }
});

// --- Chat & File Upload Support ---

// Ensure uploads directory exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

// In-memory chat messages (for demo; use DB in production)
let chatMessages = [
  { id: 1, text: 'Welcome to the family chat!', sender: 'system', timestamp: Date.now() }
];

// Get all chat messages
app.get('/api/chat/messages', authenticate, (req, res) => {
  res.json(chatMessages);
});

// Post a new chat message
app.post('/api/chat/message', authenticate, (req, res) => {
  const { text, sender, fileUrl } = req.body;
  if (!text && !fileUrl) return res.status(400).json({ message: 'Message text or file required.' });
  const msg = {
    id: Date.now(),
    text: text || '',
    sender: sender || req.user.id,
    fileUrl: fileUrl || null,
    timestamp: Date.now()
  };
  chatMessages.push(msg);
  res.status(201).json(msg);
});

// File upload endpoint
app.post('/api/chat/upload', authenticate, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'No file uploaded.' });
  const fileUrl = `/uploads/${req.file.filename}`;
  res.status(201).json({ fileUrl });
});

// Serve uploaded files
app.use('/uploads', express.static(uploadDir));

// --- Real-time Chat with Socket.io ---
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

let onlineUsers = {};

io.on('connection', (socket) => {
  let userId = null;
  socket.on('login', (id) => {
    userId = id;
    onlineUsers[userId] = socket.id;
    io.emit('onlineUsers', Object.keys(onlineUsers));
  });
  socket.on('sendMessage', (msg) => {
    chatMessages.push(msg);
    io.emit('newMessage', msg);
  });
  socket.on('deleteMessage', (msgId) => {
    chatMessages = chatMessages.filter(m => m.id !== msgId);
    io.emit('deleteMessage', msgId);
  });
  socket.on('disconnect', () => {
    if (userId) delete onlineUsers[userId];
    io.emit('onlineUsers', Object.keys(onlineUsers));
  });
});

// Message deletion endpoint
app.delete('/api/chat/message/:id', authenticate, (req, res) => {
  const msgId = parseInt(req.params.id);
  const msg = chatMessages.find(m => m.id === msgId);
  if (!msg) return res.status(404).json({ message: 'Message not found.' });
  // Only allow sender or admin to delete
  if (msg.sender !== req.user.id && msg.sender !== 'system') return res.status(403).json({ message: 'Not allowed.' });
  chatMessages = chatMessages.filter(m => m.id !== msgId);
  res.json({ success: true });
});

// Get online/offline family members (stub)
app.get('/api/chat/online-users', authenticate, async (req, res) => {
  // For demo, return all users with online status
  const users = await User.find({}, 'firstName surname _id email').lean();
  const online = Object.keys(onlineUsers);
  res.json(users.map(u => ({ ...u, online: online.includes(u._id.toString()) })));
});

// Ensure models directory exists
const modelsDir = path.join(__dirname, 'models');
if (!fs.existsSync(modelsDir)) fs.mkdirSync(modelsDir);

// Add new person routes
const personRouter = express.Router();

// Create a new person
personRouter.post('/', async (req, res) => {
  try {
    const person = new Person(req.body);
    await person.save();
    res.status(201).json(person);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Get a person's profile (with relationships populated)
personRouter.get('/:id', async (req, res) => {
  try {
    const person = await Person.findById(req.params.id)
      .populate('parents spouses children siblings');
    if (!person) return res.status(404).json({ error: 'Not found' });
    res.json(person);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Update a person (add relationships, update info)
personRouter.put('/:id', async (req, res) => {
  try {
    const person = await Person.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(person);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Get a person's family tree (recursive, basic version)
personRouter.get('/:id/tree', async (req, res) => {
  async function buildTree(personId, depth = 2) {
    if (depth === 0) return null;
    const person = await Person.findById(personId)
      .populate('spouses children siblings parents');
    if (!person) return null;
    return {
      _id: person._id,
      name: `${person.firstName} ${person.surname}`,
      gender: person.gender,
      avatar: person.avatar,
      spouses: await Promise.all((person.spouses || []).map(s => buildTree(s._id, depth - 1))),
      children: await Promise.all((person.children || []).map(c => buildTree(c._id, depth - 1))),
      siblings: await Promise.all((person.siblings || []).map(s => buildTree(s._id, depth - 1))),
      parents: await Promise.all((person.parents || []).map(p => buildTree(p._id, depth - 1))),
    };
  }
  try {
    const tree = await buildTree(req.params.id, 3); // 3 levels deep
    res.json(tree);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.use('/api/person', personRouter);

// Add group routes
app.use('/api/groups', groupRoutes);

// Fetch invitation details by token
app.get('/api/invitation/:token', async (req, res) => {
  try {
    const invite = await Invitation.findOne({ token: req.params.token });
    if (!invite) return res.status(404).json({ message: 'Invitation not found' });
    res.json({ invite });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Familypedia (Family History) Endpoints
app.get('/api/familypedia/:identifier', async (req, res) => {
  try {
    const items = await Familypedia.find({ familyId: req.params.identifier }).sort({ date: -1 });
    res.json({ history: items });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch family history.' });
  }
});

app.post('/api/familypedia/:identifier', authenticate, async (req, res) => {
  try {
    const { title, details, date } = req.body;
    if (!title || !details) return res.status(400).json({ message: 'Title and details are required.' });
    const item = await Familypedia.create({
      title,
      details,
      date,
      familyId: req.params.identifier,
      createdBy: req.user.id,
    });
    res.json({ item });
  } catch (err) {
    res.status(500).json({ message: 'Failed to add family history.' });
  }
});

app.put('/api/familypedia/:id', authenticate, async (req, res) => {
  try {
    const { title, details, date } = req.body;
    const item = await Familypedia.findByIdAndUpdate(
      req.params.id,
      { title, details, date, updatedAt: Date.now() },
      { new: true }
    );
    if (!item) return res.status(404).json({ message: 'Not found.' });
    res.json({ item });
  } catch (err) {
    res.status(500).json({ message: 'Failed to update family history.' });
  }
});

app.delete('/api/familypedia/:id', authenticate, async (req, res) => {
  try {
    const item = await Familypedia.findByIdAndDelete(req.params.id);
    if (!item) return res.status(404).json({ message: 'Not found.' });
    res.json({ message: 'Deleted.' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to delete family history.' });
  }
});

// Personal Stories Endpoints
app.get('/api/personal-stories/:userId', async (req, res) => {
  try {
    const stories = await PersonalStory.find({ userId: req.params.userId }).sort({ date: -1 });
    res.json({ stories });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch personal stories.' });
  }
});

app.post('/api/personal-stories/:userId', authenticate, async (req, res) => {
  try {
    const { title, content, isPublic } = req.body;
    if (!title || !content) return res.status(400).json({ message: 'Title and content are required.' });
    const story = await PersonalStory.create({
      title,
      content,
      isPublic: !!isPublic,
      userId: req.params.userId,
    });
    res.json({ story });
  } catch (err) {
    res.status(500).json({ message: 'Failed to add personal story.' });
  }
});

app.put('/api/personal-stories/:id', authenticate, async (req, res) => {
  try {
    const { title, content, isPublic } = req.body;
    const story = await PersonalStory.findByIdAndUpdate(
      req.params.id,
      { title, content, isPublic, updatedAt: Date.now() },
      { new: true }
    );
    if (!story) return res.status(404).json({ message: 'Not found.' });
    res.json({ story });
  } catch (err) {
    res.status(500).json({ message: 'Failed to update personal story.' });
  }
});

app.delete('/api/personal-stories/:id', authenticate, async (req, res) => {
  try {
    const story = await PersonalStory.findByIdAndDelete(req.params.id);
    if (!story) return res.status(404).json({ message: 'Not found.' });
    res.json({ message: 'Deleted.' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to delete personal story.' });
  }
});

// Start the Server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));

// Helper to get inverse relationship
function getInverseRelationship(rel) {
  switch (rel) {
    case 'spouse': return 'spouse';
    case 'father': return 'child';
    case 'mother': return 'child';
    case 'child': return 'parent';
    case 'sibling': return 'sibling';
    default: return 'relative';
  }
}