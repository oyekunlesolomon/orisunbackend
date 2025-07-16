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
const scrabbleRoutes = require('./routes/scrabble');
const scrabbleGames = require('./routes/scrabble').games; // Expose games object
const User = require('./models/User');
const Person = require('./models/Person');
const Invitation = require('./models/Invitation');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const Familypedia = require('./models/Familypedia');
const PersonalStory = require('./models/PersonalStory');
const wordListPath = path.join(__dirname, '../node_modules/word-list/words.txt');
const _ = require('lodash');
let WORD_SET = null;
function loadWordSet() {
  if (!WORD_SET) {
    const words = fs.readFileSync(wordListPath, 'utf8').split('\n');
    WORD_SET = new Set(words.map(w => w.toUpperCase()));
  }
}
loadWordSet();

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
    const user = new User({
      email,
      password: hashedPassword,
      firstName,
      surname,
      person: person._id,
      relatives: [],
    });
    await user.save();

    // If registering via invite, update both users' relatives and link relationships
    if (invite) {
      const invitation = await Invitation.findOne({ token: invite, inviteeEmail: email, status: 'pending' });
      if (invitation) {
        invitation.status = 'accepted';
        await invitation.save();
        // Add inviter to invitee's relatives
        const inviterUser = await User.findById(invitation.inviter).populate('person');
        if (inviterUser) {
          // Link as spouse if relationship is spouse
          if (invitation.relationship === 'spouse') {
            // Add each other as spouses in Person
            const inviteePerson = person;
            if (!inviteePerson.spouses.some(x => x.equals(inviterUser.person._id))) {
              inviteePerson.spouses.push(inviterUser.person._id);
              await inviteePerson.save();
            }
            const inviterPerson = await Person.findById(inviterUser.person._id);
            if (!inviterPerson.spouses.some(x => x.equals(inviteePerson._id))) {
              inviterPerson.spouses.push(inviteePerson._id);
              await inviterPerson.save();
            }
            // Add each other as spouses in User.relatives
            const already = (user.relatives || []).some(r => r.email === inviterUser.email && r.relationship === 'spouse');
            if (!already) {
              user.relatives.push({
                name: inviterUser.firstName,
                surname: inviterUser.surname,
                email: inviterUser.email,
                relationship: 'spouse',
                gender: inviterUser.gender,
              });
              await user.save();
            }
            const already2 = (inviterUser.relatives || []).some(r => r.email === email && r.relationship === 'spouse');
            if (!already2) {
              inviterUser.relatives.push({
                name: firstName,
                surname: surname,
                email: email,
                relationship: 'spouse',
                gender: gender,
              });
              await inviterUser.save();
            }
            // --- NEW: Link all inviter's children to registering user as children ---
            const inviterPersonWithChildren = await Person.findById(inviterUser.person._id).populate('children');
            for (const child of inviterPersonWithChildren.children) {
              // Add to registering user's Person
              if (!person.children.some(x => x.equals(child._id))) {
                person.children.push(child._id);
                await person.save();
              }
              // Add registering user as parent to child
              const childPerson = await Person.findById(child._id);
              if (!childPerson.parents.some(x => x.equals(person._id))) {
                childPerson.parents.push(person._id);
                await childPerson.save();
              }
              // Add to User.relatives if registering user is a user
              const alreadyChild = (user.relatives || []).some(r => r.email === childPerson.email && r.relationship === 'child');
              if (!alreadyChild) {
                user.relatives.push({
                  name: childPerson.firstName,
                  surname: childPerson.surname,
                  email: childPerson.email,
                  relationship: 'child',
                  gender: childPerson.gender,
                });
                await user.save();
              }
              // Add to spouse's User.relatives if child is a user
              const childUser = await User.findOne({ person: child._id });
              if (childUser) {
                const alreadyParent = (childUser.relatives || []).some(r => r.email === email && r.relationship === 'parent');
                if (!alreadyParent) {
                  childUser.relatives.push({
                    name: firstName,
                    surname: surname,
                    email: email,
                    relationship: 'parent',
                    gender: gender,
                  });
                  await childUser.save();
                }
              }
            }
          }
          // If relationship is child/parent, link accordingly
          if (invitation.relationship === 'child' || invitation.relationship === 'father' || invitation.relationship === 'mother' || invitation.relationship === 'parent') {
            // Add inviter as parent to invitee's Person
            if (!person.parents.some(x => x.equals(inviterUser.person._id))) {
              person.parents.push(inviterUser.person._id);
              await person.save();
            }
            // Add invitee as child to inviter's Person
            const inviterPerson = await Person.findById(inviterUser.person._id);
            if (!inviterPerson.children.some(x => x.equals(person._id))) {
              inviterPerson.children.push(person._id);
              await inviterPerson.save();
            }
            // --- NEW: If inviter has a spouse, add spouse as parent to registering user ---
            if (inviterPerson.spouses && inviterPerson.spouses.length > 0) {
              for (const spouseId of inviterPerson.spouses) {
                if (!person.parents.some(x => x.equals(spouseId))) {
                  person.parents.push(spouseId);
                  await person.save();
                }
                const spousePerson = await Person.findById(spouseId);
                if (!spousePerson.children.some(x => x.equals(person._id))) {
                  spousePerson.children.push(person._id);
                  await spousePerson.save();
                }
                // Add to User.relatives for both
                const spouseUser = await User.findOne({ person: spouseId });
                if (spouseUser) {
                  const already = (spouseUser.relatives || []).some(r => r.email === email && r.relationship === 'child');
                  if (!already) {
                    spouseUser.relatives.push({
                      name: firstName,
                      surname: surname,
                      email: email,
                      relationship: 'child',
                      gender: gender,
                    });
                    await spouseUser.save();
                  }
                  const already2 = (user.relatives || []).some(r => r.email === spouseUser.email && r.relationship === 'parent');
                  if (!already2) {
                    user.relatives.push({
                      name: spouseUser.firstName,
                      surname: spouseUser.surname,
                      email: spouseUser.email,
                      relationship: 'parent',
                      gender: spouseUser.gender,
                    });
                    await user.save();
                  }
                }
              }
            }
            // Add to User.relatives for both
            const already = (user.relatives || []).some(r => r.email === inviterUser.email && r.relationship === getInverseRelationship(invitation.relationship));
            if (!already) {
              user.relatives.push({
                name: inviterUser.firstName,
                surname: inviterUser.surname,
                email: inviterUser.email,
                relationship: getInverseRelationship(invitation.relationship),
                gender: inviterUser.gender,
              });
              await user.save();
            }
            const already2 = (inviterUser.relatives || []).some(r => r.email === email && r.relationship === invitation.relationship);
            if (!already2) {
              inviterUser.relatives.push({
                name: firstName,
                surname: surname,
                email: email,
                relationship: invitation.relationship,
                gender: gender,
              });
              await inviterUser.save();
            }
          }
          // If relationship is parent (registering user is parent of inviter)
          if (invitation.relationship === 'parent' || invitation.relationship === 'father' || invitation.relationship === 'mother') {
            // Add registering user as parent to inviter's Person
            const inviterPerson = await Person.findById(inviterUser.person._id);
            if (!inviterPerson.parents.some(x => x.equals(person._id))) {
              inviterPerson.parents.push(person._id);
              await inviterPerson.save();
            }
            // Add inviter as child to registering user's Person
            if (!person.children.some(x => x.equals(inviterUser.person._id))) {
              person.children.push(inviterUser.person._id);
              await person.save();
            }
            // --- NEW: If inviter has a spouse, add registering user as parent to spouse's Person ---
            if (inviterPerson.spouses && inviterPerson.spouses.length > 0) {
              for (const spouseId of inviterPerson.spouses) {
                const spousePerson = await Person.findById(spouseId);
                if (!spousePerson.parents.some(x => x.equals(person._id))) {
                  spousePerson.parents.push(person._id);
                  await spousePerson.save();
                }
                if (!person.children.some(x => x.equals(spouseId))) {
                  person.children.push(spouseId);
                  await person.save();
                }
                // Add to User.relatives for both
                const spouseUser = await User.findOne({ person: spouseId });
                if (spouseUser) {
                  const already = (spouseUser.relatives || []).some(r => r.email === email && r.relationship === 'parent');
                  if (!already) {
                    spouseUser.relatives.push({
                      name: firstName,
                      surname: surname,
                      email: email,
                      relationship: 'parent',
                      gender: gender,
                    });
                    await spouseUser.save();
                  }
                  const already2 = (user.relatives || []).some(r => r.email === spouseUser.email && r.relationship === 'child');
                  if (!already2) {
                    user.relatives.push({
                      name: spouseUser.firstName,
                      surname: spouseUser.surname,
                      email: spouseUser.email,
                      relationship: 'child',
                      gender: spouseUser.gender,
                    });
                    await user.save();
                  }
                }
              }
            }
          }
        }
      }
    }

    // After creating/saving the person and user, resolve pending relationships
    // Find all Person docs with pendingRelationships for this email
    const pendingFromOthers = await Person.find({ 'pendingRelationships.email': email });
    for (const other of pendingFromOthers) {
      // For each pending relationship
      const pendings = (other.pendingRelationships || []).filter(pr => pr.email === email);
      for (const pending of pendings) {
        switch (pending.type) {
          case 'spouse':
            // Add each other as spouses
            if (!other.spouses.some(x => x.equals(person._id))) {
              other.spouses.push(person._id);
            }
            if (!person.spouses.some(x => x.equals(other._id))) {
              person.spouses.push(other._id);
            }
            break;
          case 'child':
            // Add as child to other, and other as parent to person
            if (!other.children.some(x => x.equals(person._id))) {
              other.children.push(person._id);
            }
            if (!person.parents.some(x => x.equals(other._id))) {
              person.parents.push(other._id);
            }
            // If other has a spouse, add as parent to person and add person as child to spouse
            if (other.spouses && other.spouses.length > 0) {
              for (const spouseId of other.spouses) {
                const spouse = await Person.findById(spouseId);
                if (spouse) {
                  if (!person.parents.some(x => x.equals(spouse._id))) {
                    person.parents.push(spouse._id);
                  }
                  if (!spouse.children.some(x => x.equals(person._id))) {
                    spouse.children.push(person._id);
                    await spouse.save();
                  }
                }
              }
            }
            break;
          case 'parent':
            // Add as parent to other, and other as child to person
            if (!person.children.some(x => x.equals(other._id))) {
              person.children.push(other._id);
            }
            if (!other.parents.some(x => x.equals(person._id))) {
              other.parents.push(person._id);
            }
            // If other has a spouse, add as child to person and add person as parent to spouse
            if (other.spouses && other.spouses.length > 0) {
              for (const spouseId of other.spouses) {
                const spouse = await Person.findById(spouseId);
                if (spouse) {
                  if (!person.children.some(x => x.equals(spouse._id))) {
                    person.children.push(spouse._id);
                  }
                  if (!spouse.parents.some(x => x.equals(person._id))) {
                    spouse.parents.push(person._id);
                    await spouse.save();
                  }
                }
              }
            }
            break;
          case 'sibling':
            // Add each other as siblings
            if (!other.siblings.some(x => x.equals(person._id))) {
              other.siblings.push(person._id);
            }
            if (!person.siblings.some(x => x.equals(other._id))) {
              person.siblings.push(other._id);
            }
            break;
        }
      }
      // Remove resolved pending relationships
      other.pendingRelationships = (other.pendingRelationships || []).filter(pr => pr.email !== email);
      await other.save();
    }
    await person.save();

    const token = jwt.sign({ id: user._id.toString() }, JWT_SECRET, { expiresIn: '1h' });
    const inviteLink = `http://localhost:3000/register?invite=${token}`;
    await sendInvitationEmail(email, `${firstName} ${surname}`, relationship, inviteLink);
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

    const user = await User.findById(req.user.id).populate('person');
    if (!user) return sendResponse(res, 404, 'User not found.');
    const userPerson = await Person.findById(user.person);
    if (!userPerson) return sendResponse(res, 404, 'User person not found.');

    // 1. Find or create/update the Person for the relative
    let relativePerson = null;
    const validGenders = ['male', 'female', 'other'];
    let personData = { firstName: name, surname, maidenName, email, dob };
    if (validGenders.includes(gender)) personData.gender = gender;
    if (email) {
      relativePerson = await Person.findOne({ email });
      if (relativePerson) {
        let changed = false;
        if (relativePerson.firstName !== name) { relativePerson.firstName = name; changed = true; }
        if (relativePerson.surname !== surname) { relativePerson.surname = surname; changed = true; }
        if (relativePerson.maidenName !== maidenName) { relativePerson.maidenName = maidenName; changed = true; }
        if (validGenders.includes(gender) && relativePerson.gender !== gender) { relativePerson.gender = gender; changed = true; }
        if (dob && (!relativePerson.dob || String(relativePerson.dob) !== String(new Date(dob)))) { relativePerson.dob = dob; changed = true; }
        if (changed) await relativePerson.save();
      }
    }
    if (!relativePerson && email) {
      // Add pending relationship to userPerson
      userPerson.pendingRelationships = userPerson.pendingRelationships || [];
      userPerson.pendingRelationships.push({
        type: relationship.toLowerCase(),
        email: email
      });
      await userPerson.save();
    }
    if (!relativePerson) {
      relativePerson = new Person(personData);
      await relativePerson.save();
    }

    // 2. Update both Person documents for the relationship
    const addUnique = (arr, id) => arr.some(x => x.equals(id)) ? arr : [...arr, id];
    const relType = relationship.toLowerCase();
    // User -> Relative
    switch (relType) {
      case 'father':
      case 'mother':
      case 'parent':
        userPerson.parents = addUnique(userPerson.parents, relativePerson._id);
        break;
      case 'child': {
        // Add child to user
        userPerson.children = addUnique(userPerson.children, relativePerson._id);
        // If parentName is specified, find the spouse by name and add child to their children array, and add both parents to child's parents array
        let spouse = null;
        if (parentName) {
          // Try to find spouse by full name (case-insensitive)
          spouse = await Person.findOne({ $or: [
            { $expr: { $eq: [ { $concat: ["$firstName", " ", "$surname"] }, parentName ] } },
            { $expr: { $eq: [ { $concat: ["$surname", " ", "$firstName"] }, parentName ] } }
          ] });
          if (!spouse) {
            // Try to find by email if parentName is an email
            spouse = await Person.findOne({ email: parentName });
          }
        } else if (userPerson.spouses && userPerson.spouses.length > 0) {
          spouse = await Person.findById(userPerson.spouses[0]);
        }
        if (spouse) {
          // Add child to spouse
          spouse.children = addUnique(spouse.children, relativePerson._id);
          await spouse.save();
          // Add both parents to child's parents array
          relativePerson.parents = addUnique(relativePerson.parents, spouse._id);
          relativePerson.parents = addUnique(relativePerson.parents, userPerson._id);
          // Ensure user and spouse are spouses of each other
          userPerson.spouses = addUnique(userPerson.spouses, spouse._id);
          spouse.spouses = addUnique(spouse.spouses, userPerson._id);
          await userPerson.save();
          await spouse.save();
        } else {
          // No spouse found, just add user as parent
          relativePerson.parents = addUnique(relativePerson.parents, userPerson._id);
          await userPerson.save();
        }
        // Update siblings for all children of these parents
        const allParentIds = spouse ? [userPerson._id, spouse._id] : [userPerson._id];
        let allChildren = new Set();
        for (const parentId of allParentIds) {
          const parent = await Person.findById(parentId);
          if (parent && parent.children) {
            parent.children.forEach(cid => allChildren.add(cid.toString()));
          }
        }
        allChildren = Array.from(allChildren);
        for (const cid of allChildren) {
          const child = await Person.findById(cid);
          if (child) {
            child.siblings = Array.from(new Set([...allChildren.filter(id => id !== cid), ...(child.siblings || []).map(x => x.toString())])).map(id => mongoose.Types.ObjectId(id));
            await child.save();
          }
        }
        break;
      }
      case 'spouse':
        userPerson.spouses = addUnique(userPerson.spouses, relativePerson._id);
        break;
      case 'sibling':
        userPerson.siblings = addUnique(userPerson.siblings, relativePerson._id);
        break;
      // Add more as needed
    }
    await userPerson.save();
    // Relative -> User (inverse)
    switch (relType) {
      case 'father':
      case 'mother':
      case 'parent':
        relativePerson.children = addUnique(relativePerson.children, userPerson._id);
        break;
      case 'child':
        relativePerson.parents = addUnique(relativePerson.parents, userPerson._id);
        break;
      case 'spouse':
        relativePerson.spouses = addUnique(relativePerson.spouses, userPerson._id);
        break;
      case 'sibling':
        relativePerson.siblings = addUnique(relativePerson.siblings, userPerson._id);
        break;
      // Add more as needed
    }
    await relativePerson.save();

    // 3. Update User.relatives for both users (if both are users)
    const relativeUser = email ? await User.findOne({ email }) : null;
    // Helper to get relationship label for user -> relative
    const getRelLabel = () => {
      if (relType === 'child') {
        if (userPerson.gender === 'male') return 'father';
        if (userPerson.gender === 'female') return 'mother';
        return 'parent';
      }
      return relType;
    };
    // Helper to get inverse label for relative -> user
    const getInverseLabel = () => {
      if (relType === 'father' || relType === 'mother' || relType === 'parent') return 'child';
      if (relType === 'child') {
        if (relativePerson.gender === 'male') return 'son';
        if (relativePerson.gender === 'female') return 'daughter';
        return 'child';
      }
      return relType;
    };
    // Add to user's relatives
    const alreadyInUser = (user.relatives || []).some(r => r.email === email && r.relationship === relType);
    if (!alreadyInUser) {
      user.relatives.push({ name, surname, maidenName, email, relationship: relType, gender, dob, parentName });
      await user.save();
    }
    // Add to relative's relatives if they are a user
    if (relativeUser) {
      const alreadyInRel = (relativeUser.relatives || []).some(r => r.email === user.email && r.relationship === getRelLabel());
      if (!alreadyInRel) {
        relativeUser.relatives.push({
          name: user.firstName,
          surname: user.surname,
          email: user.email,
          relationship: getRelLabel(),
          gender: user.gender,
        });
        await relativeUser.save();
      }
    }

    // 4. Send invitation email if the relative is not already a user and email is provided
    if (email && !relativeUser) {
      const token = crypto.randomBytes(24).toString('hex');
      const invitation = new Invitation({ inviter: user._id, inviteeEmail: email, relationship, token, status: 'pending' });
      await invitation.save();
      const inviteLink = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/register?invite=${token}`;
      await sendInvitationEmail(email, `${user.firstName} ${user.surname}`, relationship, inviteLink);
    }

    sendResponse(res, 201, 'Relative added and synced successfully!', { relative: { name, surname, maidenName, email, relationship, gender, dob, parentName } });
  } catch (error) {
    console.error('Error adding relative:', error.message);
    sendResponse(res, 500, 'Internal server error');
  }
});

// Edit Relative Endpoint
app.post('/api/edit-relative', authenticate, async (req, res) => {
  try {
    const { index, ...updatedRelative } = req.body;
    const user = await User.findById(req.user.id).populate('person');
    if (!user) {
      return sendResponse(res, 404, 'User not found.');
    }
    if (index === undefined || !user.relatives[index]) {
      return sendResponse(res, 400, 'Invalid relative index.');
    }
    const oldRelative = user.relatives[index];
    // Update user.relatives
    user.relatives[index] = { ...user.relatives[index], ...updatedRelative };
    await user.save();

    // --- Sync Person relationships ---
    const userPerson = await Person.findById(user.person);
    if (userPerson) {
      // Remove old relationship
      let oldRelativePerson = null;
      if (oldRelative.email) {
        oldRelativePerson = await Person.findOne({ email: oldRelative.email });
      }
      if (oldRelativePerson) {
        // Remove from user's Person
        const removeRel = (arr, id) => arr.filter(x => !x.equals(id));
        switch (oldRelative.relationship) {
          case 'father':
          case 'mother':
          case 'parent':
            userPerson.parents = removeRel(userPerson.parents, oldRelativePerson._id);
            break;
          case 'child':
            userPerson.children = removeRel(userPerson.children, oldRelativePerson._id);
            break;
          case 'spouse':
            userPerson.spouses = removeRel(userPerson.spouses, oldRelativePerson._id);
            break;
          case 'sibling':
            userPerson.siblings = removeRel(userPerson.siblings, oldRelativePerson._id);
            break;
        }
        await userPerson.save();
        // Remove inverse from relative's Person
        switch (oldRelative.relationship) {
          case 'father':
          case 'mother':
          case 'parent':
            oldRelativePerson.children = removeRel(oldRelativePerson.children, userPerson._id);
            break;
          case 'child':
            oldRelativePerson.parents = removeRel(oldRelativePerson.parents, userPerson._id);
            break;
          case 'spouse':
            oldRelativePerson.spouses = removeRel(oldRelativePerson.spouses, userPerson._id);
            break;
          case 'sibling':
            oldRelativePerson.siblings = removeRel(oldRelativePerson.siblings, userPerson._id);
            break;
        }
        await oldRelativePerson.save();
      }
      // Add new relationship
      let newRelativePerson = null;
      if (updatedRelative.email) {
        newRelativePerson = await Person.findOne({ email: updatedRelative.email });
        if (newRelativePerson) {
          // Update info if changed
          let changed = false;
          if (newRelativePerson.firstName !== updatedRelative.name) { newRelativePerson.firstName = updatedRelative.name; changed = true; }
          if (newRelativePerson.surname !== updatedRelative.surname) { newRelativePerson.surname = updatedRelative.surname; changed = true; }
          if (newRelativePerson.maidenName !== updatedRelative.maidenName) { newRelativePerson.maidenName = updatedRelative.maidenName; changed = true; }
          if (newRelativePerson.gender !== updatedRelative.gender) { newRelativePerson.gender = updatedRelative.gender; changed = true; }
          if (updatedRelative.dob && (!newRelativePerson.dob || String(newRelativePerson.dob) !== String(new Date(updatedRelative.dob)))) { newRelativePerson.dob = updatedRelative.dob; changed = true; }
          if (changed) await newRelativePerson.save();
        }
      }
      if (!newRelativePerson) {
        newRelativePerson = new Person({
          firstName: updatedRelative.name,
          surname: updatedRelative.surname,
          maidenName: updatedRelative.maidenName,
          email: updatedRelative.email,
          gender: updatedRelative.gender,
          dob: updatedRelative.dob,
        });
        await newRelativePerson.save();
      }
      const hasRel = (arr, id) => arr.some(x => x.equals(id));
      // Add to user's Person
      switch (updatedRelative.relationship) {
        case 'father':
        case 'mother':
        case 'parent':
          if (!hasRel(userPerson.parents, newRelativePerson._id)) {
            userPerson.parents.push(newRelativePerson._id);
          }
          break;
        case 'child':
          if (!hasRel(userPerson.children, newRelativePerson._id)) {
            userPerson.children.push(newRelativePerson._id);
          }
          break;
        case 'spouse':
          if (!hasRel(userPerson.spouses, newRelativePerson._id)) {
            userPerson.spouses.push(newRelativePerson._id);
          }
          break;
        case 'sibling':
          if (!hasRel(userPerson.siblings, newRelativePerson._id)) {
            userPerson.siblings.push(newRelativePerson._id);
          }
          break;
      }
      await userPerson.save();
      // Add inverse to relative's Person
      switch (updatedRelative.relationship) {
        case 'father':
        case 'mother':
        case 'parent':
          if (!hasRel(newRelativePerson.children, userPerson._id)) {
            newRelativePerson.children.push(userPerson._id);
          }
          break;
        case 'child':
          if (!hasRel(newRelativePerson.parents, userPerson._id)) {
            newRelativePerson.parents.push(userPerson._id);
          }
          break;
        case 'spouse':
          if (!hasRel(newRelativePerson.spouses, userPerson._id)) {
            newRelativePerson.spouses.push(userPerson._id);
          }
          break;
        case 'sibling':
          if (!hasRel(newRelativePerson.siblings, userPerson._id)) {
            newRelativePerson.siblings.push(userPerson._id);
          }
          break;
      }
      await newRelativePerson.save();
    }
    sendResponse(res, 200, 'Relative updated and synced successfully.', { relative: user.relatives[index] });
  } catch (error) {
    console.error('Error editing relative:', error);
    sendResponse(res, 500, 'Internal server error', { error: error.message });
  }
});

// Delete Relative Endpoint
app.delete('/api/delete-relative', authenticate, async (req, res) => {
  try {
    const { index } = req.body;
    const user = await User.findById(req.user.id).populate('person');
    if (!user) {
      return sendResponse(res, 404, 'User not found.');
    }
    if (index === undefined || !user.relatives[index]) {
      return sendResponse(res, 400, 'Invalid relative index.');
    }
    const oldRelative = user.relatives[index];
    // Remove from user.relatives
    user.relatives.splice(index, 1);
    await user.save();
    // --- Sync Person relationships ---
    const userPerson = await Person.findById(user.person);
    if (userPerson) {
      let oldRelativePerson = null;
      if (oldRelative.email) {
        oldRelativePerson = await Person.findOne({ email: oldRelative.email });
      }
      if (oldRelativePerson) {
        // Remove from user's Person
        switch (oldRelative.relationship) {
          case 'father':
          case 'mother':
          case 'parent':
            userPerson.parents = userPerson.parents.filter(id => !id.equals(oldRelativePerson._id));
            break;
          case 'child':
            userPerson.children = userPerson.children.filter(id => !id.equals(oldRelativePerson._id));
            break;
          case 'spouse':
            userPerson.spouses = userPerson.spouses.filter(id => !id.equals(oldRelativePerson._id));
            break;
          case 'sibling':
            userPerson.siblings = userPerson.siblings.filter(id => !id.equals(oldRelativePerson._id));
            break;
        }
        await userPerson.save();
        // Remove inverse from relative's Person
        switch (oldRelative.relationship) {
          case 'father':
          case 'mother':
          case 'parent':
            oldRelativePerson.children = oldRelativePerson.children.filter(id => !id.equals(userPerson._id));
            break;
          case 'child':
            oldRelativePerson.parents = oldRelativePerson.parents.filter(id => !id.equals(userPerson._id));
            break;
          case 'spouse':
            oldRelativePerson.spouses = oldRelativePerson.spouses.filter(id => !id.equals(userPerson._id));
            break;
          case 'sibling':
            oldRelativePerson.siblings = oldRelativePerson.siblings.filter(id => !id.equals(userPerson._id));
            break;
        }
        await oldRelativePerson.save();
      }
    }
    sendResponse(res, 200, 'Relative deleted and synced successfully.');
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

// --- Chess Game Backend Integration ---
const { Chess } = require('chess.js');
const games = {};

// REST endpoint to create a new chess game room
app.post('/create-room', (req, res) => {
  const roomId = Math.random().toString(36).substr(2, 9);
  games[roomId] = {
    chess: new Chess(),
    players: [],
    turn: 'w',
    status: 'waiting',
  };
  res.json({ roomId });
});

// Attach socket.io chess logic
if (typeof io !== 'undefined') {
  io.on('connection', (socket) => {
    socket.on('joinRoom', ({ roomId }) => {
      const game = games[roomId];
      if (!game) {
        socket.emit('error', 'Room does not exist');
        return;
      }
      if (game.players.length >= 2) {
        socket.emit('error', 'Room is full');
        return;
      }
      game.players.push(socket.id);
      socket.join(roomId);
      socket.emit('joined', { color: game.players.length === 1 ? 'w' : 'b' });
      if (game.players.length === 2) {
        game.status = 'playing';
        io.to(roomId).emit('startGame', { fen: game.chess.fen() });
      }
    });

    socket.on('move', ({ roomId, from, to, promotion }) => {
      const game = games[roomId];
      if (!game || game.status !== 'playing') return;
      const move = { from, to };
      if (promotion) move.promotion = promotion;
      const result = game.chess.move(move);
      if (result) {
        io.to(roomId).emit('move', { from, to, promotion, fen: game.chess.fen(), turn: game.chess.turn() });
        if (game.chess.isGameOver()) {
          io.to(roomId).emit('gameOver', { result: getGameResult(game.chess) });
          game.status = 'finished';
        }
      }
    });

    socket.on('disconnecting', () => {
      for (const roomId of socket.rooms) {
        if (games[roomId]) {
          games[roomId].players = games[roomId].players.filter(id => id !== socket.id);
          if (games[roomId].players.length === 0) {
            delete games[roomId];
          } else {
            io.to(roomId).emit('opponentLeft');
          }
        }
      }
    });
  });
}

function getGameResult(chess) {
  if (chess.in_checkmate()) {
    return chess.turn() === 'w' ? 'Black wins by checkmate' : 'White wins by checkmate';
  } else if (chess.in_stalemate()) {
    return 'Draw by stalemate';
  } else if (chess.in_draw()) {
    return 'Draw';
  } else if (chess.in_threefold_repetition()) {
    return 'Draw by repetition';
  } else if (chess.insufficient_material()) {
    return 'Draw by insufficient material';
  }
  return 'Game over';
}

// --- Scrabble Socket.io Logic ---
const BOARD_SIZE = 15;
const RACK_SIZE = 7;
const MAX_PLAYERS = 4;
const MIN_PLAYERS = 2;

const LETTER_VALUES = {
  A: 1, B: 3, C: 3, D: 2, E: 1, F: 4, G: 2, H: 4, I: 1, J: 8, K: 5, L: 1, M: 3, N: 1, O: 1, P: 3, Q: 10, R: 1, S: 1, T: 1, U: 1, V: 4, W: 4, X: 8, Y: 4, Z: 10, BLANK: 0
};

// Helper: get all words formed by the placements
function getWords(board, placements) {
  // Find the main word (direction: horizontal or vertical)
  if (!placements.length) return [];
  // Assume all placements are in a line
  const isHorizontal = placements.every(p => p.row === placements[0].row);
  const isVertical = placements.every(p => p.col === placements[0].col);
  if (!isHorizontal && !isVertical) return [];
  const words = [];
  // Main word
  let mainTiles = [];
  if (isHorizontal) {
    const row = placements[0].row;
    let minCol = Math.min(...placements.map(p => p.col));
    let maxCol = Math.max(...placements.map(p => p.col));
    // Extend left
    while (minCol > 0 && board[row][minCol - 1]) minCol--;
    // Extend right
    while (maxCol < BOARD_SIZE - 1 && board[row][maxCol + 1]) maxCol++;
    for (let c = minCol; c <= maxCol; c++) {
      mainTiles.push({ row, col: c, letter: board[row][c] });
    }
    words.push({
      word: mainTiles.map(t => t.letter).join(''),
      tiles: mainTiles,
      direction: 'horizontal',
    });
    // Check for perpendicular words at each placed tile
    for (const p of placements) {
      let tiles = [{ row: p.row, col: p.col, letter: board[p.row][p.col] }];
      // Extend up
      let r = p.row - 1;
      while (r >= 0 && board[r][p.col]) { tiles.unshift({ row: r, col: p.col, letter: board[r][p.col] }); r--; }
      // Extend down
      r = p.row + 1;
      while (r < BOARD_SIZE && board[r][p.col]) { tiles.push({ row: r, col: p.col, letter: board[r][p.col] }); r++; }
      if (tiles.length > 1) {
        words.push({ word: tiles.map(t => t.letter).join(''), tiles, direction: 'vertical' });
      }
    }
  } else if (isVertical) {
    const col = placements[0].col;
    let minRow = Math.min(...placements.map(p => p.row));
    let maxRow = Math.max(...placements.map(p => p.row));
    // Extend up
    while (minRow > 0 && board[minRow - 1][col]) minRow--;
    // Extend down
    while (maxRow < BOARD_SIZE - 1 && board[maxRow + 1][col]) maxRow++;
    for (let r = minRow; r <= maxRow; r++) {
      mainTiles.push({ row: r, col: col, letter: board[r][col] });
    }
    words.push({
      word: mainTiles.map(t => t.letter).join(''),
      tiles: mainTiles,
      direction: 'vertical',
    });
    // Check for perpendicular words at each placed tile
    for (const p of placements) {
      let tiles = [{ row: p.row, col: p.col, letter: board[p.row][p.col] }];
      // Extend left
      let c = p.col - 1;
      while (c >= 0 && board[p.row][c]) { tiles.unshift({ row: p.row, col: c, letter: board[p.row][c] }); c--; }
      // Extend right
      c = p.col + 1;
      while (c < BOARD_SIZE && board[p.row][c]) { tiles.push({ row: p.row, col: c, letter: board[p.row][c] }); c++; }
      if (tiles.length > 1) {
        words.push({ word: tiles.map(t => t.letter).join(''), tiles, direction: 'horizontal' });
      }
    }
  }
  // Remove duplicates (main word may be found as a perpendicular word)
  const unique = [];
  for (const w of words) {
    if (!unique.some(u => u.word === w.word && u.tiles.length === w.tiles.length && u.tiles.every((t, i) => t.row === w.tiles[i].row && t.col === w.tiles[i].col))) {
      unique.push(w);
    }
  }
  return unique;
}

// Helper: score a word (no multipliers for now)
function scoreWord(wordObj, placements) {
  // Optionally, you can add board multipliers here
  let score = 0;
  for (const t of wordObj.tiles) {
    score += LETTER_VALUES[t.letter] || 0;
  }
  return score;
}

io.on('connection', (socket) => {
  // Join Scrabble room
  socket.on('joinScrabbleRoom', ({ roomId, playerId }) => {
    socket.join(roomId);
    const game = scrabbleGames[roomId];
    if (game) {
      io.to(roomId).emit('lobbyUpdate', { players: game.players });
    }
  });

  // Start game
  socket.on('startScrabbleGame', ({ roomId }) => {
    const game = scrabbleGames[roomId];
    if (!game || game.started || game.players.length < MIN_PLAYERS) return;
    // Shuffle tile bag and distribute racks
    game.tileBag = createTileBag().sort(() => Math.random() - 0.5);
    game.players.forEach(p => {
      p.rack = [];
      p.score = 0;
      for (let i = 0; i < RACK_SIZE; i++) {
        p.rack.push(game.tileBag.pop());
      }
    });
    game.started = true;
    game.turn = 0;
    game.chat = [];
    game.passes = 0; // Track consecutive passes
    io.to(roomId).emit('gameStarted', {
      board: game.board,
      players: game.players.map(p => ({ id: p.id, name: p.name, score: p.score })),
      racks: game.players.map(p => p.rack),
      turn: game.turn,
    });
  });

  // Play move
  socket.on('playScrabbleMove', ({ roomId, playerId, placements }) => {
    const game = scrabbleGames[roomId];
    if (!game || !game.started) return;
    const playerIdx = game.players.findIndex(p => p.id === playerId);
    if (playerIdx !== game.turn) return; // Not this player's turn
    // placements: [{row, col, letter}]
    // Basic validation: all placements are on empty squares and from player's rack
    let valid = true;
    const rackCopy = [...game.players[playerIdx].rack];
    for (const { row, col, letter } of placements) {
      if (game.board[row][col]) valid = false;
      const rackIdx = rackCopy.indexOf(letter);
      if (rackIdx === -1) valid = false;
      else rackCopy.splice(rackIdx, 1);
    }
    if (!valid) return;
    // Place tiles
    for (const { row, col, letter } of placements) {
      game.board[row][col] = letter;
      const rackIdx = game.players[playerIdx].rack.indexOf(letter);
      if (rackIdx !== -1) game.players[playerIdx].rack.splice(rackIdx, 1);
    }
    // Word validation and scoring
    const words = getWords(game.board, placements);
    if (!words.length || !words.every(w => WORD_SET.has(w.word))) {
      // Undo placements
      for (const { row, col } of placements) game.board[row][col] = null;
      // Restore rack
      for (const { letter } of placements) game.players[playerIdx].rack.push(letter);
      socket.emit('status', 'Invalid word!');
      return;
    }
    let points = 0;
    let wordEvents = [];
    for (const w of words) {
      const wordScore = scoreWord(w, placements);
      points += wordScore;
      wordEvents.push({
        word: w.word,
        tiles: w.tiles,
        score: wordScore,
        player: game.players[playerIdx].name,
      });
    }
    // Bingo bonus
    if (placements.length === 7) points += 50;
    game.players[playerIdx].score = (game.players[playerIdx].score || 0) + points;
    // Draw new tiles
    while (game.players[playerIdx].rack.length < RACK_SIZE && game.tileBag.length > 0) {
      game.players[playerIdx].rack.push(game.tileBag.pop());
    }
    // Emit wordPlayed for each word
    for (const evt of wordEvents) {
      io.to(roomId).emit('wordPlayed', evt);
    }
    // Advance turn
    game.turn = (game.turn + 1) % game.players.length;
    // End game if tile bag empty and any player rack is empty
    if (game.tileBag.length === 0 && game.players.some(p => p.rack.length === 0)) {
      endScrabbleGame(roomId);
      return;
    }
    // Reset passes on successful move
    game.passes = 0;
    io.to(roomId).emit('gameState', {
      board: game.board,
      players: game.players.map(p => ({ id: p.id, name: p.name, score: p.score })),
      racks: game.players.map(p => p.rack),
      turn: game.turn,
    });
  });

  // Pass turn
  socket.on('passScrabbleTurn', ({ roomId, playerId }) => {
    const game = scrabbleGames[roomId];
    if (!game || !game.started) return;
    const playerIdx = game.players.findIndex(p => p.id === playerId);
    if (playerIdx !== game.turn) return;
    game.passes = (game.passes || 0) + 1;
    // Advance turn
    game.turn = (game.turn + 1) % game.players.length;
    // End game if 6 consecutive passes
    if (game.passes >= 6) {
      endScrabbleGame(roomId);
      return;
    }
    io.to(roomId).emit('gameState', {
      board: game.board,
      players: game.players.map(p => ({ id: p.id, name: p.name, score: p.score })),
      racks: game.players.map(p => p.rack),
      turn: game.turn,
    });
  });

  // Exchange tiles
  socket.on('exchangeScrabbleTiles', ({ roomId, playerId, tiles }) => {
    const game = scrabbleGames[roomId];
    if (!game || !game.started) return;
    const playerIdx = game.players.findIndex(p => p.id === playerId);
    if (playerIdx !== game.turn) return;
    if (game.tileBag.length < tiles.length) return; // Not enough tiles to exchange
    // Remove tiles from rack
    for (const letter of tiles) {
      const idx = game.players[playerIdx].rack.indexOf(letter);
      if (idx !== -1) game.players[playerIdx].rack.splice(idx, 1);
    }
    // Put exchanged tiles back in bag and shuffle
    game.tileBag.push(...tiles);
    game.tileBag = _.shuffle(game.tileBag);
    // Draw new tiles
    while (game.players[playerIdx].rack.length < RACK_SIZE && game.tileBag.length > 0) {
      game.players[playerIdx].rack.push(game.tileBag.pop());
    }
    game.passes = (game.passes || 0) + 1;
    // Advance turn
    game.turn = (game.turn + 1) % game.players.length;
    // End game if 6 consecutive passes
    if (game.passes >= 6) {
      endScrabbleGame(roomId);
      return;
    }
    io.to(roomId).emit('gameState', {
      board: game.board,
      players: game.players.map(p => ({ id: p.id, name: p.name, score: p.score })),
      racks: game.players.map(p => p.rack),
      turn: game.turn,
    });
  });

  // End-game detection after a move
  function endScrabbleGame(roomId) {
    const game = scrabbleGames[roomId];
    if (!game) return;
    // Final scoring: subtract remaining rack tiles from each player
    game.players.forEach(p => {
      const penalty = (p.rack || []).reduce((sum, l) => sum + (LETTER_VALUES[l] || 0), 0);
      p.score -= penalty;
    });
    // Find winner(s)
    const maxScore = Math.max(...game.players.map(p => p.score));
    const winners = game.players.filter(p => p.score === maxScore).map(p => p.name);
    io.to(roomId).emit('gameOver', {
      players: game.players.map(p => ({ id: p.id, name: p.name, score: p.score })),
      winners,
    });
    game.started = false;
  }

  // Chat
  socket.on('scrabbleChat', ({ roomId, playerId, message }) => {
    const game = scrabbleGames[roomId];
    if (!game) return;
    const player = game.players.find(p => p.id === playerId);
    const chatMsg = { name: player ? player.name : 'Player', message };
    game.chat = game.chat || [];
    game.chat.push(chatMsg);
    io.to(roomId).emit('scrabbleChat', chatMsg);
  });
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
app.use('/api/scrabble', scrabbleRoutes);

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