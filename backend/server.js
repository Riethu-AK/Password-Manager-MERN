// ...existing code...
// Google Sign-In (optional). Only initialize if GOOGLE_CLIENT_ID is provided.
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
let googleClient = null;
if (GOOGLE_CLIENT_ID) {
  const { OAuth2Client } = require('google-auth-library');
  googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);
}
// ...existing code...
// dotenv.config() should only be called after require('dotenv')
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");
const nodemailer = require("nodemailer");

dotenv.config();
// Nodemailer transporter setup (Gmail)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS
  }
});

const app = express();
host this project 
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Serve React build folder (combined deployment) - moved to end
const path = require('path');

// Simple request logger for debugging
// Google OAuth2 login endpoint (must be after app and middleware setup)
app.post('/auth/google', async (req, res) => {
  if (!googleClient || !GOOGLE_CLIENT_ID) {
    return res.status(503).json({ error: 'Google Sign-In disabled' });
  }
  const { token } = req.body;
  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload();
    // Find or create user in DB
    let user = await User.findOne({ email: payload.email });
    if (!user) {
      user = new User({
        username: payload.email.split('@')[0],
        email: payload.email,
        passwordHash: '', // no password for Google users
        role: 'user',
        photo: payload.picture || ''
      });
      await user.save();
    }
    // Issue JWT
    const jwtToken = jwt.sign({ id: user._id, username: user.username, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token: jwtToken, user: { id: user._id, username: user.username, email: user.email, role: user.role } });
  } catch (err) {
    res.status(401).json({ error: 'Invalid Google token' });
  }
});
app.use((req, res, next) => {
  console.log(`[REQ] ${new Date().toISOString()} ${req.method} ${req.originalUrl}`);
  next();
});

// ✅ MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB error:", err));

// ✅ Message Schema & Model
const MessageSchema = new mongoose.Schema({
  text: { type: String, required: true },
  email: { type: String }, // now optional, always filled by backend
  // store password as plain string (encryption removed)
  password: { type: String, required: true },
  // owner of the message (link to User)
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now }
});

const Message = mongoose.model("Message", MessageSchema);

// User schema for authentication
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String },
  passwordHash: { type: String, required: true },
  // base64 JPEG/PNG data URL of selfie captured at signup (optional)
  photo: { type: String },
  // user role: 'user' or 'admin'
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  // track login stats
  lastLogin: { type: Date },
  loginCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", UserSchema);

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';

// encryption removed

// simple middleware to protect routes
const authMiddleware = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// middleware to check admin role
const adminMiddleware = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Auth routes
app.post('/auth/signup', async (req, res) => {
  try {
    const { username, email, password, photo } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });
    const existing = await User.findOne({ username });
    if (existing) return res.status(409).json({ error: 'Username already taken' });
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    const user = new User({ username, email, passwordHash: hash, photo });
    await user.save();
    const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user: { id: user._id, username: user.username, email: user.email } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get stored user photo (for client-side verification)
app.get('/auth/user/:username/photo', async (req, res) => {
  try {
    const { username } = req.params;
    const u = await User.findOne({ username });
    if (!u) return res.status(404).json({ error: 'Not found' });
    res.json({ photo: u.photo || null });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Simple reset-by-photo (prototype only): replace password if photo verified client-side
app.post('/auth/reset-by-photo', async (req, res) => {
  try {
    const { username, newPassword } = req.body;
    if (!username || !newPassword) return res.status(400).json({ error: 'username and newPassword required' });
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    const salt = await bcrypt.genSalt(10);
    user.passwordHash = await bcrypt.hash(newPassword, salt);
    await user.save();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    // Update login stats
    user.lastLogin = new Date();
    user.loginCount = (user.loginCount || 0) + 1;
    await user.save();

    const token = jwt.sign({ 
      id: user._id, 
      username: user.username, 
      role: user.role || 'user' 
    }, JWT_SECRET, { expiresIn: '7d' });

    res.json({ 
      token, 
      user: { 
        id: user._id, 
        username: user.username, 
        email: user.email,
        role: user.role || 'user'
      } 
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ POST route (Save message)
app.post("/messages", authMiddleware, async (req, res) => {
  try {
    const { text, password } = req.body;
    // attach owner from authenticated token
    const ownerId = req.user && req.user.id;
    if (!ownerId) return res.status(401).json({ error: 'Unauthorized' });

    // Find the user's registered email
    const user = await mongoose.model('User').findById(ownerId);
    if (!user || !user.email) return res.status(400).json({ error: 'User email not found' });

    const newMsg = new Message({ text, email: user.email, password, owner: ownerId });
    await newMsg.save();

    // Send email notification to the user's registered email
    const mailOptions = {
      from: process.env.GMAIL_USER,
      to: user.email,
      subject: 'New Password Added to Your Account',
      text: `A new password for "${text}" was added to your account in Cryptix Password Manager on ${new Date().toLocaleString()}.\n\nIf this was not you, please log in and review your saved passwords.\n\n- Cryptix Team`
    };
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Email send error:', error);
      } else {
        console.log('Email sent:', info.response);
      }
    });

    res.status(201).json(newMsg);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ✅ GET route (Fetch all messages)
app.get("/messages", authMiddleware, async (req, res) => {
  try {
  const ownerId = req.user && req.user.id;
  if (!ownerId) return res.status(401).json({ error: 'Unauthorized' });
  const msgs = await Message.find({ owner: ownerId }).sort({ createdAt: -1 });
  res.json(msgs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET single message decrypted (useful if stored password wasn't decrypted earlier)
// decrypt endpoint removed since passwords are stored plaintext
app.get('/messages/:id/decrypt', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const msg = await Message.findById(id);
    if (!msg) return res.status(404).json({ error: 'Not found' });
    res.json({ password: msg.password });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ DELETE route (remove by ID)
// Simple in-memory OTP store (for demo only)
const otpStore = {};

// Endpoint to request OTP (for demo, not secure)
app.post('/messages/:id/request-otp', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const msg = await Message.findById(id);
    if (!msg) return res.status(404).json({ error: 'Message not found' });
    // Only owner can request OTP
    if (String(msg.owner) !== String(req.user.id)) return res.status(403).json({ error: 'Forbidden' });
    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore[id] = { otp, expires: Date.now() + 15 * 60 * 1000 };
    // Send OTP via email (using nodemailer)
    const mailOptions = {
      from: process.env.GMAIL_USER,
      to: msg.email,
      subject: 'Your Cryptix OTP',
      text: `Your OTP for password change is: ${otp}`
    };
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('OTP email error:', error);
      } else {
        console.log('OTP email sent:', info.response);
      }
    });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Endpoint to verify OTP and change password
app.post('/messages/:id/change-password', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { otp, newPassword } = req.body;
    const msg = await Message.findById(id);
    if (!msg) return res.status(404).json({ error: 'Message not found' });
    if (String(msg.owner) !== String(req.user.id)) return res.status(403).json({ error: 'Forbidden' });
    // OTP verification
    if (otp) {
      const entry = otpStore[id];
      if (!entry || entry.otp !== otp || entry.expires < Date.now()) {
        return res.status(400).json({ error: 'Invalid or expired OTP' });
      }
      return res.json({ success: true });
    }
    // Password change (after OTP verified)
    if (newPassword) {
      msg.password = newPassword;
      await msg.save();
      // Remove OTP from store
      delete otpStore[id];
      return res.json({ success: true });
    }
    return res.status(400).json({ error: 'Missing otp or newPassword' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.delete("/messages/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    // ensure only owner can delete
    const ownerId = req.user && req.user.id;
    const msg = await Message.findById(id);
    if (!msg) return res.status(404).json({ error: 'Not found' });
    if (String(msg.owner) !== String(ownerId)) return res.status(403).json({ error: 'Forbidden' });
    await Message.findByIdAndDelete(id);
    res.json({ message: "Deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Migration: assign owner to messages by matching message.email to user.email
app.post('/migrate-assign-owners', authMiddleware, async (req, res) => {
  try {
    // only allow admin-like action for now: require a special JWT claim? keep simple: allow if user exists
    const users = await User.find();
    let assigned = 0;
    for (const u of users) {
      if (!u.email) continue;
      const updated = await Message.updateMany({ owner: { $exists: false }, email: u.email }, { $set: { owner: u._id } });
      assigned += (updated.modifiedCount || 0);
    }
    res.json({ assigned });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Cleanup: delete all orphaned messages (messages without owner)
app.delete('/cleanup-orphaned-messages', authMiddleware, async (req, res) => {
  try {
    const result = await Message.deleteMany({ owner: { $exists: false } });
    res.json({ 
      deleted: result.deletedCount,
      message: `Deleted ${result.deletedCount} orphaned messages`
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Debug: list all messages with owner info
app.get('/debug-messages', authMiddleware, async (req, res) => {
  try {
    const all = await Message.find({}, 'text email owner createdAt').populate('owner', 'username email');
    const orphaned = await Message.countDocuments({ owner: { $exists: false } });
    res.json({ 
      total: all.length,
      orphaned,
      messages: all.map(m => ({
        id: m._id,
        text: m.text,
        email: m.email,
        owner: m.owner ? m.owner.username : 'NO_OWNER',
        created: m.createdAt
      }))
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== ADMIN ROUTES ==========

// Admin Dashboard - Get all users and their stats
app.get('/admin/dashboard', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    // Get user stats
    const totalUsers = await User.countDocuments();
    const totalMessages = await Message.countDocuments();
    const usersWithMessages = await Message.distinct('owner');

    // Get users with their message counts
    const users = await User.aggregate([
      {
        $lookup: {
          from: 'messages',
          localField: '_id',
          foreignField: 'owner',
          as: 'messages'
        }
      },
      {
        $project: {
          username: 1,
          email: 1,
          role: 1,
          loginCount: 1,
          lastLogin: 1,
          createdAt: 1,
          messageCount: { $size: '$messages' }
        }
      },
      {
        $sort: { createdAt: -1 }
      }
    ]);

    // Get recent activity
    const recentLogins = await User.find({ lastLogin: { $exists: true } })
      .sort({ lastLogin: -1 })
      .limit(10)
      .select('username lastLogin');

    const recentMessages = await Message.find()
      .populate('owner', 'username')
      .sort({ createdAt: -1 })
      .limit(10)
      .select('text email createdAt owner');

    res.json({
      stats: {
        totalUsers,
        totalMessages,
        activeUsers: usersWithMessages.length,
        orphanedMessages: await Message.countDocuments({ owner: { $exists: false } })
      },
      users,
      recentActivity: {
        logins: recentLogins,
        messages: recentMessages
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin - Get specific user details
app.get('/admin/users/:userId', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { userId } = req.params;
    const user = await User.findById(userId).select('-passwordHash');
    if (!user) return res.status(404).json({ error: 'User not found' });

    const messages = await Message.find({ owner: userId })
      .sort({ createdAt: -1 })
      .select('text email createdAt');

    res.json({
      user,
      messages,
      messageCount: messages.length
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin - Create admin user (one-time setup)
app.post('/admin/setup', async (req, res) => {
  try {
    const { username, password, setupKey } = req.body;

    // Simple setup key check (you can change this)
    if (setupKey !== 'SETUP_ADMIN_2025') {
      return res.status(403).json({ error: 'Invalid setup key' });
    }

    // Check if admin already exists
    const existingAdmin = await User.findOne({ role: 'admin' });
    if (existingAdmin) {
      return res.status(409).json({ error: 'Admin already exists' });
    }

    const existing = await User.findOne({ username });
    if (existing) return res.status(409).json({ error: 'Username already taken' });

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    const admin = new User({ 
      username, 
      passwordHash: hash, 
      role: 'admin',
      email: 'admin@cryptix.local'
    });
    await admin.save();

    res.status(201).json({ 
      message: 'Admin user created successfully',
      admin: { username: admin.username, role: admin.role }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Migration helper (manual) - encrypt existing plaintext passwords
// migration endpoint removed — no-op when using plaintext storage
app.post('/migrate-encrypt', authMiddleware, async (req, res) => {
  res.json({ migrated: 0, message: 'Encryption removed, no migration necessary' });
});

// Serve React build folder (combined deployment)
app.use(express.static(path.join(__dirname, '../frontend/build')));

// Catch-all handler: send back React's index.html file for any non-API routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/build', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});