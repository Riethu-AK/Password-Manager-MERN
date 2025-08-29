const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");

dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Simple request logger for debugging
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
  email: { type: String, required: true },
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
    const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, username: user.username, email: user.email } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ POST route (Save message)
app.post("/messages", authMiddleware, async (req, res) => {
  try {
    const { text, email, password } = req.body;
  // attach owner from authenticated token
  const ownerId = req.user && req.user.id;
  if (!ownerId) return res.status(401).json({ error: 'Unauthorized' });
  const newMsg = new Message({ text, email, password, owner: ownerId });
    await newMsg.save();
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

// Migration helper (manual) - encrypt existing plaintext passwords
// migration endpoint removed — no-op when using plaintext storage
app.post('/migrate-encrypt', authMiddleware, async (req, res) => {
  res.json({ migrated: 0, message: 'Encryption removed, no migration necessary' });
});



app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
