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
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB error:", err));

// ✅ Message Schema & Model
const MessageSchema = new mongoose.Schema({
  text: { type: String, required: true },
  email: { type: String, required: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const Message = mongoose.model("Message", MessageSchema);

// User schema for authentication
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String },
  passwordHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", UserSchema);

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';

const crypto = require('crypto');

// Encryption key: prefer ENCRYPTION_KEY (base64 or raw), otherwise derive from JWT_SECRET (dev only)
function getEncKey() {
  const envKey = process.env.ENCRYPTION_KEY;
  if (envKey) {
    try {
      // if base64
      const buf = Buffer.from(envKey, 'base64');
      if (buf.length === 32) return buf;
    } catch (e) {
      // fall through
    }
    // fallback: use raw string hashed to 32 bytes
    return crypto.createHash('sha256').update(envKey).digest();
  }
  // dev fallback - derive from JWT_SECRET
  return crypto.createHash('sha256').update(JWT_SECRET).digest();
}

const ENC_ALGO = 'aes-256-gcm';

function encryptText(plain) {
  const key = getEncKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ENC_ALGO, key, iv);
  const encrypted = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { cipher: encrypted.toString('base64'), iv: iv.toString('base64'), tag: tag.toString('base64') };
}

function decryptText(encrypted) {
  // defensive: if no data, return null
  if (!encrypted) return null;

  // if it's already a plain string, return as-is
  if (typeof encrypted === 'string') return encrypted;

  // attempt to locate expected fields (support slight variations)
  const c = encrypted.cipher || encrypted.c || encrypted.encrypted || encrypted.cipherText;
  const iv = encrypted.iv || encrypted.ivBase64 || encrypted.nonce;
  const tag = encrypted.tag || encrypted.authTag;

  if (!c || !iv || !tag) {
    console.warn('Decryption skipped: missing cipher/iv/tag fields');
    return null;
  }

  try {
    const key = getEncKey();
    const decipher = crypto.createDecipheriv(ENC_ALGO, key, Buffer.from(iv, 'base64'));
    decipher.setAuthTag(Buffer.from(tag, 'base64'));
    const out = Buffer.concat([decipher.update(Buffer.from(c, 'base64')), decipher.final()]);
    return out.toString('utf8');
  } catch (err) {
    console.error('Decryption failed', err.message);
    return null;
  }
}

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
    const { username, email, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });
    const existing = await User.findOne({ username });
    if (existing) return res.status(409).json({ error: 'Username already taken' });
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    const user = new User({ username, email, passwordHash: hash });
    await user.save();
    const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user: { id: user._id, username: user.username, email: user.email } });
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
  const encryptedPassword = encryptText(password);
  const newMsg = new Message({ text, email, password: encryptedPassword });
    await newMsg.save();
    res.status(201).json(newMsg);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ✅ GET route (Fetch all messages)
app.get("/messages", authMiddleware, async (req, res) => {
  try {
    const msgs = await Message.find().sort({ createdAt: -1 });
    const decryptedMsgs = msgs.map(msg => ({
      ...msg.toObject(),
      password: decryptText(msg.password)
    }));
    res.json(decryptedMsgs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET single message decrypted (useful if stored password wasn't decrypted earlier)
app.get('/messages/:id/decrypt', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const msg = await Message.findById(id);
    if (!msg) return res.status(404).json({ error: 'Not found' });
    let plaintext = null;
    if (msg.password) {
      if (typeof msg.password === 'string') plaintext = msg.password;
      else plaintext = decryptText(msg.password);
    }
    res.json({ password: plaintext });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ DELETE route (remove by ID)
app.delete("/messages/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    await Message.findByIdAndDelete(id);
    res.json({ message: "Deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Migration helper (manual) - encrypt existing plaintext passwords
app.post('/migrate-encrypt', authMiddleware, async (req, res) => {
  try {
    const all = await Message.find();
    let updated = 0;
    for (const m of all) {
      if (m.password && typeof m.password === 'string') {
        const enc = encryptText(m.password);
        m.password = enc;
        await m.save();
        updated++;
      }
    }
    res.json({ migrated: updated });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});



app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
