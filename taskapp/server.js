require('dotenv').config();
const http = require('http');
const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { Server } = require('socket.io');

const { MONGODB_URI, JWT_SECRET } = process.env;
if (!MONGODB_URI || !JWT_SECRET) { console.error('Set MONGODB_URI and JWT_SECRET in .env'); process.exit(1); }

const app = express();
const server = http.createServer(app);
const io = new Server(server);
app.use(express.json({ limit: '50kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Models ----------
const User = mongoose.model('User', new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 80 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
}));
const Task = mongoose.model('Task', new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  title: { type: String, required: true, trim: true, maxlength: 200 },
  description: { type: String, default: '', maxlength: 2000 },
  status: { type: String, enum: ['todo', 'in-progress', 'done'], default: 'todo' },
  priority: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
  dueDate: Date,
}, { timestamps: true }));

// ---------- Auth ----------
const sign = u => jwt.sign({ id: u._id }, JWT_SECRET, { expiresIn: '7d' });
const publicUser = u => ({ id: u._id, name: u.name, email: u.email });

function auth(req, res, next) {
  const token = (req.get('authorization') || '').replace('Bearer ', '');
  try { req.userId = jwt.verify(token, JWT_SECRET).id; next(); }
  catch { res.status(401).json({ error: 'Please log in again.' }); }
}

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });

app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !/^\S+@\S+\.\S+$/.test(email || '')) return res.status(400).json({ error: 'Enter a name and a valid email.' });
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  if (await User.findOne({ email: email.toLowerCase() })) return res.status(409).json({ error: 'That email is already registered.' });
  const user = await User.create({ name, email, password: await bcrypt.hash(password, 10) });
  res.status(201).json({ token: sign(user), user: publicUser(user) });
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const user = await User.findOne({ email: String(req.body.email || '').toLowerCase() });
  if (!user || !(await bcrypt.compare(req.body.password || '', user.password)))
    return res.status(401).json({ error: 'Wrong email or password.' });
  res.json({ token: sign(user), user: publicUser(user) });
});

app.get('/api/auth/me', auth, async (req, res) => {
  const user = await User.findById(req.userId);
  user ? res.json(publicUser(user)) : res.status(401).json({ error: 'Please log in again.' });
});

// ---------- Tasks (each user only sees and edits their own) ----------
const fields = b => {
  const o = {};
  for (const k of ['title', 'description', 'status', 'priority']) if (b[k] !== undefined) o[k] = b[k];
  if (b.dueDate !== undefined) o.dueDate = b.dueDate || null;
  return o;
};
const emit = (userId, event, payload) => io.to(`user:${userId}`).emit(event, payload);

app.get('/api/tasks', auth, async (req, res) => {
  res.json(await Task.find({ owner: req.userId }).sort({ createdAt: -1 }));
});

app.post('/api/tasks', auth, async (req, res) => {
  try {
    const task = await Task.create({ ...fields(req.body), owner: req.userId });
    emit(req.userId, 'task:saved', task);
    res.status(201).json(task);
  } catch (e) { res.status(400).json({ error: 'A title is required.' }); }
});

app.put('/api/tasks/:id', auth, async (req, res) => {
  try {
    const task = await Task.findOneAndUpdate({ _id: req.params.id, owner: req.userId }, fields(req.body), { new: true, runValidators: true });
    if (!task) return res.status(404).json({ error: 'Task not found.' });
    emit(req.userId, 'task:saved', task);
    res.json(task);
  } catch (e) { res.status(400).json({ error: 'Invalid task data.' }); }
});

app.delete('/api/tasks/:id', auth, async (req, res) => {
  try {
    const task = await Task.findOneAndDelete({ _id: req.params.id, owner: req.userId });
    if (!task) return res.status(404).json({ error: 'Task not found.' });
    emit(req.userId, 'task:deleted', { _id: task._id });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: 'Invalid task id.' }); }
});

// ---------- Real-time: each logged-in user joins a private room ----------
io.use((socket, next) => {
  try { socket.userId = jwt.verify(socket.handshake.auth.token, JWT_SECRET).id; next(); }
  catch { next(new Error('unauthorized')); }
});
io.on('connection', s => s.join(`user:${s.userId}`));

mongoose.connect(MONGODB_URI).then(() => {
  const port = process.env.PORT || 3000;
  server.listen(port, () => console.log(`http://localhost:${port}`));
}).catch(e => { console.error('MongoDB connection failed:', e.message); process.exit(1); });
