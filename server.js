// server.js
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';

// MySQL pool
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASS || '',
    database: process.env.DB_NAME || 'lms_db',
    waitForConnections: true,
    connectionLimit: 10
});

function createToken(user) {
    return jwt.sign({ id: user.id, name: user.name, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '1d' });
}

async function authMiddleware(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ message: 'No token' });
    const token = auth.split(' ')[1];
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        req.user = payload;
        next();
    } catch (err) {
        return res.status(401).json({ message: 'Invalid token' });
    }
}

// Register
app.post('/api/auth/register', async(req, res) => {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password || !role) return res.status(400).json({ message: 'Missing fields' });
    try {
        const [exists] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
        if (exists.length) return res.status(400).json({ message: 'Email already registered' });

        const hash = await bcrypt.hash(password, 10);
        const [result] = await pool.query('INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)', [name, email, hash, role]);
        const userId = result.insertId;
        const user = { id: userId, name, email, role };
        const token = createToken(user);
        res.json({ message: 'Registered', token, user });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// Login
app.post('/api/auth/login', async(req, res) => {
    const { email, password, role } = req.body;
    if (!email || !password || !role) return res.status(400).json({ message: 'Missing fields' });
    try {
        const [rows] = await pool.query('SELECT id, name, email, password_hash, role FROM users WHERE email = ?', [email]);
        if (!rows.length) return res.status(400).json({ message: 'User not found' });
        const user = rows[0];
        if (user.role !== role) return res.status(403).json({ message: `This account is registered as ${user.role}` });

        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) return res.status(400).json({ message: 'Invalid credentials' });

        const token = createToken({ id: user.id, name: user.name, email: user.email, role: user.role });
        res.json({ message: 'Logged in', token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get courses (public)
app.get('/api/courses', async(req, res) => {
    try {
        const [rows] = await pool.query(
            `SELECT c.id, c.title, c.description, c.duration, c.teacher_id, c.created_at, u.name as teacher_name
       FROM courses c JOIN users u ON u.id = c.teacher_id ORDER BY c.created_at DESC`
        );
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// Create course (teacher only)
app.post('/api/courses', authMiddleware, async(req, res) => {
    const user = req.user;
    if (!user) return res.status(401).json({ message: 'Unauthorized' });
    if (user.role !== 'teacher') return res.status(403).json({ message: 'Only teachers can create courses' });

    const { title, description, duration } = req.body;
    if (!title || !description) return res.status(400).json({ message: 'Missing fields' });

    try {
        const [result] = await pool.query('INSERT INTO courses (title, description, duration, teacher_id) VALUES (?, ?, ?, ?)', [title, description, duration || null, user.id]);
        const insertId = result.insertId;
        const [rows] = await pool.query('SELECT c.id, c.title, c.description, c.duration, u.name as teacher_name FROM courses c JOIN users u ON u.id = c.teacher_id WHERE c.id = ?', [insertId]);
        res.json({ message: 'Course created', course: rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// fallback to login
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
}); 

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));