const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const db = require('../config/db');
const { signToken } = require('../config/jwt');

const privateKey = fs.readFileSync(
  path.join(__dirname, '../../storage/rsa/private.pem'),
  'utf8'
);

// Register
exports.register = async (req, res) => {
  const { name, email, password } = req.body;

  const hash = await bcrypt.hash(password, 10);

  await db.query(
    'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
    [name, email, hash]
  );

  res.status(201).json({ message: 'User registered successfully' });
};

// Login (RSA encrypted)
exports.login = async (req, res) => {
  const { email, password } = req.body;

  let decryptedPassword;

  try {
    decryptedPassword = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PADDING,
      },
      Buffer.from(password, 'base64')
    ).toString();
  } catch {
    return res.status(400).json({ message: 'Password decryption failed' });
  }

  const [rows] = await db.query(
    'SELECT * FROM users WHERE email = ?',
    [email]
  );

  if (!rows.length) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const user = rows[0];
  const valid = await bcrypt.compare(decryptedPassword, user.password);

  if (!valid) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

const token = signToken(user);

  res.json({
    user: { id: user.id, name: user.name, email: user.email },
    access_token: token,
    token_type: 'Bearer',
  });
};

// Profile
exports.profile = async (req, res) => {
  res.json(req.user);
};

// Logout
exports.logout = async (req, res) => {
  res.json({ message: 'Logout handled on client side' });
};