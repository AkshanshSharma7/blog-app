const express = require('express');
const cors = require('cors');
const mongoose = require("mongoose");
const User = require('./models/User');
const Post = require('./models/Post');
const bcrypt = require('bcryptjs');
const app = express();
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const uploadMiddleware = multer({ dest: 'uploads/' });
const fs = require('fs');

const salt = bcrypt.genSaltSync(10);
const secret = 'asdfe45we45w345wegw345werjktjwertkj';

app.use(cors({ credentials: true, origin: 'http://localhost:3000' }));
app.use(express.json());
app.use(cookieParser());
app.use('/uploads', express.static(__dirname + '/uploads'));

// Connect to local MongoDB
mongoose.connect('mongodb://localhost:27017/blog-app')
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('Error connecting to MongoDB:', err));

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ message: 'Unauthorized: No token provided' });
  }
  jwt.verify(token, secret, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Unauthorized: Invalid token' });
    }
    req.user = decoded;
    next();
  });
};

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const userDoc = await User.create({
      username,
      password: bcrypt.hashSync(password, salt),
    });
    res.json(userDoc);
  } catch (e) {
    console.log(e);
    res.status(400).json(e);
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const userDoc = await User.findOne({ username });
  const passOk = bcrypt.compareSync(password, userDoc.password);
  if (passOk) {
    jwt.sign({ username, id: userDoc._id }, secret, {}, (err, token) => {
      if (err) throw err;
      res.cookie('token', token).json({
        id: userDoc._id,
        username,
      });
    });
  } else {
    res.status(400).json('Wrong credentials');
  }
});

// Protected route example
app.get('/profile', verifyToken, (req, res) => {
  res.json(req.user); // Access decoded user information from req.user
});

app.post('/logout', (req, res) => {
  res.cookie('token', '').json('Logout successful');
});

app.post('/post', verifyToken, uploadMiddleware.single('file'), async (req, res) => {
  const { originalname, path } = req.file;
  const parts = originalname.split('.');
  const ext = parts[parts.length - 1];
  const newPath = path + '.' + ext;
  fs.renameSync(path, newPath);

  const { id } = req.user; // Access user ID from decoded token
  try {
    const postDoc = await Post.create({
      title: req.body.title,
      summary: req.body.summary,
      content: req.body.content,
      cover: newPath,
      author: id,
    });
    res.json(postDoc);
  } catch (err) {
    console.error('Error creating post:', err);
    res.status(500).json({ message: 'Error creating post' });
  }
});

app.put('/post', verifyToken, uploadMiddleware.single('file'), async (req, res) => {
  let newPath = null;
  if (req.file) {
    const { originalname, path } = req.file;
    const parts = originalname.split('.');
    const ext = parts[parts.length - 1];
    newPath = path + '.' + ext;
    fs.renameSync(path, newPath);
  }

  const { id } = req.user; // Access user ID from decoded token
  try {
    const postDoc = await Post.findById(req.body.id);
    if (!postDoc) {
      return res.status(404).json({ message: 'Post not found' });
    }
    if (postDoc.author.toString() !== id) {
      return res.status(403).json({ message: 'Unauthorized: You are not the author' });
    }
    postDoc.title = req.body.title;
    postDoc.summary = req.body.summary;
    postDoc.content = req.body.content;
    postDoc.cover = newPath ? newPath : postDoc.cover;
    await postDoc.save();
    res.json(postDoc);
  } catch (err) {
    console.error('Error updating post:', err);
    res.status(500).json({ message: 'Error updating post' });
  }
});

app.get('/post', async (req, res) => {
  try {
    const posts = await Post.find()
      .populate('author', ['username'])
      .sort({ createdAt: -1 })
      .limit(20);
    res.json(posts);
  } catch (err) {
    console.error('Error fetching posts:', err);
    res.status(500).json({ message: 'Error fetching posts' });
  }
});

app.get('/post/:id', async (req, res) => {
  try {
    const postDoc = await Post.findById(req.params.id).populate('author', ['username']);
    if (!postDoc) {
      return res.status(404).json({ message: 'Post not found' });
    }
    res.json(postDoc);
  } catch (err) {
    console.error('Error fetching post by ID:', err);
    res.status(500).json({ message: 'Error fetching post' });
  }
});

app.listen(4000, () => {
  console.log('Server is running on port: http://localhost:4000');
});
