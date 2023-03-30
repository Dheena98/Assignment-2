const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors());

mongoose.connect('mongodb://localhost/assignment', { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        console.log("Connected to MongoDB database");
    }).catch((err) => {
        console.log(err);
        process.exit();
    });

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const postSchema = new mongoose.Schema({
    title: { type: String, required: true },
    body: { type: String, required: true },
    image: { type: String, required: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
});

const User = mongoose.model('User', userSchema);
const Post = mongoose.model('Post', postSchema);

// Register new user
app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    // Check if user already exists
    let user = await User.findOne({ email });
    if (user) {
        return res.status(400).json({ error: "User already exists" });
    }

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user
    user = new User({ name, email, password: hashedPassword });
    await user.save();

    res.status(200).json({ message: "User registered successfully" });
});

// Login user
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
        return res.status(400).json({ error: "Invalid credentials" });
    }

    // Check if password is correct
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
        return res.status(400).json({ error: "Invalid credentials" });
    }

    // Generate and return token
    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET);
    res.header('auth-token', token).json({ token });
});
// Middleware for verifying token and checking authorization
const authMiddleware = (req, res, next) => {
    const token = req.header('auth-token');
    if (!token) {
        return res.status(401).json({ error: "Access denied" });
    }

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).json({ error: "Invalid token" });
    }
}

// Add CRUD routes for posts
// Get all posts
app.get('/posts', async (req, res) => {
    const posts = await Post.find().populate('user', 'name email');
    res.status(200).json({ posts });
});

// Create a new post
app.post('/posts', authMiddleware, async (req, res) => {
    const { title, body, image } = req.body;
    const user = req.user._id;

    const post = new Post({ title, body, image, user });
    await post.save();

    res.status(200).json({ post });
});

// Edit a post
app.put('/posts/:postId', authMiddleware, async (req, res) => {
    const { title, body, image } = req.body;
    const postId = req.params.postId;
    const user = req.user._id;

    let post = await Post.findById(postId);
    if (!post) {
        return res.status(404).json({ error: "Post not found" });
    }

    if (post.user.toString() !== user.toString()) {
        return res.status(403).json({ error: "You are not authorized to edit this post" });
    }

    post.title = title;
    post.body = body;
    post.image = image;
    await post.save();

    res.status(200).json({ message: "Post updated successfully" });
});

// Delete a post
app.delete('/posts/:postId', authMiddleware, async (req, res) => {
    const postId = req.params.postId;
    const user = req.user._id;

    let post = await Post.findById(postId);
    if (!post) {
        return res.status(404).json({ error: "Post not found" });
    }

    if (post.user.toString() !== user.toString()) {
        return res.status(403).json({ error: "You are not authorized to delete this post" });
    }

    await post.remove();

    res.status(200).json({ message: "Post deleted successfully" });
});

// Start the server
const port = 3000;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
