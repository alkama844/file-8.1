const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
const http = require('http');
const socketIo = require('socket.io');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Trust proxy for deployment
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'nafij-social-share-2024-super-secure-jwt-secret-key-with-256-bits-entropy-for-maximum-security-and-protection-against-attacks';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'pronafij';

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  trustProxy: true
});
app.use('/api/', limiter);

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());
app.use(express.static('public'));

// Create uploads directory
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

app.use('/uploads', (req, res, next) => {
  res.header('Cross-Origin-Resource-Policy', 'cross-origin');
  next();
}, express.static('uploads'));

// MongoDB connection
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// User Schema (Enhanced from fullstack-chat-app)
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  fullName: {
    type: String,
    required: true,
    trim: true,
    minlength: 2,
    maxlength: 50
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  profilePic: {
    type: String,
    default: ''
  },
  bio: {
    type: String,
    maxlength: 200,
    default: ''
  },
  isPremium: {
    type: Boolean,
    default: false
  },
  isOnline: {
    type: Boolean,
    default: false
  },
  lastSeen: {
    type: Date,
    default: Date.now
  }
}, { timestamps: true });

// Auto-set premium status based on email first letter
userSchema.pre('save', function(next) {
  if (this.isNew && this.email) {
    const firstLetter = this.email.charAt(0).toLowerCase();
    const premiumLetters = ['n', 'm', 'x', 'p', 'a', 'o', 'b'];
    this.isPremium = premiumLetters.includes(firstLetter);
  }
  next();
});

const User = mongoose.model('User', userSchema);

// Message Schema (From fullstack-chat-app)
const messageSchema = new mongoose.Schema({
  senderId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  receiverId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  text: {
    type: String,
    trim: true
  },
  image: {
    type: String
  }
}, { timestamps: true });

const Message = mongoose.model('Message', messageSchema);

// Post Schema (Your existing posts)
const postSchema = new mongoose.Schema({
  user: {
    type: String,
    required: true,
    maxlength: 20
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  text: {
    type: String,
    maxlength: 2000
  },
  media: [{
    filename: String,
    originalName: String,
    mimetype: String,
    size: Number,
    url: String
  }],
  likes: {
    type: Number,
    default: 0
  },
  likedBy: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  reactions: {
    love: { type: Number, default: 0 },
    laugh: { type: Number, default: 0 },
    like: { type: Number, default: 0 },
    wow: { type: Number, default: 0 },
    sad: { type: Number, default: 0 },
    angry: { type: Number, default: 0 },
    total: { type: Number, default: 0 }
  },
  comments: [{
    _id: { type: mongoose.Schema.Types.ObjectId, auto: true },
    user: String,
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    text: String,
    likes: { type: Number, default: 0 },
    likedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    createdAt: { type: Date, default: Date.now },
    replies: [{
      _id: { type: mongoose.Schema.Types.ObjectId, auto: true },
      user: String,
      userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      text: String,
      likes: { type: Number, default: 0 },
      likedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
      createdAt: { type: Date, default: Date.now }
    }]
  }],
  hashtags: [String]
}, { timestamps: true });

const Post = mongoose.model('Post', postSchema);

// Multer configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 50 * 1024 * 1024,
    files: 10
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|webp|mp4|webm|avi|mov|mp3|wav|ogg|pdf|doc|docx|txt|zip|rar/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = file.mimetype.startsWith('image/') || 
                    file.mimetype.startsWith('video/') || 
                    file.mimetype.startsWith('audio/') ||
                    ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'text/plain', 'application/zip', 'application/x-rar-compressed'].includes(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Invalid file type'));
    }
  }
});

// JWT token generation (From fullstack-chat-app)
const generateToken = (userId, res) => {
  const token = jwt.sign({ userId }, JWT_SECRET, {
    expiresIn: '7d'
  });

  res.cookie('jwt', token, {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV !== 'development'
  });

  return token;
};

// Authentication middleware
const protectRoute = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;

    if (!token) {
      return res.status(401).json({ message: 'Unauthorized - No Token Provided' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    if (!decoded) {
      return res.status(401).json({ message: 'Unauthorized - Invalid Token' });
    }

    const user = await User.findById(decoded.userId).select('-password');

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    req.user = user;
    next();
  } catch (error) {
    console.log('Error in protectRoute middleware: ', error.message);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// Optional auth middleware for posts
const optionalAuth = async (req, res, next) => {
  const token = req.cookies.jwt;

  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await User.findById(decoded.userId).select('-password');
      if (user) {
        req.user = user;
      }
    } catch (error) {
      // Token invalid, continue without user
    }
  }
  next();
};

// Socket.IO connection handling (Enhanced from fullstack-chat-app)
const userSocketMap = {};

function getReceiverSocketId(userId) {
  return userSocketMap[userId];
}

io.on('connection', (socket) => {
  console.log('A user connected', socket.id);

  const userId = socket.handshake.query.userId;
  if (userId && userId !== 'undefined') {
    userSocketMap[userId] = socket.id;
    
    // Update user online status
    User.findByIdAndUpdate(userId, { 
      isOnline: true,
      lastSeen: new Date()
    }).catch(console.error);
  }

  // Emit online users
  io.emit('getOnlineUsers', Object.keys(userSocketMap));

  // WebRTC signaling for calls
  socket.on('webrtc-offer', (data) => {
    const { targetUserId, offer } = data;
    const targetSocketId = userSocketMap[targetUserId];
    
    if (targetSocketId) {
      io.to(targetSocketId).emit('webrtc-offer', {
        offer,
        senderId: userId
      });
    }
  });
  
  socket.on('webrtc-answer', (data) => {
    const { targetUserId, answer } = data;
    const targetSocketId = userSocketMap[targetUserId];
    
    if (targetSocketId) {
      io.to(targetSocketId).emit('webrtc-answer', {
        answer,
        senderId: userId
      });
    }
  });
  
  socket.on('webrtc-ice-candidate', (data) => {
    const { targetUserId, candidate } = data;
    const targetSocketId = userSocketMap[targetUserId];
    
    if (targetSocketId) {
      io.to(targetSocketId).emit('webrtc-ice-candidate', {
        candidate,
        senderId: userId
      });
    }
  });

  // Call functionality
  socket.on('initiateCall', (data) => {
    const { targetUserId, callType } = data;
    const targetSocketId = userSocketMap[targetUserId];
    
    if (targetSocketId) {
      io.to(targetSocketId).emit('incomingCall', {
        callerId: userId,
        callerName: socket.username,
        callType
      });
    }
  });

  socket.on('callResponse', (data) => {
    const { callerId, accepted } = data;
    const callerSocketId = userSocketMap[callerId];
    
    if (callerSocketId) {
      io.to(callerSocketId).emit('callResponse', {
        accepted,
        responderId: userId,
        responderName: socket.username
      });
    }
  });

  socket.on('callEnded', (data) => {
    const { targetUserId } = data;
    const targetSocketId = userSocketMap[targetUserId];
    
    if (targetSocketId) {
      io.to(targetSocketId).emit('callEnded', {
        endedBy: userId
      });
    }
  });

  socket.on('disconnect', () => {
    console.log('A user disconnected', socket.id);
    
    if (userId && userId !== 'undefined') {
      delete userSocketMap[userId];
      
      // Update user offline status
      User.findByIdAndUpdate(userId, { 
        isOnline: false,
        lastSeen: new Date()
      }).catch(console.error);
    }
    
    io.emit('getOnlineUsers', Object.keys(userSocketMap));
  });
});

// Auth Routes (From fullstack-chat-app)
app.post('/api/auth/signup', [
  body('fullName').isLength({ min: 2, max: 50 }).trim(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 })
], async (req, res) => {
  const { fullName, email, password } = req.body;
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }

    const user = await User.findOne({ email });

    if (user) return res.status(400).json({ message: 'Email already exists' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({
      fullName,
      email,
      password: hashedPassword,
    });

    if (newUser) {
      generateToken(newUser._id, res);
      await newUser.save();

      res.status(201).json({
        _id: newUser._id,
        fullName: newUser.fullName,
        email: newUser.email,
        profilePic: newUser.profilePic,
        isPremium: newUser.isPremium
      });
    } else {
      res.status(400).json({ message: 'Invalid user data' });
    }
  } catch (error) {
    console.log('Error in signup controller', error.message);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    generateToken(user._id, res);

    res.status(200).json({
      _id: user._id,
      fullName: user.fullName,
      email: user.email,
      profilePic: user.profilePic,
      isPremium: user.isPremium
    });
  } catch (error) {
    console.log('Error in login controller', error.message);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  try {
    res.cookie('jwt', '', { maxAge: 0 });
    res.status(200).json({ message: 'Logged out successfully' });
  } catch (error) {
    console.log('Error in logout controller', error.message);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.put('/api/auth/update-profile', protectRoute, upload.single('profilePic'), async (req, res) => {
  try {
    const { profilePic } = req.body;
    const userId = req.user._id;

    let imageUrl = req.user.profilePic;
    
    if (req.file) {
      imageUrl = `/uploads/${req.file.filename}`;
    } else if (profilePic && profilePic.startsWith('data:')) {
      // Handle base64 image
      const base64Data = profilePic.replace(/^data:image\/\w+;base64,/, '');
      const buffer = Buffer.from(base64Data, 'base64');
      const filename = `profile-${userId}-${Date.now()}.jpg`;
      const filepath = path.join(uploadsDir, filename);
      
      fs.writeFileSync(filepath, buffer);
      imageUrl = `/uploads/${filename}`;
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { profilePic: imageUrl },
      { new: true }
    ).select('-password');

    res.status(200).json(updatedUser);
  } catch (error) {
    console.log('error in update profile:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/auth/check', protectRoute, (req, res) => {
  try {
    res.status(200).json(req.user);
  } catch (error) {
    console.log('Error in checkAuth controller', error.message);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// Message Routes (From fullstack-chat-app)
app.get('/api/messages/users', protectRoute, async (req, res) => {
  try {
    const loggedInUserId = req.user._id;
    const filteredUsers = await User.find({ _id: { $ne: loggedInUserId } })
      .select('-password')
      .sort({ isOnline: -1, lastSeen: -1 });

    res.status(200).json(filteredUsers);
  } catch (error) {
    console.error('Error in getUsersForSidebar: ', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/messages/:id', protectRoute, async (req, res) => {
  try {
    const { id: userToChatId } = req.params;
    const myId = req.user._id;

    const messages = await Message.find({
      $or: [
        { senderId: myId, receiverId: userToChatId },
        { senderId: userToChatId, receiverId: myId },
      ],
    }).populate('senderId', 'fullName profilePic')
      .populate('receiverId', 'fullName profilePic');

    res.status(200).json(messages);
  } catch (error) {
    console.log('Error in getMessages controller: ', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/messages/send/:id', protectRoute, upload.single('image'), async (req, res) => {
  try {
    const { text, image } = req.body;
    const { id: receiverId } = req.params;
    const senderId = req.user._id;

    let imageUrl;
    if (req.file) {
      imageUrl = `/uploads/${req.file.filename}`;
    } else if (image && image.startsWith('data:')) {
      // Handle base64 image
      const base64Data = image.replace(/^data:image\/\w+;base64,/, '');
      const buffer = Buffer.from(base64Data, 'base64');
      const filename = `message-${Date.now()}.jpg`;
      const filepath = path.join(uploadsDir, filename);
      
      fs.writeFileSync(filepath, buffer);
      imageUrl = `/uploads/${filename}`;
    }

    const newMessage = new Message({
      senderId,
      receiverId,
      text,
      image: imageUrl,
    });

    await newMessage.save();
    await newMessage.populate('senderId', 'fullName profilePic');
    await newMessage.populate('receiverId', 'fullName profilePic');

    const receiverSocketId = getReceiverSocketId(receiverId);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('newMessage', newMessage);
    }

    res.status(201).json(newMessage);
  } catch (error) {
    console.log('Error in sendMessage controller: ', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Post Routes (Your existing functionality)
app.post('/api/posts', protectRoute, upload.array('files', 10), async (req, res) => {
  try {
    const { text } = req.body;
    
    const uploadedFiles = [];
    if (req.files && req.files.length > 0) {
      uploadedFiles.push(...req.files);
    }
    
    if (!text && uploadedFiles.length === 0) {
      return res.status(400).json({ error: 'Post must contain text or media' });
    }

    const hashtags = text ? text.match(/#\w+/g) || [] : [];

    const media = uploadedFiles.map(file => ({
      filename: file.filename,
      originalName: file.originalname,
      mimetype: file.mimetype,
      size: file.size,
      url: `/uploads/${file.filename}`
    }));

    const post = new Post({
      user: req.user.fullName,
      userId: req.user._id,
      text: text || '',
      media,
      hashtags: hashtags.map(tag => tag.toLowerCase())
    });

    await post.save();
    await post.populate('userId', 'fullName email isPremium profilePic');

    io.emit('newPost', post);

    res.status(201).json(post);
  } catch (error) {
    console.error('Create post error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/posts', optionalAuth, async (req, res) => {
  try {
    const { page = 0, limit = 10, userId, since, topLiked } = req.query;
    
    let query = {};
    if (userId) {
      query.userId = userId;
    }
    
    if (since) {
      query.createdAt = { $gt: new Date(since) };
    }

    let posts;
    
    if (topLiked === 'true') {
      // Get top 10 liked posts for welcome screen
      posts = await Post.find(query)
        .populate('userId', 'fullName email isPremium profilePic')
        .populate('comments.userId', 'fullName isPremium profilePic')
        .populate('comments.replies.userId', 'fullName isPremium profilePic')
        .sort({ likes: -1 })
        .limit(10);
    } else {
      posts = await Post.find(query)
        .populate('userId', 'fullName email isPremium profilePic')
        .populate('comments.userId', 'fullName isPremium profilePic')
        .populate('comments.replies.userId', 'fullName isPremium profilePic')
        .sort({ createdAt: -1 })
        .limit(parseInt(limit))
        .skip(parseInt(page) * parseInt(limit));
    }

    if (req.user) {
      posts.forEach(post => {
        post.userLiked = post.likedBy.includes(req.user._id);
        post.comments.forEach(comment => {
          comment.userLiked = comment.likedBy.includes(req.user._id);
          comment.replies.forEach(reply => {
            reply.userLiked = reply.likedBy.includes(req.user._id);
          });
        });
      });
    }

    res.json(posts);
  } catch (error) {
    console.error('Get posts error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/posts/:id/like', protectRoute, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const userLiked = post.likedBy.includes(req.user._id);
    
    if (userLiked) {
      post.likedBy.pull(req.user._id);
      post.likes = Math.max(0, post.likes - 1);
    } else {
      post.likedBy.push(req.user._id);
      post.likes += 1;
    }

    await post.save();

    io.emit('postLiked', {
      postId: post._id,
      likes: post.likes,
      userId: req.user._id,
      liked: !userLiked
    });

    res.json({ likes: post.likes, liked: !userLiked });
  } catch (error) {
    console.error('Like post error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/posts/:id', protectRoute, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    if (post.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Not authorized to delete this post' });
    }

    // Delete associated files
    if (post.media && post.media.length > 0) {
      post.media.forEach(file => {
        const filePath = path.join(__dirname, file.url);
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
        }
      });
    }

    await Post.findByIdAndDelete(req.params.id);

    io.emit('postDeleted', { postId: req.params.id });

    res.json({ message: 'Post deleted successfully' });
  } catch (error) {
    console.error('Delete post error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Search functionality
app.get('/api/search', optionalAuth, async (req, res) => {
  try {
    const { q, type = 'all', page = 0, limit = 10 } = req.query;
    
    if (!q || q.trim().length < 2) {
      return res.json({ users: [], posts: [] });
    }

    const searchQuery = q.trim();
    const skip = parseInt(page) * parseInt(limit);
    const limitNum = parseInt(limit);

    let users = [];
    let posts = [];

    if (type === 'users' || type === 'all') {
      let userQuery = {
        $or: [
          { fullName: { $regex: searchQuery, $options: 'i' } },
          { email: { $regex: searchQuery, $options: 'i' } }
        ]
      };
      
      if (req.user) {
        userQuery._id = { $ne: req.user._id };
      }
      
      users = await User.find(userQuery)
        .select('_id fullName email isPremium profilePic bio isOnline lastSeen')
        .limit(limitNum)
        .skip(skip)
        .sort({ isPremium: -1, fullName: 1 });
    }

    if (type === 'posts' || type === 'all') {
      posts = await Post.find({
        $or: [
          { text: { $regex: searchQuery, $options: 'i' } },
          { hashtags: { $in: [new RegExp(searchQuery, 'i')] } }
        ]
      })
        .populate('userId', 'fullName isPremium profilePic')
        .limit(limitNum)
        .skip(skip)
        .sort({ createdAt: -1 });
    }

    res.json({ users, posts });
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin routes
let registrationEnabled = true;

app.get('/api/auth/registration-status', (req, res) => {
  res.json({ enabled: registrationEnabled });
});

app.post('/api/admin/toggle-registration', async (req, res) => {
  try {
    const { password } = req.body;
    
    if (password !== ADMIN_PASSWORD) {
      return res.status(401).json({ error: 'Invalid admin password' });
    }
    
    registrationEnabled = !registrationEnabled;
    res.json({ enabled: registrationEnabled });
  } catch (error) {
    console.error('Toggle registration error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/posts', async (req, res) => {
  try {
    const { password } = req.body;
    
    if (password !== ADMIN_PASSWORD) {
      return res.status(401).json({ error: 'Invalid admin password' });
    }
    
    const posts = await Post.find()
      .populate('userId', 'fullName email isPremium profilePic')
      .sort({ createdAt: -1 });
    
    res.json(posts);
  } catch (error) {
    console.error('Get admin posts error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/admin/posts/:id', async (req, res) => {
  try {
    const { password } = req.body;
    
    if (password !== ADMIN_PASSWORD) {
      return res.status(401).json({ error: 'Invalid admin password' });
    }
    
    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    // Delete associated files
    if (post.media && post.media.length > 0) {
      post.media.forEach(file => {
        const filePath = path.join(__dirname, file.url);
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
        }
      });
    }

    await Post.findByIdAndDelete(req.params.id);
    res.json({ message: 'Post deleted successfully' });
  } catch (error) {
    console.error('Delete admin post error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Error:', error);
  
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large. Maximum size is 50MB.' });
    }
    if (error.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({ error: 'Too many files. Maximum is 10 files per upload.' });
    }
  }
  
  res.status(500).json({ error: 'Something went wrong!' });
});

// Serve static files and routes
app.get('/all', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'all.html'));
});

app.get('/info', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'info.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/search', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'search.html'));
});

app.get('/profile', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

// Catch-all route for SPA
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/') || req.path.startsWith('/uploads/')) {
    return res.status(404).json({ error: 'Not found' });
  }
  
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = { app, server, io };