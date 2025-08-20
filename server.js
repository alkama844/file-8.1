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

// Trust proxy for Render deployment
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// Generate a stronger JWT secret if using default
const STRONG_JWT_SECRET = process.env.JWT_SECRET || require('crypto').randomBytes(64).toString('hex');

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // limit each IP to 200 requests per windowMs
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

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Serve uploaded files with proper headers
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

// User Schema (Enhanced)
const userSchema = new mongoose.Schema({
  fullName: {
    type: String,
    required: true,
    trim: true,
    minlength: 2,
    maxlength: 50
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
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
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

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

// Message Schema (Enhanced)
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
  },
  messageType: {
    type: String,
    enum: ['text', 'image', 'file'],
    default: 'text'
  },
  readBy: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    readAt: { type: Date, default: Date.now }
  }],
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Message = mongoose.model('Message', messageSchema);

// Post Schema (Keep existing)
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
  hashtags: [String],
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Post = mongoose.model('Post', postSchema);

// Multer configuration for file uploads
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
    fileSize: 50 * 1024 * 1024, // 50MB limit
    files: 10 // Max 10 files per upload
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

// JWT token generation
const generateToken = (userId, res) => {
  const token = jwt.sign({ userId }, STRONG_JWT_SECRET, {
    expiresIn: '7d',
    issuer: 'nafij-social-share',
    audience: 'nafij-users'
  });

  res.cookie('jwt', token, {
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV !== 'development'
  });

  return token;
};

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  try {
    const token = req.cookies.jwt || (req.headers['authorization'] && req.headers['authorization'].split(' ')[1]);

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const decoded = jwt.verify(token, STRONG_JWT_SECRET, {
      issuer: 'nafij-social-share',
      audience: 'nafij-users'
    });
    
    const user = await User.findById(decoded.userId).select('-password');
    if (!user) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    
    // Update last seen when token is used
    await User.findByIdAndUpdate(user._id, { 
      lastSeen: new Date(),
      isOnline: true 
    });
    
    req.user = user;
    next();
  } catch (error) {
    console.error('Token verification error:', error.message);
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Optional authentication middleware
const optionalAuth = async (req, res, next) => {
  const token = req.cookies.jwt || (req.headers['authorization'] && req.headers['authorization'].split(' ')[1]);

  if (token) {
    try {
      const decoded = jwt.verify(token, STRONG_JWT_SECRET, {
        issuer: 'nafij-social-share',
        audience: 'nafij-users'
      });
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

// Socket.IO connection handling
const connectedUsers = new Map();

function getReceiverSocketId(userId) {
  return connectedUsers.get(userId.toString());
}

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  // User authentication for socket
  socket.on('authenticate', async (token) => {
    try {
      const decoded = jwt.verify(token, STRONG_JWT_SECRET, {
        issuer: 'nafij-social-share',
        audience: 'nafij-users'
      });
      const user = await User.findById(decoded.userId);
      if (user) {
        socket.userId = user._id.toString();
        socket.username = user.fullName;
        connectedUsers.set(user._id.toString(), socket.id);
        
        // Update user online status
        await User.findByIdAndUpdate(user._id, { 
          isOnline: true,
          lastSeen: new Date()
        });
        
        // Emit online users list
        io.emit('getOnlineUsers', Array.from(connectedUsers.keys()));
        
        socket.emit('authenticated', { user: user.fullName });
        
        // WebRTC signaling for calls
        socket.on('webrtc-offer', (data) => {
          const { targetUserId, offer } = data;
          const targetSocketId = connectedUsers.get(targetUserId);
          
          if (targetSocketId) {
            io.to(targetSocketId).emit('webrtc-offer', {
              offer,
              senderId: socket.userId
            });
          }
        });
        
        socket.on('webrtc-answer', (data) => {
          const { targetUserId, answer } = data;
          const targetSocketId = connectedUsers.get(targetUserId);
          
          if (targetSocketId) {
            io.to(targetSocketId).emit('webrtc-answer', {
              answer,
              senderId: socket.userId
            });
          }
        });
        
        socket.on('webrtc-ice-candidate', (data) => {
          const { targetUserId, candidate } = data;
          const targetSocketId = connectedUsers.get(targetUserId);
          
          if (targetSocketId) {
            io.to(targetSocketId).emit('webrtc-ice-candidate', {
              candidate,
              senderId: socket.userId
            });
          }
        });

        // Call functionality
        socket.on('initiateCall', (data) => {
          const { targetUserId, callType } = data;
          const targetSocketId = connectedUsers.get(targetUserId);
          
          if (targetSocketId) {
            io.to(targetSocketId).emit('incomingCall', {
              callerId: socket.userId,
              callerName: socket.username,
              callType
            });
          }
        });

        socket.on('callResponse', (data) => {
          const { callerId, accepted } = data;
          const callerSocketId = connectedUsers.get(callerId);
          
          if (callerSocketId) {
            io.to(callerSocketId).emit('callResponse', {
              accepted,
              responderId: socket.userId,
              responderName: socket.username
            });
          }
        });

        socket.on('callEnded', (data) => {
          const { targetUserId } = data;
          const targetSocketId = connectedUsers.get(targetUserId);
          
          if (targetSocketId) {
            io.to(targetSocketId).emit('callEnded', {
              endedBy: socket.userId
            });
          }
        });
        
        socket.on('callCancelled', (data) => {
          const { targetUserId } = data;
          const targetSocketId = connectedUsers.get(targetUserId);
          
          if (targetSocketId) {
            io.to(targetSocketId).emit('callCancelled', {
              cancelledBy: socket.userId
            });
          }
        });
      }
    } catch (error) {
      socket.emit('authError', { error: 'Invalid token' });
    }
  });

  // Handle disconnect
  socket.on('disconnect', async () => {
    console.log('User disconnected:', socket.id);
    
    if (socket.userId) {
      connectedUsers.delete(socket.userId);
      
      // Update user offline status
      await User.findByIdAndUpdate(socket.userId, { 
        isOnline: false,
        lastSeen: new Date()
      });

      // Emit updated online users list
      io.emit('getOnlineUsers', Array.from(connectedUsers.keys()));
    }
  });
});

// Routes

// Auth Routes
app.post('/api/auth/signup', [
  body('fullName').isLength({ min: 2, max: 50 }).trim(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
    }

    const { fullName, email, password } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already exists' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const user = new User({
      fullName,
      email,
      password: hashedPassword
    });

    await user.save();

    // Generate JWT token
    generateToken(user._id, res);

    res.status(201).json({
      _id: user._id,
      fullName: user.fullName,
      email: user.email,
      profilePic: user.profilePic,
      isPremium: user.isPremium
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/auth/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
    }

    const { email, password } = req.body;
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Update last seen and online status
    await User.findByIdAndUpdate(user._id, { 
      lastSeen: new Date(),
      isOnline: true 
    });

    // Generate JWT token
    generateToken(user._id, res);

    res.json({
      _id: user._id,
      fullName: user.fullName,
      email: user.email,
      profilePic: user.profilePic,
      isPremium: user.isPremium
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  try {
    res.cookie('jwt', '', { maxAge: 0 });
    res.status(200).json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/auth/check', authenticateToken, async (req, res) => {
  try {
    res.status(200).json(req.user);
  } catch (error) {
    console.error('Check auth error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/auth/update-profile', authenticateToken, upload.single('profilePic'), async (req, res) => {
  try {
    const { fullName, bio } = req.body;
    const updateData = {};
    
    if (fullName) updateData.fullName = fullName;
    if (bio !== undefined) updateData.bio = bio;
    
    if (req.file) {
      updateData.profilePic = `/uploads/${req.file.filename}`;
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.user._id,
      updateData,
      { new: true }
    ).select('-password');

    res.json(updatedUser);
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Message Routes
app.get('/api/messages/users', authenticateToken, async (req, res) => {
  try {
    const loggedInUserId = req.user._id;
    const users = await User.find({ _id: { $ne: loggedInUserId } })
      .select('-password')
      .sort({ isOnline: -1, lastSeen: -1 });

    res.json(users);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/messages/:id', authenticateToken, async (req, res) => {
  try {
    const { id: userToChatId } = req.params;
    const myId = req.user._id;

    const messages = await Message.find({
      $or: [
        { senderId: myId, receiverId: userToChatId },
        { senderId: userToChatId, receiverId: myId }
      ]
    })
    .populate('senderId', 'fullName profilePic')
    .populate('receiverId', 'fullName profilePic')
    .sort({ createdAt: 1 });

    res.json(messages);
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/messages/send/:id', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const { text } = req.body;
    const { id: receiverId } = req.params;
    const senderId = req.user._id;

    let imageUrl;
    if (req.file) {
      imageUrl = `/uploads/${req.file.filename}`;
    }

    const newMessage = new Message({
      senderId,
      receiverId,
      text,
      image: imageUrl,
      messageType: imageUrl ? 'image' : 'text'
    });

    await newMessage.save();
    
    // Populate sender info
    await newMessage.populate('senderId', 'fullName profilePic');
    await newMessage.populate('receiverId', 'fullName profilePic');

    const receiverSocketId = getReceiverSocketId(receiverId);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('newMessage', newMessage);
    }

    res.status(201).json(newMessage);
  } catch (error) {
    console.error('Send message error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Post Routes (Keep existing functionality)
app.post('/api/posts', upload.array('files', 10), async (req, res) => {
  try {
    const token = req.cookies.jwt || (req.headers['authorization'] && req.headers['authorization'].split(' ')[1]);
    
    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    let user;
    try {
      const decoded = jwt.verify(token, STRONG_JWT_SECRET, {
        issuer: 'nafij-social-share',
        audience: 'nafij-users'
      });
      user = await User.findById(decoded.userId);
      if (!user) {
        return res.status(401).json({ error: 'Invalid token' });
      }
    } catch (error) {
      return res.status(403).json({ error: 'Invalid token' });
    }

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
      user: user.fullName,
      userId: user._id,
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
    const { page = 0, limit = 10, userId, since } = req.query;
    
    let query = {};
    if (userId) {
      query.userId = userId;
    }
    
    if (since) {
      query.createdAt = { $gt: new Date(since) };
    }

    const posts = await Post.find(query)
      .populate('userId', 'fullName email isPremium profilePic')
      .populate('comments.userId', 'fullName isPremium profilePic')
      .populate('comments.replies.userId', 'fullName isPremium profilePic')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(parseInt(page) * parseInt(limit));

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

// Keep all other existing post routes (like, comment, delete, etc.)
app.post('/api/posts/:id/like', authenticateToken, async (req, res) => {
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

// Admin routes (keep existing)
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

// Catch-all route for SPA
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/') || req.path.startsWith('/uploads/')) {
    return res.status(404).json({ error: 'Not found' });
  }
  
  if (req.path === '/info.html' || req.path === '/search.html' || 
      req.path === '/profile.html' || req.path === '/all.html' || 
      req.path === '/admin.html') {
    return res.sendFile(path.join(__dirname, 'public', req.path));
  }
  
  if (req.path === '/info') {
    return res.sendFile(path.join(__dirname, 'public', 'info.html'));
  }
  
  if (req.path === '/admin') {
    return res.sendFile(path.join(__dirname, 'public', 'admin.html'));
  }
  
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = { app, server, io };