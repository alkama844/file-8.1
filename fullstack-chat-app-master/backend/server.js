const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(cookieParser());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));
app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? false : ['http://localhost:3000', 'http://localhost:5173'],
  credentials: true
}));

// MongoDB Connection
const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI || process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log(`MongoDB connected: ${conn.connection.host}`);
  } catch (error) {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  }
};

// Connect to database
connectDB();

// Post Model
const postSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true,
    maxlength: 200
  },
  content: {
    type: String,
    required: true,
    trim: true,
    maxlength: 2000
  },
  likes: {
    type: Number,
    default: 0,
    min: 0
  },
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: false
  },
  authorName: {
    type: String,
    default: 'Anonymous'
  }
}, { 
  timestamps: true 
});

const Post = mongoose.model('Post', postSchema);

// Import existing auth routes and models
let authRoutes;
let messageRoutes;
let User;

try {
  authRoutes = require('./src/routes/auth.route.js');
  messageRoutes = require('./src/routes/message.route.js');
  User = require('./src/models/user.model.js');
} catch (error) {
  console.log('Auth routes not found, creating basic auth structure...');
  
  // Create basic User model if not exists
  const userSchema = new mongoose.Schema({
    fullName: {
      type: String,
      required: true,
      trim: true
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
    }
  }, { timestamps: true });

  User = mongoose.model('User', userSchema);
}

// Socket.IO setup (if exists)
let io;
try {
  const { app: socketApp, server, io: socketIO } = require('./src/lib/socket.js');
  io = socketIO;
} catch (error) {
  console.log('Socket.IO not configured, running without real-time features');
}

// Auth middleware
const protectRoute = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;
    
    if (!token) {
      return res.status(401).json({ message: 'Unauthorized - No Token Provided' });
    }

    const jwt = require('jsonwebtoken');
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

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

// Routes

// Use existing auth routes if available
if (authRoutes) {
  app.use('/api/auth', authRoutes);
}

// Use existing message routes if available
if (messageRoutes) {
  app.use('/api/messages', messageRoutes);
}

// Posts Routes

// GET /all - Return all posts sorted by newest first
app.get('/all', async (req, res) => {
  try {
    const posts = await Post.find()
      .populate('author', 'fullName email profilePic')
      .sort({ createdAt: -1 })
      .lean();

    res.json({
      success: true,
      count: posts.length,
      data: posts
    });
  } catch (error) {
    console.error('Error fetching all posts:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Server error while fetching posts' 
    });
  }
});

// GET / - Return top 10 posts sorted by likes (main page)
app.get('/', async (req, res) => {
  try {
    // Check if React build exists
    const buildPath = path.join(__dirname, '../../frontend/dist');
    const indexPath = path.join(buildPath, 'index.html');
    
    if (fs.existsSync(indexPath)) {
      return res.sendFile(indexPath);
    }

    // If no build, return top 10 posts by likes
    const posts = await Post.find()
      .populate('author', 'fullName email profilePic')
      .sort({ likes: -1, createdAt: -1 })
      .limit(10)
      .lean();

    res.json({
      success: true,
      message: 'Top 10 posts by likes',
      count: posts.length,
      data: posts
    });
  } catch (error) {
    console.error('Error fetching top posts:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Server error while fetching top posts' 
    });
  }
});

// POST /posts - Create a new post
app.post('/posts', async (req, res) => {
  try {
    const { title, content } = req.body;

    // Validation
    if (!title || !content) {
      return res.status(400).json({
        success: false,
        error: 'Title and content are required'
      });
    }

    if (title.length > 200) {
      return res.status(400).json({
        success: false,
        error: 'Title must be less than 200 characters'
      });
    }

    if (content.length > 2000) {
      return res.status(400).json({
        success: false,
        error: 'Content must be less than 2000 characters'
      });
    }

    // Create post data
    const postData = {
      title: title.trim(),
      content: content.trim(),
      likes: 0
    };

    // Add author info if user is authenticated
    if (req.user) {
      postData.author = req.user._id;
      postData.authorName = req.user.fullName;
    } else {
      postData.authorName = 'Anonymous';
    }

    const post = new Post(postData);
    await post.save();

    // Populate author info for response
    await post.populate('author', 'fullName email profilePic');

    // Emit to socket if available
    if (io) {
      io.emit('newPost', post);
    }

    res.status(201).json({
      success: true,
      message: 'Post created successfully',
      data: post
    });
  } catch (error) {
    console.error('Error creating post:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Server error while creating post' 
    });
  }
});

// POST /posts/:id/like - Increment likes on a post
app.post('/posts/:id/like', async (req, res) => {
  try {
    const { id } = req.params;

    // Validate ObjectId
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid post ID'
      });
    }

    const post = await Post.findById(id);

    if (!post) {
      return res.status(404).json({
        success: false,
        error: 'Post not found'
      });
    }

    // Increment likes
    post.likes += 1;
    await post.save();

    // Populate author info
    await post.populate('author', 'fullName email profilePic');

    // Emit to socket if available
    if (io) {
      io.emit('postLiked', { postId: id, likes: post.likes });
    }

    res.json({
      success: true,
      message: 'Post liked successfully',
      data: {
        _id: post._id,
        likes: post.likes,
        title: post.title
      }
    });
  } catch (error) {
    console.error('Error liking post:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Server error while liking post' 
    });
  }
});

// GET /posts - Get posts with pagination and sorting options
app.get('/posts', async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 10, 
      sortBy = 'createdAt', 
      order = 'desc',
      search = ''
    } = req.query;

    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    const skip = (pageNum - 1) * limitNum;

    // Build query
    let query = {};
    if (search) {
      query = {
        $or: [
          { title: { $regex: search, $options: 'i' } },
          { content: { $regex: search, $options: 'i' } }
        ]
      };
    }

    // Build sort
    const sortOrder = order === 'desc' ? -1 : 1;
    const sort = { [sortBy]: sortOrder };

    // Execute query
    const posts = await Post.find(query)
      .populate('author', 'fullName email profilePic')
      .sort(sort)
      .skip(skip)
      .limit(limitNum)
      .lean();

    // Get total count for pagination
    const total = await Post.countDocuments(query);

    res.json({
      success: true,
      data: posts,
      pagination: {
        current: pageNum,
        pages: Math.ceil(total / limitNum),
        total,
        hasNext: pageNum < Math.ceil(total / limitNum),
        hasPrev: pageNum > 1
      }
    });
  } catch (error) {
    console.error('Error fetching posts:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Server error while fetching posts' 
    });
  }
});

// DELETE /posts/:id - Delete a post (protected route)
app.delete('/posts/:id', protectRoute, async (req, res) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid post ID'
      });
    }

    const post = await Post.findById(id);

    if (!post) {
      return res.status(404).json({
        success: false,
        error: 'Post not found'
      });
    }

    // Check if user owns the post or is admin
    if (post.author && post.author.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        error: 'Not authorized to delete this post'
      });
    }

    await Post.findByIdAndDelete(id);

    // Emit to socket if available
    if (io) {
      io.emit('postDeleted', { postId: id });
    }

    res.json({
      success: true,
      message: 'Post deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting post:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Server error while deleting post' 
    });
  }
});

// Frontend Support - Serve React build if exists
const frontendBuildPath = path.join(__dirname, '../../frontend/dist');
const frontendIndexPath = path.join(frontendBuildPath, 'index.html');

if (fs.existsSync(frontendBuildPath)) {
  console.log('Frontend build found, serving static files...');
  app.use(express.static(frontendBuildPath));
  
  // Handle React Router routes
  app.get('*', (req, res) => {
    // Skip API routes
    if (req.path.startsWith('/api/') || req.path.startsWith('/posts') || req.path === '/all') {
      return res.status(404).json({ error: 'Route not found' });
    }
    
    if (fs.existsSync(frontendIndexPath)) {
      res.sendFile(frontendIndexPath);
    } else {
      res.status(404).json({ error: 'Frontend not found' });
    }
  });
} else {
  console.log('No frontend build found, API-only mode');
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Global 404 handler for API routes
app.use('/api/*', (req, res) => {
  res.status(404).json({ 
    success: false,
    error: 'API route not found' 
  });
});

// Global error handler
app.use((error, req, res, next) => {
  console.error('Global error handler:', error);
  
  // Mongoose validation error
  if (error.name === 'ValidationError') {
    const errors = Object.values(error.errors).map(err => err.message);
    return res.status(400).json({
      success: false,
      error: 'Validation Error',
      details: errors
    });
  }

  // Mongoose duplicate key error
  if (error.code === 11000) {
    return res.status(400).json({
      success: false,
      error: 'Duplicate field value entered'
    });
  }

  // JWT errors
  if (error.name === 'JsonWebTokenError') {
    return res.status(401).json({
      success: false,
      error: 'Invalid token'
    });
  }

  // Default error
  res.status(500).json({
    success: false,
    error: 'Internal server error'
  });
});

// Start server
const server = app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 MongoDB: ${process.env.MONGO_URI ? 'Connected' : 'Using default connection'}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
    mongoose.connection.close();
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
    mongoose.connection.close();
  });
});

module.exports = { app, server };