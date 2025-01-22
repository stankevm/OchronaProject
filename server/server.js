const express = require("express");
const app = express();
const cors = require("cors");
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const prisma = new PrismaClient();
const corsOptions = {
    origin: ["http://localhost:5173"],
}

app.use(cors(corsOptions));
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId; // Add userId to request object
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Add validation helpers at the top
const validateEmail = (email) => {
  if (!email || typeof email !== 'string') return 'Email is required';
  if (email.length > 255) return 'Email is too long';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return 'Invalid email format';
  return null;
};

const validateUsername = (username) => {
  if (!username || typeof username !== 'string') return 'Username is required';
  if (username.length < 3) return 'Username must be at least 3 characters';
  if (username.length > 30) return 'Username must be less than 30 characters';
  if (!/^[a-zA-Z0-9_-]+$/.test(username)) return 'Username can only contain letters, numbers, underscores, and hyphens';
  return null;
};

const validatePassword = (password) => {
  if (!password || typeof password !== 'string') return 'Password is required';
  if (password.length < 6) return 'Password must be at least 6 characters';
  if (password.length > 100) return 'Password is too long';
  if (!/\d/.test(password)) return 'Password must contain at least one number';
  if (!/[a-z]/.test(password)) return 'Password must contain at least one lowercase letter';
  if (!/[A-Z]/.test(password)) return 'Password must contain at least one uppercase letter';
  return null;
};

const validateTweetContent = (content) => {
  if (!content || typeof content !== 'string') return 'Tweet content is required';
  if (content.trim() === '') return 'Tweet cannot be empty';
  if (content.length > 280) return 'Tweet must be less than 280 characters';
  // Check for potentially harmful content
  if (/<[^>]*>/.test(content)) return 'HTML tags are not allowed';
  return null;
};

// Get all tweets with author information
app.get("/api/tweets", authenticateToken, async (req, res) => {
    try {
        const tweets = await prisma.tweet.findMany({
            include: {
                author: {
                    select: {
                        username: true,
                        id: true,
                    },
                },
            },
            orderBy: {
                id: 'desc',
            },
        });
        res.json(tweets);
    } catch (error) {
        console.error('Error fetching tweets:', error);
        res.status(500).json({ error: 'Failed to fetch tweets' });
    }
});

// Create a new tweet
app.post("/api/tweets", authenticateToken, async (req, res) => {
    const { content } = req.body;
    
    const contentError = validateTweetContent(content);
    if (contentError) {
        return res.status(400).json({ error: contentError });
    }

    try {
        const newTweet = await prisma.tweet.create({
            data: {
                content: content.trim(), // Sanitize by trimming
                authorId: req.userId,
            },
            include: {
                author: {
                    select: {
                        username: true,
                    },
                },
            },
        });
        res.status(201).json(newTweet);
    } catch (error) {
        console.error('Error creating tweet:', error);
        res.status(500).json({ error: 'Failed to create tweet' });
    }
});

// Create a new user with secure password hashing
app.post("/api/users", async (req, res) => {
    const { email, username, password } = req.body;

    // Validate all fields
    const emailError = validateEmail(email);
    if (emailError) return res.status(400).json({ error: emailError });

    const usernameError = validateUsername(username);
    if (usernameError) return res.status(400).json({ error: usernameError });

    const passwordError = validatePassword(password);
    if (passwordError) return res.status(400).json({ error: passwordError });

    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = await prisma.user.create({
            data: {
                email: email.toLowerCase().trim(),
                username: username.trim(),
                password: hashedPassword,
            },
            select: {
                id: true,
                username: true,
                email: true,
            },
        });

        // Generate token after successful signup
        const token = jwt.sign({ userId: newUser.id }, JWT_SECRET, { expiresIn: '1h' });
        
        // Return both user data and token
        res.status(201).json({ user: newUser, token });
    } catch (error) {
        if (error.code === 'P2002') {
            res.status(400).json({ error: 'Username or email already exists' });
        } else {
            console.error('Error creating user:', error);
            res.status(500).json({ error: 'Failed to create user' });
        }
    }
});

// Fix login endpoint as well
app.post("/api/login", async (req, res) => {
    const { email, password } = req.body;

    const emailError = validateEmail(email);
    if (emailError) return res.status(400).json({ error: emailError });

    if (!password || typeof password !== 'string') {
        return res.status(400).json({ error: 'Password is required' });
    }

    try {
        const user = await prisma.user.findUnique({
            where: { email: email.toLowerCase().trim() }, // Normalize email
        });

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Compare the password directly with bcrypt
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });

        // Send user data without password
        const { password: _, ...userData } = user;
        res.json({ user: userData, token });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Get user by id
app.get("/api/users/:id", authenticateToken, async (req, res) => {
    const { id } = req.params;
    
    try {
        const user = await prisma.user.findUnique({
            where: {
                id: parseInt(id),
            },
            select: {
                id: true,
                username: true,
                email: true,
                tweets: true,
            },
        });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(user);
    } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({ error: 'Failed to fetch user' });
    }
});

app.listen(8080, () => {
    console.log("Server started on port 8080");
});

// Cleanup Prisma connection on server shutdown
process.on('beforeExit', async () => {
    await prisma.$disconnect();
});