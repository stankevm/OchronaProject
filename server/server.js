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
    
    if (!content || content.trim() === '') {
        return res.status(400).json({ error: 'Tweet content is required' });
    }

    try {
        const newTweet = await prisma.tweet.create({
            data: {
                content,
                authorId: req.userId, // Use the userId from the token
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

    if (!email || !username || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        const salt = await bcrypt.genSalt(10);
        // Hash the password with the generated salt
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = await prisma.user.create({
            data: {
                email,
                username,
                password: hashedPassword,
            },
            select: {
                id: true,
                username: true,
                email: true,
            },
        });
        res.status(201).json(newUser);
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

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        const user = await prisma.user.findUnique({
            where: { email },
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