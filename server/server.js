const express = require("express");
const app = express();
const cors = require("cors");
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');

const prisma = new PrismaClient();
const corsOptions = {
    origin: ["http://localhost:5173"],
}

app.use(cors(corsOptions));
app.use(express.json());

// Get all tweets with author information
app.get("/api/tweets", async (req, res) => {
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
app.post("/api/tweets", async (req, res) => {
    const { content, userId } = req.body;
    
    if (!content || content.trim() === '') {
        return res.status(400).json({ error: 'Tweet content is required' });
    }

    try {
        const newTweet = await prisma.tweet.create({
            data: {
                content,
                authorId: userId || 1, // For now, default to user 1 if no userId provided
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
        // Just hash once with a salt - double hashing isn't necessary
        const hashedPassword = await bcrypt.hash(password, 10);

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

        // Send user data without password
        const { password: _, ...userData } = user;
        res.json(userData);
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Get user by id
app.get("/api/users/:id", async (req, res) => {
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