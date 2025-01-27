const express = require("express");
const app = express();
const cors = require("cors");
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { generateKeyPair, encryptPrivateKey, decryptPrivateKey, signData, verifySignature } = require('./utils/crypto');

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
    const { content, password } = req.body;
    
    const contentError = validateTweetContent(content);
    if (contentError) {
        return res.status(400).json({ error: contentError });
    }

    try {
        const user = await prisma.user.findUnique({
            where: { id: req.userId },
            select: {
                password: true,
                encryptedPrivateKey: true,
                publicKey: true
            }
        });

        // Verify password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid password' });
        }

        // Decrypt private key and sign content
        const privateKey = decryptPrivateKey(user.encryptedPrivateKey, password);
        const signature = signData(content, privateKey);

        // Verify signature before saving
        const verified = verifySignature(content, signature, user.publicKey);

        const newTweet = await prisma.tweet.create({
            data: {
                content: content.trim(),
                signature,
                verified,
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

        // Generate key pair
        const { publicKey, privateKey } = generateKeyPair();
        const encryptedPrivateKey = encryptPrivateKey(privateKey, password);

        const newUser = await prisma.user.create({
            data: {
                email: email.toLowerCase().trim(),
                username: username.trim(),
                password: hashedPassword,
                publicKey,
                encryptedPrivateKey
            },
            select: {
                id: true,
                username: true,
                email: true,
            },
        });

        const token = jwt.sign({ userId: newUser.id }, JWT_SECRET, { expiresIn: '1h' });
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

// Generate 2FA secret and QR code
app.post("/api/2fa/generate", authenticateToken, async (req, res) => {
    try {
        // Get user email for the QR code label
        const user = await prisma.user.findUnique({
            where: { id: req.userId },
            select: { email: true }
        });

        console.log(user.email);

        const secret = speakeasy.generateSecret({
            name: `MiniTwitter:${user.email}` // Now we have the email
        });

        // Store the secret temporarily
        await prisma.user.update({
            where: { id: req.userId },
            data: { 
                twoFactorSecret: secret.base32,
                twoFactorEnabled: false
            }
        });

        // Generate QR code
        const qrCode = await QRCode.toDataURL(secret.otpauth_url);

        res.json({
            secret: secret.base32,
            qrCode
        });
    } catch (error) {
        console.error('Error generating 2FA:', error);
        res.status(500).json({ error: 'Failed to generate 2FA' });
    }
});

// Verify and enable 2FA
app.post("/api/2fa/verify", authenticateToken, async (req, res) => {
    const { token } = req.body;

    try {
        const user = await prisma.user.findUnique({
            where: { id: req.userId }
        });

        console.log(user.twoFactorSecret);

        const verified = speakeasy.totp.verify({
            secret: user.twoFactorSecret,
            encoding: 'base32',
            token
        });

        console.log(verified);

        if (verified) {
            await prisma.user.update({
                where: { id: req.userId },
                data: { twoFactorEnabled: true }
            });
            res.json({ success: true });
        } else {
            res.status(400).json({ error: 'Invalid token' });
        }
    } catch (error) {
        console.error('Error verifying 2FA:', error);
        res.status(500).json({ error: 'Failed to verify 2FA' });
    }
});

// Add helper function for random delay
const getRandomDelay = () => {
  return Math.floor(Math.random() * 1000) + 500; // Random delay between 500-1500ms
};

// Modify login endpoint to handle attempts
app.post("/api/login", async (req, res) => {
    const { email, password, totpToken } = req.body;
    console.log('Login attempt:', { email, hasPassword: !!password, totpToken });

    const emailError = validateEmail(email);
    if (emailError) return res.status(400).json({ error: emailError });

    if (!password || typeof password !== 'string') {
        return res.status(400).json({ error: 'Password is required' });
    }

    try {
        const user = await prisma.user.findUnique({
            where: { email: email.toLowerCase().trim() }
        });

        if (!user) {
            // Add random delay even for non-existent users
            await new Promise(resolve => setTimeout(resolve, getRandomDelay()));
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check if user is locked out
        if (user.loginAttempts >= 10) {
            const lockoutTime = 15 * 60 * 1000; // 15 minutes
            if (user.lastAttempt && Date.now() - user.lastAttempt.getTime() < lockoutTime) {
                const remainingTime = Math.ceil((lockoutTime - (Date.now() - user.lastAttempt.getTime())) / 60000);
                return res.status(429).json({ 
                    error: `Too many failed attempts. Please try again in ${remainingTime} minutes.` 
                });
            } else {
                // Reset attempts after lockout period
                await prisma.user.update({
                    where: { id: user.id },
                    data: { 
                        loginAttempts: 0,
                        lastAttempt: null
                    }
                });
            }
        }

        // Add random delay before password check
        await new Promise(resolve => setTimeout(resolve, getRandomDelay()));

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            // Increment failed attempts
            await prisma.user.update({
                where: { id: user.id },
                data: { 
                    loginAttempts: {
                        increment: 1
                    },
                    lastAttempt: new Date()
                }
            });
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check 2FA if enabled
        if (user.twoFactorEnabled) {
            if (!totpToken) {
                return res.status(403).json({ 
                    requires2FA: true,
                    message: 'Please provide 2FA token' 
                });
            }

            const verified = speakeasy.totp.verify({
                secret: user.twoFactorSecret,
                encoding: 'base32',
                token: totpToken,
                window: 1
            });

            if (!verified) {
                // Increment failed attempts for invalid 2FA too
                await prisma.user.update({
                    where: { id: user.id },
                    data: { 
                        loginAttempts: {
                            increment: 1
                        },
                        lastAttempt: new Date()
                    }
                });
                return res.status(401).json({ error: 'Invalid 2FA token' });
            }
        }

        // Reset attempts on successful login
        await prisma.user.update({
            where: { id: user.id },
            data: { 
                loginAttempts: 0,
                lastAttempt: null
            }
        });

        // Generate JWT and send response
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
        const { password: _, twoFactorSecret: __, ...userData } = user;
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

// Add endpoint to verify token and return user data
app.get("/api/verify-token", authenticateToken, async (req, res) => {
    try {
        const user = await prisma.user.findUnique({
            where: { id: req.userId },
            select: {
                id: true,
                username: true,
                email: true,
                twoFactorEnabled: true
            }
        });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(user);
    } catch (error) {
        console.error('Error verifying token:', error);
        res.status(500).json({ error: 'Failed to verify token' });
    }
});

// Initiate password reset
app.post("/api/reset-password/request", async (req, res) => {
    const { email } = req.body;
    
    try {
        const user = await prisma.user.findUnique({
            where: { email: email.toLowerCase().trim() }
        });

        if (!user || !user.twoFactorEnabled) {
            // Don't reveal if user exists or has 2FA
            return res.json({ message: 'the account didnt have 2FA enabled, you will not be able to reset the password.' });
        }

        // Mark that user requested reset
        await prisma.user.update({
            where: { id: user.id },
            data: { resetRequested: new Date() }
        });

        res.json({ requires2FA: true });
    } catch (error) {
        console.error('Error requesting password reset:', error);
        res.status(500).json({ error: 'Failed to process reset request' });
    }
});

// Verify 2FA and reset password
app.post("/api/reset-password/verify", async (req, res) => {
    const { email, totpToken, newPassword } = req.body;

    try {
        const user = await prisma.user.findUnique({
            where: { email: email.toLowerCase().trim() }
        });

        if (!user || !user.resetRequested) {
            return res.status(400).json({ error: 'Invalid reset request' });
        }

        // Verify 2FA token
        const verified = speakeasy.totp.verify({
            secret: user.twoFactorSecret,
            encoding: 'base32',
            token: totpToken,
            window: 1
        });

        if (!verified) {
            return res.status(401).json({ error: 'Invalid 2FA token' });
        }

        // Reset password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        await prisma.user.update({
            where: { id: user.id },
            data: { 
                password: hashedPassword,
                resetRequested: null
            }
        });

        res.json({ message: 'Password reset successful' });
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({ error: 'Failed to reset password' });
    }
});

app.listen(8080, () => {
    console.log("Server started on port 8080");
});

// Cleanup Prisma connection on server shutdown
process.on('beforeExit', async () => {
    await prisma.$disconnect();
});