const express = require("express");
const app = express();
const cors = require("cors");
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { generateKeyPair, encryptPrivateKey, decryptPrivateKey, signData, verifySignature } = require('./utils/crypto');
const { 
  validateEmail, 
  validateUsername, 
  validatePassword, 
  validateTweetContent 
} = require('./utils/validation');
const { 
    generateTwoFactorSecret, 
    verifyTwoFactorToken, 
    verifyTwoFactorLogin 
} = require('./utils/twoFactor');

const prisma = new PrismaClient();
const corsOptions = {
    origin: ["http://localhost:5173"],
}

app.use(cors(corsOptions));
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;

// middleware do sprawdzania JWT tokenu
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId; // Dodajemy userId do request object
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// pobieramy wszystkie tweety z informacja o autorze
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

// Tworzymy nowy tweet
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

        // Sprawdzamy password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid password' });
        }

        // Deszyfrujemy private key i tworzymy podpis
        const privateKey = decryptPrivateKey(user.encryptedPrivateKey, password);
        const signature = signData(content, privateKey);

        // Sprawdzamy podpis przed zapisaniem
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

// Tworzymy nowego użytkownika z bezpiecznym hashowaniem hasła
app.post("/api/users", async (req, res) => {
    const { email, username, password } = req.body;

    // Sprawdzamy wszystkie pola
    const emailError = validateEmail(email);
    if (emailError) return res.status(400).json({ error: emailError });

    const usernameError = validateUsername(username);
    if (usernameError) return res.status(400).json({ error: usernameError });

    const passwordError = validatePassword(password);
    if (passwordError) return res.status(400).json({ error: passwordError });

    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Generujemy klucz publiczny i prywatny
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

// Generujemy 2fa secret i qr code
app.post("/api/2fa/generate", authenticateToken, async (req, res) => {
    try {
        const user = await prisma.user.findUnique({
            where: { id: req.userId },
            select: { email: true }
        });

        const twoFactorData = await generateTwoFactorSecret(req.userId, user.email);
        res.json(twoFactorData);
    } catch (error) {
        console.error('Error generating 2FA:', error);
        res.status(500).json({ error: 'Failed to generate 2FA' });
    }
});

// Sprawdzamy i włączamy 2fa
app.post("/api/2fa/verify", authenticateToken, async (req, res) => {
    const { token } = req.body;

    try {
        const verified = await verifyTwoFactorToken(req.userId, token);
        if (verified) {
            res.json({ success: true });
        } else {
            res.status(400).json({ error: 'Invalid token' });
        }
    } catch (error) {
        console.error('Error verifying 2FA:', error);
        res.status(500).json({ error: 'Failed to verify 2FA' });
    }
});

// Dodajemy pomocniczą funkcję do losowego opóźnienia (rndom delay)
const getRandomDelay = () => {
  return Math.floor(Math.random() * 1000) + 500; // Losowe opóźnienie między 500-1500ms
};

// endpoint logowania z obsługą prób logowania
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
            // Dodajemy losowe opóźnienie nawet dla nieistniejących użytkowników
            await new Promise(resolve => setTimeout(resolve, getRandomDelay()));
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Sprawdzamy, czy użytkownik jest zablokowany
        if (user.loginAttempts >= 10) {
            const lockoutTime = 15 * 60 * 1000; // 15 minutes
            if (user.lastAttempt && Date.now() - user.lastAttempt.getTime() < lockoutTime) {
                const remainingTime = Math.ceil((lockoutTime - (Date.now() - user.lastAttempt.getTime())) / 60000);
                return res.status(429).json({ 
                    error: `Too many failed attempts. Please try again in ${remainingTime} minutes.` 
                });
            } else {
                // Resetujemy próby po okresie blokady
                await prisma.user.update({
                    where: { id: user.id },
                    data: { 
                        loginAttempts: 0,
                        lastAttempt: null
                    }
                });
            }
        }

        // Dodajemy losowe opóźnienie przed sprawdzeniem hasła
        await new Promise(resolve => setTimeout(resolve, getRandomDelay()));

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            // Zwiększamy liczbę prób
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

        // Sprawdzamy 2fa jeśli jest włączone
        if (user.twoFactorEnabled) {
            if (!totpToken) {
                return res.status(403).json({ 
                    requires2FA: true,
                    message: 'Please provide 2FA token' 
                });
            }
            // Sprawdzamy 2fa
            const verified = verifyTwoFactorLogin(user.twoFactorSecret, totpToken);

            if (!verified) {
                // Zwiększamy liczbę prób dla nieprawidłowego 2fa
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

        // Resetujemy próby po pomyślnym logowaniu
        await prisma.user.update({
            where: { id: user.id },
            data: { 
                loginAttempts: 0,
                lastAttempt: null
            }
        });

        // Generujemy JWT i wysyłamy odpowiedź
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
        const { password: _, twoFactorSecret: __, ...userData } = user;
        res.json({ user: userData, token });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Pobieramy użytkownika po id
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

// endpoint do sprawdzania tokenu i zwracania danych użytkownika
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

// inicjujemy reset hasła
app.post("/api/reset-password/request", async (req, res) => {
    const { email } = req.body;
    
    try {
        const user = await prisma.user.findUnique({
            where: { email: email.toLowerCase().trim() }
        });

        if (!user || !user.twoFactorEnabled) {
            // Nie ujawniamy   czy użytkownik istnieje lub ma 2fa
            return res.json({ message: 'the account didnt have 2FA enabled, you will not be able to reset the password.' });
        }

        // oznaczamy że użytkownik zażądał resetu
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

// sprawdzamy 2fa i resetujemy hasło
app.post("/api/reset-password/verify", async (req, res) => {
    const { email, totpToken, newPassword } = req.body;

    try {
        const user = await prisma.user.findUnique({
            where: { email: email.toLowerCase().trim() }
        });

        if (!user || !user.resetRequested) {
            return res.status(400).json({ error: 'Invalid reset request' });
        }

        // Sprawdzamy token 2fa
        const verified = speakeasy.totp.verify({
            secret: user.twoFactorSecret,
            encoding: 'base32',
            token: totpToken,
            window: 1
        });

        if (!verified) {
            return res.status(401).json({ error: 'Invalid 2FA token' });
        }

        // Resetujemy hasło
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

// czyszczymy połączenie z Prisma przy zamknięciu serwera
process.on('beforeExit', async () => {
    await prisma.$disconnect();
});