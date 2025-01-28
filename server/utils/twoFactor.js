const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

const generateTwoFactorSecret = async (userId, userEmail) => {
    try {
        const secret = speakeasy.generateSecret({
            name: `MiniTwitter:${userEmail}`
        });

        // aktualizujemy użytkownika w bazie danych
        await prisma.user.update({
            where: { id: userId },
            data: { 
                twoFactorSecret: secret.base32,
                twoFactorEnabled: false
            }
        });

        // Generujemy qr code
        const qrCode = await QRCode.toDataURL(secret.otpauth_url);

        return {
            secret: secret.base32,
            qrCode
        };
    } catch (error) {
        console.error('Error generating 2FA:', error);
        throw new Error('Failed to generate 2FA');
    }
};

// sprawdzamy token 2fa
const verifyTwoFactorToken = async (userId, token) => {
    try {
        const user = await prisma.user.findUnique({
            where: { id: userId }
        });

        const verified = speakeasy.totp.verify({
            secret: user.twoFactorSecret,
            encoding: 'base32',
            token,
            window: 1
        });

        if (verified) {
            await prisma.user.update({
                where: { id: userId },
                data: { twoFactorEnabled: true }
            });
        }

        return verified;
    } catch (error) {
        console.error('Error verifying 2FA:', error);
        throw new Error('Failed to verify 2FA');
    }
};


const verifyTwoFactorLogin = (secret, token) => {
    return speakeasy.totp.verify({
        secret: secret,
        encoding: 'base32',
        token: token,
        window: 1
    });
};

module.exports = {
    generateTwoFactorSecret,
    verifyTwoFactorToken,
    verifyTwoFactorLogin
}; 