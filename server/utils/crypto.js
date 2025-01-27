const crypto = require('crypto');

const generateKeyPair = () => {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });
};

const encryptPrivateKey = (privateKey, password) => {
  // Generate a random 16 bytes IV
  const iv = crypto.randomBytes(16);
  // Create key from password
  const key = crypto.scryptSync(password, 'salt', 32);
  // Create cipher
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  
  let encrypted = cipher.update(privateKey, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  // Return both the IV and encrypted data
  return iv.toString('hex') + ':' + encrypted;
};

const decryptPrivateKey = (encryptedData, password) => {
  // Split IV and encrypted data
  const [ivHex, encryptedKey] = encryptedData.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  // Create key from password
  const key = crypto.scryptSync(password, 'salt', 32);
  // Create decipher
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  
  let decrypted = decipher.update(encryptedKey, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};

const signData = (data, privateKey) => {
  const signer = crypto.createSign('SHA256');
  signer.update(data);
  return signer.sign(privateKey, 'base64');
};

const verifySignature = (data, signature, publicKey) => {
  const verifier = crypto.createVerify('SHA256');
  verifier.update(data);
  return verifier.verify(publicKey, signature, 'base64');
};

module.exports = {
  generateKeyPair,
  encryptPrivateKey,
  decryptPrivateKey,
  signData,
  verifySignature
}; 