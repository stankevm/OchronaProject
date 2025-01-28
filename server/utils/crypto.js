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
  // generujemy losowy 16-bitowy iv
  const iv = crypto.randomBytes(16);
  // tworzymy klucz z hasła
  const key = crypto.scryptSync(password, 'salt', 32);
  // tworzymy szyfr
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  
  let encrypted = cipher.update(privateKey, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  // zwracamy iv i zaszyfrowane dane
  return iv.toString('hex') + ':' + encrypted;
};

const decryptPrivateKey = (encryptedData, password) => {
  // dzielimy iv i zaszyfrowane dane
  const [ivHex, encryptedKey] = encryptedData.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  // tworzymy klucz z hasła
  const key = crypto.scryptSync(password, 'salt', 32);
  // tworzymy deszyfr
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