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
  if (/<[^>]*>/.test(content)) return 'HTML tags are not allowed';
  return null;
};

module.exports = {
  validateEmail,
  validateUsername,
  validatePassword,
  validateTweetContent
}; 