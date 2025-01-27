import { useState, useEffect, useRef } from 'react'
import './App.css'
import RichTextEditor from './components/RichTextEditor'
import './components/RichTextEditor.css'
import TurndownService from 'turndown'
import ReactMarkdown from 'react-markdown'

const turndown = new TurndownService()

// Add validation functions at the top (same as server-side ones)
const validateEmail = (email) => {
  if (!email) return 'Email is required';
  if (email.length > 255) return 'Email is too long';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return 'Invalid email format';
  return null;
};

const validateUsername = (username) => {
  if (!username) return 'Username is required';
  if (username.length < 3) return 'Username must be at least 3 characters';
  if (username.length > 30) return 'Username must be less than 30 characters';
  if (!/^[a-zA-Z0-9_-]+$/.test(username)) return 'Username can only contain letters, numbers, underscores, and hyphens';
  return null;
};

const calculatePasswordEntropy = (password) => {
  let charset = 0;
  // Check for different character types
  if (/[a-z]/.test(password)) charset += 26;  // lowercase letters
  if (/[A-Z]/.test(password)) charset += 26;  // uppercase letters
  if (/[0-9]/.test(password)) charset += 10;  // numbers
  if (/[^a-zA-Z0-9]/.test(password)) charset += 33;  // special characters

  // Calculate entropy: log2(charset size ^ password length)
  const entropy = Math.log2(Math.pow(charset, password.length));
  return entropy;
};

const validatePassword = (password) => {
  if (!password || typeof password !== 'string') return 'Password is required';
  if (password.length < 6) return 'Password must be at least 6 characters';
  if (password.length > 100) return 'Password is too long';
  if (!/\d/.test(password)) return 'Password must contain at least one number';
  if (!/[a-z]/.test(password)) return 'Password must contain at least one lowercase letter';
  if (!/[A-Z]/.test(password)) return 'Password must contain at least one uppercase letter';
  
  const entropy = calculatePasswordEntropy(password);
  if (entropy < 60) return 'Weak password - please use a stronger combination of characters';
  
  return null;
};

const validateTweetContent = (content) => {
  if (!content) return 'Tweet content is required';
  if (content.trim() === '') return 'Tweet cannot be empty';
  if (content.length > 280) return 'Tweet must be less than 280 characters';
  if (/<[^>]*>/.test(content)) return 'HTML tags are not allowed';
  return null;
};

// Move TwoFactorSetup outside of App component
const TwoFactorSetup = ({ 
  twoFactorQR, 
  twoFactorToken, 
  setTwoFactorToken, 
  verifyTwoFactor 
}) => (
  <div className="two-factor-setup">
    <h2>Setup Two-Factor Authentication</h2>
    {twoFactorQR && (
      <>
        <p>Scan this QR code with Google Authenticator:</p>
        <img src={twoFactorQR} alt="2FA QR Code" />
        <form onSubmit={verifyTwoFactor}>
          <input
            type="text"
            inputMode="numeric"
            pattern="[0-9]*"
            maxLength="6"
            placeholder="Enter 6-digit verification code"
            value={twoFactorToken}
            onChange={(e) => {
              const value = e.target.value.replace(/\D/g, '');
              setTwoFactorToken(value);
            }}
            required
          />
          <button type="submit">Verify</button>
        </form>
      </>
    )}
  </div>
);

function App() {
  const [tweets, setTweets] = useState([]);
  const [newTweet, setNewTweet] = useState('');
  const [user, setUser] = useState(null);
  const [showSignup, setShowSignup] = useState(false);
  const [showLogin, setShowLogin] = useState(false);
  const [token, setToken] = useState(null);
  const [signupData, setSignupData] = useState({
    email: '',
    username: '',
    password: ''
  });
  const [loginData, setLoginData] = useState({
    email: '',
    password: ''
  });
  const [errors, setErrors] = useState({
    tweet: null,
    signup: null,
    login: null
  });
  const [showTwoFactorSetup, setShowTwoFactorSetup] = useState(false);
  const [twoFactorQR, setTwoFactorQR] = useState(null);
  const [twoFactorSecret, setTwoFactorSecret] = useState(null);
  const [twoFactorToken, setTwoFactorToken] = useState('');
  const [loginTwoFactorToken, setLoginTwoFactorToken] = useState('');
  const [requiresTwoFactor, setRequiresTwoFactor] = useState(false);
  const [pendingLoginData, setPendingLoginData] = useState(null);
  const [passwordStrength, setPasswordStrength] = useState({
    entropy: 0,
    message: ''
  });
  const [showResetPassword, setShowResetPassword] = useState(false);
  const [resetEmail, setResetEmail] = useState('');
  const [resetToken, setResetToken] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [resetRequires2FA, setResetRequires2FA] = useState(false);
  const [tweetPassword, setTweetPassword] = useState('');

  const inputRef = useRef(null);

  useEffect(() => {
    if (user && token) {
      fetchTweets();
    }
  }, [user, token]);

  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.focus();
    }
  }, []);

  useEffect(() => {
    setTweetPassword('');
    setNewTweet('');
  }, [user?.id]);

  // Check for saved token on mount
  useEffect(() => {
    const savedToken = localStorage.getItem('token');
    if (savedToken) {
      verifyAndSetToken(savedToken);
    }
  }, []);

  const fetchTweets = async () => {
    try {
      const response = await fetch('http://localhost:8080/api/tweets', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (response.ok) {
        const data = await response.json();
        setTweets(data);
      } else {
        setTweets([]);
        if (response.status === 401) {
          setUser(null);
          setToken(null);
        }
      }
    } catch (error) {
      console.error('Error fetching tweets:', error);
      setTweets([]);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const contentError = validateTweetContent(newTweet);
    if (contentError) {
      setErrors(prev => ({ ...prev, tweet: contentError }));
      return;
    }

    try {
      const response = await fetch('http://localhost:8080/api/tweets', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ 
          content: newTweet,
          password: tweetPassword 
        }),
      });
      
      if (response.ok) {
        setNewTweet('');
        setTweetPassword('');
        fetchTweets();
      }
    } catch (error) {
      console.error('Error creating tweet:', error);
    }
  };

  const handleSignup = async (e) => {
    e.preventDefault();
    
    const emailError = validateEmail(signupData.email);
    const usernameError = validateUsername(signupData.username);
    const passwordError = validatePassword(signupData.password);

    if (emailError || usernameError || passwordError) {
      setErrors(prev => ({
        ...prev,
        signup: emailError || usernameError || passwordError
      }));
      return;
    }
    setErrors(prev => ({ ...prev, signup: null }));

    try {
      const response = await fetch('http://localhost:8080/api/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(signupData),
      });

      const data = await response.json();
      
      if (response.ok) {
        localStorage.setItem('token', data.token); // Save token
        setToken(data.token);
        setUser(data.user);
        setShowSignup(false);
        setSignupData({ email: '', username: '', password: '' });
      } else {
        alert(data.error || 'Failed to create account');
      }
    } catch (error) {
      console.error('Error signing up:', error);
      alert('Failed to create account');
    }
  };

  const setupTwoFactor = async () => {
    try {
      console.log('Setting up 2FA...');
      const response = await fetch('http://localhost:8080/api/2fa/generate', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      console.log('Response status:', response.status);

      if (response.ok) {
        const data = await response.json();
        console.log('2FA setup successful');
        setTwoFactorQR(data.qrCode);
        setTwoFactorSecret(data.secret);
        setShowTwoFactorSetup(true);
      } else {
        const error = await response.json();
        console.error('2FA setup failed:', error);
        alert(error.error || 'Failed to setup 2FA');
      }
    } catch (error) {
      console.error('Error setting up 2FA:', error);
      alert('Failed to setup 2FA');
    }
  };

  // Move verifyTwoFactor outside of render
  const handleVerifyTwoFactor = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch('http://localhost:8080/api/2fa/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ token: twoFactorToken })
      });

      if (response.ok) {
        setShowTwoFactorSetup(false);
        setTwoFactorToken('');
        alert('2FA enabled successfully!');
      } else {
        alert('Invalid verification code');
      }
    } catch (error) {
      console.error('Error verifying 2FA:', error);
      alert('Failed to verify 2FA');
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    
    const emailError = validateEmail(loginData.email);
    if (emailError) {
      setErrors(prev => ({ ...prev, login: emailError }));
      return;
    }
    if (!loginData.password) {
      setErrors(prev => ({ ...prev, login: 'Password is required' }));
      return;
    }
    setErrors(prev => ({ ...prev, login: null }));

    try {
      const loginPayload = requiresTwoFactor ? {
        ...pendingLoginData,
        totpToken: loginTwoFactorToken
      } : {
        email: loginData.email,
        password: loginData.password
      };

      console.log('Sending login request with:', { 
        ...loginPayload,
        hasPassword: !!loginPayload.password
      });

      const response = await fetch('http://localhost:8080/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(loginPayload),
      });

      const data = await response.json();
      console.log('Login response:', { status: response.status, data });
      
      if (response.ok) {
        localStorage.setItem('token', data.token); // Save token
        setToken(data.token);
        setUser(data.user);
        setShowLogin(false);
        setLoginData({ email: '', password: '' });
        setLoginTwoFactorToken('');
        setRequiresTwoFactor(false);
        setPendingLoginData(null);
      } else if (data.requires2FA) {
        setRequiresTwoFactor(true);
        setPendingLoginData({
          email: loginData.email,
          password: loginData.password
        });
        setErrors(prev => ({ ...prev, login: 'Please enter your 2FA code' }));
      } else {
        setErrors(prev => ({ ...prev, login: data.error || 'Login failed' }));
      }
    } catch (error) {
      console.error('Error logging in:', error);
      setErrors(prev => ({ ...prev, login: 'Login failed' }));
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token'); // Remove token
    setUser(null);
    setToken(null);
    setTweets([]);
    setPendingLoginData(null);
    setRequiresTwoFactor(false);
    setLoginTwoFactorToken('');
  };

  const handlePasswordChange = (e) => {
    const password = e.target.value;
    setSignupData(prev => ({ ...prev, password }));
    
    // Calculate and set password strength
    const entropy = calculatePasswordEntropy(password);
    let message = '';
    if (entropy < 40) message = 'Very weak';
    else if (entropy < 60) message = 'Weak';
    else if (entropy < 80) message = 'Moderate';
    else if (entropy < 100) message = 'Strong';
    else message = 'Very strong';
    
    setPasswordStrength({ entropy, message });
  };

  // Add function to verify token and get user data
  const verifyAndSetToken = async (savedToken) => {
    try {
      const response = await fetch('http://localhost:8080/api/verify-token', {
        headers: {
          'Authorization': `Bearer ${savedToken}`
        }
      });

      if (response.ok) {
        const userData = await response.json();
        setToken(savedToken);
        setUser(userData);
      } else {
        // If token is invalid, remove it
        localStorage.removeItem('token');
      }
    } catch (error) {
      console.error('Error verifying token:', error);
      localStorage.removeItem('token');
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();

    if (!resetRequires2FA) {
      // Initial reset request
      try {
        const response = await fetch('http://localhost:8080/api/reset-password/request', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: resetEmail })
        });

        const data = await response.json();
        
        if (data.requires2FA) {
          setResetRequires2FA(true);
        } else {
          alert(data.message);
        }
      } catch (error) {
        console.error('Error requesting reset:', error);
        alert('Failed to process reset request');
      }
    } else {
      // Verify 2FA and set new password
      try {
        const response = await fetch('http://localhost:8080/api/reset-password/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: resetEmail,
            totpToken: resetToken,
            newPassword
          })
        });

        const data = await response.json();
        
        if (response.ok) {
          alert('Password reset successful');
          setShowResetPassword(false);
          setResetEmail('');
          setResetToken('');
          setNewPassword('');
          setResetRequires2FA(false);
        } else {
          alert(data.error);
        }
      } catch (error) {
        console.error('Error resetting password:', error);
        alert('Failed to reset password');
      }
    }
  };

  return (
    <div className="container">
      <header className="header">
        <h1>Mini Twitter</h1>
        {user ? (
          <div className="user-info">
            Welcome, @{user.username}!
            <button 
              onClick={handleLogout} 
              className="logout-button"
            >
              Logout
            </button>
          </div>
        ) : (
          <div className="auth-buttons">
            <button onClick={() => {setShowLogin(true); setShowSignup(false)}} className="login-button">
              Login
            </button>
            <button onClick={() => {setShowSignup(true); setShowLogin(false)}} className="signup-button">
              Sign Up
            </button>
          </div>
        )}
      </header>
      
      {showLogin && !user && (
        <div className="auth-form">
          <h2>Login</h2>
          <form onSubmit={handleLogin}>
            <input
              type="email"
              placeholder="Email"
              value={loginData.email}
              onChange={(e) => setLoginData({...loginData, email: e.target.value})}
              required
            />
            <input
              type="password"
              placeholder="Password"
              value={loginData.password}
              onChange={(e) => setLoginData({...loginData, password: e.target.value})}
              required
            />
            {requiresTwoFactor && (
              <input
                key="2fa-input"
                autoFocus
                type="text"
                inputMode="numeric"
                pattern="[0-9]*"
                maxLength="6"
                placeholder="Enter 6-digit 2FA code"
                value={loginTwoFactorToken}
                onChange={(e) => {
                  const value = e.target.value.replace(/\D/g, '');
                  setLoginTwoFactorToken(value);
                }}
                required
              />
            )}
            {errors.login && <div className="error-message">{errors.login}</div>}
            <div className="auth-buttons">
              <button type="submit">Login</button>
              <button type="button" onClick={() => setShowLogin(false)}>Cancel</button>
            </div>
          </form>
          <button 
            type="button" 
            onClick={() => {
              setShowLogin(false);
              setShowResetPassword(true);
            }}
            className="forgot-password-button"
          >
            Forgot Password?
          </button>
        </div>
      )}
      
      {showSignup && !user && (
        <div className="signup-form">
          <h2>Create Account</h2>
          <form onSubmit={handleSignup}>
            <input
              type="email"
              placeholder="Email"
              value={signupData.email}
              onChange={(e) => setSignupData({...signupData, email: e.target.value})}
              required
            />
            <input
              type="text"
              placeholder="Username"
              value={signupData.username}
              onChange={(e) => setSignupData({...signupData, username: e.target.value})}
              required
            />
            <div className="password-input-container">
              <input
                type="password"
                placeholder="Password"
                value={signupData.password}
                onChange={handlePasswordChange}
                required
              />
              {signupData.password && (
                <div className={`password-strength ${passwordStrength.message.toLowerCase()}`}>
                  <div className="strength-bar" style={{ 
                    width: `${Math.min(100, (passwordStrength.entropy / 100) * 100)}%`
                  }}></div>
                  <span>{passwordStrength.message}</span>
                </div>
              )}
            </div>
            {errors.signup && <div className="error-message">{errors.signup}</div>}
            <div className="signup-buttons">
              <button type="submit">Create Account</button>
              <button type="button" onClick={() => setShowSignup(false)}>Cancel</button>
            </div>
          </form>
        </div>
      )}
      
      {showResetPassword && !user && (
        <div className="auth-form">
          <h2>Reset Password</h2>
          <form onSubmit={handleResetPassword}>
            <input
              type="email"
              placeholder="Email"
              value={resetEmail}
              onChange={(e) => setResetEmail(e.target.value)}
              required
              disabled={resetRequires2FA}
            />
            {resetRequires2FA && (
              <>
                <input
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  maxLength="6"
                  placeholder="Enter 6-digit 2FA code"
                  value={resetToken}
                  onChange={(e) => setResetToken(e.target.value.replace(/\D/g, ''))}
                  required
                />
                <input
                  type="password"
                  placeholder="New Password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required
                />
              </>
            )}
            <div className="auth-buttons">
              <button type="submit">
                {resetRequires2FA ? 'Reset Password' : 'Continue'}
              </button>
              <button 
                type="button" 
                onClick={() => {
                  setShowResetPassword(false);
                  setResetEmail('');
                  setResetToken('');
                  setNewPassword('');
                  setResetRequires2FA(false);
                }}
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}
      
      {user && (
        <div className="user-section">
          {!showTwoFactorSetup && (
            <button onClick={setupTwoFactor} className="setup-2fa-button">
              Setup Two-Factor Authentication
            </button>
          )}

          {showTwoFactorSetup && (
            <TwoFactorSetup
              twoFactorQR={twoFactorQR}
              twoFactorToken={twoFactorToken}
              setTwoFactorToken={setTwoFactorToken}
              verifyTwoFactor={handleVerifyTwoFactor}
            />
          )}

          <form onSubmit={handleSubmit} className="tweet-form">
            <RichTextEditor 
              content={newTweet} 
              onChange={setNewTweet}
            />
            <input
              type="password"
              placeholder="Enter your password to sign tweet"
              value={tweetPassword}
              onChange={(e) => setTweetPassword(e.target.value)}
              required
            />
            {errors.tweet && <div className="error-message">{errors.tweet}</div>}
            <button type="submit">Tweet</button>
          </form>

          <div className="tweets">
            {tweets.map((tweet) => (
              <div key={tweet.id} className="tweet">
                <div className="tweet-header">
                  <span className="username">@{tweet.author.username}</span>
                  {tweet.verified && (
                    <span className="verified-badge">✓ Verified</span>
                  )}
                </div>
                <div className="content">
                  <ReactMarkdown>{tweet.content}</ReactMarkdown>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
      
      {!user && (
        <div className="welcome-message">
          <h2>Welcome to Mini Twitter</h2>
          <p>Please login or sign up to see and post tweets!</p>
        </div>
      )}
    </div>
  )
}

export default App
