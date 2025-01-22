import { useState, useEffect } from 'react'
import './App.css'

function App() {
  const [tweets, setTweets] = useState([]);
  const [newTweet, setNewTweet] = useState('');
  const [user, setUser] = useState(null);
  const [showSignup, setShowSignup] = useState(false);
  const [showLogin, setShowLogin] = useState(false);
  const [signupData, setSignupData] = useState({
    email: '',
    username: '',
    password: ''
  });
  const [loginData, setLoginData] = useState({
    email: '',
    password: ''
  });

  useEffect(() => {
    fetchTweets();
  }, []);

  const fetchTweets = async () => {
    try {
      const response = await fetch('http://localhost:8080/api/tweets');
      const data = await response.json();
      setTweets(data);
    } catch (error) {
      console.error('Error fetching tweets:', error);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!newTweet.trim()) return;

    try {
      const response = await fetch('http://localhost:8080/api/tweets', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
          content: newTweet,
          userId: user?.id || 1 // Use logged in user's ID or default to 1
        }),
      });
      
      if (response.ok) {
        setNewTweet('');
        fetchTweets();
      }
    } catch (error) {
      console.error('Error creating tweet:', error);
    }
  };

  const handleSignup = async (e) => {
    e.preventDefault();
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
        setUser(data);
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

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch('http://localhost:8080/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(loginData),
      });

      const data = await response.json();
      
      if (response.ok) {
        setUser(data);
        setShowLogin(false);
        setLoginData({ email: '', password: '' });
      } else {
        alert(data.error || 'Login failed');
      }
    } catch (error) {
      console.error('Error logging in:', error);
      alert('Login failed');
    }
  };

  return (
    <div className="container">
      <header className="header">
        <h1>Mini Twitter</h1>
        {user ? (
          <div className="user-info">
            Welcome, @{user.username}!
            <button onClick={() => setUser(null)} className="logout-button">
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
            <div className="auth-buttons">
              <button type="submit">Login</button>
              <button type="button" onClick={() => setShowLogin(false)}>Cancel</button>
            </div>
          </form>
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
            <input
              type="password"
              placeholder="Password"
              value={signupData.password}
              onChange={(e) => setSignupData({...signupData, password: e.target.value})}
              required
            />
            <div className="signup-buttons">
              <button type="submit">Create Account</button>
              <button type="button" onClick={() => setShowSignup(false)}>Cancel</button>
            </div>
          </form>
        </div>
      )}
      
      <form onSubmit={handleSubmit} className="tweet-form">
        <textarea
          value={newTweet}
          onChange={(e) => setNewTweet(e.target.value)}
          placeholder="What's happening?"
          maxLength={280}
        />
        <button type="submit">Tweet</button>
      </form>

      <div className="tweets">
        {tweets.map((tweet) => (
          <div key={tweet.id} className="tweet">
            <div className="tweet-header">
              <span className="username">@{tweet.author.username}</span>
            </div>
            <p className="content">{tweet.content}</p>
          </div>
        ))}
      </div>
    </div>
  )
}

export default App
