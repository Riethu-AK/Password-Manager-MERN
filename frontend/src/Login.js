import React, { useState } from 'react';
import './Login.css';
import { useToasts } from './components/ToastProvider';

function Login({ onLogin }) {
  const [mode, setMode] = useState('signin'); // or 'signup'
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [email, setEmail] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { toasts, add, remove } = useToasts();

  const handleSubmit = (e) => {
    e.preventDefault();
    setError('');
    if (!username || !password || (mode === 'signup' && !email)) {
      setError('Please complete all required fields');
      return;
    }

    const base = 'http://localhost:5000';
    setLoading(true);
    setError('');
    const doError = (msg) => {
      setError(msg);
      add(msg, 'error');
      setLoading(false);
    };

    if (mode === 'signin') {
      fetch(`${base}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      })
        .then(async (r) => {
          let data;
          try { data = await r.json(); } catch (e) { throw new Error('Invalid server response'); }
          if (!r.ok) throw new Error(data.error || 'Login failed');
          add('Signed in', 'success');
          setLoading(false);
          if (onLogin) onLogin(data);
        })
        .catch((err) => doError(err.message || 'Login error'));
    } else {
      // signup -> call backend
      fetch('http://localhost:5000/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, email })
      })
        .then(async (r) => {
          let data;
          try { data = await r.json(); } catch (e) { throw new Error('Invalid server response'); }
          if (!r.ok) throw new Error(data.error || 'Signup failed');
          add('Account created', 'success');
          setLoading(false);
          if (onLogin) onLogin(data);
        })
        .catch((err) => doError(err.message || 'Signup error'));
    }
  };

  return (
    <div className="login-wrapper">
      <div className="login-card">
        <form onSubmit={handleSubmit}>
          <div className="brand">🔒 Cryptix</div>
          <h2>{mode === 'signin' ? 'Welcome back' : 'Create account'}</h2>
          <p className="muted">{mode === 'signin' ? 'Sign in to access your Cryptix vault' : 'Sign up to save your passwords securely'}</p>
          <label>Username</label>
          <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Choose a username" />

          {mode === 'signup' && (
            <>
              <label>Email</label>
              <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@company.com" />
            </>
          )}

          <label>Password</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Create a strong password" />

          <button type="submit" className="primary" disabled={loading}>{loading ? 'Please wait...' : (mode === 'signin' ? 'Sign in' : 'Create account')}</button>

          {error && <div className="error">{error}</div>}

          <div className="login-foot">
            {mode === 'signin' ? (
              <>
                <a href="#" className="forgot">Forgot password?</a>
                <div className="switch">New here? <button type="button" onClick={() => { setMode('signup'); setError(''); }}>Create an account</button></div>
              </>
            ) : (
              <div className="switch">Already have an account? <button type="button" onClick={() => { setMode('signin'); setError(''); }}>Sign in</button></div>
            )}
          </div>
        </form>

        <div className="login-hero">
          <h3 className="hero-title">{mode === 'signin' ? 'Welcome back' : 'Create your Cryptix account'}</h3>
          <p className="hero-sub muted">Securely store and manage your passwords with Cryptix.</p>
        </div>
        {/* toast container for local toasts */}
        <div style={{ position: 'relative' }}>
          {/* render toasts */}
          {toasts && toasts.length > 0 && (
            <div className="toast-container" style={{ position: 'absolute', insetInlineEnd: 0, insetBlockEnd: 0 }}>
              {toasts.map(t => (
                <div key={t.id} className={`toast ${t.type}`}>{t.message}</div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default Login;
