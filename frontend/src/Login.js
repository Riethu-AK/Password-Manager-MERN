import React, { useState } from 'react';
import { GoogleOAuthProvider, GoogleLogin } from '@react-oauth/google';
import './Login.css';
import { useToasts } from './components/ToastProvider';

function Login({ onLogin }) {
  // Add missing state and functions
  const [signupPhoto, setSignupPhoto] = useState(null);

  const openCamera = async () => {
    try {
      const s = await navigator.mediaDevices.getUserMedia({ video: true });
      return s;
    } catch (err) {
      add('Camera access denied', 'error');
      return null;
    }
  };

  const capturePhotoFromStream = (stream) => {
    const video = document.createElement('video');
    video.srcObject = stream;
    video.play();
    return new Promise((resolve) => {
      video.onloadedmetadata = () => {
        const canvas = document.createElement('canvas');
        canvas.width = video.videoWidth || 320;
        canvas.height = video.videoHeight || 240;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        const dataUrl = canvas.toDataURL('image/jpeg', 0.8);
        video.pause();
        if (stream.getTracks) stream.getTracks().forEach(t => t.stop());
        resolve(dataUrl);
      };
    });
  };
  const [mode, setMode] = useState('signin'); // or 'signup' or 'admin-setup'
  const [googleLoggedIn, setGoogleLoggedIn] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [email, setEmail] = useState('');
  const [setupKey, setSetupKey] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { toasts, add } = useToasts();

  const handleSubmit = (e) => {
    e.preventDefault();
    setError('');
    if (googleLoggedIn) {
      // Google login already handled, skip form submit
      return;
    }
    if (mode === 'admin-setup') {
      if (!username || !password || !setupKey) {
        setError('Please complete all fields for admin setup');
        return;
      }
      setLoading(true);
      fetch('http://localhost:5000/admin/setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, setupKey })
      })
        .then(async (r) => {
          let data;
          try { data = await r.json(); } catch (e) { throw new Error('Invalid server response'); }
          if (!r.ok) throw new Error(data.error || 'Admin setup failed');
          add('Admin account created successfully', 'success');
          setLoading(false);
          setMode('signin');
          setSetupKey('');
        })
        .catch((err) => {
          setError(err.message || 'Admin setup error');
          add(err.message || 'Admin setup error', 'error');
          setLoading(false);
        });
      return;
    }
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
      // include photo if captured
      const payload = { username, password, email, photo: signupPhoto };
      fetch('http://localhost:5000/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
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

  // const handleTakeSignupPhoto = async () => {
  //   const s = await openCamera();
  //   if (!s) return;
  //   const data = await capturePhotoFromStream(s);
  //   setSignupPhoto(data);
  //   add('Photo captured', 'success');
  // };

  // simple pixel-diff compare (very rough) — used client-side
  const imagesSimilar = (dataUrlA, dataUrlB, tolerance = 0.15) => {
    if (!dataUrlA || !dataUrlB) return false;
    const imgA = new Image();
    const imgB = new Image();
    return new Promise((resolve) => {
      let loaded = 0;
      const check = () => {
        loaded++;
        if (loaded < 2) return;
        const canvas = document.createElement('canvas');
        const w = Math.min(imgA.width, imgB.width);
        const h = Math.min(imgA.height, imgB.height);
        canvas.width = w; canvas.height = h;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(imgA, 0, 0, w, h);
        const dA = ctx.getImageData(0,0,w,h).data;
        ctx.clearRect(0,0,w,h);
        ctx.drawImage(imgB, 0, 0, w, h);
        const dB = ctx.getImageData(0,0,w,h).data;
        let diff = 0;
        for (let i = 0; i < dA.length; i += 4) {
          diff += Math.abs(dA[i] - dB[i]);
          diff += Math.abs(dA[i+1] - dB[i+1]);
          diff += Math.abs(dA[i+2] - dB[i+2]);
        }
        const max = w*h*3*255;
        const ratio = diff / max;
        resolve(ratio <= tolerance);
      };
      imgA.onload = check; imgB.onload = check;
      imgA.src = dataUrlA; imgB.src = dataUrlB;
    });
  };

  const handleForgot = async () => {
    const uname = prompt('Enter your username to verify:');
    if (!uname) return;
    // open camera and capture
    const s = await openCamera();
    if (!s) return;
    const selfie = await capturePhotoFromStream(s);
    // fetch stored photo
    try {
      const res = await fetch(`http://localhost:5000/auth/user/${encodeURIComponent(uname)}/photo`);
      if (!res.ok) { add('User not found', 'error'); return; }
      const data = await res.json();
      const stored = data.photo;
      if (!stored) { add('No photo on record for user', 'error'); return; }
      const ok = await imagesSimilar(selfie, stored);
      if (!ok) { add('Photo verification failed', 'error'); return; }
      const newPw = prompt('Photo verified — enter new password:');
      if (!newPw) return;
      const r2 = await fetch('http://localhost:5000/auth/reset-by-photo', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: uname, newPassword: newPw }) });
      if (!r2.ok) { const err = await r2.json(); add(err.error || 'Reset failed', 'error'); return; }
      add('Password reset — sign in with new password', 'success');
    } catch (err) {
      console.error(err);
      add('Reset failed', 'error');
    }
  };


  return (
    <GoogleOAuthProvider clientId="942596418627-t0jik8i9tikm0ad4cul65kde7klrd0f4.apps.googleusercontent.com">
      <div className="login-wrapper">
        <div className="login-card">
          <form onSubmit={handleSubmit}>
            <div className="brand">🔒 Cryptix</div>
            <h2>
              {mode === 'signin' ? 'Welcome back' : 
               mode === 'signup' ? 'Create account' : 
               'Admin Setup'}
            </h2>
            <p className="muted">
              {mode === 'signin' ? 'Sign in to access your Cryptix vault' : 
               mode === 'signup' ? 'Sign up to save your passwords securely' :
               'Create the first admin account'}
            </p>

            {/* Hide username/password fields if Google login is successful */}
            {!googleLoggedIn && <>
              <label>Username</label>
              <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Choose a username" />

              {mode === 'signup' && (
                <>
                  <label>Email</label>
                  <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@company.com" />
                </>
              )}

              {mode === 'admin-setup' && (
                <>
                  <label>Setup Key</label>
                  <input type="password" value={setupKey} onChange={(e) => setSetupKey(e.target.value)} placeholder="Enter admin setup key" />
                </>
              )}

              <label>Password</label>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Create a strong password" />
            </>}


          <button type="submit" className="primary" disabled={loading}>
            {loading ? 'Please wait...' : 
             mode === 'signin' ? 'Sign in' : 
             mode === 'signup' ? 'Create account' :
             'Create Admin Account'}
          </button>
          {/* Google Sign-In button only for sign-in mode */}
          {mode === 'signin' && (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginTop: 12, marginBottom: 16 }}>
              <GoogleLogin
                onSuccess={credentialResponse => {
                  fetch('http://localhost:5000/auth/google', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token: credentialResponse.credential })
                  })
                  .then(res => res.json())
                  .then(data => {
                    if (data.token) {
                      setGoogleLoggedIn(true);
                      onLogin(data);
                    } else {
                      setError(data.error || 'Google login failed');
                    }
                  });
                }}
                onError={() => {
                  setError('Google Sign-In failed');
                }}
              />
            </div>
          )}

          {error && <div className="error">{error}</div>}

          <div className="login-foot">
            {mode === 'signin' ? (
              <>
                <button type="button" className="forgot" onClick={handleForgot}>Forgot password?</button>
                <div className="switch">
                  New here? <button type="button" onClick={() => { setMode('signup'); setError(''); }}>Create an account</button>
                  <br />
                  <small>
                    <button type="button" onClick={() => { setMode('admin-setup'); setError(''); }} style={{marginTop: '5px', fontSize: '12px'}}>
                      Setup Admin Account
                    </button>
                  </small>
                </div>
              </>
            ) : mode === 'signup' ? (
              <div className="switch">Already have an account? <button type="button" onClick={() => { setMode('signin'); setError(''); }}>Sign in</button></div>
            ) : (
              <div className="switch">
                <button type="button" onClick={() => { setMode('signin'); setError(''); setSetupKey(''); }}>Back to Sign In</button>
              </div>
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
  </GoogleOAuthProvider>
  );

}
export default Login;
