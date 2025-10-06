import React, { useState, useEffect, useCallback } from "react";
import "./MessageApp.css";
import { useToasts } from './components/ToastProvider';
import emailjs from 'emailjs-com';

const apiBase = process.env.REACT_APP_API_URL;

function MessageApp({ onLogout, user }) {
  const [formData, setFormData] = useState({ text: "", password: "", email: "" });
  const [messages, setMessages] = useState([]);
  const [query, setQuery] = useState("");
  const [activePage, setActivePage] = useState("home");
  const [changeModal, setChangeModal] = useState({ open: false, msgId: null });
  const [otpRequested, setOtpRequested] = useState(false);
  const [otpTimer, setOtpTimer] = useState(0);
  const [enteredOtp, setEnteredOtp] = useState("");
  const [otpVerified, setOtpVerified] = useState(false);
  const [newPassword, setNewPassword] = useState("");

  const { toasts, add } = useToasts();

  const fetchMessages = useCallback(async () => {
    try {
      const token = user && user.token ? user.token : (localStorage.getItem('ps_user') ? JSON.parse(localStorage.getItem('ps_user')).token : null);
      const res = await fetch(`${apiBase}/messages`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
      const data = await res.json();
      if (!res.ok) {
        console.error('Failed to fetch messages', data);
        if (res.status === 401) {
          // token invalid or expired
          if (onLogout) onLogout();
        }
        return;
      }
      setMessages(data);
    } catch (err) {
      console.error("Error fetching messages:", err);
      add('Failed to fetch entries', 'error');
    }
  }, [user, onLogout, add]);

  useEffect(() => {
    fetchMessages();
  }, [fetchMessages]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!formData.text || !formData.password || !formData.email) {
      alert("Please fill all fields, including email!");
      return;
    }
    try {
      const token = user && user.token ? user.token : (localStorage.getItem('ps_user') ? JSON.parse(localStorage.getItem('ps_user')).token : null);
      const res = await fetch(`${apiBase}/messages`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
  body: JSON.stringify(formData),
      });
      const data = await res.json();
      if (!res.ok) {
        console.error('Save failed', data);
        add(data.error || 'Save failed', 'error');
        if (res.status === 401 && onLogout) onLogout();
        return;
      }
      setMessages((prev) => [data, ...prev]);
      add('Saved', 'success');
  setFormData({ text: "", password: "", email: "" });
    } catch (error) {
      console.error("Error saving message:", error);
      add('Save failed', 'error');
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm("Delete this entry?")) return;
    try {
      const token = user && user.token ? user.token : (localStorage.getItem('ps_user') ? JSON.parse(localStorage.getItem('ps_user')).token : null);
      const res = await fetch(`${apiBase}/messages/${id}`, { method: "DELETE", headers: token ? { Authorization: `Bearer ${token}` } : {} });
      if (!res.ok) {
        const data = await res.json();
        console.error('Delete failed', data);
        add(data.error || 'Delete failed', 'error');
        if (res.status === 401 && onLogout) onLogout();
        return;
      }
      setMessages((prev) => prev.filter((m) => m._id !== id));
      add('Deleted', 'success');
    } catch (error) {
      console.error("Error deleting message:", error);
      add('Delete failed', 'error');
    }
  };

  const copyToClipboard = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
  add('Copied to clipboard', 'success');
    } catch (e) {
      console.error("Clipboard error:", e);
  add('Failed to copy', 'error');
    }
  };

  const [visiblePasswords, setVisiblePasswords] = useState({});
  const toggleShow = (id) => {
    const key = String(id);
    setVisiblePasswords((v) => ({ ...v, [key]: !v[key] }));
  };

  // encryption removed on server; messages come with plaintext passwords

  const filtered = messages.filter((m) => {
    const q = query.trim().toLowerCase();
    if (!q) return true;
    return (
      (m.text || "").toLowerCase().includes(q) ||
      (m.email || "").toLowerCase().includes(q)
    );
  });

  const strength = (pw) => {
    if (!pw) return "empty";
    let score = 0;
    if (pw.length >= 8) score++;
    if (/[0-9]/.test(pw)) score++;
    if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
    return score >= 3 ? "strong" : "weak";
  };

  const stats = {
    total: messages.length,
    strong: messages.filter((m) => strength(m.password) === "strong").length,
    weak: messages.filter((m) => strength(m.password) === "weak").length,
    empty: messages.filter((m) => !m.password).length,
  };

  const handleLogoutClick = () => {
    if (onLogout) return onLogout();
    localStorage.removeItem("ps_user");
    window.location.reload();
  };

  // eslint-disable-next-line no-unused-vars
  const sendOtpEmail = async (userEmail, otp) => {
    // Replace with your emailjs service/template/user IDs
    const serviceId = 'service_g2e4m96';
    const templateId = 'template_h3ljzjc';
    const userId = '9aWnRByE9s2kPdMVz';
    try {
      await emailjs.send(serviceId, templateId, {
        to_email: userEmail,
        passcode: otp
      }, userId);
      add('OTP sent to your email!', 'success');
    } catch (err) {
      add('Failed to send OTP email', 'error');
      console.error('EmailJS error:', err);
    }
  };

  const openChangeModal = (msgId) => setChangeModal({ open: true, msgId });
  const closeChangeModal = () => setChangeModal({ open: false, msgId: null });
  // Reset OTP modal state when closing
  const resetOtpModal = () => {
    setEnteredOtp("");
    setOtpVerified(false);
    setNewPassword("");
    setOtpRequested(false);
    setOtpTimer(0);
  };
  const closeChangeModalAndReset = () => {
    closeChangeModal();
    resetOtpModal();
  };

  const handleRequestOtp = async () => {
    setOtpRequested(true);
    setOtpTimer(30);
    // Request OTP from backend
    const msgId = changeModal.msgId;
    const token = user && user.token ? user.token : (localStorage.getItem('ps_user') ? JSON.parse(localStorage.getItem('ps_user')).token : null);
    try {
      const res = await fetch(`${apiBase}/messages/${msgId}/request-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }
      });
      const data = await res.json();
      if (!res.ok) {
        add(data.error || 'Failed to request OTP', 'error');
        return;
      }
      add('OTP sent to your email!', 'success');
    } catch (err) {
      add('Failed to request OTP', 'error');
      console.error('OTP request error:', err);
    }
  };

  useEffect(() => {
    let timer;
    if (otpRequested && otpTimer > 0) {
      timer = setTimeout(() => setOtpTimer(otpTimer - 1), 1000);
    }
    return () => clearTimeout(timer);
  }, [otpRequested, otpTimer]);

  // Example usage: sendOtpEmail('user@example.com', '123456');
  // Call this when user requests OTP in the change password modal.

  return (
    <div className="app-wrapper">
      <header className="header">
        <div className="logo">🔒 Cryptix</div>
        <nav className="nav-links">
          <button onClick={(e)=>{e.preventDefault(); setActivePage('home')}}>Home</button>
          <button onClick={(e)=>{e.preventDefault(); setActivePage('user')}}>User</button>
          <button onClick={(e)=>{e.preventDefault(); handleLogoutClick()}}>Logout</button>
        </nav>
      </header>

      <div className="app-layout">
        <aside className="sidebar">
          <h2>🔐 Cryptix</h2>
          <ul>
            <li>Passwords</li>
          </ul>
        </aside>

        <main className="main-content">
          {activePage === 'home' && (
            <>
              <h2>Password Manager</h2>

              <form onSubmit={handleSubmit}>
            <label>Website / App</label>
            <input
              type="text"
              value={formData.text}
              onChange={(e) => setFormData({ ...formData, text: e.target.value })}
              placeholder="e.g. github.com"
            />

            <label>Email</label>
            <input
              type="email"
              value={formData.email}
              onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              placeholder="Enter email for OTP"
              required
            />

            <label>Password</label>
            <input
              type="password"
              value={formData.password}
              onChange={(e) => setFormData({ ...formData, password: e.target.value })}
              placeholder="Enter password"
            />

            <button type="submit">Save</button>
          </form>

            <div className="controls">
            <div className="search-input">
              <input
                placeholder="Search by site or email..."
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
            </div>
            <button type="button" className="small-btn" onClick={fetchMessages}>Refresh</button>
          </div>

          <div className="saved-entries">
            <h3>Saved Entries</h3>
            {filtered.length === 0 && <div className="empty">No entries yet.</div>}

            {filtered.map((msg) => (
              <div className="saved-entry" key={msg._id}>
                <div className="entry-row">
                  <div>
                    <div style={{ fontWeight: 700 }}>{msg.text}</div>
                    <div className="entry-meta">{msg.email || "—"}</div>
                  </div>
                  <div className="entry-meta">{new Date(msg.createdAt).toLocaleString()}</div>
                </div>

                <div className="password-text">
                  {visiblePasswords[String(msg._id)] ? msg.password : msg.password ? "*".repeat(msg.password.length) : "—"}
                </div>

                <div className="entry-actions">
                  <button type="button" className="action-btn btn-show" onClick={() => toggleShow(msg._id)}>{visiblePasswords[String(msg._id)] ? 'Hide' : 'Show'}</button>
                  <button type="button" className="action-btn btn-copy" onClick={() => copyToClipboard(msg.password || '')}>Copy</button>
                  <button type="button" className="action-btn btn-change" onClick={() => openChangeModal(msg._id)}>Change</button>
                  <button type="button" className="action-btn btn-delete" onClick={() => handleDelete(msg._id)}>Delete</button>
                </div>
              </div>
            ))}
          </div>
            </>
          )}

          {activePage === 'user' && (
            <div>
              <h2>User Stats</h2>
              <div style={{display:'flex',gap:16,marginBlockStart:12}}>
                <div style={{padding:16,background:'#fff',borderRadius:12,boxShadow:'0 6px 16px rgba(15,23,42,0.06)'}}> 
                  <div style={{fontSize:20,fontWeight:700}}>{stats.total}</div>
                  <div className="entry-meta">Total entries</div>
                </div>
                <div style={{padding:16,background:'#fff',borderRadius:12,boxShadow:'0 6px 16px rgba(15,23,42,0.06)'}}> 
                  <div style={{fontSize:20,fontWeight:700,color:'#10b981'}}>{stats.strong}</div>
                  <div className="entry-meta">Strong passwords</div>
                </div>
                <div style={{padding:16,background:'#fff',borderRadius:12,boxShadow:'0 6px 16px rgba(15,23,42,0.06)'}}> 
                  <div style={{fontSize:20,fontWeight:700,color:'#f97316'}}>{stats.weak}</div>
                  <div className="entry-meta">Weak passwords</div>
                </div>
              </div>
            </div>
          )}
            {/* global toasts */}
            {toasts && toasts.length > 0 && (
              <div className="toast-container" aria-live="polite">
                {toasts.map(t => (
                  <div key={t.id} className={`toast ${t.type}`}>{t.message}</div>
                ))}
              </div>
            )}

            {/* Change Password Modal */}
{changeModal.open && (
  <div className="modal-overlay" style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.3)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
  <div className="modal-content" style={{ background: '#fff', padding: 32, borderRadius: 8, minWidth: 320, boxShadow: '0 2px 16px rgba(0,0,0,0.15)' }}>
      <h3>Change Password</h3>
      <p>To change your password, request an OTP to your email.</p>
      <div style={{ display: 'flex', gap: 16, marginTop: 24, marginBottom: 16 }}>
        <button
          className="action-btn btn-otp"
          onClick={handleRequestOtp}
          disabled={otpRequested && otpTimer > 0}
        >
          {otpRequested ? `Resend OTP (${otpTimer}s)` : 'Request OTP'}
        </button>
  <button className="action-btn btn-cancel" onClick={closeChangeModalAndReset}>Cancel</button>
      </div>
      {!otpVerified ? (
        <>
          <div style={{ marginBottom: 16 }}>
            <label htmlFor="otp-input">Enter 6-digit OTP:</label>
            <input
              id="otp-input"
              type="text"
              maxLength={6}
              pattern="\d{6}"
              value={enteredOtp}
              onChange={e => setEnteredOtp(e.target.value.replace(/[^0-9]/g, ""))}
              style={{ fontSize: 18, letterSpacing: 4, padding: 8, width: 120, textAlign: 'center' }}
              placeholder="------"
            />
          </div>
          <div style={{ display: 'flex', gap: 16, marginBottom: 8 }}>
            <button
              className="action-btn btn-confirm"
              onClick={async () => {
                if (!enteredOtp || enteredOtp.length !== 6) {
                  add('Please enter a valid 6-digit OTP', 'error');
                  return;
                }
                const msgId = changeModal.msgId;
                const token = user && user.token ? user.token : (localStorage.getItem('ps_user') ? JSON.parse(localStorage.getItem('ps_user')).token : null);
                let res, data;
                try {
                  res = await fetch(`${apiBase}/messages/${msgId}/change-password`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
                    body: JSON.stringify({ otp: enteredOtp })
                  });
                  data = await res.json();
                } catch (err) {
                  add('Network error', 'error');
                  console.error('OTP confirm error:', err);
                  return;
                }
                if (!res.ok) {
                  add(data.error || 'OTP verification failed', 'error');
                  console.error('OTP confirm failed:', data);
                  return;
                }
                setOtpVerified(true);
                add('OTP verified! Enter new password.', 'success');
              }}
              disabled={enteredOtp.length !== 6}
            >
              Confirm
            </button>
          </div>
        </>
      ) : (
        <>
          <div style={{ marginBottom: 16 }}>
            <label htmlFor="new-password">New Password:</label>
            <input
              id="new-password"
              type="password"
              value={newPassword}
              onChange={e => setNewPassword(e.target.value)}
              style={{ fontSize: 18, padding: 8, width: 180, textAlign: 'center' }}
              placeholder="Enter new password"
            />
          </div>
          <div style={{ display: 'flex', gap: 16, marginBottom: 8 }}>
            <button
              className="action-btn btn-confirm"
              onClick={async () => {
                if (!newPassword) {
                  add('Please enter a new password', 'error');
                  return;
                }
                const msgId = changeModal.msgId;
                const token = user && user.token ? user.token : (localStorage.getItem('ps_user') ? JSON.parse(localStorage.getItem('ps_user')).token : null);
                let res, data;
                try {
                  res = await fetch(`${apiBase}/messages/${msgId}/change-password`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
                    body: JSON.stringify({ newPassword })
                  });
                  data = await res.json();
                } catch (err) {
                  add('Network error', 'error');
                  console.error('Password update error:', err);
                  return;
                }
                if (!res.ok) {
                  add(data.error || 'Password update failed', 'error');
                  console.error('Password update failed:', data);
                  return;
                }
                add('Password changed successfully!', 'success');
                closeChangeModalAndReset();
                fetchMessages();
              }}
              disabled={!newPassword}
            >
              Save Password
            </button>
          </div>
        </>
      )}
    </div>
  </div>
)}
        </main>
      </div>
    </div>
  );
}

export default MessageApp;
