import React, { useState, useEffect } from "react";
import "./MessageApp.css";
import { useToasts } from './components/ToastProvider';

function MessageApp({ onLogout, user }) {
  const [formData, setFormData] = useState({ text: "", email: "", password: "" });
  const [messages, setMessages] = useState([]);
  const [query, setQuery] = useState("");
  const [activePage, setActivePage] = useState("home");

  useEffect(() => {
    fetchMessages();
  }, []);
  const { toasts, add, remove } = useToasts();

  const fetchMessages = async () => {
    try {
      const token = user && user.token ? user.token : (localStorage.getItem('ps_user') ? JSON.parse(localStorage.getItem('ps_user')).token : null);
      const res = await fetch("http://localhost:5000/messages", { headers: token ? { Authorization: `Bearer ${token}` } : {} });
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
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!formData.text || !formData.email || !formData.password) {
      alert("Please fill all fields!");
      return;
    }
    try {
      const token = user && user.token ? user.token : (localStorage.getItem('ps_user') ? JSON.parse(localStorage.getItem('ps_user')).token : null);
      const res = await fetch("http://localhost:5000/messages", {
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
      setFormData({ text: "", email: "", password: "" });
    } catch (error) {
      console.error("Error saving message:", error);
      add('Save failed', 'error');
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm("Delete this entry?")) return;
    try {
      const token = user && user.token ? user.token : (localStorage.getItem('ps_user') ? JSON.parse(localStorage.getItem('ps_user')).token : null);
      const res = await fetch(`http://localhost:5000/messages/${id}`, { method: "DELETE", headers: token ? { Authorization: `Bearer ${token}` } : {} });
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

  return (
    <div className="app-wrapper">
      <header className="header">
        <div className="logo">🔒 Cryptix</div>
        <nav className="nav-links">
          <a href="#" onClick={(e)=>{e.preventDefault(); setActivePage('home')}}>Home</a>
          <a href="#" onClick={(e)=>{e.preventDefault(); setActivePage('user')}}>User</a>
          <a href="#" onClick={(e)=>{e.preventDefault(); handleLogoutClick()}}>Logout</a>
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
              placeholder="you@company.com"
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
        </main>
      </div>
    </div>
  );
}

export default MessageApp;
