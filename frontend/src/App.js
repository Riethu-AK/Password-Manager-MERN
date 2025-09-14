import React, { useState, useEffect } from "react";
import MessageApp from "./MessageApp";
import Login from "./Login";
import AdminDashboard from "./AdminDashboard";

function App() {
  const [user, setUser] = useState(null);

  useEffect(() => {
    const raw = localStorage.getItem("ps_user");
    if (raw) {
      try {
        const parsed = JSON.parse(raw);
        // Expect an object with a token and user
        if (parsed && parsed.token) {
          setUser(parsed);
        } else {
          // clear legacy or malformed session
          localStorage.removeItem('ps_user');
        }
      } catch (err) {
        // not JSON (legacy value) - remove it
        localStorage.removeItem('ps_user');
      }
    }
  }, []);

  const handleLogin = (authResult) => {
    // authResult expected { token, user }
    if (authResult && authResult.token) {
      const payload = { token: authResult.token, user: authResult.user };
      localStorage.setItem("ps_user", JSON.stringify(payload));
      setUser(payload);
      return true;
    }
    return false;
  };

  const handleLogout = () => {
    localStorage.removeItem("ps_user");
    setUser(null);
  };

  // If user is logged in, check their role
  if (user) {
    if (user.user && user.user.role === 'admin') {
      return <AdminDashboard token={user.token} onLogout={handleLogout} />;
    } else {
      return <MessageApp onLogout={handleLogout} user={user} />;
    }
  }

  return <Login onLogin={handleLogin} />;
}

export default App;
