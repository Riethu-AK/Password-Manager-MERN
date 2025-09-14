import React, { useState, useEffect } from 'react';
import './AdminDashboard.css';

const AdminDashboard = ({ token, onLogout }) => {
  const [dashboardData, setDashboardData] = useState(null);
  const [selectedUser, setSelectedUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchDashboardData();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      const response = await fetch('http://localhost:5000/admin/dashboard', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (response.ok) {
        const data = await response.json();
        setDashboardData(data);
      } else {
        const errorData = await response.json();
        setError(errorData.error || 'Failed to fetch dashboard data');
      }
    } catch (err) {
      setError('Network error: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const fetchUserDetails = async (userId) => {
    try {
      const response = await fetch(`http://localhost:5000/admin/users/${userId}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (response.ok) {
        const data = await response.json();
        setSelectedUser(data);
      } else {
        const errorData = await response.json();
        setError(errorData.error || 'Failed to fetch user details');
      }
    } catch (err) {
      setError('Network error: ' + err.message);
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'Never';
    return new Date(dateString).toLocaleString();
  };

  if (loading) {
    return <div className="admin-dashboard loading">Loading admin dashboard...</div>;
  }

  if (error) {
    return (
      <div className="admin-dashboard error">
        <h2>Error</h2>
        <p>{error}</p>
        <button onClick={fetchDashboardData}>Retry</button>
        <button onClick={onLogout}>Logout</button>
      </div>
    );
  }

  return (
    <div className="admin-dashboard">
      <header className="admin-header">
        <h1>🛡️ Admin Dashboard</h1>
        <button onClick={onLogout} className="logout-btn">Logout</button>
      </header>

      {/* Stats Overview */}
      <div className="stats-grid">
        <div className="stat-card">
          <h3>Total Users</h3>
          <p className="stat-number">{dashboardData.stats.totalUsers}</p>
        </div>
        <div className="stat-card">
          <h3>Total Passwords</h3>
          <p className="stat-number">{dashboardData.stats.totalMessages}</p>
        </div>
        <div className="stat-card">
          <h3>Active Users</h3>
          <p className="stat-number">{dashboardData.stats.activeUsers}</p>
        </div>
        <div className="stat-card">
          <h3>Orphaned Passwords</h3>
          <p className="stat-number">{dashboardData.stats.orphanedMessages}</p>
        </div>
      </div>

      <div className="dashboard-content">
        {/* Users List */}
        <div className="users-section">
          <h2>All Users</h2>
          <div className="users-table">
            <table>
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Passwords</th>
                  <th>Login Count</th>
                  <th>Last Login</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {dashboardData.users.map(user => (
                  <tr key={user._id}>
                    <td>{user.username}</td>
                    <td>{user.email}</td>
                    <td>
                      <span className={`role-badge ${user.role}`}>
                        {user.role}
                      </span>
                    </td>
                    <td>{user.messageCount}</td>
                    <td>{user.loginCount || 0}</td>
                    <td>{formatDate(user.lastLogin)}</td>
                    <td>{formatDate(user.createdAt)}</td>
                    <td>
                      <button 
                        onClick={() => fetchUserDetails(user._id)}
                        className="view-btn"
                      >
                        View Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Recent Activity */}
        <div className="activity-section">
          <div className="recent-logins">
            <h3>Recent Logins</h3>
            <ul>
              {dashboardData.recentActivity.logins.map((login, index) => (
                <li key={index}>
                  <strong>{login.username}</strong> - {formatDate(login.lastLogin)}
                </li>
              ))}
            </ul>
          </div>

          <div className="recent-passwords">
            <h3>Recent Password Saves</h3>
            <ul>
              {dashboardData.recentActivity.messages.map((msg, index) => (
                <li key={index}>
                  <strong>{msg.owner?.username || 'Unknown'}</strong> saved password for {msg.email} - {formatDate(msg.createdAt)}
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      {/* User Details Modal */}
      {selectedUser && (
        <div className="modal-overlay" onClick={() => setSelectedUser(null)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <h2>User Details: {selectedUser.user.username}</h2>
            <div className="user-details">
              <p><strong>Email:</strong> {selectedUser.user.email}</p>
              <p><strong>Role:</strong> {selectedUser.user.role}</p>
              <p><strong>Login Count:</strong> {selectedUser.user.loginCount || 0}</p>
              <p><strong>Last Login:</strong> {formatDate(selectedUser.user.lastLogin)}</p>
              <p><strong>Created:</strong> {formatDate(selectedUser.user.createdAt)}</p>
              <p><strong>Total Passwords:</strong> {selectedUser.messageCount}</p>
            </div>
            
            <h3>User's Passwords</h3>
            <div className="user-messages">
              {selectedUser.messages.length > 0 ? (
                <table>
                  <thead>
                    <tr>
                      <th>Website/App</th>
                      <th>Email/Username</th>
                      <th>Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selectedUser.messages.map(msg => (
                      <tr key={msg._id}>
                        <td>{msg.text}</td>
                        <td>{msg.email}</td>
                        <td>{formatDate(msg.createdAt)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <p>No passwords saved yet.</p>
              )}
            </div>
            
            <button onClick={() => setSelectedUser(null)} className="close-btn">
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default AdminDashboard;
