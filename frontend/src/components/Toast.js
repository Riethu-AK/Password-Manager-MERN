import React, { useEffect } from 'react';
import './Toast.css';

function Toast({ id, message, type = 'info', duration = 4000, onClose }) {
  useEffect(() => {
    const t = setTimeout(() => onClose && onClose(id), duration);
    return () => clearTimeout(t);
  }, [id, duration, onClose]);

  return (
    <div className={`toast ${type}`} role="status" aria-live="polite">
      <div className="toast-body">{message}</div>
      <button className="toast-close" onClick={() => onClose && onClose(id)} aria-label="close">×</button>
    </div>
  );
}

export default Toast;
