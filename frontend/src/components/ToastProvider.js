import React, { useCallback, useState } from 'react';
import Toast from './Toast';
import './Toast.css';

let idCounter = 1;

export function useToasts() {
  const [toasts, setToasts] = useState([]);
  const add = useCallback((message, type = 'info', duration = 4000) => {
    const id = idCounter++;
    setToasts((s) => [...s, { id, message, type, duration }]);
    return id;
  }, []);
  const remove = useCallback((id) => setToasts((s) => s.filter((t) => t.id !== id)), []);
  return { toasts, add, remove };
}

export default function ToastContainer({ toasts, onRemove }) {
  return (
    <div className="toast-container" aria-live="polite">
      {toasts.map(t => (
        <Toast key={t.id} id={t.id} message={t.message} type={t.type} duration={t.duration} onClose={onRemove} />
      ))}
    </div>
  );
}
