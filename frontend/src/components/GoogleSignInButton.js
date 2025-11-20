import React from 'react';
import { GoogleLogin } from '@react-oauth/google';

// Wrapper component that safely handles GoogleLogin
// Only use this when GoogleOAuthProvider is available
function GoogleSignInButton({ onSuccess, onError, disabled }) {
  const hasClientId = !!process.env.REACT_APP_GOOGLE_CLIENT_ID;
  
  // If no client ID, show a disabled message or nothing
  if (!hasClientId) {
    return (
      <div style={{
        padding: '12px',
        textAlign: 'center',
        background: 'rgba(255,255,255,0.05)',
        borderRadius: '8px',
        color: 'rgba(255,255,255,0.5)',
        fontSize: '12px',
        border: '1px solid rgba(255,255,255,0.1)'
      }}>
        Google Sign-In not configured
      </div>
    );
  }

  return (
    <GoogleLogin
      onSuccess={onSuccess}
      onError={onError}
      useOneTap={false}
      disabled={disabled}
      text="signin_with"
      shape="rectangular"
      theme="outline"
      size="large"
      width="100%"
    />
  );
}

export default GoogleSignInButton;

