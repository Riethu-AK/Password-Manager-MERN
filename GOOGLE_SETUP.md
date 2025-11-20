# Google Sign-In Setup Guide

This guide will help you set up Google Sign-In for your Password Manager application.

## Prerequisites

1. A Google Cloud Platform (GCP) account
2. Access to the [Google Cloud Console](https://console.cloud.google.com/)

## Step 1: Create OAuth 2.0 Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Navigate to **APIs & Services** > **Credentials**
4. Click **+ CREATE CREDENTIALS** > **OAuth client ID**
5. If prompted, configure the OAuth consent screen:
   - Choose **External** (unless you have a Google Workspace)
   - Fill in the required fields (App name, User support email, Developer contact)
   - Add scopes: `email`, `profile`, `openid`
   - Add test users if your app is in testing mode
6. Create the OAuth client:
   - Application type: **Web application**
   - Name: `Password Manager Web Client`
   - Authorized JavaScript origins:
     - `http://localhost:3000` (for development)
     - `http://localhost:5000` (if serving from backend)
     - Your production domain (e.g., `https://yourdomain.com`)
   - Authorized redirect URIs:
     - `http://localhost:3000` (for development)
     - Your production domain
7. Click **Create**
8. Copy the **Client ID** (it looks like: `xxxxx.apps.googleusercontent.com`)

## Step 2: Configure Frontend

1. Create a `.env` file in the `frontend` directory:
```env
REACT_APP_API_URL=http://localhost:5000
REACT_APP_GOOGLE_CLIENT_ID=your-client-id-here.apps.googleusercontent.com
```

2. Replace `your-client-id-here.apps.googleusercontent.com` with your actual Client ID from Step 1.

3. Restart your React development server if it's running:
```bash
cd frontend
npm start
```

## Step 3: Configure Backend

1. Create a `.env` file in the `backend` directory (if it doesn't exist):
```env
MONGO_URI=mongodb://localhost:27017/password-manager
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
PORT=5000
GMAIL_USER=your-email@gmail.com
GMAIL_PASS=your-app-password
GOOGLE_CLIENT_ID=your-client-id-here.apps.googleusercontent.com
```

2. Replace `your-client-id-here.apps.googleusercontent.com` with the **same** Client ID from Step 1.

3. Restart your backend server:
```bash
cd backend
npm start
```

## Step 4: Test Google Sign-In

1. Start both frontend and backend servers
2. Navigate to the login page
3. You should see a "Sign in with Google" button
4. Click it and sign in with your Google account
5. You should be automatically logged in and redirected to the main app

## Troubleshooting

### "Google Sign-In disabled" error
- Make sure `GOOGLE_CLIENT_ID` is set in your backend `.env` file
- Restart the backend server after adding the environment variable

### "Invalid Google token" error
- Verify that the Client ID in frontend and backend `.env` files match exactly
- Check that the authorized JavaScript origins include your current URL
- Make sure you're using the same Google account that's added as a test user (if app is in testing mode)

### Google Sign-In button not showing
- Make sure `REACT_APP_GOOGLE_CLIENT_ID` is set in your frontend `.env` file
- Restart the React development server after adding the environment variable
- Check the browser console for any errors

### CORS errors
- Ensure your backend CORS settings allow requests from your frontend URL
- Check that authorized JavaScript origins in Google Console match your frontend URL

## Security Notes

- Never commit `.env` files to version control
- Use different Client IDs for development and production
- Keep your JWT_SECRET secure and use a strong random string in production
- Regularly rotate your OAuth credentials

## Production Deployment

When deploying to production:

1. Update authorized JavaScript origins and redirect URIs in Google Console to include your production domain
2. Update `.env` files with production values
3. Ensure environment variables are set in your hosting platform (Heroku, Vercel, AWS, etc.)
4. Test the Google Sign-In flow in production

