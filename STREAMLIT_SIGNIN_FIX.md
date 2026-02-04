# Fix "operation-not-supported-in-this-environment" on Streamlit

Firebase’s “Sign in with Google” **popup** doesn’t work when the button runs inside Streamlit’s iframe (no web storage / wrong environment). The app is set up so that **if you add Google OAuth**, it will use that instead and show a normal **“Sign in” link** that works.

## What to do

### 1. Create Google OAuth credentials (same project as Firebase is fine)

1. Open [Google Cloud Console](https://console.cloud.google.com/) and select your project (e.g. **DGX-Incident Management Tool**).
2. Go to **APIs & Services** → **Credentials**.
3. Click **Create credentials** → **OAuth client ID**.
4. If asked, complete the **OAuth consent screen** (e.g. External, add your email as test user).
5. Application type: **Web application**.
6. Under **Authorized redirect URIs**, add:
   - `https://incident-management-3ogabwegruatebfg3z58j6.streamlit.app/`
7. Create and copy the **Client ID** and **Client secret**.

### 2. Add these to Streamlit Cloud Secrets

In **Streamlit Cloud** → your app → **Settings** → **Secrets**, add (or merge with your existing secrets):

```toml
OAUTH_PROVIDER = "google"
OAUTH_REDIRECT_URI = "https://incident-management-3ogabwegruatebfg3z58j6.streamlit.app/"
GOOGLE_CLIENT_ID = "your-client-id.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "your-client-secret"
```

Keep your existing `ENV`, `SESSION_SECRET_KEY`, `ADMIN_USERS`, and Firebase keys if you like; the app will **prefer OAuth** when both are set, so the “Sign in” link will work and the Firebase environment error will stop.

### 3. Save and reboot

Save the secrets and use **Reboot app** (or wait for the next deploy). You should see **“Sign in”** (link) instead of the blue Firebase button; clicking it will take you to Google and back to the app without the iframe error.
