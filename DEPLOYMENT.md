# Deploy Incident Management Live with OAuth

This guide gets your app on a **public URL** so anyone can open it and sign in with **OAuth** (Google, Azure AD, or another provider). Recommended host: **Streamlit Community Cloud** (free).

---

## 1. Push your app to GitHub

1. Create a new repository on [GitHub](https://github.com/new) (e.g. `incident-management`).
2. From your project folder:

   ```bash
   git init
   git add app.py modules/ config/ requirements.txt .streamlit/ .env.example .gitignore
   git commit -m "Incident Management app with OAuth"
   git branch -M main
   git remote add origin https://github.com/YOUR_USERNAME/incident-management.git
   git push -u origin main
   ```

   Do **not** add `.env` or `database/*.db` (they are in `.gitignore`).

---

## 2. Create OAuth credentials (choose one provider)

Your **redirect URI** will be your **live app URL** (you get this in step 3). Use the exact URL Streamlit Cloud gives you, e.g. `https://yourapp.streamlit.app/`.

### Option A: Google OAuth (good for “Sign in with Google”)

1. Go to [Google Cloud Console](https://console.cloud.google.com/) and create or select a project.
2. **APIs & Services** → **Credentials** → **Create credentials** → **OAuth client ID**.
3. Application type: **Web application**.
4. **Authorized redirect URIs**: add your **live app URL** (from step 3), e.g.  
   `https://incident-management-xxxx.streamlit.app/`  
   (same as `OAUTH_REDIRECT_URI` you’ll set in Streamlit secrets).
5. Copy the **Client ID** and **Client secret**.

### Option B: Azure AD (Microsoft Entra ID)

1. In [Azure Portal](https://portal.azure.com/) go to **Microsoft Entra ID** → **App registrations** → **New registration**.
2. Set **Redirect URI** to **Web** and your live app URL, e.g.  
   `https://incident-management-xxxx.streamlit.app/`
3. After creation: **Certificates & secrets** → New client secret. Copy **Client ID**, **Tenant ID**, and **Client secret**.

---

## 3. Deploy on Streamlit Community Cloud

1. Go to [share.streamlit.io](https://share.streamlit.io) and sign in with GitHub.
2. **New app**:
   - **Repository**: `YOUR_USERNAME/incident-management`
   - **Branch**: `main`
   - **Main file path**: `app.py`
3. Click **Advanced settings** and add your **Secrets** (environment variables). You can paste TOML or use the form. Example for **Google**:

   ```toml
   ENV = "production"
   OAUTH_PROVIDER = "google"
   OAUTH_REDIRECT_URI = "https://YOUR-APP-NAME.streamlit.app/"
   SESSION_SECRET_KEY = "your-long-random-secret-at-least-32-characters"
   GOOGLE_CLIENT_ID = "your-google-client-id"
   GOOGLE_CLIENT_SECRET = "your-google-client-secret"
   SESSION_TIMEOUT_MINUTES = "60"
   ADMIN_USERS = "admin@yourdomain.com"
   # Optional: AI incident intake and formal reports (either key enables; Anthropic preferred if both set)
   # ANTHROPIC_API_KEY = "your-anthropic-api-key"
   # OPENAI_API_KEY = "your-openai-api-key"
   ```

   **Important:** Replace `https://YOUR-APP-NAME.streamlit.app/` with the **exact** URL Streamlit shows for your app (e.g. after first deploy). Then in Google (or Azure) set that **exact** URL as the redirect URI.

4. Deploy. Wait for the app to build and open the URL (e.g. `https://incident-management-xxxx.streamlit.app/`).
5. In Google (or Azure) set the **Authorized redirect URI** to that **exact** URL (with trailing `/` if you use it in secrets).
6. If you had to change `OAUTH_REDIRECT_URI` after seeing the real URL, update the app’s **Secrets** in Streamlit Cloud and redeploy.

---

## 4. Production behaviour

- **ENV=production** turns off demo login; only OAuth is allowed.
- **OAUTH_REDIRECT_URI** must match the **live app URL** and what you registered in Google/Azure.
- **SESSION_SECRET_KEY** must be set (long random string); the app uses it for signing and encryption.
- Users open the public link → **Sign in** → redirect to Google (or Azure) → after login they return to your app and see the dashboard.
- **Optional:** Set **either** `ANTHROPIC_API_KEY` **or** `OPENAI_API_KEY` in Secrets to enable the smart incident flow (one summary → AI classifies, assigns risk/escalation, and generates a report with root cause and mitigating actions). If both are set, Anthropic is used. If neither is set, the manual incident form and reports still work.

---

## 5. Optional: custom domain and other hosts

- **Streamlit Cloud**: Use the default `*.streamlit.app` URL as above. Custom domains are a paid feature.
- **Railway / Render / other**: Deploy the same repo, set the same env vars, and set **OAUTH_REDIRECT_URI** to your app’s root URL (e.g. `https://yourapp.up.railway.app/`). Register that exact URL as the redirect URI in your OAuth provider.

---

## Checklist

- [ ] Code pushed to GitHub (no `.env` or `*.db`).
- [ ] OAuth app created (Google or Azure) with **redirect URI = live app URL**.
- [ ] Streamlit Cloud app created, **Secrets** set (`ENV`, `OAUTH_PROVIDER`, `OAUTH_REDIRECT_URI`, `SESSION_SECRET_KEY`, provider credentials).
- [ ] `OAUTH_REDIRECT_URI` matches the app URL and the OAuth provider’s redirect URI.
- [ ] After deploy, open the public URL and use **Sign in** to test OAuth.
