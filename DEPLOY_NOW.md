# Deploy now – step-by-step

Do these in order. Steps 2–4 require your browser and accounts.

---

## Step 1: Push this folder to GitHub (you need Git installed)

**If Git is not installed:** Install from https://git-scm.com/download/win or run in PowerShell (as Admin):  
`winget install Git.Git`

**Then in a new terminal** (so Git is on PATH), from this project folder:

```powershell
cd "g:\My Drive\Cursor Folders\projects\c-Users-temp8-Incident-Management"

git init
git add app.py modules config requirements.txt .streamlit .env.example .gitignore README.md DEPLOYMENT.md DEPLOY_NOW.md tests run_tests.bat
git commit -m "Incident Management with OAuth - ready for deployment"

# Create a NEW empty repo on GitHub (page may already be open: github.com/new, name: incident-management).
# Do NOT add a README or .gitignore (we already have them). Create repository.
# Then run (replace YOUR_USERNAME and YOUR_REPO with your GitHub username and repo name):
git remote set-url origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git push -u origin main
```
If this is the first time: `git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git` then `git push -u origin main`.

---

## Step 2: Create Google OAuth credentials

1. Open: **https://console.cloud.google.com/**
2. Create or select a project → **APIs & Services** → **Credentials**
3. **Create credentials** → **OAuth client ID**
4. If asked, configure **OAuth consent screen** (External, add your email as test user).
5. Application type: **Web application**
6. **Authorized redirect URIs** → **Add URI**  
   Use your Streamlit app URL from **Step 4** (e.g. `https://yourrepo-incident-management-xxxx.streamlit.app/`).  
   You can add this **after** your first deploy and then edit the OAuth client to add the URI.
7. Copy **Client ID** and **Client secret** (you’ll paste them in Step 4).

---

## Step 3: Deploy on Streamlit Community Cloud

1. Open: **https://share.streamlit.io**
2. Sign in with **GitHub**
3. **New app**
   - Repository: **YOUR_USERNAME/YOUR_REPO**
   - Branch: **main**
   - Main file path: **app.py**
4. Click **Advanced settings** and open **Secrets**
5. Paste the contents of **`.streamlit/secrets.toml.example`** into the Secrets box, then:
   - Replace `OAUTH_REDIRECT_URI` with the **exact** app URL Streamlit shows (e.g. `https://yourrepo-incident-management-xxxx.streamlit.app/`)
   - Replace `SESSION_SECRET_KEY` with a long random string (e.g. from https://randomkeygen.com/)
   - Replace `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` with the values from Step 2
   - Replace `ADMIN_USERS` with your admin email
6. Click **Deploy**. Wait for the app to build and open.

---

## Step 4: Set redirect URI in Google

1. Note your app URL from Streamlit (e.g. `https://incident-management-xxxx.streamlit.app/`)
2. In Google Cloud Console → **Credentials** → your OAuth client → **Edit**
3. Under **Authorized redirect URIs**, add that **exact** URL (with trailing `/` if you used it in secrets)
4. Save

If you had to change `OAUTH_REDIRECT_URI` in Streamlit secrets, go to your app → **Settings** → **Secrets**, update it, and **Reboot app**.

---

## Step 5: Test

Open your app URL. Click **Sign in** → you should be redirected to Google → sign in → back to the app dashboard. Share the app URL with your team; they can sign in with their Google accounts (if allowed by your OAuth consent screen).
