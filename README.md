# Incident Management (Secure OAuth)

**Deploy live with OAuth:** See **[DEPLOYMENT.md](DEPLOYMENT.md)** for putting the app on a public URL (e.g. Streamlit Community Cloud) so anyone can open it and sign in with Google or Azure AD.

Security-hardened OAuth implementation per the OAuth Security Audit plan.

## Security measures implemented

- **No unverified JWT decoding** – No Firebase or other path that accepts unverified JWTs.
- **OAuth state + PKCE in backend store** – State and `code_verifier` are stored in SQLite (`database/auth_store.db`) and consumed on callback; survives redirects and multi-worker.
- **PKCE** – All OAuth flows (Azure AD, Google, OIDC) use `code_challenge` / `code_challenge_method=S256` and `code_verifier` in the token request.
- **Firebase one-time code** – If using Firebase, tokens are never passed in the URL; use `create_firebase_code_for_user_info` and `exchange_firebase_code_for_session` (verify ID token server-side first).
- **SESSION_SECRET_KEY** – Required when OAuth is configured; used for signing state and encrypting tokens. No random default in production.
- **Redirect URI validation** – Callback can validate `request_url` against `OAUTH_REDIRECT_URI`.
- **Demo mode only when not production** – `ENV=production` requires OAuth; demo login is disabled.
- **Encrypted token storage** – Tokens in session are encrypted with Fernet (key derived from `SESSION_SECRET_KEY`).
- **Token refresh** – Providers implement `refresh_token()`; session can refresh access tokens before expiry.
- **OIDC nonce** – Nonce is sent in authorization requests and stored with state.
- **Generic error messages** – Users see “Authentication failed”; details are logged server-side.
- **Permission config cached** – `oauth_config.json` roles are loaded once and cached.
- **Rate limiting** – Login and callback are rate-limited per key (e.g. per host) via `auth_store`.

## Run locally

1. Copy `.env.example` to `.env` and set at least:
   - `ENV=development` (or `production` with OAuth configured)
   - For OAuth: `OAUTH_PROVIDER`, provider credentials, and `SESSION_SECRET_KEY`
2. Install: `pip install -r requirements.txt`
3. Run: `streamlit run app.py`

With no OAuth configured and `ENV=development`, the app uses demo login. For production, set `ENV=production` and configure OAuth and `SESSION_SECRET_KEY`.

**Optional – AI incident intake and formal reports:** Set **either** `ANTHROPIC_API_KEY` **or** `OPENAI_API_KEY` (in `.env` or Streamlit Secrets) to enable the smart flow: one summary + jurisdiction → AI classifies, assigns risk and escalation, and generates a formal report (summary, root cause, mitigating actions from the decision tree). If both keys are set, Anthropic is used. If neither is set, the app works with the manual form only.

## Run tests

From the project root (with Python and dependencies installed):

```bash
python tests/test_auth.py
```

Or with pytest:

```bash
pip install pytest
python -m pytest tests/test_auth.py -v
```

Tests cover: auth_store (OAuth state/PKCE save–consume, Firebase one-time code, rate limiting), PKCE/sign helpers, AuthConfig, get_auth_manager (demo vs production), demo login/logout, OAuth login URL and state cookie, and token encrypt/decrypt. No live OAuth provider is required.
