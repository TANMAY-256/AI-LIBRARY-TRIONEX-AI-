# Trionex AI — Setup Guide

A complete **Trionex AI** website built with **HTML, CSS, and JavaScript** only. It includes login/signup, a premium dashboard, and working tools powered by real APIs.

---

## 📁 Folder Structure

```
/
├── index.html      → Login & Sign up page
├── dashboard.html  → Main AI dashboard (after login)
├── style.css       → All styling (glassmorphism, gradients, responsive)
├── script.js       → Auth, AI APIs, background remover, video-to-audio
├── server.js       → GitHub OAuth proxy (run for GitHub login)
└── README.md       → This file
```

---

## 🚀 How to Run Locally

1. **Get the code**  
   Ensure all files (`index.html`, `dashboard.html`, `style.css`, `script.js`) are in one folder.

2. **Open the app**  
   - **Option A:** Double-click `index.html` to open it in your default browser.  
   - **Option B:** Use a local server (recommended for some APIs):
     - If you have **Node.js:** run `npx serve .` in the project folder, then open `http://localhost:3000`.
     - If you have **Python 3:** run `python -m http.server 8000` in the project folder, then open `http://localhost:8000`.

3. **Sign up**  
   Use the “Sign Up” tab to create an account (email + password). User data is stored in the browser’s **Local Storage**.

4. **Log in**  
   After signup you are redirected to the dashboard. Next time, use the “Log In” tab with the same email and password.

5. **Use the tools**  
   Add your API keys (see below), then use AI Chatbot, Code Explainer, Code Generator, AI Assistant, Background Remover, and Video to MP3 from the sidebar.

---

## 🔑 Adding API Keys

The app needs API keys for AI and background removal. You can set them in code or via the browser console.

### Method 1: Edit `script.js`

At the top of `script.js` you’ll see:

```javascript
AILibrary.config = {
  geminiKey: localStorage.getItem('ai_library_gemini_key') || '',  // ← primary for AI tools
  removeBgKey: localStorage.getItem('ai_library_removebg_key') || '',
  openaiKey: localStorage.getItem('ai_library_openai_key') || '',  // optional fallback
  useGemini: true   // true = Gemini (default). Set false to use OpenAI
};
```

- Set **Gemini** (used for Chatbot, Code Explainer, Code Generator, AI Assistant):
  - Replace the empty string for `geminiKey` with your key, e.g.  
    `geminiKey: 'your-gemini-api-key-here',`
- Set **Remove.bg** (for Image Background Remover):
  - Replace the empty string for `removeBgKey` with your key, e.g.  
    `removeBgKey: 'your-removebg-key-here',`
- Optional **OpenAI**: set `openaiKey` and `useGemini: false` to use OpenAI instead of Gemini for AI features.

Save the file and refresh the page.

### Method 2: Live Server only (no Node server)

If you open the app with **Live Server** (e.g. port 5501) and do **not** run `node server.js`, add your Gemini key in **script.js** at the top:

```javascript
var GEMINI_KEY_FALLBACK = 'your-gemini-api-key-here';
```

Save and refresh. The chatbot will use this key. (You can copy the value from your `.env` file.)

### Method 3: Browser console (Local Storage)

1. Open the site in your browser.
2. Press **F12** (or right-click → Inspect) and go to the **Console** tab.
3. Run (replace with your real keys):

```javascript
localStorage.setItem('ai_library_gemini_key', 'your-gemini-api-key-here');
localStorage.setItem('ai_library_removebg_key', 'your-removebg-key-here');
```

4. Refresh the page. The app reads these keys on load.

### Method 4: `.env` file (recommended when using Node server)

1. Copy `.env.example` to `.env` in the project folder.
2. Edit `.env` and add your keys (no quotes needed):
   ```
   GEMINI_KEY=your-gemini-api-key-here
   REMOVEBG_KEY=your-removebg-key-here
   ```
3. **Start the Node server** (required for `.env` keys). In the project folder run:
   ```bash
   node server.js
   ```
   Leave it running.
4. Open the dashboard: either **http://localhost:3001/dashboard.html** or your usual Live Server URL (e.g. 5501). The app will load API keys from `.env` via the Node server. Do not commit `.env`; it is in `.gitignore`.

### Where to get keys

| Feature              | Key used   | Where to get it |
|----------------------|-----------|------------------|
| AI (all 4 tools)     | Gemini    | [aistudio.google.com](https://aistudio.google.com/app/apikey) — create an API key. |
| Optional AI (OpenAI)| OpenAI    | [platform.openai.com](https://platform.openai.com/api-keys) — use if `useGemini: false`. |
| Background Remover   | Remove.bg | [remove.bg](https://www.remove.bg/api) — sign up; free tier has a limited number of calls/month. |

---

## 🔐 Social Login (Google, Facebook, GitHub) — Where to Get Client IDs

Social login is **optional**. If you don’t add these, you can still sign in with email and password. To enable “Log in with Google / Facebook / GitHub”, get the credentials below and add them in `script.js` or via the browser console.

### Google (Client ID)

1. Go to **[Google Cloud Console → APIs & Services → Credentials](https://console.cloud.google.com/apis/credentials)**.
2. Sign in with your Google account.
3. Click **“Create Credentials”** → **“OAuth client ID”**.
4. If asked, set the **OAuth consent screen** (User type: External, add your email, app name, save).
5. Application type: **“Web application”**.
6. **Name:** e.g. `Trionex AI`.
7. Under **“Authorized JavaScript origins”** add: `http://127.0.0.1:5500`, `http://localhost:3000`, or your site URL.
8. Under **“Authorized redirect URIs”** add: `http://127.0.0.1:5500/callback.html` (or your site + `/callback.html`).
9. Click **Create**. Copy the **Client ID** (looks like `xxxxx.apps.googleusercontent.com`).
10. In `script.js`, set:  
    `googleClientId: 'YOUR_CLIENT_ID_HERE',`  
    Or in the browser console:  
    `localStorage.setItem('ai_library_google_client_id', 'YOUR_CLIENT_ID_HERE');` then refresh.

### Facebook (App ID)

1. Go to **[developers.facebook.com](https://developers.facebook.com)** and sign in.
2. **My Apps** → **Create App** → choose **“Consumer”** (or “Other”) → name it (e.g. Trionex AI) → Create.
3. In the app dashboard, go to **Facebook Login** → **Settings** (under “Products”).
4. Under **“Valid OAuth Redirect URIs”** add your site URL, e.g. `http://127.0.0.1:5500/` or `https://yoursite.com/`.
5. Save. Copy the **App ID** from the dashboard (top of the page).
6. In `script.js`, set:  
   `facebookAppId: 'YOUR_APP_ID_HERE',`  
   Or in the console:  
   `localStorage.setItem('ai_library_facebook_app_id', 'YOUR_APP_ID_HERE');` then refresh.

### GitHub (Client ID)

1. Go to **[GitHub → Settings → Developer settings → OAuth Apps](https://github.com/settings/developers)** (or [github.com/settings/developers](https://github.com/settings/developers)).
2. Click **“New OAuth App”**.
3. **Application name:** e.g. Trionex AI.  
   **Homepage URL:** e.g. `http://127.0.0.1:5500` or your site URL.  
   **Authorization callback URL:** must be exactly where your app is hosted + `/callback.html`, e.g.  
   `http://127.0.0.1:5500/callback.html` or `https://yoursite.com/callback.html`.
4. Register. Copy **Client ID** and **Generate a new client secret** (copy that too).
5. In `script.js`, set `githubClientId: 'YOUR_CLIENT_ID_HERE',`
6. **Run the server** (new terminal): `set GITHUB_CLIENT_ID=yourid&& set GITHUB_CLIENT_SECRET=yoursecret&& node server.js` (Windows) or `GITHUB_CLIENT_ID=yourid GITHUB_CLIENT_SECRET=yoursecret node server.js` (Mac/Linux). Leave it running.
7. Refresh your app and click **Log in with GitHub**.

**Note for GitHub:** Completing the sign-in (exchanging the code for a user) requires a small server or serverless function that has your GitHub **Client Secret**. The app’s `callback.html` is set up to work with such a backend; Run `server.js` with your Client ID and Client Secret (step 6).

---

## 📋 Features Overview

| Feature              | What it does |
|----------------------|--------------|
| **Login & Signup**   | Create account and log in. Data stored in Local Storage. Redirects to dashboard after login. |
| **AI Chatbot**       | Send messages and get real-time AI replies (Gemini by default, or OpenAI if configured). |
| **Code Explainer**   | Paste code; AI explains it in simple language. |
| **Code Generator**   | Describe what you need + choose language; AI generates code. Copy button copies the result. |
| **AI Assistant**     | General assistant: questions, essays, debugging, etc. |
| **Background Remover**| Upload an image; Remove.bg API removes the background; download the result. |
| **Video to MP3**     | Upload a video; the app extracts the audio in the browser. When the lamejs library is loaded (included from CDN), the download is MP3; otherwise it is WebM. |

---

## 🛠 Technical Notes

- **Auth:** Passwords are stored in Local Storage (not hashed). Use only for local/demo; for production use a proper backend and hashing.
- **AI:** Uses Gemini API by default (or OpenAI if `useGemini: false`). All requests go from the browser; keep API keys private and consider usage/costs.
- **Background removal:** Uses Remove.bg API; free tier has limits.
- **Video to audio:** Done in the browser (no server). Output is WebM audio; for MP3 use an external tool or a server-side converter.

---

## ✅ Summary

1. Put all files in one folder.
2. Open `index.html` (or run a local server and open the given URL).
3. Sign up / log in.
4. Add your Gemini key (and optionally Remove.bg) in `script.js` or via `localStorage` in the console.
5. Use the dashboard tools from the sidebar.

All features are implemented with real APIs (and client-side video-to-audio); there are no placeholder or fake demos.
