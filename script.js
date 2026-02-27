/**
 * Trionex AI — Main logic & APIs
 */

var AILibrary = window.AILibrary || {};

// Global Error Handling
window.onerror = function (message, source, lineno, colno, error) {
  console.error("Global Catch:", message, "at", source, ":", lineno, ":", colno);
  // Optional: Display a user-friendly toast or alert
};
window.onunhandledrejection = function (event) {
  console.error("Unhandled Promise Rejection:", event.reason);
};


// =============================================================================
// 🔑 ADD YOUR API KEYS HERE — Paste your keys in the quotes below (or use localStorage)
// =============================================================================
// If you use Live Server only (no "node server.js"), paste your keys below (or leave as set from .env):
var GEMINI_KEY_FALLBACK = 
var GOOGLE_CLIENT_ID_FALLBACK = 
var GITHUB_CLIENT_ID_FALLBACK = 
// Gemini: aistudio.google.com/app/apikey  |  Remove.bg: remove.bg/api  |  OpenAI: platform.openai.com/api-keys
// =============================================================================

AILibrary.config = {
  geminiKey: localStorage.getItem('ai_library_gemini_key') || (typeof GEMINI_KEY_FALLBACK !== 'undefined' ? GEMINI_KEY_FALLBACK : ''),
  removeBgKey: localStorage.getItem('ai_library_removebg_key') || 
  openaiKey: localStorage.getItem('ai_library_openai_key') || '',
  useGemini: true,
  serverAvailable: true,
  googleClientId: localStorage.getItem('ai_library_google_client_id') || (typeof GOOGLE_CLIENT_ID_FALLBACK !== 'undefined' ? GOOGLE_CLIENT_ID_FALLBACK : ''),

  githubClientId: localStorage.getItem('ai_library_github_client_id') || (typeof GITHUB_CLIENT_ID_FALLBACK !== 'undefined' ? GITHUB_CLIENT_ID_FALLBACK : ''),
  githubOAuthProxyUrl: localStorage.getItem('ai_library_github_proxy_url') || 'http://localhost:3001/api/github-auth',
  githubRedirectUri: typeof location !== 'undefined' ? (localStorage.getItem('ai_library_github_redirect_uri') || (location.origin + '/callback.html')) : ''
};

// If app is served from Node server, load API keys from .env via /api/config
AILibrary.configReady = Promise.resolve();
(function loadEnvConfig() {
  var apiConfigUrl = typeof location !== 'undefined' && location.origin ? (location.origin + '/api/config') : '';
  if (!apiConfigUrl) return;
  function mergeEnv(env) {
    if (env && typeof env === 'object') {
      if (env.geminiKey) AILibrary.config.geminiKey = env.geminiKey;
      if (env.removeBgKey) AILibrary.config.removeBgKey = env.removeBgKey;
      if (env.openaiKey) AILibrary.config.openaiKey = env.openaiKey;
      if (env.googleClientId) AILibrary.config.googleClientId = env.googleClientId;

      if (env.githubClientId) AILibrary.config.githubClientId = env.githubClientId;
    }
  }
  function tryConfig(url) {
    return fetch(url, { method: 'GET', credentials: 'omit' })
      .then(function (r) {
        if (r.ok && r.headers.get('content-type')?.includes('application/json')) {
          return r.json().then(function (data) {
            // Verify this is actually our Node server and not an HTML error page
            if (data && (data.geminiKey !== undefined || data.githubClientId !== undefined)) {
              var apiUrl = new URL(url);
              AILibrary.config.apiBaseUrl = apiUrl.origin;
              console.log('✅ Connected to API Server at:', apiUrl.origin);
              return data;
            }
            return Promise.reject(new Error('Invalid config format'));
          });
        }
        return Promise.reject(new Error('not ok'));
      })
      .then(mergeEnv);
  }
  AILibrary.configReady = tryConfig(apiConfigUrl).catch(function () {
    console.log('API not found on current origin (Live Server), seeking Node server on port 3001...');
    return tryConfig('http://localhost:3001/api/config').catch(function () {
      console.log('Still seeking, trying 127.0.0.1:3001...');
      return tryConfig('http://127.0.0.1:3001/api/config');
    });
  }).catch(function (err) {
    console.warn('⚠️ Node server (port 3001) not found. OTP/password-reset won\'t work. Run: node server.js');
    AILibrary.config.apiBaseUrl = '';
    AILibrary.config.serverAvailable = false;
  });
})();

// =============================================================================
// 🔐 SOCIAL LOGIN — Where to get Client IDs (optional; see README.md for full steps)
// =============================================================================
// • Google Client ID: https://console.cloud.google.com/apis/credentials
//   → Create Credentials → OAuth client ID → Web application
//   → Add "Authorized JavaScript origins" (e.g. http://127.0.0.1:5500, http://localhost:3000)
//   → Copy the Client ID (xxxxx.apps.googleusercontent.com)

// • GitHub Client ID: https://github.com/settings/developers
//   → New OAuth App → Authorization callback URL = your site + /callback.html
//   → Copy Client ID (GitHub sign-in also needs a backend to exchange code; set githubOAuthProxyUrl)
// =============================================================================

// ——— Theme (Dark / Light) ———
AILibrary.theme = (function () {
  var STORAGE_KEY = 'ai_library_theme';
  function get() {
    return localStorage.getItem(STORAGE_KEY) || 'dark';
  }
  function set(theme) {
    theme = theme === 'light' ? 'light' : 'dark';
    localStorage.setItem(STORAGE_KEY, theme);
    document.documentElement.setAttribute('data-theme', theme);
    return theme;
  }
  function toggle() {
    return set(get() === 'dark' ? 'light' : 'dark');
  }
  function apply() {
    document.documentElement.setAttribute('data-theme', get());
  }
  function updateButton(btn) {
    if (!btn) return;
    btn.textContent = get() === 'dark' ? '🌙' : '☀️';
    btn.setAttribute('aria-label', get() === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
    btn.title = get() === 'dark' ? 'Light mode' : 'Dark mode';
  }
  function updateDropdownTheme() {
    var icon = document.getElementById('dropdown-theme-icon');
    var label = document.getElementById('dropdown-theme-label');
    if (icon) icon.textContent = get() === 'dark' ? '🌙' : '☀️';
    if (label) label.textContent = get() === 'dark' ? 'Light mode' : 'Dark mode';
  }
  function init() {
    apply();
    var btn = document.getElementById('theme-toggle');
    if (btn) {
      updateButton(btn);
      btn.addEventListener('click', function () {
        toggle();
        updateButton(btn);
        updateDropdownTheme();
      });
    }
    updateDropdownTheme();
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
  return { get: get, set: set, toggle: toggle, apply: apply, updateDropdownTheme: updateDropdownTheme };
})();

// ——— Auth (Local Storage) ———
AILibrary.auth = (function () {
  var USERS_KEY = 'ai_library_users';
  var CURRENT_KEY = 'ai_library_current_user';

  function getUsers() {
    try {
      var raw = localStorage.getItem(USERS_KEY);
      return raw ? JSON.parse(raw) : {};
    } catch (e) {
      return {};
    }
  }

  function saveUsers(users) {
    localStorage.setItem(USERS_KEY, JSON.stringify(users));
  }

  async function logSignupToServer(username, email) {
    await AILibrary.configReady;
    if (AILibrary.config.serverAvailable === false) return;
    try {
      var baseUrl = AILibrary.config.apiBaseUrl || '';
      fetch(baseUrl + '/api/log-signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username, email: email, time: Date.now() })
      }).catch(e => console.warn('Failed to log signup:', e));
    } catch (e) { }
  }

  async function hashPassword(password) {
    if (!window.crypto || !window.crypto.subtle) {
      console.warn('Crypto API not available (insecure context/file protocol). Using simple fallback.');
      // Simple fallback hash for file:// protocol (NOT SECURE, but functional for local demo)
      var hash = 0;
      for (var i = 0; i < password.length; i++) {
        var char = password.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32bit integer
      }
      return 'insecure-hash-' + Math.abs(hash).toString(16);
    }
    const msgBuffer = new TextEncoder().encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async function signUp(name, email, password) {
    if (!email || !password) return { success: false, message: 'Email and password required.' };
    if (password.length < 6) return { success: false, message: 'Password must be at least 6 characters.' };
    var users = getUsers();
    email = email.toLowerCase().trim();
    if (users[email]) return { success: false, message: 'An account with this email already exists.' };

    // Hash password
    const hashedPassword = await hashPassword(password);

    users[email] = { name: (name || '').trim(), email: email, password: hashedPassword };
    saveUsers(users);
    var user = { name: users[email].name, email: users[email].email };
    localStorage.setItem(CURRENT_KEY, JSON.stringify(user));

    // Log to server
    logSignupToServer(user.name, user.email);

    return { success: true, user: user };
  }

  async function login(email, password) {
    if (!email || !password) return { success: false, message: 'Email and password required.' };
    var users = getUsers();
    email = email.toLowerCase().trim();
    var u = users[email];

    if (!u) return { success: false, message: 'Invalid email or password.' };

    const hashedPassword = await hashPassword(password);

    // Check if password matches the hash
    if (u.password !== hashedPassword) {
      // Fallback: Check if it's a legacy plain-text password
      if (u.password === password) {
        // Upgrade to hashed password
        console.log('Upgrading legacy password for:', email);
        u.password = hashedPassword;
        saveUsers(users);
        // Continue to login...
      } else {
        return { success: false, message: 'Invalid email or password.' };
      }
    }

    var user = { name: u.name, email: u.email };
    localStorage.setItem(CURRENT_KEY, JSON.stringify(user));
    return { success: true, user: user };
  }

  function getCurrentUser() {
    try {
      var raw = localStorage.getItem(CURRENT_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      return null;
    }
  }

  function isLoggedIn() {
    return !!getCurrentUser();
  }

  function logout() {
    localStorage.removeItem(CURRENT_KEY);
  }

  function socialLoginOrSignUp(email, name) {
    if (!email) return { success: false, message: 'Email required.' };
    var users = getUsers();
    email = email.toLowerCase().trim();
    name = (name || '').trim() || email.split('@')[0];
    if (users[email]) {
      var user = { name: users[email].name, email: users[email].email };
      localStorage.setItem(CURRENT_KEY, JSON.stringify(user));
      return { success: true, user: user };
    }
    users[email] = { name: name, email: email, password: '', social: true };
    saveUsers(users);
    var user = { name: name, email: email };
    localStorage.setItem(CURRENT_KEY, JSON.stringify(user));

    // Log to server
    logSignupToServer(user.name, user.email);

    return { success: true, user: user };
  }

  async function requestOtp(email) {
    // Ensure we have found the Node server first
    await AILibrary.configReady;

    if (AILibrary.config.serverAvailable === false) {
      return { success: false, message: 'Node server is not running. Open a terminal in the project folder and run: node server.js' };
    }

    var users = getUsers();
    email = email.toLowerCase().trim();
    if (!users[email]) return { success: false, message: 'No account found with this email.' };
    try {
      var baseUrl = AILibrary.config.apiBaseUrl || '';
      var requestUrl = baseUrl + '/api/otp/request';
      console.log('Sending OTP request to:', requestUrl);
      var res = await fetch(requestUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email })
      });
      if (!res.ok) {
        return { success: false, message: 'Server at ' + (baseUrl || 'origin') + ' failed (' + res.status + ')' };
      }
      return await res.json();
    } catch (e) {
      console.error('OTP Request Error:', e);
      return { success: false, message: 'Could not connect to Node server on port 3001. Please run "node server.js".' };
    }
  }

  async function verifyOtpAndReset(email, otp, newPassword) {
    await AILibrary.configReady;

    if (AILibrary.config.serverAvailable === false) {
      return { success: false, message: 'Node server is not running. Open a terminal in the project folder and run: node server.js' };
    }

    if (!otp || otp.length !== 6) return { success: false, message: 'Invalid OTP format.' };
    if (!newPassword || newPassword.length < 6) return { success: false, message: 'Password must be at least 6 characters.' };
    try {
      var baseUrl = AILibrary.config.apiBaseUrl || '';
      var requestUrl = baseUrl + '/api/otp/verify';
      var res = await fetch(requestUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email, otp: otp })
      });
      if (!res.ok) {
        return { success: false, message: 'Verification failed at ' + (baseUrl || 'origin') + ' (' + res.status + ')' };
      }
      var result = await res.json();
      if (result.success) {
        var users = getUsers();
        email = email.toLowerCase().trim();
        const hashedPassword = await hashPassword(newPassword);
        users[email].password = hashedPassword;
        saveUsers(users);
        return { success: true, message: 'Password updated successfully!' };
      }
      return result;
    } catch (e) {
      return { success: false, message: 'Verification failed.' };
    }
  }

  return { signUp: signUp, login: login, getCurrentUser: getCurrentUser, isLoggedIn: isLoggedIn, logout: logout, socialLoginOrSignUp: socialLoginOrSignUp, requestOtp: requestOtp, verifyOtpAndReset: verifyOtpAndReset };
})();

// ——— Social Login (Google, Facebook, GitHub) ———
AILibrary.socialAuth = (function () {
  var config = AILibrary.config || {};

  function showError(el, msg) {
    if (!el) return;
    el.textContent = msg || '';
    el.classList.remove('form-hint');
  }
  function showHint(el, msg) {
    if (!el) return;
    el.textContent = msg || '';
    el.classList.add('form-hint');
  }

  function parseJwtPayload(token) {
    try {
      var parts = (token || '').split('.');
      if (parts.length !== 3) return null;
      var payload = parts[1];
      var decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
      return JSON.parse(decoded);
    } catch (e) {
      return null;
    }
  }

  function loginGoogle(errorEl, onSuccess) {
    var clientId = config.googleClientId || '';
    if (!clientId) {
      showHint(errorEl, 'Social login is optional. Add googleClientId in script.js to enable Google sign-in (see comments at top).');
      return;
    }
    var redirectUri = (typeof location !== 'undefined' ? location.origin + '/callback.html' : '');
    var scope = encodeURIComponent('email profile openid');
    var url = 'https://accounts.google.com/o/oauth2/v2/auth?client_id=' + encodeURIComponent(clientId) +
      '&redirect_uri=' + encodeURIComponent(redirectUri) +
      '&response_type=token&scope=' + scope + '&include_granted_scopes=true';
    if (typeof location !== 'undefined') location.href = url;
  }

  function loginGoogleWithCredential(errorEl, onSuccess) {
    var clientId = config.googleClientId || '';
    if (!clientId) {
      showHint(errorEl, 'Social login is optional. Add googleClientId in script.js to enable Google sign-in (see comments at top).');
      return;
    }
    if (typeof google === 'undefined' || !google.accounts || !google.accounts.id) {
      showHint(errorEl, 'Google Sign-In is loading. Try again in a moment.');
      return;
    }
    google.accounts.id.initialize({
      client_id: clientId,
      callback: function (cred) {
        if (!cred || !cred.credential) {
          showError(errorEl, 'Google sign-in was cancelled.');
          return;
        }
        var payload = parseJwtPayload(cred.credential);
        if (!payload) {
          showError(errorEl, 'Could not read Google profile.');
          return;
        }
        var email = payload.email;
        var name = (payload.name || payload.given_name || '').trim() || (email ? email.split('@')[0] : 'User');
        var result = AILibrary.auth.socialLoginOrSignUp(email, name);
        if (result.success && onSuccess) onSuccess();
        else showError(errorEl, result.message || 'Sign-in failed.');
      }
    });
    google.accounts.id.prompt(function () { });
  }



  function loginGitHub(errorEl, onSuccess) {
    var clientId = config.githubClientId || '';
    var redirectUri = config.githubRedirectUri || (typeof location !== 'undefined' ? location.origin + '/callback.html' : '');
    if (!clientId) {
      showHint(errorEl, 'Social login is optional. Add githubClientId in script.js to enable GitHub sign-in (see comments at top).');
      return;
    }
    var url = 'https://github.com/login/oauth/authorize?client_id=' + encodeURIComponent(clientId) +
      '&redirect_uri=' + encodeURIComponent(redirectUri) +
      '&scope=user:email&state=ai_trionex';
    if (typeof location !== 'undefined') location.href = url;
  }

  return {
    loginGoogle: loginGoogle,
    loginGoogleWithCredential: loginGoogleWithCredential,

    loginGitHub: loginGitHub
  };
})();

// ——— AI (Gemini by default, OpenAI optional fallback) ———
AILibrary.ai = (function () {
  function getOpenAIKey() {
    return AILibrary.config.openaiKey || '';
  }

  function getGeminiKey() {
    return AILibrary.config.geminiKey || '';
  }

  function openAIRequest(messages, options) {
    options = options || {};
    var key = getOpenAIKey();
    if (!key) return Promise.reject(new Error('OpenAI API key not set. Set it in Settings or localStorage (ai_library_openai_key).'));

    return fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + key
      },
      body: JSON.stringify({
        model: options.model || 'gpt-4o-mini',
        messages: messages,
        max_tokens: options.max_tokens || 2048,
        temperature: options.temperature !== undefined ? options.temperature : 0.7
      })
    }).then(function (r) {
      if (!r.ok) return r.json().then(function (j) { throw new Error(j.error && j.error.message ? j.error.message : r.statusText); });
      return r.json();
    }).then(function (data) {
      var text = data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content;
      return text || '';
    });
  }

  var GEMINI_MODELS = ['gemini-2.5-flash-lite', 'gemini-2.0-flash'];
  function geminiRequestWithRetry(prompt, options, modelIndex, retriedAfter429) {
    modelIndex = modelIndex || 0;
    retriedAfter429 = retriedAfter429 || false;
    var model = GEMINI_MODELS[modelIndex] || GEMINI_MODELS[0];
    options = options || {};
    var key = getGeminiKey();
    if (!key) return Promise.reject(new Error('Gemini API key not set. Set it in Settings or localStorage (ai_library_gemini_key).'));

    var url = 'https://generativelanguage.googleapis.com/v1beta/models/' + model + ':generateContent?key=' + encodeURIComponent(key);
    var contentsBody;
    if (Array.isArray(prompt)) {
      // Multimodal: prompt is already an array of parts
      contentsBody = {
        contents: [{ role: 'user', parts: prompt }],
        generationConfig: {
          maxOutputTokens: options.max_tokens || 2048,
          temperature: options.temperature !== undefined ? options.temperature : 0.6
        }
      };
    } else {
      // Text-only: wrap string
      contentsBody = {
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: {
          maxOutputTokens: options.max_tokens || 2048,
          temperature: options.temperature !== undefined ? options.temperature : 0.6
        }
      };
    }

    return fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(contentsBody)
    }).then(function (r) {
      if (!r.ok) return r.text().then(function (t) {
        var errObj;
        try { errObj = JSON.parse(t); } catch (e) { errObj = {}; }
        var code = (errObj.error && errObj.error.code) || r.status;
        var msg = (errObj.error && errObj.error.message) || t || r.statusText;
        if (code === 429 || r.status === 429) {
          var retrySec = 45;
          if (msg && /retry in (\d+(?:\.\d+)?)s/i.test(msg)) retrySec = Math.min(90, Math.ceil(parseFloat(msg.match(/retry in (\d+(?:\.\d+)?)s/i)[1])));
          var err = new Error('QUOTA_RETRY_' + retrySec);
          err.retrySec = retrySec;
          err.is429 = true;
          throw err;
        }
        throw new Error(msg.length > 200 ? msg.slice(0, 200) + '…' : msg);
      });
      return r.json();
    }).then(function (data) {
      var text = data.candidates && data.candidates[0] && data.candidates[0].content && data.candidates[0].content.parts && data.candidates[0].content.parts[0];
      return text ? text.text : '';
    }).catch(function (err) {
      if (err.is429 && err.retrySec && !retriedAfter429) {
        return new Promise(function (resolve, reject) {
          setTimeout(function () {
            geminiRequestWithRetry(prompt, options, modelIndex, true).then(resolve).catch(reject);
          }, err.retrySec * 1000);
        });
      }
      if (err.is429 && modelIndex + 1 < GEMINI_MODELS.length) {
        return geminiRequestWithRetry(prompt, options, modelIndex + 1, false);
      }
      if (err.message && err.message.indexOf('QUOTA_RETRY_') === 0) {
        err.message = 'Quota exceeded. Please try again in a minute or check your Gemini API quota: https://ai.google.dev/gemini-api/docs/rate-limits';
      }
      throw err;
    });
  }

  function geminiRequest(prompt, options) {
    return geminiRequestWithRetry(prompt, options, 0);
  }

  function buildChatPrompt(messages) {
    return messages.map(function (m) {
      // If content is array (multimodal), we can't easily stringify it for OpenAI fallback in this simple fn,
      // but for Gemini we should pass it through.
      // However, `buildChatPrompt` was designed for a string-only prompt for the `geminiRequest` wrapper.
      // If we are sending multimodal, `chat` handles it by calling `geminiRequest` with the array.
      if (Array.isArray(m.content)) return 'User sent an image.';
      var label = m.role === 'user' ? 'User' : 'Assistant';
      return label + ': ' + (m.content || '');
    }).join('\n\n') + '\n\nAssistant:';
  }

  function chatStream(messages, onChunk) {
    var key = getGeminiKey();
    if (!AILibrary.config.useGemini || !getGeminiKey()) {
      return Promise.reject(new Error('Gemini API key missing. Option 1: Run "node server.js" and open the dashboard. Option 2: In script.js set GEMINI_KEY_FALLBACK = "YOUR_KEY". Option 3: Console: localStorage.setItem("ai_library_gemini_key", "YOUR_KEY"); then refresh.'));
    }
    key = getGeminiKey();
    var prompt = buildChatPrompt(messages);
    var model = GEMINI_MODELS[0];
    var url = 'https://generativelanguage.googleapis.com/v1beta/models/' + model + ':streamGenerateContent?key=' + encodeURIComponent(key) + '&alt=sse';
    return fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: {
          maxOutputTokens: 1024,
          temperature: 0.6
        }
      })
    }).then(function (r) {
      if (!r.ok) return r.text().then(function (t) { throw new Error(t || r.statusText); });
      var reader = r.body.getReader();
      var decoder = new TextDecoder();
      var buffer = '';
      var full = '';
      return reader.read().then(function processChunk(result) {
        if (result.done) return full;
        buffer += decoder.decode(result.value, { stream: true });
        var lines = buffer.split('\n');
        buffer = lines.pop() || '';
        for (var i = 0; i < lines.length; i++) {
          var line = lines[i].replace(/^data:\s*/, '').trim();
          if (!line || line === '[DONE]') continue;
          try {
            var obj = JSON.parse(line);
            var part = obj.candidates && obj.candidates[0] && obj.candidates[0].content && obj.candidates[0].content.parts && obj.candidates[0].content.parts[0];
            if (part && part.text) {
              full += part.text;
              if (onChunk) onChunk(part.text, full);
            }
          } catch (e) { /* skip */ }
        }
        return reader.read().then(processChunk);
      });
    });
  }

  function chat(messages) {
    if (AILibrary.config.useGemini && getGeminiKey()) {
      // If we have a multimodal message (content is array), pass it directly to geminiRequest
      // We assume the LAST message is the one with the image for simplicity in this update
      var lastMsg = messages[messages.length - 1];
      if (Array.isArray(lastMsg.content)) {
        return geminiRequest(lastMsg.content, { max_tokens: 1024 });
      }

      var prompt = buildChatPrompt(messages);
      return geminiRequest(prompt, { max_tokens: 1024 });
    }
    return openAIRequest(messages, {});
  }

  function complete(prompt, systemPrompt) {
    var messages = [];
    if (systemPrompt) messages.push({ role: 'system', content: systemPrompt });
    messages.push({ role: 'user', content: prompt });
    if (AILibrary.config.useGemini && getGeminiKey()) {
      var full = (systemPrompt ? systemPrompt + '\n\n' : '') + prompt;
      return geminiRequest(full, {});
    }
    return openAIRequest(messages, {});
  }

  return { chat: chat, chatStream: chatStream, complete: complete, openAIRequest: openAIRequest };
})();

// ——— Background removal (remove.bg) ———
AILibrary.backgroundRemover = (function () {
  function getKey() {
    return AILibrary.config.removeBgKey || '';
  }

  function removeBackground(fileBlob) {
    var key = getKey();
    if (!key) return Promise.reject(new Error('Remove.bg API key not set. Set it in Settings or localStorage (ai_library_removebg_key).'));

    var form = new FormData();
    form.append('size', 'auto');
    form.append('image_file', fileBlob);

    return fetch('https://api.remove.bg/v1.0/removebg', {
      method: 'POST',
      headers: { 'X-Api-Key': key },
      body: form
    }).then(function (r) {
      if (!r.ok) return r.json().then(function (j) { throw new Error(j.errors && j.errors[0] ? j.errors[0].title : r.statusText); });
      return r.blob();
    });
  }

  return { removeBackground: removeBackground };
})();




// ——— QR Code Generator ———
AILibrary.qrCodeGenerator = (function () {
  var qrCodeDisplay;

  function init() {
    var qrLinkInput = document.getElementById('qr-link-input');
    var qrFileInput = document.getElementById('qr-file-input');
    var qrSizeInput = document.getElementById('qr-size-input');
    var qrColorDarkInput = document.getElementById('qr-color-dark-input');
    var qrColorLightInput = document.getElementById('qr-color-light-input');
    var qrGenerateBtn = document.getElementById('qr-generate-btn');
    var qrClearBtn = document.getElementById('qr-clear-btn');
    qrCodeDisplay = document.getElementById('qr-code-display');

    if (!qrGenerateBtn) return;

    if (qrClearBtn) {
      qrClearBtn.addEventListener('click', function () {
        qrLinkInput.value = '';
        qrFileInput.value = '';
        qrSizeInput.value = '256';
        qrColorDarkInput.value = '#000000';
        qrColorLightInput.value = '#ffffff';
        qrCodeDisplay.innerHTML = '<p class="result-placeholder">Your QR code will appear here.</p>';
      });
    }

    qrGenerateBtn.addEventListener('click', function () {
      var text = qrLinkInput ? qrLinkInput.value : '';
      var colorDark = qrColorDarkInput ? qrColorDarkInput.value : '#000000';
      var colorLight = qrColorLightInput ? qrColorLightInput.value : '#ffffff';

      if (!text) {
        if (qrCodeDisplay) {
          qrCodeDisplay.style.display = 'block';
          qrCodeDisplay.innerHTML = '<p class="result-placeholder error">Please enter text or a link.</p>';
        }
        return;
      }
      // Activate layout (inline since QR is a separate module)
      var qrLayout = document.getElementById('qr-layout');
      var qrWelcome = document.getElementById('qr-welcome');
      if (qrLayout) qrLayout.classList.add('active');
      if (qrWelcome) { qrWelcome.style.opacity = '0'; qrWelcome.style.flex = '0'; qrWelcome.style.pointerEvents = 'none'; }
      if (qrCodeDisplay) qrCodeDisplay.style.display = 'block';
      generateQrCode(text, 256, colorDark, colorLight);
    });

    // Enter key support for QR input
    if (qrLinkInput) {
      qrLinkInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { e.preventDefault(); qrGenerateBtn.click(); }
      });
    }
  }

  function generateQrCode(data, size, colorDark, colorLight) {
    console.log('Generating QR Code:', { data: data, size: size, colorDark: colorDark, colorLight: colorLight });
    try {
      if (typeof QRCode === 'undefined') {
        console.error('QRCode library not loaded!');
        qrCodeDisplay.innerHTML = '<p class="error">QRCode library missing.</p>';
        return;
      }

      qrCodeDisplay.innerHTML = ''; // Clear previous QR code
      var correctLevel = (QRCode.CorrectLevel && QRCode.CorrectLevel.H) ? QRCode.CorrectLevel.H : 2;
      new QRCode(qrCodeDisplay, {
        text: data,
        width: size,
        height: size,
        colorDark: colorDark,
        colorLight: colorLight,
        correctLevel: correctLevel
      });
    } catch (err) {
      console.error('QR code generation error:', err);
      qrCodeDisplay.innerHTML = '<p class="error">Error generating QR Code. See console for details.</p>';
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  return { init: init };
})();



// ——— Dashboard UI & section switching ———
AILibrary.dashboard = (function () {
  var sectionTitles = {
    'chatbot': 'AI Chatbot',
    'code-explainer': 'Code Explainer',
    'code-generator': 'Code Generator',
    'assistant': 'AI Assistant',
    'prompt-generator': 'Prompt Generator',

    'bg-remover': 'Image Background Remover',

    'qr-generator': 'QR Code Generator',
    'history': 'Account History',
    'about': 'About Us'
  };

  var HISTORY_KEY = 'ai_library_history';

  function escapeHtml(s) {
    return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function getHistory() {
    try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]'); }
    catch (e) { return []; }
  }
  function saveHistory(arr) {
    // Keep last 100 entries
    if (arr.length > 100) arr = arr.slice(-100);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(arr));
  }
  function logActivity(tool, detail) {
    var history = getHistory();
    history.push({ tool: tool, detail: detail || '', time: Date.now() });
    saveHistory(history);
  }

  function loadHistoryItem(tool, detail) {
    var sectionMap = {
      'AI Chatbot': 'chatbot',
      'Code Explainer': 'code-explainer',
      'Code Generator': 'code-generator',
      'AI Assistant': 'assistant',
      'Prompt Generator': 'prompt-generator',
      'Image Background Remover': 'bg-remover',
      'QR Code Generator': 'qr-generator'
    };
    var sectionId = sectionMap[tool];
    if (!sectionId) return;

    showSection(sectionId);

    if (detail) {
      // Decode HTML entities if necessary or just use the raw string if not double-encoded
      // Since we store raw string but render escaped, here we use the raw 'detail' passed in
      if (sectionId === 'chatbot') {
        var el = document.getElementById('chat-input');
        if (el) el.value = detail;
      } else if (sectionId === 'code-explainer') {
        var el = document.getElementById('explainer-code');
        if (el) el.value = detail;
      } else if (sectionId === 'code-generator') {
        var el = document.getElementById('generator-prompt');
        if (el) el.value = detail;
      } else if (sectionId === 'assistant') {
        var el = document.getElementById('assistant-input');
        if (el) el.value = detail;
      } else if (sectionId === 'prompt-generator') {
        var el = document.getElementById('prompt-gen-input');
        if (el) el.value = detail;
      } else if (sectionId === 'qr-generator') {
        var el = document.getElementById('qr-link-input');
        if (el) el.value = detail;
      }
    }
  }

  function renderHistory() {
    var container = document.querySelector('#section-history .tool-card');
    if (!container) return;
    var history = getHistory();

    // Keep the heading
    var html = '<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:0.5rem;margin-bottom:1rem;">'
      + '<div><h3>Account History</h3><p class="tool-desc" style="margin:0;">Your recent activity and usage history.</p></div>'
      + '<button type="button" class="btn btn-outline btn-sm" id="clear-history-btn">Clear History</button></div>';

    if (history.length === 0) {
      html += '<div class="history-placeholder"><p style="color:var(--theme-text-muted);text-align:center;padding:2rem 0;">No activity recorded yet. Start using tools to see your history here.</p></div>';
    } else {
      // Group by date
      var grouped = {};
      history.slice().reverse().forEach(function (item) {
        var date = new Date(item.time);
        var dateKey = date.toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
        if (!grouped[dateKey]) grouped[dateKey] = [];
        grouped[dateKey].push(item);
      });

      var toolIcons = {
        'AI Chatbot': '💬', 'Code Explainer': '📖', 'Code Generator': '⚡',
        'AI Assistant': '🤖', 'Prompt Generator': '✨', 'Background Remover': '🖼️',
        'Video to MP3': '🎵', 'Currency Calculator': '💱', 'QR Code Generator': '📷',
        'Login': '🔐', 'Signup': '📝', 'Password Reset': '🔑'
      };

      html += '<div class="history-timeline">';
      for (var dateKey in grouped) {
        html += '<div class="history-date-group">';
        html += '<p class="history-date-label">' + dateKey + '</p>';
        grouped[dateKey].forEach(function (item) {
          var time = new Date(item.time).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
          var icon = toolIcons[item.tool] || '📋';
          var detail = item.detail ? '<span class="history-detail">' + escapeHtml(item.detail).substring(0, 80) + (item.detail.length > 80 ? '...' : '') + '</span>' : '';
          html += '<div class="history-item" data-tool="' + item.tool + '" data-detail="' + escapeHtml(item.detail) + '" style="cursor:pointer;">'
            + '<span class="history-icon">' + icon + '</span>'
            + '<div class="history-item-content">'
            + '<span class="history-tool-name">' + item.tool + '</span>'
            + detail
            + '</div>'
            + '<span class="history-time">' + time + '</span>'
            + '</div>';
        });
        html += '</div>';
      }
      html += '</div>';
    }

    container.innerHTML = html;

    // Add click listeners to history items
    container.querySelectorAll('.history-item').forEach(function (el) {
      el.addEventListener('click', function () {
        var tool = this.getAttribute('data-tool');
        var detail = this.getAttribute('data-detail');
        // Unescape specifically for the value to put back in input
        var temp = document.createElement('div');
        temp.innerHTML = detail;
        var unescaped = temp.textContent || temp.innerText || '';
        loadHistoryItem(tool, unescaped);
      });
    });

    // Wire up clear button
    var clearBtn = document.getElementById('clear-history-btn');
    if (clearBtn) {
      clearBtn.addEventListener('click', function () {
        localStorage.removeItem(HISTORY_KEY);
        renderHistory();
      });
    }
  }

  function showSection(sectionId) {
    document.querySelectorAll('.dashboard-section').forEach(function (el) { el.classList.remove('active'); });
    document.querySelectorAll('.nav-item').forEach(function (el) { el.classList.remove('active'); });
    var section = document.getElementById('section-' + sectionId);
    var nav = document.querySelector('.nav-item[data-section="' + sectionId + '"]');
    var titleEl = document.getElementById('page-title');
    if (section) section.classList.add('active');
    if (nav) nav.classList.add('active');
    if (titleEl) titleEl.textContent = sectionTitles[sectionId] || sectionId;
    if (sectionId === 'history') renderHistory();
  }

  function init() {
    var sidebar = document.getElementById('sidebar');
    var menuBtn = document.getElementById('menu-btn');
    var sidebarToggle = document.getElementById('sidebar-toggle');
    if (sidebarToggle) {
      sidebarToggle.addEventListener('click', function () {
        sidebar.classList.toggle('open');
      });
    }
    if (menuBtn) {
      menuBtn.addEventListener('click', function () {
        sidebar.classList.toggle('open');
      });
    }
    var logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', function (e) {
        e.preventDefault();
        AILibrary.auth.logout();
        window.location.href = 'index.html';
      });
    }

    var settingsBtn = document.getElementById('settings-btn');
    var settingsDropdown = document.getElementById('settings-dropdown');
    if (settingsBtn && settingsDropdown) {
      settingsBtn.addEventListener('click', function (e) {
        e.stopPropagation();
        settingsDropdown.classList.toggle('open');
      });
      var dropdownTheme = document.getElementById('dropdown-theme');
      if (dropdownTheme) {
        dropdownTheme.addEventListener('click', function () {
          AILibrary.theme.toggle();
          if (AILibrary.theme.updateDropdownTheme) AILibrary.theme.updateDropdownTheme();
        });
      }
      var dropdownHistory = document.getElementById('dropdown-history');
      if (dropdownHistory) {
        dropdownHistory.addEventListener('click', function () {
          settingsDropdown.classList.remove('open');
          showSection('history');
        });
      }
      var dropdownAbout = document.getElementById('dropdown-about');
      if (dropdownAbout) {
        dropdownAbout.addEventListener('click', function () {
          settingsDropdown.classList.remove('open');
          showSection('about');
        });
      }
      document.addEventListener('click', function () {
        settingsDropdown.classList.remove('open');
      });
      settingsDropdown.addEventListener('click', function (e) {
        e.stopPropagation();
      });
    }

    document.querySelectorAll('.nav-item').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var section = this.getAttribute('data-section');
        if (section) showSection(section);
        if (window.innerWidth <= 900) sidebar.classList.remove('open');
      });
    });

    // Chat
    var chatInput = document.getElementById('chat-input');
    var chatSend = document.getElementById('chat-send');
    var chatMessages = document.getElementById('chat-messages');
    if (chatSend && chatInput && chatMessages) {
      // escapeHtml moved to top-level of module

      function formatBotContent(text) {
        if (!text) return '';
        var lines = text.split('\n');
        var result = [];
        var i = 0;
        while (i < lines.length) {
          var line = lines[i];
          if (/^\s*[-*]\s+/.test(line)) {
            var list = [];
            while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) {
              var rest = lines[i].replace(/^\s*[-*]\s+/, '');
              list.push(escapeHtml(rest).replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>'));
              i++;
            }
            result.push('<ul>' + list.map(function (l) { return '<li>' + l + '</li>'; }).join('') + '</ul>');
          } else {
            result.push(escapeHtml(line).replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>'));
            i++;
          }
        }
        return result.join('<br>');
      }

      // Wikipedia image search — extract topic keywords from user message
      function extractSearchTopic(text) {
        // Remove common question words to get the core topic
        var cleaned = text
          .replace(/^(what|who|where|when|why|how|tell|explain|describe|show|give|define|can you|could you|please|me|is|are|was|were|do|does|about|the|a|an|of|in|on|to|for|and|or|it|its|this|that|i|my)\s+/gi, '')
          .replace(/[?!.,;:]+$/g, '')
          .trim();
        // If too short after cleaning, use original text
        if (cleaned.length < 3) cleaned = text.replace(/[?!.,;:]+$/g, '').trim();
        // Take first meaningful words (max 4) for search
        var words = cleaned.split(/\s+/).slice(0, 4).join(' ');
        return words;
      }

      function shouldFetchImages(text) {
        // Skip image fetching for code-heavy, math, or very short queries
        var skipPatterns = /^(hi|hello|hey|thanks|thank you|ok|okay|yes|no|bye|help)$/i;
        var codePatterns = /```|function\s*\(|var\s+|const\s+|let\s+|console\.|import\s+|<\/?[a-z]+>/i;
        if (skipPatterns.test(text.trim()) || codePatterns.test(text)) return false;
        if (text.trim().split(/\s+/).length < 2) return false;
        return true;
      }

      function fetchWikipediaImages(topic) {
        var searchUrl = 'https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch='
          + encodeURIComponent(topic) + '&srlimit=1&format=json&origin=*';

        return fetch(searchUrl)
          .then(function (r) { return r.json(); })
          .then(function (data) {
            if (!data.query || !data.query.search || !data.query.search.length) return [];
            var pageTitle = data.query.search[0].title;

            // Fetch images from that page
            var imagesUrl = 'https://en.wikipedia.org/w/api.php?action=query&titles='
              + encodeURIComponent(pageTitle)
              + '&prop=images&imlimit=20&format=json&origin=*';

            return fetch(imagesUrl)
              .then(function (r) { return r.json(); })
              .then(function (imgData) {
                var pages = imgData.query && imgData.query.pages;
                if (!pages) return [];
                var images = [];
                for (var pid in pages) {
                  if (pages[pid].images) {
                    images = images.concat(pages[pid].images);
                  }
                }
                // Filter out icons, logos, commons stuff, svgs
                var validImages = images.filter(function (img) {
                  var t = img.title.toLowerCase();
                  return !t.includes('icon') && !t.includes('logo') && !t.includes('commons-logo')
                    && !t.includes('ambox') && !t.includes('edit-clear') && !t.includes('disambig')
                    && !t.includes('question_book') && !t.includes('wiki') && !t.includes('flag')
                    && !t.includes('.svg') && !t.includes('symbol') && !t.includes('stub')
                    && !t.includes('padlock') && !t.includes('crystal') && !t.includes('folder')
                    && (t.endsWith('.jpg') || t.endsWith('.jpeg') || t.endsWith('.png') || t.endsWith('.webp'));
                }).slice(0, 4);

                if (validImages.length === 0) return [];

                // Get actual image URLs
                var fileTitles = validImages.map(function (img) { return img.title; }).join('|');
                var urlsUrl = 'https://en.wikipedia.org/w/api.php?action=query&titles='
                  + encodeURIComponent(fileTitles)
                  + '&prop=imageinfo&iiprop=url|extmetadata&iiurlwidth=300&format=json&origin=*';

                return fetch(urlsUrl)
                  .then(function (r) { return r.json(); })
                  .then(function (urlData) {
                    var urlPages = urlData.query && urlData.query.pages;
                    if (!urlPages) return [];
                    var results = [];
                    for (var uid in urlPages) {
                      var info = urlPages[uid].imageinfo && urlPages[uid].imageinfo[0];
                      if (info && info.thumburl) {
                        var desc = '';
                        if (info.extmetadata && info.extmetadata.ObjectName) {
                          desc = info.extmetadata.ObjectName.value || '';
                        }
                        if (!desc) desc = (urlPages[uid].title || '').replace('File:', '').replace(/_/g, ' ').replace(/\.\w+$/, '');
                        results.push({
                          thumb: info.thumburl,
                          full: info.url,
                          caption: desc
                        });
                      }
                    }
                    return results;
                  });
              });
          })
          .catch(function () { return []; });
      }

      function appendWikiImages(targetDiv, images) {
        if (!images || images.length === 0) return;
        var container = document.createElement('div');
        container.className = 'chat-wiki-images';
        container.innerHTML = '<p class="chat-wiki-images-label">📷 Related Images</p>';
        var gallery = document.createElement('div');
        gallery.className = 'chat-wiki-gallery';

        images.forEach(function (img) {
          var wrap = document.createElement('div');
          wrap.className = 'chat-wiki-img-wrap';
          wrap.title = img.caption;
          var imgEl = document.createElement('img');
          imgEl.src = img.thumb;
          imgEl.alt = img.caption;
          imgEl.loading = 'lazy';
          var caption = document.createElement('div');
          caption.className = 'chat-wiki-img-caption';
          caption.textContent = img.caption;

          wrap.appendChild(imgEl);
          wrap.appendChild(caption);

          // Click to view full size
          wrap.addEventListener('click', function () {
            var overlay = document.createElement('div');
            overlay.className = 'chat-wiki-overlay';
            var fullImg = document.createElement('img');
            fullImg.src = img.full;
            fullImg.alt = img.caption;
            overlay.appendChild(fullImg);
            overlay.addEventListener('click', function () { overlay.remove(); });
            document.body.appendChild(overlay);
          });

          gallery.appendChild(wrap);
        });

        container.appendChild(gallery);
        targetDiv.appendChild(container);
        chatMessages.scrollTop = chatMessages.scrollHeight;
      }

      function showImageShimmer(targetDiv) {
        var container = document.createElement('div');
        container.className = 'chat-wiki-images';
        container.innerHTML = '<p class="chat-wiki-images-label">📷 Finding related images...</p>';
        var shimmerWrap = document.createElement('div');
        shimmerWrap.className = 'chat-wiki-img-loading';
        for (var s = 0; s < 3; s++) {
          var shimmer = document.createElement('div');
          shimmer.className = 'shimmer';
          shimmerWrap.appendChild(shimmer);
        }
        container.appendChild(shimmerWrap);
        targetDiv.appendChild(container);
        chatMessages.scrollTop = chatMessages.scrollHeight;
        return container;
      }

      function appendMsg(content, isUser) {
        var div = document.createElement('div');
        div.className = 'chat-msg ' + (isUser ? 'user' : 'bot');
        if (isUser) {
          div.textContent = content;
        } else {
          div.innerHTML = '<div class="chat-msg-text">' + formatBotContent(content) + '</div>';
        }
        chatMessages.appendChild(div);
        chatMessages.scrollTop = chatMessages.scrollHeight;
        return div;
      }
      function setLoading(loading) {
        var last = chatMessages.querySelector('.chat-msg.bot:last-child');
        if (loading && last && last.classList.contains('loading')) return;
        if (loading) {
          var d = document.createElement('div');
          d.className = 'chat-msg bot loading';
          d.textContent = '';
          chatMessages.appendChild(d);
          chatMessages.scrollTop = chatMessages.scrollHeight;
        } else {
          var l = chatMessages.querySelector('.chat-msg.bot.loading');
          if (l) l.remove();
        }
      }
      function sendChat() {
        var text = (chatInput.value || '').trim();
        // Allow sending if there's an image even if text is empty (or provide a default prompt)
        if (!text && !currentImageBase64) return;

        chatInput.value = '';

        // If image present but no text, provide a default prompt to the AI
        if (!text && currentImageBase64) {
          text = "What is in this image?";
        }

        var imageToSend = currentImageBase64; // Capture current image

        // Clear preview
        if (currentImageBase64) {
          currentImageBase64 = null;
          fileInput.value = '';
          previewContainer.style.display = 'none';
        }

        // Activate ChatGPT layout on first message
        var layout = document.getElementById('chatgpt-layout');
        if (layout && !layout.classList.contains('active')) {
          layout.classList.add('active');
        }

        // Show user message (with image if applicable)
        var userMsgHTML = escapeHtml(text);
        if (imageToSend) {
          userMsgHTML += '<br><img src="' + imageToSend + '" style="max-width:200px;border-radius:8px;margin-top:8px;">';
        }

        var uDiv = document.createElement('div');
        uDiv.className = 'chat-msg user';
        uDiv.innerHTML = userMsgHTML;
        chatMessages.appendChild(uDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;

        logActivity('AI Chatbot', text.substring(0, 60));
        setLoading(true);
        var botDiv = null;
        var wikiImagesPromise = null;
        var userQuery = text;

        // Start fetching Wikipedia images in parallel (if applicable)
        if (shouldFetchImages(userQuery)) {
          var topic = extractSearchTopic(userQuery);
          wikiImagesPromise = fetchWikipediaImages(topic);
        }

        function attachImages(targetDiv) {
          if (!wikiImagesPromise || !targetDiv) return;
          var shimmer = showImageShimmer(targetDiv);
          wikiImagesPromise.then(function (images) {
            shimmer.remove();
            appendWikiImages(targetDiv, images);
          }).catch(function () {
            shimmer.remove();
          });
        }

        function appendStreamChunk(chunk, full) {
          if (!botDiv) {
            setLoading(false);
            botDiv = document.createElement('div');
            botDiv.className = 'chat-msg bot';
            botDiv.innerHTML = '<div class="chat-msg-text">' + formatBotContent(full) + '</div>';
            chatMessages.appendChild(botDiv);
          } else {
            // Preserve wiki images container if already appended
            var existingWiki = botDiv.querySelector('.chat-wiki-images');
            var textContainer = botDiv.querySelector('.chat-msg-text');
            if (!textContainer) {
              textContainer = document.createElement('div');
              textContainer.className = 'chat-msg-text';
              botDiv.insertBefore(textContainer, botDiv.firstChild);
            }
            textContainer.innerHTML = formatBotContent(full);
          }
          chatMessages.scrollTop = chatMessages.scrollHeight;
        }
        (AILibrary.configReady || Promise.resolve()).then(function () {
          if (AILibrary.ai.chatStream && AILibrary.config.useGemini) {
            AILibrary.ai.chatStream([{ role: 'user', content: text }], appendStreamChunk)
              .then(function (reply) {
                setLoading(false);
                if (!botDiv) botDiv = appendMsg(reply || 'No response.', false);
                attachImages(botDiv);
              })
              .catch(function (err) {
                setLoading(false);
                if (botDiv) botDiv.remove();
                var msg = err && err.message ? err.message : 'Request failed.';
                appendMsg('Error: ' + msg, false);
              });
          } else {
            // Construct payload for chat: support text + optional image
            // If image is present, we must use the 'user' role with content parts
            var payload = { role: 'user', parts: [] };
            payload.parts.push({ text: text });

            if (imageToSend) {
              // Extract base64 (remove data:image/xyz;base64, prefix)
              var base64Data = imageToSend.split(',')[1];
              var mimeType = imageToSend.split(';')[0].split(':')[1];
              payload.parts.push({
                inline_data: {
                  mime_type: mimeType,
                  data: base64Data
                }
              });
            }

            // AILibrary.ai.chat expects an array of messages. 
            // NOTE: The current simple `chat` function in AILibrary.ai might need a slight tweak 
            // to handle the `parts` structure if it doesn't already. 
            // Let's look at `chat` and `geminiRequest`.
            // `chat` calls `geminiRequest(prompt)`. 
            // We need to bypass the simple string prompt and pass the full request body or adapt `geminiRequest`.

            // To avoid breaking existing logic, let's call a new method or modify `geminiRequest` to accept objects.
            // OR: We can manually construct the request here since logic is inside script.js.

            // Actually, let's use the visible `geminiRequestWithRetry` if we can access it, 
            // or better, let's modify `AILibrary.ai.chat` to handle this.
            // For now, I will assume we can pass the complex object to `geminiRequest` if we modify it.
            // BUT, `geminiRequest` takes a STRING prompt currently.

            // Strategy: We will call `AILibrary.ai.chat` but pass the special structure.
            // We need to update `AILibrary.ai.chat` and `geminiRequest` to handle this `parts` array vs string.

            AILibrary.ai.chat([{ role: 'user', content: payload.parts }])
              .then(function (reply) {
                setLoading(false);
                botDiv = appendMsg(reply || 'No response.', false);
                attachImages(botDiv);
              })
              .catch(function (err) {
                setLoading(false);
                appendMsg('Error: ' + (err.message || 'Request failed.'), false);
              });
          }
        }).catch(function (err) {
          setLoading(false);
          appendMsg('Error: ' + (err.message || 'Request failed.'), false);
        });
      }
      chatSend.addEventListener('click', sendChat);
      chatInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
          e.preventDefault();
          sendChat();
        }
      });

      // --- Image Upload Logic ---
      var fileInput = document.getElementById('chat-file-input');
      var previewContainer = document.getElementById('chat-image-preview');
      var previewImg = document.getElementById('chat-preview-img');
      var previewClose = document.getElementById('chat-preview-close');
      var currentImageBase64 = null;

      if (fileInput && previewContainer) {
        fileInput.addEventListener('change', function (e) {
          var file = e.target.files[0];
          if (!file) return;
          var reader = new FileReader();
          reader.onload = function (evt) {
            currentImageBase64 = evt.target.result; // data:image/png;base64,...
            previewImg.src = currentImageBase64;
            previewContainer.style.display = 'block';
            chatInput.focus();
          };
          reader.readAsDataURL(file);
        });

        previewClose.addEventListener('click', function () {
          fileInput.value = '';
          currentImageBase64 = null;
          previewContainer.style.display = 'none';
        });
      }

      var chatClear = document.getElementById('chat-clear');
      if (chatClear) {
        chatClear.addEventListener('click', function () {
          // Identify active section
          var activeSectionId = '';
          var activeSection = document.querySelector('.dashboard-section.active');
          if (activeSection) activeSectionId = activeSection.id;

          if (activeSectionId === 'section-chatbot') {
            chatMessages.innerHTML = '';
            if (chatInput) chatInput.value = '';
            // Reset back to welcome state
            var layout = document.getElementById('chatgpt-layout');
            if (layout) layout.classList.remove('active');
          }
          else if (activeSectionId === 'section-code-explainer') {
            var result = document.getElementById('explainer-result');
            var code = document.getElementById('explainer-code');
            var layout = document.getElementById('explainer-layout');
            var welcome = document.getElementById('explainer-welcome');
            if (result) result.innerHTML = '';
            if (code) code.value = '';
            if (layout) layout.classList.remove('active');
            if (welcome) { welcome.style.opacity = '1'; welcome.style.flex = '1'; welcome.style.pointerEvents = 'auto'; }
          }
          else if (activeSectionId === 'section-code-generator') {
            var result = document.getElementById('generator-result-area');
            var prompt = document.getElementById('generator-prompt');
            var layout = document.getElementById('generator-layout');
            var welcome = document.getElementById('generator-welcome');
            if (result) result.innerHTML = '';
            if (prompt) prompt.value = '';
            if (layout) layout.classList.remove('active');
            if (welcome) { welcome.style.opacity = '1'; welcome.style.flex = '1'; welcome.style.pointerEvents = 'auto'; }
          }
          else if (activeSectionId === 'section-assistant') {
            var result = document.getElementById('assistant-result');
            var input = document.getElementById('assistant-input');
            var layout = document.getElementById('assistant-layout');
            var welcome = document.getElementById('assistant-welcome');
            if (result) result.innerHTML = '';
            if (input) input.value = '';
            if (layout) layout.classList.remove('active');
            if (welcome) { welcome.style.opacity = '1'; welcome.style.flex = '1'; welcome.style.pointerEvents = 'auto'; }
          }
          else if (activeSectionId === 'section-prompt-generator') {
            var result = document.getElementById('prompt-gen-result-area');
            var input = document.getElementById('prompt-gen-input');
            var layout = document.getElementById('prompt-gen-layout');
            var welcome = document.getElementById('prompt-gen-welcome');
            if (result) result.innerHTML = '';
            if (input) input.value = '';
            if (layout) layout.classList.remove('active');
            if (welcome) { welcome.style.opacity = '1'; welcome.style.flex = '1'; welcome.style.pointerEvents = 'auto'; }
          }

          else if (activeSectionId === 'section-bg-remover') {
            var input = document.getElementById('bg-file-input');
            var preview = document.getElementById('bg-preview-wrap');
            var status = document.getElementById('bg-status');
            var label = document.getElementById('bg-file-label');
            if (input) input.value = '';
            if (preview) preview.style.display = 'none';
            if (status) status.textContent = '';
            if (label) label.textContent = 'Click + to upload an image';
          }
          else if (activeSectionId === 'section-qr-generator') {
            var link = document.getElementById('qr-link-input');
            var display = document.getElementById('qr-code-display');
            var layout = document.getElementById('qr-layout');
            var welcome = document.getElementById('qr-welcome');
            if (link) link.value = '';
            if (display) {
              display.innerHTML = '';
              display.style.display = 'none';
            }
            if (layout) layout.classList.remove('active');
            if (welcome) { welcome.style.opacity = '1'; welcome.style.flex = '1'; welcome.style.pointerEvents = 'auto'; }
          }
        });
      }

      // Mic button — Web Speech API voice input
      var micBtn = document.getElementById('chat-mic-btn');
      if (micBtn) {
        var SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
        if (SpeechRecognition) {
          var recognition = new SpeechRecognition();
          recognition.lang = 'en-US';
          recognition.interimResults = false;
          recognition.continuous = false;
          var isRecording = false;

          micBtn.addEventListener('click', function () {
            if (isRecording) {
              recognition.stop();
              return;
            }
            isRecording = true;
            micBtn.classList.add('recording');
            recognition.start();
          });

          recognition.addEventListener('result', function (e) {
            var transcript = '';
            for (var i = e.resultIndex; i < e.results.length; i++) {
              transcript += e.results[i][0].transcript;
            }
            if (transcript) {
              chatInput.value = (chatInput.value ? chatInput.value + ' ' : '') + transcript;
              chatInput.focus();
            }
          });

          recognition.addEventListener('end', function () {
            isRecording = false;
            micBtn.classList.remove('recording');
          });

          recognition.addEventListener('error', function () {
            isRecording = false;
            micBtn.classList.remove('recording');
          });
        } else {
          micBtn.title = 'Voice input not supported in this browser';
          micBtn.style.opacity = '0.4';
          micBtn.style.cursor = 'default';
        }
      }

      // Attach button — triggers hidden file input
      var attachBtn = document.getElementById('chat-attach-btn');
      if (attachBtn && fileInput) {
        attachBtn.addEventListener('click', function () {
          fileInput.click();
        });
      }
    }

    // Code Explainer
    // ========== Reusable ChatGPT-layout activator ==========
    function activateToolLayout(layoutId, welcomeId) {
      var layout = document.getElementById(layoutId);
      var welcome = document.getElementById(welcomeId);
      if (layout) layout.classList.add('active');
      if (welcome) { welcome.style.opacity = '0'; welcome.style.flex = '0'; welcome.style.pointerEvents = 'none'; }
    }

    function addToolMessage(containerId, content, type) {
      var container = document.getElementById(containerId);
      if (!container) return;
      container.style.display = 'flex';
      var msg = document.createElement('div');
      msg.className = 'chat-msg ' + (type || 'bot');
      msg.innerHTML = content;
      container.appendChild(msg);
      container.scrollTop = container.scrollHeight;
      return msg;
    }

    // Code Explainer
    var explainerBtn = document.getElementById('explainer-btn');
    var explainerCode = document.getElementById('explainer-code');
    var explainerResult = document.getElementById('explainer-result');
    if (explainerBtn && explainerCode) {
      function handleExplain() {
        var code = (explainerCode.value || '').trim();
        if (!code) return;
        activateToolLayout('explainer-layout', 'explainer-welcome');
        addToolMessage('explainer-result', '<pre style="white-space:pre-wrap;margin:0;font-size:0.85rem">' + escapeHtml(code.substring(0, 200)) + (code.length > 200 ? '...' : '') + '</pre>', 'user');
        var botMsg = addToolMessage('explainer-result', 'Explaining...', 'bot');
        explainerCode.value = '';
        logActivity('Code Explainer', code.substring(0, 60));
        var systemPrompt = 'You are a code explainer. Explain the following code in simple, clear language. Be concise but cover what the code does step by step. Do not include the code again, only the explanation.';
        AILibrary.ai.complete('Explain this code:\n\n' + code, systemPrompt)
          .then(function (text) { botMsg.innerHTML = escapeHtml(text); })
          .catch(function (err) { botMsg.innerHTML = '<span style="color:#ff6b6b">' + escapeHtml(err.message || 'Request failed.') + '</span>'; });
      }
      explainerBtn.addEventListener('click', handleExplain);
      explainerCode.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleExplain(); }
      });
    }

    // Code Generator
    var generatorBtn = document.getElementById('generator-btn');
    var generatorPrompt = document.getElementById('generator-prompt');
    var generatorLang = document.getElementById('generator-lang');
    if (generatorBtn && generatorPrompt) {
      function handleGenerate() {
        var prompt = (generatorPrompt.value || '').trim();
        if (!prompt) return;
        var lang = (generatorLang && generatorLang.value) || 'HTML/CSS/JavaScript';
        activateToolLayout('generator-layout', 'generator-welcome');
        addToolMessage('generator-result-area', escapeHtml(prompt) + ' <span style="opacity:0.5">(' + lang + ')</span>', 'user');
        var botMsg = addToolMessage('generator-result-area', 'Generating...', 'bot');
        generatorPrompt.value = '';
        logActivity('Code Generator', prompt.substring(0, 60) + ' (' + lang + ')');
        var systemPrompt = 'You are a code generator. Generate only the requested code, no extra commentary before or after. Output plain code that the user can copy. Use the requested language: ' + lang + '.';
        AILibrary.ai.complete('Generate code for: ' + prompt + '\n\nLanguage: ' + lang, systemPrompt)
          .then(function (text) {
            var code = stripMarkdownCode(text);
            botMsg.innerHTML = '<pre style="white-space:pre-wrap;margin:0;font-size:0.85rem;cursor:pointer" title="Click to copy">' + escapeHtml(code || text) + '</pre>';
            botMsg.querySelector('pre').addEventListener('click', function () {
              navigator.clipboard.writeText(code || text).then(function () {
                botMsg.querySelector('pre').style.outline = '2px solid #22c55e';
                setTimeout(function () { botMsg.querySelector('pre').style.outline = ''; }, 1000);
              });
            });
          })
          .catch(function (err) { botMsg.innerHTML = '<span style="color:#ff6b6b">' + escapeHtml(err.message || 'Request failed.') + '</span>'; });
      }
      generatorBtn.addEventListener('click', handleGenerate);
      generatorPrompt.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { e.preventDefault(); handleGenerate(); }
      });
    }

    // AI Assistant
    var assistantBtn = document.getElementById('assistant-btn');
    var assistantInput = document.getElementById('assistant-input');
    if (assistantBtn && assistantInput) {
      function handleAssistant() {
        var prompt = (assistantInput.value || '').trim();
        if (!prompt) return;
        activateToolLayout('assistant-layout', 'assistant-welcome');
        addToolMessage('assistant-result', escapeHtml(prompt), 'user');
        var botMsg = addToolMessage('assistant-result', 'Thinking...', 'bot');
        assistantInput.value = '';
        logActivity('AI Assistant', prompt.substring(0, 60));
        AILibrary.ai.complete(prompt)
          .then(function (text) { botMsg.innerHTML = escapeHtml(text); })
          .catch(function (err) { botMsg.innerHTML = '<span style="color:#ff6b6b">' + escapeHtml(err.message || 'Request failed.') + '</span>'; });
      }
      assistantBtn.addEventListener('click', handleAssistant);
      assistantInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { e.preventDefault(); handleAssistant(); }
      });
    }

    // Prompt Generator
    var promptGenBtn = document.getElementById('prompt-gen-btn');
    var promptGenInput = document.getElementById('prompt-gen-input');
    var promptGenType = document.getElementById('prompt-gen-type');
    if (promptGenBtn && promptGenInput) {
      function handlePromptGen() {
        var idea = (promptGenInput.value || '').trim();
        if (!idea) return;
        var pType = (promptGenType && promptGenType.value) || 'general';
        activateToolLayout('prompt-gen-layout', 'prompt-gen-welcome');
        addToolMessage('prompt-gen-result-area', escapeHtml(idea) + ' <span style="opacity:0.5">(' + pType + ')</span>', 'user');
        var botMsg = addToolMessage('prompt-gen-result-area', 'Generating...', 'bot');
        promptGenInput.value = '';
        logActivity('Prompt Generator', idea.substring(0, 60) + ' (' + pType + ')');
        var typeInstructions = {
          image: 'Generate a single, detailed prompt suitable for AI image generators (e.g. DALL·E, Midjourney, Stable Diffusion). Include style, lighting, composition, and mood. Output only the prompt, no extra text.',
          story: 'Generate a writing prompt that will help someone write a short story or creative piece. Be specific about tone, setting, and direction. Output only the prompt.',
          ad: 'Generate a concise, punchy marketing or ad copy prompt. Include target audience and key message. Output only the prompt.',
          general: 'Generate a clear, detailed prompt that captures the user\'s idea and can be used with any AI tool. Output only the prompt.'
        };
        var systemPrompt = 'You are an expert prompt engineer. ' + (typeInstructions[pType] || typeInstructions.general);
        AILibrary.ai.complete('User idea: ' + idea + '\n\nGenerate an optimized prompt for this idea.', systemPrompt)
          .then(function (text) {
            botMsg.innerHTML = escapeHtml((text || '').trim() || 'No output.');
            botMsg.style.cursor = 'pointer';
            botMsg.title = 'Click to copy';
            botMsg.addEventListener('click', function () {
              navigator.clipboard.writeText(text.trim()).then(function () {
                botMsg.style.outline = '2px solid #22c55e';
                setTimeout(function () { botMsg.style.outline = ''; }, 1000);
              });
            });
          })
          .catch(function (err) { botMsg.innerHTML = '<span style="color:#ff6b6b">' + escapeHtml(err.message || 'Request failed.') + '</span>'; });
      }
      promptGenBtn.addEventListener('click', handlePromptGen);
      promptGenInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { e.preventDefault(); handlePromptGen(); }
      });
    }

    // Background Remover
    var bgUploadZone = document.getElementById('bg-upload-zone');
    var bgFileInput = document.getElementById('bg-file-input');
    var bgPreviewWrap = document.getElementById('bg-preview-wrap');
    var bgOriginal = document.getElementById('bg-original');
    var bgRemoved = document.getElementById('bg-removed');
    var bgClear = document.getElementById('bg-clear');
    var bgStatus = document.getElementById('bg-status');
    var bgDownloadBtn = document.getElementById('bg-download-btn');
    if (bgClear && bgFileInput && bgPreviewWrap) {
      bgClear.addEventListener('click', function () {
        bgFileInput.value = '';
        bgPreviewWrap.style.display = 'none';
        if (bgOriginal) bgOriginal.src = '';
        if (bgRemoved) bgRemoved.src = '';
        if (bgStatus) bgStatus.textContent = '';
        if (bgDownloadBtn) bgDownloadBtn.style.display = 'none';
      });
    }
    if (bgUploadZone && bgFileInput) {
      bgUploadZone.addEventListener('click', function () { bgFileInput.click(); });
      bgUploadZone.addEventListener('dragover', function (e) { e.preventDefault(); bgUploadZone.style.borderColor = 'rgba(102,126,234,0.6)'; });
      bgUploadZone.addEventListener('dragleave', function () { bgUploadZone.style.borderColor = ''; });
      bgUploadZone.addEventListener('drop', function (e) {
        e.preventDefault();
        bgUploadZone.style.borderColor = '';
        var file = e.dataTransfer.files[0];
        if (file && file.type.indexOf('image/') === 0) handleBgFile(file);
      });
      bgFileInput.addEventListener('change', function () {
        var file = this.files[0];
        if (file) handleBgFile(file);
        this.value = '';
      });
    }

    function handleBgFile(file) {
      if (!bgPreviewWrap || !bgOriginal || !bgRemoved || !bgDownloadBtn || !bgStatus) return;
      activateToolLayout('bg-layout', 'bg-welcome');
      var label = document.getElementById('bg-file-label');
      if (label) label.textContent = file.name;
      bgStatus.textContent = 'Processing...';
      bgPreviewWrap.style.display = 'block';
      bgDownloadBtn.style.display = 'none';
      bgOriginal.src = URL.createObjectURL(file);
      bgRemoved.src = '';
      AILibrary.backgroundRemover.removeBackground(file)
        .then(function (blob) {
          bgRemoved.src = URL.createObjectURL(blob);
          bgDownloadBtn.href = URL.createObjectURL(blob);
          bgDownloadBtn.download = 'no-bg.png';
          bgDownloadBtn.style.display = 'inline-flex';
          bgStatus.textContent = 'Background removed. Download the image below.';
        })
        .catch(function (err) {
          bgStatus.textContent = 'Error: ' + (err.message || 'Failed to remove background.');
        });
    }







  }

  function escapeHtml(s) {
    var div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
  }

  function stripMarkdownCode(text) {
    if (!text) return text;
    var m = text.match(/```[\w]*\n?([\s\S]*?)```/);
    if (m) return m[1].trim();
    return text.trim();
  }

  return { init: init, showSection: showSection };
})();
