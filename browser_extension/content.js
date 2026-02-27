
// Auto-detect login forms and show popup
(function() {
  'use strict';

  let vaultPopup = null;
  let detectedMatches = [];
  let selectedEntryId = null;
  let apiUrl = null;
  let token = null;
  let hasAutofilled = false; // Track if autofill was already done
  let autofillTimestamp = 0; // Track when autofill happened
  let isChecking = false; // Prevent multiple simultaneous checks
  let lastFilledPassword = null; // Track last autofilled password
  let lastFilledEntryId = null; // Track which entry was autofilled
  let savePromptShown = false; // Track if save prompt was already shown for this attempt
  let formSubmissionTracked = false; // Track if form submit was already processed for update prompt
  const shownAttemptIds = new Set(); // Track which attemptIds have shown prompts

  // Load settings from storage
  async function loadSettings() {
    try {
      const data = await chrome.storage.local.get(['apiUrl', 'token']);
      apiUrl = data.apiUrl || 'http://127.0.0.1:5005';
      token = data.token || '';
      return apiUrl && token;
    } catch (e) {
      return false;
    }
  }

  // Check if fields are completely empty (for showing popup)
  function areFieldsEmpty() {
    const passwordFields = document.querySelectorAll('input[type="password"]');
    for (const pwdField of passwordFields) {
      if (pwdField.value && pwdField.value.trim().length > 0) {
        return false;
      }
    }
    
    const usernameFields = document.querySelectorAll(
      'input[type="email"], input[type="text"], input[name*="user" i], input[name*="email" i], input[id*="user" i], input[id*="email" i]'
    );
    for (const userField of usernameFields) {
      if (userField.type !== 'password' && userField.value && userField.value.trim().length > 0) {
        return false;
      }
    }
    
    return true;
  }

  // Check if fields are already filled
  function areFieldsFilled() {
    const passwordFields = document.querySelectorAll('input[type="password"]');
    for (const pwdField of passwordFields) {
      if (pwdField.value && pwdField.value.trim().length > 0) {
        return true;
      }
    }
    
    const usernameFields = document.querySelectorAll(
      'input[type="email"], input[type="text"], input[name*="user" i], input[name*="email" i], input[id*="user" i], input[id*="email" i]'
    );
    for (const userField of usernameFields) {
      if (userField.type !== 'password' && userField.value && userField.value.trim().length > 0) {
        return true;
      }
    }
    
    return false;
  }

  // Detect if page has login/signup form
  function detectLoginForm() {
    // Don't detect if already autofilled recently (within 30 seconds)
    const now = Date.now();
    if (hasAutofilled && (now - autofillTimestamp) < 30000) {
      return false;
    }

    // ONLY show popup if fields are completely EMPTY
    if (!areFieldsEmpty()) {
      return false;
    }

    // Look for password fields
    const passwordFields = document.querySelectorAll('input[type="password"]');
    if (passwordFields.length === 0) return false;

    // Look for username/email fields near password fields
    for (const pwdField of passwordFields) {
      const form = pwdField.closest('form');
      if (!form) continue;

      // Check for username/email fields in the same form
      const usernameFields = form.querySelectorAll(
        'input[type="email"], input[type="text"], input[name*="user" i], input[name*="email" i], input[id*="user" i], input[id*="email" i]'
      );
      
      if (usernameFields.length > 0) {
        return true;
      }
    }
    return false;
  }

  // Fetch matches from extension server (via background to avoid CORS from page origin)
  async function fetchMatches() {
    if (!apiUrl || !token) {
      await loadSettings();
      if (!apiUrl || !token) return [];
    }

    try {
      const url = window.location.href;
      const endpoint = `${apiUrl.replace(/\/$/, '')}/api/extension/get-matches?url=${encodeURIComponent(url)}&token=${encodeURIComponent(token)}`;
      const proxyRes = await chrome.runtime.sendMessage({ type: 'FETCH_EXTENSION_API', url: endpoint, method: 'GET' });
      const res = { ok: proxyRes.ok, status: proxyRes.status };
      const data = proxyRes.data;
      const matches = (data && data.ok) ? (data.matches || []) : [];
      if (!res.ok) return [];
      if (!data || !data.ok) return [];
      return data.matches || [];
    } catch (e) {
      return [];
    }
  }

  // Create popup overlay
  function createPopup() {
    if (vaultPopup) return;

    vaultPopup = document.createElement('div');
    vaultPopup.id = 'secure-vault-popup';
    vaultPopup.innerHTML = `
      <div class="sv-popup-container">
        <div class="sv-popup-header">
          <span class="sv-popup-title">🔐 Secure Vault</span>
          <button class="sv-popup-close" id="sv-close-btn">×</button>
        </div>
        <div class="sv-popup-content">
          <div id="sv-matches-list"></div>
          <div id="sv-phrase-dialog" style="display: none;">
            <div class="sv-phrase-title">Enter Master Phrase</div>
            <div class="sv-phrase-hint">Enter your login passphrase to autofill credentials.</div>
            <input type="password" id="sv-phrase-input" class="sv-phrase-input" placeholder="Master phrase" />
            <div class="sv-phrase-buttons">
              <button id="sv-verify-btn" class="sv-btn-primary">Verify & Fill</button>
              <button id="sv-cancel-btn" class="sv-btn-secondary">Cancel</button>
            </div>
          </div>
          <div id="sv-status" class="sv-status"></div>
          <div class="sv-skip-section">
            <button id="sv-skip-btn" class="sv-btn-skip">Skip - I'll fill manually</button>
          </div>
        </div>
      </div>
    `;

    // Add styles
    const style = document.createElement('style');
    style.textContent = `
      #secure-vault-popup {
        position: fixed;
        top: 60px;
        right: 20px;
        z-index: 999999;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
        pointer-events: auto;
      }
      .sv-popup-container {
        background: white;
        border-radius: 8px;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15), 0 4px 16px rgba(0, 0, 0, 0.1);
        width: 360px;
        max-height: 500px;
        overflow: hidden;
        display: flex;
        flex-direction: column;
        border: 1px solid #e5e7eb;
      }
      .sv-popup-header {
        background: #f9fafb;
        color: #111827;
        padding: 12px 16px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        border-bottom: 1px solid #e5e7eb;
      }
      .sv-popup-title {
        font-weight: 600;
        font-size: 14px;
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .sv-popup-title::before {
        content: '🔐';
        font-size: 16px;
      }
      .sv-popup-close {
        background: none;
        border: none;
        color: #6b7280;
        font-size: 20px;
        cursor: pointer;
        padding: 0;
        width: 24px;
        height: 24px;
        line-height: 1;
        display: flex;
        align-items: center;
        justify-content: center;
      }
      .sv-popup-close:hover {
        color: #111827;
        background: #f3f4f6;
        border-radius: 4px;
      }
      .sv-popup-content {
        padding: 12px 16px;
        overflow-y: auto;
        flex: 1;
        max-height: 400px;
      }
      #sv-matches-list {
        max-height: 250px;
        overflow-y: auto;
      }
      .sv-match-item {
        padding: 10px 12px;
        margin: 6px 0;
        border: 1px solid #e5e7eb;
        border-radius: 6px;
        cursor: pointer;
        background: #ffffff;
        transition: all 0.2s;
      }
      .sv-match-item:hover {
        background: #f9fafb;
        border-color: #2563eb;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
      }
      .sv-match-service {
        font-weight: 600;
        color: #111827;
        margin-bottom: 4px;
        font-size: 14px;
      }
      .sv-match-username {
        color: #6b7280;
        font-size: 13px;
      }
      .sv-match-url {
        color: #9ca3af;
        font-size: 11px;
        margin-top: 2px;
      }
      #sv-phrase-dialog {
        margin-top: 12px;
      }
      .sv-phrase-title {
        font-weight: 600;
        margin-bottom: 6px;
        color: #111827;
        font-size: 14px;
      }
      .sv-phrase-hint {
        font-size: 12px;
        color: #6b7280;
        margin-bottom: 10px;
      }
      .sv-phrase-input {
        width: 100%;
        padding: 8px 10px;
        border: 1px solid #d1d5db;
        border-radius: 6px;
        font-size: 13px;
        box-sizing: border-box;
        margin-bottom: 10px;
      }
      .sv-phrase-input:focus {
        outline: none;
        border-color: #2563eb;
        box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.1);
      }
      .sv-phrase-buttons {
        display: flex;
        gap: 8px;
      }
      .sv-btn-primary, .sv-btn-secondary {
        flex: 1;
        padding: 8px 12px;
        border: none;
        border-radius: 6px;
        font-size: 13px;
        font-weight: 500;
        cursor: pointer;
        transition: all 0.2s;
      }
      .sv-btn-primary {
        background: #2563eb;
        color: white;
      }
      .sv-btn-primary:hover {
        background: #1d4ed8;
      }
      .sv-btn-secondary {
        background: #f3f4f6;
        color: #374151;
        border: 1px solid #e5e7eb;
      }
      .sv-btn-secondary:hover {
        background: #e5e7eb;
      }
      .sv-status {
        margin-top: 10px;
        font-size: 12px;
        color: #6b7280;
        min-height: 18px;
      }
      .sv-status.error {
        color: #dc2626;
      }
      .sv-status.success {
        color: #16a34a;
      }
      .sv-skip-section {
        margin-top: 12px;
        padding-top: 12px;
        border-top: 1px solid #e5e7eb;
        text-align: center;
      }
      .sv-btn-skip {
        background: transparent;
        border: none;
        color: #6b7280;
        font-size: 12px;
        cursor: pointer;
        text-decoration: underline;
        padding: 4px 8px;
      }
      .sv-btn-skip:hover {
        color: #374151;
      }
    `;
    document.head.appendChild(style);
    document.body.appendChild(vaultPopup);

    // Event listeners
    document.getElementById('sv-close-btn').addEventListener('click', closePopup);
    document.getElementById('sv-verify-btn').addEventListener('click', verifyAndFill);
    document.getElementById('sv-cancel-btn').addEventListener('click', cancelPhrase);
    document.getElementById('sv-skip-btn').addEventListener('click', skipAutofill);
    
    // Enter key in phrase input
    document.getElementById('sv-phrase-input').addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        verifyAndFill();
      }
    });

    // Don't close on outside click for corner popup - user can use X button or Skip
  }

  // Show matches in popup
  function showMatches(matches) {
    if (!vaultPopup) createPopup();

    const matchesList = document.getElementById('sv-matches-list');
    const phraseDialog = document.getElementById('sv-phrase-dialog');
    const status = document.getElementById('sv-status');

    matchesList.style.display = 'block';
    phraseDialog.style.display = 'none';
    status.textContent = '';
    status.className = 'sv-status';

    if (matches.length === 0) {
      matchesList.innerHTML = '<div style="text-align: center; color: #6b7280; padding: 16px; font-size: 13px;">No saved credentials found for this website.</div>';
      return;
    }

    matchesList.innerHTML = '<div style="font-weight: 600; margin-bottom: 10px; color: #111827; font-size: 13px;">Select a credential:</div>';

    matches.forEach(match => {
      const item = document.createElement('div');
      item.className = 'sv-match-item';
      item.innerHTML = `
        <div class="sv-match-service">${escapeHtml(match.service || 'Unknown Service')}</div>
        <div class="sv-match-username">${escapeHtml(match.username || 'No username')}</div>
        ${match.url ? `<div class="sv-match-url">${escapeHtml(match.url)}</div>` : ''}
      `;
      item.addEventListener('click', () => {
        selectedEntryId = match.id;
        showPhraseDialog(match);
      });
      matchesList.appendChild(item);
    });
  }

  // Show phrase dialog
  function showPhraseDialog(match) {
    const matchesList = document.getElementById('sv-matches-list');
    const phraseDialog = document.getElementById('sv-phrase-dialog');
    const phraseInput = document.getElementById('sv-phrase-input');
    const status = document.getElementById('sv-status');

    matchesList.style.display = 'none';
    phraseDialog.style.display = 'block';
    phraseInput.value = '';
    phraseInput.focus();
    status.textContent = `Selected: ${match.service} (${match.username})`;
    status.className = 'sv-status';
  }

  // Verify phrase and autofill
  async function verifyAndFill() {
    const phraseInput = document.getElementById('sv-phrase-input');
    const phrase = phraseInput.value.trim();
    const status = document.getElementById('sv-status');

    if (!phrase) {
      status.textContent = '❌ Please enter your master phrase.';
      status.className = 'sv-status error';
      return;
    }

    if (!selectedEntryId) {
      status.textContent = '❌ No entry selected.';
      status.className = 'sv-status error';
      return;
    }

    if (!apiUrl || !token) {
      await loadSettings();
      if (!apiUrl || !token) {
        status.textContent = '❌ Extension not configured. Set API URL and token in extension popup.';
        status.className = 'sv-status error';
        return;
      }
    }

    status.textContent = 'Verifying...';
    status.className = 'sv-status';

    try {
      const endpoint = `${apiUrl.replace(/\/$/, '')}/api/extension/verify-phrase`;
      const proxyRes = await chrome.runtime.sendMessage({
        type: 'FETCH_EXTENSION_API',
        url: endpoint,
        method: 'POST',
        body: { token: token, entry_id: selectedEntryId, phrase: phrase }
      });
      const res = { ok: proxyRes.ok, status: proxyRes.status };
      const data = proxyRes.data;

      if (!res.ok) {
        if (res.status === 401) {
          phraseInput.value = '';
          status.textContent = '❌ Invalid master phrase. Please try again.';
          status.className = 'sv-status error';
          return;
        }
        status.textContent = `❌ Verification failed: HTTP ${res.status}`;
        status.className = 'sv-status error';
        return;
      }
      if (!data.ok || !data.entry) {
        status.textContent = data.message || 'Failed to get entry.';
        status.className = 'sv-status error';
        return;
      }

      // Autofill - Fill both username and password
      const entry = data.entry;
      const passwordValue = extractPasswordValue(entry.password);
      
      // Extract username - ensure it's a string
      let usernameValue = '';
      if (typeof entry.username === 'string') {
        usernameValue = entry.username;
      } else if (entry.username && typeof entry.username === 'object') {
        usernameValue = entry.username.username || entry.username.value || '';
      } else if (entry.username) {
        usernameValue = String(entry.username);
      }
      
      let usernameFilled = false;
      let passwordFilled = false;

      // Fill username - only if field is empty
      const usernameSelectors = [
        'input[type="email"]',
        'input[name*="email" i]',
        'input[name*="user" i]',
        'input[id*="email" i]',
        'input[id*="user" i]',
        'input[type="text"]'
      ];
      for (const sel of usernameSelectors) {
    const el = document.querySelector(sel);
        if (el && el.type !== 'password' && (!el.value || el.value.trim().length === 0)) {
          // Don't focus - let user continue typing if they want
          el.value = usernameValue;
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
          usernameFilled = true;
          break;
        }
      }

      // Fill password - only if field is empty
      const passwordSelectors = [
        'input[type="password"]',
        'input[name*="pass" i]',
        'input[id*="pass" i]'
      ];
      for (const sel of passwordSelectors) {
        const el = document.querySelector(sel);
        if (el && (!el.value || el.value.trim().length === 0)) {
          // Don't focus - let user continue typing if they want
          el.value = passwordValue;
          el.dispatchEvent(new Event('input', { bubbles: true }));
          el.dispatchEvent(new Event('change', { bubbles: true }));
          passwordFilled = true;
          break;
        }
      }

      if (usernameFilled || passwordFilled) {
        const filledParts = [];
        if (usernameFilled) filledParts.push('username');
        if (passwordFilled) filledParts.push('password');
        status.textContent = `✅ Filled ${filledParts.join(' and ')} for: ${entry.service || 'this site'}`;
        status.className = 'sv-status success';
        
        // Mark as autofilled to prevent showing popup again
        hasAutofilled = true;
        autofillTimestamp = Date.now();
        
        // Track filled password for later comparison
        lastFilledPassword = passwordValue;
        lastFilledEntryId = selectedEntryId;
        savePromptShown = false; // Reset save prompt flag
        
        // Close popup automatically after 1 second (shorter delay for better UX)
        setTimeout(() => {
          closePopup();
        }, 1000);
      } else {
        status.textContent = '⚠️ No input fields found.';
        status.className = 'sv-status error';
      }

      phraseInput.value = '';
      selectedEntryId = null;
    } catch (e) {
      status.textContent = `❌ Error: ${e.message}`;
      status.className = 'sv-status error';
    }
  }

  // Cancel phrase dialog
  function cancelPhrase() {
    const matchesList = document.getElementById('sv-matches-list');
    const phraseDialog = document.getElementById('sv-phrase-dialog');
    const phraseInput = document.getElementById('sv-phrase-input');
    const status = document.getElementById('sv-status');

    matchesList.style.display = 'block';
    phraseDialog.style.display = 'none';
    phraseInput.value = '';
    selectedEntryId = null;
    status.textContent = '';
    status.className = 'sv-status';
  }

  // Skip autofill - user wants to fill manually
  function skipAutofill() {
    // Mark as skipped to prevent showing again for this session
    hasAutofilled = true;
    autofillTimestamp = Date.now();
    closePopup();
  }

  // Close popup
  function closePopup() {
    if (vaultPopup) {
      vaultPopup.remove();
      vaultPopup = null;
      detectedMatches = [];
      selectedEntryId = null;
    }
  }

  // Reset autofill flag when page changes or form is cleared
  function resetAutofillFlag() {
    // Reset if fields are cleared (user manually cleared them)
    if (hasAutofilled && !areFieldsFilled()) {
      const now = Date.now();
      // Only reset if it's been more than 5 seconds since autofill
      if ((now - autofillTimestamp) > 5000) {
        hasAutofilled = false;
        autofillTimestamp = 0;
      }
    }
  }

  // Escape HTML
  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  // Extract actual password string from API response (handles dict/object/stringified dict)
  function extractPasswordValue(raw) {
    if (raw == null || raw === '') return '';
    if (typeof raw === 'string') {
      const s = raw.trim();
      // If string looks like dict repr (e.g. "{'password': 'x', 'totp_secret': None}")
      if (s.startsWith('{') && (s.includes("'password'") || s.includes('"password"'))) {
        try {
          const jsonStr = s.replace(/'/g, '"').replace(/None/g, 'null').replace(/True/g, 'true').replace(/False/g, 'false');
          const parsed = JSON.parse(jsonStr);
          return typeof parsed.password === 'string' ? parsed.password : (parsed.password ? String(parsed.password) : '');
        } catch (e) {
          const m = s.match(/(?:'password'|"password")\s*:\s*['"]([^'"]*)['"]/);
          return m ? m[1] : s;
        }
      }
      return s;
    }
    if (typeof raw === 'object') {
      return raw.password || raw.value || '';
    }
    return String(raw);
  }

  // Main detection logic
  async function checkAndShowPopup() {
    // Skip if already checking (prevent multiple simultaneous checks)
    if (isChecking) return;
    
    // Skip if popup already shown
    if (vaultPopup) return;

    // Skip if already autofilled/skipped recently (within 30 seconds)
    const now = Date.now();
    if (hasAutofilled && (now - autofillTimestamp) < 30000) {
      return;
    }

    // Check if login form exists
    const hasLoginForm = detectLoginForm();
    if (!hasLoginForm) return;

    // ONLY show if fields are completely EMPTY
    if (!areFieldsEmpty()) {
      return;
    }

    isChecking = true;

    try {
      // Load settings
      const settingsOk = await loadSettings();
      if (!settingsOk) {
        isChecking = false;
        return;
      }

      // Fetch matches
      const matches = await fetchMatches();
      if (matches.length === 0) {
        isChecking = false;
        return;
      }

      detectedMatches = matches;
      createPopup();
      showMatches(matches);
    } finally {
      isChecking = false;
    }
  }

  // Monitor for password fields
  function startMonitoring() {
    // Initial check
    setTimeout(checkAndShowPopup, 1000);

    // Watch for dynamically added forms (with throttling)
    let lastCheck = 0;
    const observer = new MutationObserver(() => {
      const now = Date.now();
      // Throttle checks to once per 2 seconds
      if (now - lastCheck < 2000) return;
      lastCheck = now;
      
      if (!vaultPopup && !hasAutofilled) {
        resetAutofillFlag();
        // Only check if fields are empty
        if (areFieldsEmpty()) {
          checkAndShowPopup();
        }
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });

    // Also check on focus of password fields (with throttling)
    let lastFocusCheck = 0;
    document.addEventListener('focusin', (e) => {
      if (e.target && e.target.type === 'password' && !vaultPopup) {
        const now = Date.now();
        // Throttle focus checks to once per 3 seconds
        if (now - lastFocusCheck < 3000) return;
        lastFocusCheck = now;
        
        if (!hasAutofilled && areFieldsEmpty()) {
          resetAutofillFlag();
          setTimeout(checkAndShowPopup, 500);
        }
      }
    }, true);

    // Monitor for form resets or field clearing (for autofill only, NOT for save prompt)
    document.addEventListener('input', (e) => {
      if (e.target && (e.target.type === 'password' || e.target.type === 'text' || e.target.type === 'email')) {
        // If field is cleared and we had autofilled, reset the flag after a delay
        if (hasAutofilled && !e.target.value) {
          setTimeout(resetAutofillFlag, 1000);
        }
        
        // DO NOT trigger save prompt on typing - only on form submit
      }
    }, true);

    // Capture credentials ONLY at form submit time
    function captureCredentialsOnSubmit(form) {
      const passwordFields = form.querySelectorAll('input[type="password"]');
      if (passwordFields.length === 0 || !passwordFields[0].value || passwordFields[0].value.trim().length === 0) {
        return; // No password field or empty password
      }

      // Extract username/email from form (prioritize email)
      let username = '';
      const emailFields = form.querySelectorAll('input[type="email"], input[autocomplete="username"], input[name*="email" i], input[id*="email" i]');
      const usernameFields = form.querySelectorAll('input[type="text"], input[name*="user" i], input[id*="user" i]');
      
      // Priority: email fields first
      for (const field of emailFields) {
        if (field.value && field.value.trim().length > 0) {
          username = field.value.trim();
          break;
        }
      }
      // Fallback: username fields
      if (!username) {
        for (const field of usernameFields) {
          if (field.type !== 'password' && field.value && field.value.trim().length > 0) {
            username = field.value.trim();
            break;
          }
        }
      }

      const password = passwordFields[0].value;
      const origin = window.location.origin;
      const url = window.location.href;
      const formAction = form.action ? new URL(form.action, window.location.href).href : url;
      const attemptId = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

      // Send to background service worker
      chrome.runtime.sendMessage({
        type: 'CREDENTIAL_SUBMIT',
        attemptId: attemptId,
        origin: origin,
        url: url,
        formAction: formAction,
        username: username || 'Unknown',
        password: password
      }).then(response => {
        console.log('[SV] Credential sent to background (attemptId:', attemptId, '), response:', response);
      }).catch(err => {
        console.error('[SV] Failed to send credential to background:', err);
      });

      // Start a post-submit watcher for AJAX/SPA flows (no navigation). This will
      // only show the save prompt if a success state is detected.
      try {
        const isSignupAttempt = classifyAttemptIsSignup(form);
        beginPostSubmitWatch({
          attemptId,
          origin,
          username: username || 'Unknown',
          password,
          isSignup: isSignupAttempt,
          formRef: form // Pass form reference for removal detection
        });
      } catch (e) {
        // best-effort only
      }

      console.log('[SV] AUTH SUBMIT captured - attemptId:', attemptId, ', username:', username || 'Unknown', ', url:', url);
    }

    // Listen for form submissions
    document.addEventListener('submit', (e) => {
      if (e.target && e.target.tagName === 'FORM') {
        const form = e.target;
        
        // Check if password changed after autofill (for update prompt)
        if (lastFilledPassword) {
          const passwordFields = form.querySelectorAll('input[type="password"]');
          if (passwordFields.length > 0) {
            const currentPassword = passwordFields[0].value;
            if (currentPassword && currentPassword !== lastFilledPassword) {
              // Password changed - check after navigation
              setTimeout(() => {
                if (detectSuccessfulLogin()) {
                  showUpdatePrompt();
                }
              }, 2000);
            }
          }
        }
        
        // Capture credentials for save prompt
        captureCredentialsOnSubmit(form);
      }
    }, true);

    // Fallback: Capture on submit button click (some sites don't fire submit event)
    document.addEventListener('click', (e) => {
      const target = e.target;
      if (target && (target.type === 'submit' || target.tagName === 'BUTTON')) {
        // Find the form containing this button
        let form = target.closest('form');
        if (!form && target.form) {
          form = target.form;
        }
        if (form) {
          // Small delay to ensure form values are captured
          setTimeout(() => {
            captureCredentialsOnSubmit(form);
          }, 100);
        }
      }
    }, true);

    // Listen for messages from background service worker
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.type === 'SHOW_SAVE_PROMPT') {
        console.log('[SV] Received SHOW_SAVE_PROMPT message:', message.attemptId);
        
        // Background detected success - show save prompt
        if (shownAttemptIds.has(message.attemptId)) {
          console.log('[SV] Prompt already shown for attemptId:', message.attemptId);
          sendResponse({ ok: true, alreadyShown: true });
          return true;
        }

        console.log('[SV] Attempting to show save prompt for attemptId:', message.attemptId);

        // Show the save prompt - only mark as shown AFTER successful DOM insertion
        showSavePromptFromBackground(message.attemptId, message.origin, message.username, message.password)
          .then((rendered) => {
            if (rendered) {
              // Only mark as shown if DOM was actually inserted
              shownAttemptIds.add(message.attemptId);
              console.log('[SV] Save prompt rendered, marked attemptId as shown:', message.attemptId);
              chrome.runtime.sendMessage({
                type: 'PROMPT_DECIDED',
                attemptId: message.attemptId
              }).catch(() => {});
            } else {
              console.log('[SV] Save prompt NOT rendered, allowing retry for attemptId:', message.attemptId);
            }
          })
          .catch((err) => {
            console.error('[SV] Error showing save prompt:', err);
            // Don't mark as shown - allow retry
          });

        sendResponse({ ok: true });
        return true;
      }
      return false;
    });
  }

  // ---------------------- post-submit success watching ----------------------
  // Some sites update the DOM without a navigation (AJAX / SPA). Background success
  // detection relies on navigation events, so we also watch after submit and trigger
  // the save prompt only when we see a success state.

  function isElementVisible(el) {
    if (!el) return false;
    try {
      const style = window.getComputedStyle(el);
      if (!style) return false;
      if (style.display === 'none' || style.visibility === 'hidden') return false;
      // Opacity 0 is effectively invisible for UX purposes
      if (style.opacity === '0') return false;
      const rect = el.getBoundingClientRect();
      return rect.width > 0 && rect.height > 0;
    } catch (e) {
      return false;
    }
  }

  function getVisiblePasswordFields(root = document) {
    try {
      return Array.from(root.querySelectorAll('input[type="password"]')).filter(isElementVisible);
    } catch (e) {
      return [];
    }
  }

  // UI-based error detection - returns {failed, reason}
  // Only scans error containers, NOT the entire page text
  function detectAuthFailure() {
    const errorTerms = [
      'invalid', 'incorrect', 'failed', 'try again', 'wrong',
      'required', 'must be', 'does not match', "don't match",
      'already exists', 'unable to', 'problem', 'denied',
      'not found', 'unauthorized', 'expired', 'locked'
    ];
    
    const errorSelectors = [
      '.error', '.errors', '.alert-danger', '.alert-error', '.invalid-feedback',
      '.form-error', '.toast-error', '.field-error', '.validation-error',
      '[class*="error-message"]', '[class*="form-error"]',
      '[role="alert"][aria-live="assertive"]'
    ];

    let errorText = '';
    let foundInContainer = false;
    
    try {
      const els = document.querySelectorAll(errorSelectors.join(','));
      const visibleEls = Array.from(els).filter(isElementVisible);
      errorText = visibleEls.map(e => (e.textContent || '').toLowerCase()).join(' ');
      foundInContainer = visibleEls.length > 0;
    } catch (e) {
      errorText = '';
    }

    // Check aria-invalid inputs with visible helper text nearby
    let hasAriaInvalidWithText = false;
    try {
      const invalidInputs = document.querySelectorAll('[aria-invalid="true"]');
      for (const input of invalidInputs) {
        if (!isElementVisible(input)) continue;
        const describedBy = input.getAttribute('aria-describedby');
        if (describedBy) {
          const helperEl = document.getElementById(describedBy);
          if (helperEl && isElementVisible(helperEl)) {
            const helperText = (helperEl.textContent || '').toLowerCase();
            if (errorTerms.some(t => helperText.includes(t))) {
              hasAriaInvalidWithText = true;
              errorText += ' ' + helperText;
              break;
            }
          }
        }
        const parent = input.closest('.form-group, .field, .input-wrapper, [class*="form-field"]');
        if (parent) {
          const helperEls = parent.querySelectorAll('.helper-text, .hint, .message, small, span');
          for (const h of helperEls) {
            if (isElementVisible(h)) {
              const txt = (h.textContent || '').toLowerCase();
              if (errorTerms.some(t => txt.includes(t))) {
                hasAriaInvalidWithText = true;
                errorText += ' ' + txt;
                break;
              }
            }
          }
        }
      }
    } catch (e) {}

    const matched = errorTerms.some(t => errorText.includes(t));
    const failed = matched || hasAriaInvalidWithText;
    const reason = failed ? `Error detected in UI: "${errorText.substring(0, 100)}..."` : 'No error signals';
    
    console.log('[SV] detectAuthFailure:', { failed, reason: reason.substring(0, 80) });
    return { failed, reason };
  }

  // Legacy wrapper for compatibility
  function detectAuthError() {
    return detectAuthFailure().failed;
  }

  function classifyAttemptIsSignup(form) {
    try {
      const formText = (form?.textContent || '').toLowerCase();
      const formAction = (form?.action || '').toLowerCase();
      const url = window.location.href.toLowerCase();
      const keywords = ['sign up', 'signup', 'register', 'registration', 'create account', 'new account', 'join', 'create'];
      const pwCount = (form?.querySelectorAll?.('input[type="password"]') || []).length;
      const hasConfirm = pwCount > 1;
      return hasConfirm || keywords.some(k => {
        const compact = k.replace(/\s+/g, '');
        return formText.includes(k) || formAction.includes(compact) || url.includes(compact);
      });
    } catch (e) {
      return false;
    }
  }

  function beginPostSubmitWatch(attempt) {
    const startedAt = Date.now();
    const MAX_MS = 25000; // Extended to 25 seconds for slower sites
    const POLL_INTERVAL = 400; // Poll every 400ms
    let done = false;
    let tickCount = 0;
    
    // Store submitted URL and form reference for comparison
    _submittedUrl = window.location.href;
    _submittedFormRef = attempt.formRef || null;

    console.log('[SV] beginPostSubmitWatch started - attemptId:', attempt.attemptId, ', isSignup:', attempt.isSignup);

    const cleanup = (observer, intervalId, reason) => {
      if (done) return;
      done = true;
      console.log('[SV] Watcher cleanup:', reason);
      try { observer && observer.disconnect(); } catch (e) {}
      try { intervalId && clearInterval(intervalId); } catch (e) {}
    };

    const check = async (observer, intervalId) => {
      if (done) return;
      tickCount++;
      
      const elapsed = Date.now() - startedAt;
      if (elapsed > MAX_MS) {
        cleanup(observer, intervalId, 'timeout');
        return;
      }

      // Check for failure using UI-based error detection
      const failureResult = detectAuthFailure();
      if (failureResult.failed) {
        console.log('[SV] Watcher: failure detected -', failureResult.reason);
        cleanup(observer, intervalId, 'failure detected');
        return;
      }

      // Check for success using weighted signals
      const successResult = detectAuthSuccess({ 
        isSignup: attempt.isSignup, 
        submittedUrl: _submittedUrl,
        submittedFormRef: _submittedFormRef
      });
      
      // Log every 5th tick to avoid spam
      if (tickCount % 5 === 0) {
        console.log('[SV] Watcher tick', tickCount, '- confidence:', successResult.confidence, ', elapsed:', elapsed + 'ms');
      }
      
      if (!successResult.success) return;

      console.log('[SV] SUCCESS detected:', successResult.reason, '(confidence:', successResult.confidence + ')');

      if (shownAttemptIds.has(attempt.attemptId) || savePromptShown) {
        cleanup(observer, intervalId, 'already shown');
        return;
      }

      // Attempt to show prompt - only mark as shown AFTER successful DOM insertion
      try {
        const rendered = await showSavePromptFromBackground(attempt.attemptId, attempt.origin, attempt.username, attempt.password);
        if (rendered) {
          shownAttemptIds.add(attempt.attemptId);
          console.log('[SV] Watcher: prompt rendered, marked attemptId as shown:', attempt.attemptId);
          chrome.runtime.sendMessage({ type: 'PROMPT_DECIDED', attemptId: attempt.attemptId }).catch(() => {});
          cleanup(observer, intervalId, 'prompt shown');
        } else {
          console.log('[SV] Watcher: prompt NOT rendered, will retry');
        }
      } catch (e) {
        console.log('[SV] Watcher: error showing prompt, will retry:', e.message);
      }
    };

    let intervalId = null;
    const observer = new MutationObserver(() => {
      check(observer, intervalId);
    });

    try {
      observer.observe(document.documentElement || document.body, {
        childList: true,
        subtree: true,
        attributes: true,
        characterData: true
      });
    } catch (e) {}

    intervalId = setInterval(() => check(observer, intervalId), POLL_INTERVAL);
    // Run an immediate check after a short delay (allow page to start updating)
    setTimeout(() => check(observer, intervalId), 500);
  }

  // Detect if this is a signup form (not login)
  function isSignupForm() {
    const passwordFields = document.querySelectorAll('input[type="password"]');
    if (passwordFields.length === 0) return false;
    
    // Look for signup indicators
    const signupKeywords = ['sign up', 'signup', 'register', 'create account', 'new account', 'join', 'create', 'sign-up', 'registration'];
    const pageText = document.body.textContent.toLowerCase();
    const pageTitle = document.title.toLowerCase();
    const hasSignupKeyword = signupKeywords.some(keyword => 
      pageText.includes(keyword) || pageTitle.includes(keyword)
    );
    
    // Check for confirm password fields (common in signup)
    const allPasswordFields = document.querySelectorAll('input[type="password"]');
    const hasConfirmField = allPasswordFields.length > 1;
    
    // Check form action/name/id
    const forms = document.querySelectorAll('form');
    for (const form of forms) {
      const formText = (form.textContent || '').toLowerCase();
      const formAction = (form.action || '').toLowerCase();
      const formId = (form.id || '').toLowerCase();
      const formName = (form.name || '').toLowerCase();
      if (signupKeywords.some(k => 
        formText.includes(k) || formAction.includes(k) || formId.includes(k) || formName.includes(k)
      )) {
      return true;
    }
  }
    
    // Check URL for signup indicators
    const currentUrl = window.location.href.toLowerCase();
    const hasSignupInUrl = signupKeywords.some(k => currentUrl.includes(k));
    
    return hasSignupKeyword || hasConfirmField || hasSignupInUrl;
  }

  // Track submitted form and URL for success detection
  let _submittedFormRef = null;
  let _submittedUrl = '';

  // Weighted success detection - returns {success, reason, confidence}
  function detectAuthSuccess(options = {}) {
    const { isSignup = false, submittedUrl = _submittedUrl, submittedFormRef = _submittedFormRef } = options;
    const currentUrl = window.location.href.toLowerCase();
    let confidence = 0;
    const signals = [];

    // Signal 1: URL path changed away from auth routes (+40 points)
    const authPatterns = ['/login', '/signin', '/sign-in', '/signup', '/sign-up', '/register', '/auth', '/authenticate'];
    const submittedIsAuth = authPatterns.some(p => (submittedUrl || '').toLowerCase().includes(p));
    const currentIsAuth = authPatterns.some(p => currentUrl.includes(p));
    
    if (submittedUrl && submittedUrl !== window.location.href) {
      try {
        const submittedPath = new URL(submittedUrl).pathname.toLowerCase();
        const currentPath = new URL(window.location.href).pathname.toLowerCase();
        if (submittedPath !== currentPath) {
          if (submittedIsAuth && !currentIsAuth) {
            confidence += 40;
            signals.push('URL changed away from auth route (+40)');
          } else {
            confidence += 25;
            signals.push('URL path changed (+25)');
          }
        }
      } catch (e) {
        if (submittedIsAuth && !currentIsAuth) {
          confidence += 40;
          signals.push('URL changed away from auth (+40)');
        }
      }
    }

    // Signal 2: Visible password field disappeared (+30 points)
    const visiblePwdFields = getVisiblePasswordFields();
    if (visiblePwdFields.length === 0) {
      confidence += 30;
      signals.push('Password field gone (+30)');
    }

    // Signal 3: Submitted form removed from DOM (+20 points)
    if (submittedFormRef && !document.body.contains(submittedFormRef)) {
      confidence += 20;
      signals.push('Form removed from DOM (+20)');
    }

    // Signal 4: "Log out" / "Sign out" link/button appears (+25 points)
    const logoutTerms = ['log out', 'logout', 'sign out', 'signout', 'cerrar sesión', 'déconnexion'];
    const hasLogoutLink = (() => {
      try {
        const clickables = document.querySelectorAll('a, button, [role="button"]');
        for (const el of clickables) {
          if (!isElementVisible(el)) continue;
          const text = (el.textContent || el.innerText || '').toLowerCase().trim();
          const href = (el.getAttribute('href') || '').toLowerCase();
          if (logoutTerms.some(t => text.includes(t) || href.includes(t))) {
            return true;
          }
        }
      } catch (e) {}
      return false;
    })();
    if (hasLogoutLink) {
      confidence += 25;
      signals.push('Logout link found (+25)');
    }

    // Signal 5: Profile/avatar/dashboard elements appear (+15 points)
    const profileSelectors = [
      '[data-testid*="avatar"]', '[data-testid*="profile"]', '[data-testid*="user"]',
      '.avatar', '.user-avatar', '.profile-icon', '.user-menu', '.account-menu',
      '[class*="avatar"]', '[class*="profile-menu"]', '[class*="user-dropdown"]'
    ];
    const dashboardTerms = ['dashboard', 'my account', 'my profile', 'settings', 'preferences'];
    const hasProfileElements = (() => {
      try {
        for (const sel of profileSelectors) {
          const el = document.querySelector(sel);
          if (el && isElementVisible(el)) return true;
        }
        const clickables = document.querySelectorAll('a, button, [role="button"], nav *');
        for (const el of clickables) {
          if (!isElementVisible(el)) continue;
          const text = (el.textContent || '').toLowerCase().trim();
          if (dashboardTerms.some(t => text.includes(t))) return true;
        }
      } catch (e) {}
      return false;
    })();
    if (hasProfileElements) {
      confidence += 15;
      signals.push('Profile/dashboard elements found (+15)');
    }

    // Signal 6: Success message in dedicated containers (+20 points)
    const successContainerSelectors = [
      '[role="status"]', '[role="alert"][aria-live="polite"]', '.alert-success', '.success',
      '.toast-success', '.notification-success', '.message-success', '[class*="success-message"]'
    ];
    const successTerms = [
      'success', 'welcome', 'logged in', 'signed in', 'authenticated',
      'account created', 'registration complete', 'signup successful', 'registered',
      'verify your email', 'check your email', 'confirmation sent', 'email sent'
    ];
    const hasSuccessContainer = (() => {
      try {
        for (const sel of successContainerSelectors) {
          const els = document.querySelectorAll(sel);
          for (const el of els) {
            if (!isElementVisible(el)) continue;
            const text = (el.textContent || '').toLowerCase();
            if (successTerms.some(t => text.includes(t))) return true;
          }
        }
      } catch (e) {}
      return false;
    })();
    if (hasSuccessContainer) {
      confidence += 20;
      signals.push('Success container found (+20)');
    }

    // For signup: check for "go to login" or redirect indicators
    if (isSignup) {
      const goToLoginTerms = ['go to login', 'sign in now', 'login now', 'proceed to login'];
      const hasGoToLogin = (() => {
        try {
          const clickables = document.querySelectorAll('a, button');
          for (const el of clickables) {
            if (!isElementVisible(el)) continue;
            const text = (el.textContent || '').toLowerCase();
            if (goToLoginTerms.some(t => text.includes(t))) return true;
          }
        } catch (e) {}
        return false;
      })();
      if (hasGoToLogin) {
        confidence += 15;
        signals.push('Go-to-login link found (+15)');
      }
    }

    const success = confidence >= 50;
    const reason = signals.length > 0 ? signals.join(', ') : 'No success signals';
    
    console.log('[SV] detectAuthSuccess:', { success, confidence, signals, isSignup });
    return { success, reason, confidence };
  }

  // Legacy wrappers for compatibility
  function detectSuccessfulLogin() {
    return detectAuthSuccess({ isSignup: false }).success;
  }

  function detectSuccessfulSignup() {
    return detectAuthSuccess({ isSignup: true }).success;
  }

  // Check if password changed after autofill
  async function checkPasswordChange() {
    if (!lastFilledPassword || !lastFilledEntryId || formSubmissionTracked) return;
    
    const passwordFields = document.querySelectorAll('input[type="password"]');
    if (passwordFields.length === 0) {
      // No password field - likely successful login
      showUpdatePrompt();
      return;
    }
    
    const currentPassword = passwordFields[0].value;
    if (!currentPassword || currentPassword === lastFilledPassword) return;
    
    // Password changed - show update prompt
    formSubmissionTracked = true;
    showUpdatePrompt();
  }

  // Show prompt to update password
  async function showUpdatePrompt() {
    if (!apiUrl || !token || formSubmissionTracked) return;
    
    const passwordFields = document.querySelectorAll('input[type="password"]');
    const usernameFields = document.querySelectorAll('input[type="email"], input[type="text"], input[name*="user" i], input[name*="email" i]');
    
    const username = usernameFields.length > 0 ? usernameFields[0].value : '';
    const currentUrl = window.location.origin;
    const currentPassword = passwordFields.length > 0 ? passwordFields[0].value : lastFilledPassword;
    
    if (!currentPassword || currentPassword === lastFilledPassword) return;
    
    formSubmissionTracked = true;
    await createSavePrompt('update', {
      entry_id: lastFilledEntryId,
      service: document.title || new URL(currentUrl).hostname,
      username: username,
      url: currentUrl,
      password: currentPassword,
      message: 'Password has changed. Update saved password?'
    });
  }

  // Show save prompt when background service worker detects success
  // Returns true if prompt was successfully rendered, false otherwise
  async function showSavePromptFromBackground(attemptId, origin, username, password) {
    console.log('[SV] showSavePromptFromBackground called - attemptId:', attemptId);
    
    // Don't block if we autofilled - user might want to save a different credential
    if (savePromptShown) {
      console.log('[SV] Save prompt already shown, returning false');
      return false;
    }

    // Check if credential is new
    if (!apiUrl || !token) {
      await loadSettings();
      if (!apiUrl || !token) {
        console.log('[SV] API not configured, returning false');
        return false;
      }
    }

    const matches = await fetchMatches();
    const currentOrigin = window.location.origin;
    const currentDomain = new URL(currentOrigin).hostname;

    // Check if this is a NEW credential
    // API returns 'username' field (not 'username_email')
    const usernameLower = username.toLowerCase().trim();
    const hasExactMatch = matches.some(m => {
      // Check both 'username' and 'username_email' for compatibility
      const matchUsername = (m.username || m.username_email || '').toLowerCase().trim();
      const matchUrl = (m.url || '').toLowerCase();
      let matchDomain = '';
      try {
        matchDomain = matchUrl ? new URL(matchUrl).hostname : '';
      } catch (e) {
        matchDomain = '';
      }
      const domainMatch = matchDomain === currentDomain;
      const usernameMatch = matchUsername === usernameLower;
      return usernameMatch && domainMatch;
    });

    if (hasExactMatch) {
      console.log('[SV] Credential already exists in vault, skipping save prompt');
      return false;
    }

    // Parse email vs username
    let email = '';
    let usernameValue = '';
    if (isEmail(username)) {
      email = username;
    } else {
      usernameValue = username;
    }

    console.log('[SV] Attempting to render save prompt:', {
      attemptId,
      email: email || 'none',
      username: usernameValue || 'none',
      domain: currentDomain
    });

    const rendered = await createSavePrompt('save', {
      attemptId: attemptId,
      service: document.title || currentDomain,
      email: email,
      username: usernameValue,
      primaryIdentifier: email || usernameValue || 'Unknown',
      url: currentOrigin,
      password: password,
      message: 'Do you want to save this password?'
    });

    // Update savePromptShown based on actual DOM state
    savePromptShown = !!document.querySelector('.sv-save-prompt-container');
    
    return rendered;
  }

  // Helper function to check if a string is an email
  function isEmail(str) {
    if (!str || typeof str !== 'string') return false;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(str.trim());
  }

  // Check if we should never ask for this credential
  async function shouldNeverAsk(domain, username) {
    try {
      const key = `never_ask_${domain}_${(username || '').toLowerCase()}`;
      const data = await chrome.storage.local.get([key]);
      return data[key] === true;
    } catch (e) {
  return false;
    }
  }

  // Mark credential as "never ask"
  async function markNeverAsk(domain, username) {
    try {
      const key = `never_ask_${domain}_${(username || '').toLowerCase()}`;
      await chrome.storage.local.set({ [key]: true });
      console.log('[SV] Marked as never ask:', domain, username);
    } catch (e) {
      console.error('[SV] Failed to mark never ask:', e);
    }
  }

  // Create save/update prompt popup (Google Password Manager style)
  // Returns true if prompt was successfully inserted into DOM, false otherwise
  async function createSavePrompt(type, data) {
    // Close existing popup if present (save prompt takes priority over autofill popup)
    if (vaultPopup) {
      console.log('[SV] Closing existing popup to show save prompt');
      try {
        vaultPopup.remove();
      } catch (e) {}
      vaultPopup = null;
      detectedMatches = [];
      selectedEntryId = null;
    }
    
    // For 'save' type, background service worker has already verified success
    // No need to check here - just show the prompt
    
    // Check if user previously selected "Never" for this credential
    const currentDomain = new URL(data.url || window.location.origin).hostname;
    const shouldSkip = await shouldNeverAsk(currentDomain, data.username || data.primaryIdentifier || '');
    if (shouldSkip) {
      console.log('[SV] Skipping save prompt - user selected "Never" previously');
      return false;
    }
    
    // Determine primary identifier (email or username)
    const email = data.email || '';
    const username = data.username || '';
    const primaryIdentifier = email || username || 'Unknown';
    
    vaultPopup = document.createElement('div');
    vaultPopup.id = 'secure-vault-popup';
    vaultPopup.innerHTML = `
      <div class="sv-save-prompt-container">
        <button class="sv-save-close-btn" id="sv-save-close-btn">×</button>
        <div class="sv-save-title">Save password for ${currentDomain}?</div>
        <div class="sv-save-fields">
          <div class="sv-save-field">
            <div class="sv-save-input-wrapper">
              <input type="text" class="sv-save-input" id="sv-save-username" value="${escapeHtml(primaryIdentifier)}" placeholder="Username or email" />
            </div>
          </div>
          <div class="sv-save-field">
            <div class="sv-save-input-wrapper">
              <input type="password" class="sv-save-input" id="sv-save-password" value="${escapeHtml(data.password || '')}" placeholder="Password" />
              <button type="button" class="sv-save-eye-btn" id="sv-save-eye-btn" aria-label="Show password">👁</button>
            </div>
          </div>
        </div>
        <div class="sv-save-buttons">
          <button class="sv-save-primary-btn" id="sv-save-confirm-btn">Save</button>
          <button class="sv-save-secondary-btn" id="sv-save-never-btn">Never</button>
        </div>
        <div class="sv-save-footer">
          Passwords are saved to <span class="sv-save-link">Secure Vault</span> on this device.
        </div>
      </div>
    `;
    
    // Add styles for save prompt
    if (!document.getElementById('sv-save-prompt-styles')) {
      const style = document.createElement('style');
      style.id = 'sv-save-prompt-styles';
      style.textContent = `
        #secure-vault-popup {
          position: fixed;
          top: 20px;
          right: 20px;
          z-index: 999999;
          font-family: 'Google Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
          pointer-events: none;
        }
        .sv-save-prompt-container {
          background: #ffffff;
          border-radius: 8px;
          box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2), 0 0 0 1px rgba(0, 0, 0, 0.1);
          width: 360px;
          padding: 16px;
          position: relative;
          color: #202124;
          pointer-events: auto;
        }
        .sv-save-close-btn {
          position: absolute;
          top: 8px;
          right: 8px;
          background: none;
          border: none;
          color: #5f6368;
          font-size: 20px;
          line-height: 1;
          cursor: pointer;
          width: 32px;
          height: 32px;
          display: flex;
          align-items: center;
          justify-content: center;
          border-radius: 50%;
          padding: 0;
        }
        .sv-save-close-btn:hover {
          background: rgba(60, 64, 67, 0.08);
          color: #202124;
        }
        .sv-save-title {
          font-size: 16px;
          font-weight: 400;
          color: #202124;
          margin-bottom: 16px;
          padding-right: 32px;
          line-height: 1.5;
        }
        .sv-save-fields {
          margin-bottom: 16px;
        }
        .sv-save-field {
          margin-bottom: 12px;
        }
        .sv-save-field:last-child {
          margin-bottom: 0;
        }
        .sv-save-input-wrapper {
          position: relative;
          display: flex;
          align-items: center;
        }
        .sv-save-input {
          width: 100%;
          padding: 10px 40px 10px 12px;
          background: #ffffff;
          border: 1px solid #dadce0;
          border-radius: 4px;
          color: #202124;
          font-size: 14px;
          box-sizing: border-box;
          font-family: inherit;
        }
        .sv-save-input:focus {
          outline: none;
          border-color: #1a73e8;
          box-shadow: 0 0 0 1px #1a73e8;
        }
        .sv-save-input::placeholder {
          color: #9aa0a6;
        }
        .sv-save-dropdown {
          position: absolute;
          right: 12px;
          color: #9aa0a6;
          font-size: 10px;
          pointer-events: none;
        }
        .sv-save-eye-btn {
          position: absolute;
          right: 8px;
          background: none;
          border: none;
          color: #5f6368;
          cursor: pointer;
          font-size: 18px;
          padding: 4px 8px;
          display: flex;
          align-items: center;
          justify-content: center;
          border-radius: 4px;
        }
        .sv-save-eye-btn:hover {
          background: rgba(60, 64, 67, 0.08);
          color: #202124;
        }
        .sv-save-buttons {
          display: flex;
          gap: 8px;
          margin-bottom: 12px;
        }
        .sv-save-primary-btn {
          flex: 1;
          padding: 8px 16px;
          background: #1a73e8;
          color: #ffffff;
          border: none;
          border-radius: 4px;
          font-size: 14px;
          font-weight: 500;
          cursor: pointer;
          transition: background 0.2s;
          font-family: inherit;
        }
        .sv-save-primary-btn:hover {
          background: #1765cc;
          box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
        }
        .sv-save-primary-btn:active {
          background: #1557b0;
        }
        .sv-save-secondary-btn {
          flex: 1;
          padding: 8px 16px;
          background: #ffffff;
          color: #1a73e8;
          border: 1px solid #dadce0;
          border-radius: 4px;
          font-size: 14px;
          font-weight: 500;
          cursor: pointer;
          transition: background 0.2s;
          font-family: inherit;
        }
        .sv-save-secondary-btn:hover {
          background: #f8f9fa;
          border-color: #c4c7c5;
        }
        .sv-save-secondary-btn:active {
          background: #f1f3f4;
        }
        .sv-save-footer {
          font-size: 12px;
          color: #5f6368;
          text-align: center;
          line-height: 1.4;
        }
        .sv-save-link {
          color: #1a73e8;
          cursor: pointer;
          text-decoration: none;
        }
        .sv-save-link:hover {
          text-decoration: underline;
        }
        .sv-save-radio-group {
          display: flex;
          gap: 16px;
          margin-top: 4px;
        }
        .sv-save-radio-label {
          display: flex;
          align-items: center;
          gap: 6px;
          font-size: 14px;
          color: #e8eaed;
          cursor: pointer;
        }
        .sv-save-radio-label input[type="radio"] {
          margin: 0;
          cursor: pointer;
          accent-color: #8ab4f8;
        }
        .sv-save-radio-label span {
          user-select: none;
        }
        /* Dark theme support */
        @media (prefers-color-scheme: dark) {
          .sv-save-prompt-container {
            background: #2d2e30;
            color: #e8eaed;
          }
          .sv-save-title {
            color: #e8eaed;
          }
          .sv-save-input {
            background: #3c4043;
            border-color: #5f6368;
            color: #e8eaed;
          }
          .sv-save-input:focus {
            border-color: #8ab4f8;
            box-shadow: 0 0 0 1px #8ab4f8;
          }
          .sv-save-input::placeholder {
            color: #9aa0a6;
          }
          .sv-save-secondary-btn {
            background: #3c4043;
            border-color: #5f6368;
            color: #e8eaed;
          }
          .sv-save-secondary-btn:hover {
            background: #5f6368;
          }
          .sv-save-footer {
            color: #9aa0a6;
          }
          .sv-save-close-btn {
            color: #9aa0a6;
          }
          .sv-save-close-btn:hover {
            background: rgba(255, 255, 255, 0.1);
            color: #e8eaed;
          }
          .sv-save-eye-btn {
            color: #9aa0a6;
          }
          .sv-save-eye-btn:hover {
            background: rgba(255, 255, 255, 0.1);
            color: #e8eaed;
          }
        }
        .sv-save-radio-group {
          display: flex;
          gap: 16px;
          margin-top: 4px;
        }
        .sv-save-radio-label {
          display: flex;
          align-items: center;
          gap: 6px;
          font-size: 14px;
          color: #e8eaed;
          cursor: pointer;
        }
        .sv-save-radio-label input[type="radio"] {
          margin: 0;
          cursor: pointer;
          accent-color: #8ab4f8;
        }
        .sv-save-radio-label span {
          user-select: none;
        }
      `;
      document.head.appendChild(style);
    }
    
    document.body.appendChild(vaultPopup);
    
    // Event listeners
    document.getElementById('sv-save-close-btn').addEventListener('click', () => {
      savePromptShown = false;
      // Notify background that prompt was dismissed
      if (data.attemptId) {
        chrome.runtime.sendMessage({
          type: 'PROMPT_DECIDED',
          attemptId: data.attemptId
        }).catch(() => {});
      }
      closePopup();
    });
    
    // Eye button to toggle password visibility
    let passwordVisible = false;
    const passwordInput = document.getElementById('sv-save-password');
    const eyeBtn = document.getElementById('sv-save-eye-btn');
    eyeBtn.addEventListener('click', () => {
      passwordVisible = !passwordVisible;
      passwordInput.type = passwordVisible ? 'text' : 'password';
      eyeBtn.textContent = passwordVisible ? '🙈' : '👁';
    });
    
    // Save button - show master phrase dialog (with updated values from editable fields)
    document.getElementById('sv-save-confirm-btn').addEventListener('click', () => {
      // Get updated values from editable fields
      const usernameInput = document.getElementById('sv-save-username');
      const passwordInput = document.getElementById('sv-save-password');
      
      const updatedUsername = usernameInput ? usernameInput.value.trim() : '';
      const updatedPassword = passwordInput.value.trim();
      
      // Determine if it's an email or username
      const isEmail = updatedUsername.includes('@');
      
      // Update data with user-edited values
      const updatedData = {
        ...data,
        email: isEmail ? updatedUsername : (data.email || ''),
        username: isEmail ? (data.username || '') : updatedUsername,
        primaryIdentifier: updatedUsername || 'Unknown',
        password: updatedPassword || data.password
      };
      
      showMasterPhraseDialog(type, updatedData);
    });
    
    // Never button - dismiss and don't ask again
    document.getElementById('sv-save-never-btn').addEventListener('click', async () => {
      const currentDomain = new URL(data.url || window.location.origin).hostname;
      // Use username/email from input field with fallback to data
      const usernameInput = document.getElementById('sv-save-username');
      let identifier = usernameInput ? usernameInput.value.trim() : '';
      if (!identifier) {
        identifier = data.primaryIdentifier || data.email || data.username || '';
      }
      
      await markNeverAsk(currentDomain, identifier);
      savePromptShown = false;
      // Notify background that prompt was dismissed
      if (data.attemptId) {
        chrome.runtime.sendMessage({
          type: 'PROMPT_DECIDED',
          attemptId: data.attemptId
        }).catch(() => {});
      }
      closePopup();
    });

    // Verify DOM insertion succeeded
    const inserted = document.body.contains(vaultPopup) && !!document.querySelector('.sv-save-prompt-container');
    if (inserted) {
      console.log('[SV] SAVE PROMPT RENDERED successfully');
    } else {
      console.log('[SV] SAVE PROMPT FAILED - DOM not inserted');
    }
    return inserted;
  }
  
  // Show master phrase dialog after user clicks Save
  function showMasterPhraseDialog(type, data) {
    // Replace the save prompt content with master phrase dialog
    const container = vaultPopup.querySelector('.sv-save-prompt-container');
    container.innerHTML = `
      <button class="sv-save-close-btn" id="sv-phrase-close-btn">×</button>
      <div class="sv-save-title">Enter Master Phrase</div>
      <div style="margin-bottom: 16px; font-size: 13px; color: #5f6368; text-align: center;">
        Enter your login passphrase to ${type === 'update' ? 'update' : 'save'} credentials.
      </div>
      <div class="sv-save-field">
        <input type="password" id="sv-phrase-input" class="sv-save-input" placeholder="Master phrase" style="padding: 10px 12px;" autofocus />
      </div>
      <div id="sv-phrase-status" style="min-height: 20px; font-size: 12px; color: #ea4335; text-align: center; margin-bottom: 12px; padding: 0 8px;"></div>
      <div class="sv-save-buttons">
        <button class="sv-save-primary-btn" id="sv-phrase-save-btn">${type === 'update' ? 'Update' : 'Save'}</button>
        <button class="sv-save-secondary-btn" id="sv-phrase-cancel-btn">Cancel</button>
      </div>
    `;
    
    // Event listeners
    document.getElementById('sv-phrase-close-btn').addEventListener('click', () => {
      savePromptShown = false;
      closePopup();
    });
    
    document.getElementById('sv-phrase-cancel-btn').addEventListener('click', async () => {
      // Go back to save prompt
      await createSavePrompt(type, data);
    });
    
    document.getElementById('sv-phrase-save-btn').addEventListener('click', () => {
      const phrase = document.getElementById('sv-phrase-input').value.trim();
      if (!phrase) {
        document.getElementById('sv-phrase-status').textContent = 'Please enter your master phrase.';
        return;
      }
      saveOrUpdateSecret(type, data, phrase);
    });
    
    document.getElementById('sv-phrase-input').addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        document.getElementById('sv-phrase-save-btn').click();
      }
    });
    
    document.getElementById('sv-phrase-input').focus();
  }

  // Save or update secret
  async function saveOrUpdateSecret(type, data, phrase) {
    const statusEl = document.getElementById('sv-phrase-status');
    const saveBtn = document.getElementById('sv-phrase-save-btn');
    
    if (!phrase || phrase.trim().length === 0) {
      statusEl.textContent = 'Please enter your master phrase.';
      statusEl.style.color = '#ea4335';
      return;
    }
    
    saveBtn.disabled = true;
    saveBtn.textContent = type === 'update' ? 'Updating...' : 'Saving...';
    statusEl.textContent = '';
    
    // Use primary identifier (email or username) as the username field for API
    const primaryIdentifier = data.primaryIdentifier || data.email || data.username || 'Unknown';
    
    console.log('[SV] Saving credential:', {
      type: type,
      service: data.service,
      email: data.email || 'none',
      username: data.username || 'none',
      primaryIdentifier: primaryIdentifier,
      url: data.url,
      hasPassword: !!data.password
    });
    
    try {
      const endpoint = `${apiUrl.replace(/\/$/, '')}/api/extension/save-secret`;
      const requestBody = {
        token: token,
        phrase: phrase,
        service: data.service,
        username: primaryIdentifier, // Use selected primary identifier (email or username)
        url: data.url,
        password: data.password,
        entry_id: data.entry_id || null
      };
      
      console.log('[SV] Sending save request to:', endpoint);
      
      const proxyRes = await chrome.runtime.sendMessage({
        type: 'FETCH_EXTENSION_API',
        url: endpoint,
        method: 'POST',
        body: requestBody
      });
      const res = { ok: proxyRes.ok, status: proxyRes.status };
      const result = proxyRes.data || {};
      
      if (!res.ok) {
        if (res.status === 401) {
          statusEl.textContent = 'Invalid master phrase. Please try again.';
          statusEl.style.color = '#ea4335';
          document.getElementById('sv-phrase-input').value = '';
          saveBtn.disabled = false;
          saveBtn.textContent = type === 'update' ? 'Update' : 'Save';
          console.log('[SV] Save failed: Invalid master phrase');
          return;
        }
        statusEl.textContent = result.message || 'Failed to save';
        statusEl.style.color = '#ea4335';
        saveBtn.disabled = false;
        saveBtn.textContent = type === 'update' ? 'Update' : 'Save';
        console.log('[SV] Save failed:', result.message);
        return;
      }
      if (result.ok) {
        statusEl.textContent = type === 'update' ? 'Password updated successfully!' : 'Password saved successfully!';
        statusEl.style.color = '#34a853';
        
        console.log('[SV] Credential saved successfully!');
        
        // Reset tracking
        if (type === 'update') {
          lastFilledPassword = data.password;
        }
        savePromptShown = false;
        
        // Notify background that prompt was decided (saved)
        if (data.attemptId) {
          chrome.runtime.sendMessage({
            type: 'PROMPT_DECIDED',
            attemptId: data.attemptId
          }).catch(() => {});
        }
        
        setTimeout(() => {
          closePopup();
        }, 1500);
      } else {
        statusEl.textContent = result.message || 'Failed to save';
        statusEl.style.color = '#ea4335';
        saveBtn.disabled = false;
        saveBtn.textContent = type === 'update' ? 'Update' : 'Save';
        console.log('[SV] Save failed:', result.message);
      }
    } catch (e) {
      statusEl.textContent = `Error: ${e.message}`;
      statusEl.style.color = '#ea4335';
      saveBtn.disabled = false;
      saveBtn.textContent = type === 'update' ? 'Update' : 'Save';
      console.error('[SV] Save error:', e);
    }
  }

  // Start when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', startMonitoring);
  } else {
    startMonitoring();
  }

  // Handle messages from popup/background
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || message.type !== 'VAULT_AUTOFILL') {
      sendResponse({ success: false, error: 'Invalid message type' });
      return;
    }
    
    try {
      const entry = message.entry || {};
      const passwordValue = extractPasswordValue(entry.password);
      
      // Extract username - ensure it's a string
      let usernameValue = '';
      if (typeof entry.username === 'string') {
        usernameValue = entry.username;
      } else if (entry.username && typeof entry.username === 'object') {
        usernameValue = entry.username.username || entry.username.value || '';
      } else if (entry.username) {
        usernameValue = String(entry.username);
      }
      
      // Fill both username and password fields
      const usernameFilled = fillInput([
    'input[type="email"]',
    'input[name*="email" i]',
    'input[name*="user" i]',
    'input[id*="email" i]',
    'input[id*="user" i]',
    'input[type="text"]'
      ], usernameValue);

      const passwordFilled = fillInput([
    'input[type="password"]',
    'input[name*="pass" i]',
    'input[id*="pass" i]'
      ], passwordValue);

      sendResponse({ 
        success: true, 
        usernameFilled, 
        passwordFilled,
        service: entry.service || 'Unknown'
      });
    } catch (error) {
      sendResponse({ success: false, error: error.message });
    }
    
    return true;
  });

  // Helper function for manual autofill
function fillInput(selectors, value) {
  if (!value || value.trim().length === 0) return false;
  
  for (const sel of selectors) {
    const el = document.querySelector(sel);
    if (el) {
      // Only fill if field is empty
      if (!el.value || el.value.trim().length === 0) {
      el.focus();
      el.value = value;
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
      }
    }
  }
  return false;
}
})();
