// Background service worker for Secure Vault extension
// Handles pending credential attempts and success detection

'use strict';

// Pending credential attempts keyed by tabId
// Structure: { attemptId, origin, submittedUrl, username, password, formAction, createdAt }
const pendingAttempts = new Map();

// TTL for pending attempts (60 seconds)
const CREDENTIAL_TTL = 60000;

// Track which attempts have shown prompts (to prevent duplicates)
const promptShown = new Set();

// Cleanup expired attempts
setInterval(() => {
  const now = Date.now();
  for (const [tabId, attempt] of pendingAttempts.entries()) {
    if (now - attempt.createdAt > CREDENTIAL_TTL) {
      console.log('[SV Background] Pending attempt expired:', attempt.attemptId);
      wipeAttempt(attempt);
      pendingAttempts.delete(tabId);
    }
  }
}, 5000); // Check every 5 seconds

// Wipe sensitive data from attempt
function wipeAttempt(attempt) {
  if (attempt.password) {
    attempt.password = '';
    attempt.password = null;
  }
}

// Proxy extension API requests (avoids CORS - content script fetch has page Origin)
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'FETCH_EXTENSION_API') {
    const { url, method = 'GET', body } = message;
    if (!url) {
      sendResponse({ ok: false, error: 'Missing url' });
      return;
    }
    fetch(url, {
      method: method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
      cache: 'no-cache'
    })
      .then(async (res) => {
        const text = await res.text();
        let data = null;
        try {
          data = text ? JSON.parse(text) : null;
        } catch (e) {
          data = null;
        }
        sendResponse({ ok: res.ok, status: res.status, data });
      })
      .catch((e) => {
        sendResponse({ ok: false, error: String(e.message || e) });
      });
    return true; // Async response
  }

  if (message.type === 'CREDENTIAL_SUBMIT') {
    const tabId = sender.tab?.id;
    if (!tabId) {
      console.error('[SV Background] No tab ID for credential submit');
      return;
    }

    // Wipe any existing attempt for this tab
    const existing = pendingAttempts.get(tabId);
    if (existing) {
      wipeAttempt(existing);
    }

    // Store new pending attempt
    const attempt = {
      attemptId: message.attemptId,
      origin: message.origin,
      submittedUrl: message.url,
      username: message.username,
      password: message.password, // Keep in memory only, will be wiped after decision
      formAction: message.formAction || null,
      createdAt: Date.now(),
      tabId: tabId
    };

    pendingAttempts.set(tabId, attempt);
    console.log('[SV Background] Credential captured at submit time:', {
      attemptId: attempt.attemptId,
      origin: attempt.origin,
      submittedUrl: attempt.submittedUrl,
      username: attempt.username,
      tabId: tabId
    });

    // Set TTL cleanup
    setTimeout(() => {
      const current = pendingAttempts.get(tabId);
      if (current && current.attemptId === attempt.attemptId) {
        console.log('[SV Background] Pending attempt expired (TTL):', attempt.attemptId);
        wipeAttempt(current);
        pendingAttempts.delete(tabId);
      }
    }, CREDENTIAL_TTL);

    sendResponse({ ok: true });
    return true;
  }

  if (message.type === 'CHECK_SUCCESS') {
    // Content script requesting success check
    const tabId = sender.tab?.id;
    if (!tabId) {
      sendResponse({ success: false });
      return;
    }

    const attempt = pendingAttempts.get(tabId);
    if (!attempt) {
      sendResponse({ success: false });
      return;
    }

    // Run success heuristics
    checkSuccessHeuristics(tabId, attempt, sender.tab.url)
      .then(success => {
        sendResponse({ success: success });
      })
      .catch(() => {
        sendResponse({ success: false });
      });
    return true; // Async response
  }

  if (message.type === 'PROMPT_DECIDED') {
    // Content script has shown/decided on prompt
    const attemptId = message.attemptId;
    if (attemptId) {
      promptShown.add(attemptId);
      // Find and wipe attempt by attemptId
      for (const [tabId, attempt] of pendingAttempts.entries()) {
        if (attempt.attemptId === attemptId) {
          wipeAttempt(attempt);
          pendingAttempts.delete(tabId);
          break;
        }
      }
    }
    sendResponse({ ok: true });
    return true;
  }
});

// Monitor navigation completion
chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0) return; // Only main frame

  const tabId = details.tabId;
  const attempt = pendingAttempts.get(tabId);
  if (!attempt) {
    return;
  }
  
  if (promptShown.has(attempt.attemptId)) {
    console.log('[SV Background] Prompt already shown for attempt:', attempt.attemptId);
    return;
  }

  console.log('[SV Background] Navigation completed, checking success (tabId:', tabId, ', url:', details.url, ')');

  // Wait a bit for page to load, then check success
  setTimeout(() => {
    checkSuccessAndPrompt(tabId, attempt, details.url);
  }, 2000); // Wait 2 seconds for page to fully load
}, {
  url: [{ schemes: ['http', 'https'] }]
});

// Fallback: Use tabs.onUpdated if webNavigation not available
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete' || !tab.url) {
    return;
  }

  const attempt = pendingAttempts.get(tabId);
  if (!attempt || promptShown.has(attempt.attemptId)) {
    return;
  }

  // Wait a bit for page to load, then check success
  setTimeout(() => {
    checkSuccessAndPrompt(tabId, attempt, tab.url);
  }, 2000); // Wait 2 seconds for page to fully load
});

// Check success heuristics and show prompt if successful
async function checkSuccessAndPrompt(tabId, attempt, currentUrl) {
  if (promptShown.has(attempt.attemptId)) {
    return;
  }

  // Inject content script to check success
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId: tabId },
      func: runSuccessHeuristics,
      args: [attempt.submittedUrl, currentUrl]
    });

    if (results && results[0]) {
      const success = results[0].result;
      console.log('[SV Background] Success check result:', success, 'for attempt:', attempt.attemptId);
      
      if (success === true) {
        console.log('[SV Background] Success detected, sending prompt message:', attempt.attemptId);
        
        // Send message to content script to show prompt with exponential backoff retry
        const sendPromptWithRetry = async (retryCount = 0, delay = 500) => {
          try {
            const response = await chrome.tabs.sendMessage(tabId, {
              type: 'SHOW_SAVE_PROMPT',
              attemptId: attempt.attemptId,
              origin: attempt.origin,
              username: attempt.username,
              password: attempt.password
            });
            
            // Only mark as shown after successful delivery
            if (response && response.ok) {
              promptShown.add(attempt.attemptId);
              console.log('[SV Background] Prompt message delivered successfully');
            }
          } catch (err) {
            console.error('[SV Background] Failed to send prompt message (attempt', retryCount + 1, '):', err.message);
            
            // Retry up to 3 times with exponential backoff
            if (retryCount < 3) {
              setTimeout(() => {
                sendPromptWithRetry(retryCount + 1, delay * 2);
              }, delay);
            } else {
              console.error('[SV Background] All retries failed, clearing attempt');
              wipeAttempt(attempt);
              pendingAttempts.delete(tabId);
            }
          }
        };
        
        // Send immediately
        sendPromptWithRetry();
      } else {
        // Don't clear attempt on false success - content.js watcher may still detect success
        // Let TTL handle cleanup instead
        console.log('[SV Background] Success heuristics returned false, keeping attempt for watcher:', attempt.attemptId);
      }
    } else {
      // No result, but don't clear - watcher may still succeed
      console.log('[SV Background] Success check returned no result, keeping attempt:', attempt.attemptId);
    }
  } catch (error) {
    console.error('[SV Background] Error checking success:', error);
    // Don't clear attempt on error - may be temporary
  }
}

// Success heuristics function (injected into page) - WEIGHTED APPROACH
// Returns true if confidence >= 50 (success threshold)
function runSuccessHeuristics(submittedUrl, currentUrl) {
  'use strict';
  
  let confidence = 0;
  const signals = [];
  
  // Helper: check element visibility
  function isElementVisible(el) {
    if (!el) return false;
    try {
      const style = window.getComputedStyle(el);
      if (!style) return false;
      if (style.display === 'none' || style.visibility === 'hidden') return false;
      if (style.opacity === '0') return false;
      const rect = el.getBoundingClientRect();
      return rect.width > 0 && rect.height > 0;
    } catch (e) {
      return false;
    }
  }

  // Helper: get visible password fields
  function getVisiblePasswordFields() {
    try {
      return Array.from(document.querySelectorAll('input[type="password"]')).filter(isElementVisible);
    } catch (e) {
      return [];
    }
  }

  // UI-BASED FAILURE CHECK (only error containers, not whole page)
  const errorTerms = ['invalid', 'incorrect', 'failed', 'try again', 'wrong', 'required', 'denied'];
  const errorSelectors = [
    '.error', '.errors', '.alert-danger', '.alert-error', '.invalid-feedback',
    '.form-error', '.toast-error', '[role="alert"][aria-live="assertive"]'
  ];
  let hasUIError = false;
  try {
    const errorEls = document.querySelectorAll(errorSelectors.join(','));
    const visibleErrorEls = Array.from(errorEls).filter(isElementVisible);
    const errorText = visibleErrorEls.map(e => (e.textContent || '').toLowerCase()).join(' ');
    hasUIError = errorTerms.some(t => errorText.includes(t));
  } catch (e) {}
  
  if (hasUIError) {
    console.log('[SV] Background heuristics: UI error detected, returning false');
    return false;
  }

  // Signal 1: URL path changed away from auth routes (+40 points)
  const authPatterns = ['/login', '/signin', '/sign-in', '/signup', '/sign-up', '/register', '/auth', '/authenticate'];
  const submittedIsAuth = authPatterns.some(p => submittedUrl.toLowerCase().includes(p));
  const currentIsAuth = authPatterns.some(p => currentUrl.toLowerCase().includes(p));
  
  if (submittedUrl !== currentUrl) {
    try {
      const submittedPath = new URL(submittedUrl).pathname.toLowerCase();
      const currentPath = new URL(currentUrl).pathname.toLowerCase();
      if (submittedPath !== currentPath) {
        if (submittedIsAuth && !currentIsAuth) {
          confidence += 40;
          signals.push('URL changed away from auth (+40)');
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

  // Signal 3: "Log out" / "Sign out" link/button appears (+25 points)
  const logoutTerms = ['log out', 'logout', 'sign out', 'signout'];
  let hasLogoutLink = false;
  try {
    const clickables = document.querySelectorAll('a, button, [role="button"]');
    for (const el of clickables) {
      if (!isElementVisible(el)) continue;
      const text = (el.textContent || el.innerText || '').toLowerCase().trim();
      const href = (el.getAttribute('href') || '').toLowerCase();
      if (logoutTerms.some(t => text.includes(t) || href.includes(t))) {
        hasLogoutLink = true;
        break;
      }
    }
  } catch (e) {}
  if (hasLogoutLink) {
    confidence += 25;
    signals.push('Logout link found (+25)');
  }

  // Signal 4: Profile/avatar/dashboard elements appear (+15 points)
  const profileSelectors = [
    '[data-testid*="avatar"]', '[data-testid*="profile"]', '.avatar', '.user-avatar',
    '.profile-icon', '.user-menu', '.account-menu', '[class*="avatar"]'
  ];
  const dashboardTerms = ['dashboard', 'my account', 'my profile', 'settings'];
  let hasProfileElements = false;
  try {
    for (const sel of profileSelectors) {
      const el = document.querySelector(sel);
      if (el && isElementVisible(el)) {
        hasProfileElements = true;
        break;
      }
    }
    if (!hasProfileElements) {
      const clickables = document.querySelectorAll('a, button, nav *');
      for (const el of clickables) {
        if (!isElementVisible(el)) continue;
        const text = (el.textContent || '').toLowerCase().trim();
        if (dashboardTerms.some(t => text.includes(t))) {
          hasProfileElements = true;
          break;
        }
      }
    }
  } catch (e) {}
  if (hasProfileElements) {
    confidence += 15;
    signals.push('Profile/dashboard elements (+15)');
  }

  // Signal 5: Success message in dedicated containers (+20 points)
  const successContainerSelectors = [
    '[role="status"]', '.alert-success', '.success', '.toast-success',
    '.notification-success', '[class*="success-message"]'
  ];
  const successTerms = [
    'success', 'welcome', 'logged in', 'signed in', 'authenticated',
    'account created', 'registration complete', 'registered', 'verify your email'
  ];
  let hasSuccessContainer = false;
  try {
    for (const sel of successContainerSelectors) {
      const els = document.querySelectorAll(sel);
      for (const el of els) {
        if (!isElementVisible(el)) continue;
        const text = (el.textContent || '').toLowerCase();
        if (successTerms.some(t => text.includes(t))) {
          hasSuccessContainer = true;
          break;
        }
      }
      if (hasSuccessContainer) break;
    }
  } catch (e) {}
  if (hasSuccessContainer) {
    confidence += 20;
    signals.push('Success container (+20)');
  }

  const success = confidence >= 50;
  console.log('[SV] Background heuristics:', { success, confidence, signals });
  return success;
}

// Check success heuristics (alternative function for direct call)
async function checkSuccessHeuristics(tabId, attempt, currentUrl) {
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId: tabId },
      func: runSuccessHeuristics,
      args: [attempt.submittedUrl, currentUrl]
    });
    return results && results[0] && results[0].result === true;
  } catch (error) {
    console.error('[SV Background] Error in success check:', error);
    return false;
  }
}


