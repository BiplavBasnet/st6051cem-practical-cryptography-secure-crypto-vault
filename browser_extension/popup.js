
const statusEl = document.getElementById('status');

function setStatus(msg) {
  if (statusEl) statusEl.textContent = msg;
}

async function loadSettings() {
  const data = await chrome.storage.local.get(['apiUrl', 'token']);
  const apiUrlEl = document.getElementById('apiUrl');
  const tokenEl = document.getElementById('token');
  if (apiUrlEl) apiUrlEl.value = data.apiUrl || 'http://127.0.0.1:5005';
  if (tokenEl) tokenEl.value = data.token || '';
}

async function saveSettings() {
  const apiUrl = document.getElementById('apiUrl').value.trim();
  const token = document.getElementById('token').value.trim();
  await chrome.storage.local.set({ apiUrl, token });
  setStatus('Settings saved.');
}

async function resetDefault() {
  await chrome.storage.local.set({ apiUrl: 'http://127.0.0.1:5005' });
  document.getElementById('apiUrl').value = 'http://127.0.0.1:5005';
  setStatus('API URL reset to default (5005).');
}

async function testConnection() {
  const { apiUrl, token } = await chrome.storage.local.get(['apiUrl', 'token']);
  if (!apiUrl) {
    return setStatus('Set API URL first.');
  }
  const url = `${apiUrl.replace(/\/$/, '')}/health`;
  try {
    const res = await fetch(url, {
      method: 'GET',
      mode: 'cors',
      cache: 'no-cache'
    });
    
    if (!res.ok) {
      return setStatus(`Connection failed: HTTP ${res.status}. Make sure desktop app is running and logged in.`);
    }
    
    const data = await res.json();
    if (data && data.ok) {
      setStatus('✅ Connected to desktop extension API.');
    } else {
      setStatus('Desktop API responded but not OK.');
    }
  } catch (e) {
    const errorMsg = e.message || 'Unknown error';
    setStatus(`❌ Cannot reach desktop API: ${errorMsg}\n\nMake sure:\n1. Desktop app is running\n2. You are logged in\n3. Extension API is started\n4. Firewall allows 127.0.0.1:5005`);
  }
}

let selectedEntryId = null;

async function autofill() {
  const { apiUrl, token } = await chrome.storage.local.get(['apiUrl', 'token']);
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) {
    return setStatus('No active tab URL.');
  }
  if (!apiUrl || !token) {
    return setStatus('Set API URL and token first.');
  }

  // Check if URL is valid (not chrome://, chrome-extension://, etc.)
  if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://') || 
      tab.url.startsWith('edge://') || tab.url.startsWith('moz-extension://')) {
    return setStatus('❌ Cannot autofill on browser internal pages.');
  }

  // Auto-detect URL and get matching entries
  const matchesEndpoint = `${apiUrl.replace(/\/$/, '')}/api/extension/get-matches?url=${encodeURIComponent(tab.url)}`;

  try {
    const res = await fetch(matchesEndpoint, {
      method: 'GET',
      mode: 'cors',
      cache: 'no-cache',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    
    if (!res.ok) {
      if (res.status === 401) {
        return setStatus('❌ Authentication failed. Check your token or make sure desktop app is logged in.');
      }
      if (res.status === 403) {
        try {
          const errData = await res.json();
          const msg = errData.message || errData.reason || 'Request denied.';
          return setStatus(`❌ ${msg}\n\nUnlock the desktop app or sign in again, then retry.`);
        } catch (_) {
          return setStatus('❌ Request denied. Unlock the desktop app or sign in again, then retry.');
        }
      }
      return setStatus(`❌ Request failed: HTTP ${res.status}`);
    }
    
    const data = await res.json();
    if (!data.ok) {
      return setStatus(data.message || 'Failed to get matches.');
    }

    const matches = data.matches || [];
    
    if (matches.length === 0) {
      return setStatus('No matching entries found for this website.');
    }

    // If only one match, use it directly
    if (matches.length === 1) {
      selectedEntryId = matches[0].id;
      showPhraseDialog(matches[0]);
      return;
    }

    // Multiple matches - show selection
    showMatchSelection(matches);
  } catch (e) {
    const errorMsg = e.message || 'Unknown error';
    if (errorMsg.includes('Failed to fetch') || errorMsg.includes('NetworkError')) {
      setStatus(`❌ Connection failed: ${errorMsg}\n\nMake sure:\n1. Desktop app is running\n2. You are logged in\n3. Extension API is started`);
    } else {
      setStatus(`❌ Error: ${errorMsg}`);
    }
  }
}

function showMatchSelection(matches) {
  const matchesList = document.getElementById('matchesList');
  matchesList.style.display = 'block';
  matchesList.innerHTML = '<div style="font-weight: bold; margin-bottom: 8px;">Multiple matches found. Select one:</div>';
  
  matches.forEach(match => {
    const item = document.createElement('div');
    item.className = 'match-item';
    item.innerHTML = `
      <div class="match-service">${match.service || 'Unknown Service'}</div>
      <div class="match-username">${match.username || 'No username'}</div>
      <div class="match-username" style="font-size: 10px; color: #999;">${match.url || ''}</div>
    `;
    item.onclick = () => {
      selectedEntryId = match.id;
      showPhraseDialog(match);
      matchesList.style.display = 'none';
    };
    matchesList.appendChild(item);
  });
}

function showPhraseDialog(match) {
  const dialog = document.getElementById('phraseDialog');
  const phraseInput = document.getElementById('phraseInput');
  dialog.style.display = 'block';
  phraseInput.value = '';
  phraseInput.focus();
  setStatus(`Selected: ${match.service} (${match.username})\nEnter master phrase to autofill.`);
}

async function verifyAndFill() {
  const { apiUrl, token } = await chrome.storage.local.get(['apiUrl', 'token']);
  const phrase = document.getElementById('phraseInput').value.trim();
  
  if (!phrase) {
    return setStatus('❌ Please enter your master phrase.');
  }

  if (!selectedEntryId) {
    return setStatus('❌ No entry selected.');
  }

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) {
    return setStatus('❌ No active tab.');
  }

  const verifyEndpoint = `${apiUrl.replace(/\/$/, '')}/api/extension/verify-phrase`;

  try {
    const res = await fetch(verifyEndpoint, {
      method: 'POST',
      mode: 'cors',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token: token,
        entry_id: selectedEntryId,
        phrase: phrase
      })
    });
    
    if (!res.ok) {
      if (res.status === 401) {
        document.getElementById('phraseInput').value = '';
        return setStatus('❌ Invalid master phrase. Please try again.');
      }
      return setStatus(`❌ Verification failed: HTTP ${res.status}`);
    }
    
    const data = await res.json();
    if (!data.ok || !data.entry) {
      return setStatus(data.message || 'Failed to get entry.');
    }

    // Hide phrase dialog
    document.getElementById('phraseDialog').style.display = 'none';
    document.getElementById('matchesList').style.display = 'none';

    // Inject content script and autofill
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ['content.js']
      });
      
      await new Promise(resolve => setTimeout(resolve, 200));
      
      const response = await chrome.tabs.sendMessage(tab.id, { 
        type: 'VAULT_AUTOFILL', 
        entry: data.entry 
      });
      
      if (response && response.success) {
        const filled = [];
        if (response.usernameFilled) filled.push('username');
        if (response.passwordFilled) filled.push('password');
        if (filled.length > 0) {
          setStatus(`✅ Filled ${filled.join(' and ')} for: ${data.entry.service}`);
        } else {
          setStatus(`⚠️ No input fields found for: ${data.entry.service}`);
        }
      } else {
        setStatus(`✅ Autofill sent for: ${data.entry.service}`);
      }
      
      // Clear phrase input
      document.getElementById('phraseInput').value = '';
      selectedEntryId = null;
    } catch (msgError) {
      const errorMsg = msgError.message || 'Unknown error';
      setStatus(`❌ Autofill error: ${errorMsg}\n\nTry refreshing the page.`);
    }
  } catch (e) {
    const errorMsg = e.message || 'Unknown error';
    setStatus(`❌ Verification failed: ${errorMsg}`);
  }
}

function cancelPhrase() {
  document.getElementById('phraseDialog').style.display = 'none';
  document.getElementById('matchesList').style.display = 'none';
  document.getElementById('phraseInput').value = '';
  selectedEntryId = null;
  setStatus('Cancelled.');
}

document.getElementById('save').addEventListener('click', saveSettings);
document.getElementById('reset').addEventListener('click', resetDefault);
document.getElementById('health').addEventListener('click', testConnection);
document.getElementById('autofill').addEventListener('click', autofill);
document.getElementById('verifyPhrase').addEventListener('click', verifyAndFill);
document.getElementById('cancelPhrase').addEventListener('click', cancelPhrase);

// Allow Enter key in phrase input
document.getElementById('phraseInput').addEventListener('keypress', (e) => {
  if (e.key === 'Enter') {
    verifyAndFill();
  }
});

loadSettings();
