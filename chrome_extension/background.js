// background.js

const API_URL = "http://localhost:5000/predict";

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  if (message.type === "ANALYZE_URL") {
    const tabId = sender.tab?.id;

    chrome.cookies.getAll({ url: message.url || "http://example.com" }, (cookies) => {
      message.features.cookies_count = cookies ? cookies.length : 0;
      
      fetch(API_URL, {
        method : "POST",
        headers: { "Content-Type": "application/json" },
        body   : JSON.stringify(message.features)
      })
    .then(r => r.json())
    .then(result => {
      chrome.storage.local.set({ [`result_${tabId}`]: result });

      const pct = Math.round(result.confidence * 100);
      if (result.is_phishing && pct >= 65) {
        chrome.action.setBadgeText({ text: "!", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#c0392b", tabId });
      } else if (result.is_phishing) {
        chrome.action.setBadgeText({ text: "?", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#e67e22", tabId });
      } else {
        chrome.action.setBadgeText({ text: "✓", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#27ae60", tabId });
      }
      sendResponse({ result });
    })
    .catch(err => {
      console.warn("[ScamShield 2.0] API error:", err.message);
      sendResponse({ error: err.message });
    });
    });

    return true;
  }

  if (message.type === "GET_RESULT") {
    chrome.storage.local.get([`result_${message.tabId}`], (data) => {
      sendResponse({ result: data[`result_${message.tabId}`] || null });
    });
    return true;
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    chrome.storage.local.remove([`result_${tabId}`]);
    chrome.action.setBadgeText({ text: "", tabId });
  }
});
