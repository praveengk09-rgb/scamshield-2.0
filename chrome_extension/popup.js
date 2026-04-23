// popup.js

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;

  let attempts = 0;
  function tryFetch() {
    attempts++;
    chrome.runtime.sendMessage({ type: "GET_RESULT", tabId: tab.id }, (res) => {
      if (chrome.runtime.lastError) return;
      if (res && res.result) showResult(res.result);
      else if (attempts < 15) setTimeout(tryFetch, 600);
    });
  }
  tryFetch();
}

function showResult(result) {
  const card     = document.getElementById('statusCard');
  const icon     = document.getElementById('statusIcon');
  const label    = document.getElementById('statusLabel');
  const sub      = document.getElementById('statusSub');
  const confWrap = document.getElementById('confWrap');
  const confPct  = document.getElementById('confPct');
  const confFill = document.getElementById('confFill');
  const featBox  = document.getElementById('featuresBox');
  const featList = document.getElementById('featuresList');

  const pct        = Math.round(result.confidence * 100);
  const mlPct      = Math.round((result.ml_confidence || 0) * 100);
  const attackType = result.se_attack_type || "";
  const isKnown    = attackType &&
                     attackType !== "NOT-Malicious General Class" &&
                     attackType !== "Unknown";
  const boosted    = result.se_boosted    || false;
  const suppressed = result.se_suppressed || false;

  // ── Status card ────────────────────────────────────
  // suppressed check MUST come first — SE confirmed safe
  if (suppressed) {
    // SE verified legitimate content → green
    // Fixes: LinkedIn/WhatsApp/Canva false positives
    card.className     = "status-card legitimate";
    icon.textContent   = "✅";
    label.textContent  = "Site Looks Safe";
    sub.textContent    = `SE layer verified legitimate content`;
    confFill.className = "confidence-fill legitimate";

  } else if (result.is_phishing && attackType === "Brand Impersonation") {
    // Render Brand Impersonation specifically as Orange (Suspicious)
    card.className    = "status-card checking";
    icon.textContent  = "🔶";
    label.textContent = "Suspicious Impersonation";
    sub.textContent   = `This site visually mimics a known brand (${pct}% confident)`;
    confFill.className= "confidence-fill checking";

  } else if (result.is_phishing && pct >= 85) {
    card.className     = "status-card phishing";
    icon.textContent   = "⚠️";
    label.textContent  = "PHISHING DETECTED";
    sub.textContent    = `Avoid entering personal information! (${pct}% confident)`;
    confFill.className = "confidence-fill phishing";

  } else if (result.is_phishing && pct >= 65) {
    card.className    = "status-card checking";
    icon.textContent  = "🔶";
    label.textContent = "Suspicious Site";
    sub.textContent   = `Proceed with caution (${pct}% confident)`;
    confFill.className= "confidence-fill checking";

  } else if (result.is_phishing && boosted) {
    // SE boosted a borderline case
    card.className    = "status-card checking";
    icon.textContent  = "🔶";
    label.textContent = "Suspicious Site";
    sub.textContent   = `SE detected ${attackType} — proceed with caution`;
    confFill.style.background = "#e67e22";

  } else {
    card.className     = "status-card legitimate";
    icon.textContent   = "✅";
    label.textContent  = "Site Looks Safe";
    sub.textContent    = `No strong phishing signals (${pct}% confident)`;
    confFill.className = "confidence-fill legitimate";
  }

  confWrap.style.display = "block";
  confPct.textContent    = `${pct}%`;
  confFill.style.width   = `${pct}%`;

  // ── Signals ────────────────────────────────────────
  featBox.style.display = "block";
  const rows = [
    {
      label: "🤖 ML Model",
      val  : result.is_phishing ? `${mlPct}% phishing prob` : `${100 - mlPct}% legitimate`,
      color: result.is_phishing ? "var(--color-text-danger)" : "var(--color-text-success)"
    },
    {
      label: "🧠 SE Detection",
      val  : isKnown ? attackType : "No threat",
      color: isKnown ? "var(--color-text-danger)" : "var(--color-text-success)"
    },
  ];

  if (isKnown) {
    rows.push({
      label: "⚡ SE Confidence",
      val  : `${result.se_attack_conf || 0}%`,
      color: "var(--color-text-warning)"
    });
  }

  if (suppressed) {
    rows.push({
      label: "🛡️ SE Override",
      val  : "Content verified safe",
      color: "var(--color-text-success)"
    });
  }

  if (boosted) {
    rows.push({
      label: "🚀 SE Boost",
      val  : "Attack pattern detected",
      color: "var(--color-text-warning)"
    });
  }

  rows.forEach(({ label, val, color }) => {
    const row = document.createElement('div');
    row.className = "feature-row";
    row.innerHTML = `<span>${label}</span><span class="feature-val" style="color:${color}">${val}</span>`;
    featList.appendChild(row);
  });
}

document.getElementById('openDashboardBtn').addEventListener('click', () => {
  chrome.tabs.create({ url: "http://localhost:5000/dashboard" });
});

init();