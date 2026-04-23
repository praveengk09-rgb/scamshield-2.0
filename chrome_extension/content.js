// content.js — extracts ML features + page text for SE NLP

(function () {

  function extractFeatures(url) {
    const urlObj  = new URL(url);
    const fullURL = url;
    const domain  = urlObj.hostname;
    const count   = (str, ch) => (str.split(ch).length - 1);

    const pageText = (() => {
      try {
        const clone = document.body.cloneNode(true);
        clone.querySelectorAll('script,style,noscript').forEach(el => el.remove());
        return (clone.innerText || clone.textContent || "").replace(/\s+/g,' ').trim().slice(0,3000);
      } catch { return ""; }
    })();

    return {
      url        : fullURL,
      page_text  : pageText,
      page_title : document.title || "",
      URLLength              : fullURL.length,
      DomainLength           : domain.length,
      IsDomainIP             : /^\d{1,3}(\.\d{1,3}){3}$/.test(domain) ? 1 : 0,
      TLDLength              : domain.split('.').pop().length,
      NoOfSubDomain          : Math.max(0, domain.split('.').length - 2),
      NoOfLettersInURL       : (fullURL.match(/[a-zA-Z]/g)||[]).length,
      LetterRatioInURL       : parseFloat(((fullURL.match(/[a-zA-Z]/g)||[]).length/fullURL.length).toFixed(4)),
      NoOfDegitsInURL        : (fullURL.match(/\d/g)||[]).length,
      DegitRatioInURL        : parseFloat(((fullURL.match(/\d/g)||[]).length/fullURL.length).toFixed(4)),
      NoOfEqualsInURL        : count(fullURL,'='),
      NoOfQMarkInURL         : count(fullURL,'?'),
      NoOfAmpersandInURL     : count(fullURL,'&'),
      NoOfOtherSpecialCharsInURL: (fullURL.match(/[^a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]/g)||[]).length,
      SpacialCharRatioInURL  : parseFloat(((fullURL.match(/[^a-zA-Z0-9]/g)||[]).length/fullURL.length).toFixed(4)),
      IsHTTPS                : urlObj.protocol==='https:' ? 1 : 0,
      HasObfuscation         : fullURL.includes('%') ? 1 : 0,
      NoOfObfuscatedChar     : (fullURL.match(/%[0-9A-Fa-f]{2}/g)||[]).length,
      ObfuscationRatio       : parseFloat((((fullURL.match(/%[0-9A-Fa-f]{2}/g)||[]).length)/fullURL.length).toFixed(4)),
      LineOfCode             : document.documentElement.innerHTML.split('\n').length,
      LargestLineLength      : Math.max(...document.documentElement.innerHTML.split('\n').map(l=>l.length)),
      HasTitle               : document.title ? 1 : 0,
      HasFavicon             : document.querySelector('link[rel*="icon"]') ? 1 : 0,
      IsResponsive           : document.querySelector('meta[name="viewport"]') ? 1 : 0,
      NoOfURLRedirect        : 0, NoOfSelfRedirect: 0,
      HasDescription         : document.querySelector('meta[name="description"]') ? 1 : 0,
      NoOfPopup              : 0,
      NoOfiFrame             : document.querySelectorAll('iframe').length,
      HasExternalFormSubmit  : (() => {
        for (const f of document.querySelectorAll('form')) {
          const a = f.getAttribute('action')||'';
          if (a && !a.startsWith('/') && !a.includes(domain)) return 1;
        }
        return 0;
      })(),
      HasSocialNet    : /facebook|twitter|instagram|linkedin|youtube/i.test(document.body.innerHTML) ? 1 : 0,
      HasSubmitButton : document.querySelectorAll('input[type="submit"],button[type="submit"]').length > 0 ? 1 : 0,
      HasHiddenFields : document.querySelectorAll('input[type="hidden"]').length,
      HasPasswordField: document.querySelectorAll('input[type="password"]').length > 0 ? 1 : 0,
      Bank            : /bank|banking/i.test(fullURL+document.title) ? 1 : 0,
      Pay             : /pay|payment|paypal/i.test(fullURL+document.title) ? 1 : 0,
      Crypto          : /crypto|bitcoin|btc|ethereum|wallet/i.test(fullURL+document.title) ? 1 : 0,
      HasCopyrightInfo: /copyright|©/i.test(document.body.innerHTML) ? 1 : 0,
      NoOfImage       : document.querySelectorAll('img').length,
      NoOfCSS         : document.querySelectorAll('link[rel="stylesheet"]').length,
      NoOfJS          : document.querySelectorAll('script[src]').length,
      NoOfSelfRef     : (() => { let n=0; document.querySelectorAll('a[href]').forEach(l=>{if((l.href||'').includes(domain))n++;}); return n; })(),
      NoOfEmptyRef    : (() => { let n=0; document.querySelectorAll('a[href]').forEach(l=>{if(!l.getAttribute('href')||l.getAttribute('href')==='#')n++;}); return n; })(),
      NoOfExternalRef : (() => { let n=0; document.querySelectorAll('a[href]').forEach(l=>{if(l.href&&!l.href.includes(domain)&&l.href.startsWith('http'))n++;}); return n; })(),
      Robots: 0,
    };
  }

  const features = extractFeatures(window.location.href);

  chrome.runtime.sendMessage({ type:"ANALYZE_URL", url:window.location.href, features }, (response) => {
    if (chrome.runtime.lastError) return;
    if (response && response.result) {
      const result = response.result;
      const pct    = Math.round(result.confidence * 100);
      if (result.is_phishing && pct >= 85) injectBanner(result, "phishing");
      else if (result.is_phishing && pct >= 65) injectBanner(result, "suspicious");
      else if (result.is_phishing && result.se_boosted) injectBanner(result, "suspicious");
    }
  });

  function injectBanner(result, type) {
    if (document.getElementById('scamshield-host')) return;

    const isPhishing = type === "phishing";
    const bgColor    = isPhishing ? "#c0392b" : "#e67e22";
    const pct        = Math.round(result.confidence * 100);
    const attack     = result.se_attack_type &&
                       result.se_attack_type !== "NOT-Malicious General Class"
                       ? ' | ' + result.se_attack_type : '';

    // Host element — sits in real DOM
    const host = document.createElement('div');
    host.id = 'scamshield-host';
    host.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:2147483647;pointer-events:none;';

    // Shadow DOM — page CSS and JS cannot reach inside
    const shadow = host.attachShadow({ mode: 'open' });

    const banner = document.createElement('div');
    banner.style.cssText =
      'display:flex;align-items:center;justify-content:space-between;' +
      'background:' + bgColor + ';color:white;padding:12px 20px;' +
      'font-family:Arial,sans-serif;font-size:14px;font-weight:bold;' +
      'box-shadow:0 2px 8px rgba(0,0,0,0.4);box-sizing:border-box;width:100%;' +
      'pointer-events:all;';

    const text = document.createElement('span');
    text.style.cssText = 'color:white;font-size:14px;font-weight:bold;flex:1;font-family:Arial,sans-serif;';
    text.textContent = (isPhishing ? '⚠️ PHISHING DETECTED' : '🔶 Suspicious Site') +
                       ' (' + pct + '% confidence' + attack + ') — Do not enter personal info.';

    const btn = document.createElement('button');
    btn.style.cssText =
      'background:white;color:' + bgColor + ';border:none;' +
      'padding:6px 14px;border-radius:4px;cursor:pointer;font-weight:bold;' +
      'font-family:Arial,sans-serif;font-size:14px;margin-left:16px;flex-shrink:0;' +
      'pointer-events:all;position:relative;z-index:2147483647;' +
      '-webkit-user-select:none;user-select:none;touch-action:manipulation;';
    btn.textContent = 'Dismiss';

    // ── Dismiss button fix ──────────────────────────────
    // mousedown + capture phase fires BEFORE LinkedIn/WhatsApp/Canva
    // can intercept it. stopImmediatePropagation blocks ALL other listeners.

    function removeBanner() {
      var h = document.getElementById('scamshield-host');
      if (h) h.remove();
    }

    btn.addEventListener('mousedown', function(e) {
      e.stopImmediatePropagation();
      e.stopPropagation();
      e.preventDefault();
      removeBanner();
    }, true);   // ← true = capture phase, critical for SPAs

    btn.addEventListener('pointerdown', function(e) {
      e.stopImmediatePropagation();
      e.stopPropagation();
      e.preventDefault();
      removeBanner();
    }, true);

    btn.addEventListener('click', function(e) {
      e.stopImmediatePropagation();
      e.stopPropagation();
      e.preventDefault();
      removeBanner();
    }, true);

    banner.appendChild(text);
    banner.appendChild(btn);
    shadow.appendChild(banner);
    document.documentElement.prepend(host);
  }

})();