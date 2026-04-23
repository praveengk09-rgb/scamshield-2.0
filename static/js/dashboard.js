const API_BASE = "http://localhost:5000";

let globalHistory = [];
let currentModalScanId = null;
let distributionChartInstance = null;
let dailyTrendChartInstance = null;

function formatIST(timestampStr) {
    if(!timestampStr) return "Unknown";
    if (!timestampStr.endsWith("Z") && !timestampStr.includes("GMT") && !timestampStr.includes("T")) {
        timestampStr += "Z";
    }
    const d = new Date(timestampStr);
    return d.toLocaleString('en-IN', { 
        timeZone: 'Asia/Kolkata',
        hour12: true,
        year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute:'2-digit', second:'2-digit'
    });
}

// Tab Navigation
function navigateTab(targetId) {
    document.querySelector('.nav-links li.active')?.classList.remove('active');
    document.querySelector(`.nav-links li[data-target="${targetId}"]`)?.classList.add('active');

    document.querySelectorAll('.page-section').forEach(sec => {
        sec.classList.remove('active');
    });
    document.getElementById(targetId).classList.add('active');
    
    if (targetId === 'whitelist') {
        if (typeof populateWhitelist === 'function') populateWhitelist();
    }
}

document.querySelectorAll('.nav-links li').forEach(link => {
    link.addEventListener('click', () => {
        const target = link.getAttribute('data-target');
        navigateTab(target);
    });
});

// Fetch Stats
async function fetchStats() {
    try {
        const res = await fetch(`${API_BASE}/api/stats`);
        const data = await res.json();
        
        document.getElementById('total-scanned').innerText = data.totalScanned;
        document.getElementById('total-phishing').innerText = data.totalPhishing;
        document.getElementById('total-safe').innerText = data.totalSafe;
        document.getElementById('total-suspicious').innerText = data.totalSuspicious;
        
        document.getElementById('cookies-risky').innerText = data.cookiesOnRisky;
        document.getElementById('total-whitelisted').innerText = data.totalWhitelisted || "0";
        document.getElementById('false-positives').innerText = data.falsePositives;
        document.getElementById('false-negatives').innerText = data.falseNegatives;

        renderDistributionChart(data.totalPhishing, data.totalSuspicious, data.totalSafe);
        renderTrendChart(data.dailyTrend);
    } catch (e) {
        console.error("Error fetching stats:", e);
    }
}

// Fetch History
async function fetchHistory() {
    try {
        const res = await fetch(`${API_BASE}/api/history`);
        const data = await res.json();
        globalHistory = data.history;

        // Populate tables
        populateRecentScans();
        populateCookieTracking();
        populatePostmortemList();
        
        // This handles History table directly via the default filter
        applyHistoryFilter();
    } catch (e) {
        console.error("Error fetching history:", e);
    }
}

function populateRecentScans() {
    const tbody = document.querySelector('#recent-scans-table tbody');
    tbody.innerHTML = '';
    
    for(let index = 0; index < Math.min(5, globalHistory.length); index++) {
        const scan = globalHistory[index];
        const timeStr = formatIST(scan.timestamp);
        const badgeClass = scan.verdict === 'phishing' ? 'phishing' : 'legitimate';
        
        const actionBtnHtml = `<button class="btn" onclick="showPostMortem(${index})">View Analysis</button>`;
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${timeStr}</td>
            <td title="${scan.url}"><a href="${scan.url}" target="_blank" style="color:var(--info); text-decoration:none;">${scan.url.substring(0, 40)}...</a></td>
            <td><span class="badge ${badgeClass}">${scan.verdict}</span></td>
            <td>${(scan.confidence * 100).toFixed(1)}%</td>
            <td>${actionBtnHtml}</td>
        `;
        tbody.appendChild(tr);
    }
}

function populateCookieTracking() {
    const tbody = document.querySelector('#cookie-table tbody');
    tbody.innerHTML = '';
    
    globalHistory.forEach((scan, index) => {
        if (scan.cookies_count !== undefined && scan.cookies_count > 0) {
            const timeStr = formatIST(scan.timestamp);
            const badgeClass = scan.verdict === 'phishing' ? 'phishing' : 'legitimate';
            const actionBtnHtml = `<button class="btn" onclick="showPostMortem(${index})">View Analysis</button>`;
            
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${formatIST(scan.timestamp)}</td>
                <td title="${scan.url}">${scan.url.substring(0, 40)}...</td>
                <td><span class="badge ${badgeClass}">${scan.verdict}</span></td>
                <td><strong style="color: var(--accent);">${scan.cookies_count}</strong></td>
                <td>${actionBtnHtml}</td>
            `;
            tbody.appendChild(tr);
        }
    });
}

function populatePostmortemList() {
    const tbody = document.querySelector('#postmortem-table tbody');
    tbody.innerHTML = '';
    
    globalHistory.forEach((scan, index) => {
        const timeStr = formatIST(scan.timestamp);
        const badgeClass = scan.verdict === 'phishing' ? 'phishing' : 'legitimate';
        const actionBtnHtml = `<button class="btn" onclick="showPostMortem(${index})">View Analysis</button>`;
        
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${timeStr}</td>
            <td title="${scan.url}"><a href="${scan.url}" target="_blank" style="color:var(--info); text-decoration:none;">${scan.url.substring(0, 40)}...</a></td>
            <td><span class="badge ${badgeClass}">${scan.verdict}</span></td>
            <td>${actionBtnHtml}</td>
        `;
        tbody.appendChild(tr);
    });
}

// Visualizations 
function renderDistributionChart(phishing, suspicious, safe) {
    const ctx = document.getElementById('distributionChart').getContext('2d');
    if (distributionChartInstance) distributionChartInstance.destroy();
    
    distributionChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Phishing', 'Suspicious', 'Safe'],
            datasets: [{
                data: [phishing, suspicious, safe],
                backgroundColor: ['#e74c3c', '#f39c12', '#2ecc71'],
                borderWidth: 0,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom', labels: { color: '#c5c6c7' } }
            }
        }
    });
}

function renderTrendChart(dailyTrendData) {
    const ctx = document.getElementById('dailyTrendChart').getContext('2d');
    if (dailyTrendChartInstance) dailyTrendChartInstance.destroy();

    const labels = Object.keys(dailyTrendData);
    const phishingData = labels.map(l => dailyTrendData[l].phishing);
    const safeData = labels.map(l => dailyTrendData[l].legitimate);

    dailyTrendChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Phishing',
                    data: phishingData,
                    borderColor: '#e74c3c',
                    backgroundColor: 'rgba(231, 76, 60, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                },
                {
                    label: 'Safe',
                    data: safeData,
                    borderColor: '#2ecc71',
                    backgroundColor: 'rgba(46, 204, 113, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { ticks: { color: '#c5c6c7' }, grid: { color: 'rgba(255,255,255,0.05)' } },
                y: { ticks: { color: '#c5c6c7', stepSize: 1 }, grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true }
            },
            plugins: {
                legend: { labels: { color: '#c5c6c7' } }
            }
        }
    });
}

// Filters & History Sync
window.filterHistory = function(type) {
    const select = document.getElementById('history-filter-select');
    select.value = type;
    navigateTab('history');
    applyHistoryFilter();
};

window.applyHistoryFilter = function() {
    const type = document.getElementById('history-filter-select').value;
    const tbody = document.querySelector('#history-table tbody');
    tbody.innerHTML = '';
    
    globalHistory.forEach((scan, index) => {
        let show = false;
        
        if (type === 'all') show = true;
        else if (type === 'whitelisted' && scan.se_attack_type === 'User Whitelisted') show = true;
        else if (type === 'phishing' && scan.verdict === 'phishing') show = true;
        else if (type === 'safe' && scan.verdict === 'legitimate' && scan.se_attack_type !== 'User Whitelisted' && scan.confidence < 0.4) show = true;
        else if (type === 'suspicious' && scan.verdict === 'legitimate' && scan.confidence >= 0.4 && scan.se_attack_type !== 'User Whitelisted') show = true;
        
        if(type === 'safe' && scan.verdict === 'legitimate' && scan.se_attack_type !== 'User Whitelisted') show = true;

        if (show) {
            const timeStr = formatIST(scan.timestamp);
            const badgeClass = scan.verdict === 'phishing' ? 'phishing' : 'legitimate';
            const actionBtnHtml = `<button class="btn" onclick="showPostMortem(${index})">View Analysis</button>`;
            
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${formatIST(scan.timestamp)}</td>
                <td title="${scan.title || ''}">${scan.title ? scan.title.substring(0,30) + '...' : 'No Title'}</td>
                <td title="${scan.url}"><a href="${scan.url}" target="_blank" style="color:var(--info); text-decoration:none;">${scan.url.substring(0, 40)}...</a></td>
                <td><span class="badge ${badgeClass}">${scan.verdict}</span></td>
                <td>${actionBtnHtml}</td>
            `;
            tbody.appendChild(tr);
        }
    });
}

// Explainability and Post Mortem Tab Logic
window.closePostMortem = function() {
    document.getElementById('postmortem-list-view').style.display = 'block';
    document.getElementById('postmortem-content').style.display = 'none';
};

window.showPostMortem = function(historyIndex) {
    const scan = globalHistory[historyIndex];
    if (!scan) return;
    
    currentModalScanId = scan;
    navigateTab('postmortem');
    
    document.getElementById('postmortem-list-view').style.display = 'none';
    document.getElementById('postmortem-content').style.display = 'block';

    document.getElementById('pm-url').innerText = scan.url;
    document.getElementById('pm-verdict').innerHTML = `<span class="badge ${scan.verdict === 'phishing' ? 'phishing' : 'legitimate'}" style="font-size: 16px;">${scan.verdict}</span>`;
    document.getElementById('pm-ml-conf').innerText = `${(scan.confidence * 100).toFixed(1)}%`;
    document.getElementById('pm-attack').innerText = scan.se_attack_type && scan.se_attack_type !== "NOT-Malicious General Class" ? scan.se_attack_type : "None Documented";

    const featuresList = document.getElementById('pm-features');
    featuresList.innerHTML = '';

    const featuresMap = {
        "LargestLineLength": "Unusually long and complex lines of code",
        "LineOfCode": "Unexpected total website code length",
        "NoOfSelfRef": "Self-referencing links redirecting to the same site",
        "URLLength": "Suspicious, long or complicated website URL",
        "NoOfCSS": "Abnormal number of imported design styles",
        "NoOfImage": "Count of images on the webpage",
        "NoOfExternalRef": "High number of links pointing to outside domains",
        "HasExternalFormSubmit": "User inputs submitting to third-party domains",
        "HasObfuscation": "Code obfuscation used to hide behaviors",
        "HasPasswordField": "Presence of a password entry field",
        "IsHTTPS": "Data transmission security protocol (HTTPS)",
        "DegitRatioInURL": "High ratio of numbers/digits inside the URL",
        "SpacialCharRatioInURL": "Too many special characters in URL",
        "NoOfSubDomain": "Suspicious number of subdomains",
        "HasSocialNet": "Detected social network links/icons",
        "HasSubmitButton": "Found form submit/login buttons"
    };

    try {
        const jsonStr = scan.feature_json.replace(/'/g, '"');
        const features = JSON.parse(jsonStr);
        Object.keys(features).forEach((k, index) => {
            const val = features[k].value;
            const humanName = featuresMap[k] || "Machine Learning Factor: " + k;
            
            // Derive a generic impact based on order (top 5 are returned, so rank them high to low)
            let impactStr = "High Impact";
            if(index > 1) impactStr = "Moderate Impact";
            if(index > 3) impactStr = "Low Impact";

            const item = document.createElement('div');
            item.className = 'feature-item';
            item.innerHTML = `<span><strong style="font-size:15px; color:#fff;">${humanName}</strong> <span style="font-size:11px; opacity:0.6;">(${k})</span></span>
                              <span><span style="color:var(--warning); font-weight:600;">${impactStr}</span> &nbsp;|&nbsp; Value: <span style="color:var(--info); font-weight:bold;">${val.toFixed(2)}</span></span>`;
            featuresList.appendChild(item);
        });
    } catch(e) {
        featuresList.innerHTML = `<span>Could not parse feature contributions. Feature details logged at scan time may be corrupt.</span>`;
    }

    // Populate SE
    const seTactics = (scan.se_tactics && scan.se_tactics !== 'None') ? scan.se_tactics : "No notable social engineering tactics identified in content.";
    const seSummary = (scan.se_summary && scan.se_summary !== 'None') ? scan.se_summary : "Safe content or too little text for NLP scanning.";
    document.getElementById('pm-se-tactics').innerText = Array.isArray(seTactics) ? seTactics.join(", ") : seTactics.replace(/[\[\]']/g, "");
    document.getElementById('pm-se-summary').innerText = seSummary;
}

// Feedback System
window.submitFeedback = async function(type) {
    if (!currentModalScanId) return;
    
    let userVerdict = 'unknown';
    if(type === 'false_positive' || type === 'safe') {
        userVerdict = 'legitimate';
        const confirmSafe = confirm("WARNING: Marking this site as legitimate will aggressively whitelist its domain locally. Future scans will ignore phishing signals on this site until reversed. Continue?");
        if (!confirmSafe) return;
    }
    if(type === 'false_negative') userVerdict = 'phishing';

    try {
        await fetch(`${API_BASE}/api/feedback`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                scan_id: currentModalScanId.id,
                url: currentModalScanId.url,
                feedback_type: type,
                user_verdict: userVerdict
            })
        });
        
        alert("Verdict recorded! Thank you for the proactive feedback to improve the model.");
        navigateTab('history');
        fetchStats(); 
    } catch (e) {
        console.error("Error submitting feedback:", e);
        alert("Error submitting feedback. Ensure backend is running local.");
    }
}

window.revokeFeedback = async function() {
    if (!currentModalScanId) return;
    
    const confirmRevoke = confirm("WARNING: Reversing decision will remove this website's local whitelist/blacklist policy. Continue?");
    if (!confirmRevoke) return;
    
    try {
        await fetch(`${API_BASE}/api/revoke_feedback`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: currentModalScanId.url })
        });
        
        alert("Decisions reversed for this domain!");
        navigateTab('history');
    } catch (e) {
        console.error("Error revoking decision:", e);
        alert("Error reversing feedback.");
    }
}

// Init
fetchStats();
fetchHistory();

// Added Whitelist function
window.populateWhitelist = async function() {
    try {
        const res = await fetch('/api/whitelist');
        const data = await res.json();
        
        const tbody = document.getElementById('whitelist-table');
        if (!tbody) return;
        tbody.innerHTML = '';
        
        if (!data || data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-secondary);">No custom overridden websites found.</td></tr>';
            return;
        }

        data.forEach(item => {
            const timeStr = formatIST(item.timestamp);
            let badgeClass = item.user_verdict === "legitimate" ? "legitimate" : "phishing";
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>#${item.id}</td>
                <td title="${item.url}">${item.url}</td>
                <td><span class="badge ${badgeClass}">${item.user_verdict}</span></td>
                <td>${timeStr}</td>
                <td><button class="btn btn-fp" onclick="removeWhitelistItem(${item.id})">Remove Domain</button></td>
            `;
            tbody.appendChild(tr);
        });
    } catch(err) {
        console.error("Error fetching whitelist", err);
    }
}

window.removeWhitelistItem = async function(id) {
    if(!confirm("Are you sure you want to remove this override and reset the domain back to its default AI classification?")) return;
    try {
        const res = await fetch('/api/whitelist/delete/' + id, { method: "DELETE" });
        const data = await res.json();
        if(data.status === "success") {
            populateWhitelist();
            fetchStats();
        }
    } catch(err) {
        console.error(err);
    }
}
