/* Requested finalization enhancements layered over the stable dashboard. */

function setInvestigationActive(isActive){
    const spinner = document.getElementById("investigationSpinner");
    if(spinner){
        spinner.classList.toggle("is-spinning", Boolean(isActive));
    }
}


function setStatusCardsProcessing(){
    [
        "accounts",
        "github",
        "confidence",
        "threat",
        "risk",
        "confidenceText",
        "threatValue"
    ].forEach(id => {
        const value = document.getElementById(id);
        value.innerText = "Processing...";
        value.classList.add("processing-value");
    });

    document.getElementById("threatReason").innerText =
        "Processing investigation results...";
}


function clearStatusCardsProcessing(){
    [
        "accounts",
        "github",
        "confidence",
        "threat",
        "risk",
        "confidenceText",
        "threatValue"
    ].forEach(id => {
        document.getElementById(id).classList.remove("processing-value");
    });
}


function setStatusCardsUnavailable(){
    clearStatusCardsProcessing();
    [
        "accounts",
        "github",
        "confidence",
        "threat",
        "risk",
        "confidenceText",
        "threatValue"
    ].forEach(id => {
        document.getElementById(id).innerText = "Unavailable";
    });

    document.getElementById("threatReason").innerText =
        "Investigation failed before results were available.";
}


function scanOverviewCount(value){
    const parsed = Number(value);
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
}


function dashboardConfidenceScore(results, accounts){
    if(typeof getConfidenceScore === "function"){
        return getConfidenceScore(results, accounts);
    }

    const backendScore = Number(results && results.confidence);
    if(Number.isFinite(backendScore)){
        return Math.max(0, Math.min(100, Math.round(backendScore)));
    }

    const accountScores = (Array.isArray(accounts) ? accounts : [])
        .map(account => Number(account && account.confidence))
        .filter(Number.isFinite)
        .sort((a, b) => b - a);

    return accountScores.length
        ? Math.max(0, Math.min(100, Math.round(accountScores[0])))
        : 0;
}


function dashboardConfidenceLevel(results, score){
    if(typeof getConfidenceLevel === "function"){
        return getConfidenceLevel(results, score);
    }
    if(results && typeof results.confidence_level === "string"){
        return results.confidence_level;
    }
    if(score <= 0) return "No Confirmed Evidence";
    if(score < 25) return "Very Low";
    if(score < 45) return "Low";
    if(score < 70) return "Moderate";
    if(score < 90) return "High";
    return "Very High";
}


function dashboardConfidenceReasons(results){
    if(typeof getConfidenceReasons === "function"){
        return getConfidenceReasons(results);
    }
    return results && Array.isArray(results.confidence_reasons)
        ? results.confidence_reasons.filter(
            reason => typeof reason === "string" && reason.trim()
        )
        : [];
}


function renderEnhancedScanOverview(data){
    const results = data.results || {};
    const summary = results.summary || {};
    const accounts = Array.isArray(results.accounts) ? results.accounts : [];
    const ghunt = results.ghunt && typeof results.ghunt === "object"
        ? results.ghunt
        : {};

    const servicesFromResult = Array.isArray(ghunt.google_services)
        ? new Set(ghunt.google_services.filter(Boolean).map(String)).size
        : 0;
    const ghuntServices = Object.prototype.hasOwnProperty.call(
        summary,
        "ghunt_services"
    )
        ? scanOverviewCount(summary.ghunt_services)
        : servicesFromResult;

    const githubText = document.getElementById("github").innerText;
    const threatText = document.getElementById("threat").innerText;
    const confidenceText = document.getElementById("confidence").innerText;
    const confidenceScore = dashboardConfidenceScore(results, accounts);
    const confidenceLevel = dashboardConfidenceLevel(results, confidenceScore);
    const confidenceReasons = dashboardConfidenceReasons(results);
    const hibpStatus = summary.hibp || "Not Available";

    document.getElementById("summary").innerHTML = `
        <div class="scan-overview-meta">
            <div><b>Target</b><br>${escapeHtml(String(data.target || "-"))}</div>
            <div><b>Accounts Found</b><br>${accounts.length}</div>
            <div><b>GitHub</b><br>${escapeHtml(githubText)}</div>
            <div><b>Threat / Confidence</b><br>${escapeHtml(threatText)} / ${escapeHtml(confidenceText)}</div>
        </div>

        <div class="scan-overview-section">
            <h3>Confidence Evidence</h3>
            <div class="scan-overview-row"><span>Confidence Level</span><span>${escapeHtml(confidenceLevel)}</span></div>
            ${confidenceReasons.length
                ? confidenceReasons.map(reason => `
                    <div class="scan-overview-row"><span>✓ ${escapeHtml(reason)}</span><span></span></div>
                `).join("")
                : `<div class="scan-overview-row"><span>No confidence explanation returned</span><span></span></div>`}
        </div>

        <div class="scan-overview-section">
            <h3>Username Intelligence</h3>
            <div class="scan-overview-row"><span>Sherlock</span><span>${scanOverviewCount(summary.sherlock)}</span></div>
            <div class="scan-overview-row"><span>Blackbird</span><span>${scanOverviewCount(summary.blackbird)}</span></div>
            <div class="scan-overview-row"><span>Maigret</span><span>${scanOverviewCount(summary.maigret)}</span></div>
            <div class="scan-overview-row"><span>WhatsMyName</span><span>${scanOverviewCount(summary.whatsmyname)}</span></div>
            <div class="scan-overview-row"><span>GitFive</span><span>${scanOverviewCount(summary.gitfive)}</span></div>
        </div>

        <div class="scan-overview-section">
            <h3>Email Intelligence</h3>
            <div class="scan-overview-row"><span>Holehe — Accounts Found</span><span>${scanOverviewCount(summary.holehe)}</span></div>
            <div class="scan-overview-row"><span>GHunt — Google Account Found</span><span>${scanOverviewCount(summary.ghunt)}</span></div>
            <div class="scan-overview-row"><span>GHunt — Services Found</span><span>${ghuntServices}</span></div>
            <div class="scan-overview-row"><span>HIBP Status</span><span>${escapeHtml(String(hibpStatus))}</span></div>
        </div>
    `;
}


function renderAiSectionContent(lines){
    let html = "";
    let bulletItems = [];

    function flushBullets(){
        if(bulletItems.length === 0) return;
        html += `<ul>${bulletItems.map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
        bulletItems = [];
    }

    lines.forEach(rawLine => {
        const line = rawLine.trim();
        if(!line) return;

        const bullet = line.match(/^(?:[-*•]|\d+[.)])\s+(.*)$/);
        if(bullet){
            bulletItems.push(bullet[1]);
            return;
        }

        flushBullets();
        const className = /^risk\s*level\s*:/i.test(line)
            ? " class=\"ai-report-risk\""
            : "";
        html += `<p${className}>${escapeHtml(line)}</p>`;
    });

    flushBullets();
    return html;
}


const originalRenderAiSummary = renderAiSummary;

renderAiSummary = function renderEnhancedAiSummary(aiSummaryRaw){
    if(
        aiSummaryRaw === undefined
        || aiSummaryRaw === null
        || aiSummaryRaw === ""
        || (typeof aiSummaryRaw === "object" && aiSummaryRaw.error)
    ){
        originalRenderAiSummary(aiSummaryRaw);
        return;
    }

    const text = typeof aiSummaryRaw === "string"
        ? aiSummaryRaw
        : JSON.stringify(aiSummaryRaw);
    const reportHeadings = [
        "Investigation Overview",
        "Important Findings",
        "Account and Platform Information",
        "Risk Indicators",
        "Confidence Explanation",
        "Threat Assessment",
        "Conclusion"
    ];
    const headingLookup = new Map(
        reportHeadings.map(heading => [heading.toLowerCase(), heading])
    );
    const sections = [];
    let currentSection = null;

    text.split(/\r?\n/).forEach(rawLine => {
        const cleanHeading = rawLine
            .trim()
            .replace(/^#{1,6}\s*/, "")
            .replace(/^\*\*(.*?)\*\*:?$/, "$1")
            .replace(/:$/, "")
            .trim();
        const knownHeading = headingLookup.get(cleanHeading.toLowerCase());

        if(knownHeading){
            currentSection = {heading: knownHeading, lines: []};
            sections.push(currentSection);
        }
        else if(currentSection){
            currentSection.lines.push(rawLine);
        }
    });

    if(sections.length < 5){
        originalRenderAiSummary(aiSummaryRaw);
        return;
    }

    const box = document.getElementById("aiSummary");
    const badge = document.getElementById("aiSummaryBadge");
    const riskMatch = text.match(
        /risk\s*level\**\s*:\s*\**\s*(low|medium|high|insufficient\s+evidence)/i
    );

    if(riskMatch){
        const riskWord = riskMatch[1].trim().toLowerCase();
        let riskClass = "risk-unknown";
        if(riskWord.startsWith("low")) riskClass = "risk-low";
        else if(riskWord.startsWith("med")) riskClass = "risk-medium";
        else if(riskWord.startsWith("high")) riskClass = "risk-high";
        badge.className = "ai-risk-badge " + riskClass;
        badge.innerText = riskWord.toUpperCase();
    }
    else{
        badge.className = "ai-risk-badge ai-risk-hidden";
        badge.innerText = "";
    }

    box.className = "ai-summary-box";
    box.innerHTML = sections.map(section => `
        <section class="ai-report-section">
            <h3>${escapeHtml(section.heading)}</h3>
            ${renderAiSectionContent(section.lines) || "<p>No information provided.</p>"}
        </section>
    `).join("");
};


const originalUpdateDashboard = updateDashboard;

updateDashboard = function updateEnhancedDashboard(data){
    clearStatusCardsProcessing();
    originalUpdateDashboard(data);
    renderEnhancedScanOverview(data);
};


const originalScanTarget = scanTarget;

scanTarget = async function scanTargetWithProcessingState(){
    const target = document.getElementById("target").value.trim();
    if(target === ""){
        return originalScanTarget();
    }

    const scanPromise = originalScanTarget();
    setStatusCardsProcessing();
    setInvestigationActive(true);

    try{
        return await scanPromise;
    }
    finally{
        if(document.getElementById("progressText").innerText === "Investigation failed."){
            setStatusCardsUnavailable();
        }
        setInvestigationActive(false);
    }
};
