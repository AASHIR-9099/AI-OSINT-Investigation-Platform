const SETTINGS_KEY = "ironclad_settings";

const DEFAULT_SETTINGS = {
    apiUrl: "http://127.0.0.1:8000",
    pollInterval: 700,
    theme: "dark"
};

function loadSettings(){
    try{
        const raw = localStorage.getItem(SETTINGS_KEY);
        if(!raw) return { ...DEFAULT_SETTINGS };
        const parsed = JSON.parse(raw);
        return { ...DEFAULT_SETTINGS, ...parsed };
    }catch(err){
        console.error("Failed to load settings, using defaults:", err);
        return { ...DEFAULT_SETTINGS };
    }
}

let appSettings = loadSettings();

// API_URL is used throughout the app - kept as a variable (not const)
// so Settings can change it at runtime without a page reload.
let API_URL = appSettings.apiUrl;

let latestResult = null;


function applyTheme(theme){
    document.body.classList.toggle("theme-light", theme === "light");
}


function populateSettingsForm(){
    document.getElementById("settingApiUrl").value = appSettings.apiUrl;
    document.getElementById("settingPollInterval").value = appSettings.pollInterval;
    document.getElementById("settingTheme").value = appSettings.theme;
}


function openSettings(){
    populateSettingsForm();
    document.getElementById("settingsOverlay").classList.remove("hidden");
    document.getElementById("backendStatusText").innerText = "Backend status: unknown";
    document.getElementById("backendStatusDot").className = "status-dot";
}


function closeSettings(){
    document.getElementById("settingsOverlay").classList.add("hidden");
}


function saveSettings(){

    const apiUrlInput = document.getElementById("settingApiUrl").value.trim();
    const pollInput = parseInt(document.getElementById("settingPollInterval").value, 10);
    const themeInput = document.getElementById("settingTheme").value;

    appSettings.apiUrl = apiUrlInput || DEFAULT_SETTINGS.apiUrl;
    appSettings.pollInterval = (!isNaN(pollInput) && pollInput >= 200) ? pollInput : DEFAULT_SETTINGS.pollInterval;
    appSettings.theme = themeInput;

    localStorage.setItem(SETTINGS_KEY, JSON.stringify(appSettings));

    API_URL = appSettings.apiUrl;
    applyTheme(appSettings.theme);

    closeSettings();
}


function clearAllSettings(){

    if(!confirm("This will reset all settings to defaults and clear any saved data. Continue?")){
        return;
    }

    localStorage.removeItem(SETTINGS_KEY);
    appSettings = { ...DEFAULT_SETTINGS };
    API_URL = appSettings.apiUrl;
    applyTheme(appSettings.theme);
    populateSettingsForm();
    resetDashboard();
}


async function checkBackendStatus(){

    const dot = document.getElementById("backendStatusDot");
    const text = document.getElementById("backendStatusText");

    text.innerText = "Testing connection...";
    dot.className = "status-dot";

    const urlToTest = document.getElementById("settingApiUrl").value.trim() || API_URL;

    try{
        const response = await fetch(urlToTest + "/", { method: "GET" });

        if(response.ok){
            dot.className = "status-dot online";
            text.innerText = "Backend status: online";
        }else{
            dot.className = "status-dot offline";
            text.innerText = "Backend status: error (" + response.status + ")";
        }
    }catch(err){
        dot.className = "status-dot offline";
        text.innerText = "Backend status: unreachable";
    }

}


/* =====================================
   RESET / DEFAULT STATE
   Restores the dashboard to its empty
   starting state. Called on every page
   load/reload AND right before a new
   scan begins, so nothing from a
   previous investigation lingers.
===================================== */

function resetDashboard(clearInput = true){

    if(clearInput){
        document.getElementById("target").value = "";
    }

    document.getElementById("progressBar").style.width = "0%";
    document.getElementById("progressText").innerText = "Waiting for investigation...";

    document.getElementById("accounts").innerText = "0";
    document.getElementById("github").innerText = "NONE";
    document.getElementById("confidence").innerText = "0%";
    document.getElementById("threat").innerText = "LOW";

    document.getElementById("profileName").innerText = "No Target Selected";
    document.getElementById("risk").innerText = "Unknown";
    document.getElementById("confidenceText").innerText = "0%";

    document.getElementById("threatValue").innerText = "LOW";
    document.getElementById("threatReason").innerText = "No investigation performed.";

    document.getElementById("summary").innerText = "Waiting for investigation...";
    document.getElementById("loading").innerText = "System Ready...";

    document.getElementById("aiSummary").innerText = "Waiting for investigation...";
    document.getElementById("aiSummary").className = "ai-summary-box";
    const aiBadgeReset = document.getElementById("aiSummaryBadge");
    aiBadgeReset.className = "ai-risk-badge ai-risk-hidden";
    aiBadgeReset.innerText = "";
    document.getElementById("socialResults").innerText = "No investigation performed.";
    document.getElementById("githubResults").innerText = "No GitHub intelligence available.";
    document.getElementById("hibpResults").className = "";
    document.getElementById("hibpResults").innerText = "No investigation performed.";
    document.getElementById("result").textContent = "No investigation started.";

    setThreatLevelClasses("low");

    if(typeof clearStatusCardsProcessing === "function"){
        clearStatusCardsProcessing();
    }

    latestResult = null;
}


/* Run once when the page first loads */
document.addEventListener("DOMContentLoaded", () => {
    applyTheme(appSettings.theme);
    resetDashboard();
});

/* Also run when the page is restored from the browser's
   back/forward cache (bfcache) - some browsers repopulate
   inputs from cache on reload without firing a fresh load */
window.addEventListener("pageshow", (event) => {
    if(event.persisted){
        resetDashboard();
    }
});


/* =====================================
   START INVESTIGATION
===================================== */

async function scanTarget(){

    const target =
        document.getElementById("target").value.trim();


    if(target === ""){

        alert("Enter username/email/domain");

        return;

    }

    const isEmailTarget = target.includes("@");

    // Clear out any previous investigation's results before
    // starting a new one, but keep the target the user typed.
    resetDashboard(false);

    // Show the submitted target as soon as the investigation begins.
    document.getElementById("profileName").innerText = target;

    const loading =
        document.getElementById("loading");


    const result =
        document.getElementById("result");



    loading.innerHTML =
    "Initializing Investigation...<br>";


    result.textContent =
    "Running investigation...";

    document.getElementById("progressText").innerText =
    isEmailTarget
        ? "Initializing Investigation... (0%)"
        : "Starting OSINT Scan...";

    document.getElementById("aiSummary").className = "ai-summary-box";
    document.getElementById("aiSummary").innerHTML =
        `<div class="ai-summary-loading">
            <span class="ai-summary-spinner"></span>
            Waiting for scan data before running local AI (Llama) analysis...
        </div>`;



    try{

        // 1) Kick off the scan - backend returns immediately
        //    with a job_id and runs the real scan in the
        //    background.

        const startResponse = await fetch(
            `${API_URL}/scan`,
            {
                method:"POST",
                headers:{
                    "Content-Type":"application/json"
                },
                body:JSON.stringify({
                    target:target
                })
            }
        );

        if(!startResponse.ok){
            throw new Error(
                "Backend returned error: " + startResponse.status
            );
        }

        const startData = await startResponse.json();
        const jobId = startData.job_id;

        if(!jobId){
            throw new Error("Backend did not return a job_id.");
        }

        // 2) Poll /status/{job_id} - this reflects the REAL,
        //    live progress of the backend scan (not a simulated
        //    timer), so the bar moves exactly as fast/slow as
        //    each OSINT engine actually runs.

        const finalData = await pollJobUntilDone(jobId, isEmailTarget);

        latestResult = finalData;

        result.textContent =
            JSON.stringify(finalData, null, 4);

        updateDashboard(finalData);

        loading.innerHTML +=
        `
        <br>
        <span style="color:#00D084">
        ✓ INVESTIGATION COMPLETED
        </span>
        `;

        document.getElementById("progressBar").style.width = "100%";
        document.getElementById("progressText").innerText =
            isEmailTarget
                ? "Investigation Complete (100%)"
                : "Investigation completed.";

    }

    catch(error){

        console.error(error);

        loading.innerHTML +=
        `
        <br>
        <span style="color:red">
        Connection Failed
        </span>
        `;

        result.textContent =
        error.message;

        document.getElementById("progressText").innerText =
        "Investigation failed.";

    }

}




/* =====================================
   POLL BACKEND FOR REAL PROGRESS
   Polls /status/{job_id} at the interval
   configured in Settings (default 700ms)
   and drives the progress bar + live log
   from whatever the backend actually
   reports - no fake/simulated timing.
===================================== */

function pollJobUntilDone(jobId, isEmailInvestigation = false){

    const progressBar = document.getElementById("progressBar");
    const progressText = document.getElementById("progressText");
    const log = document.getElementById("loading");

    let lastDescription = "";
    let renderedEventCount = 0;
    let pollInFlight = false;
    let pollFinished = false;

    // Multiple tools can start or finish between two polls. Keep the Live
    // Investigation Log immediate, while the headline consumes the same event
    // history in order so short-lived states (for example Sherlock running or
    // completing) are not skipped.
    const HEADLINE_EVENT_MS = 400;
    const headlineQueue = [];
    const headlineWaiters = [];
    let headlineBusy = false;
    let headlineTimer = null;
    let plannedHeadlinePercent = 0;
    let runningToolCount = 0;
    let completedToolCount = 0;

    function isToolTerminalEvent(description){
        return (
            description.startsWith("Completed:") ||
            description.startsWith("Completed with limitations:") ||
            description.startsWith("Skipped:") ||
            description.startsWith("Failed:") ||
            description.startsWith("Timed out:") ||
            description.startsWith("Unavailable:") ||
            description.startsWith("Rate limited:") ||
            description.startsWith("Parser failure:")
        );
    }

    function nextEmailHeadlinePercent(description, backendPercent){
        let proposedPercent = plannedHeadlinePercent;

        if(description.startsWith("Starting OSINT Scan")){
            proposedPercent = 5;
        }
        else if(description.startsWith("Running:")){
            runningToolCount += 1;
            const runningMilestones = [15, 30, 45];
            proposedPercent = runningMilestones[
                Math.min(runningToolCount, runningMilestones.length) - 1
            ];
        }
        else if(isToolTerminalEvent(description)){
            completedToolCount += 1;
            const completionMilestones = [60, 75, 85];
            proposedPercent = completionMilestones[
                Math.min(completedToolCount, completionMilestones.length) - 1
            ];
        }
        else if(description.startsWith("All OSINT tools completed")){
            proposedPercent = 90;
        }
        else if(description.startsWith("Generating AI Risk Summary")){
            proposedPercent = 95;
        }
        else if(description.startsWith("Investigation completed")){
            proposedPercent = 100;
        }
        else if(Number.isFinite(backendPercent)){
            proposedPercent = backendPercent;
        }

        plannedHeadlinePercent = Math.max(
            plannedHeadlinePercent,
            Math.min(Math.max(proposedPercent, 0), 100)
        );

        return plannedHeadlinePercent;
    }

    function releaseHeadlineWaiters(){
        if(headlineBusy || headlineQueue.length > 0){
            return;
        }

        while(headlineWaiters.length > 0){
            headlineWaiters.shift()();
        }
    }

    function processHeadlineQueue(){
        if(headlineBusy){
            return;
        }

        const event = headlineQueue.shift();

        if(!event){
            releaseHeadlineWaiters();
            return;
        }

        headlineBusy = true;
        progressBar.style.width = event.percent + "%";
        progressText.innerText =
            event.description + " (" + event.percent + "%)";

        headlineTimer = setTimeout(() => {
            headlineTimer = null;
            headlineBusy = false;
            processHeadlineQueue();
            releaseHeadlineWaiters();
        }, HEADLINE_EVENT_MS);
    }

    function enqueueHeadlineEvent(description, backendPercent){
        let headlinePercent;

        if(isEmailInvestigation){
            // Preserve the existing three-tool email milestone behavior.
            headlinePercent =
                nextEmailHeadlinePercent(description, backendPercent);
        }
        else{
            // Username investigations already receive real percentages with
            // their backend events. Keep them monotonic while displaying every
            // event in order.
            const safePercent = Number.isFinite(backendPercent)
                ? Math.min(Math.max(backendPercent, 0), 100)
                : plannedHeadlinePercent;

            plannedHeadlinePercent = Math.max(
                plannedHeadlinePercent,
                safePercent
            );

            headlinePercent = plannedHeadlinePercent;
        }

        headlineQueue.push({
            description: description,
            percent: headlinePercent
        });
        processHeadlineQueue();
    }

    function waitForHeadlineQueue(){
        if(!headlineBusy && headlineQueue.length === 0){
            return Promise.resolve();
        }

        return new Promise(resolveHeadline => {
            headlineWaiters.push(resolveHeadline);
        });
    }

    function cancelHeadlineQueue(){
        if(headlineTimer !== null){
            clearTimeout(headlineTimer);
            headlineTimer = null;
        }

        headlineQueue.length = 0;
        headlineBusy = false;
        releaseHeadlineWaiters();
    }

    function appendProgressEvent(description){
        let marker = "✓";

        if(description.startsWith("Running:")){
            marker = "→";
        }
        else if(
            description.startsWith("Failed:") ||
            description.startsWith("Timed out:") ||
            description.startsWith("Unavailable:") ||
            description.startsWith("Skipped:") ||
            description.startsWith("Rate limited:") ||
            description.startsWith("Parser failure:")
        ){
            marker = "!";
        }

        log.innerHTML += marker + " " + description + "<br>";
    }

    return new Promise((resolve, reject) => {

        const intervalId = setInterval(async () => {

            if(pollInFlight || pollFinished){
                return;
            }

            pollInFlight = true;

            try{

                const response = await fetch(`${API_URL}/status/${jobId}`);

                if(!response.ok){
                    throw new Error(
                        "Backend returned error: " + response.status
                    );
                }

                const job = await response.json();

                if(job.error && job.done !== true && !("percent" in job)){
                    throw new Error(job.error);
                }

                const percent = job.percent ?? 0;
                const description = job.description || "Working...";

                const events = Array.isArray(job.events) ? job.events : [];

                if(events.length > 0){
                    for(
                        let index = renderedEventCount;
                        index < events.length;
                        index++
                    ){
                        const eventDescription =
                            events[index].description || "Working...";

                        // Keep the existing Live Investigation Log behavior.
                        appendProgressEvent(eventDescription);
                        enqueueHeadlineEvent(
                            eventDescription,
                            events[index].percent ?? percent
                        );
                    }

                    renderedEventCount = events.length;
                    lastDescription = description;
                }
                else if(description !== lastDescription){
                    // Compatibility with a backend that predates event history.
                    appendProgressEvent(description);
                    enqueueHeadlineEvent(description, percent);
                    lastDescription = description;
                }

                if(job.done){

                    pollFinished = true;
                    clearInterval(intervalId);

                    // Do not let the final dashboard update overwrite queued
                    // tool headlines that have not yet been displayed.
                    await waitForHeadlineQueue();

                    if(job.error){
                        reject(new Error(job.error));
                        return;
                    }

                    resolve({
                        target: job.target,
                        results: job.results
                    });

                }

            }
            catch(err){
                pollFinished = true;
                clearInterval(intervalId);
                cancelHeadlineQueue();
                reject(err);
            }
            finally{
                pollInFlight = false;
            }

        }, appSettings.pollInterval || DEFAULT_SETTINGS.pollInterval);

    });

}




/* =====================================
   THREAT LEVEL STYLING HELPER
===================================== */

function setThreatLevelClasses(level){

    // level is "low" | "medium" | "high"

    const threatCircle = document.getElementById("threatValue").parentElement;
    const threatCard = document.getElementById("threat").parentElement;

    threatCircle.classList.remove("level-low","level-medium","level-high");
    threatCard.classList.remove("level-low","level-medium","level-high");

    threatCircle.classList.add("level-" + level);
    threatCard.classList.add("level-" + level);

}




/* =====================================
   RENDER SOCIAL ACCOUNTS
===================================== */

function socialDisplayValue(value){

    if(value === null || value === undefined){
        return "";
    }

    const text = String(value).trim();
    const rejectedValues = new Set(["", "#", "null", "undefined"]);

    return rejectedValues.has(text.toLowerCase()) ? "" : text;

}


function socialProfileUrl(value){

    const url = socialDisplayValue(value);

    // Display only an actual URL returned by the backend. Never construct one.
    return /^https?:\/\/[^/\s?#]+(?:[/?#]|$)/i.test(url) ? url : "";

}


function escapeHtmlAttribute(value){

    return escapeHtml(String(value))
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");

}


function renderSocialResults(accounts){

    const container = document.getElementById("socialResults");
    const usableAccounts = (Array.isArray(accounts) ? accounts : [])
        .map(acc => {
            if(!acc || typeof acc !== "object"){
                return null;
            }

            const platform = [acc.website, acc.platform, acc.site]
                .map(socialDisplayValue)
                .find(Boolean) || "";

            if(!platform){
                return null;
            }

            const identifier = [
                acc.username,
                acc.account_identifier,
                acc.email
            ].map(socialDisplayValue).find(Boolean) || "";
            const url = socialProfileUrl(acc.url);
            const toolSources = Array.isArray(acc.tools)
                ? acc.tools.map(socialDisplayValue).filter(Boolean).join(", ")
                : "";
            const source = socialDisplayValue(acc.source) || toolSources;

            return {platform, identifier, url, source};
        })
        .filter(Boolean);

    if(usableAccounts.length === 0){
        container.innerText = "No social accounts were discovered.";
        return;
    }

    container.innerHTML = usableAccounts.map(account => `
        <p>
            <strong>${escapeHtml(account.platform)}</strong><br>
            ${account.identifier
                ? `<small>${escapeHtml(account.identifier)}</small><br>`
                : ""}
            ${account.url
                ? `<small><a href="${escapeHtmlAttribute(account.url)}" target="_blank" rel="noopener noreferrer" style="color:var(--blue);">${escapeHtml(account.url)}</a></small>`
                : `<small>Account Exists</small>`}
            ${account.source
                ? `<br><small>Source: ${escapeHtml(account.source)}</small>`
                : ""}
        </p>
    `).join("");

}




/* =====================================
   RENDER GITHUB INTELLIGENCE
===================================== */

function renderGithubResults(gitfive){

    const container = document.getElementById("githubResults");

    if(!gitfive || !gitfive.github_found){
        container.innerText = "No GitHub intelligence available.";
        return;
    }

    let html = "";

    for(const [key, value] of Object.entries(gitfive)){

        if(key === "accounts") continue;

        html +=
        `<div class="gh-row">
            <span>${key}</span>
            <span>${value}</span>
        </div>`;

    }

    container.innerHTML = html || "GitHub account detected.";

}




/* =====================================
   RENDER HIBP BREACH INTELLIGENCE
===================================== */

function renderHibpResults(hibp){

    const container = document.getElementById("hibpResults");

    if(!hibp){
        container.className = "";
        container.innerText = "No investigation performed.";
        return;
    }

    if(hibp.error){
        container.className = "hibp-unconfigured";
        container.innerText = "HIBP check failed: " + hibp.error;
        return;
    }

    if(hibp.skipped || hibp.configured === false){
        container.className = "hibp-unconfigured";
        container.innerText =
            hibp.reason ||
            "HIBP check skipped - set the HIBP_API_KEY environment variable to enable email breach lookups.";
        return;
    }

    if(hibp.breached){

        const breaches = hibp.breaches || [];

        container.className = "hibp-breached";
        container.innerHTML =
            `<div class="hibp-row">
                <span>Status</span>
                <span>BREACHED - found in ${breaches.length} breach(es)</span>
            </div>
            <div class="breach-list">
                ${breaches.map(name => `<span class="breach-tag">${name}</span>`).join("")}
            </div>`;

        return;
    }

    container.className = "hibp-safe";
    container.innerText = "No known breaches found for this email.";

}






/* =====================================
   CONFIDENCE HELPERS
   The backend is the source of truth.
   The fallback uses existing per-account
   scores only and never account volume.
===================================== */

function clampConfidenceScore(value){
    const numeric = Number(value);
    if(!Number.isFinite(numeric)) return 0;
    return Math.max(0, Math.min(100, Math.round(numeric)));
}


function getConfidenceScore(results, accounts){
    if(
        results
        && Object.prototype.hasOwnProperty.call(results, "confidence")
        && Number.isFinite(Number(results.confidence))
    ){
        return clampConfidenceScore(results.confidence);
    }

    const accountScores = (Array.isArray(accounts) ? accounts : [])
        .map(account => Number(account && account.confidence))
        .filter(Number.isFinite)
        .sort((a, b) => b - a);

    return accountScores.length
        ? clampConfidenceScore(accountScores[0])
        : 0;
}


function getConfidenceLevel(results, score){
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


function getConfidenceReasons(results){
    if(!results || !Array.isArray(results.confidence_reasons)){
        return [];
    }

    return results.confidence_reasons
        .filter(reason => typeof reason === "string" && reason.trim())
        .map(reason => reason.trim());
}


/* =====================================
   UPDATE DASHBOARD
===================================== */


function updateDashboard(data){



    const results =
    data.results || {};



    const accounts =
    results.accounts || [];



    const gitfive =
    results.gitfive || {};



    const summary =
    results.summary || {};



    // Accounts


    document.getElementById("accounts")
    .innerText =
    accounts.length;


    document.getElementById("profileName")
    .innerText =
    data.target;




    // Github


    let githubFound=false;

    if(gitfive.github_found){

        githubFound=true;

    }



    document.getElementById("github")
    .innerText =
    githubFound ? "FOUND":"NONE";




    // Confidence
    // Backend evidence scoring is authoritative. Account count and GitHub
    // presence are not recalculated in the browser.

    const confidence = getConfidenceScore(results, accounts);
    const confidenceLevel = getConfidenceLevel(results, confidence);
    const confidenceReasons = getConfidenceReasons(results);

    document.getElementById("confidence")
    .innerText =
    confidence+"%";

    document.getElementById("confidenceText")
    .innerText =
    confidence+"%";




    // -----------------------------------------
    // THREAT LEVEL
    // Based on how many accounts/platforms the
    // target's identity was confirmed on:
    //   0-20   accounts -> LOW
    //   21-50  accounts -> MEDIUM
    //   50+    accounts -> HIGH
    // Only ever calculated after a scan has
    // actually returned results (i.e. here).
    // -----------------------------------------

    let threat="LOW";
    let threatLevelClass="low";
    let threatReason =
        `Only ${accounts.length} account(s) linked to this identity. Low public exposure.`;

    if(accounts.length>20){
        threat="MEDIUM";
        threatLevelClass="medium";
        threatReason =
            `${accounts.length} accounts linked to this identity across multiple platforms. Moderate public exposure.`;
    }

    if(accounts.length>50){
        threat="HIGH";
        threatLevelClass="high";
        threatReason =
            `${accounts.length} accounts linked to this identity. High public exposure - this identity is easily traceable across the web.`;
    }

    if(githubFound){
        threatReason += " GitHub presence detected, increasing identifiable footprint.";
    }


    document.getElementById("risk")
    .innerText =
    threat;


    document.getElementById("threat")
    .innerText =
    threat;


    document.getElementById("threatValue")
    .innerText =
    threat;

    document.getElementById("threatReason")
    .innerText =
    threatReason;

    setThreatLevelClasses(threatLevelClass);




    // Social accounts + GitHub panels

    renderSocialResults(accounts);
    renderGithubResults(gitfive);
    renderHibpResults(results.hibp);




    // Summary


    document.getElementById("summary")
    .innerHTML =


    `
    <b>Target:</b>
    ${data.target}

    <br><br>

    <b>Accounts Found:</b>
    ${accounts.length}

    <br>

    <b>GitHub:</b>
    ${githubFound ? "Detected":"Not Found"}

    <br>

    <b>Threat Level:</b>
    ${threat}

    <br>

    <b>Confidence:</b>
    ${confidence}% (${escapeHtml(confidenceLevel)})

    <br><br>

    <b>Confidence Evidence:</b>
    <br>
    ${confidenceReasons.length
        ? confidenceReasons.map(reason => `✓ ${escapeHtml(reason)}`).join("<br>")
        : "No confidence explanation was returned."}

    <br><br>


    <b>Tools Used:</b>

    <br>

    Sherlock:
    ${summary.sherlock || 0}

    <br>

    Blackbird:
    ${summary.blackbird || 0}

    <br>

    Maigret:
    ${summary.maigret || 0}

    <br>

    GitFive:
    ${summary.gitfive || 0}

    <br>

    WhatsMyName:
    ${summary.whatsmyname || 0}

    `;


    // Real AI (Llama) summary, generated by ai_analyzer.py / ollama_ai.py
    renderAiSummary(results.ai_summary);


}




/* =====================================
   RENDER AI (LLAMA) SUMMARY
   Backend sends results.ai_summary as either:
     - a plain string like:
         "Risk Level: MEDIUM
          Reason: ...
          Recommendation: ..."
     - or, if generation failed: { error: "..." }
===================================== */

function renderAiSummary(aiSummaryRaw){

    const box = document.getElementById("aiSummary");
    const badge = document.getElementById("aiSummaryBadge");

    // Nothing came back at all
    if(aiSummaryRaw === undefined || aiSummaryRaw === null || aiSummaryRaw === ""){

        box.className = "ai-summary-box";
        box.innerText = "No AI summary was returned for this scan.";

        badge.className = "ai-risk-badge ai-risk-hidden";
        badge.innerText = "";

        return;
    }

    // Backend-reported failure (e.g. Ollama not running)
    if(typeof aiSummaryRaw === "object" && aiSummaryRaw.error){

        box.className = "ai-summary-error";
        box.innerHTML =
            `<i class="fa-solid fa-triangle-exclamation"></i>
            AI analysis failed: ${escapeHtml(aiSummaryRaw.error)}`;

        badge.className = "ai-risk-badge ai-risk-hidden";
        badge.innerText = "";

        return;
    }

    const text =
        typeof aiSummaryRaw === "string"
            ? aiSummaryRaw
            : JSON.stringify(aiSummaryRaw);

    // Try to pull structured "Risk Level / Reason / Recommendation"
    // fields out of the model's free-text response. The model is
    // asked to use these labels but LLM output can vary, so this
    // is tolerant of extra formatting (markdown bold, punctuation, etc).
    const riskMatch =
        text.match(/risk\s*level\**\s*:\s*\**\s*([A-Za-z]+)/i);

    const reasonMatch =
        text.match(/reason\**\s*:\s*\**\s*([\s\S]*?)(?:\n?\s*\**\s*recommendation\**\s*:|$)/i);

    const recommendationMatch =
        text.match(/recommendation\**\s*:\s*\**\s*([\s\S]*)/i);

    if(riskMatch){

        const riskWord = riskMatch[1].trim().toLowerCase();

        let riskClass = "risk-unknown";
        if(riskWord.startsWith("low")) riskClass = "risk-low";
        else if(riskWord.startsWith("med")) riskClass = "risk-medium";
        else if(riskWord.startsWith("high")) riskClass = "risk-high";

        badge.className = "ai-risk-badge " + riskClass;
        badge.innerText = riskWord.toUpperCase();

        const reason =
            reasonMatch ? reasonMatch[1].trim() : "";

        const recommendation =
            recommendationMatch ? recommendationMatch[1].trim() : "";

        box.className = "ai-summary-box";
        box.innerHTML = `
            <div class="ai-summary-row">
                <span class="label">Risk Level</span>
                <span class="value">${escapeHtml(riskMatch[1].trim())}</span>
            </div>
            ${reason ? `
            <div class="ai-summary-row">
                <span class="label">Reason</span>
                <span class="value">${escapeHtml(reason)}</span>
            </div>` : ""}
            ${recommendation ? `
            <div class="ai-summary-row">
                <span class="label">Recommendation</span>
                <span class="value">${escapeHtml(recommendation)}</span>
            </div>` : ""}
        `;

        return;
    }

    // Couldn't confidently parse structured fields - just show
    // the model's raw response so nothing is silently hidden.
    badge.className = "ai-risk-badge ai-risk-hidden";
    badge.innerText = "";

    box.className = "ai-summary-raw";
    box.innerText = text;

}




/* Small helper so AI/model output is never injected as raw HTML */
function escapeHtml(str){

    const div = document.createElement("div");
    div.innerText = str;
    return div.innerHTML;

}






/* =====================================
   DOWNLOAD JSON REPORT
===================================== */


function downloadJSON(){


    if(!latestResult){

        alert(
        "Run investigation first"
        );

        return;

    }



    const blob =
    new Blob(

        [
            JSON.stringify(
                latestResult,
                null,
                4
            )
        ],

        {
            type:"application/json"
        }

    );



    saveFile(
        blob,
        "ironclad_report.json"
    );


}






/* =====================================
   DOWNLOAD CSV
===================================== */


function downloadCSV(){



    if(!latestResult){

        alert(
        "Run investigation first"
        );

        return;

    }



    let csv =
    "Website,URL\n";



    const accounts =
    latestResult.results.accounts || [];



    accounts.forEach(acc=>{


        csv +=

        `${acc.website},${acc.url}\n`;


    });



    const blob =
    new Blob(

        [csv],

        {
            type:"text/csv"
        }

    );



    saveFile(
        blob,
        "ironclad_report.csv"
    );

}




/* =====================================
   DOWNLOAD PDF REPORT
   Generates a professional, branded PDF
   intelligence report from the latest
   scan result using jsPDF.
===================================== */

function downloadPDF(){

    if(!latestResult){
        alert("Run investigation first");
        return;
    }

    if(!window.jspdf){
        alert("PDF library failed to load. Check your internet connection and try again.");
        return;
    }

    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({ unit: "pt", format: "a4" });

    const pageWidth = doc.internal.pageSize.getWidth();
    const marginX = 40;
    let y = 50;

    const results = latestResult.results || {};
    const accounts = results.accounts || [];
    const gitfive = results.gitfive || {};
    const summary = results.summary || {};

    const githubFound = !!gitfive.github_found;

    const confidence = getConfidenceScore(results, accounts);
    const confidenceLevel = getConfidenceLevel(results, confidence);
    const confidenceReasons = getConfidenceReasons(results);

    let threat = "LOW";
    let threatColor = [0, 208, 132];      // green
    if(accounts.length > 20){ threat = "MEDIUM"; threatColor = [255, 176, 32]; }  // yellow
    if(accounts.length > 50){ threat = "HIGH"; threatColor = [255, 71, 87]; }     // red

    // ---- Header ----
    doc.setFillColor(11, 19, 32);
    doc.rect(0, 0, pageWidth, 70, "F");

    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(20);
    doc.text("IRONCLAD", marginX, 35);

    doc.setFont("helvetica", "normal");
    doc.setFontSize(11);
    doc.text("Cyber Intelligence Investigation Report", marginX, 52);

    doc.setFontSize(9);
    doc.text(new Date().toLocaleString(), pageWidth - marginX, 35, { align: "right" });

    y = 100;
    doc.setTextColor(20, 20, 20);

    // ---- Target Overview ----
    doc.setFont("helvetica", "bold");
    doc.setFontSize(13);
    doc.text("Target Overview", marginX, y);
    y += 20;

    doc.setFont("helvetica", "normal");
    doc.setFontSize(11);
    doc.text(`Target: ${latestResult.target || "-"}`, marginX, y); y += 16;
    doc.text(`Username: ${results.username || "-"}`, marginX, y); y += 16;
    doc.text(`Accounts Found: ${accounts.length}`, marginX, y); y += 16;
    doc.text(`GitHub Presence: ${githubFound ? "Detected" : "Not Found"}`, marginX, y); y += 16;
    doc.text(`Confidence Score: ${confidence}% (${confidenceLevel})`, marginX, y); y += 20;

    if(confidenceReasons.length){
        doc.setFontSize(9);
        confidenceReasons.slice(0, 5).forEach(reason => {
            const wrapped = doc.splitTextToSize(`- ${reason}`, pageWidth - (marginX * 2));
            doc.text(wrapped, marginX, y);
            y += (wrapped.length * 11) + 3;
        });
        doc.setFontSize(11);
        y += 8;
    }
    else{
        y += 10;
    }

    // ---- Threat Level Badge ----
    doc.setFont("helvetica", "bold");
    doc.setFontSize(13);
    doc.text("Threat Analysis", marginX, y);
    y += 12;

    doc.setFillColor(...threatColor);
    doc.roundedRect(marginX, y, 90, 26, 5, 5, "F");
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(12);
    doc.text(threat, marginX + 45, y + 17, { align: "center" });

    doc.setTextColor(20, 20, 20);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(10);
    doc.text(
        `Based on ${accounts.length} linked account(s) across public platforms.`,
        marginX + 100,
        y + 17
    );
    y += 45;

    // ---- Tools Used Summary ----
    doc.setFont("helvetica", "bold");
    doc.setFontSize(13);
    doc.text("Tools Used", marginX, y);
    y += 18;

    doc.setFont("helvetica", "normal");
    doc.setFontSize(10);
    const toolLines = [
        `Sherlock: ${summary.sherlock || 0}`,
        `Blackbird: ${summary.blackbird || 0}`,
        `Maigret: ${summary.maigret || 0}`,
        `GitFive: ${summary.gitfive || 0}`,
        `WhatsMyName: ${summary.whatsmyname || 0}`,
    ];
    toolLines.forEach(line => {
        doc.text(line, marginX, y);
        y += 14;
    });
    y += 16;

    // ---- Social Accounts Table ----
    doc.setFont("helvetica", "bold");
    doc.setFontSize(13);
    doc.text("Discovered Social Accounts", marginX, y);
    y += 18;

    doc.setFontSize(9);

    if(accounts.length === 0){
        doc.setFont("helvetica", "italic");
        doc.text("No accounts discovered for this target.", marginX, y);
        y += 16;
    }else{

        accounts.forEach(acc => {

            if(y > 780){
                doc.addPage();
                y = 50;
            }

            const site = acc.website || acc.site || "Unknown";
            const url = acc.url || "-";

            doc.setFont("helvetica", "bold");
            doc.text(String(site), marginX, y);

            doc.setFont("helvetica", "normal");
            doc.text(String(url), marginX + 130, y);

            y += 14;

        });

    }

    // ---- Footer ----
    const pageCount = doc.internal.getNumberOfPages();
    for(let i = 1; i <= pageCount; i++){
        doc.setPage(i);
        doc.setFontSize(8);
        doc.setTextColor(120, 120, 120);
        doc.text(
            `IRONCLAD Intelligence Report - Page ${i} of ${pageCount}`,
            marginX,
            820
        );
    }

    doc.save("ironclad_report.pdf");

}





function saveFile(blob,name){


    const link =
    document.createElement("a");



    link.href =
    URL.createObjectURL(blob);



    link.download =
    name;



    link.click();

}





/* =====================================
   SIDEBAR BUTTONS
===================================== */


function focusSearch(){

    document.getElementById("target")
    .focus();

}



function openReports(){

    downloadJSON();

}
