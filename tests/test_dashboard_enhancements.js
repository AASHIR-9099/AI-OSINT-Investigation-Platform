const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");


async function main(){
    const source = fs.readFileSync(
        path.join(__dirname, "..", "frontend", "dashboard_enhancements.js"),
        "utf8"
    );
    const elements = new Map();

    function element(id){
        if(!elements.has(id)){
            const classes = new Set();
            elements.set(id, {
                value: "",
                innerText: "",
                innerHTML: "",
                className: "",
                classList: {
                    add(name){ classes.add(name); },
                    remove(name){ classes.delete(name); },
                    toggle(name, force){
                        if(force) classes.add(name);
                        else classes.delete(name);
                    },
                    contains(name){ return classes.has(name); }
                }
            });
        }
        return elements.get(id);
    }

    let finishScan;
    const context = {
        console,
        document: {getElementById: element},
        escapeHtml(value){
            return String(value)
                .replaceAll("&", "&amp;")
                .replaceAll("<", "&lt;")
                .replaceAll(">", "&gt;");
        },
        renderAiSummary(){},
        updateDashboard(){
            element("github").innerText = "NONE";
            element("threat").innerText = "LOW";
            element("confidence").innerText = "40%";
        },
        scanTarget(){
            return new Promise(resolve => { finishScan = resolve; });
        }
    };

    vm.createContext(context);
    vm.runInContext(source, context);

    element("target").value = "person@example.com";
    const running = context.scanTarget();

    for(const id of ["accounts", "github", "confidence", "threat"]){
        assert.strictEqual(element(id).innerText, "Processing...");
        assert.ok(element(id).classList.contains("processing-value"));
    }
    for(const id of ["risk", "confidenceText", "threatValue"]){
        assert.strictEqual(element(id).innerText, "Processing...");
        assert.ok(element(id).classList.contains("processing-value"));
    }
    assert.strictEqual(
        element("threatReason").innerText,
        "Processing investigation results..."
    );
    assert.ok(element("investigationSpinner").classList.contains("is-spinning"));

    finishScan();
    await running;
    assert.ok(!element("investigationSpinner").classList.contains("is-spinning"));

    context.updateDashboard({
        target: "person@example.com",
        results: {
            accounts: [{platform: "Google"}],
            ghunt: {google_services: ["Maps", "Photos", "Maps"]},
            summary: {
                sherlock: 2,
                blackbird: 1,
                maigret: 3,
                whatsmyname: 4,
                social_analyzer: 5,
                gitfive: 1,
                holehe: 6,
                ghunt: 1,
                ghunt_services: 2
            }
        }
    });

    const overview = element("summary").innerHTML;
    for(const label of (
        ["Username Intelligence", "Sherlock", "Blackbird", "Maigret",
         "WhatsMyName", "GitFive", "Email Intelligence",
         "Holehe — Accounts Found", "GHunt — Google Account Found",
         "GHunt — Services Found"]
    )){
        assert.ok(overview.includes(label));
    }
    assert.ok(overview.includes("GHunt — Services Found</span><span>2"));
    assert.ok(!overview.includes("Social Analyzer"));
    assert.ok(!overview.includes("TheHarvester"));

    for(const id of [
        "accounts",
        "github",
        "confidence",
        "threat",
        "risk",
        "confidenceText",
        "threatValue"
    ]){
        assert.ok(!element(id).classList.contains("processing-value"));
    }

    context.renderAiSummary(`
Investigation Overview
Scope summary.
Important Findings
- One finding.
Account and Platform Information
- Google account.
Risk Indicators
- One exposure.
Confidence Explanation
Verification supports confidence.
Threat Assessment
Risk Level: Medium
Assessment: Evidence-based rating.
Conclusion
Professional conclusion.
    `);

    const aiHtml = element("aiSummary").innerHTML;
    assert.ok(aiHtml.includes("Investigation Overview"));
    assert.ok(aiHtml.includes("Confidence Explanation"));
    assert.ok(aiHtml.includes("Conclusion"));
    assert.strictEqual(element("aiSummaryBadge").innerText, "MEDIUM");
}


main().catch(error => {
    console.error(error);
    process.exitCode = 1;
});
