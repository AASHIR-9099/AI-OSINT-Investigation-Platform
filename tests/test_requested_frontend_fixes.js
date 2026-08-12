const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");


function htmlEscape(value){
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;");
}


function createDom(){
    const elements = new Map();

    function element(id){
        if(elements.has(id)) return elements.get(id);

        const classes = new Set();
        let innerText = "";
        let innerHTML = "";
        let textContent = "";
        const value = {
            id,
            value: "",
            style: {},
            className: "",
            focus(){},
            classList: {
                add(...names){ names.forEach(name => classes.add(name)); },
                remove(...names){ names.forEach(name => classes.delete(name)); },
                toggle(name, force){
                    if(force === undefined){
                        if(classes.has(name)) classes.delete(name);
                        else classes.add(name);
                    }
                    else if(force) classes.add(name);
                    else classes.delete(name);
                },
                contains(name){ return classes.has(name); }
            },
            parentElement: {
                classList: {
                    add(){},
                    remove(){}
                }
            }
        };

        Object.defineProperties(value, {
            innerText: {
                get(){ return innerText; },
                set(next){
                    innerText = String(next);
                    textContent = String(next);
                    innerHTML = htmlEscape(next);
                }
            },
            innerHTML: {
                get(){ return innerHTML; },
                set(next){ innerHTML = String(next); }
            },
            textContent: {
                get(){ return textContent; },
                set(next){
                    textContent = String(next);
                    innerText = String(next);
                    innerHTML = htmlEscape(next);
                }
            }
        });

        elements.set(id, value);
        return value;
    }

    return {
        element,
        document: {
            body: element("body"),
            getElementById: element,
            addEventListener(){},
            createElement(){
                const div = {};
                let encoded = "";
                Object.defineProperties(div, {
                    innerText: {
                        set(next){ encoded = htmlEscape(next); }
                    },
                    innerHTML: {
                        get(){ return encoded; }
                    }
                });
                return div;
            }
        }
    };
}


async function main(){
    const projectRoot = path.join(__dirname, "..");
    const scriptSource = fs.readFileSync(
        path.join(projectRoot, "frontend", "script.js"),
        "utf8"
    ).replace(
        "const HEADLINE_EVENT_MS = 400;",
        "const HEADLINE_EVENT_MS = 1;"
    );
    const enhancementSource = fs.readFileSync(
        path.join(projectRoot, "frontend", "dashboard_enhancements.js"),
        "utf8"
    );
    const enhancementCss = fs.readFileSync(
        path.join(projectRoot, "frontend", "dashboard_enhancements.css"),
        "utf8"
    );
    const pageSource = fs.readFileSync(
        path.join(projectRoot, "frontend", "index.html"),
        "utf8"
    );

    const {document, element} = createDom();
    const completedJob = {
        target: "person@example.com",
        percent: 100,
        description: "Investigation completed",
        done: true,
        error: null,
        events: [{percent: 100, description: "Investigation completed"}],
        results: {
            target: "person@example.com",
            username: null,
            accounts: [{
                platform: "Google",
                email: "person@example.com",
                url: "",
                source: "GHunt"
            }],
            confidence: 64,
            confidence_level: "High",
            confidence_reasons: ["GHunt confirmed the exact email."],
            gitfive: {github_found: false, accounts: []},
            ghunt: {google_services: []},
            hibp: {configured: false, skipped: true, reason: "Not configured"},
            summary: {holehe: 0, ghunt: 1, ghunt_services: 0, unique: 1},
            ai_summary: ""
        }
    };

    let activeTarget = completedJob.target;
    const context = {
        console,
        document,
        window: {addEventListener(){}},
        localStorage: {
            getItem: () => JSON.stringify({pollInterval: 1}),
            setItem(){},
            removeItem(){}
        },
        setInterval,
        clearInterval,
        setTimeout,
        clearTimeout,
        confirm: () => true,
        alert(){},
        fetch: async (url, options = {}) => {
            if(String(url).endsWith("/scan")){
                activeTarget = JSON.parse(options.body).target;
                return {ok: true, json: async () => ({job_id: "job-1"})};
            }
            return {
                ok: true,
                json: async () => ({
                    ...completedJob,
                    target: activeTarget,
                    results: {
                        ...completedJob.results,
                        target: activeTarget,
                        username: activeTarget.includes("@") ? null : activeTarget
                    }
                })
            };
        }
    };

    vm.createContext(context);
    vm.runInContext(scriptSource, context);
    vm.runInContext(enhancementSource, context);

    element("target").value = "person@example.com";
    const scan = context.scanTarget();

    assert.strictEqual(element("profileName").innerText, "person@example.com");
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

    await scan;

    assert.strictEqual(element("profileName").innerText, "person@example.com");
    assert.strictEqual(element("accounts").innerText, "1");
    assert.strictEqual(element("confidence").innerText, "64%");
    assert.strictEqual(element("risk").innerText, "LOW");
    assert.strictEqual(element("confidenceText").innerText, "64%");
    assert.strictEqual(element("threatValue").innerText, "LOW");
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

    element("target").value = "aashir_yt";
    const usernameScan = context.scanTarget();
    assert.strictEqual(element("profileName").innerText, "aashir_yt");
    await usernameScan;
    assert.strictEqual(element("profileName").innerText, "aashir_yt");

    context.renderSocialResults([
        {
            platform: "Spotify",
            email: "person@example.com",
            url: "",
            source: "Holehe"
        },
        {
            platform: "Instagram",
            username: "real_user",
            url: "https://instagram.com/real_user",
            source: "GHunt"
        },
        {platform: "", url: "#"},
        {website: null, platform: "undefined", url: null}
    ]);

    const socialHtml = element("socialResults").innerHTML;
    assert.ok(socialHtml.includes("Spotify"));
    assert.ok(socialHtml.includes("Account Exists"));
    assert.ok(socialHtml.includes("Source: Holehe"));
    assert.ok(socialHtml.includes("https://instagram.com/real_user"));
    assert.ok(!socialHtml.includes("Unknown Platform"));
    assert.ok(!socialHtml.includes('href="#"'));
    assert.ok(!socialHtml.includes(">null<"));
    assert.ok(!socialHtml.includes(">undefined<"));

    context.renderSocialResults([{platform: "", url: "#"}]);
    assert.strictEqual(
        element("socialResults").innerText,
        "No social accounts were discovered."
    );

    assert.ok(enhancementCss.includes("animation:status-processing-pulse"));
    assert.strictEqual((pageSource.match(/id="profileName"/g) || []).length, 1);
    assert.strictEqual((pageSource.match(/id="username"/g) || []).length, 0);

    const frontendText = [scriptSource, enhancementSource, pageSource].join("\n");
    assert.ok(!frontendText.includes("Social Analyzer"));
    assert.ok(!frontendText.includes("TheHarvester"));
}


main().catch(error => {
    console.error(error);
    process.exitCode = 1;
});
