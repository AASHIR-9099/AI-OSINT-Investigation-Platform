const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");


async function main(){
    const scriptPath = path.join(__dirname, "..", "frontend", "script.js");
    const source = fs.readFileSync(scriptPath, "utf8").replace(
        "const EMAIL_HEADLINE_EVENT_MS = 400;",
        "const EMAIL_HEADLINE_EVENT_MS = 5;"
    );

    const elements = new Map();
    const headlineChanges = [];

    function element(id){
        if(!elements.has(id)){
            const value = {
                style: {},
                classList: {
                    add(){},
                    remove(){},
                    toggle(){}
                },
                innerHTML: "",
                textContent: "",
                value: "",
                parentElement: {
                    classList: {
                        add(){},
                        remove(){}
                    }
                }
            };

            let innerText = "";
            Object.defineProperty(value, "innerText", {
                get(){
                    return innerText;
                },
                set(newValue){
                    innerText = newValue;
                    if(id === "progressText"){
                        headlineChanges.push(newValue);
                    }
                }
            });

            elements.set(id, value);
        }

        return elements.get(id);
    }

    const descriptions = [
        "Starting OSINT Scan...",
        "Running: Holehe",
        "Running: GHunt",
        "Running: HIBP Email Breach Check",
        "Completed with limitations: Holehe",
        "Completed: GHunt",
        "Skipped: HIBP Email Breach Check (not configured)",
        "All OSINT tools completed",
        "Generating AI Risk Summary...",
        "Investigation completed"
    ];

    const job = {
        target: "person@example.com",
        percent: 100,
        description: "Investigation completed",
        done: true,
        results: {target: "person@example.com"},
        error: null,
        events: descriptions.map((description, index) => ({
            percent: index === descriptions.length - 1 ? 100 : 0,
            description
        }))
    };

    const context = {
        console,
        setInterval,
        clearInterval,
        setTimeout,
        clearTimeout,
        confirm: () => true,
        alert: () => {},
        localStorage: {
            getItem: () => JSON.stringify({pollInterval: 1}),
            setItem(){},
            removeItem(){}
        },
        document: {
            body: element("body"),
            getElementById: element,
            addEventListener(){}
        },
        window: {
            addEventListener(){}
        },
        fetch: async () => ({
            ok: true,
            json: async () => job
        })
    };

    vm.createContext(context);
    vm.runInContext(source, context);

    const result = await context.pollJobUntilDone("job-1", true);

    assert.deepStrictEqual(
        Array.from(headlineChanges),
        [
            "Starting OSINT Scan... (5%)",
            "Running: Holehe (15%)",
            "Running: GHunt (30%)",
            "Running: HIBP Email Breach Check (45%)",
            "Completed with limitations: Holehe (60%)",
            "Completed: GHunt (75%)",
            "Skipped: HIBP Email Breach Check (not configured) (85%)",
            "All OSINT tools completed (90%)",
            "Generating AI Risk Summary... (95%)",
            "Investigation completed (100%)"
        ]
    );

    const liveLog = element("loading").innerHTML;
    for(const description of descriptions){
        assert.ok(liveLog.includes(description));
    }

    assert.strictEqual(result.target, "person@example.com");
    assert.deepStrictEqual(
        JSON.parse(JSON.stringify(result.results)),
        {target: "person@example.com"}
    );
}


main().catch(error => {
    console.error(error);
    process.exitCode = 1;
});
