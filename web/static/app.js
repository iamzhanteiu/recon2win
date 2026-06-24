/* recon2win web UI — xterm.js terminal + form handler
 *
 * Boots an xterm.js terminal, wires the form to POST /api/run, and
 * streams the resulting scan's stdout via Server-Sent Events.
 */

(function () {
    "use strict";

    const $ = (id) => document.getElementById(id);

    // ------------------------------------------------------------------
    // Terminal setup
    // ------------------------------------------------------------------
    const term = new Terminal({
        fontFamily: 'ui-monospace, "SF Mono", Menlo, Consolas, monospace',
        fontSize: 13,
        lineHeight: 1.2,
        cursorBlink: true,
        convertEol: true,           // \n → \r\n
        scrollback: 5000,
        theme: {
            background: "#000000",
            foreground: "#d4d4d4",
            cursor: "#00d4ff",
            selectionBackground: "#264f78",
        },
    });
    const fit = new FitAddon.FitAddon();
    term.loadAddon(fit);
    term.open($("terminal"));
    fit.fit();
    window.addEventListener("resize", () => fit.fit());

    term.writeln("\x1b[1;36mrecon2win web UI\x1b[0m");
    term.writeln("Enter a target domain and click \x1b[1mRun scan\x1b[0m.");
    term.writeln("");

    // ------------------------------------------------------------------
    // Status bar
    // ------------------------------------------------------------------
    function setStatus(label, cls) {
        const el = $("status");
        el.textContent = label;
        el.className = cls || "";
    }

    function setMeta(text) {
        $("meta").textContent = text || "";
    }

    // ------------------------------------------------------------------
    // Form
    // ------------------------------------------------------------------
    const form = $("run-form");
    const runBtn = $("run-btn");
    const stopBtn = $("stop-btn");
    let activeSource = null;
    let activeScanId = null;

    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const domain = $("domain").value.trim();
        const argsRaw = $("args").value.trim();
        const args = argsRaw ? argsRaw.split(/\s+/).filter(Boolean) : [];
        const tty = $("tty").checked;
        if (tty) args.push("--color");   // force ANSI colors in the terminal

        if (!domain) return;
        if (activeSource) activeSource.close();

        term.clear();
        runBtn.disabled = true;
        stopBtn.disabled = false;
        setStatus("starting…", "running");
        setMeta("");

        try {
            const res = await fetch("/api/run", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ domain, args }),
            });
            const data = await res.json();
            if (!res.ok) {
                term.writeln(`\x1b[31merror: ${data.error || res.statusText}\x1b[0m`);
                finish("failed");
                return;
            }
            activeScanId = data.scan_id;
            setMeta(`scan ${activeScanId} · ${domain}`);
            setStatus("running", "running");
            attachStream(activeScanId);
        } catch (err) {
            term.writeln(`\x1b[31mnetwork error: ${err.message}\x1b[0m`);
            finish("failed");
        }
    });

    stopBtn.addEventListener("click", () => {
        // We don't have a server-side kill endpoint (intentional — would
        // leave half-written outputs). Closing the EventSource just
        // detaches the UI; the scan keeps running on the server.
        if (activeSource) activeSource.close();
        term.writeln("");
        term.writeln("\x1b[33m[detached from UI — server-side scan still running]\x1b[0m");
        setStatus("detached", "failed");
        runBtn.disabled = false;
        stopBtn.disabled = true;
    });

    function attachStream(scanId) {
        const src = new EventSource(`/api/stream/${scanId}`);
        activeSource = src;

        src.onmessage = (e) => {
            // xterm.js understands ANSI escape codes natively, so we
            // can write the raw line straight to the terminal.
            // The server un-escapes embedded \n so each event is one
            // physical line.
            term.write(e.data + "\r\n");
        };

        src.addEventListener("end", (e) => {
            const finalStatus = e.data || "done";
            term.writeln("");
            term.writeln(`\x1b[1m[scan ${finalStatus}]\x1b[0m`);
            finish(finalStatus);
            src.close();
        });

        src.onerror = () => {
            // EventSource auto-retries; only mark failed if the server
            // closed the connection without an `end` event.
            // We use readyState to detect that.
            if (src.readyState === EventSource.CLOSED) {
                term.writeln("");
                term.writeln("\x1b[31m[stream closed]\x1b[0m");
                finish("failed");
            }
        };
    }

    function finish(status) {
        activeSource = null;
        activeScanId = null;
        runBtn.disabled = false;
        stopBtn.disabled = true;
        const cls = status === "done" ? "done" : "failed";
        setStatus(status, cls);
    }
})();
