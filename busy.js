/**
 * Security Toolkit - busy states
 *
 * API calls take seconds and used to look like "nothing happened", which made
 * people click again. Busy.run() gives immediate feedback and blocks repeats:
 *   - the button is disabled, shows a spinner and a working label
 *   - a progress bar runs along the top of the page while anything is busy
 *   - screen readers hear what is happening (polite live region)
 *   - a second click while busy is ignored
 *
 * Usage:
 *   button.addEventListener("click", () =>
 *       Busy.run(button, "Testing...", async () => { await doTheWork(); }));
 */
const Busy = (() => {
    let active = 0;
    const MIN_VISIBLE_MS = 500; // a very fast call still shows its cue, so it never looks like nothing happened

    function liveRegion() {
        let r = document.getElementById("busy-live");
        if (!r) {
            r = document.createElement("div");
            r.id = "busy-live";
            r.className = "sr-only";
            r.setAttribute("role", "status");
            r.setAttribute("aria-live", "polite");
            document.body.append(r);
        }
        return r;
    }

    function ensureBar() {
        if (!document.querySelector(".busybar")) {
            const bar = document.createElement("div");
            bar.className = "busybar";
            bar.setAttribute("aria-hidden", "true");
            document.body.prepend(bar);
        }
    }

    /** Manually mark work as started/finished (for work that is not a single button) */
    function begin(message) {
        ensureBar();
        active += 1;
        document.body.classList.add("is-working");
        if (message) liveRegion().textContent = message;
    }

    function end(message) {
        active = Math.max(0, active - 1);
        if (active === 0) document.body.classList.remove("is-working");
        if (message) liveRegion().textContent = message;
    }

    /**
     * Run an async function while showing a busy state on a button.
     * @param {HTMLButtonElement} button
     * @param {string} label - text shown while working, e.g. "Testing..."
     * @param {() => Promise<any>} fn
     * @param {{lock?: HTMLElement[]}} [options] - other controls to disable meanwhile
     */
    async function run(button, label, fn, options = {}) {
        if (button.getAttribute("aria-busy") === "true") return undefined; // ignore repeat clicks

        const original = [...button.childNodes];
        const wasDisabled = button.disabled;
        const locked = (options.lock || []).map((el) => [el, el.disabled]);

        button.setAttribute("aria-busy", "true");
        button.classList.add("is-busy");
        button.disabled = true;
        const spinner = document.createElement("span");
        spinner.className = "spinner";
        spinner.setAttribute("aria-hidden", "true");
        button.replaceChildren(spinner, document.createTextNode(label));
        locked.forEach(([el]) => {
            el.disabled = true;
        });
        begin(label);

        const started = Date.now();
        try {
            return await fn();
        } finally {
            const wait = MIN_VISIBLE_MS - (Date.now() - started);
            if (wait > 0) await new Promise((r) => setTimeout(r, wait));
            button.replaceChildren(...original);
            button.classList.remove("is-busy");
            button.removeAttribute("aria-busy");
            button.disabled = wasDisabled;
            locked.forEach(([el, was]) => {
                el.disabled = was;
            });
            end("Finished");
        }
    }

    return { run, begin, end };
})();
