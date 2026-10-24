const API_BASE = "/api";

const state = {
    history: [],
    activeTab: "file",
    view: "overview"
};

const $ = id => document.getElementById(id);


// Display notification messages
function toast(message) {
    const node = $("toast");

    node.textContent = message;
    node.classList.add("show");

    clearTimeout(toast.timer);

    toast.timer = setTimeout(() => {
        node.classList.remove("show");
    }, 3500);
}


// Escape HTML before displaying server-provided values
function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, character => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[character]);
}


// Navigation
function switchView(view) {
    state.view = view;

    document.querySelectorAll(".view").forEach(section => {
        section.classList.add("hidden");
    });

    $(`${view}-view`).classList.remove("hidden");

    document.querySelectorAll(".nav-item").forEach(button => {
        button.classList.toggle(
            "active",
            button.dataset.view === view
        );
    });

    const titles = {
        overview: "Overview",
        scanner: "Threat Scanner",
        history: "Scan History"
    };

    $("page-title").textContent = titles[view] || "Overview";

    if (view === "history") {
        renderHistory();
    }
}


// Switch between File, URL and Search tabs
function setTab(tab) {
    state.activeTab = tab;

    document.querySelectorAll(".scan-tab").forEach(button => {
        button.classList.toggle(
            "active",
            button.dataset.tab === tab
        );
    });

    ["file", "url", "search"].forEach(name => {
        const quickForm = $(`quick-${name}`);
        const wideForm = $(`wide-${name}`);

        if (quickForm) {
            quickForm.classList.toggle("hidden", name !== tab);
        }

        if (wideForm) {
            wideForm.classList.toggle("hidden", name !== tab);
        }
    });

    $("result-area").classList.add("hidden");
}


// Format dates
function formatDate(date) {
    return new Intl.DateTimeFormat(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit"
    }).format(new Date(date));
}


// Determine displayed status
function verdict(item) {
    if (item.error) {
        return { label: "Error", cls: "error" };
    }

    if (item.status === "pending") {
        return { label: "Pending", cls: "pending" };
    }

    if (item.malicious > 0 || item.suspicious > 0) {
        return { label: "Flagged", cls: "flagged" };
    }

    if (item.status === "complete") {
        return { label: "No detections", cls: "clean" };
    }

    return { label: "Submitted", cls: "pending" };
}


// Add a scan to browser-session history
function addHistory(item) {
    state.history.unshift({
        ...item,
        timestamp: new Date().toISOString()
    });

    state.history = state.history.slice(0, 50);

    renderMetrics();
    renderRecent();

    if (state.view === "history") {
        renderHistory();
    }
}


// Update dashboard metrics
function renderMetrics() {
    $("metric-total").textContent = state.history.length;

    $("metric-clean").textContent =
        state.history.filter(item =>
            !item.error &&
            item.status === "complete" &&
            item.malicious === 0 &&
            item.suspicious === 0
        ).length;

    $("metric-flagged").textContent =
        state.history.filter(item =>
            !item.error &&
            (item.malicious > 0 || item.suspicious > 0)
        ).length;

    $("metric-pending").textContent =
        state.history.filter(item =>
            item.error ||
            item.status === "pending" ||
            item.status !== "complete"
        ).length;
}


// Build a history row
function activityMarkup(item) {
    const status = verdict(item);

    const icon = {
        file: "▤",
        url: "↗",
        search: "⌕"
    }[item.kind] || "•";

    const name =
        item.name ||
        item.query ||
        item.url ||
        "Scan";

    const detectionText =
        item.malicious != null
            ? ` · ${item.malicious} malicious`
            : "";

    return `
        <div class="activity-item">

            <div class="activity-symbol">
                ${icon}
            </div>

            <div class="activity-meta">

                <b title="${escapeHtml(name)}">
                    ${escapeHtml(name)}
                </b>

                <small>
                    ${escapeHtml(item.kind.toUpperCase())}
                    · ${escapeHtml(formatDate(item.timestamp))}
                    ${detectionText}
                </small>

            </div>

            <span class="badge ${status.cls}">
                ${status.label}
            </span>

        </div>
    `;
}


// Render recent scans
function renderRecent() {
    const items = state.history.slice(0, 5);

    $("recent-list").innerHTML = items.length
        ? items.map(activityMarkup).join("")
        : `
            <div class="empty-state">
                No scans yet. Start by scanning a file or URL.
            </div>
        `;
}


// Render complete session history
function renderHistory() {
    $("history-list").innerHTML = state.history.length
        ? state.history.map(activityMarkup).join("")
        : `
            <div class="empty-state">
                No scan history available.
            </div>
        `;
}


// Send API request to backend
async function requestJson(path, options = {}) {
    const response = await fetch(`${API_BASE}${path}`, options);

    const payload = await response.json().catch(() => ({}));

    if (!response.ok) {
        throw new Error(
            payload.error ||
            `Server returned HTTP ${response.status}`
        );
    }

    return payload;
}


// Display VirusTotal analysis statistics
function renderResult(data, kind, label) {
    const attributes =
        data?.data?.attributes ||
        data?.attributes ||
        {};

    const stats = attributes.last_analysis_stats || {};

    const malicious = Number(stats.malicious || 0);
    const suspicious = Number(stats.suspicious || 0);
    const harmless = Number(stats.harmless || 0);
    const undetected = Number(stats.undetected || 0);

    const total =
        malicious +
        suspicious +
        harmless +
        undetected;

    const analysisId = data?.data?.id || "";

    const resultType =
        kind === "file" ? "file" :
        kind === "url" ? "url" :
        "search";

    const analysisUrl = analysisId
        ? `https://www.virustotal.com/gui/${resultType}/${encodeURIComponent(analysisId)}`
        : "";

    const hasStats =
        Object.keys(stats).length > 0;

    const status = hasStats ? "complete" : "pending";

    addHistory({
        kind,
        name: label,
        query: kind === "search" ? label : undefined,
        url: kind === "url" ? label : undefined,
        status,
        malicious,
        suspicious,
        harmless,
        undetected,
        analysisId,
        analysisUrl
    });

    $("result-area").classList.remove("hidden");

    $("result-area").innerHTML = `
        <div class="result-summary">

            <div>
                <p class="eyebrow">ANALYSIS RESULT</p>

                <h3>${escapeHtml(label)}</h3>

                <p>
                    ${
                        hasStats
                        ? "Analysis statistics returned by VirusTotal."
                        : "Submission received. The completed report may not be available yet."
                    }
                </p>
            </div>

            <div class="result-count">
                ${total ? `${malicious + suspicious}/${total}` : "Pending"}

                <small>malicious / engines</small>
            </div>

        </div>

        <div class="result-stats">

            <div class="result-stat">
                <b style="color:var(--red)">
                    ${malicious}
                </b>
                <small>Malicious</small>
            </div>

            <div class="result-stat">
                <b style="color:var(--amber)">
                    ${suspicious}
                </b>
                <small>Suspicious</small>
            </div>

            <div class="result-stat">
                <b style="color:var(--green)">
                    ${harmless}
                </b>
                <small>Harmless</small>
            </div>

            <div class="result-stat">
                <b>${undetected}</b>
                <small>Undetected</small>
            </div>

        </div>

        <div class="result-details">

            ${
                analysisId
                ? `Analysis ID: <code>${escapeHtml(analysisId)}</code><br>`
                : ""
            }

            ${
                analysisUrl
                ? `<a href="${analysisUrl}" target="_blank" rel="noopener noreferrer">
                    Open in VirusTotal ↗
                   </a>`
                : ""
            }

            <br>

            <small>
                Detection counts are third-party results and do not
                guarantee that a file or URL is safe.
            </small>

        </div>
    `;

    $("result-area").scrollIntoView({
        behavior: "smooth",
        block: "nearest"
    });
}


// Display request errors
function showApiError(error, kind, label) {
    const message = error.message || "Request failed.";

    addHistory({
        kind,
        name: label,
        status: "error",
        error: message,
        malicious: 0,
        suspicious: 0
    });

    $("result-area").classList.remove("hidden");

    $("result-area").innerHTML = `
        <div class="result-summary">

            <div>
                <p class="eyebrow">REQUEST FAILED</p>
                <h3>${escapeHtml(label)}</h3>

                <p class="result-details">
                    ${escapeHtml(message)}
                </p>
            </div>

            <span class="badge error">Error</span>

        </div>

        <p>
            Check the backend server, API key and
            your VirusTotal API permissions.
        </p>
    `;

    toast(message);
}


// Submit a file to VirusTotal
async function scanFile(file) {
    if (!file) {
        toast("Please select a file first.");
        return;
    }

    const MAX_SIZE = 32 * 1024 * 1024;

    if (file.size > MAX_SIZE) {
        toast("The demo supports files up to 32 MB.");
        return;
    }

    const label = file.name;

    const formData = new FormData();
    formData.append("file", file);

    toast("Uploading file for analysis...");

    try {
        const data = await requestJson("/scan/file", {
            method: "POST",
            body: formData
        });

        renderResult(data, "file", label);

        toast("File submitted to VirusTotal.");

    } catch (error) {
        showApiError(error, "file", label);
    }
}


// Submit a URL to VirusTotal
async function scanUrl(value) {
    const url = value.trim();

    if (!url) {
        toast("Enter a URL first.");
        return;
    }

    try {
        toast("Submitting URL...");

        const data = await requestJson("/scan/url", {
            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({ url })
        });

        renderResult(data, "url", url);

        toast("URL submitted to VirusTotal.");

    } catch (error) {
        showApiError(error, "url", url);
    }
}


// Search VirusTotal Intelligence
async function searchQuery(value) {
    const query = value.trim();

    if (!query) {
        toast("Enter a search query first.");
        return;
    }

    try {
        toast("Searching VirusTotal...");

        const data = await requestJson(
            `/search?q=${encodeURIComponent(query)}`
        );

        const items = data.data || [];

        addHistory({
            kind: "search",
            name: `${query} (${items.length} results)`,
            query,
            status: "complete",
            malicious: 0,
            suspicious: 0
        });

        $("result-area").classList.remove("hidden");

        const resultHtml = items.slice(0, 20).map(item => {
            const attributes = item.attributes || {};
            const id = item.id || "";
            const type = item.type || "file";

            const name =
                attributes.meaningful_name ||
                attributes.name ||
                id;

            return `
                <div class="activity-item">

                    <div class="activity-symbol">⌕</div>

                    <div class="activity-meta">

                        <b>${escapeHtml(name)}</b>

                        <small>
                            ${escapeHtml(type)} · ${escapeHtml(id)}
                        </small>

                    </div>

                    <a
                        href="https://www.virustotal.com/gui/${encodeURIComponent(type)}/${encodeURIComponent(id)}"
                        target="_blank"
                        rel="noopener noreferrer"
                    >
                        Open ↗
                    </a>

                </div>
            `;
        }).join("");

        $("result-area").innerHTML = `
            <div class="result-summary">

                <div>
                    <p class="eyebrow">SEARCH RESULTS</p>

                    <h3>${escapeHtml(query)}</h3>

                    <p>
                        ${items.length} result(s) returned.
                    </p>
                </div>

                <div class="result-count">
                    ${items.length}
                    <small>results</small>
                </div>

            </div>

            <div class="result-details">
                ${
                    resultHtml ||
                    '<div class="empty-state">No results found.</div>'
                }
            </div>
        `;

    } catch (error) {
        showApiError(error, "search", query);
    }
}


// Check backend health
async function checkHealth() {
    try {
        const data = await requestJson("/health");

        $("service-status").textContent =
            data.apiKeyConfigured
            ? "Online · API key configured"
            : "Online · API key missing";

    } catch {
        $("service-status").textContent =
            "Backend unavailable";
    }
}


// Navigation buttons
document.querySelectorAll("[data-view]").forEach(button => {
    button.addEventListener("click", () => {
        switchView(button.dataset.view);
    });
});

document.querySelectorAll("[data-open-scanner]").forEach(button => {
    button.addEventListener("click", () => {
        switchView("scanner");
    });
});


// Tab buttons
document.querySelectorAll(".scan-tab").forEach(button => {
    button.addEventListener("click", () => {
        setTab(button.dataset.tab);
    });
});


// File selection labels
$("file-input").addEventListener("change", event => {
    $("file-name").textContent =
        event.target.files[0]?.name || "No file selected";
});

$("wide-file-input").addEventListener("change", event => {
    $("wide-file-name").textContent =
        event.target.files[0]?.name || "No file selected";
});


// File scan buttons
$("file-scan-btn").addEventListener("click", () => {
    scanFile($("file-input").files[0]);
});

$("wide-file-scan-btn").addEventListener("click", () => {
    scanFile($("wide-file-input").files[0]);
});


// URL forms
$("quick-url").addEventListener("submit", event => {
    event.preventDefault();
    scanUrl($("url-input").value);
});

$("wide-url").addEventListener("submit", event => {
    event.preventDefault();
    scanUrl($("wide-url-input").value);
});


// Search forms
$("quick-search").addEventListener("submit", event => {
    event.preventDefault();
    searchQuery($("search-input").value);
});

$("wide-search").addEventListener("submit", event => {
    event.preventDefault();
    searchQuery($("wide-search-input").value);
});


// Clear history
$("clear-history").addEventListener("click", () => {
    state.history = [];

    renderMetrics();
    renderRecent();
    renderHistory();

    toast("Scan history cleared.");
});


// Initialise dashboard
setTab("file");
renderMetrics();
renderRecent();
checkHealth();
