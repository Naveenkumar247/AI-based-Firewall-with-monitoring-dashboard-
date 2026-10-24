const API_BASE = "/api";

const state = {
    history: [],
    activeTab: "file",
    view: "overview"
};

const $ = id => document.getElementById(id);


// --------------------------------------------------
// Notifications
// --------------------------------------------------

function toast(message) {
    const node = $("toast");

    if (!node) {
        console.log(message);
        return;
    }

    node.textContent = message;
    node.classList.add("show");

    clearTimeout(toast.timer);

    toast.timer = setTimeout(() => {
        node.classList.remove("show");
    }, 4000);
}


// --------------------------------------------------
// Safe HTML output
// --------------------------------------------------

function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, character => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[character]);
}


// --------------------------------------------------
// Navigation
// --------------------------------------------------

function switchView(view) {
    const target = $(`${view}-view`);

    if (!target) {
        return;
    }

    state.view = view;

    document.querySelectorAll(".view").forEach(section => {
        section.classList.add("hidden");
    });

    target.classList.remove("hidden");

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


// --------------------------------------------------
// Scanner tabs
// --------------------------------------------------

function setTab(tab) {
    state.activeTab = tab;

    document.querySelectorAll(".scan-tab").forEach(button => {
        button.classList.toggle(
            "active",
            button.dataset.tab === tab
        );
    });

    ["file", "url", "search"].forEach(name => {
        const quick = $(`quick-${name}`);
        const wide = $(`wide-${name}`);

        if (quick) {
            quick.classList.toggle("hidden", name !== tab);
        }

        if (wide) {
            wide.classList.toggle("hidden", name !== tab);
        }
    });

    $("result-area")?.classList.add("hidden");
}


// --------------------------------------------------
// Date formatting
// --------------------------------------------------

function formatDate(date) {
    return new Intl.DateTimeFormat(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit"
    }).format(new Date(date));
}


// --------------------------------------------------
// Verdict classification
// --------------------------------------------------

function verdict(item) {
    if (item.error) {
        return {
            label: "Error",
            cls: "error"
        };
    }

    if (item.status === "pending") {
        return {
            label: "Pending",
            cls: "pending"
        };
    }

    if (item.malicious > 0) {
        return {
            label: "Malicious",
            cls: "flagged"
        };
    }

    if (item.suspicious > 0) {
        return {
            label: "Suspicious",
            cls: "flagged"
        };
    }

    if (item.status === "complete") {
        return {
            label: "No detections",
            cls: "clean"
        };
    }

    return {
        label: "Submitted",
        cls: "pending"
    };
}


// --------------------------------------------------
// Scan history
// --------------------------------------------------

function addHistory(item) {
    const existing = state.history.findIndex(
        entry => entry.id && entry.id === item.id
    );

    const updated = {
        ...item,
        timestamp:
            item.timestamp || new Date().toISOString()
    };

    if (existing >= 0) {
        state.history[existing] = {
            ...state.history[existing],
            ...updated
        };
    } else {
        state.history.unshift(updated);
    }

    state.history = state.history.slice(0, 50);

    renderMetrics();
    renderRecent();

    if (state.view === "history") {
        renderHistory();
    }
}


// --------------------------------------------------
// Dashboard statistics
// --------------------------------------------------

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
            (
                item.malicious > 0 ||
                item.suspicious > 0
            )
        ).length;

    $("metric-pending").textContent =
        state.history.filter(item =>
            item.error ||
            item.status === "pending" ||
            item.status === "error"
        ).length;
}


// --------------------------------------------------
// Activity rows
// --------------------------------------------------

function activityMarkup(item) {
    const status = verdict(item);

    const icons = {
        file: "▤",
        url: "↗",
        search: "⌕"
    };

    const name =
        item.name ||
        item.query ||
        item.url ||
        "Scan";

    return `
        <div class="activity-item">

            <div class="activity-symbol">
                ${icons[item.kind] || "•"}
            </div>

            <div class="activity-meta">

                <b title="${escapeHtml(name)}">
                    ${escapeHtml(name)}
                </b>

                <small>
                    ${escapeHtml((item.kind || "scan").toUpperCase())}
                    · ${escapeHtml(formatDate(item.timestamp))}
                    ${
                        item.malicious !== undefined
                        ? ` · ${item.malicious} malicious`
                        : ""
                    }
                </small>

            </div>

            <span class="badge ${status.cls}">
                ${status.label}
            </span>

        </div>
    `;
}


// --------------------------------------------------
// Render history lists
// --------------------------------------------------

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


function renderHistory() {
    $("history-list").innerHTML = state.history.length
        ? state.history.map(activityMarkup).join("")
        : `
            <div class="empty-state">
                No scan history available.
            </div>
        `;
}


// --------------------------------------------------
// API request helper
// --------------------------------------------------

async function requestJson(path, options = {}) {
    const response = await fetch(`${API_BASE}${path}`, {
        ...options,
        headers: {
            ...(options.headers || {})
        }
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
        throw new Error(
            data.error ||
            `Request failed with HTTP ${response.status}`
        );
    }

    return data;
}


// --------------------------------------------------
// Extract VirusTotal analysis information
// --------------------------------------------------

function extractAnalysis(data) {
    const attributes =
        data?.data?.attributes ||
        data?.attributes ||
        {};

    const stats =
        attributes.stats ||
        attributes.last_analysis_stats ||
        {};

    return {
        status: attributes.status || "queued",

        malicious: Number(stats.malicious || 0),

        suspicious: Number(stats.suspicious || 0),

        harmless: Number(stats.harmless || 0),

        undetected: Number(stats.undetected || 0),

        stats
    };
}


// --------------------------------------------------
// Wait for VirusTotal analysis completion
// --------------------------------------------------

async function pollAnalysis(analysisId, kind, label, historyId) {
    const maxAttempts = 12;
    const delayMs = 5000;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
        await new Promise(resolve => setTimeout(resolve, delayMs));

        let analysis;

        try {
            analysis = await requestJson(
                `/analysis/${encodeURIComponent(analysisId)}`
            );
        } catch (error) {
            // A temporary failure should not erase the submission.
            if (attempt === maxAttempts - 1) {
                throw error;
            }

            continue;
        }

        const result = extractAnalysis(analysis);

        if (result.status === "completed") {
            return result;
        }

        updatePendingHistory(historyId, {
            status: "pending",
            name: label,
            kind,
            analysisId
        });
    }

    // The analysis may still be processing. The report endpoints
    // can sometimes provide an already-existing report.
    return await tryExistingReport(kind, label, historyId, analysisId);
}


// --------------------------------------------------
// Try retrieving an existing report
// --------------------------------------------------

async function tryExistingReport(kind, label, historyId, analysisId) {
    const entry = state.history.find(
        item => item.id === historyId
    );

    if (kind === "file" && entry?.sha256) {
        try {
            const report = await requestJson(
                `/report/file/${encodeURIComponent(entry.sha256)}`
            );

            return extractAnalysis(report);
        } catch {
            // Keep the original pending status if no report is available.
        }
    }

    if (kind === "url" && entry?.urlId) {
        try {
            const report = await requestJson(
                `/report/url/${encodeURIComponent(entry.urlId)}`
            );

            return extractAnalysis(report);
        } catch {
            // The report may not be available yet.
        }
    }

    updatePendingHistory(historyId, {
        status: "pending",
        kind,
        name: label,
        analysisId
    });

    return null;
}


// --------------------------------------------------
// Update an existing pending record
// --------------------------------------------------

function updatePendingHistory(id, values) {
    const entry = state.history.find(item => item.id === id);

    if (!entry) {
        return;
    }

    Object.assign(entry, values);

    renderMetrics();
    renderRecent();

    if (state.view === "history") {
        renderHistory();
    }
}


// --------------------------------------------------
// Get the final file or URL report
// --------------------------------------------------

async function fetchFinalReport(kind, submission, label, historyId) {
    const analysisId = submission?.data?.id;

    if (!analysisId) {
        throw new Error(
            "VirusTotal did not return an analysis ID."
        );
    }

    const initialAttributes =
        submission?.data?.attributes || {};

    const sha256 =
        initialAttributes.sha256 ||
        "";

    const urlId =
        kind === "url"
            ? initialAttributes.url_id || ""
            : "";

    updatePendingHistory(historyId, {
        analysisId,
        sha256,
        urlId
    });

    const analysis = await pollAnalysis(
        analysisId,
        kind,
        label,
        historyId
    );

    // If the analysis is still pending, do not display zeros
    // as if they were a completed security verdict.
    if (!analysis) {
        renderPendingResult(label, analysisId, historyId);
        return;
    }

    // A completed analysis may contain stats directly.
    // Fetch the object report for additional file/URL metadata.
    let report = null;

    const entry = state.history.find(
        item => item.id === historyId
    );

    if (kind === "file" && entry?.sha256) {
        try {
            report = await requestJson(
                `/report/file/${encodeURIComponent(entry.sha256)}`
            );
        } catch {
            // Use completed analysis statistics if available.
        }
    }

    if (kind === "url" && entry?.urlId) {
        try {
            report = await requestJson(
                `/report/url/${encodeURIComponent(entry.urlId)}`
            );
        } catch {
            // Use completed analysis statistics if available.
        }
    }

    const finalData = report || submission;

    const finalStats = report
        ? extractAnalysis(finalData)
        : analysis;

    renderCompletedResult(
        finalData,
        finalStats,
        kind,
        label,
        analysisId,
        historyId
    );
}


// --------------------------------------------------
// Render pending analysis
// --------------------------------------------------

function renderPendingResult(label, analysisId, historyId) {
    updatePendingHistory(historyId, {
        status: "pending",
        malicious: undefined,
        suspicious: undefined,
        harmless: undefined,
        undetected: undefined,
        analysisId
    });

    const resultArea = $("result-area");

    resultArea.classList.remove("hidden");

    resultArea.innerHTML = `
        <div class="result-summary">

            <div>
                <p class="eyebrow">ANALYSIS IN PROGRESS</p>

                <h3>${escapeHtml(label)}</h3>

                <p>
                    VirusTotal has not completed this analysis yet.
                    No final verdict is available.
                </p>
            </div>

            <span class="badge pending">Pending</span>

        </div>

        <p class="result-details">
            Analysis ID:
            <code>${escapeHtml(analysisId)}</code>
        </p>

        <p class="result-details">
            You can check the result directly on VirusTotal.
        </p>

        <a
            href="https://www.virustotal.com/gui/analyses/${encodeURIComponent(analysisId)}"
            target="_blank"
            rel="noopener noreferrer"
        >
            Open analysis in VirusTotal ↗
        </a>
    `;
}


// --------------------------------------------------
// Render completed results
// --------------------------------------------------

function renderCompletedResult(
    data,
    stats,
    kind,
    label,
    analysisId,
    historyId
) {
    const attributes =
        data?.data?.attributes ||
        data?.attributes ||
        {};

    const malicious = Number(stats.malicious || 0);
    const suspicious = Number(stats.suspicious || 0);
    const harmless = Number(stats.harmless || 0);
    const undetected = Number(stats.undetected || 0);

    const total =
        malicious +
        suspicious +
        harmless +
        undetected;

    const sha256 =
        attributes.sha256 ||
        state.history.find(item => item.id === historyId)?.sha256 ||
        "";

    const resultId =
        data?.data?.id ||
        analysisId;

    const guiType =
        kind === "file"
            ? "file"
            : "url";

    const guiUrl =
        kind === "url" && resultId
            ? `https://www.virustotal.com/gui/url/${encodeURIComponent(resultId)}`
            : kind === "file" && sha256
                ? `https://www.virustotal.com/gui/file/${encodeURIComponent(sha256)}`
                : `https://www.virustotal.com/gui/analyses/${encodeURIComponent(analysisId)}`;

    updatePendingHistory(historyId, {
        status: "complete",
        malicious,
        suspicious,
        harmless,
        undetected,
        analysisId,
        sha256
    });

    $("result-area").classList.remove("hidden");

    $("result-area").innerHTML = `
        <div class="result-summary">

            <div>
                <p class="eyebrow">COMPLETED ANALYSIS</p>

                <h3>${escapeHtml(label)}</h3>

                <p>
                    Results returned by VirusTotal.
                </p>
            </div>

            <div class="result-count">
                ${malicious + suspicious}/${total}

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
                sha256
                ? `SHA-256: <code>${escapeHtml(sha256)}</code><br>`
                : ""
            }

            ${
                analysisId
                ? `Analysis ID: <code>${escapeHtml(analysisId)}</code><br>`
                : ""
            }

            <a
                href="${guiUrl}"
                target="_blank"
                rel="noopener noreferrer"
            >
                Open in VirusTotal ↗
            </a>

            <br>

            <small>
                A zero-detection result is not a guarantee that
                the file or URL is safe.
            </small>

        </div>
    `;

    $("result-area").scrollIntoView({
        behavior: "smooth",
        block: "nearest"
    });
}


// --------------------------------------------------
// Error display
// --------------------------------------------------

function showApiError(error, kind, label, historyId) {
    const message =
        error.message ||
        "The request failed.";

    if (historyId) {
        updatePendingHistory(historyId, {
            status: "error",
            error: message
        });
    } else {
        addHistory({
            id: crypto.randomUUID(),
            kind,
            name: label,
            status: "error",
            error: message
        });
    }

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
            Check your connection, Render deployment logs,
            API key and VirusTotal API permissions.
        </p>
    `;

    toast(message);
}

// --------------------------------------------------
// File scanning
// --------------------------------------------------

async function scanFile(file) {
    if (!file) {
        toast("Please select a file first.");
        return;
    }

    const MAX_SIZE = 32 * 1024 * 1024;

    if (file.size > MAX_SIZE) {
        toast("The maximum supported file size is 32 MB.");
        return;
    }

    const label = file.name;

    const historyId = crypto.randomUUID();

    addHistory({
        id: historyId,
        kind: "file",
        name: label,
        status: "pending",
        size: file.size
    });

    $("result-area").classList.remove("hidden");

    $("result-area").innerHTML = `
        <div class="empty-state">
            Uploading ${escapeHtml(label)} to VirusTotal...
        </div>
    `;

    const formData = new FormData();

    formData.append("file", file);

    try {
        const submission = await requestJson("/scan/file", {
            method: "POST",
            body: formData
        });

        toast("File submitted. Waiting for analysis...");

        await fetchFinalReport(
            "file",
            submission,
            label,
            historyId
        );

    } catch (error) {
        showApiError(error, "file", label, historyId);
    }
}


// --------------------------------------------------
// URL scanning
// --------------------------------------------------

async function scanUrl(value) {
    const url = value.trim();

    if (!url) {
        toast("Enter a URL first.");
        return;
    }

    const historyId = crypto.randomUUID();

    addHistory({
        id: historyId,
        kind: "url",
        name: url,
        url,
        status: "pending"
    });

    $("result-area").classList.remove("hidden");

    $("result-area").innerHTML = `
        <div class="empty-state">
            Submitting URL to VirusTotal...
        </div>
    `;

    try {
        const submission = await requestJson("/scan/url", {
            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({ url })
        });

        toast("URL submitted. Waiting for analysis...");

        await fetchFinalReport(
            "url",
            submission,
            url,
            historyId
        );

    } catch (error) {
        showApiError(error, "url", url, historyId);
    }
}


// --------------------------------------------------
// VirusTotal Intelligence search
// --------------------------------------------------

async function searchQuery(value) {
    const query = value.trim();

    if (!query) {
        toast("Enter a search query.");
        return;
    }

    try {
        toast("Searching VirusTotal...");

        const data = await requestJson(
            `/search?q=${encodeURIComponent(query)}`
        );

        const items = Array.isArray(data.data)
            ? data.data
            : [];

        addHistory({
            id: crypto.randomUUID(),
            kind: "search",
            name: `${query} (${items.length} results)`,
            query,
            status: "complete"
        });

        const resultHtml = items.slice(0, 20).map(item => {
            const attributes = item.attributes || {};
            const id = item.id || "";
            const type = item.type || "file";

            const name =
                attributes.meaningful_name ||
                attributes.name ||
                id;

            let guiType = "files";

            if (type === "url") {
                guiType = "url";
            } else if (type === "domain") {
                guiType = "domain";
            } else if (type === "ip_address") {
                guiType = "ip-address";
            }

            return `
                <div class="activity-item">

                    <div class="activity-symbol">⌕</div>

                    <div class="activity-meta">

                        <b>${escapeHtml(name)}</b>

                        <small>
                            ${escapeHtml(type)}
                            · ${escapeHtml(id)}
                        </small>

                    </div>

                    <a
                        href="https://www.virustotal.com/gui/${guiType}/${encodeURIComponent(id)}"
                        target="_blank"
                        rel="noopener noreferrer"
                    >
                        Open ↗
                    </a>

                </div>
            `;
        }).join("");

        $("result-area").classList.remove("hidden");

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


// --------------------------------------------------
// Backend health check
// --------------------------------------------------

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


// --------------------------------------------------
// Event listeners: navigation
// --------------------------------------------------

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


// --------------------------------------------------
// Event listeners: tabs
// --------------------------------------------------

document.querySelectorAll(".scan-tab").forEach(button => {
    button.addEventListener("click", () => {
        setTab(button.dataset.tab);
    });
});


// --------------------------------------------------
// File selection
// --------------------------------------------------

$("file-input").addEventListener("change", event => {
    $("file-name").textContent =
        event.target.files[0]?.name ||
        "No file selected";
});

$("wide-file-input").addEventListener("change", event => {
    $("wide-file-name").textContent =
        event.target.files[0]?.name ||
        "No file selected";
});


// --------------------------------------------------
// File scan buttons
// --------------------------------------------------

$("file-scan-btn").addEventListener("click", () => {
    scanFile($("file-input").files[0]);
});

$("wide-file-scan-btn").addEventListener("click", () => {
    scanFile($("wide-file-input").files[0]);
});


// --------------------------------------------------
// URL forms
// --------------------------------------------------

$("quick-url").addEventListener("submit", event => {
    event.preventDefault();

    scanUrl($("url-input").value);
});

$("wide-url").addEventListener("submit", event => {
    event.preventDefault();

    scanUrl($("wide-url-input").value);
});


// --------------------------------------------------
// Search forms
// --------------------------------------------------

$("quick-search").addEventListener("submit", event => {
    event.preventDefault();

    searchQuery($("search-input").value);
});

$("wide-search").addEventListener("submit", event => {
    event.preventDefault();

    searchQuery($("wide-search-input").value);
});


// --------------------------------------------------
// Clear history
// --------------------------------------------------

$("clear-history").addEventListener("click", () => {
    state.history = [];

    renderMetrics();
    renderRecent();
    renderHistory();

    toast("Scan history cleared.");
});


// --------------------------------------------------
// Initialise dashboard
// --------------------------------------------------

setTab("file");

renderMetrics();
renderRecent();

checkHealth();
