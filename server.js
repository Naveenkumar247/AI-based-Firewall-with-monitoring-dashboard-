require("dotenv").config();

const express = require("express");
const multer = require("multer");
const path = require("path");

const app = express();

const PORT = Number(process.env.PORT || 3000);
const API_KEY = process.env.VIRUSTOTAL_API_KEY;

const VIRUSTOTAL_BASE = "https://www.virustotal.com/api/v3";

const MAX_FILE_SIZE = 32 * 1024 * 1024;

// --------------------------------------------------
// Middleware
// --------------------------------------------------

app.disable("x-powered-by");

app.use(express.json({ limit: "1mb" }));

app.use(express.static(__dirname, {
    index: "index.html"
}));

const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: MAX_FILE_SIZE
    }
});

// --------------------------------------------------
// API key validation
// --------------------------------------------------

function requireApiKey(req, res, next) {
    if (!API_KEY) {
        return res.status(503).json({
            error:
                "VirusTotal API key is missing. Configure VIRUSTOTAL_API_KEY in Render Environment."
        });
    }

    next();
}

// --------------------------------------------------
// VirusTotal API helper
// --------------------------------------------------

async function vtRequest(endpoint, options = {}) {
    const response = await fetch(
        `${VIRUSTOTAL_BASE}${endpoint}`,
        {
            ...options,
            headers: {
                "x-apikey": API_KEY,
                "accept": "application/json",
                ...(options.headers || {})
            },
            signal: AbortSignal.timeout(30000)
        }
    );

    const responseText = await response.text();

    let data = {};

    try {
        data = responseText
            ? JSON.parse(responseText)
            : {};
    } catch {
        data = {
            message: responseText
        };
    }

    if (!response.ok) {
        const apiMessage =
            data?.error?.message ||
            data?.message ||
            `VirusTotal returned HTTP ${response.status}`;

        const error = new Error(apiMessage);

        error.status = response.status;
        error.apiCode = data?.error?.code;

        throw error;
    }

    return data;
}

// --------------------------------------------------
// Error response helper
// --------------------------------------------------

function sendVtError(res, error) {
    console.error(
        "VirusTotal API error:",
        error.status || "",
        error.message
    );

    let status = 502;

    if (
        Number.isInteger(error.status) &&
        error.status >= 400 &&
        error.status < 500
    ) {
        status = error.status;
    }

    if (error.name === "TimeoutError") {
        status = 504;
    }

    res.status(status).json({
        error: error.message || "VirusTotal request failed."
    });
}

// --------------------------------------------------
// Health check
// --------------------------------------------------

app.get("/api/health", (req, res) => {
    res.json({
        ok: true,
        service: "Sentinel Firewall Dashboard",
        apiKeyConfigured: Boolean(API_KEY)
    });
});

// --------------------------------------------------
// File submission
// POST /api/scan/file
// --------------------------------------------------

app.post(
    "/api/scan/file",
    requireApiKey,
    upload.single("file"),
    async (req, res) => {
        if (!req.file) {
            return res.status(400).json({
                error: "Please select a file."
            });
        }

        try {
            const form = new FormData();

            form.append(
                "file",
                new Blob([req.file.buffer], {
                    type:
                        req.file.mimetype ||
                        "application/octet-stream"
                }),
                req.file.originalname
            );

            const result = await vtRequest("/files", {
                method: "POST",
                body: form
            });

            res.status(200).json(result);

        } catch (error) {
            sendVtError(res, error);
        }
    }
);

// --------------------------------------------------
// URL submission
// POST /api/scan/url
// --------------------------------------------------

app.post(
    "/api/scan/url",
    requireApiKey,
    async (req, res) => {
        const value =
            typeof req.body?.url === "string"
                ? req.body.url.trim()
                : "";

        if (!value) {
            return res.status(400).json({
                error: "URL is required."
            });
        }

        let parsed;

        try {
            parsed = new URL(value);
        } catch {
            return res.status(400).json({
                error:
                    "Enter a valid URL beginning with http:// or https://."
            });
        }

        if (
            parsed.protocol !== "http:" &&
            parsed.protocol !== "https:"
        ) {
            return res.status(400).json({
                error: "Only HTTP and HTTPS URLs are supported."
            });
        }

        try {
            const body = new URLSearchParams({
                url: parsed.toString()
            });

            const result = await vtRequest("/urls", {
                method: "POST",
                headers: {
                    "Content-Type":
                        "application/x-www-form-urlencoded"
                },
                body: body.toString()
            });

            res.status(200).json(result);

        } catch (error) {
            sendVtError(res, error);
        }
    }
);

// --------------------------------------------------
// Retrieve analysis status
// GET /api/analysis/:id
// --------------------------------------------------

app.get(
    "/api/analysis/:id",
    requireApiKey,
    async (req, res) => {
        const id = req.params.id;

        if (!id || id.length > 200) {
            return res.status(400).json({
                error: "Invalid analysis ID."
            });
        }

        try {
            const result = await vtRequest(
                `/analyses/${encodeURIComponent(id)}`
            );

            res.json(result);

        } catch (error) {
            sendVtError(res, error);
        }
    }
);

// --------------------------------------------------
// Retrieve completed file report
// GET /api/report/file/:id
// --------------------------------------------------

app.get(
    "/api/report/file/:id",
    requireApiKey,
    async (req, res) => {
        const id = req.params.id;

        // A file report requires a SHA-256 hash.
        if (!/^[a-fA-F0-9]{64}$/.test(id)) {
            return res.status(400).json({
                error: "A valid SHA-256 file hash is required."
            });
        }

        try {
            const result = await vtRequest(
                `/files/${encodeURIComponent(id)}`
            );

            res.json(result);

        } catch (error) {
            sendVtError(res, error);
        }
    }
);

// --------------------------------------------------
// Retrieve completed URL report
// GET /api/report/url/:id
// --------------------------------------------------

app.get(
    "/api/report/url/:id",
    requireApiKey,
    async (req, res) => {
        const id = req.params.id;

        // VirusTotal URL IDs are URL-safe Base64 strings.
        if (!/^[a-zA-Z0-9_-]{1,500}$/.test(id)) {
            return res.status(400).json({
                error: "Invalid VirusTotal URL identifier."
            });
        }

        try {
            const result = await vtRequest(
                `/urls/${encodeURIComponent(id)}`
            );

            res.json(result);

        } catch (error) {
            sendVtError(res, error);
        }
    }
);

// --------------------------------------------------
// VirusTotal Intelligence search
// GET /api/search?q=domain:example.com
// --------------------------------------------------

app.get(
    "/api/search",
    requireApiKey,
    async (req, res) => {
        const query =
            typeof req.query.q === "string"
                ? req.query.q.trim()
                : "";

        if (!query) {
            return res.status(400).json({
                error: "Search query is required."
            });
        }

        if (query.length > 500) {
            return res.status(400).json({
                error:
                    "Search query must not exceed 500 characters."
            });
        }

        try {
            const result = await vtRequest(
                "/intelligence/search?query=" +
                encodeURIComponent(query)
            );

            res.json(result);

        } catch (error) {
            sendVtError(res, error);
        }
    }
);

// --------------------------------------------------
// Handle file upload errors
// --------------------------------------------------

app.use((error, req, res, next) => {
    if (error.code === "LIMIT_FILE_SIZE") {
        return res.status(413).json({
            error:
                "File exceeds the 32 MB upload limit."
        });
    }

    if (error instanceof multer.MulterError) {
        return res.status(400).json({
            error: error.message
        });
    }

    console.error("Server error:", error.message);

    res.status(500).json({
        error: "Unexpected server error."
    });
});

// --------------------------------------------------
// Start server
// --------------------------------------------------

app.listen(PORT, "0.0.0.0", () => {
    console.log(
        `Sentinel Dashboard running on port ${PORT}`
    );

    console.log(
        `VirusTotal API key configured: ${Boolean(API_KEY)}`
    );
});
