require("dotenv").config();

const express = require("express");
const multer = require("multer");
const path = require("path");

const app = express();

const PORT = Number(process.env.PORT || 3000);

const VIRUSTOTAL_BASE =
    "https://www.virustotal.com/api/v3";

const API_KEY = process.env.VIRUSTOTAL_API_KEY;


// Store uploaded files in memory, not in a public folder.
const upload = multer({
    storage: multer.memoryStorage(),

    limits: {
        fileSize: 32 * 1024 * 1024
    }
});

app.disable("x-powered-by");

app.use(express.json({
    limit: "1mb"
}));

app.use(express.static(__dirname));


// Require a configured API key
function requireApiKey(req, res, next) {
    if (!API_KEY) {
        return res.status(503).json({
            error:
                "VirusTotal API key is missing. Configure your .env file."
        });
    }

    next();
}


// Send a request to VirusTotal
async function vtRequest(endpoint, options = {}) {
    const response = await fetch(
        `${VIRUSTOTAL_BASE}${endpoint}`,
        {
            ...options,

            headers: {
                "x-apikey": API_KEY,
                ...(options.headers || {})
            }
        }
    );

    const text = await response.text();

    let data = {};

    try {
        data = text ? JSON.parse(text) : {};
    } catch {
        data = {
            message: text
        };
    }

    if (!response.ok) {
        const message =
            data?.error?.message ||
            data?.message ||
            `VirusTotal returned HTTP ${response.status}`;

        const error = new Error(message);

        error.status = response.status;

        throw error;
    }

    return data;
}


// Return a safe error message to the frontend
function sendVtError(res, error) {
    let status = 502;

    if (
        error.status === 401 ||
        error.status === 403 ||
        error.status === 429
    ) {
        status = error.status;
    } else if (
        error.status >= 400 &&
        error.status < 500
    ) {
        status = error.status;
    }

    res.status(status).json({
        error: error.message || "VirusTotal request failed."
    });
}


// Backend health endpoint
app.get("/api/health", (req, res) => {
    res.json({
        ok: true,
        apiKeyConfigured: Boolean(API_KEY)
    });
});


// File scanning endpoint
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

            res.json(result);

        } catch (error) {
            sendVtError(res, error);
        }
    }
);


// URL scanning endpoint
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

                body
            });

            res.json(result);

        } catch (error) {
            sendVtError(res, error);
        }
    }
);


// VirusTotal Intelligence search endpoint
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
                    "Search query exceeds the 500-character limit."
            });
        }

        try {
            const endpoint =
                "/intelligence/search?query=" +
                encodeURIComponent(query);

            const result = await vtRequest(endpoint);

            res.json(result);

        } catch (error) {
            sendVtError(res, error);
        }
    }
);


// Handle upload errors
app.use((error, req, res, next) => {
    if (error.code === "LIMIT_FILE_SIZE") {
        return res.status(413).json({
            error: "File exceeds the 32 MB upload limit."
        });
    }

    console.error("Server error:", error.message);

    res.status(500).json({
        error: "Unexpected server error."
    });
});


// Start the server
app.listen(PORT, () => {
    console.log(
        `Sentinel dashboard running at http://localhost:${PORT}`
    );
});
