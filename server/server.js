require("dotenv").config();

const express = require("express");
const cors = require("cors");
const ipaddr = require("ipaddr.js");
const {
    getInteractivePreview
} = require("./interactivePreview");

const { checkThreatIntel } = require("./threatIntel");
const { analyzeWithAI } = require("./aiAnalyzer");
const { getSafePreview } = require("./safePreview");

const app = express();

app.use(cors());
app.use(express.json({ limit: "100kb" }));

// ==========================================
// URL ANALYSIS
// ==========================================

function analyzeURL(inputURL) {
    let score = 0;
    const reasons = [];
    let url;

    try {
        url = new URL(inputURL);
    } catch {
        return {
            riskScore: 100,
            level: "HIGH",
            reasons: ["Invalid URL format"]
        };
    }

    const hostname = url.hostname.toLowerCase();
    const fullURL = inputURL.toLowerCase();

    // 1. HTTP instead of HTTPS
    if (url.protocol !== "https:") {
        score += 15;
        reasons.push("Connection does not use HTTPS");
    }

    // 2. IP address instead of domain
    const ipPattern = /^(?:\d{1,3}\.){3}\d{1,3}$/;

    if (ipPattern.test(hostname)) {
        score += 30;
        reasons.push(
            "URL uses an IP address instead of a domain"
        );
    }

    // 3. @ symbol
    if (inputURL.includes("@")) {
        score += 25;
        reasons.push("URL contains @ symbol");
    }

    // 4. Very long URL
    if (inputURL.length > 100) {
        score += 10;
        reasons.push("URL is unusually long");
    }

    // 5. Too many subdomains
    const subdomainCount =
        hostname.split(".").length - 2;

    if (subdomainCount >= 3) {
        score += 15;
        reasons.push(
            "URL contains many subdomains"
        );
    }

    // 6. Suspicious words
    const suspiciousWords = [
        "login",
        "verify",
        "verification",
        "password",
        "signin",
        "account",
        "secure",
        "update",
        "wallet",
        "claim",
        "free"
    ];

    const foundWords = suspiciousWords.filter(
        word => fullURL.includes(word)
    );

    if (foundWords.length > 0) {
        score += Math.min(
            foundWords.length * 5,
            20
        );

        reasons.push(
            `Contains suspicious keyword(s): ${foundWords.join(", ")}`
        );
    }

    // 7. URL shorteners
    const shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly"
    ];

    if (shorteners.includes(hostname)) {
        score += 20;
        reasons.push(
            "Uses a URL shortening service"
        );
    }

    score = Math.min(score, 100);

    let level;

    if (score <= 30) {
        level = "LOW";
    } else if (score <= 60) {
        level = "MEDIUM";
    } else {
        level = "HIGH";
    }

    return {
        riskScore: score,
        level,
        reasons
    };
}

// ==========================================
// BASIC SAFE URL VALIDATION
// ==========================================

function validatePreviewURL(inputURL) {
    let parsed;

    try {
        parsed = new URL(inputURL);
    } catch {
        return {
            valid: false,
            message: "Invalid URL"
        };
    }

    if (
        parsed.protocol !== "http:" &&
        parsed.protocol !== "https:"
    ) {
        return {
            valid: false,
            message: "Only HTTP and HTTPS URLs are allowed"
        };
    }

    const hostname = parsed.hostname;

    // Block localhost
    if (
        hostname === "localhost" ||
        hostname.endsWith(".localhost")
    ) {
        return {
            valid: false,
            message: "Localhost preview is not allowed"
        };
    }

    // Block common private/internal hostnames
    const blockedHostnames = [
        "metadata.google.internal",
        "metadata.google",
        "host.docker.internal"
    ];

    if (blockedHostnames.includes(hostname)) {
        return {
            valid: false,
            message: "Internal host preview is not allowed"
        };
    }

    // Check literal IP addresses
    try {
        const address = ipaddr.parse(hostname);
        const range = address.range();

        const blockedRanges = [
            "private",
            "loopback",
            "linkLocal",
            "uniqueLocal",
            "carrierGradeNat",
            "unspecified",
            "reserved"
        ];

        if (blockedRanges.includes(range)) {
            return {
                valid: false,
                message:
                    "Private or internal IP addresses cannot be previewed"
            };
        }
    } catch {
        // Normal domain name — continue.
    }

    return {
        valid: true,
        url: parsed.toString()
    };
}

// ==========================================
// URL SCAN API
// ==========================================

app.post("/api/scan", async (req, res) => {
    const { url } = req.body;

    if (!url) {
        return res.status(400).json({
            error: "URL is required"
        });
    }

    try {
        // 1. Rule-based analysis
        const result = analyzeURL(url);

        // 2. Live threat intelligence
        const threatIntel =
            await checkThreatIntel(url);

        // 3. AI analysis
        const aiResult =
            await analyzeWithAI(
                url,
                result,
                threatIntel
            );

        // 4. Combine risk scores
        let finalScore = Math.max(
            result.riskScore,
            aiResult.riskScore
        );

        // Known malicious URL = minimum 90
        if (threatIntel.knownThreat) {
            finalScore = Math.max(
                finalScore,
                90
            );
        }

        finalScore = Math.min(
            finalScore,
            100
        );

        // 5. Final risk level
        let finalLevel;

        if (finalScore <= 30) {
            finalLevel = "LOW";
        } else if (finalScore <= 60) {
            finalLevel = "MEDIUM";
        } else {
            finalLevel = "HIGH";
        }

        // 6. Combine reasons
        const reasons = [
            ...result.reasons
        ];

        if (threatIntel.knownThreat) {
            reasons.push(
                `Known malicious URL detected by: ${threatIntel.sources.join(", ")}`
            );
        }

        // 7. Response
        return res.json({
            url,
            riskScore: finalScore,
            level: finalLevel,
            reasons,

            threatIntel: {
                knownThreat:
                    threatIntel.knownThreat,

                sources:
                    threatIntel.sources,

                threatType:
                    threatIntel.threatType
            },

            aiAnalysis: {
                explanation:
                    aiResult.explanation,

                recommendation:
                    aiResult.recommendation
            },

            message:
                "URL analysis completed"
        });

    } catch (error) {
        console.error(
            "Scan error:",
            error.message
        );

        return res.status(500).json({
            error:
                "Unable to analyze URL"
        });
    }
});

// ==========================================
// SAFE PREVIEW API
// ==========================================

app.post("/api/preview", async (req, res) => {
    const { url } = req.body;

    if (!url) {
        return res.status(400).json({
            error: "URL is required"
        });
    }

    // Validate URL before sending it
    // to the preview service.
    const validation =
        validatePreviewURL(url);

    if (!validation.valid) {
        return res.status(400).json({
            error: validation.message
        });
    }

    try {
        const preview =
            await getSafePreview(
                validation.url
            );

        if (!preview.success) {
            return res.status(400).json({
                error: preview.message
            });
        }

        return res.json({
            success: true,
            title: preview.title,
            html: preview.html
        });

    } catch (error) {
        console.error(
            "Preview API error:",
            error.message
        );

        return res.status(500).json({
            error:
                "Unable to generate safe preview"
        });
    }
});

// ==========================================
// INTERACTIVE PREVIEW API
// ==========================================

app.post("/api/interactive-preview", async (req, res) => {
    const { url } = req.body;

    if (!url) {
        return res.status(400).json({
            error: "URL is required"
        });
    }

    const validation = validatePreviewURL(url);

    if (!validation.valid) {
        return res.status(400).json({
            error: validation.message
        });
    }

    try {
        const preview = await getInteractivePreview(
            validation.url
        );

        if (!preview.success) {
            return res.status(400).json({
                error: preview.message
            });
        }

        return res.json({
            success: true,
            title: preview.title,
            html: preview.html
        });

    } catch (error) {
        console.error(
            "Interactive preview error:",
            error.message
        );

        return res.status(500).json({
            error: "Unable to generate interactive preview"
        });
    }
});

// ==========================================
// HEALTH CHECK
// ==========================================

app.get("/api/health", (req, res) => {
    res.json({
        success: true,
        service: "LinkShield API",
        status: "running"
    });
});

// ==========================================
// SAFE PREVIEW ASSET PROXY
// ==========================================

app.get("/api/preview-asset", async (req, res) => {
    const { url } = req.query;

    if (!url) {
        return res.status(400).send("Asset URL is required");
    }

    try {
        const parsed = new URL(url);

        if (!["http:", "https:"].includes(parsed.protocol)) {
            return res.status(400).send("Invalid asset URL");
        }

        const response = await axios.get(parsed.href, {
            timeout: 10000,
            maxRedirects: 3,
            responseType: "arraybuffer",

            headers: {
                "User-Agent": "LinkShield-SafePreview/1.0",
                "Accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8"
            },

            validateStatus: status =>
                status >= 200 && status < 400
        });

        const contentType =
            response.headers["content-type"] || "";

        if (!contentType.toLowerCase().startsWith("image/")) {
            return res.status(400).send("Resource is not an image");
        }

        res.setHeader("Content-Type", contentType);

        // Prevent browser caching sensitive preview assets
        res.setHeader(
            "Cache-Control",
            "no-store"
        );

        // Prevent MIME sniffing
        res.setHeader(
            "X-Content-Type-Options",
            "nosniff"
        );

        return res.send(response.data);

    } catch (error) {

        console.error(
            "Preview asset error:",
            error.message
        );

        return res.status(502).send(
            "Unable to load preview asset"
        );
    }
});

// ==========================================
// START SERVER
// ==========================================

const PORT = process.env.PORT || 5001;

app.listen(PORT, () => {
    console.log(
        `LinkShield server running on port ${PORT}`
    );
});