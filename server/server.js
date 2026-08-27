require("dotenv").config();

const express = require("express");
const cors = require("cors");
const axios = require("axios");
const ipaddr = require("ipaddr.js");

const {
    getInteractivePreview
} = require("./interactivePreview");

const {
    checkThreatIntel
} = require("./threatIntel");

const {
    analyzeWithAI
} = require("./aiAnalyzer");

const {
    getSafePreview
} = require("./safePreview");


const app = express();


// =========================================================
// CORS
// =========================================================

app.use(
    cors({
        origin: "https://linkshield-kappa.vercel.app",
        methods: ["GET", "POST", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"]
    })
);

app.use(
    express.json({
        limit: "100kb"
    })
);


// =========================================================
// URL NORMALIZATION
// =========================================================

function normalizeURL(inputURL) {

    if (
        !inputURL ||
        typeof inputURL !== "string"
    ) {
        return "";
    }

    let value = inputURL.trim();

    if (!value) {
        return "";
    }

    if (!/^https?:\/\//i.test(value)) {
        value = `https://${value}`;
    }

    return value;
}


// =========================================================
// URL RISK ENGINE
// =========================================================

function analyzeURL(inputURL) {
    const normalizedURL = normalizeURL(inputURL);

    if (!normalizedURL) {
        return {
            riskScore: 100,
            level: "HIGH",
            reasons: ["Invalid or empty URL"]
        };
    }

    let url;

    try {
        url = new URL(normalizedURL);
    } catch {
        return {
            riskScore: 100,
            level: "HIGH",
            reasons: ["Invalid URL format"]
        };
    }

    const hostname = url.hostname.toLowerCase();
    const pathname = url.pathname.toLowerCase();
    const fullURL = normalizedURL.toLowerCase();
    const reasons = [];
    let score = 0;

    const add = (points, reason) => {
        score += points;
        reasons.push(reason);
    };

    // ---------------------------------------------------------
    // 1. Transport
    // HTTPS itself is NOT suspicious. HTTP gets only a small hit.
    // ---------------------------------------------------------
    if (url.protocol !== "https:") {
        add(10, "Connection does not use HTTPS");
    }

    // ---------------------------------------------------------
    // 2. Raw IP destination
    // ---------------------------------------------------------
    const ipPattern = /^(?:\d{1,3}\.){3}\d{1,3}$/;

    if (ipPattern.test(hostname)) {
        add(25, "URL uses an IP address instead of a domain");
    }

    // ---------------------------------------------------------
    // 3. User-info / @ deception
    // ---------------------------------------------------------
    if (url.username || url.password || fullURL.includes("@")) {
        add(
            30,
            "URL contains user-info/@ syntax that can obscure the actual destination"
        );
    }

    // ---------------------------------------------------------
    // 4. Punycode
    // ---------------------------------------------------------
    if (hostname.includes("xn--")) {
        add(15, "Hostname contains a punycode label");
    }

    // ---------------------------------------------------------
    // 5. Excessive subdomains
    // ---------------------------------------------------------
    const hostnameParts = hostname.split(".").filter(Boolean);
    const subdomainCount = Math.max(0, hostnameParts.length - 2);

    if (subdomainCount >= 4) {
        add(8, "URL contains an unusually deep subdomain structure");
    }

    // ---------------------------------------------------------
    // 6. URL shortening services
    // ---------------------------------------------------------
    const shorteners = new Set([
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly",
        "ow.ly",
        "shorturl.at",
        "rebrand.ly",
        "rb.gy"
    ]);

    if (shorteners.has(hostname)) {
        add(18, "Uses a URL shortening service that hides the final destination");
    }

    // ---------------------------------------------------------
    // 7. URL complexity
    // A long URL is not malicious by itself, so the weight is low.
    // ---------------------------------------------------------
    if (normalizedURL.length > 220) {
        add(5, "URL is unusually long");
    }

    if ((normalizedURL.match(/%[0-9a-f]{2}/gi) || []).length >= 8) {
        add(5, "URL contains unusually heavy percent-encoding");
    }

    // ---------------------------------------------------------
    // 8. Credential indicators
    // These matter more when they appear in a path/query rather than
    // ordinary words such as 'account' or 'security'.
    // ---------------------------------------------------------
    const credentialTerms = [
        "password",
        "passwd",
        "credential",
        "username",
        "secret",
        "otp",
        "pin",
        "token"
    ];

    const credentialMatches = credentialTerms.filter((term) =>
        fullURL.includes(term)
    );

    const hasCredentialSignal = credentialMatches.length > 0;

    if (hasCredentialSignal) {
        add(10, "URL contains credential-related indicators");
    }

    // ---------------------------------------------------------
    // 9. Sensitive query parameters
    // ---------------------------------------------------------
    const sensitiveParameters = new Set([
        "password",
        "passwd",
        "credential",
        "username",
        "token",
        "otp",
        "pin",
        "secret",
        "apikey",
        "api_key"
    ]);

    let sensitiveParameterFound = false;

    for (const [key] of url.searchParams.entries()) {
        if (sensitiveParameters.has(key.toLowerCase())) {
            sensitiveParameterFound = true;
            break;
        }
    }

    if (sensitiveParameterFound) {
        add(
            15,
            "URL contains a sensitive credential-related parameter"
        );
    }

    // ---------------------------------------------------------
    // 10. Authentication paths
    // IMPORTANT: login/account/verify alone are NOT malicious.
    // They only contribute when paired with stronger evidence.
    // ---------------------------------------------------------
    const authenticationTerms = [
        "login",
        "signin",
        "sign-in",
        "verify",
        "verification",
        "account",
        "confirm",
        "confirmation",
        "reset",
        "recover"
    ];

    const authenticationMatches = authenticationTerms.filter((term) =>
        fullURL.includes(term)
    );

    const hasAuthenticationSignal = authenticationMatches.length > 0;
    const multipleAuthenticationSignals = authenticationMatches.length >= 2;

    if (multipleAuthenticationSignals) {
        add(
            5,
            "Multiple authentication or account-verification indicators are present"
        );
    }

    const credentialPath =
        /\/(login|signin|sign-in|verify|verification|account|security|password|reset|recover)(?:[/?#]|$)/i;

    const credentialPathFound = credentialPath.test(pathname);

    if (credentialPathFound && hasCredentialSignal) {
        add(
            10,
            "Authentication-related path is combined with credential indicators"
        );
    }

    // ---------------------------------------------------------
    // 11. Dangerous downloads
    // ---------------------------------------------------------
    const dangerousExtensions = [
        ".exe",
        ".scr",
        ".msi",
        ".bat",
        ".cmd",
        ".ps1",
        ".apk",
        ".jar",
        ".dmg",
        ".pkg"
    ];

    if (dangerousExtensions.some((extension) => pathname.endsWith(extension))) {
        add(
            25,
            "URL points to a potentially executable or installable file"
        );
    }

    // ---------------------------------------------------------
    // 12. Urgency / reward language
    // These are weak alone. They become meaningful with auth signals.
    // ---------------------------------------------------------
    const urgencyTerms = [
        "urgent",
        "immediately",
        "expire",
        "suspended",
        "limited",
        "claim",
        "reward",
        "bonus",
        "free"
    ];

    const urgencyFound = urgencyTerms.some((term) =>
        fullURL.includes(term)
    );

    if (urgencyFound && hasAuthenticationSignal) {
        add(
            10,
            "Urgency or reward language is combined with authentication-related signals"
        );
    }

    // ---------------------------------------------------------
    // 13. Strong correlated phishing pattern
    // ---------------------------------------------------------
    const strongCredentialPattern =
        multipleAuthenticationSignals &&
        hasCredentialSignal &&
        (sensitiveParameterFound || credentialPathFound);

    if (strongCredentialPattern) {
        add(
            15,
            "Multiple correlated authentication and credential signals form a stronger phishing pattern"
        );
    }

    // ---------------------------------------------------------
    // 14. Final deterministic score
    // ---------------------------------------------------------
    score = Math.min(Math.max(Math.round(score), 0), 100);

    let level = "LOW";

    if (score > 60) {
        level = "HIGH";
    } else if (score > 30) {
        level = "MEDIUM";
    }

    return {
        riskScore: score,
        level,
        reasons,
        evidenceCount: reasons.length,
        hasStrongEvidence:
            score >= 25 ||
            strongCredentialPattern ||
            dangerousExtensions.some((extension) => pathname.endsWith(extension))
    };
}

// =========================================================
// SAFE PREVIEW VALIDATION
// =========================================================

function validatePreviewURL(inputURL) {

    let parsed;

    try {

        parsed =
            new URL(inputURL);

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
            message:
                "Only HTTP and HTTPS URLs are allowed"
        };

    }


    const hostname =
        parsed.hostname.toLowerCase();


    // BLOCK LOCALHOST

    if (
        hostname === "localhost" ||
        hostname.endsWith(".localhost")
    ) {

        return {
            valid: false,
            message:
                "Localhost preview is not allowed"
        };

    }


    // BLOCK INTERNAL HOSTNAMES

    const blockedHostnames = [

        "metadata.google.internal",
        "metadata.google",
        "host.docker.internal"

    ];

    if (
        blockedHostnames.includes(hostname)
    ) {

        return {
            valid: false,
            message:
                "Internal host preview is not allowed"
        };

    }


    // BLOCK PRIVATE IP RANGES

    try {

        const address =
            ipaddr.parse(hostname);

        const range =
            address.range();

        const blockedRanges = [

            "private",
            "loopback",
            "linkLocal",
            "uniqueLocal",
            "carrierGradeNat",
            "unspecified",
            "reserved"

        ];

        if (
            blockedRanges.includes(range)
        ) {

            return {
                valid: false,
                message:
                    "Private or internal IP addresses cannot be previewed"
            };

        }

    } catch {

        // Normal hostname.
        // Continue.

    }


    return {

        valid: true,

        url:
            parsed.toString()

    };

}


// =========================================================
// SCAN API
// =========================================================

app.post(
    "/api/scan",
    async (req, res) => {

        const {
            url
        } = req.body;


        if (
            !url ||
            typeof url !== "string"
        ) {

            return res.status(400).json({

                error:
                    "URL is required"

            });

        }


        try {

            // =================================================
            // 1. NORMALIZE
            // =================================================

            const normalizedURL =
                normalizeURL(url);

            if (!normalizedURL) {

                return res.status(400).json({

                    error:
                        "URL is required"

                });

            }


            // =================================================
            // 2. LOCAL RULE ANALYSIS
            // =================================================

            const ruleResult =
                analyzeURL(
                    normalizedURL
                );


            console.log(
                "URL:",
                normalizedURL
            );

            console.log(
                "RULE RESULT:",
                ruleResult
            );


            // =================================================
            // 3. THREAT INTELLIGENCE
            // =================================================

            let threatIntel = {

                knownThreat: false,

                sources: [],

                threatType: null

            };


            try {

                const threatResult =
                    await checkThreatIntel(
                        normalizedURL
                    );
                if (
                    threatResult &&
                    typeof threatResult === "object"
                ) {

                    threatIntel = {

                        knownThreat:
                            threatResult.knownThreat === true,

                        sources:
                            Array.isArray(
                                threatResult.sources
                            )
                                ? threatResult.sources
                                : [],

                        threatType:
                            threatResult.threatType ||
                            null

                    };

                }

            } catch (error) {

                console.error(
                    "Threat intelligence error:",
                    error.message
                );

                // Threat intelligence failure
                // must NOT make a URL HIGH risk.

                threatIntel = {

                    knownThreat: false,

                    sources: [],

                    threatType: null

                };

            }


            console.log(
                "THREAT INTEL:",
                threatIntel
            );


            // =================================================
            // 4. AI ANALYSIS
            // =================================================

            let aiResult = null;


            try {

                aiResult =
                    await analyzeWithAI(
                        normalizedURL,
                        ruleResult,
                        threatIntel
                    );

            } catch (error) {

                console.error(
                    "AI analysis error:",
                    error.message
                );

                aiResult = null;

            }


            console.log(
                "AI RESULT:",
                aiResult
            );

            console.log("FINAL DEBUG:", {
                url: normalizedURL,
                ruleScore: ruleResult.riskScore,
                ruleLevel: ruleResult.level,
                threatKnown: threatIntel.knownThreat,
                threatSources: threatIntel.sources,
                aiScore: aiResult?.riskScore,
                aiClassification: aiResult?.classification,
                aiConfidence: aiResult?.confidence
            });


            // =================================================
            // 5. FINAL SCORE
            // =================================================

            let finalScore =
                ruleResult.riskScore;


            // =================================================
            // CONFIRMED THREAT INTELLIGENCE
            // =================================================

            if (
                threatIntel.knownThreat === true
            ) {

                finalScore =
                    Math.max(
                        finalScore,
                        90
                    );

            }


            // =================================================
            // AI SECOND OPINION
            // =================================================
            // AI may strengthen evidence that already exists.
            // AI must NEVER turn a clean URL into HIGH by itself.

            const aiConfidence = Number(aiResult?.confidence || 0);
            const aiScore = Number(aiResult?.riskScore || 0);
            const aiClassification = String(
                aiResult?.classification || ""
            ).toUpperCase();

            const hasObjectiveEvidence =
                ruleResult.hasStrongEvidence === true ||
                ruleResult.evidenceCount >= 2;

            if (
                hasObjectiveEvidence &&
                aiConfidence >= 85 &&
                (aiClassification === "HIGH" || aiClassification === "CRITICAL") &&
                Number.isFinite(aiScore) &&
                aiScore > finalScore
            ) {
                finalScore = Math.max(
                    finalScore,
                    Math.min(aiScore, finalScore + 20)
                );
            }

            // =================================================
            // FINAL SCORE BOUNDARY
            // =================================================

            finalScore =
                Math.min(
                    Math.max(
                        Math.round(finalScore),
                        0
                    ),
                    100
                );


            // =================================================
            // FINAL LEVEL
            // =================================================

            let finalLevel;

            if (finalScore <= 30) {

                finalLevel = "LOW";

            } else if (finalScore <= 60) {

                finalLevel = "MEDIUM";

            } else {

                finalLevel = "HIGH";

            }


            // =================================================
            // REASONS
            // =================================================

            const reasons = [
                ...ruleResult.reasons
            ];


            // THREAT INTEL REASON

            if (
                threatIntel.knownThreat === true
            ) {

                reasons.push(

                    `Known malicious URL detected by: ${
                        threatIntel.sources.length > 0
                            ? threatIntel.sources.join(", ")
                            : "connected threat intelligence"
                    }`

                );

            }


            // AI INDICATORS

            if (
                Array.isArray(
                    aiResult?.indicators
                )
            ) {

                for (
                    const indicator
                    of aiResult.indicators
                ) {

                    if (

                        typeof indicator === "string" &&

                        indicator.trim() &&

                        !reasons.includes(indicator)

                    ) {

                        reasons.push(
                            `AI assessment: ${indicator}`
                        );

                    }

                }

            }


            // =================================================
            // RESPONSE
            // =================================================

            return res.json({

                url:
                    normalizedURL,

                riskScore:
                    finalScore,

                level:
                    finalLevel,

                reasons,

                threatIntel: {

                    knownThreat:
                        threatIntel.knownThreat === true,

                    sources:
                        Array.isArray(
                            threatIntel.sources
                        )
                            ? threatIntel.sources
                            : [],

                    threatType:
                        threatIntel.threatType ||
                        null

                },

                aiAnalysis: {

                    classification:
                        aiResult?.classification ||
                        ruleResult.level,

                    riskScore:
                        Number.isFinite(
                            Number(
                                aiResult?.riskScore
                            )
                        )
                            ? Number(
                                aiResult.riskScore
                            )
                            : ruleResult.riskScore,

                    confidence:
                        Number.isFinite(
                            Number(
                                aiResult?.confidence
                            )
                        )
                            ? Number(
                                aiResult.confidence
                            )
                            : null,

                    isLegitimate:
                        aiResult?.isLegitimate ??
                        null,

                    explanation:
                        aiResult?.explanation ||
                        "AI analysis was unavailable. LinkShield used its local security analysis.",

                    recommendation:
                        aiResult?.recommendation ||
                        "Review the domain and available security indicators before interacting with the URL."

                },

                message:
                    "URL analysis completed"

            });

        } catch (error) {

            console.error(
                "Scan error:",
                error
            );

            return res.status(500).json({

                error:
                    "Unable to analyze URL"

            });

        }

    }
);


// =========================================================
// SAFE PREVIEW API
// =========================================================

app.post(
    "/api/preview",
    async (req, res) => {

        const {
            url
        } = req.body;


        if (!url) {

            return res.status(400).json({

                error:
                    "URL is required"

            });

        }


        const normalizedURL =
            normalizeURL(url);


        const validation =
            validatePreviewURL(
                normalizedURL
            );


        if (!validation.valid) {

            return res.status(400).json({

                error:
                    validation.message

            });

        }


        try {

            const preview =
                await getSafePreview(
                    validation.url
                );


            if (
                !preview.success
            ) {

                return res.status(400).json({

                    error:
                        preview.message

                });

            }


            return res.json({

                success: true,

                title:
                    preview.title,

                html:
                    preview.html

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

    }
);


// =========================================================
// INTERACTIVE PREVIEW API
// =========================================================

app.post(
    "/api/interactive-preview",
    async (req, res) => {

        const {
            url
        } = req.body;


        if (!url) {

            return res.status(400).json({

                error:
                    "URL is required"

            });

        }


        const normalizedURL =
            normalizeURL(url);


        const validation =
            validatePreviewURL(
                normalizedURL
            );


        if (!validation.valid) {

            return res.status(400).json({

                error:
                    validation.message

            });

        }


        try {

            const preview =
                await getInteractivePreview(
                    validation.url
                );


            if (
                !preview.success
            ) {

                return res.status(400).json({

                    error:
                        preview.message

                });

            }


            return res.json({

                success: true,

                title:
                    preview.title,

                html:
                    preview.html

            });

        } catch (error) {

            console.error(
                "Interactive preview error:",
                error.message
            );

            return res.status(500).json({

                error:
                    "Unable to generate interactive preview"

            });

        }

    }
);


// =========================================================
// HEALTH CHECK
// =========================================================

app.get(
    "/api/health",
    (req, res) => {

        res.json({

            success: true,

            service:
                "LinkShield API",

            status:
                "running"

        });

    }
);


// =========================================================
// SAFE PREVIEW ASSET PROXY
// =========================================================

app.get(
    "/api/preview-asset",
    async (req, res) => {

        const {
            url
        } = req.query;


        if (!url) {

            return res.status(400).send(
                "Asset URL is required"
            );

        }


        try {

            const parsed =
                new URL(url);


            if (
                ![
                    "http:",
                    "https:"
                ].includes(
                    parsed.protocol
                )
            ) {

                return res.status(400).send(
                    "Invalid asset URL"
                );

            }


            const validation =
                validatePreviewURL(
                    parsed.href
                );


            if (!validation.valid) {

                return res.status(400).send(
                    validation.message
                );

            }


            const response =
                await axios.get(
                    parsed.href,
                    {

                        timeout: 10000,

                        maxRedirects: 3,

                        responseType:
                            "arraybuffer",

                        headers: {

                            "User-Agent":
                                "LinkShield-SafePreview/1.0",

                            "Accept":
                                "image/avif,image/webp,image/apng,image/*,*/*;q=0.8"

                        },

                        validateStatus:
                            status =>
                                status >= 200 &&
                                status < 400

                    }
                );


            const contentType =
                response.headers[
                    "content-type"
                ] || "";


            if (
                !contentType
                    .toLowerCase()
                    .startsWith("image/")
            ) {

                return res.status(400).send(
                    "Resource is not an image"
                );

            }


            res.setHeader(
                "Content-Type",
                contentType
            );

            res.setHeader(
                "Cache-Control",
                "no-store"
            );

            res.setHeader(
                "X-Content-Type-Options",
                "nosniff"
            );


            return res.send(
                response.data
            );

        } catch (error) {

            console.error(
                "Preview asset error:",
                error.message
            );

            return res.status(502).send(
                "Unable to load preview asset"
            );

        }

    }
);


// =========================================================
// START SERVER
// =========================================================

const PORT =
    process.env.PORT || 5001;


app.listen(
    PORT,
    () => {

        console.log(
            `LinkShield server running on port ${PORT}`
        );

    }
);