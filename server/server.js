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
        allowedHeaders: [
            "Content-Type",
            "Authorization"
        ]
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

    let score = 0;

    const reasons = [];

    const signals = [];

    const normalizedURL =
        normalizeURL(inputURL);

    let url;

    try {

        url = new URL(normalizedURL);

    } catch {

        return {
            riskScore: 100,
            level: "HIGH",
            reasons: [
                "Invalid URL format"
            ],
            signals: [
                "invalid_url"
            ]
        };

    }


    const hostname =
        url.hostname.toLowerCase();

    const pathname =
        url.pathname.toLowerCase();

    const fullURL =
        normalizedURL.toLowerCase();

    const search =
        url.search.toLowerCase();


    // =====================================================
    // 1. HTTP
    // =====================================================

    if (url.protocol !== "https:") {

        score += 10;

        reasons.push(
            "Connection does not use HTTPS"
        );

        signals.push(
            "http_connection"
        );

    }


    // =====================================================
    // 2. RAW IP ADDRESS
    // =====================================================

    const ipPattern =
        /^(?:\d{1,3}\.){3}\d{1,3}$/;

    if (ipPattern.test(hostname)) {

        score += 25;

        reasons.push(
            "URL uses an IP address instead of a domain"
        );

        signals.push(
            "ip_host"
        );

    }


    // =====================================================
    // 3. @ OBFUSCATION
    // =====================================================

    if (
        normalizedURL.includes("@")
    ) {

        score += 30;

        reasons.push(
            "URL contains @ symbol, which can obscure the actual destination"
        );

        signals.push(
            "at_symbol"
        );

    }


    // =====================================================
    // 4. VERY LONG URL
    // =====================================================

    if (
        normalizedURL.length > 150
    ) {

        score += 8;

        reasons.push(
            "URL is unusually long"
        );

        signals.push(
            "long_url"
        );

    }


    // =====================================================
    // 5. VERY DEEP SUBDOMAINS
    // =====================================================

    const hostnameParts =
        hostname
            .split(".")
            .filter(Boolean);

    const subdomainCount =
        Math.max(
            0,
            hostnameParts.length - 2
        );

    if (
        subdomainCount >= 4
    ) {

        score += 10;

        reasons.push(
            "URL contains an unusually deep subdomain structure"
        );

        signals.push(
            "deep_subdomains"
        );

    }


    // =====================================================
    // 6. PUNYCODE
    // =====================================================

    if (
        hostname.includes("xn--")
    ) {

        score += 15;

        reasons.push(
            "Hostname contains a punycode/internationalized label"
        );

        signals.push(
            "punycode"
        );

    }


    // =====================================================
    // 7. URL SHORTENERS
    // =====================================================

    const shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly",
        "ow.ly",
        "shorturl.at",
        "rb.gy",
        "tiny.cc",
        "lnkd.in"
    ];

    if (
        shorteners.includes(hostname)
    ) {

        score += 18;

        reasons.push(
            "Uses a URL shortening service"
        );

        signals.push(
            "url_shortener"
        );

    }


    // =====================================================
    // 8. SECURITY / ACCOUNT KEYWORDS
    // =====================================================

    const suspiciousWords = [

        "login",
        "signin",
        "sign-in",
        "verify",
        "verification",
        "password",
        "credential",
        "account",
        "secure",
        "security",
        "update",
        "confirm",
        "confirmation",
        "reset",
        "recover",
        "wallet",
        "payment",
        "billing",
        "claim",
        "bonus",
        "reward",
        "free",
        "suspended",
        "unlock"

    ];

    const foundWords =
        suspiciousWords.filter(
            word =>
                fullURL.includes(word)
        );

    if (
        foundWords.length > 0
    ) {

        score += Math.min(
            foundWords.length * 2,
            8
        );

        reasons.push(
            `Contains security-sensitive keyword(s): ${foundWords.join(", ")}`
        );

        signals.push(
            "security_keywords"
        );

    }


    // =====================================================
    // 9. AUTHENTICATION COMBINATION
    // =====================================================

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

    const authenticationMatches =
        authenticationTerms.filter(
            term =>
                fullURL.includes(term)
        );

    if (
        authenticationMatches.length >= 2
    ) {

        score += 10;

        reasons.push(
            "Multiple authentication or account-verification indicators are present"
        );

        signals.push(
            "multiple_auth_signals"
        );

    }


    // =====================================================
    // 10. CREDENTIAL INDICATORS
    // =====================================================

    const credentialTerms = [

        "password",
        "passwd",
        "credential",
        "username",
        "secret",
        "otp",
        "pin",
        "token",
        "apikey",
        "api_key"

    ];

    const credentialMatches =
        credentialTerms.filter(
            term =>
                fullURL.includes(term)
        );

    if (
        credentialMatches.length > 0
    ) {

        score += 10;

        reasons.push(
            "URL contains credential-related indicators"
        );

        signals.push(
            "credential_terms"
        );

    }


    // =====================================================
    // 11. SENSITIVE QUERY PARAMETERS
    // =====================================================

    const sensitiveParameters = [

        "password",
        "passwd",
        "credential",
        "username",
        "token",
        "otp",
        "pin",
        "secret",
        "apikey",
        "api_key",
        "access_token",
        "auth"

    ];

    let sensitiveParameterFound =
        false;

    let sensitiveParameterName =
        null;

    for (
        const parameter
        of sensitiveParameters
    ) {

        if (
            url.searchParams.has(parameter)
        ) {

            sensitiveParameterFound =
                true;

            sensitiveParameterName =
                parameter;

            break;

        }

    }

    if (
        sensitiveParameterFound
    ) {

        score += 15;

        reasons.push(
            `URL contains a sensitive parameter: ${sensitiveParameterName}`
        );

        signals.push(
            "sensitive_parameter"
        );

    }


    // =====================================================
    // 12. MANY QUERY PARAMETERS
    // =====================================================

    const parameterCount =
        Array.from(
            url.searchParams.keys()
        ).length;

    if (
        parameterCount >= 8
    ) {

        score += 6;

        reasons.push(
            "URL contains an unusually large number of query parameters"
        );

        signals.push(
            "many_parameters"
        );

    }


    // =====================================================
    // 13. DECEPTIVE HOSTNAME
    // =====================================================

    const hostnameSecurityTerms = [

        "login",
        "signin",
        "verify",
        "verification",
        "security",
        "secure",
        "account",
        "support",
        "update",
        "confirm",
        "wallet",
        "payment",
        "billing"

    ];

    const hostnameSecurityMatches =
        hostnameSecurityTerms.filter(
            term =>
                hostname.includes(term)
        );

    if (
        hostnameSecurityMatches.length >= 2
    ) {

        score += 12;

        reasons.push(
            "Hostname contains multiple security or account-related terms"
        );

        signals.push(
            "deceptive_hostname"
        );

    }


    // =====================================================
    // 14. SUSPICIOUS AUTHENTICATION PATH
    // =====================================================

    const credentialPath =
        /\/(login|signin|sign-in|verify|verification|account|security|password|reset|recover)(\/|$)/i;

    if (
        credentialPath.test(pathname) &&
        credentialMatches.length > 0
    ) {

        score += 10;

        reasons.push(
            "Authentication-related path is combined with credential indicators"
        );

        signals.push(
            "credential_path_combination"
        );

    }


    // =====================================================
    // 15. HIGH-RISK CREDENTIAL COMBINATION
    // =====================================================

    const hasAuthenticationSignal =
        authenticationMatches.length >= 2;

    const hasCredentialSignal =
        credentialMatches.length > 0;

    const hasSensitiveParameter =
        sensitiveParameterFound;

    const hasDeceptiveHostname =
        hostnameSecurityMatches.length >= 2;


    if (
        hasAuthenticationSignal &&
        hasCredentialSignal &&
        (
            hasSensitiveParameter ||
            hasDeceptiveHostname
        )
    ) {

        score += 18;

        reasons.push(
            "Multiple correlated credential and verification signals form a high-risk pattern"
        );

        signals.push(
            "high_risk_credential_combination"
        );

    }


    // =====================================================
    // 16. EXECUTABLE DOWNLOAD
    // =====================================================

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
        ".vbs",
        ".hta",
        ".iso"

    ];

    const hasDangerousDownload =
        dangerousExtensions.some(
            extension =>
                pathname.endsWith(extension)
        );

    if (
        hasDangerousDownload
    ) {

        score += 25;

        reasons.push(
            "URL points to a potentially executable or installable file"
        );

        signals.push(
            "dangerous_download"
        );

    }


    // =====================================================
    // 17. SUSPICIOUS FILE PATH
    // =====================================================

    const suspiciousFileTerms = [
        "payload",
        "dropper",
        "malware",
        "stealer",
        "keylogger",
        "crack",
        "loader"
    ];

    const suspiciousFileFound =
        suspiciousFileTerms.some(
            term =>
                pathname.includes(term)
        );

    if (
        suspiciousFileFound
    ) {

        score += 18;

        reasons.push(
            "URL path contains suspicious file or malware-related terminology"
        );

        signals.push(
            "suspicious_file_path"
        );

    }


    // =====================================================
    // 18. URGENCY / REWARD + AUTHENTICATION
    // =====================================================

    const urgencyTerms = [

        "urgent",
        "immediately",
        "expire",
        "suspended",
        "limited",
        "claim",
        "reward",
        "bonus",
        "free",
        "unlock"

    ];

    const urgencyFound =
        urgencyTerms.some(
            term =>
                fullURL.includes(term)
        );

    if (
        urgencyFound &&
        (
            hasAuthenticationSignal ||
            hasCredentialSignal
        )
    ) {

        score += 15;

        reasons.push(
            "Urgency, reward, or account-pressure language is combined with authentication or credential indicators"
        );

        signals.push(
            "urgency_auth_combination"
        );

    }


    // =====================================================
    // 19. MULTIPLE SUSPICIOUS SIGNALS
    // =====================================================

    if (
        signals.length >= 4
    ) {

        score += 8;

        reasons.push(
            "Several independent suspicious URL signals are present"
        );

        signals.push(
            "multiple_independent_signals"
        );

    }


    // =====================================================
    // SCORE
    // =====================================================

    score =
        Math.min(
            Math.max(
                Math.round(score),
                0
            ),
            100
        );


    let level;

    if (
        score <= 30
    ) {

        level = "LOW";

    } else if (
        score <= 60
    ) {

        level = "MEDIUM";

    } else {

        level = "HIGH";

    }


    return {

        riskScore: score,

        level,

        reasons,

        signals

    };

}


// =========================================================
// SAFE PREVIEW URL VALIDATION
// =========================================================

function validatePreviewURL(
    inputURL
) {

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


    // =====================================================
    // LOCALHOST
    // =====================================================

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


    // =====================================================
    // INTERNAL HOSTNAMES
    // =====================================================

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


    // =====================================================
    // PRIVATE IP RANGES
    // =====================================================

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
// SCORE COMBINATION
// =========================================================

function calculateFinalScore(
    ruleResult,
    aiResult,
    threatIntel
) {

    const ruleScore =
        Number(
            ruleResult?.riskScore || 0
        );

    const aiScore =
        Number(
            aiResult?.riskScore || 0
        );

    const aiConfidence =
        Number(
            aiResult?.confidence || 0
        );


    // =====================================================
    // KNOWN MALICIOUS = STRONG OVERRIDE
    // =====================================================

    if (
        threatIntel?.knownThreat === true
    ) {

        return 95;

    }


    // =====================================================
    // AI SCORE IS WEIGHTED BY CONFIDENCE
    // =====================================================

    let aiWeight = 0.35;

    if (
        aiConfidence >= 90
    ) {

        aiWeight = 0.45;

    } else if (
        aiConfidence >= 75
    ) {

        aiWeight = 0.40;

    } else if (
        aiConfidence >= 60
    ) {

        aiWeight = 0.30;

    } else {

        aiWeight = 0.20;

    }


    const ruleWeight =
        1 - aiWeight;


    let combinedScore =
        (
            ruleScore * ruleWeight
        ) +
        (
            aiScore * aiWeight
        );


    // =====================================================
    // STRONG OBJECTIVE EVIDENCE
    // =====================================================

    const strongSignals =
        ruleResult?.signals || [];

    const strongEvidence =
        strongSignals.some(
            signal =>
                [
                    "at_symbol",
                    "ip_host",
                    "dangerous_download",
                    "sensitive_parameter",
                    "high_risk_credential_combination",
                    "credential_path_combination"
                ].includes(signal)
        );


    if (
        strongEvidence &&
        aiConfidence >= 80 &&
        aiScore >= 70
    ) {

        combinedScore += 10;

    }


    // =====================================================
    // MULTIPLE SIGNAL + HIGH AI AGREEMENT
    // =====================================================

    if (
        strongSignals.length >= 4 &&
        aiConfidence >= 80 &&
        aiScore >= 75
    ) {

        combinedScore += 8;

    }


    // =====================================================
    // DON'T LET AI CREATE A HIGH RESULT FROM NOTHING
    // =====================================================

    if (
        ruleScore <= 10 &&
        aiScore >= 80 &&
        aiConfidence >= 85
    ) {

        combinedScore =
            Math.min(
                combinedScore,
                45
            );

    }


    return Math.min(
        Math.max(
            Math.round(combinedScore),
            0
        ),
        100
    );

}


// =========================================================
// FINAL LEVEL
// =========================================================

function getFinalLevel(score) {

    if (
        score <= 30
    ) {

        return "LOW";

    }

    if (
        score <= 60
    ) {

        return "MEDIUM";

    }

    return "HIGH";

}


// =========================================================
// URL SCAN API
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
            // 2. LOCAL RULE ENGINE
            // =================================================

            const ruleResult =
                analyzeURL(
                    normalizedURL
                );


            console.log(
                "LINKSHIELD URL:",
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

            }


            console.log(
                "AI RESULT:",
                aiResult
            );


            // =================================================
            // 5. FINAL SCORE
            // =================================================

            const finalScore =
                calculateFinalScore(
                    ruleResult,
                    aiResult,
                    threatIntel
                );


            const finalLevel =
                getFinalLevel(
                    finalScore
                );


            // =================================================
            // 6. REASONS
            // =================================================

            const reasons = [
                ...(ruleResult.reasons || [])
            ];


            if (
                threatIntel.knownThreat
            ) {

                reasons.push(

                    `Known malicious URL detected by: ${
                        threatIntel.sources.length
                            ? threatIntel.sources.join(", ")
                            : "connected threat intelligence"
                    }`

                );

            }


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
                        !reasons.includes(
                            `AI assessment: ${indicator}`
                        )
                    ) {

                        reasons.push(
                            `AI assessment: ${indicator}`
                        );

                    }

                }

            }


            // =================================================
            // 7. SCORE BREAKDOWN
            // =================================================

            const scoreBreakdown = {

                ruleScore:
                    ruleResult.riskScore,

                aiScore:
                    Number(
                        aiResult?.riskScore || 0
                    ),

                aiConfidence:
                    Number(
                        aiResult?.confidence || 0
                    ),

                threatIntelConfirmed:
                    Boolean(
                        threatIntel.knownThreat
                    ),

                scoringMethod:
                    threatIntel.knownThreat
                        ? "Threat intelligence override"
                        : "Weighted rule engine + AI analysis"

            };


            // =================================================
            // 8. RESPONSE
            // =================================================

            return res.json({

                url:
                    normalizedURL,

                riskScore:
                    finalScore,

                level:
                    finalLevel,

                reasons,

                signals:
                    ruleResult.signals || [],

                scoreBreakdown,

                threatIntel: {

                    knownThreat:
                        Boolean(
                            threatIntel.knownThreat
                        ),

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

                    available:
                        Boolean(aiResult),

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
                        "Review the domain and available security indicators before interacting with the URL.",

                    indicators:
                        Array.isArray(
                            aiResult?.indicators
                        )
                            ? aiResult.indicators
                            : []

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


        if (
            !validation.valid
        ) {

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


        if (
            !validation.valid
        ) {

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
                "running",

            aiConfigured:
                Boolean(
                    process.env.OPENAI_API_KEY
                ),

            threatIntel:
                "URLhaus"

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


            if (
                !validation.valid
            ) {

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

        console.log(
            `AI configured: ${
                Boolean(
                    process.env.OPENAI_API_KEY
                )
            }`
        );

    }
);