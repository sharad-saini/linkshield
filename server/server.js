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
            level: "CRITICAL",
            reasons: ["Invalid or empty URL"],
            evidenceCount: 1,
            hasStrongEvidence: true
        };
    }

    let url;

    try {
        url = new URL(normalizedURL);
    } catch {
        return {
            riskScore: 100,
            level: "CRITICAL",
            reasons: ["Invalid URL format"],
            evidenceCount: 1,
            hasStrongEvidence: true
        };
    }

    const hostname = url.hostname.toLowerCase();
    const pathname = url.pathname.toLowerCase();
    const search = url.search.toLowerCase();
    const fullURL = normalizedURL.toLowerCase();
    const reasons = [];
    let score = 0;

    const add = (points, reason) => {
        score += points;
        reasons.push(reason);
    };

    // 1. Transport
    if (url.protocol !== "https:") {
        add(10, "Connection does not use HTTPS");
    }

    // 2. Raw IP destination
    const ipPattern = /^(?:\d{1,3}\.){3}\d{1,3}$/;
    const isRawIP = ipPattern.test(hostname);

    if (isRawIP) {
        add(25, "URL uses an IP address instead of a domain");
    }

    // 3. User-info / @ deception
    if (url.username || url.password || fullURL.includes("@")) {
        add(
            30,
            "URL contains user-info/@ syntax that can obscure the actual destination"
        );
    }

    // 4. Punycode
    if (hostname.includes("xn--")) {
        add(20, "Hostname contains a punycode label");
    }

    // 5. Excessive subdomains
    const hostnameParts = hostname.split(".").filter(Boolean);
    const subdomainCount = Math.max(0, hostnameParts.length - 2);

    if (subdomainCount >= 4) {
        add(10, "URL contains an unusually deep subdomain structure");
    } else if (subdomainCount >= 3) {
        add(5, "URL contains multiple subdomain levels");
    }

    // 6. URL shorteners
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

    // 7. URL complexity / encoding
    if (normalizedURL.length > 220) {
        add(5, "URL is unusually long");
    }

    if ((normalizedURL.match(/%[0-9a-f]{2}/gi) || []).length >= 8) {
        add(8, "URL contains unusually heavy percent-encoding");
    }

    // 8. Credential indicators
    const credentialTerms = [
        "password",
        "passwd",
        "credential",
        "username",
        "secret",
        "otp",
        "pin",
        "token",
        "wallet"
    ];

    const credentialMatches = credentialTerms.filter((term) =>
        fullURL.includes(term)
    );

    const hasCredentialSignal = credentialMatches.length > 0;

    if (credentialMatches.length >= 2) {
        add(18, "URL contains multiple credential-related indicators");
    } else if (hasCredentialSignal) {
        add(12, "URL contains a credential-related indicator");
    }

    // 9. Sensitive query parameters
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
        "api_key",
        "wallet"
    ]);

    let sensitiveParameterFound = false;

    for (const [key] of url.searchParams.entries()) {
        if (sensitiveParameters.has(key.toLowerCase())) {
            sensitiveParameterFound = true;
            break;
        }
    }

    if (sensitiveParameterFound) {
        add(15, "URL contains a sensitive credential-related parameter");
    }

    // 10. Authentication / verification signals
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
        "recover",
        "security"
    ];

    const authenticationMatches = authenticationTerms.filter((term) =>
        fullURL.includes(term)
    );

    const hasAuthenticationSignal = authenticationMatches.length > 0;
    const multipleAuthenticationSignals =
        authenticationMatches.length >= 2;

    if (authenticationMatches.length >= 4) {
        add(
            12,
            "URL contains many authentication or account-verification indicators"
        );
    } else if (multipleAuthenticationSignals) {
        add(
            8,
            "Multiple authentication or account-verification indicators are present"
        );
    }

    const credentialPath =
        /\/(login|signin|sign-in|verify|verification|account|security|password|reset|recover)(?:[/?#]|$)/i;

    const credentialPathFound = credentialPath.test(pathname);

    if (credentialPathFound && hasCredentialSignal) {
        add(
            12,
            "Authentication-related path is combined with credential indicators"
        );
    }

    // 11. Brand impersonation
    // A brand keyword in a hostname is high-signal when the actual
    // registrable domain is not the brand's legitimate domain.
    const brandDomains = {
        paypal: ["paypal.com"],
        microsoft: ["microsoft.com", "live.com", "office.com", "outlook.com"],
        apple: ["apple.com", "icloud.com"],
        amazon: ["amazon.com", "amazon.in"],
        google: ["google.com"],
        facebook: ["facebook.com", "fb.com"],
        instagram: ["instagram.com"],
        netflix: ["netflix.com"],
        linkedin: ["linkedin.com"],
        github: ["github.com"],
        binance: ["binance.com"],
        coinbase: ["coinbase.com"]
    };

    const registrableDomain = hostnameParts.length >= 2
        ? hostnameParts.slice(-2).join(".")
        : hostname;

    const brandMatches = Object.entries(brandDomains)
        .filter(([brand]) => {
            const brandPattern = new RegExp(
                `(^|[-._])${brand.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}([-. _]|$)`,
                "i"
            );
            return brandPattern.test(hostname);
        })
        .map(([brand]) => brand);

    const impersonatedBrands = brandMatches.filter((brand) =>
        !brandDomains[brand].some(
            (domain) =>
                hostname === domain ||
                hostname.endsWith(`.${domain}`)
        )
    );

    if (impersonatedBrands.length > 0) {
        add(
            25,
            `Possible brand impersonation detected: ${impersonatedBrands.join(", ")}`
        );
    }

    // 12. Dangerous downloads
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

    if (
        dangerousExtensions.some((extension) =>
            pathname.endsWith(extension)
        )
    ) {
        add(
            25,
            "URL points to a potentially executable or installable file"
        );
    }

    // 13. Urgency / reward language
    const urgencyTerms = [
        "urgent",
        "immediately",
        "expire",
        "expired",
        "suspended",
        "limited",
        "claim",
        "reward",
        "bonus",
        "free",
        "alert"
    ];

    const urgencyFound = urgencyTerms.some((term) =>
        fullURL.includes(term)
    );

    if (urgencyFound && hasAuthenticationSignal) {
        add(
            12,
            "Urgency or reward language is combined with authentication-related signals"
        );
    }

    // 14. Strong correlated phishing patterns
    const strongCredentialPattern =
        multipleAuthenticationSignals &&
        hasCredentialSignal &&
        (sensitiveParameterFound || credentialPathFound);

    if (strongCredentialPattern) {
        add(
            18,
            "Multiple correlated authentication and credential signals form a strong phishing pattern"
        );
    }

    // 15. Additional strong combinations
    if (
        isRawIP &&
        hasAuthenticationSignal &&
        hasCredentialSignal
    ) {
        add(
            15,
            "IP-hosted destination is combined with authentication and credential signals"
        );
    }

    if (
        impersonatedBrands.length > 0 &&
        hasAuthenticationSignal
    ) {
        add(
            15,
            "Brand impersonation is combined with account or login activity"
        );
    }

    if (
        impersonatedBrands.length > 0 &&
        hasCredentialSignal
    ) {
        add(
            15,
            "Brand impersonation is combined with credential-related content"
        );
    }

    // Generic financial / wallet deception is also strong when the
    // hostname and path jointly request authentication or credentials.
    const financialTerms = [
        "bank",
        "banking",
        "payment",
        "wallet",
        "crypto",
        "bitcoin",
        "card"
    ];

    const financialSignal = financialTerms.some((term) =>
        hostname.includes(term)
    );

    if (
        financialSignal &&
        hasAuthenticationSignal &&
        hasCredentialSignal
    ) {
        add(
            20,
            "Financial or wallet-related hostname is combined with authentication and credential signals"
        );
    }

    // 16. Final deterministic score
    score = Math.min(Math.max(Math.round(score), 0), 100);

    let level = "LOW";

    if (score >= 86) {
        level = "CRITICAL";
    } else if (score >= 61) {
        level = "HIGH";
    } else if (score >= 31) {
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
            impersonatedBrands.length > 0 ||
            (isRawIP && hasCredentialSignal) ||
            dangerousExtensions.some((extension) =>
                pathname.endsWith(extension)
            )
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

            if (finalScore >= 86) {

                finalLevel = "CRITICAL";

            } else if (finalScore >= 61) {

                finalLevel = "HIGH";

            } else if (finalScore >= 31) {

                finalLevel = "MEDIUM";

            } else {

                finalLevel = "LOW";

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
                await Promise.race([
                    getInteractivePreview(
                        validation.url
                    ),
                    new Promise((_, reject) =>
                        setTimeout(
                            () => reject(
                                new Error(
                                    "Preview timed out after 10 seconds. The destination may use bot protection or may be too slow to render."
                                )
                            ),
                            10000
                        )
                    )
                ]);


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