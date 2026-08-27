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

app.use(cors({
    origin: "https://linkshield-kappa.vercel.app"
}));
app.use(
    express.json({
        limit: "100kb"
    })
);


// =========================================================
// LINKSHIELD URL RISK ENGINE
// =========================================================
//
// Important design:
//
// 1. URL heuristics provide objective technical signals.
// 2. Threat intelligence provides known-threat evidence.
// 3. AI acts as a secondary analytical layer.
// 4. AI cannot invent threat intelligence.
// 5. Unknown does NOT mean malicious.
// 6. A normal login/account URL is NOT automatically HIGH.
// 7. Multiple correlated suspicious signals increase risk.
//
// =========================================================


function normalizeURL(inputURL) {

    if (!inputURL || typeof inputURL !== "string") {
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


function analyzeURL(inputURL) {

    let score = 0;

    const reasons = [];

    const normalizedURL = normalizeURL(inputURL);

    let url;


    try {

        url = new URL(normalizedURL);

    } catch {

        return {
            riskScore: 100,
            level: "HIGH",
            reasons: [
                "Invalid URL format"
            ]
        };

    }

    const hostname =
        url.hostname.toLowerCase();

    const pathname =
        url.pathname.toLowerCase();
        
        const fullURL =
        normalizedURL.toLowerCase();
    // =====================================================
    // 1. CONNECTION SECURITY
    // =====================================================
    //
    // HTTP is a weakness, but HTTP alone is NOT proof
    // of malicious behavior.
    //
    // =====================================================

    if (url.protocol !== "https:") {

        score += 10;

        reasons.push(
            "Connection does not use HTTPS"
        );

    }


    // =====================================================
    // 2. RAW IP ADDRESS
    // =====================================================
    //
    // Legitimate systems can use IP addresses, so this
    // is treated as a strong signal, not automatic malware.
    //
    // =====================================================

    const ipPattern =
        /^(?:\d{1,3}\.){3}\d{1,3}$/;


    if (ipPattern.test(hostname)) {

        score += 25;

        reasons.push(
            "URL uses an IP address instead of a domain"
        );

    }


    // =====================================================
    // 3. @ SYMBOL / USERINFO OBFUSCATION
    // =====================================================

    if (inputURL.includes("@")) {

        score += 30;

        reasons.push(
            "URL contains @ symbol, which can be used to obscure the actual destination"
        );

    }


    // =====================================================
    // 4. UNUSUALLY LONG URL
    // =====================================================

    if (inputURL.length > 150) {

        score += 8;

        reasons.push(
            "URL is unusually long"
        );

    }


    // =====================================================
    // 5. EXCESSIVE SUBDOMAINS
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


    if (subdomainCount >= 4) {

        score += 10;

        reasons.push(
            "URL contains an unusually deep subdomain structure"
        );

    }


    // =====================================================
    // 6. PUNYCODE / INTERNATIONALIZED HOSTNAME
    // =====================================================
    //
    // Punycode is legitimate, but it deserves a small
    // amount of scrutiny because homograph attacks can
    // use visually similar characters.
    //
    // =====================================================

    if (hostname.includes("xn--")) {

        score += 15;

        reasons.push(
            "Hostname contains an internationalized/punycode label"
        );

    }


    // =====================================================
    // 7. SUSPICIOUS URL SHORTENERS
    // =====================================================

    const shorteners = [

        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly",
        "ow.ly",
        "shorturl.at"

    ];


    if (
        shorteners.includes(hostname)
    ) {

        score += 18;

        reasons.push(
            "Uses a URL shortening service"
        );

    }


    // =====================================================
    // 8. SECURITY / ACCOUNT KEYWORDS
    // =====================================================
    //
    // Important:
    //
    // These words alone are NOT treated as malicious.
    //
    // Example:
    //
    // https://leetcode.com/login
    //
    // should remain LOW.
    //
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
        "free"

    ];


    const foundWords =
        suspiciousWords.filter(
            word =>
                fullURL.includes(word)
        );


    if (foundWords.length > 0) {

        score += Math.min(
            foundWords.length * 2,
            8
        );

        reasons.push(
            `Contains security-sensitive keyword(s): ${foundWords.join(", ")}`
        );

    }


    // =====================================================
    // 9. AUTHENTICATION COMBINATION
    // =====================================================
    //
    // One login page is normal.
    //
    // Several authentication terms together deserve
    // additional attention.
    //
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

    }


    // =====================================================
    // 10. CREDENTIAL-RELATED CONTENT
    // =====================================================

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

    }


    // =====================================================
    // 11. SENSITIVE QUERY PARAMETERS
    // =====================================================
    //
    // A URL explicitly carrying password/token/OTP style
    // parameters is considerably more concerning.
    //
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
        "api_key"

    ];


    let sensitiveParameterFound =
        false;


    for (
        const parameter
        of sensitiveParameters
    ) {

        if (
            url.searchParams.has(
                parameter
            )
        ) {

            sensitiveParameterFound =
                true;

            break;

        }

    }


    if (
        sensitiveParameterFound
    ) {

        score += 15;

        reasons.push(
            "URL contains a sensitive credential-related parameter"
        );

    }


    // =====================================================
    // 12. DECEPTIVE SECURITY HOSTNAME
    // =====================================================
    //
    // We do NOT maintain a giant trusted-site whitelist.
    //
    // Instead, we look for suspicious combinations in
    // the hostname itself.
    //
    // Example:
    //
    // paypal-security-verification.example.com
    //
    // contains multiple security/verification concepts
    // before the actual registered domain.
    //
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
        "confirm"

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

    }


    // =====================================================
    // 13. SUSPICIOUS AUTHENTICATION PATH
    // =====================================================

    const credentialPath =
        /\/(login|signin|verify|verification|account|security|password|reset|recover)[^/]*(\/|$)/i;


    if (
        credentialPath.test(pathname) &&
        credentialMatches.length > 0
    ) {

        score += 10;

        reasons.push(
            "Authentication-related path is combined with credential indicators"
        );

    }


    // =====================================================
    // 14. HIGH-RISK CREDENTIAL COMBINATION
    // =====================================================
    //
    // This is deliberately based on multiple independent
    // signals rather than a single keyword.
    //
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

        score += 15;

        reasons.push(
            "Multiple correlated credential and verification signals form a high-risk pattern"
        );

    }


    // =====================================================
    // 15. DOWNLOAD / EXECUTABLE INDICATORS
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
        ".dmg"

    ];


    const hasDangerousDownload =
        dangerousExtensions.some(
            extension =>
                pathname.endsWith(extension)
        );


    if (
        hasDangerousDownload
    ) {

        score += 18;

        reasons.push(
            "URL points to a potentially executable or installable file"
        );

    }


    // =====================================================
    // 16. URGENT / REWARD + ACCOUNT COMBINATION
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
        "free"

    ];


    const urgencyFound =
        urgencyTerms.some(
            term =>
                fullURL.includes(term)
        );


    if (
        urgencyFound &&
        hasAuthenticationSignal
    ) {

        score += 10;

        reasons.push(
            "Urgency or reward language is combined with authentication-related signals"
        );

    }


    // =====================================================
    // FINAL SCORE
    // =====================================================

    score = Math.min(
        Math.max(score, 0),
        100
    );


    // =====================================================
    // FINAL LOCAL LEVEL
    // =====================================================

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

            message:
                "Invalid URL"

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


    // -----------------------------------------------------
    // BLOCK LOCALHOST
    // -----------------------------------------------------

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


    // -----------------------------------------------------
    // BLOCK INTERNAL HOSTNAMES
    // -----------------------------------------------------

    const blockedHostnames = [

        "metadata.google.internal",
        "metadata.google",
        "host.docker.internal"

    ];


    if (
        blockedHostnames.includes(
            hostname
        )
    ) {

        return {

            valid: false,

            message:
                "Internal host preview is not allowed"

        };

    }


    // -----------------------------------------------------
    // BLOCK PRIVATE / INTERNAL IP RANGES
    // -----------------------------------------------------

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
            blockedRanges.includes(
                range
            )
        ) {

            return {

                valid: false,

                message:
                    "Private or internal IP addresses cannot be previewed"

            };

        }

    } catch {

        // Normal hostname.
        // Continue validation.

    }


    return {

        valid: true,

        url:
            parsed.toString()

    };

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


        if (!url) {

            return res.status(400).json({

                error:
                    "URL is required"

            });

        }


        try {

            // ------------------------------------------------
            // 1. LOCAL TECHNICAL ANALYSIS
            // ------------------------------------------------

            const normalizedURL = normalizeURL(url);

            if (!normalizedURL) {
                return res.status(400).json({
                    error: "URL is required"
                });
            }
            
            const ruleResult =
                analyzeURL(
                    normalizedURL
                );
            
            const threatIntel =
                await checkThreatIntel(
                    normalizedURL
                );
            
            const aiResult =
                await analyzeWithAI(
                    normalizedURL,
                    ruleResult,
                    threatIntel
                );
            // ------------------------------------------------
            // 4. FINAL SCORE
            // ------------------------------------------------
            //
            // The deterministic technical analysis is the
            // baseline.
            //
            // Confirmed threat intelligence can only increase
            // the score.
            //
            // AI is treated as a secondary opinion rather than
            // unquestioned proof.
            //
            // ------------------------------------------------

            let finalScore =
                ruleResult.riskScore;


            // ------------------------------------------------
            // CONFIRMED THREAT INTELLIGENCE
            // ------------------------------------------------

            if (
                threatIntel.knownThreat
            ) {

                finalScore =
                    Math.max(
                        finalScore,
                        90
                    );

            }


            // ------------------------------------------------
            // AI SECOND OPINION
            // ------------------------------------------------
            //
            // Only allow a strong AI assessment to increase
            // a result when:
            //
            // - AI confidence is high
            // - AI classification is HIGH/CRITICAL
            // - there is already objective suspicious evidence
            //
            // This prevents AI hallucinations from turning
            // normal websites into HIGH risk.
            //
            // ------------------------------------------------

            const aiConfidence =
                Number(
                    aiResult?.confidence || 0
                );


            const aiScore =
                Number(
                    aiResult?.riskScore || 0
                );


            const aiClassification =
                String(
                    aiResult?.classification ||
                    ""
                ).toUpperCase();


            const hasObjectiveEvidence =
                ruleResult.reasons.length >= 2;


            if (
                aiConfidence >= 85 &&
                hasObjectiveEvidence &&
                (
                    aiClassification === "HIGH" ||
                    aiClassification === "CRITICAL"
                ) &&
                aiScore > finalScore
            ) {

                // AI can strengthen the result, but cannot
                // jump an otherwise weak URL straight to 100.
                //
                // Maximum AI contribution:
                // +25 points over deterministic score.

                finalScore =
                    Math.max(
                        finalScore,
                        Math.min(
                            aiScore,
                            finalScore + 25
                        )
                    );

            }


            // ------------------------------------------------
            // FINAL SCORE BOUNDARY
            // ------------------------------------------------

            finalScore =
                Math.min(
                    Math.max(
                        Math.round(
                            finalScore
                        ),
                        0
                    ),
                    100
                );


            // ------------------------------------------------
            // FINAL RISK LEVEL
            // ------------------------------------------------

            let finalLevel;


            if (
                finalScore <= 30
            ) {

                finalLevel = "LOW";

            } else if (
                finalScore <= 60
            ) {

                finalLevel = "MEDIUM";

            } else {

                finalLevel = "HIGH";

            }


            // ------------------------------------------------
            // REASONS
            // ------------------------------------------------

            const reasons = [
                ...ruleResult.reasons
            ];


            if (
                threatIntel.knownThreat
            ) {

                reasons.push(
                    `Known malicious URL detected by: ${
                        threatIntel.sources?.join(
                            ", "
                        ) ||
                        "connected threat intelligence"
                    }`
                );

            }


            // ------------------------------------------------
            // AI INDICATORS
            // ------------------------------------------------

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
                        typeof indicator ===
                        "string" &&
                        indicator.trim() &&
                        !reasons.includes(
                            indicator
                        )
                    ) {

                        reasons.push(
                            `AI assessment: ${indicator}`
                        );

                    }

                }

            }


            // ------------------------------------------------
            // RESPONSE
            // ------------------------------------------------

// ------------------------------------------------
// RESPONSE
// ------------------------------------------------

// ------------------------------------------------
// RESPONSE
// ------------------------------------------------

return res.json({

    url: normalizedURL,

    riskScore: finalScore,

    level: finalLevel,

    reasons,

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

        classification:
            aiResult?.classification ||
            ruleResult.level,

        riskScore:
            Number.isFinite(
                aiResult?.riskScore
            )
                ? aiResult.riskScore
                : ruleResult.riskScore,

        confidence:
            Number.isFinite(
                aiResult?.confidence
            )
                ? aiResult.confidence
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

        const normalizedURL = normalizeURL(url);

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


        const validation =
            validatePreviewURL(
                url
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


            // ------------------------------------------------
            // Validate the asset hostname before requesting it.
            // ------------------------------------------------

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
                    .startsWith(
                        "image/"
                    )
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