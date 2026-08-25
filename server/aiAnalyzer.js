require("dotenv").config();

const axios = require("axios");

/*
=========================================================
LINKSHIELD AI ANALYZER
=========================================================

This module:
1. Uses rule-based URL information.
2. Generates context-aware recommendations.
3. Optionally uses an AI API if OPENAI_API_KEY exists.
4. Never gives the same recommendation for every URL.
=========================================================
*/


// =======================================================
// CONTEXT-AWARE RECOMMENDATION
// =======================================================

function generateRecommendation(
    url,
    riskScore,
    level,
    reasons = [],
    threatIntel = {}
) {
    const text = `${url} ${reasons.join(" ")}`.toLowerCase();


    // ---------------------------------------------------
    // KNOWN MALICIOUS URL
    // ---------------------------------------------------

    if (threatIntel.knownThreat) {
        return (
            "Do not open or interact with this URL. " +
            "It has been identified as a known malicious threat."
        );
    }


    // ---------------------------------------------------
    // HIGH RISK
    // ---------------------------------------------------

    if (level === "HIGH" || riskScore > 60) {
        return (
            "Avoid opening this website. " +
            "The URL contains multiple high-risk indicators."
        );
    }


    // ---------------------------------------------------
    // LOGIN / SIGN IN
    // ---------------------------------------------------

    if (
        text.includes("login") ||
        text.includes("sign in") ||
        text.includes("signin") ||
        text.includes("log in")
    ) {
        return (
            "Check that the domain is the official website " +
            "before entering your login credentials."
        );
    }


    // ---------------------------------------------------
    // VERIFICATION
    // ---------------------------------------------------

    if (
        text.includes("verify") ||
        text.includes("verification") ||
        text.includes("confirm account") ||
        text.includes("account verification")
    ) {
        return (
            "If this is an account verification request, " +
            "confirm that it came from the official website " +
            "before continuing."
        );
    }


    // ---------------------------------------------------
    // PASSWORD RESET
    // ---------------------------------------------------

    if (
        text.includes("password") ||
        text.includes("reset password") ||
        text.includes("forgot password")
    ) {
        return (
            "For password changes, use the official website " +
            "or app directly rather than relying on the link."
        );
    }


    // ---------------------------------------------------
    // PAYMENT / CHECKOUT
    // ---------------------------------------------------

    if (
        text.includes("payment") ||
        text.includes("checkout") ||
        text.includes("billing") ||
        text.includes("credit card") ||
        text.includes("card")
    ) {
        return (
            "Check the domain and HTTPS connection carefully " +
            "before entering payment or financial information."
        );
    }


    // ---------------------------------------------------
    // CRYPTO / WALLET
    // ---------------------------------------------------

    if (
        text.includes("wallet") ||
        text.includes("crypto") ||
        text.includes("connect wallet") ||
        text.includes("metamask")
    ) {
        return (
            "Do not connect a crypto wallet unless you " +
            "recognize and trust the website and its domain."
        );
    }


    // ---------------------------------------------------
    // DOWNLOAD
    // ---------------------------------------------------

    if (
        text.includes("download") ||
        text.includes(".exe") ||
        text.includes(".zip") ||
        text.includes(".dmg")
    ) {
        return (
            "Verify the source before downloading files " +
            "from this website."
        );
    }


    // ---------------------------------------------------
    // MEDIUM RISK
    // ---------------------------------------------------

    if (level === "MEDIUM" || riskScore > 30) {
        return (
            "Proceed with caution. Review the domain and URL " +
            "indicators before interacting with the website."
        );
    }


    // ---------------------------------------------------
    // LOW RISK
    // ---------------------------------------------------

    return (
        "No major suspicious indicators were detected. " +
        "You can browse normally, but avoid sharing sensitive " +
        "information unless you trust the website."
    );
}


// =======================================================
// LOCAL AI-STYLE EXPLANATION
// =======================================================

function generateLocalExplanation(
    url,
    ruleResult,
    threatIntel
) {
    const reasons = ruleResult.reasons || [];

    if (threatIntel.knownThreat) {
        return (
            "Threat intelligence identified this URL as potentially " +
            "malicious. LinkShield recommends avoiding interaction " +
            "with the website."
        );
    }

    if (ruleResult.level === "HIGH") {
        if (reasons.length > 0) {
            return (
                "The URL has a high risk score because LinkShield " +
                "detected suspicious indicators including: " +
                reasons.join(", ") +
                "."
            );
        }

        return (
            "The URL received a high risk score based on the " +
            "security analysis performed by LinkShield."
        );
    }

    if (ruleResult.level === "MEDIUM") {
        if (reasons.length > 0) {
            return (
                "The URL contains some indicators that require " +
                "caution, including: " +
                reasons.join(", ") +
                "."
            );
        }

        return (
            "The URL has some potentially suspicious characteristics, " +
            "so LinkShield recommends caution before interacting with it."
        );
    }

    if (reasons.length > 0) {
        return (
            "The URL has a low overall risk score, although LinkShield " +
            "detected the following minor indicators: " +
            reasons.join(", ") +
            "."
        );
    }

    return (
        "LinkShield did not detect major suspicious indicators " +
        "in the URL using the available security checks."
    );
}


// =======================================================
// OPTIONAL OPENAI ANALYSIS
// =======================================================

async function analyzeWithOpenAI(
    url,
    ruleResult,
    threatIntel
) {
    const apiKey = process.env.OPENAI_API_KEY;

    // No API key -> use local analysis
    if (!apiKey) {
        return null;
    }

    try {
        const prompt = `
You are a cybersecurity URL analysis assistant.

Analyze this URL:

URL:
${url}

Rule-based risk score:
${ruleResult.riskScore}

Rule-based risk level:
${ruleResult.level}

Detected reasons:
${JSON.stringify(ruleResult.reasons)}

Known threat:
${threatIntel.knownThreat}

Threat sources:
${JSON.stringify(threatIntel.sources || [])}

Provide a short cybersecurity explanation.

Important:
- Do not claim that a website is safe with certainty.
- Do not invent threat intelligence.
- Do not tell the user to enter sensitive information.
- Give a recommendation appropriate to the apparent purpose of the URL.
- If the URL appears related to login, mention credentials.
- If it appears related to verification, mention verification.
- If it appears related to payment, mention payment information.
- If it appears related to crypto/wallets, mention wallet safety.
- If it appears related to downloading, mention file safety.
- If it is a normal website, give a normal browsing recommendation.

Return ONLY valid JSON:

{
    "explanation": "...",
    "recommendation": "..."
}
`;

        const response = await axios.post(
            "https://api.openai.com/v1/chat/completions",
            {
                model:
                    process.env.OPENAI_MODEL ||
                    "gpt-4o-mini",

                messages: [
                    {
                        role: "system",
                        content:
                            "You are a cybersecurity URL analysis assistant."
                    },
                    {
                        role: "user",
                        content: prompt
                    }
                ],

                temperature: 0.2,

                response_format: {
                    type: "json_object"
                }
            },
            {
                timeout: 20000,

                headers: {
                    "Content-Type": "application/json",
                    Authorization:
                        `Bearer ${apiKey}`
                }
            }
        );

        const content =
            response.data?.choices?.[0]?.message?.content;

        if (!content) {
            return null;
        }

        const parsed = JSON.parse(content);

        if (
            typeof parsed.explanation !== "string" ||
            typeof parsed.recommendation !== "string"
        ) {
            return null;
        }

        return {
            explanation: parsed.explanation,
            recommendation: parsed.recommendation
        };

    } catch (error) {
        console.error(
            "OpenAI analysis unavailable:",
            error.message
        );

        return null;
    }
}


// =======================================================
// MAIN ANALYZER
// =======================================================

async function analyzeWithAI(
    url,
    ruleResult,
    threatIntel
) {
    try {

        // -------------------------------------------------
        // LOCAL ANALYSIS
        // -------------------------------------------------

        const localExplanation =
            generateLocalExplanation(
                url,
                ruleResult,
                threatIntel
            );

        const localRecommendation =
            generateRecommendation(
                url,
                ruleResult.riskScore,
                ruleResult.level,
                ruleResult.reasons,
                threatIntel
            );


        // -------------------------------------------------
        // TRY AI ANALYSIS
        // -------------------------------------------------

        const aiResult =
            await analyzeWithOpenAI(
                url,
                ruleResult,
                threatIntel
            );


        // -------------------------------------------------
        // AI AVAILABLE
        // -------------------------------------------------

        if (aiResult) {

            return {
                riskScore: ruleResult.riskScore,

                explanation:
                    aiResult.explanation,

                recommendation:
                    aiResult.recommendation
            };
        }


        // -------------------------------------------------
        // AI UNAVAILABLE
        // LOCAL FALLBACK
        // -------------------------------------------------

        return {
            riskScore: ruleResult.riskScore,

            explanation:
                localExplanation,

            recommendation:
                localRecommendation
        };

    } catch (error) {

        console.error(
            "AI Analyzer Error:",
            error.message
        );

        // -------------------------------------------------
        // FINAL FALLBACK
        // -------------------------------------------------

        return {
            riskScore: ruleResult.riskScore,

            explanation:
                generateLocalExplanation(
                    url,
                    ruleResult,
                    threatIntel
                ),

            recommendation:
                generateRecommendation(
                    url,
                    ruleResult.riskScore,
                    ruleResult.level,
                    ruleResult.reasons,
                    threatIntel
                )
        };
    }
}


// =======================================================
// EXPORT
// =======================================================

module.exports = {
    analyzeWithAI
};