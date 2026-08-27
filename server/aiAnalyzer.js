require("dotenv").config();

const axios = require("axios");


// =========================================================
// LINKSHIELD AI ANALYZER
// =========================================================
//
// AI is a secondary analytical layer.
//
// It:
// - receives objective URL signals
// - receives threat-intelligence results
// - evaluates combinations
// - provides explanation/recommendation
//
// It must NOT invent:
// - domain reputation
// - malware reports
// - domain age
// - ownership
// - external security intelligence
//
// =========================================================


// =========================================================
// LOCAL RECOMMENDATION
// =========================================================

function generateRecommendation(
    url,
    riskScore,
    level,
    reasons = [],
    threatIntel = {}
) {

    if (
        threatIntel.knownThreat
    ) {

        return (
            "Do not open or interact with this URL. " +
            "Connected threat intelligence identified it as a known malicious URL."
        );

    }


    if (
        riskScore >= 80
    ) {

        return (
            "Avoid interacting with this URL. " +
            "Multiple strong risk indicators were detected. " +
            "Do not enter passwords, OTPs, payment details, or wallet information."
        );

    }


    if (
        riskScore > 60 ||
        level === "HIGH"
    ) {

        return (
            "Proceed with extreme caution. " +
            "Verify the domain independently before entering sensitive information."
        );

    }


    if (
        riskScore > 30 ||
        level === "MEDIUM"
    ) {

        return (
            "Some suspicious indicators were detected. " +
            "Verify the destination before entering sensitive information."
        );

    }


    return (
        "No major malicious indicators were detected by the available checks. " +
        "Continue normal security practices."
    );

}


// =========================================================
// LOCAL EXPLANATION
// =========================================================

function generateLocalExplanation(
    url,
    ruleResult,
    threatIntel
) {

    if (
        threatIntel.knownThreat
    ) {

        return (
            "Connected threat intelligence identified this URL " +
            "as a known malicious threat."
        );

    }


    const reasons =
        ruleResult?.reasons || [];


    if (
        reasons.length === 0
    ) {

        return (
            "The available technical checks did not identify " +
            "major suspicious indicators in this URL."
        );

    }


    return (
        "LinkShield's local security engine identified these signals: " +
        reasons.join("; ") +
        ". These indicators increase risk but are not, by themselves, proof of maliciousness."
    );

}


// =========================================================
// OPENAI ANALYSIS
// =========================================================

async function analyzeWithOpenAI(
    url,
    ruleResult,
    threatIntel
) {

    const apiKey =
        process.env.OPENAI_API_KEY;


    if (
        !apiKey
    ) {

        console.log(
            "OPENAI_API_KEY is not configured."
        );

        return null;

    }


    const model =
        process.env.OPENAI_MODEL ||
        "gpt-4o-mini";


    try {

        const prompt = `
You are LinkShield's secondary cybersecurity URL analyst.

Analyze ONLY the evidence supplied below.

URL:
${url}

LOCAL TECHNICAL ANALYSIS:
${JSON.stringify(
    ruleResult,
    null,
    2
)}

THREAT INTELLIGENCE:
${JSON.stringify(
    threatIntel,
    null,
    2
)}

IMPORTANT SECURITY RULES:

1. A confirmed threat-intelligence match is strong evidence of maliciousness.

2. Never invent:
   - domain age
   - domain ownership
   - malware reports
   - reputation
   - blacklist membership
   - geographic information
   - external security findings

3. "Not found in threat intelligence" does NOT mean safe.

4. HTTPS alone is NOT evidence that a website is malicious.

5. Login, signin, account, secure, password, verification,
   payment, wallet, and similar words are NOT automatically malicious.

6. A legitimate website can naturally contain login,
   account, payment, verification, learning, coding,
   shopping, or wallet-related functionality.

7. Stronger concern comes from combinations such as:
   - IP-hosted authentication pages
   - @-based destination obfuscation
   - credential terms combined with authentication
   - sensitive credential query parameters
   - deceptive security terminology in hostnames
   - executable downloads
   - suspicious file names
   - urgency/reward language combined with credential requests
   - several independent suspicious signals

8. If the URL looks normal and there is no strong malicious evidence,
   classify it LOW.

9. Do not use the URL's brand name alone as proof of legitimacy.

10. Do not claim certainty.
    The classification represents the evidence available.

11. AI should distinguish between:
    - suspicious
    - potentially dangerous
    - known malicious

12. A known malicious threat-intelligence result should normally
    receive a very high score.

13. If threat intelligence is unavailable or empty,
    do not assume maliciousness.

SCORING GUIDANCE:

LOW:
0-30

MEDIUM:
31-60

HIGH:
61-85

CRITICAL:
86-100

The AI risk score must reflect the supplied evidence.

Examples:

Normal website:
LOW

Normal login page:
LOW or MEDIUM depending on additional evidence

IP + login + credential parameter:
HIGH or CRITICAL

Executable download + suspicious authentication:
HIGH or CRITICAL

Confirmed threat intelligence:
CRITICAL

Return ONLY valid JSON.

Required structure:

{
  "classification": "LOW",
  "riskScore": 10,
  "confidence": 90,
  "isLegitimate": true,
  "explanation": "Short evidence-based explanation.",
  "recommendation": "Practical security recommendation.",
  "indicators": []
}

Allowed classification values:

LOW
MEDIUM
HIGH
CRITICAL
UNKNOWN

Do not return markdown.
`;


        const response =
            await axios.post(

                "https://api.openai.com/v1/chat/completions",

                {

                    model,

                    messages: [

                        {

                            role:
                                "system",

                            content:
                                "You are a careful cybersecurity URL analyst. " +
                                "Avoid false positives and never invent evidence."

                        },

                        {

                            role:
                                "user",

                            content:
                                prompt

                        }

                    ],

                    temperature:
                        0.1,

                    response_format: {
                        type:
                            "json_object"
                    }

                },

                {

                    timeout:
                        15000,

                    headers: {

                        "Content-Type":
                            "application/json",

                        Authorization:
                            `Bearer ${apiKey}`

                    }

                }

            );


        const content =
            response
                ?.data
                ?.choices?.[0]
                ?.message?.content;


        if (
            !content
        ) {

            return null;

        }


        const parsed =
            JSON.parse(content);


        const allowedLevels = [

            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
            "UNKNOWN"

        ];


        const classification =
            String(
                parsed.classification || ""
            ).toUpperCase();


        if (
            !allowedLevels.includes(
                classification
            )
        ) {

            return null;

        }


        let score =
            Number(
                parsed.riskScore
            );


        let confidence =
            Number(
                parsed.confidence
            );


        if (
            !Number.isFinite(score) ||
            !Number.isFinite(confidence)
        ) {

            return null;

        }


        score =
            Math.min(
                Math.max(
                    Math.round(score),
                    0
                ),
                100
            );


        confidence =
            Math.min(
                Math.max(
                    Math.round(confidence),
                    0
                ),
                100
            );


        const explanation =
            typeof parsed.explanation === "string"
                ? parsed.explanation.trim()
                : "";


        const recommendation =
            typeof parsed.recommendation === "string"
                ? parsed.recommendation.trim()
                : "";


        if (
            !explanation ||
            !recommendation
        ) {

            return null;

        }


        const indicators =
            Array.isArray(
                parsed.indicators
            )
                ? parsed.indicators
                    .filter(
                        item =>
                            typeof item === "string" &&
                            item.trim()
                    )
                    .map(
                        item =>
                            item.trim()
                    )
                    .slice(0, 8)
                : [];


        return {

            classification,

            riskScore:
                score,

            confidence,

            isLegitimate:
                parsed.isLegitimate === true,

            explanation,

            recommendation,

            indicators,

            provider:
                "OpenAI",

            model,

            available:
                true

        };

    } catch (error) {

        console.error(
            "OpenAI analysis unavailable:",
            error.response?.data ||
            error.message
        );

        return null;

    }

}


// =========================================================
// MAIN ANALYZER
// =========================================================

async function analyzeWithAI(
    url,
    ruleResult,
    threatIntel
) {

    try {

        const aiResult =
            await analyzeWithOpenAI(
                url,
                ruleResult,
                threatIntel
            );


        if (
            aiResult
        ) {

            return aiResult;

        }


        // ===================================================
        // LOCAL FALLBACK
        // ===================================================

        const localScore =
            Number(
                ruleResult?.riskScore || 0
            );


        return {

            classification:
                ruleResult?.level ||
                "UNKNOWN",

            riskScore:
                localScore,

            confidence:
                threatIntel?.knownThreat
                    ? 99
                    : 60,

            isLegitimate:
                !threatIntel?.knownThreat &&
                localScore <= 20,

            explanation:
                generateLocalExplanation(
                    url,
                    ruleResult,
                    threatIntel
                ),

            recommendation:
                generateRecommendation(
                    url,
                    localScore,
                    ruleResult?.level,
                    ruleResult?.reasons,
                    threatIntel
                ),

            indicators:
                ruleResult?.reasons || [],

            provider:
                "Local fallback",

            model:
                null,

            available:
                false

        };

    } catch (error) {

        console.error(
            "AI Analyzer Error:",
            error.message
        );


        const localScore =
            Number(
                ruleResult?.riskScore || 0
            );


        return {

            classification:
                ruleResult?.level ||
                "UNKNOWN",

            riskScore:
                localScore,

            confidence:
                50,

            isLegitimate:
                false,

            explanation:
                generateLocalExplanation(
                    url,
                    ruleResult,
                    threatIntel
                ),

            recommendation:
                generateRecommendation(
                    url,
                    localScore,
                    ruleResult?.level,
                    ruleResult?.reasons,
                    threatIntel
                ),

            indicators:
                ruleResult?.reasons || [],

            provider:
                "Local fallback",

            model:
                null,

            available:
                false

        };

    }

}


module.exports = {

    analyzeWithAI

};