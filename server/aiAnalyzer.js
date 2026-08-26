require("dotenv").config();

const axios = require("axios");

/*
=========================================================
LINKSHIELD AI ANALYZER
=========================================================

Purpose:
1. Give the AI the URL and objective security signals.
2. Ask for a structured security judgment.
3. Use AI as a SECOND opinion, not as proof.
4. Never let AI override confirmed threat intelligence.
5. If AI is unavailable, return a safe local fallback.

Important:
- "Unknown" does NOT mean malicious.
- A normal login/account/payment URL is not automatically suspicious.
- The AI must not invent reputation or threat-intelligence data.
=========================================================
*/

// =======================================================
// LOCAL FALLBACK RECOMMENDATION
// =======================================================

function generateRecommendation(
    url,
    riskScore,
    level,
    reasons = [],
    threatIntel = {}
) {
    if (threatIntel.knownThreat) {
        return (
            "Do not open or interact with this URL. " +
            "Threat intelligence has identified it as a known malicious URL."
        );
    }

    if (
        level === "CRITICAL" ||
        riskScore >= 80
    ) {
        return (
            "Avoid interacting with this URL until the source " +
            "and domain have been independently verified."
        );
    }

    if (
        level === "HIGH" ||
        riskScore > 45
    ) {
        return (
            "Proceed carefully. Review the domain and suspicious " +
            "indicators before entering sensitive information."
        );
    }

    if (
        level === "MEDIUM" ||
        riskScore > 20
    ) {
        return (
            "No confirmed malicious threat was found, but some " +
            "indicators deserve caution before sensitive interactions."
        );
    }

    return (
        "No major malicious indicators were detected by the " +
        "available checks. Continue normal security practices."
    );
}

// =======================================================
// LOCAL FALLBACK EXPLANATION
// =======================================================

function generateLocalExplanation(
    url,
    ruleResult,
    threatIntel
) {
    if (threatIntel.knownThreat) {
        return (
            "Threat intelligence identified this URL as a known " +
            "malicious threat."
        );
    }

    const reasons =
        ruleResult.reasons || [];

    if (reasons.length === 0) {
        return (
            "The available checks did not identify major " +
            "suspicious indicators in this URL."
        );
    }

    return (
        "The URL contains the following signals that were " +
        "considered during the security assessment: " +
        reasons.join(", ") +
        ". These signals are indicators, not proof of maliciousness."
    );
}

// =======================================================
// OPENAI ANALYSIS
// =======================================================

async function analyzeWithOpenAI(
    url,
    ruleResult,
    threatIntel
) {
    const apiKey =
        process.env.OPENAI_API_KEY;

    if (!apiKey) {
        return null;
    }

    try {
        const prompt = `
You are the secondary AI security analyst for LinkShield.

Your job is to assess a URL carefully and reduce false positives
without ignoring real threats.

URL:
${url}

Local technical analysis:
${JSON.stringify(ruleResult, null, 2)}

Threat intelligence:
${JSON.stringify(threatIntel, null, 2)}

Rules for your judgment:

1. A known malicious threat from threat intelligence is strong evidence.
2. Never invent reputation, malware reports, domain age, ownership,
   or external facts that were not provided.
3. "Not found in threat intelligence" does NOT prove a URL is safe.
4. Unknown does NOT mean malicious.
5. Do NOT treat these alone as malicious:
   - HTTPS
   - login
   - account
   - secure
   - password
   - verification
   - query parameters
   - a long URL
   - normal subdomains
6. A legitimate website may contain login, account, payment,
   learning, coding, shopping, or verification pages.
7. Look for combinations of strong suspicious signals:
   credential deception, embedded credentials, IP-based hosting,
   suspicious executable downloads, deceptive URL patterns,
   urgent reward/verification patterns, or other clearly suspicious
   combinations present in the supplied evidence.
8. If the URL looks like a normal legitimate website and there is
   no strong malicious evidence, classify it LOW rather than HIGH.
9. Do not claim certainty. Security classification is probabilistic.
10. Your risk score should represent the evidence available in the
    input, not your general assumptions about the internet.

Return ONLY valid JSON with exactly this structure:

{
  "classification": "LOW",
  "riskScore": 10,
  "confidence": 90,
  "isLegitimate": true,
  "explanation": "Short explanation of the evidence.",
  "recommendation": "Practical recommendation for the user.",
  "indicators": []
}

Allowed classification values:
LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN

Scoring guidance:
LOW: 0-20
MEDIUM: 21-45
HIGH: 46-75
CRITICAL: 76-100

A normal legitimate website with no strong malicious evidence
should generally be LOW, even if it has ordinary login/account
paths or query parameters.

Do not return markdown.
`;

        const response =
            await axios.post(
                "https://api.openai.com/v1/chat/completions",
                {
                    model:
                        process.env.OPENAI_MODEL ||
                        "gpt-4o-mini",

                    messages: [
                        {
                            role: "system",
                            content:
                                "You are a careful cybersecurity URL analyst. " +
                                "Avoid false positives and never invent evidence."
                        },
                        {
                            role: "user",
                            content: prompt
                        }
                    ],

                    temperature: 0.1,

                    response_format: {
                        type: "json_object"
                    }
                },
                {
                    timeout: 20000,

                    headers: {
                        "Content-Type":
                            "application/json",

                        Authorization:
                            `Bearer ${apiKey}`
                    }
                }
            );

        const content =
            response.data
                ?.choices?.[0]
                ?.message?.content;

        if (!content) {
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

        if (
            !allowedLevels.includes(
                parsed.classification
            )
        ) {
            return null;
        }

        const score =
            Number(parsed.riskScore);

        const confidence =
            Number(parsed.confidence);

        if (
            !Number.isFinite(score) ||
            !Number.isFinite(confidence) ||
            typeof parsed.explanation !== "string" ||
            typeof parsed.recommendation !== "string"
        ) {
            return null;
        }

        return {
            classification:
                parsed.classification,

            riskScore:
                Math.min(
                    Math.max(
                        Math.round(score),
                        0
                    ),
                    100
                ),

            confidence:
                Math.min(
                    Math.max(
                        Math.round(confidence),
                        0
                    ),
                    100
                ),

            isLegitimate:
                parsed.isLegitimate === true,

            explanation:
                parsed.explanation,

            recommendation:
                parsed.recommendation,

            indicators:
                Array.isArray(
                    parsed.indicators
                )
                    ? parsed.indicators
                        .filter(
                            item =>
                                typeof item === "string"
                        )
                        .slice(0, 8)
                    : []
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
        const aiResult =
            await analyzeWithOpenAI(
                url,
                ruleResult,
                threatIntel
            );

        if (aiResult) {
            return aiResult;
        }

        // ----------------------------------------------
        // AI unavailable: deterministic local fallback
        // ----------------------------------------------

        return {
            classification:
                ruleResult.level || "UNKNOWN",

            riskScore:
                ruleResult.riskScore,

            confidence:
                threatIntel.knownThreat
                    ? 99
                    : 60,

            isLegitimate:
                !threatIntel.knownThreat &&
                ruleResult.riskScore <= 20,

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
                ),

            indicators:
                ruleResult.reasons || []
        };

    } catch (error) {
        console.error(
            "AI Analyzer Error:",
            error.message
        );

        return {
            classification:
                ruleResult.level || "UNKNOWN",

            riskScore:
                ruleResult.riskScore,

            confidence: 50,

            isLegitimate: false,

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
                ),

            indicators:
                ruleResult.reasons || []
        };
    }
}

module.exports = {
    analyzeWithAI
};
