require("dotenv").config();

const axios = require("axios");

function generateRecommendation(
    riskScore,
    level,
    threatIntel = {}
) {
    if (threatIntel.knownThreat) {
        return "Do not open or interact with this URL. Threat intelligence has identified it as a known malicious URL.";
    }

    if (level === "HIGH" || riskScore > 60) {
        return "Avoid interacting with this URL until the source and domain have been independently verified.";
    }

    if (level === "MEDIUM" || riskScore > 30) {
        return "Proceed carefully. Review the domain and suspicious indicators before entering sensitive information.";
    }

    return "No major malicious indicators were detected by the available checks. Continue normal security practices.";
}

function generateLocalExplanation(ruleResult, threatIntel) {
    if (threatIntel.knownThreat) {
        return "Threat intelligence identified this URL as a known malicious threat.";
    }

    const reasons = Array.isArray(ruleResult?.reasons)
        ? ruleResult.reasons
        : [];

    if (reasons.length === 0) {
        return "The available checks did not identify major suspicious indicators in this URL.";
    }

    return (
        "The URL contains the following signals that were considered during the security assessment: " +
        reasons.join(", ") +
        ". These signals are indicators, not proof of maliciousness."
    );
}

async function analyzeWithOpenAI(url, ruleResult, threatIntel) {
    const apiKey = process.env.OPENAI_API_KEY;

    if (!apiKey) {
        return null;
    }

    const model = process.env.OPENAI_MODEL || "gpt-4o-mini";

    const prompt = `
You are the secondary AI security analyst for LinkShield.

Assess only the evidence supplied below. Reduce false positives.

URL:
${url}

Local technical analysis:
${JSON.stringify(ruleResult, null, 2)}

Threat intelligence:
${JSON.stringify(threatIntel, null, 2)}

Rules:
1. A confirmed malicious threat from threat intelligence is strong evidence.
2. Never invent reputation, malware reports, domain age, ownership, or external facts.
3. "Not found" in threat intelligence does not prove a URL is safe.
4. Unknown does not mean malicious.
5. Do NOT treat HTTPS, login, account, secure, password, verification,
   query parameters, a long URL, or normal subdomains alone as malicious.
6. Legitimate websites can contain login, account, payment, learning,
   coding, shopping, and verification pages.
7. Strong evidence comes from combinations such as credential deception,
   embedded credentials, IP hosting, dangerous downloads, deceptive URL
   structure, or multiple correlated phishing indicators.
8. A normal website with no strong malicious evidence should be LOW.
9. Do not claim certainty.
10. The score must reflect the supplied evidence, not general assumptions.
11. If local evidence is clean, do not manufacture suspicious indicators.

Return ONLY valid JSON:
{
  "classification": "LOW",
  "riskScore": 0,
  "confidence": 90,
  "isLegitimate": true,
  "explanation": "Short evidence-based explanation.",
  "recommendation": "Practical user recommendation.",
  "indicators": []
}

Allowed classification values: LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN
Scoring: LOW 0-30, MEDIUM 31-60, HIGH 61-85, CRITICAL 86-100.
`;

    try {
        const response = await axios.post(
            "https://api.openai.com/v1/chat/completions",
            {
                model,
                messages: [
                    {
                        role: "system",
                        content:
                            "You are a careful cybersecurity URL analyst. Avoid false positives and never invent evidence."
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
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${apiKey}`
                }
            }
        );

        const content = response.data?.choices?.[0]?.message?.content;

        if (!content) {
            return null;
        }

        const parsed = JSON.parse(content);

        const allowedLevels = [
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
            "UNKNOWN"
        ];

        if (!allowedLevels.includes(parsed.classification)) {
            return null;
        }

        const riskScore = Number(parsed.riskScore);
        const confidence = Number(parsed.confidence);

        if (
            !Number.isFinite(riskScore) ||
            !Number.isFinite(confidence) ||
            typeof parsed.explanation !== "string" ||
            typeof parsed.recommendation !== "string"
        ) {
            return null;
        }

        return {
            classification: parsed.classification,
            riskScore: Math.min(Math.max(Math.round(riskScore), 0), 100),
            confidence: Math.min(Math.max(Math.round(confidence), 0), 100),
            isLegitimate: parsed.isLegitimate === true,
            explanation: parsed.explanation,
            recommendation: parsed.recommendation,
            indicators: Array.isArray(parsed.indicators)
                ? parsed.indicators
                    .filter((item) => typeof item === "string")
                    .map((item) => item.trim())
                    .filter(Boolean)
                    .slice(0, 8)
                : []
        };
    } catch (error) {
        console.error("OpenAI analysis unavailable:", error.message);
        return null;
    }
}

async function analyzeWithAI(url, ruleResult, threatIntel) {
    const safeRuleResult = ruleResult || {
        riskScore: 0,
        level: "LOW",
        reasons: []
    };

    const safeThreatIntel = threatIntel || {
        knownThreat: false,
        sources: [],
        threatType: null
    };

    const aiResult = await analyzeWithOpenAI(
        url,
        safeRuleResult,
        safeThreatIntel
    );

    if (aiResult) {
        return aiResult;
    }

    const score = Number(safeRuleResult.riskScore) || 0;
    const level = safeRuleResult.level || "UNKNOWN";

    return {
        classification: level,
        riskScore: score,
        confidence: safeThreatIntel.knownThreat ? 99 : 60,
        isLegitimate:
            !safeThreatIntel.knownThreat && score <= 30,
        explanation: generateLocalExplanation(
            safeRuleResult,
            safeThreatIntel
        ),
        recommendation: generateRecommendation(
            score,
            level,
            safeThreatIntel
        ),
        indicators: Array.isArray(safeRuleResult.reasons)
            ? safeRuleResult.reasons
            : []
    };
}

module.exports = {
    analyzeWithAI
};
