const axios = require("axios");

async function checkThreatIntel(url) {
    const result = {
        knownThreat: false,
        sources: [],
        threatType: null
    };

    if (!url || typeof url !== "string") {
        return result;
    }

    try {
        const response = await axios.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            new URLSearchParams({ url: url.trim() }).toString(),
            {
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                timeout: 10000,
                validateStatus: (status) => status >= 200 && status < 500
            }
        );

        const data = response.data || {};

        // URLhaus returns query_status=ok when the submitted URL
        // has a matching record. "no_results" is NOT a threat.
        if (data.query_status === "ok") {
            result.knownThreat = true;
            result.sources.push("URLhaus");
            result.threatType =
                data.threat ||
                data.tags?.join?.(", ") ||
                "Malicious URL";
        }
    } catch (error) {
        console.error(
            "URLhaus check unavailable:",
            error.message
        );
    }

    return result;
}

module.exports = {
    checkThreatIntel
};
