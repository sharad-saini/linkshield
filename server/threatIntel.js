const axios = require("axios");

async function checkThreatIntel(url) {
    const result = {
        knownThreat: false,
        sources: [],
        threatType: null
    };

    // ==========================================
    // URLhaus
    // ==========================================

    try {
        const response = await axios.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            new URLSearchParams({
                url: url
            }).toString(),
            {
                headers: {
                    "Content-Type":
                        "application/x-www-form-urlencoded"
                },
                timeout: 10000
            }
        );

        if (
            response.data &&
            response.data.query_status === "ok"
        ) {
            result.knownThreat = true;

            result.sources.push(
                "URLhaus"
            );

            result.threatType =
                response.data.threat ||
                "Malicious URL";
        }

    } catch (error) {
        console.log(
            "URLhaus check unavailable:",
            error.message
        );
    }

    return result;
}

module.exports = {
    checkThreatIntel
};
