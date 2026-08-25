const dns = require("dns").promises;
const net = require("net");

function isPrivateIPv4(ip) {
    const parts = ip.split(".").map(Number);

    if (parts.length !== 4 || parts.some(Number.isNaN)) {
        return false;
    }

    const [a, b] = parts;

    return (
        a === 10 ||
        a === 127 ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) ||
        (a === 169 && b === 254)
    );
}

function isPrivateIPv6(ip) {
    const normalized = ip.toLowerCase();

    return (
        normalized === "::1" ||
        normalized.startsWith("fc") ||
        normalized.startsWith("fd") ||
        normalized.startsWith("fe80:")
    );
}

async function validatePreviewURL(targetUrl) {
    let parsed;

    try {
        parsed = new URL(targetUrl);
    } catch {
        return {
            allowed: false,
            reason: "Invalid URL"
        };
    }

    // Only HTTP and HTTPS are allowed
    if (!["http:", "https:"].includes(parsed.protocol)) {
        return {
            allowed: false,
            reason: "Only HTTP and HTTPS URLs are allowed"
        };
    }

    // Don't allow credentials embedded in URLs
    if (parsed.username || parsed.password) {
        return {
            allowed: false,
            reason: "URLs containing embedded credentials are blocked"
        };
    }

    const hostname = parsed.hostname.toLowerCase();

    // Block obvious local destinations
    const blockedHostnames = [
        "localhost",
        "localhost.localdomain",
        "0.0.0.0",
        "127.0.0.1",
        "::1"
    ];

    if (blockedHostnames.includes(hostname)) {
        return {
            allowed: false,
            reason: "Local destinations are blocked"
        };
    }

    // If hostname is already an IP, check it
    if (net.isIP(hostname)) {
        if (
            (net.isIPv4(hostname) && isPrivateIPv4(hostname)) ||
            (net.isIPv6(hostname) && isPrivateIPv6(hostname))
        ) {
            return {
                allowed: false,
                reason: "Private or local IP addresses are blocked"
            };
        }

        return {
            allowed: true
        };
    }

    // Resolve hostname and check the resulting IP
    try {
        const addresses = await dns.lookup(hostname, {
            all: true
        });

        for (const address of addresses) {
            const ip = address.address;

            if (
                (net.isIPv4(ip) && isPrivateIPv4(ip)) ||
                (net.isIPv6(ip) && isPrivateIPv6(ip))
            ) {
                return {
                    allowed: false,
                    reason: "Domain resolves to a private or local address"
                };
            }
        }
    } catch {
        return {
            allowed: false,
            reason: "Unable to resolve destination"
        };
    }

    return {
        allowed: true
    };
}

module.exports = {
    validatePreviewURL
};