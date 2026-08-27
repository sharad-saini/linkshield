const dns = require("dns").promises;
const ipaddr = require("ipaddr.js");
const { chromium } = require("playwright");
const cheerio = require("cheerio");

const NAV_TIMEOUT = 8000;
const TOTAL_TIMEOUT = 10000;

function isBlockedIP(address) {
    try {
        const parsed = ipaddr.parse(address);
        return [
            "private",
            "loopback",
            "linkLocal",
            "uniqueLocal",
            "carrierGradeNat",
            "unspecified",
            "reserved",
            "broadcast",
            "multicast"
        ].includes(parsed.range());
    } catch {
        return true;
    }
}

async function validateTarget(targetUrl) {
    const parsed = new URL(targetUrl);

    if (!["http:", "https:"].includes(parsed.protocol)) {
        throw new Error("Only HTTP and HTTPS URLs are allowed");
    }

    const hostname = parsed.hostname.toLowerCase();

    if (
        hostname === "localhost" ||
        hostname.endsWith(".localhost") ||
        hostname.endsWith(".local") ||
        hostname === "metadata.google.internal" ||
        hostname === "metadata.google.com" ||
        hostname === "host.docker.internal"
    ) {
        throw new Error("Local or internal destinations are not allowed");
    }

    if (ipaddr.isValid(hostname)) {
        if (isBlockedIP(hostname)) {
            throw new Error("Private or restricted IP addresses cannot be previewed");
        }
        return parsed;
    }

    const records = await dns.lookup(hostname, { all: true });

    if (!records.length) {
        throw new Error("Unable to resolve website");
    }

    for (const record of records) {
        if (isBlockedIP(record.address)) {
            throw new Error("Website resolves to a private or restricted network");
        }
    }

    return parsed;
}

function sanitizeHTML(html, baseURL) {
    const $ = cheerio.load(html, { decodeEntities: false });

    $("script, noscript, iframe, frame, frameset, object, embed, applet, portal").remove();
    $("video, audio, source, track").remove();
    $("form").each((_, el) => {
        $(el).replaceWith(
            '<div style="padding:16px;border:1px solid #f59e0b;background:#fff7ed;color:#7c2d12;border-radius:10px;font:14px system-ui">🛡️ Form blocked by LinkShield Protected Preview</div>'
        );
    });

    $("meta").each((_, el) => {
        const httpEquiv = ($(el).attr("http-equiv") || "").toLowerCase();
        if (httpEquiv === "refresh") $(el).remove();
    });

    $("base").remove();

    $("*").each((_, el) => {
        const attrs = el.attribs || {};

        for (const name of Object.keys(attrs)) {
            if (/^on/i.test(name)) {
                $(el).removeAttr(name);
            }
        }

        for (const name of ["href", "src", "action", "formaction", "poster"]) {
            const value = $(el).attr(name);
            if (!value) continue;

            try {
                const absolute = new URL(value, baseURL).href;
                if (name === "action" || name === "formaction") {
                    $(el).removeAttr(name);
                } else {
                    $(el).attr(name, absolute);
                }
            } catch {
                $(el).removeAttr(name);
            }
        }

        $(el).removeAttr("target");
    });

    $("a").each((_, el) => {
        $(el).attr("href", "#");
        $(el).attr("data-linkshield-blocked", "true");
    });

    $("head").prepend(`
        <style>
            html,body{margin:0;padding:0;background:#fff;color:#111;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
            a[data-linkshield-blocked]{cursor:not-allowed}
            img{max-width:100%;height:auto}
        </style>
    `);

    return $.html();
}

async function getInteractivePreview(targetUrl) {
    let browser;
    let timeoutId;

    try {
        const parsed = await validateTarget(targetUrl);

        browser = await chromium.launch({
            headless: true,
            args: [
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu"
            ]
        });

        const context = await browser.newContext({
            ignoreHTTPSErrors: false,
            javaScriptEnabled: true,
            viewport: { width: 1366, height: 768 },
            userAgent: "LinkShield-ProtectedPreview/1.0"
        });

        const page = await context.newPage();
        page.setDefaultNavigationTimeout(NAV_TIMEOUT);
        page.setDefaultTimeout(NAV_TIMEOUT);

        await page.route("**/*", async (route) => {
            const request = route.request();
            const type = request.resourceType();
            const url = request.url();

            if (["font", "media"].includes(type)) {
                return route.abort();
            }

            if (
                /google-analytics|googletagmanager|doubleclick|facebook\.net|connect\.facebook|hotjar|clarity\.ms/i.test(url)
            ) {
                return route.abort();
            }

            return route.continue();
        });

        timeoutId = setTimeout(() => {
            page.close().catch(() => {});
        }, TOTAL_TIMEOUT);

        try {
            await page.goto(parsed.href, {
                waitUntil: "domcontentloaded",
                timeout: NAV_TIMEOUT
            });
        } catch (error) {
            if (!page.isClosed()) {
                const currentURL = page.url();
                if (!currentURL || currentURL === "about:blank") {
                    throw new Error(
                        /timeout/i.test(error.message)
                            ? "Website took too long to respond"
                            : "Website could not be loaded"
                    );
                }
            }
        }

        if (page.isClosed()) {
            throw new Error("Preview timed out while loading the website");
        }

        await page.waitForTimeout(700).catch(() => {});

        const title = await page.title().catch(() => parsed.hostname);
        const html = await page.content();
        const sanitized = sanitizeHTML(html, page.url() || parsed.href);

        return {
            success: true,
            title: title || parsed.hostname,
            html: sanitized
        };
    } catch (error) {
        console.error("Interactive preview generation failed:", error.message);

        return {
            success: false,
            message: error.message || "Unable to generate interactive preview"
        };
    } finally {
        if (timeoutId) clearTimeout(timeoutId);
        if (browser) await browser.close().catch(() => {});
    }
}

module.exports = { getInteractivePreview };
