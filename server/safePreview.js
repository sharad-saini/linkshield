const axios = require("axios");
const cheerio = require("cheerio");
const dns = require("dns").promises;
const ipaddr = require("ipaddr.js");

/*
=========================================================
 LINKSHIELD SAFE PREVIEW
=========================================================

Goals:
- Fetch website through LinkShield backend
- Never execute original JavaScript
- Block forms
- Block navigation
- Block redirects
- Block tracking/event handlers
- Block dangerous resources
- Proxy images through LinkShield
- Prevent requests to localhost/private networks
=========================================================
*/


/* =====================================================
   CHECK WHETHER IP IS SAFE
===================================================== */

function isPrivateIP(address) {
    try {
        const parsed = ipaddr.parse(address);

        const range = parsed.range();

        const blockedRanges = [
            "private",
            "loopback",
            "linkLocal",
            "uniqueLocal",
            "unspecified",
            "broadcast",
            "carrierGradeNat",
            "reserved",
            "multicast"
        ];

        return blockedRanges.includes(range);
    } catch {
        return true;
    }
}


/* =====================================================
   CHECK HOSTNAME
===================================================== */

async function validateHostname(hostname) {

    hostname = hostname.toLowerCase();

    // Block localhost names
    if (
        hostname === "localhost" ||
        hostname.endsWith(".localhost") ||
        hostname.endsWith(".local")
    ) {
        throw new Error("Local addresses are not allowed");
    }

    // Direct IP
    if (ipaddr.isValid(hostname)) {

        if (isPrivateIP(hostname)) {
            throw new Error("Private IP addresses are not allowed");
        }

        return;
    }

    // Resolve hostname
    const addresses = await dns.lookup(hostname, {
        all: true
    });

    if (!addresses || addresses.length === 0) {
        throw new Error("Unable to resolve website");
    }

    for (const item of addresses) {

        if (isPrivateIP(item.address)) {
            throw new Error(
                "Website resolves to a private or restricted network"
            );
        }
    }
}


/* =====================================================
   VALIDATE URL
===================================================== */

async function validateURL(targetUrl) {

    const parsedUrl = new URL(targetUrl);

    if (
        !["http:", "https:"].includes(
            parsedUrl.protocol
        )
    ) {
        throw new Error(
            "Only HTTP and HTTPS URLs are allowed"
        );
    }

    await validateHostname(
        parsedUrl.hostname
    );

    return parsedUrl;
}


/* =====================================================
   FETCH WEBSITE
===================================================== */

async function fetchWebsite(targetUrl) {

    const response = await axios.get(
        targetUrl,
        {
            timeout: 10000,

            maxRedirects: 5,

            headers: {
                "User-Agent":
                    "LinkShield-SafePreview/1.0",

                "Accept":
                    "text/html,application/xhtml+xml"
            },

            responseType: "text",

            validateStatus: (status) =>
                status >= 200 &&
                status < 400
        }
    );

    return response;
}


/* =====================================================
   SAFE PREVIEW
===================================================== */

async function getSafePreview(targetUrl) {

    try {

        /* ---------------------------------------------
           1. VALIDATE URL
        --------------------------------------------- */

        const parsedUrl =
            await validateURL(targetUrl);


        /* ---------------------------------------------
           2. FETCH WEBSITE
        --------------------------------------------- */

        const response =
            await fetchWebsite(
                parsedUrl.href
            );


        /* ---------------------------------------------
           3. CHECK CONTENT TYPE
        --------------------------------------------- */

        const contentType =
            response.headers["content-type"] || "";

        if (
            !contentType
                .toLowerCase()
                .includes("text/html")
        ) {

            return {
                success: false,
                message:
                    "This website does not provide an HTML page for preview."
            };
        }


        /* ---------------------------------------------
           4. LOAD HTML
        --------------------------------------------- */

        const $ =
            cheerio.load(
                response.data,
                {
                    decodeEntities: false
                }
            );


        /* =============================================
           REMOVE JAVASCRIPT
        ============================================= */

        $("script").remove();

        $("noscript").remove();

        $("iframe").remove();

        $("frame").remove();

        $("frameset").remove();

        $("object").remove();

        $("embed").remove();

        $("applet").remove();

        $("portal").remove();

        $("video").remove();

        $("audio").remove();


        /* =============================================
           REMOVE META REDIRECTS
        ============================================= */

        $("meta").each(
            (_, element) => {

                const httpEquiv =
                    (
                        $(element)
                            .attr("http-equiv") ||
                        ""
                    ).toLowerCase();

                if (
                    httpEquiv === "refresh"
                ) {
                    $(element).remove();
                }
            }
        );


        /* =============================================
           REMOVE BASE TAG
        ============================================= */

        $("base").remove();


        /* =============================================
           BLOCK FORMS
        ============================================= */

        $("form").each(
            (_, element) => {

                $(element).replaceWith(`
                    <div class="blocked-element">
                        🛡️ Form blocked by LinkShield Safe Preview
                    </div>
                `);
            }
        );


        /* =============================================
           REMOVE EVENT HANDLERS
        ============================================= */

        $("*").each(
            (_, element) => {

                const attributes =
                    element.attribs || {};

                Object.keys(attributes)
                    .forEach(attribute => {

                        if (
                            attribute
                                .toLowerCase()
                                .startsWith("on")
                        ) {

                            $(element)
                                .removeAttr(attribute);
                        }
                    });
            }
        );


        /* =============================================
           REMOVE JAVASCRIPT URLS
        ============================================= */

        $("a").each(
            (_, element) => {

                const href =
                    $(element).attr("href");

                if (
                    href &&
                    href
                        .toLowerCase()
                        .trim()
                        .startsWith(
                            "javascript:"
                        )
                ) {

                    $(element)
                        .removeAttr("href");
                }
            }
        );


        /* =============================================
           DISABLE ALL LINKS
        ============================================= */

        $("a").each(
            (_, element) => {

                $(element)
                    .removeAttr("href");

                $(element)
                    .removeAttr("target");

                $(element)
                    .removeAttr("rel");

                $(element).attr(
                    "class",
                    `${$(element).attr("class") || ""}
                     disabled-link`
                );
            }
        );


        /* =============================================
           DISABLE INPUTS
        ============================================= */

        $(
            "input, textarea, select, button"
        ).each(
            (_, element) => {

                $(element)
                    .attr(
                        "disabled",
                        "disabled"
                    );

                $(element)
                    .removeAttr("name");

                $(element)
                    .removeAttr("value");
            }
        );


        /* =============================================
           IMAGE PROXY
        ============================================= */

        $("img").each(
            (_, element) => {

                const src =
                    $(element).attr("src");

                const srcset =
                    $(element).attr(
                        "srcset"
                    );

                /*
                Convert normal image URL
                into LinkShield proxy URL.
                */

                if (src) {

                    try {

                        const absoluteURL =
                            new URL(
                                src,
                                parsedUrl.href
                            ).href;

                        $(element).attr(
                            "src",
                            `/api/preview-asset?url=${encodeURIComponent(
                                absoluteURL
                            )}`
                        );

                    } catch {

                        $(element)
                            .removeAttr("src");
                    }
                }


                /*
                Remove srcset because it can
                generate direct requests.
                */

                if (srcset) {

                    $(element)
                        .removeAttr(
                            "srcset"
                        );
                }


                $(element).attr(
                    "loading",
                    "lazy"
                );

                $(element).attr(
                    "referrerpolicy",
                    "no-referrer"
                );
            }
        );


        /* =============================================
           SANITIZE STYLES
        ============================================= */

        $("style").each(
            (_, element) => {

                let css =
                    $(element).html() || "";

                /*
                Remove JavaScript
                */

                css = css.replace(
                    /javascript\s*:/gi,
                    ""
                );

                /*
                Remove CSS expressions
                */

                css = css.replace(
                    /expression\s*\(/gi,
                    ""
                );

                /*
                Remove imports
                */

                css = css.replace(
                    /@import[^;]+;/gi,
                    ""
                );

                /*
                Remove external url()
                requests.

                This prevents CSS from
                contacting third-party
                servers directly.
                */

                css = css.replace(
                    /url\s*\(\s*(['"]?)(https?:|\/\/)[^)]*\1\s*\)/gi,
                    ""
                );

                $(element).html(css);
            }
        );


        /* =============================================
           REMOVE EXTERNAL STYLESHEETS
        ============================================= */

        $(
            'link[rel="stylesheet"]'
        ).remove();


        /* =============================================
           REMOVE TRACKING ELEMENTS
        ============================================= */

        $(
            'img[width="1"][height="1"],' +
            'img[width="0"][height="0"],' +
            'iframe,' +
            'tracking-pixel'
        ).remove();


        /* =============================================
           TITLE
        ============================================= */

        const title =
            $("title")
                .text()
                .trim() ||

            $("h1")
                .first()
                .text()
                .trim() ||

            "Website Preview";


        /* =============================================
           BODY
        ============================================= */

        const bodyHTML =
            $("body").html() || "";


        /* =============================================
           SAFE HTML DOCUMENT
        ============================================= */

        const safeHTML = `
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>
${escapeHTML(title)}
</title>

<style>

* {
    box-sizing: border-box;
}

html,
body {
    margin: 0;
    padding: 0;
    width: 100%;
}

body {

    font-family:
        Arial,
        Helvetica,
        sans-serif;

    background: #ffffff;

    color: #222;

    line-height: 1.5;

    padding: 24px;

    overflow-x: hidden;
}


/* ==========================================
   RESPONSIVE IMAGES
========================================== */

img {

    max-width: 100%;

    height: auto;

    display: inline-block;

}


/* ==========================================
   BLOCKED FORM
========================================== */

.blocked-element {

    padding: 16px;

    margin: 18px 0;

    border: 1px solid #ffb84d;

    background: #fff7e6;

    color: #8a5a00;

    border-radius: 10px;

    font-family: Arial, sans-serif;

    text-align: center;
}


/* ==========================================
   DISABLED LINKS
========================================== */

.disabled-link {

    color: #1769aa !important;

    text-decoration: underline;

    cursor: not-allowed;

}


/* ==========================================
   DISABLED CONTROLS
========================================== */

input,
button,
textarea,
select {

    max-width: 100%;

}


/* ==========================================
   TABLE RESPONSIVENESS
========================================== */

table {

    max-width: 100%;

    overflow-x: auto;

    display: block;
}


/* ==========================================
   MOBILE
========================================== */

@media (max-width: 768px) {

    body {
        padding: 12px;
    }

    img {
        max-width: 100%;
    }

}


/* ==========================================
   SMALL MOBILE
========================================== */

@media (max-width: 480px) {

    body {
        padding: 8px;
        font-size: 14px;
    }

    h1 {
        font-size: 26px;
    }

    h2 {
        font-size: 22px;
    }

    h3 {
        font-size: 18px;
    }

}

</style>

</head>

<body>

<div
    class="linkshield-banner"
    style="
        padding:14px;
        margin:-24px -24px 24px -24px;
        background:#fff7e6;
        border-bottom:1px solid #ffb84d;
        color:#8a5a00;
        text-align:center;
        font-family:Arial,sans-serif;
    "
>

    🛡️
    <strong>
        LinkShield Safe Preview
    </strong>

    <br>

    <span>
        Sanitized copy — scripts,
        forms and redirects are disabled.
    </span>

</div>

${bodyHTML}

</body>

</html>
`;


        return {

            success: true,

            title,

            html: safeHTML
        };

    } catch (error) {

        console.error(
            "Safe Preview Error:",
            error.message
        );

        return {

            success: false,

            message:
                error.message ||
                "Unable to create a safe preview of this website."
        };
    }
}


/* =====================================================
   HTML ESCAPE
===================================================== */

function escapeHTML(value) {

    return String(value)

        .replace(
            /&/g,
            "&amp;"
        )

        .replace(
            /</g,
            "&lt;"
        )

        .replace(
            />/g,
            "&gt;"
        )

        .replace(
            /"/g,
            "&quot;"
        )

        .replace(
            /'/g,
            "&#039;"
        );
}


/* =====================================================
   EXPORTS
===================================================== */

module.exports = {

    getSafePreview,

    validateURL
};