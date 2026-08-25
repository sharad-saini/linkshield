const { chromium } = require("playwright");
const { validatePreviewURL } = require("./previewSecurity");

async function getInteractivePreview(targetUrl) {
    let browser;

    try {
        // ==========================================
        // SECURITY VALIDATION
        // ==========================================

        const validation =
            await validatePreviewURL(targetUrl);

        if (!validation.allowed) {
            return {
                success: false,
                message: validation.reason
            };
        }

        const safeURL =
            validation.url || targetUrl;

        // ==========================================
        // LAUNCH ISOLATED BROWSER
        // ==========================================

        browser = await chromium.launch({
            headless: true,

            args: [
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu"
            ]
        });

        const context =
            await browser.newContext({
                javaScriptEnabled: true,

                ignoreHTTPSErrors: false,

                viewport: {
                    width: 1440,
                    height: 900
                },

                userAgent:
                    "LinkShield-SecureBrowser/1.0"
            });

        const page =
            await context.newPage();

        // ==========================================
        // CONTROL ALL NETWORK REQUESTS
        // ==========================================

        await page.route("**/*", async (route) => {
            try {
                const request =
                    route.request();

                const requestURL =
                    new URL(request.url());

                // Only HTTP / HTTPS
                if (
                    !["http:", "https:"].includes(
                        requestURL.protocol
                    )
                ) {
                    return route.abort();
                }

                // Validate every destination
                const check =
                    await validatePreviewURL(
                        requestURL.toString()
                    );

                if (!check.allowed) {
                    console.log(
                        "🛡️ Blocked preview request:",
                        requestURL.hostname,
                        check.reason
                    );

                    return route.abort();
                }

                await route.continue();

            } catch (error) {
                console.log(
                    "🛡️ Blocked unsafe request:",
                    error.message
                );

                return route.abort();
            }
        });

        // ==========================================
        // LOAD TARGET WEBSITE
        // ==========================================

        await page.goto(safeURL, {
            waitUntil: "domcontentloaded",
            timeout: 20000
        });

        // Give modern JS applications time to render
        await page.waitForTimeout(3000);

        // Some sites keep connections open permanently.
        // Network idle is therefore optional.
        try {
            await page.waitForLoadState("networkidle", {
                timeout: 8000
            });
        } catch {}

        // ==========================================
        // PREPARE IMAGES
        // ==========================================

        await page.evaluate(() => {
            document
                .querySelectorAll("img")
                .forEach((img) => {
                    try {
                        img.loading = "eager";

                        const src =
                            img.getAttribute("src");

                        if (src) {
                            img.src = new URL(
                                src,
                                document.baseURI
                            ).href;
                        }

                        img.removeAttribute(
                            "srcset"
                        );
                    } catch {}
                });
        });

        // Let images finish
        await page.waitForTimeout(1500);

        // ==========================================
        // ADD LINKSHIELD SECURITY NOTICE
        // ==========================================

        await page.evaluate(() => {

            if (!document.body) {
                return;
            }

            const banner =
                document.createElement("div");

            const title =
                document.createElement("div");

            const message =
                document.createElement("div");

            title.textContent =
                "🛡️ LinkShield Protected Preview";

            message.textContent =
                "This page was rendered inside LinkShield's " +
                "isolated browser. The preview shown here " +
                "is static and cannot submit forms or " +
                "navigate the original website.";

            title.style.cssText = `
                font-family: system-ui, sans-serif;
                font-size: 16px;
                font-weight: 700;
                color: #ffb13b;
                margin-bottom: 5px;
            `;

            message.style.cssText = `
                font-family: system-ui, sans-serif;
                font-size: 12px;
                line-height: 1.4;
                color: #d9e4ee;
            `;

            banner.appendChild(title);
            banner.appendChild(message);

            banner.style.cssText = `
                position: sticky;
                top: 0;
                z-index: 2147483647;
                padding: 14px 20px;
                background: #101c2c;
                border-bottom: 2px solid #ffb13b;
                text-align: center;
                box-sizing: border-box;
            `;

            document.body.prepend(banner);
        });

        // ==========================================
        // CAPTURE FULL RENDERED PAGE
        // ==========================================

        const screenshot =
            await page.screenshot({
                type: "png",
                fullPage: true,
                animations: "disabled"
            });

        const imageBase64 =
            screenshot.toString("base64");

        // ==========================================
        // GET TITLE
        // ==========================================

        const title =
            await page.title();

        // ==========================================
        // STATIC SAFE HTML
        // ==========================================

        /*
         * Important:
         *
         * We do NOT return the original HTML.
         * We return a static image of the fully
         * rendered page.
         *
         * Therefore:
         *
         * - Target JavaScript does not run in React.
         * - Forms cannot be submitted.
         * - Target links cannot be clicked.
         * - Target scripts cannot access the user.
         */

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
        LinkShield Protected Preview
    </title>

    <style>
        * {
            box-sizing: border-box;
        }

        html,
        body {
            margin: 0;
            padding: 0;
            background: #ffffff;
        }

        body {
            overflow-x: hidden;
        }

        .preview-image {
            display: block;
            width: 100%;
            height: auto;
        }
    </style>
</head>

<body>

    <img
        class="preview-image"
        src="data:image/png;base64,${imageBase64}"
        alt="LinkShield protected website preview"
        draggable="false"
    >

</body>
</html>
        `;

        // ==========================================
        // CLOSE BROWSER
        // ==========================================

        await browser.close();

        browser = null;

        // ==========================================
        // RETURN
        // ==========================================

        return {
            success: true,

            title:
                title ||
                "LinkShield Interactive Preview",

            html: safeHTML,

            previewType: "static-rendered"
        };

    } catch (error) {

        console.error(
            "========================================"
        );

        console.error(
            "INTERACTIVE PREVIEW ERROR"
        );

        console.error(error);

        console.error(
            "========================================"
        );

        if (browser) {
            try {
                await browser.close();
            } catch {}
        }

        return {
            success: false,

            message:
                error.message ||
                "Unable to render protected preview."
        };
    }
}

module.exports = {
    getInteractivePreview
};