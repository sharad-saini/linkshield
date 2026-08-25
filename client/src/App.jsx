import { useState } from "react";
import "./App.css";

const API_BASE =
  import.meta.env.VITE_API_BASE_URL ||
  "http://localhost:5001";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const [showPreview, setShowPreview] = useState(false);
  const [previewHTML, setPreviewHTML] = useState("");
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState("");

  // ==========================================
  // URL SCAN
  // ==========================================

  const scanUrl = async () => {
    if (!url.trim()) {
      alert("Please enter a URL");
      return;
    }

    setLoading(true);
    setResult(null);
    setShowPreview(false);
    setPreviewHTML("");
    setPreviewError("");

    try {
      const response = await fetch(
        `${API_BASE}/api/scan`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            url: url.trim(),
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error || "Unable to scan URL"
        );
      }

      // Show normal result first
      setResult(data);

      // ==========================================
      // HIGH RISK ALERT
      // ==========================================

      if (data.level === "HIGH") {
        const message = data.threatIntel?.knownThreat
          ? `🚨 KNOWN MALICIOUS URL\n\n` +
            `Risk Score: ${data.riskScore}/100\n\n` +
            `Threat detected by: ${
              data.threatIntel.sources?.join(", ") ||
              "connected threat intelligence"
            }\n\n` +
            `⛔ Do not visit, sign in, download files, ` +
            `enter OTPs, make payments, or connect a wallet.`
          : `🚨 HIGH RISK WEBSITE\n\n` +
            `Risk Score: ${data.riskScore}/100\n\n` +
            `Multiple suspicious indicators were detected.\n\n` +
            `⚠️ Do not enter passwords, payment details, ` +
            `OTPs, wallet information, or other sensitive data.`;

        setTimeout(() => {
          alert(message);
        }, 100);
      }
    } catch (error) {
      console.error("Scan error:", error);

      alert(
        error.message ||
          "Unable to connect to LinkShield server"
      );
    } finally {
      setLoading(false);
    }
  };

  // ==========================================
  // INTERACTIVE SAFE PREVIEW
  // ==========================================

  const openPreview = async () => {
    if (!result?.url) return;

    setShowPreview(true);
    setPreviewLoading(true);
    setPreviewHTML("");
    setPreviewError("");

    try {
      const response = await fetch(
        `${API_BASE}/api/interactive-preview`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            url: result.url,
          }),
        }
      );

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(
          data.error ||
            data.message ||
            "Unable to generate interactive preview"
        );
      }

      setPreviewHTML(data.html);
    } catch (error) {
      console.error(
        "Interactive preview error:",
        error
      );

      setPreviewError(
        error.message ||
          "Unable to generate interactive preview."
      );
    } finally {
      setPreviewLoading(false);
    }
  };

  // ==========================================
  // CLOSE PREVIEW
  // ==========================================

  const closePreview = () => {
    setShowPreview(false);
    setPreviewHTML("");
    setPreviewError("");
  };

  // ==========================================
  // RISK CLASS
  // ==========================================

  const getRiskClass = (level) => {
    if (level === "LOW") return "low-risk";
    if (level === "MEDIUM") return "medium-risk";
    return "high-risk";
  };

  const getMeterClass = (level) => {
    if (level === "LOW") return "low-meter";
    if (level === "MEDIUM") return "medium-meter";
    return "high-meter";
  };

  return (
    <div className="app">

      {/* ======================================
          NAVBAR
      ====================================== */}

      <nav className="navbar">

        <div className="logo">
          🛡️ LinkShield
        </div>

        <span>
          AI + Web3 Security
        </span>

      </nav>

      {/* ======================================
          MAIN
      ====================================== */}

      <main className="hero">

        <div className="badge">
          AI POWERED WEB3 SECURITY
        </div>

        <h1>
          Know the risk
          <br />
          <span>before you click.</span>
        </h1>

        <p className="hero-description">
          LinkShield analyzes suspicious links using AI
          and creates a decentralized threat reputation.
        </p>

        {/* ======================================
            SCANNER
        ====================================== */}

        <div className="scanner">

          <input
            type="text"
            placeholder="Paste a URL here..."
            value={url}
            onChange={(e) =>
              setUrl(e.target.value)
            }
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                scanUrl();
              }
            }}
          />

          <button
            onClick={scanUrl}
            disabled={loading}
          >
            {loading
              ? "Scanning..."
              : "🔍 Scan Link"}
          </button>

        </div>

        {/* ======================================
            RESULT
        ====================================== */}

        {result && (

          <div className="result">

            <h2>
              Security Result
            </h2>

            {/* SCORE */}

            <div
              className={`score ${getRiskClass(
                result.level
              )}`}
            >
              {result.riskScore}/100
            </div>

            {/* LEVEL */}

            <h3
              className={getRiskClass(
                result.level
              )}
            >
              {result.level} RISK
            </h3>

            {/* RISK METER */}

            <div className="risk-meter">

              <div
                className={`risk-meter-fill ${getMeterClass(
                  result.level
                )}`}
                style={{
                  width: `${result.riskScore}%`,
                }}
              />

            </div>

            <p className="result-message">
              {result.message}
            </p>

            <small className="result-url">
              {result.url}
            </small>

            {/* ==================================
                HIGH RISK INLINE WARNING
            ================================== */}

            {result.level === "HIGH" && (

              <div className="high-risk-warning">

                <div className="high-risk-warning-title">
                  🚨 High Risk Warning
                </div>

                <p>
                  This URL has been classified as
                  high risk. Avoid entering passwords,
                  payment information, OTPs, wallet
                  details, or other sensitive data.
                </p>

                {result.threatIntel?.knownThreat && (
                  <p>
                    <strong>
                      Known threat detected:
                    </strong>{" "}
                    {result.threatIntel.sources?.join(
                      ", "
                    ) || "Threat intelligence source"}
                  </p>
                )}

              </div>

            )}

            {/* ==================================
                THREAT INTELLIGENCE
            ================================== */}

            <div className="threat-intel">

              <h3>
                🌐 Threat Intelligence
              </h3>

              {result.threatIntel?.knownThreat ? (

                <div className="threat-danger">

                  🔴 Known malicious URL detected

                  <p>
                    Source:{" "}
                    {result.threatIntel.sources?.join(
                      ", "
                    )}
                  </p>

                  {result.threatIntel.threatType && (

                    <p>
                      Threat type:{" "}
                      {result.threatIntel.threatType}
                    </p>

                  )}

                </div>

              ) : (

                <div className="threat-safe">

                  🟢 No known threat found in the
                  connected threat database.

                </div>

              )}

            </div>

            {/* ==================================
                REASONS
            ================================== */}

            <div className="reasons">

              <h3>
                Why was this score given?
              </h3>

              {result.reasons &&
              result.reasons.length > 0 ? (

                <ul>

                  {result.reasons.map(
                    (reason, index) => (

                      <li key={index}>
                        ⚠️ {reason}
                      </li>

                    )
                  )}

                </ul>

              ) : (

                <p className="no-reasons">
                  ✅ No suspicious indicators
                  detected.
                </p>

              )}

            </div>

            {/* ==================================
                AI ANALYSIS
            ================================== */}

            {result.aiAnalysis && (

              <div className="ai-analysis">

                <h3>
                  🤖 AI Security Analysis
                </h3>

                <div className="ai-box">

                  <p>
                    <strong>
                      Analysis:
                    </strong>
                  </p>

                  <p>
                    {
                      result.aiAnalysis
                        .explanation
                    }
                  </p>

                  <p className="recommendation">

                    <strong>
                      Recommendation:
                    </strong>{" "}

                    {
                      result.aiAnalysis
                        .recommendation
                    }

                  </p>

                </div>

              </div>

            )}

            {/* ==================================
                INTERACTIVE SAFE PREVIEW
            ================================== */}

            <div className="preview-section">

              <div className="preview-title-row">

                <h3>
                  👁️ Interactive Safe Preview
                </h3>

                <span className="protected-badge">
                  🛡️ Protected
                </span>

              </div>

              <p className="preview-description">
                Explore the website through
                LinkShield's isolated browser preview
                before opening it directly.
              </p>

              <div className="privacy-note">

                🔒 The scanned website is opened by
                LinkShield's backend browser rather than
                directly by your browser.

              </div>

              <button
                className="preview-button"
                onClick={openPreview}
                disabled={previewLoading}
              >

                {previewLoading
                  ? "⏳ Creating Preview..."
                  : "👁️ Open Interactive Preview"}

              </button>

            </div>

          </div>

        )}

      </main>

      {/* ======================================
          INTERACTIVE PREVIEW OVERLAY
      ====================================== */}

      {showPreview && (

        <div className="preview-overlay">

          <div className="preview-window">

            {/* HEADER */}

            <div className="preview-header">

              <div className="preview-header-info">

                <strong>
                  🛡️ LinkShield Interactive Preview
                </strong>

                <span className="preview-url">
                  {result?.url}
                </span>

              </div>

              <button
                className="close-preview"
                onClick={closePreview}
                aria-label="Close preview"
              >
                ✕
              </button>

            </div>

            {/* SECURITY WARNING */}

            <div className="preview-warning">

              <span>
                🛡️ Isolated Protected Preview
              </span>

              <p>
                This website is rendered through
                LinkShield's controlled browser environment.
                Direct navigation, forms and other
                potentially dangerous actions remain
                restricted.
              </p>

            </div>

            {/* PREVIEW BODY */}

            <div className="preview-body">

              {previewLoading && (

                <div className="preview-loading">

                  <div className="loading-spinner" />

                  <h3>
                    Creating Interactive Preview
                  </h3>

                  <p>
                    LinkShield is loading the webpage
                    inside its protected browser...
                  </p>

                </div>

              )}

              {!previewLoading &&
                previewError && (

                  <div className="preview-error">

                    <div className="preview-error-icon">
                      ⚠️
                    </div>

                    <h3>
                      Preview Unavailable
                    </h3>

                    <p>
                      {previewError}
                    </p>

                    <button
                      onClick={openPreview}
                      className="retry-button"
                    >
                      🔄 Try Again
                    </button>

                  </div>

                )}

              {!previewLoading &&
                !previewError &&
                previewHTML && (

                  <iframe
  className="safe-preview-frame"
  srcDoc={previewHTML}
  title="LinkShield Protected Visual Preview"
  sandbox=""
  referrerPolicy="no-referrer"
/>

                )}

            </div>

            {/* FOOTER */}

            <div className="preview-footer">

              <span>
                🛡️ LinkShield Protected
              </span>

              <span>
                Backend-rendered preview
              </span>

              <button
                onClick={closePreview}
              >
                Close
              </button>

            </div>

          </div>

        </div>

      )}

    </div>
  );
}

export default App;