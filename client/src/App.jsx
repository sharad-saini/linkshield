import { useEffect, useMemo, useState } from "react";
import "./App.css";

import Login from "./Login";
import { auth, db } from "./firebase";

import {
  onAuthStateChanged,
  signOut,
} from "firebase/auth";

import {
  collection,
  deleteDoc,
  doc,
  onSnapshot,
  query,
  where,
} from "firebase/firestore";

import { saveScan } from "./scanService";

const API_BASE =
  import.meta.env.VITE_API_BASE_URL ||
  "https://linkshield-ub5b.onrender.com";

/* =========================================================
   HELPERS
========================================================= */

const getWebsiteName = (url) => {
  if (!url) return "";

  try {
    const normalized = /^https?:\/\//i.test(url)
      ? url
      : `https://${url}`;

    const hostname = new URL(normalized).hostname
      .replace(/^www\./i, "");

    return hostname;
  } catch {
    return "";
  }
};

const getDateObject = (scan) => {
  if (!scan?.createdAt) return null;

  try {
    if (
      typeof scan.createdAt.toDate ===
      "function"
    ) {
      return scan.createdAt.toDate();
    }

    if (
      typeof scan.createdAt.seconds ===
      "number"
    ) {
      return new Date(
        scan.createdAt.seconds * 1000
      );
    }

    if (scan.createdAt instanceof Date) {
      return scan.createdAt;
    }

    const date = new Date(scan.createdAt);

    return Number.isNaN(date.getTime())
      ? null
      : date;
  } catch {
    return null;
  }
};

const formatDate = (scan) => {
  const date = getDateObject(scan);

  if (!date) {
    return "Date unavailable";
  }

  return date.toLocaleString([], {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
};

const getScanLevel = (scan) => {
  const level =
    scan?.level ||
    scan?.result?.level ||
    "";

  if (level) {
    return String(level).toUpperCase();
  }

  const score =
    scan?.riskScore ??
    scan?.result?.riskScore;

  if (typeof score === "number") {
    if (score >= 70) return "HIGH";
    if (score >= 40) return "MEDIUM";
    return "LOW";
  }

  return "UNKNOWN";
};

const getScanScore = (scan) => {
  if (
    scan?.riskScore !== null &&
    scan?.riskScore !== undefined
  ) {
    return Number(scan.riskScore);
  }

  if (
    scan?.result?.riskScore !== null &&
    scan?.result?.riskScore !== undefined
  ) {
    return Number(scan.result.riskScore);
  }

  return 0;
};

const getScanMessage = (scan) => {
  if (
    typeof scan?.result === "string"
  ) {
    return scan.result;
  }

  return (
    scan?.result?.message ||
    scan?.message ||
    scan?.result?.analysis ||
    "Scan completed"
  );
};

const getScanSiteName = (scan) => {
  return (
    scan?.siteName ||
    scan?.result?.siteName ||
    scan?.result?.title ||
    scan?.result?.pageTitle ||
    getWebsiteName(scan?.url) ||
    "Unknown website"
  );
};

const getRiskClass = (level) => {
  if (level === "LOW") {
    return "low-risk";
  }

  if (level === "MEDIUM") {
    return "medium-risk";
  }

  return "high-risk";
};

const getMeterClass = (level) => {
  if (level === "LOW") {
    return "low-meter";
  }

  if (level === "MEDIUM") {
    return "medium-meter";
  }

  return "high-meter";
};

/* =========================================================
   APP
========================================================= */

function App() {
  /* =======================================================
     AUTH
  ======================================================= */

  const [user, setUser] = useState(null);
  const [authLoading, setAuthLoading] =
    useState(true);

  /* =======================================================
     SCANNER
  ======================================================= */

  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  /* =======================================================
     PREVIEW
  ======================================================= */

  const [showPreview, setShowPreview] =
    useState(false);

  const [previewHTML, setPreviewHTML] =
    useState("");

  const [previewLoading, setPreviewLoading] =
    useState(false);

  const [previewError, setPreviewError] =
    useState("");

  /* =======================================================
     HISTORY
  ======================================================= */

  const [showHistory, setShowHistory] =
    useState(false);

  const [history, setHistory] = useState([]);

  const [historyLoading, setHistoryLoading] =
    useState(false);

  const [historyError, setHistoryError] =
    useState("");

  const [historySearch, setHistorySearch] =
    useState("");

  const [activeFilter, setActiveFilter] =
    useState("ALL");

  const [selectedScans, setSelectedScans] =
    useState([]);

  const [showSuggestions, setShowSuggestions] =
    useState(false);

  /* =======================================================
     AUTH LISTENER
  ======================================================= */

  useEffect(() => {
    const unsubscribe =
      onAuthStateChanged(
        auth,
        (currentUser) => {
          setUser(currentUser);
          setAuthLoading(false);
        }
      );

    return () => unsubscribe();
  }, []);

  /* =======================================================
     LOAD ONLY CURRENT USER'S HISTORY
     
     IMPORTANT:
     No orderBy() here.
     We sort locally so Firestore composite
     index is NOT required.
  ======================================================= */

  useEffect(() => {
    if (!user) {
      setHistory([]);
      setSelectedScans([]);
      setHistoryLoading(false);
      return;
    }

    setHistoryLoading(true);
    setHistoryError("");

    const scansQuery = query(
      collection(db, "scans"),
      where("userId", "==", user.uid)
    );

    const unsubscribe = onSnapshot(
      scansQuery,
      { includeMetadataChanges: true },
      (snapshot) => {
        const scans =
          snapshot.docs.map((item) => ({
            id: item.id,
            ...item.data(),
          }));

        /* Newest first */
        scans.sort((a, b) => {
          const dateA =
            getDateObject(a)?.getTime() || 0;

          const dateB =
            getDateObject(b)?.getTime() || 0;

          return dateB - dateA;
        });

        setHistory(scans);
        setHistoryLoading(false);
        setHistoryError("");

        /* Remove deleted IDs from selection */
        setSelectedScans((current) =>
          current.filter((id) =>
            scans.some(
              (scan) => scan.id === id
            )
          )
        );
      },
      (error) => {
        console.error(
          "History loading error:",
          error
        );

        setHistory([]);
        setHistoryLoading(false);

        setHistoryError(
          "Unable to load your scan history. Check Firestore rules and login status."
        );
      }
    );

    return () => unsubscribe();
  }, [user]);

  /* =======================================================
     USER DISPLAY NAME
  ======================================================= */

  const userDisplayName = useMemo(() => {
    if (!user) return "";

    if (user.isAnonymous) {
      return "Guest";
    }

    return (
      user.displayName ||
      user.email?.split("@")[0] ||
      "User"
    );
  }, [user]);

  /* =======================================================
     LOGOUT
  ======================================================= */

  const handleLogout = async () => {
    try {
      await signOut(auth);

      setResult(null);
      setUrl("");

      setShowHistory(false);

      setHistory([]);
      setSelectedScans([]);

      setHistorySearch("");
      setActiveFilter("ALL");

      setShowPreview(false);
      setPreviewHTML("");
      setPreviewError("");
    } catch (error) {
      console.error(
        "Logout error:",
        error
      );

      alert(
        "Unable to logout. Please try again."
      );
    }
  };

  /* =======================================================
     SCAN URL
  ======================================================= */

  const scanUrl = async () => {
    const scannedUrl = url.trim();

    if (!scannedUrl) {
      alert("Please enter a URL.");
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
            "Content-Type":
              "application/json",
          },
          body: JSON.stringify({
            url: scannedUrl,
          }),
        }
      );

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          data.error ||
            "Unable to scan URL."
        );
      }

      /* Show result */
      setResult(data);

      /* =================================================
         SAVE TO FIRESTORE
      ================================================= */

      if (user) {
        const savedScan = await saveScan({
          userId: user.uid,
          url: scannedUrl,
          result: data,
          riskScore:
            data.riskScore ?? null,
        });

        // Show the new scan immediately. Firestore onSnapshot()
        // remains the server source of truth and will reconcile it.
        if (savedScan?.id) {
          setHistory((current) => {
            const optimisticScan = {
              id: savedScan.id,
              ...savedScan.data,
              createdAt: savedScan.data.createdAt || new Date(),
            };

            return [
              optimisticScan,
              ...current.filter(
                (scan) => scan.id !== optimisticScan.id
              ),
            ];
          });
        }
      }

      /* =================================================
         HIGH RISK ALERT
      ================================================= */

      if (data.level === "HIGH") {
        const message =
          data.threatIntel?.knownThreat
            ? `🚨 KNOWN MALICIOUS URL\n\n` +
              `Risk Score: ${data.riskScore}/100\n\n` +
              `Threat detected by: ${
                data.threatIntel.sources?.join(
                  ", "
                ) ||
                "connected threat intelligence"
              }\n\n` +
              `⛔ Do not visit, sign in, download files, enter OTPs, make payments, or connect a wallet.`
            : `🚨 HIGH RISK WEBSITE\n\n` +
              `Risk Score: ${data.riskScore}/100\n\n` +
              `Multiple suspicious indicators were detected.\n\n` +
              `⚠️ Do not enter passwords, payment details, OTPs, wallet information, or other sensitive data.`;

        setTimeout(() => {
          alert(message);
        }, 100);
      }
    } catch (error) {
      console.error(
        "Scan error:",
        error
      );

      alert(
        error.message ||
          "Unable to connect to LinkShield server."
      );
    } finally {
      setLoading(false);
    }
  };

  /* =======================================================
     SAFE INTERACTIVE PREVIEW
  ======================================================= */

  const openPreview = async () => {
    if (!result?.url) {
      return;
    }

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
            "Content-Type":
              "application/json",
          },
          body: JSON.stringify({
            url: result.url,
          }),
        }
      );

      const data =
        await response.json();

      if (
        !response.ok ||
        !data.success
      ) {
        throw new Error(
          data.error ||
            data.message ||
            "Unable to generate interactive preview."
        );
      }

      setPreviewHTML(
        data.html || ""
      );
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

  const closePreview = () => {
    setShowPreview(false);
    setPreviewHTML("");
    setPreviewError("");
  };

  /* =======================================================
     SEARCHABLE TEXT
     
     One search box searches:
     - URL
     - website/site name
     - domain
     - risk
     - score
     - result/message
     - date
     ======================================================= */

  const getSearchableText = (scan) => {
    const urlText = String(
      scan?.url || ""
    );

    const siteName =
      getScanSiteName(scan);

    const domain =
      getWebsiteName(scan?.url);

    const level =
      getScanLevel(scan);

    const score =
      getScanScore(scan);

    const message =
      getScanMessage(scan);

    const date =
      getDateObject(scan);

    const dateTexts = date
      ? [
          date.toLocaleString(),
          date.toLocaleDateString(),
          date.toLocaleDateString(
            "en-US",
            {
              day: "2-digit",
              month: "short",
              year: "numeric",
            }
          ),
          date.toLocaleDateString(
            "en-US",
            {
              month: "long",
              year: "numeric",
            }
          ),
          date.toLocaleDateString(
            "en-US",
            {
              month: "short",
              year: "numeric",
            }
          ),
        ]
      : [];

    return [
      urlText,
      siteName,
      domain,
      level,
      String(score),
      message,
      ...dateTexts,
    ]
      .join(" ")
      .toLowerCase();
  };

  /* =======================================================
     DATE SEARCH
  ======================================================= */

  const matchesDateSearch = (
    scan,
    search
  ) => {
    if (!search) return true;

    const date =
      getDateObject(scan);

    if (!date) return false;

    const normalized =
      search.toLowerCase().trim();

    const now = new Date();

    const startToday = new Date(
      now.getFullYear(),
      now.getMonth(),
      now.getDate()
    );

    const tomorrow = new Date(
      now.getFullYear(),
      now.getMonth(),
      now.getDate() + 1
    );

    const yesterday = new Date(
      now.getFullYear(),
      now.getMonth(),
      now.getDate() - 1
    );

    const sevenDaysAgo = new Date(
      now.getFullYear(),
      now.getMonth(),
      now.getDate() - 7
    );

    if (
      normalized === "today"
    ) {
      return (
        date >= startToday &&
        date < tomorrow
      );
    }

    if (
      normalized === "yesterday"
    ) {
      return (
        date >= yesterday &&
        date < startToday
      );
    }

    if (
      normalized.includes(
        "last 7 days"
      ) ||
      normalized === "7 days"
    ) {
      return date >= sevenDaysAgo;
    }

    return false;
  };

  /* =======================================================
     FILTER HISTORY
  ======================================================= */

  const filteredHistory = useMemo(() => {
    const search =
      historySearch
        .trim()
        .toLowerCase();

    return history.filter(
      (scan) => {
        const level =
          getScanLevel(scan);

        const date =
          getDateObject(scan);

        /* ---------------------------
           RISK FILTER
        --------------------------- */

        if (
          activeFilter !== "ALL" &&
          activeFilter !== "TODAY" &&
          activeFilter !== "YESTERDAY" &&
          activeFilter !== "WEEK"
        ) {
          if (
            level !== activeFilter
          ) {
            return false;
          }
        }

        /* ---------------------------
           TODAY FILTER
        --------------------------- */

        if (
          activeFilter === "TODAY"
        ) {
          if (!date) return false;

          const now = new Date();

          const startToday =
            new Date(
              now.getFullYear(),
              now.getMonth(),
              now.getDate()
            );

          const tomorrow =
            new Date(
              now.getFullYear(),
              now.getMonth(),
              now.getDate() + 1
            );

          if (
            date < startToday ||
            date >= tomorrow
          ) {
            return false;
          }
        }

        /* ---------------------------
           YESTERDAY FILTER
        --------------------------- */

        if (
          activeFilter ===
          "YESTERDAY"
        ) {
          if (!date) return false;

          const now = new Date();

          const startToday =
            new Date(
              now.getFullYear(),
              now.getMonth(),
              now.getDate()
            );

          const yesterday =
            new Date(
              now.getFullYear(),
              now.getMonth(),
              now.getDate() - 1
            );

          if (
            date < yesterday ||
            date >= startToday
          ) {
            return false;
          }
        }

        /* ---------------------------
           LAST 7 DAYS
        --------------------------- */

        if (
          activeFilter === "WEEK"
        ) {
          if (!date) return false;

          const now = new Date();

          const sevenDaysAgo =
            new Date();

          sevenDaysAgo.setDate(
            now.getDate() - 7
          );

          if (
            date < sevenDaysAgo
          ) {
            return false;
          }
        }

        /* ---------------------------
           SEARCH
        --------------------------- */

        if (!search) {
          return true;
        }

        /*
          Direct searchable match.
          This handles URL, name,
          domain, date, risk, score,
          result etc.
        */
        if (
          getSearchableText(
            scan
          ).includes(search)
        ) {
          return true;
        }

        /*
          Natural date searches:
          today
          yesterday
          last 7 days
        */
        if (
          matchesDateSearch(
            scan,
            search
          )
        ) {
          return true;
        }

        return false;
      }
    );
  }, [
    history,
    historySearch,
    activeFilter,
  ]);

  /* =======================================================
     AUTOCOMPLETE SUGGESTIONS
  ======================================================= */

  const suggestions = useMemo(() => {
    const search =
      historySearch
        .trim()
        .toLowerCase();

    if (!search) {
      return [];
    }

    const resultSuggestions = [];
    const used = new Set();

    const addSuggestion = (
      type,
      value,
      icon
    ) => {
      if (!value) return;

      const key =
        `${type}-${value}`.toLowerCase();

      if (used.has(key)) {
        return;
      }

      if (
        !String(value)
          .toLowerCase()
          .includes(search)
      ) {
        return;
      }

      used.add(key);

      resultSuggestions.push({
        type,
        value,
        icon,
      });
    };

    /* URL + SITE NAME + DATE + RISK */
    history.forEach((scan) => {
      addSuggestion(
        "URL",
        scan.url,
        "🔗"
      );

      addSuggestion(
        "SITE",
        getScanSiteName(scan),
        "🌐"
      );

      const date =
        getDateObject(scan);

      if (date) {
        addSuggestion(
          "DATE",
          date.toLocaleDateString(
            "en-US",
            {
              day: "2-digit",
              month: "short",
              year: "numeric",
            }
          ),
          "📅"
        );
      }

      addSuggestion(
        "RISK",
        getScanLevel(scan),
        getScanLevel(scan) ===
          "HIGH"
          ? "🔴"
          : getScanLevel(scan) ===
            "MEDIUM"
          ? "🟠"
          : "🟢"
      );
    });

    /* Natural date suggestions */
    addSuggestion(
      "DATE",
      "today",
      "📅"
    );

    addSuggestion(
      "DATE",
      "yesterday",
      "📅"
    );

    addSuggestion(
      "DATE",
      "last 7 days",
      "📅"
    );

    return resultSuggestions.slice(
      0,
      8
    );
  }, [
    history,
    historySearch,
  ]);

  /* =======================================================
     SELECT / UNSELECT
  ======================================================= */

  const toggleScanSelection = (
    scanId
  ) => {
    setSelectedScans(
      (current) =>
        current.includes(scanId)
          ? current.filter(
              (id) => id !== scanId
            )
          : [
              ...current,
              scanId,
            ]
    );
  };

  /* =======================================================
     SELECT ALL
  ======================================================= */

  const allFilteredSelected =
    filteredHistory.length > 0 &&
    filteredHistory.every(
      (scan) =>
        selectedScans.includes(
          scan.id
        )
    );

  const toggleSelectAll = () => {
    const visibleIds =
      filteredHistory.map(
        (scan) => scan.id
      );

    if (
      visibleIds.length === 0
    ) {
      return;
    }

    if (
      allFilteredSelected
    ) {
      setSelectedScans(
        (current) =>
          current.filter(
            (id) =>
              !visibleIds.includes(
                id
              )
          )
      );
    } else {
      setSelectedScans(
        (current) => [
          ...new Set([
            ...current,
            ...visibleIds,
          ]),
        ]
      );
    }
  };

  /* =======================================================
     DELETE ONE SCAN
  ======================================================= */

  const deleteOneScan = async (
    scanId
  ) => {
    const confirmed =
      window.confirm(
        "Delete this scan from your history?\n\nThis action cannot be undone."
      );

    if (!confirmed) {
      return;
    }

    try {
      await deleteDoc(
        doc(
          db,
          "scans",
          scanId
        )
      );

      setSelectedScans(
        (current) =>
          current.filter(
            (id) =>
              id !== scanId
          )
      );
    } catch (error) {
      console.error(
        "Delete scan error:",
        error
      );

      alert(
        "Unable to delete this scan. Please try again."
      );
    }
  };

  /* =======================================================
     DELETE SELECTED
  ======================================================= */

  const deleteSelectedScans =
    async () => {
      if (
        selectedScans.length ===
        0
      ) {
        return;
      }

      const confirmed =
        window.confirm(
          `Delete ${selectedScans.length} selected scan${
            selectedScans.length ===
            1
              ? ""
              : "s"
          }?\n\nThis action cannot be undone.`
        );

      if (!confirmed) {
        return;
      }

      try {
        await Promise.all(
          selectedScans.map(
            (scanId) =>
              deleteDoc(
                doc(
                  db,
                  "scans",
                  scanId
                )
              )
          )
        );

        setSelectedScans([]);
      } catch (error) {
        console.error(
          "Bulk delete error:",
          error
        );

        alert(
          "Some scans could not be deleted. Please try again."
        );
      }
    };

  /* =======================================================
     CLEAR SEARCH
  ======================================================= */

  const clearHistorySearch =
    () => {
      setHistorySearch("");
      setShowSuggestions(false);
    };

  /* =======================================================
     SELECT SUGGESTION
  ======================================================= */

  const selectSuggestion = (
    suggestion
  ) => {
    setHistorySearch(
      suggestion.value
    );

    setActiveFilter("ALL");
    setShowSuggestions(false);
  };

  /* =======================================================
     OPEN / CLOSE HISTORY
  ======================================================= */

  const openHistory = () => {
    setShowHistory(true);
    setShowSuggestions(false);
  };

  const closeHistory = () => {
    setShowHistory(false);
    setShowSuggestions(false);
    setSelectedScans([]);
  };

  /* =======================================================
     AUTH LOADING
  ======================================================= */

  if (authLoading) {
    return (
      <div className="auth-loading">
        <div className="auth-loading-icon">
        </div>

        <h2>
          LinkShield
        </h2>

        <p>
          Loading secure environment...
        </p>
      </div>
    );
  }

  /* =======================================================
     LOGIN
  ======================================================= */

  if (!user) {
    return (
      <Login
        onLogin={setUser}
      />
    );
  }

  /* =======================================================
     MAIN APP
  ======================================================= */

  return (
    <div className="app">

      {/* ===================================================
          NAVBAR
      =================================================== */}

      <nav className="navbar">

        <div className="logo">
          <img
            src="/linkshield-logo.png"
            alt="LinkShield"
            className="navbar-logo-image"
          />
        </div>

        <div className="nav-right">

          <span className="security-label">
            AI + Web3 Security
          </span>

          <span
            className="user-avatar"
            aria-hidden="true"
          >
            {(userDisplayName || "G").trim().charAt(0).toUpperCase()}
          </span>

          <span
            className="user-info"
            title={userDisplayName}
          >
            {userDisplayName}
          </span>

          <button
            className="history-button"
            onClick={openHistory}
            aria-label="Open scan history"
            title="Scan history"
          >
            <span className="nav-button-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" focusable="false">
                <path d="M6 4.5h12v15H6z" fill="none" stroke="currentColor" strokeWidth="1.7"/>
                <path d="M9 8h6M9 11.5h6M9 15h4" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round"/>
              </svg>
            </span>
            <span className="nav-action-text">History</span>
          </button>

          <button
            className="logout-button"
            onClick={handleLogout}
            aria-label="Log out"
            title="Log out"
          >
            <span className="nav-button-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" focusable="false">
                <path d="M10 5H5.5A1.5 1.5 0 0 0 4 6.5v11A1.5 1.5 0 0 0 5.5 19H10" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round"/>
                <path d="M13 8l4 4-4 4M17 12H9" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </span>
            <span className="nav-action-text">Logout</span>
          </button>

        </div>
      </nav>

      {/* ===================================================
          MAIN HERO
      =================================================== */}

      <main className="hero">

        <div className="badge">
          AI POWERED WEB3 SECURITY
        </div>

        <h1>
          Know the risk
          <br />
          <span>
            before you click.
          </span>
        </h1>

        <p className="hero-description">
          LinkShield analyzes suspicious links
          using AI and creates a decentralized
          threat reputation.
        </p>

        {/* =================================================
            SCANNER
        ================================================= */}

        <div className="scanner">

          <input
            type="text"
            placeholder="Paste a URL here..."
            value={url}
            onChange={(e) =>
              setUrl(e.target.value)
            }
            onKeyDown={(e) => {
              if (
                e.key === "Enter"
              ) {
                scanUrl();
              }
            }}
          />

          <button
            onClick={scanUrl}
            disabled={loading}
          >
            {loading
              ? "⏳ Scanning..."
              : "🔍 Scan Link"}
          </button>

        </div>

        {/* =================================================
            HISTORY
        ================================================= */}

        {showHistory && (
          <section className="history-section">

            <div className="history-header">

              <div>
                <h2>
                  📜 Scan History
                </h2>

                <p>
                  Search and manage your previous
                  LinkShield scans.
                </p>
              </div>

              <button
                className="close-history"
                onClick={closeHistory}
                aria-label="Close history"
              >
                ✕
              </button>

            </div>

            {/* =============================================
                SEARCH
            ============================================= */}

            <div className="history-search-wrapper">

              <div className="history-search-row">

                <span className="history-search-icon">
                  🔎
                </span>

                <input
                  type="text"
                  className="history-search"
                  placeholder="Search URL, website name, date, risk..."
                  value={historySearch}
                  onChange={(e) => {
                    setHistorySearch(
                      e.target.value
                    );

                    setShowSuggestions(
                      e.target.value.trim().length > 0
                    );
                  }}
                  onFocus={() => {
                    if (
                      historySearch.trim()
                    ) {
                      setShowSuggestions(
                        true
                      );
                    }
                  }}
                  onKeyDown={(e) => {
                    if (
                      e.key ===
                      "Escape"
                    ) {
                      setShowSuggestions(
                        false
                      );
                    }
                  }}
                />

                {historySearch && (
                  <button
                    className="clear-history-search"
                    onClick={
                      clearHistorySearch
                    }
                    aria-label="Clear search"
                  >
                    ✕
                  </button>
                )}

              </div>

              {/* =========================================
                  AUTOCOMPLETE
              ========================================= */}

              {showSuggestions &&
                suggestions.length > 0 && (
                  <div className="history-suggestions">

                    <div className="suggestions-title">
                      ✨ Suggestions
                    </div>

                    {suggestions.map(
                      (
                        suggestion,
                        index
                      ) => (
                        <button
                          key={`${suggestion.type}-${suggestion.value}-${index}`}
                          className="history-suggestion"
                          onMouseDown={(
                            e
                          ) =>
                            e.preventDefault()
                          }
                          onClick={() =>
                            selectSuggestion(
                              suggestion
                            )
                          }
                        >

                          <span className="suggestion-icon">
                            {
                              suggestion.icon
                            }
                          </span>

                          <span className="suggestion-type">
                            {
                              suggestion.type
                            }
                          </span>

                          <span className="suggestion-value">
                            {
                              suggestion.value
                            }
                          </span>

                        </button>
                      )
                    )}

                  </div>
                )}

            </div>

            {/* =============================================
                QUICK FILTERS
            ============================================= */}

            <div className="history-quick-filters">

              <span className="quick-filter-label">
                Filter:
              </span>

              <button
                className={`quick-filter ${
                  activeFilter ===
                  "ALL"
                    ? "active"
                    : ""
                }`}
                onClick={() =>
                  setActiveFilter(
                    "ALL"
                  )
                }
              >
                All
              </button>

              <button
                className={`quick-filter ${
                  activeFilter ===
                  "TODAY"
                    ? "active"
                    : ""
                }`}
                onClick={() =>
                  setActiveFilter(
                    "TODAY"
                  )
                }
              >
                📅 Today
              </button>

              <button
                className={`quick-filter ${
                  activeFilter ===
                  "YESTERDAY"
                    ? "active"
                    : ""
                }`}
                onClick={() =>
                  setActiveFilter(
                    "YESTERDAY"
                  )
                }
              >
                Yesterday
              </button>

              <button
                className={`quick-filter ${
                  activeFilter ===
                  "WEEK"
                    ? "active"
                    : ""
                }`}
                onClick={() =>
                  setActiveFilter(
                    "WEEK"
                  )
                }
              >
                Last 7 Days
              </button>

              <button
                className={`quick-filter low-filter ${
                  activeFilter ===
                  "LOW"
                    ? "active"
                    : ""
                }`}
                onClick={() =>
                  setActiveFilter(
                    "LOW"
                  )
                }
              >
                🟢 Low
              </button>

              <button
                className={`quick-filter medium-filter ${
                  activeFilter ===
                  "MEDIUM"
                    ? "active"
                    : ""
                }`}
                onClick={() =>
                  setActiveFilter(
                    "MEDIUM"
                  )
                }
              >
                🟠 Medium
              </button>

              <button
                className={`quick-filter high-filter ${
                  activeFilter ===
                  "HIGH"
                    ? "active"
                    : ""
                }`}
                onClick={() =>
                  setActiveFilter(
                    "HIGH"
                  )
                }
              >
                🔴 High
              </button>

            </div>

            {/* =============================================
                ERROR
            ============================================= */}

            {historyError && (
              <div className="history-error">
                ⚠️ {historyError}
              </div>
            )}

            {/* =============================================
                ACTIONS
            ============================================= */}

            {!historyLoading &&
              history.length > 0 && (
                <div className="history-actions">

                  <label className="select-all-control">

                    <input
                      type="checkbox"
                      checked={
                        allFilteredSelected
                      }
                      onChange={
                        toggleSelectAll
                      }
                    />

                    <span>
                      Select all visible
                    </span>

                  </label>

                  <div className="history-action-right">

                    <span className="history-count">
                      {
                        filteredHistory.length
                      }{" "}
                      result
                      {filteredHistory.length !==
                      1
                        ? "s"
                        : ""}
                    </span>

                    {selectedScans.length >
                      0 && (
                      <button
                        className="delete-selected"
                        onClick={
                          deleteSelectedScans
                        }
                      >
                        🗑️ Delete Selected (
                        {
                          selectedScans.length
                        }
                        )
                      </button>
                    )}

                  </div>

                </div>
              )}

            {/* =============================================
                HISTORY CONTENT
            ============================================= */}

            <div className="history-list">

              {historyLoading ? (
                <div className="history-loading">

                  <div className="history-spinner" />

                  <h3>
                    Loading history...
                  </h3>

                  <p>
                    Fetching your saved scans.
                  </p>

                </div>
              ) : history.length ===
                0 ? (
                <div className="empty-history">

                  <div className="empty-history-icon">
                    📭
                  </div>

                  <h3>
                    No saved scans yet
                  </h3>

                  <p>
                    Scan a link and your results
                    will appear here automatically.
                  </p>

                </div>
              ) : filteredHistory.length ===
                0 ? (
                <div className="empty-history">

                  <div className="empty-history-icon">
                    🔎
                  </div>

                  <h3>
                    No matching scans
                  </h3>

                  <p>
                    Try a URL, website name,
                    date, risk level, or score.
                  </p>

                  <button
                    className="clear-filter-button"
                    onClick={() => {
                      setHistorySearch("");
                      setActiveFilter(
                        "ALL"
                      );
                    }}
                  >
                    Clear Search & Filters
                  </button>

                </div>
              ) : (
                filteredHistory.map(
                  (scan) => {
                    const level =
                      getScanLevel(
                        scan
                      );

                    const score =
                      getScanScore(
                        scan
                      );

                    const selected =
                      selectedScans.includes(
                        scan.id
                      );

                    return (
                      <div
                        className={`history-item ${
                          selected
                            ? "selected"
                            : ""
                        }`}
                        key={scan.id}
                      >

                        {/* CHECKBOX */}

                        <input
                          className="history-checkbox"
                          type="checkbox"
                          checked={
                            selected
                          }
                          onChange={() =>
                            toggleScanSelection(
                              scan.id
                            )
                          }
                          aria-label="Select scan"
                        />

                        {/* INFO */}

                        <div className="history-info">

                          <div className="history-site-name">
                            🌐{" "}
                            {getScanSiteName(
                              scan
                            )}
                          </div>

                          <div className="history-url">
                            {scan.url ||
                              "Unknown URL"}
                          </div>

                          <div className="history-meta">
                            🕒{" "}
                            {formatDate(
                              scan
                            )}
                            {" • "}
                            {getScanMessage(
                              scan
                            )}
                          </div>

                        </div>

                        {/* RISK */}

                        <div
                          className={`history-risk ${getRiskClass(
                            level
                          )}`}
                        >

                          <strong>
                            {score}/100
                          </strong>

                          <span>
                            {level}
                          </span>

                        </div>

                        {/* DELETE */}

                        <button
                          className="delete-history"
                          onClick={() =>
                            deleteOneScan(
                              scan.id
                            )
                          }
                          title="Delete scan"
                          aria-label="Delete scan"
                        >
                          🗑️
                        </button>

                      </div>
                    );
                  }
                )
              )}

            </div>

          </section>
        )}

        {/* =================================================
            RESULT
        ================================================= */}

        {result && (
          <div className="result">

            <h2>
              Security Result
            </h2>

            <div
              className={`score ${getRiskClass(
                result.level
              )}`}
            >
              {result.riskScore}/100
            </div>

            <h3
              className={getRiskClass(
                result.level
              )}
            >
              {result.level} RISK
            </h3>

            <div className="risk-meter">

              <div
                className={`risk-meter-fill ${getMeterClass(
                  result.level
                )}`}
                style={{
                  width: `${Math.min(
                    100,
                    Math.max(
                      0,
                      Number(
                        result.riskScore ||
                          0
                      )
                    )
                  )}%`,
                }}
              />

            </div>

            <p className="result-message">
              {result.message}
            </p>

            <small className="result-url">
              {result.url}
            </small>

            {/* HIGH RISK */}

            {result.level ===
              "HIGH" && (
              <div className="high-risk-warning">

                <div className="high-risk-warning-title">
                  🚨 High Risk Warning
                </div>

                <p>
                  This URL has been classified
                  as high risk. Avoid entering
                  passwords, payment information,
                  OTPs, wallet details, or other
                  sensitive data.
                </p>

                {result.threatIntel
                  ?.knownThreat && (
                  <p>
                    <strong>
                      Known threat detected:
                    </strong>{" "}
                    {result.threatIntel
                      .sources?.join(
                        ", "
                      ) ||
                      "Threat intelligence source"}
                  </p>
                )}

              </div>
            )}

            {/* THREAT INTELLIGENCE */}

            <div className="threat-intel">

              <h3>
                🌐 Threat Intelligence
              </h3>

              {result.threatIntel
                ?.knownThreat ? (
                <div className="threat-danger">

                  🔴 Known malicious URL
                  detected

                  <p>
                    Source:{" "}
                    {result.threatIntel.sources?.join(
                      ", "
                    ) ||
                      "Unknown"}
                  </p>

                  {result.threatIntel
                    .threatType && (
                    <p>
                      Threat type:{" "}
                      {
                        result
                          .threatIntel
                          .threatType
                      }
                    </p>
                  )}

                </div>
              ) : (
                <div className="threat-safe">
                  🟢 No known threat found
                  in the connected threat
                  database.
                </div>
              )}

            </div>

            {/* REASONS */}

            <div className="reasons">

              <h3>
                Why was this score given?
              </h3>

              {result.reasons &&
              result.reasons.length >
                0 ? (
                <ul>
                  {result.reasons.map(
                    (
                      reason,
                      index
                    ) => (
                      <li
                        key={index}
                      >
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

            {/* AI ANALYSIS */}

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

            {/* SAFE PREVIEW */}

            <div className="preview-section">

              <div className="preview-title-row">

                <h3>
                  👁️ Interactive Safe
                  Preview
                </h3>

                <span className="protected-badge">
                  🛡️ Protected
                </span>

              </div>

              <p className="preview-description">
                Explore the website through
                LinkShield's isolated browser
                preview before opening it directly.
              </p>

              <div className="privacy-note">
                🔒 The scanned website is opened
                by LinkShield's backend browser
                rather than directly by your browser.
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

      {/* ===================================================
          PREVIEW OVERLAY
      =================================================== */}

      {showPreview && (
        <div
          className="preview-overlay"
          onClick={(e) => {
            if (
              e.target ===
              e.currentTarget
            ) {
              closePreview();
            }
          }}
        >

          <div className="preview-window">

            <div className="preview-header">

              <div className="preview-header-info">

                <strong>
                  🛡️ LinkShield
                  Interactive Preview
                </strong>

                <span className="preview-url">
                  {result?.url}
                </span>

              </div>

              <button
                className="close-preview"
                onClick={
                  closePreview
                }
                aria-label="Close preview"
              >
                ✕
              </button>

            </div>

            <div className="preview-warning">

              <span>
                🛡️ Isolated Protected Preview
              </span>

              <p>
                This website is rendered through
                LinkShield's controlled browser
                environment. Direct navigation,
                forms and other potentially dangerous
                actions remain restricted.
              </p>

            </div>

            <div className="preview-body">

              {previewLoading && (
                <div className="preview-loading">

                  <div className="loading-spinner" />

                  <h3>
                    Creating Interactive Preview
                  </h3>

                  <p>
                    LinkShield is loading the
                    webpage inside its protected
                    browser...
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
                      onClick={
                        openPreview
                      }
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

            <div className="preview-footer">

              <span>
                🛡️ LinkShield Protected
              </span>

              <span>
                Backend-rendered preview
              </span>

              <button
                onClick={
                  closePreview
                }
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