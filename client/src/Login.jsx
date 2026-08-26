import React, { useState } from "react";
import { auth } from "./firebase";
import {
  GoogleAuthProvider,
  signInAnonymously,
  signInWithPopup,
} from "firebase/auth";
import "./Login.css";

const GoogleIcon = () => (
  <svg className="login-provider-icon google-icon" viewBox="0 0 24 24" aria-hidden="true">
    <path fill="#4285F4" d="M21.35 12.27c0-.78-.07-1.53-.22-2.25H12v4.26h5.24a4.47 4.47 0 0 1-1.94 2.94v2.45h3.14c1.84-1.69 2.91-4.18 2.91-7.4Z" />
    <path fill="#34A853" d="M12 21.75c2.63 0 4.84-.87 6.45-2.35l-3.14-2.45c-.87.58-1.98.92-3.31.92-2.54 0-4.69-1.72-5.46-4.03H3.3v2.53A9.75 9.75 0 0 0 12 21.75Z" />
    <path fill="#FBBC05" d="M6.54 13.84A5.86 5.86 0 0 1 6.23 12c0-.64.11-1.27.31-1.84V7.63H3.3A9.75 9.75 0 0 0 2.25 12c0 1.57.38 3.06 1.05 4.37l3.24-2.53Z" />
    <path fill="#EA4335" d="M12 6.13c1.43 0 2.71.49 3.72 1.45l2.79-2.79C16.83 3.22 14.62 2.25 12 2.25a9.75 9.75 0 0 0-8.7 5.38l3.24 2.53C7.31 7.85 9.46 6.13 12 6.13Z" />
  </svg>
);

const GuestIcon = () => (
  <svg className="login-provider-icon guest-icon" viewBox="0 0 24 24" aria-hidden="true">
    <circle cx="12" cy="8" r="3.5" fill="none" stroke="currentColor" strokeWidth="1.8" />
    <path d="M5.5 20c.8-4 3.05-6 6.5-6s5.7 2 6.5 6" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
  </svg>
);

export default function Login({ onLogin }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const finishLogin = (user) => {
    if (typeof onLogin === "function") onLogin(user);
  };

  const handleGoogleLogin = async () => {
    if (loading) return;
    setLoading(true);
    setError("");

    try {
      const provider = new GoogleAuthProvider();
      provider.setCustomParameters({ prompt: "select_account" });
      const result = await signInWithPopup(auth, provider);
      finishLogin(result.user);
    } catch (err) {
      console.error("Google sign-in error:", err);
      if (err?.code === "auth/popup-closed-by-user") return;
      setError("Google sign-in could not be completed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleGuestLogin = async () => {
    if (loading) return;
    setLoading(true);
    setError("");

    try {
      const result = await signInAnonymously(auth);
      finishLogin(result.user);
    } catch (err) {
      console.error("Guest sign-in error:", err);
      setError("Guest access is unavailable right now. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="login-page">
      <section className="login-card" aria-labelledby="login-title">
        <div className="login-brand" aria-label="LinkShield">
          <img
            src="/linkshield-shield.png"
            alt="LinkShield shield"
            className="login-brand-shield"
          />
          <span className="login-brand-name">LinkShield</span>
        </div>

        <div className="login-copy">
          <h1 id="login-title">Welcome to LinkShield</h1>
          <p>Protect yourself before you click.</p>
        </div>

        <div className="login-actions">
          <button
            type="button"
            className="login-button google-login-button"
            onClick={handleGoogleLogin}
            disabled={loading}
          >
            <GoogleIcon />
            <span>{loading ? "Signing in..." : "Continue with Google"}</span>
          </button>

          <div className="login-divider" aria-hidden="true">
            <span />
            <strong>OR</strong>
            <span />
          </div>

          <button
            type="button"
            className="login-button guest-login-button"
            onClick={handleGuestLogin}
            disabled={loading}
          >
            <GuestIcon />
            <span>Continue as Guest</span>
          </button>
        </div>

        {error && (
          <div className="login-error" role="alert">
            {error}
          </div>
        )}

        <p className="login-note">
          Sign in to save and view your previous link scans.
        </p>
      </section>
    </main>
  );
}
