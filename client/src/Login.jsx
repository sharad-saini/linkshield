import { useState } from "react";
import {
  GoogleAuthProvider,
  signInWithPopup,
  signInAnonymously,
} from "firebase/auth";
import { auth } from "./firebase";
import "./Login.css";

function Login({ onLogin }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const getFirebaseError = (err) => {
    console.error("Firebase error:", err);

    switch (err?.code) {
      case "auth/popup-closed-by-user":
        return "Google sign-in was cancelled.";

      case "auth/popup-blocked":
        return "Google sign-in popup was blocked. Please allow popups.";

      case "auth/cancelled-popup-request":
        return "Another sign-in popup is already open.";

      case "auth/operation-not-allowed":
        return "This sign-in method is not enabled in Firebase.";

      case "auth/unauthorized-domain":
        return "This website domain is not authorized in Firebase.";

      case "auth/network-request-failed":
        return "Network error. Please check your internet connection.";

      case "auth/too-many-requests":
        return "Too many attempts. Please wait and try again.";

      case "auth/admin-restricted-operation":
        return "This authentication operation is restricted.";

      case "auth/invalid-api-key":
        return "Firebase API key is invalid.";

      case "auth/app-not-authorized":
        return "This app is not authorized to use Firebase Authentication.";

      default:
        return err?.message || "Authentication failed. Please try again.";
    }
  };

  const loginWithGoogle = async () => {
    if (loading) return;

    try {
      setLoading(true);
      setError("");

      const provider = new GoogleAuthProvider();

      provider.setCustomParameters({
        prompt: "select_account",
      });

      const result = await signInWithPopup(auth, provider);

      console.log("Google login successful:", result.user);

      onLogin(result.user);
    } catch (err) {
      setError(getFirebaseError(err));
    } finally {
      setLoading(false);
    }
  };

  const continueAsGuest = async () => {
    if (loading) return;

    try {
      setLoading(true);
      setError("");

      const result = await signInAnonymously(auth);

      console.log("Guest login successful:", result.user);

      onLogin(result.user);
    } catch (err) {
      setError(getFirebaseError(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-card">

        <div className="login-logo">
          🛡️
        </div>

        <h1>Welcome to LinkShield</h1>

        <p className="login-subtitle">
          Protect yourself before you click.
        </p>

        <button
          className="google-login"
          onClick={loginWithGoogle}
          disabled={loading}
        >
          {loading ? "Signing in..." : "🌐 Continue with Google"}
        </button>

        <div className="login-divider">
          <span>OR</span>
        </div>

        <button
          className="guest-login"
          onClick={continueAsGuest}
          disabled={loading}
        >
          {loading ? "Please wait..." : "👤 Continue as Guest"}
        </button>

        {error && (
          <div className="login-error">
            {error}
          </div>
        )}

        <p className="login-info">
          Sign in to save and view your previous link scans.
        </p>

      </div>
    </div>
  );
}

export default Login;