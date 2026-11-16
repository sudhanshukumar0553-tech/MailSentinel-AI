import React, { useState } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  X,
  Sparkles,
  UserCheck,
  Lock,
  CheckCircle2,
  AlertCircle,
  Loader2,
  Mail,
  ArrowRight
} from "lucide-react";
import { useAuthContext } from "../context/AuthContext";
import { useTheme } from "../context/ThemeContext";

export const AuthModal: React.FC = () => {
  const { isDark } = useTheme();
  const {
    isAuthModalOpen,
    setIsAuthModalOpen,
    authModalMode,
    setAuthModalMode,
    authModalReason,
    signInWithGoogle,
    signUpWithGoogle,
    isAuthLoading,
    authError,
    setAuthError,
    switchDemoRole,
    isClerkConfigured
  } = useAuthContext();

  const [emailInput, setEmailInput] = useState("");
  const [emailFeedback, setEmailFeedback] = useState<string | null>(null);

  if (!isAuthModalOpen) return null;

  const handleClose = () => {
    setIsAuthModalOpen(false);
    setAuthError(null);
    setEmailFeedback(null);
  };

  const handleGoogleSubmit = async () => {
    setAuthError(null);
    setEmailFeedback(null);
    if (authModalMode === "sign-up") {
      await signUpWithGoogle();
    } else {
      await signInWithGoogle();
    }
  };

  const handleEmailSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!emailInput || !emailInput.includes("@")) {
      setEmailFeedback("Please enter a valid email address.");
      return;
    }
    if (isClerkConfigured) {
      setEmailFeedback("For production Clerk instances, social sign-in with Google is prioritized.");
    } else {
      setEmailFeedback(`Demo authentication for ${emailInput} registered. Use Google OAuth or Sandbox Roles below.`);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md animate-fade-in">
      <div
        className={`relative w-full max-w-md rounded-2xl border p-6 shadow-2xl transition-all ${
          isDark
            ? "bg-[#0D1527] border-cyan-500/30 text-slate-100 shadow-[0_0_50px_rgba(6,182,212,0.18)]"
            : "bg-white border-slate-200 text-slate-900 shadow-2xl"
        }`}
        role="dialog"
        aria-modal="true"
        aria-labelledby="auth-modal-title"
      >
        {/* Animated Aurora Glow Accents */}
        <div className="absolute -top-12 -left-12 w-36 h-36 bg-cyan-500/20 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -bottom-12 -right-12 w-36 h-36 bg-purple-500/20 rounded-full blur-3xl pointer-events-none" />

        {/* Close Button */}
        <button
          onClick={handleClose}
          aria-label="Close authentication modal"
          className={`absolute top-4 right-4 p-1.5 rounded-lg border transition-colors cursor-pointer ${
            isDark
              ? "border-slate-800 text-slate-400 hover:text-white hover:bg-slate-800/60"
              : "border-slate-200 text-slate-500 hover:text-slate-900 hover:bg-slate-100"
          }`}
        >
          <X className="w-5 h-5" />
        </button>

        {/* Modal Header */}
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-purple-600 via-indigo-600 to-cyan-500 flex items-center justify-center shadow-[0_0_15px_rgba(6,182,212,0.4)]">
            <Lock className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 id="auth-modal-title" className="text-lg font-bold tracking-tight">
                {authModalMode === "sign-up" ? "Create MailSentinel Account" : "Sign In to MailSentinel AI"}
              </h2>
              <span className="text-[10px] px-1.5 py-0.5 rounded font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                Phase 5.2
              </span>
            </div>
            <p className={`text-xs ${isDark ? "text-slate-400" : "text-slate-500"}`}>
              SOC Defense & AI Threat Intelligence Platform
            </p>
          </div>
        </div>

        {/* Role Restriction Banner if reason is set */}
        {authModalReason && (
          <div className="mb-4 p-3 rounded-xl border border-amber-500/40 bg-amber-500/10 text-amber-300 text-xs flex items-start gap-2.5">
            <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <div className="leading-relaxed">
              <span className="font-bold">Privilege Escalation Required:</span> {authModalReason}
            </div>
          </div>
        )}

        {/* Error Alert Banner */}
        {authError && (
          <div className="mb-4 p-3 rounded-xl border border-rose-500/40 bg-rose-500/10 text-rose-300 text-xs flex items-start justify-between gap-2 animate-fade-in">
            <div className="flex items-start gap-2">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <span>{authError}</span>
            </div>
            <button
              onClick={() => setAuthError(null)}
              className="text-rose-400 hover:text-white cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {/* Auth Mode Tabs (Sign In / Sign Up) */}
        <div className={`flex rounded-xl p-1 mb-5 border ${isDark ? "bg-slate-900/80 border-slate-800" : "bg-slate-100 border-slate-200"}`}>
          <button
            onClick={() => {
              setAuthModalMode("sign-in");
              setAuthError(null);
            }}
            className={`flex-1 py-1.5 text-xs font-semibold rounded-lg transition-all cursor-pointer ${
              authModalMode === "sign-in"
                ? isDark
                  ? "bg-blue-600/30 text-cyan-300 shadow-sm border border-cyan-500/40 font-bold"
                  : "bg-white text-slate-900 shadow-sm font-bold"
                : isDark
                ? "text-slate-400 hover:text-slate-200"
                : "text-slate-600 hover:text-slate-900"
            }`}
          >
            Sign In
          </button>
          <button
            onClick={() => {
              setAuthModalMode("sign-up");
              setAuthError(null);
            }}
            className={`flex-1 py-1.5 text-xs font-semibold rounded-lg transition-all cursor-pointer ${
              authModalMode === "sign-up"
                ? isDark
                  ? "bg-blue-600/30 text-cyan-300 shadow-sm border border-cyan-500/40 font-bold"
                  : "bg-white text-slate-900 shadow-sm font-bold"
                : isDark
                ? "text-slate-400 hover:text-slate-200"
                : "text-slate-600 hover:text-slate-900"
            }`}
          >
            Create Account
          </button>
        </div>

        {/* Primary Action: Official Google OAuth Button */}
        <div className="space-y-4">
          <button
            onClick={handleGoogleSubmit}
            disabled={isAuthLoading}
            className={`w-full flex items-center justify-center gap-3 px-4 py-3 rounded-xl border font-semibold text-sm transition-all duration-200 cursor-pointer shadow-md hover:scale-[1.01] active:scale-[0.99] disabled:opacity-50 disabled:cursor-not-allowed ${
              isDark
                ? "bg-slate-900/95 border-slate-700 text-white hover:bg-slate-800 hover:border-cyan-500/60 hover:shadow-[0_0_20px_rgba(6,182,212,0.25)]"
                : "bg-white border-slate-300 text-slate-800 hover:bg-slate-50 hover:border-slate-400"
            }`}
          >
            {isAuthLoading ? (
              <Loader2 className="w-5 h-5 animate-spin text-cyan-400" />
            ) : (
              /* SVG Multicolor Google Icon */
              <svg className="w-5 h-5 shrink-0" viewBox="0 0 24 24" aria-hidden="true">
                <path
                  fill="#4285F4"
                  d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                />
                <path
                  fill="#34A853"
                  d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                />
                <path
                  fill="#FBBC05"
                  d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                />
                <path
                  fill="#EA4335"
                  d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                />
              </svg>
            )}
            <span>
              {isAuthLoading
                ? "Connecting to Google Identity..."
                : authModalMode === "sign-up"
                ? "Sign up with Google"
                : "Continue with Google"}
            </span>
          </button>

          {/* Divider */}
          <div className="relative flex items-center justify-center my-3">
            <div className={`w-full border-t ${isDark ? "border-slate-800" : "border-slate-200"}`} />
            <span
              className={`absolute px-3 text-[10px] font-mono uppercase tracking-wider ${
                isDark ? "bg-[#0D1527] text-slate-500" : "bg-white text-slate-400"
              }`}
            >
              Or with Enterprise Email
            </span>
          </div>

          {/* Email Authentication Input Form */}
          <form onSubmit={handleEmailSubmit} className="space-y-2">
            <div className="relative">
              <Mail className="w-4 h-4 absolute left-3 top-3 text-slate-400" />
              <input
                type="email"
                placeholder="analyst@organization.com"
                value={emailInput}
                onChange={(e) => setEmailInput(e.target.value)}
                className={`w-full pl-9 pr-24 py-2.5 rounded-xl border text-xs outline-none transition-all ${
                  isDark
                    ? "bg-slate-900/80 border-slate-700 text-slate-100 focus:border-cyan-500/80 focus:ring-1 focus:ring-cyan-500/30"
                    : "bg-slate-50 border-slate-300 text-slate-900 focus:border-sky-500 focus:ring-1 focus:ring-sky-500/30"
                }`}
              />
              <button
                type="submit"
                className="absolute right-1.5 top-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center gap-1 transition-all cursor-pointer"
              >
                <span>Continue</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>
            {emailFeedback && (
              <p className={`text-[11px] ${emailFeedback.includes("valid") ? "text-rose-400" : "text-cyan-400"}`}>
                {emailFeedback}
              </p>
            )}
          </form>

          {/* Sandbox Role Switcher Section (Active in Sandbox / Dev mode) */}
          {!isClerkConfigured && (
            <div className="pt-2 border-t border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-[10px] font-mono uppercase tracking-wider text-slate-400">
                <span className="flex items-center gap-1">
                  <Sparkles className="w-3 h-3 text-cyan-400" />
                  <span>Sandbox Role Simulation</span>
                </span>
                <span className="text-cyan-400/80">Dev Environment</span>
              </div>

              <div className="grid grid-cols-1 gap-1.5">
                <button
                  type="button"
                  onClick={() => {
                    switchDemoRole?.("Admin");
                    handleClose();
                  }}
                  className={`flex items-center justify-between px-3 py-2 rounded-xl border text-xs font-medium transition-all cursor-pointer ${
                    isDark
                      ? "bg-slate-900/60 border-rose-500/30 text-rose-300 hover:bg-rose-500/10 hover:border-rose-500/50"
                      : "bg-rose-50 border-rose-200 text-rose-800 hover:bg-rose-100"
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-rose-400" />
                    <div className="text-left">
                      <div className="font-semibold text-xs">Chief Security Architect</div>
                      <div className="text-[10px] opacity-80">Admin (Unrestricted SOC Privileges)</div>
                    </div>
                  </div>
                  <CheckCircle2 className="w-3.5 h-3.5 opacity-70" />
                </button>

                <button
                  type="button"
                  onClick={() => {
                    switchDemoRole?.("SOC Analyst");
                    handleClose();
                  }}
                  className={`flex items-center justify-between px-3 py-2 rounded-xl border text-xs font-medium transition-all cursor-pointer ${
                    isDark
                      ? "bg-slate-900/60 border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/10 hover:border-cyan-500/50"
                      : "bg-sky-50 border-sky-200 text-sky-800 hover:bg-sky-100"
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-cyan-400" />
                    <div className="text-left">
                      <div className="font-semibold text-xs">Senior SOC Analyst</div>
                      <div className="text-[10px] opacity-80">SOC Analyst (Deep AI & URL Forensics)</div>
                    </div>
                  </div>
                  <CheckCircle2 className="w-3.5 h-3.5 opacity-70" />
                </button>

                <button
                  type="button"
                  onClick={() => {
                    switchDemoRole?.("Customer");
                    handleClose();
                  }}
                  className={`flex items-center justify-between px-3 py-2 rounded-xl border text-xs font-medium transition-all cursor-pointer ${
                    isDark
                      ? "bg-slate-900/60 border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/10 hover:border-emerald-500/50"
                      : "bg-emerald-50 border-emerald-200 text-emerald-800 hover:bg-emerald-100"
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <UserCheck className="w-4 h-4 text-emerald-400" />
                    <div className="text-left">
                      <div className="font-semibold text-xs">Verified Customer (Google OAuth)</div>
                      <div className="text-[10px] opacity-80">Customer (Standard Threat Scans)</div>
                    </div>
                  </div>
                  <CheckCircle2 className="w-3.5 h-3.5 opacity-70" />
                </button>
              </div>

              {/* Clerk Key Setup Banner */}
              <div
                className={`p-2.5 rounded-xl border text-[11px] font-mono leading-relaxed ${
                  isDark ? "bg-slate-950/70 border-slate-800 text-slate-400" : "bg-slate-50 border-slate-200 text-slate-600"
                }`}
              >
                <div className="flex items-center gap-1.5 font-bold mb-1 text-cyan-400">
                  <Sparkles className="w-3.5 h-3.5 shrink-0" />
                  <span>Clerk Live Credentials Setup:</span>
                </div>
                <span>
                  Paste your copied key into <code className="px-1 py-0.5 rounded bg-slate-800 text-cyan-300">frontend/.env</code> as{" "}
                  <code className="px-1 py-0.5 rounded bg-slate-800 text-cyan-300">VITE_CLERK_PUBLISHABLE_KEY</code> and{" "}
                  <code className="px-1 py-0.5 rounded bg-slate-800 text-cyan-300">backend/.env</code> as{" "}
                  <code className="px-1 py-0.5 rounded bg-slate-800 text-cyan-300">CLERK_SECRET_KEY</code> to enable live Clerk OAuth redirects.
                </span>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
