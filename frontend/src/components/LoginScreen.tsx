import React from "react";
import {
  ShieldAlert,
  Sun,
  Moon,
  ShieldCheck,
  Lock,
  Sparkles,
  UserCheck,
  CheckCircle2,
  Loader2
} from "lucide-react";
import { SignIn } from "@clerk/react";
import { useTheme } from "../context/ThemeContext";
import { useAuthContext } from "../context/AuthContext";

export const LoginScreen: React.FC = () => {
  const { isDark, toggleTheme } = useTheme();
  const {
    isClerkConfigured,
    signInWithGoogle,
    isAuthLoading,
    authError,
    switchDemoRole
  } = useAuthContext();

  return (
    <div
      className={`min-h-screen flex flex-col justify-between p-4 sm:p-6 lg:p-8 relative overflow-hidden transition-colors duration-200 ${
        isDark ? "bg-[#080D1A] text-slate-100" : "bg-slate-50 text-slate-900"
      }`}
    >
      {/* Animated Aurora Ambient Glow Accents */}
      <div className="absolute -top-32 -left-32 w-96 h-96 bg-cyan-500/15 rounded-full blur-3xl pointer-events-none animate-pulse" />
      <div className="absolute -bottom-32 -right-32 w-96 h-96 bg-purple-500/15 rounded-full blur-3xl pointer-events-none animate-pulse" />
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-blue-600/5 rounded-full blur-3xl pointer-events-none" />

      {/* Top Navigation Bar */}
      <header className="relative z-10 max-w-7xl w-full mx-auto flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-purple-600 via-indigo-600 to-cyan-500 flex items-center justify-center shadow-[0_0_20px_rgba(6,182,212,0.4)]">
            <ShieldAlert className="w-6 h-6 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span
                className={`text-lg sm:text-xl font-bold tracking-wide ${
                  isDark
                    ? "bg-gradient-to-r from-white via-cyan-200 to-cyan-400 bg-clip-text text-transparent"
                    : "text-slate-900 font-extrabold"
                }`}
              >
                MailSentinel
              </span>
              <span className="text-[11px] px-1.5 py-0.5 rounded font-mono font-bold bg-purple-500/20 text-purple-400 border border-purple-500/30">
                AI
              </span>
            </div>
            <p
              className={`text-[9px] sm:text-[10px] font-mono tracking-wider uppercase ${
                isDark ? "text-slate-400" : "text-slate-500 font-medium"
              }`}
            >
              SOC Defense Platform
            </p>
          </div>
        </div>

        {/* Theme Toggle Button */}
        <button
          onClick={toggleTheme}
          aria-label={`Switch to ${isDark ? "light" : "dark"} mode`}
          className={`p-2 rounded-xl border transition-all duration-200 flex items-center justify-center cursor-pointer ${
            isDark
              ? "bg-slate-900 border-slate-700 text-amber-300 hover:bg-slate-800 hover:border-amber-400/50 shadow-[0_0_10px_rgba(252,211,77,0.15)]"
              : "bg-white border-slate-300 text-indigo-600 hover:bg-slate-100 shadow-xs"
          }`}
        >
          {isDark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
        </button>
      </header>

      {/* Main Center Authentication Gateway */}
      <main className="relative z-10 max-w-md w-full mx-auto my-auto py-8">
        <div className="text-center mb-6 space-y-1.5">
          <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-mono font-semibold tracking-wide border border-cyan-500/30 bg-cyan-500/10 text-cyan-300 shadow-[0_0_15px_rgba(6,182,212,0.15)]">
            <Lock className="w-3.5 h-3.5" />
            <span>Zero-Trust Security Gate</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight">Enterprise Authentication</h1>
          <p className={`text-xs ${isDark ? "text-slate-400" : "text-slate-600"}`}>
            Sign in to access Sentinel Copilot, Live Email Threat Scanner & Autonomous SOC Forensics
          </p>
        </div>

        {/* Live Clerk Mode */}
        {isClerkConfigured ? (
          <div className="space-y-4">
            {/* Prominent One-Click Google OAuth Button */}
            <div
              className={`p-5 rounded-2xl border transition-all ${
                isDark
                  ? "bg-[#0D1527]/90 border-cyan-500/30 shadow-[0_0_40px_rgba(6,182,212,0.15)]"
                  : "bg-white border-slate-200 shadow-xl"
              }`}
            >
              <div className="text-center mb-4">
                <span className="text-xs font-semibold text-slate-400 uppercase font-mono tracking-wider">
                  Recommended Access Method
                </span>
              </div>
              <button
                type="button"
                onClick={async () => {
                  console.info("[MailSentinel UI] 'Continue with Google' button clicked.");
                  try {
                    await signInWithGoogle();
                  } catch (e: any) {
                    console.error("[MailSentinel UI] Click handler caught error:", e);
                  }
                }}
                disabled={isAuthLoading}
                className={`w-full flex items-center justify-center gap-3 px-5 py-3.5 rounded-xl border font-bold text-sm transition-all duration-200 cursor-pointer shadow-md hover:scale-[1.01] active:scale-[0.99] disabled:opacity-60 disabled:cursor-not-allowed ${
                  isDark
                    ? "bg-slate-900 border-slate-700 text-white hover:bg-slate-800 hover:border-cyan-500/60 hover:shadow-[0_0_20px_rgba(6,182,212,0.3)]"
                    : "bg-white border-slate-300 text-slate-800 hover:bg-slate-50 hover:border-slate-400"
                }`}
              >
                {isAuthLoading ? (
                  <Loader2 className="w-5 h-5 animate-spin text-cyan-400" />
                ) : (
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
                  {isAuthLoading ? "Connecting to Google Identity..." : "Continue with Google"}
                </span>
              </button>

              {authError && (
                <div className="mt-3 p-3 rounded-xl border border-rose-500/40 bg-rose-500/15 text-rose-300 text-xs flex items-start gap-2.5">
                  <ShieldAlert className="w-4 h-4 shrink-0 text-rose-400 mt-0.5" />
                  <div className="text-left leading-relaxed">
                    <span className="font-semibold block mb-0.5 text-rose-200">Authentication Notice</span>
                    <span>{authError}</span>
                  </div>
                </div>
              )}
            </div>

            {/* Official Clerk In-Page SignIn Component with Custom SOC Styling */}
            <div className="flex justify-center">
              <SignIn
                routing="hash"
                appearance={{
                  elements: {
                    rootBox: "w-full",
                    card: isDark
                      ? "bg-[#0D1527]/90 border border-cyan-500/20 shadow-xl rounded-2xl text-slate-100"
                      : "bg-white border border-slate-200 shadow-lg rounded-2xl text-slate-900",
                    headerTitle: isDark ? "text-slate-100 font-bold" : "text-slate-900 font-bold",
                    headerSubtitle: isDark ? "text-slate-400 text-xs" : "text-slate-500 text-xs",
                    socialButtonsBlockButton: isDark
                      ? "bg-slate-900 border border-slate-700 text-white hover:bg-slate-800 hover:border-cyan-500/50"
                      : "bg-white border border-slate-300 text-slate-800 hover:bg-slate-50",
                    formButtonPrimary:
                      "bg-gradient-to-r from-blue-600 via-indigo-600 to-cyan-500 hover:brightness-110 text-white font-bold",
                    footerActionLink: "text-cyan-400 hover:text-cyan-300 font-semibold"
                  }
                }}
              />
            </div>

            {/* SOC Internal Analyst & Automated Test Access (Local Development Only) */}
            {import.meta.env.DEV && (
              <div
                className={`p-4 rounded-xl border text-xs ${
                  isDark ? "bg-slate-900/60 border-slate-800" : "bg-white border-slate-200 shadow-sm"
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400">
                    Internal SOC Analyst & Test Access (Dev Only)
                  </span>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                    Analyst Bypass
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => switchDemoRole?.("SOC Analyst")}
                    className={`flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg border text-xs font-semibold transition-all cursor-pointer ${
                      isDark
                        ? "bg-slate-800/80 border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/10 hover:border-cyan-500/50"
                        : "bg-sky-50 border-sky-200 text-sky-800 hover:bg-sky-100"
                    }`}
                  >
                    <ShieldCheck className="w-3.5 h-3.5" />
                    <span>Senior SOC Analyst</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => switchDemoRole?.("Admin")}
                    className={`flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg border text-xs font-semibold transition-all cursor-pointer ${
                      isDark
                        ? "bg-slate-800/80 border-purple-500/30 text-purple-300 hover:bg-purple-500/10 hover:border-purple-500/50"
                        : "bg-purple-50 border-purple-200 text-purple-800 hover:bg-purple-100"
                    }`}
                  >
                    <ShieldAlert className="w-3.5 h-3.5" />
                    <span>Chief Architect</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        ) : (
          /* Sandbox / Local Fallback Mode (Defaults to Signed Out) */
          <div
            className={`p-6 rounded-2xl border transition-all space-y-4 ${
              isDark
                ? "bg-[#0D1527] border-cyan-500/30 text-slate-100 shadow-[0_0_50px_rgba(6,182,212,0.18)]"
                : "bg-white border-slate-200 text-slate-900 shadow-xl"
            }`}
          >
            {/* Prominent Google OAuth Simulation Button */}
            <button
              type="button"
              onClick={() => signInWithGoogle()}
              disabled={isAuthLoading}
              className={`w-full flex items-center justify-center gap-3 px-5 py-3.5 rounded-xl border font-bold text-sm transition-all duration-200 cursor-pointer shadow-md hover:scale-[1.01] active:scale-[0.99] ${
                isDark
                  ? "bg-slate-900 border-slate-700 text-white hover:bg-slate-800 hover:border-cyan-500/60 hover:shadow-[0_0_20px_rgba(6,182,212,0.3)]"
                  : "bg-white border-slate-300 text-slate-800 hover:bg-slate-50 hover:border-slate-400"
              }`}
            >
              {isAuthLoading ? (
                <Loader2 className="w-5 h-5 animate-spin text-cyan-400" />
              ) : (
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
              <span>Continue with Google</span>
            </button>

            {/* Divider */}
            <div className="relative flex items-center justify-center my-3">
              <div className={`w-full border-t ${isDark ? "border-slate-800" : "border-slate-200"}`} />
              <span
                className={`absolute px-3 text-[10px] font-mono uppercase tracking-wider ${
                  isDark ? "bg-[#0D1527] text-slate-500" : "bg-white text-slate-400"
                }`}
              >
                Or Test with Role Identity
              </span>
            </div>

            {/* Explicit Sandbox Role Login Buttons */}
            <div className="grid grid-cols-1 gap-2">
              <button
                type="button"
                onClick={() => switchDemoRole?.("Admin")}
                className={`flex items-center justify-between px-3.5 py-2.5 rounded-xl border text-xs font-medium transition-all cursor-pointer ${
                  isDark
                    ? "bg-slate-900/60 border-rose-500/30 text-rose-300 hover:bg-rose-500/10 hover:border-rose-500/50"
                    : "bg-rose-50 border-rose-200 text-rose-800 hover:bg-rose-100"
                }`}
              >
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                  <div className="text-left">
                    <div className="font-semibold">Sign in as Chief Architect</div>
                    <div className="text-[10px] opacity-80">Admin (Full Privilege Access)</div>
                  </div>
                </div>
                <CheckCircle2 className="w-4 h-4 opacity-70" />
              </button>

              <button
                type="button"
                onClick={() => switchDemoRole?.("SOC Analyst")}
                className={`flex items-center justify-between px-3.5 py-2.5 rounded-xl border text-xs font-medium transition-all cursor-pointer ${
                  isDark
                    ? "bg-slate-900/60 border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/10 hover:border-cyan-500/50"
                    : "bg-sky-50 border-sky-200 text-sky-800 hover:bg-sky-100"
                }`}
              >
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-cyan-400" />
                  <div className="text-left">
                    <div className="font-semibold">Sign in as Senior SOC Analyst</div>
                    <div className="text-[10px] opacity-80">SOC Analyst (Deep Forensics)</div>
                  </div>
                </div>
                <CheckCircle2 className="w-4 h-4 opacity-70" />
              </button>

              <button
                type="button"
                onClick={() => switchDemoRole?.("Customer")}
                className={`flex items-center justify-between px-3.5 py-2.5 rounded-xl border text-xs font-medium transition-all cursor-pointer ${
                  isDark
                    ? "bg-slate-900/60 border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/10 hover:border-emerald-500/50"
                    : "bg-emerald-50 border-emerald-200 text-emerald-800 hover:bg-emerald-100"
                }`}
              >
                <div className="flex items-center gap-2">
                  <UserCheck className="w-4 h-4 text-emerald-400" />
                  <div className="text-left">
                    <div className="font-semibold">Sign in as Verified Customer</div>
                    <div className="text-[10px] opacity-80">Customer (Standard Threat Scans)</div>
                  </div>
                </div>
                <CheckCircle2 className="w-4 h-4 opacity-70" />
              </button>
            </div>

            {/* Clerk Setup Info Callout */}
            <div
              className={`p-3 rounded-xl border text-[11px] font-mono leading-relaxed ${
                isDark ? "bg-slate-950/70 border-slate-800 text-slate-400" : "bg-slate-50 border-slate-200 text-slate-600"
              }`}
            >
              <div className="flex items-center gap-1.5 font-bold mb-1 text-cyan-400">
                <Sparkles className="w-3.5 h-3.5 shrink-0" />
                <span>Live Clerk Configuration:</span>
              </div>
              <span>
                Provide <code className="px-1 py-0.5 rounded bg-slate-800 text-cyan-300">VITE_CLERK_PUBLISHABLE_KEY</code> in{" "}
                <code className="px-1 py-0.5 rounded bg-slate-800 text-cyan-300">frontend/.env</code> to engage live Clerk SSO redirects.
              </span>
            </div>
          </div>
        )}
      </main>

      {/* Footer Security Badges */}
      <footer className="relative z-10 max-w-7xl w-full mx-auto flex flex-col sm:flex-row items-center justify-between gap-2 text-xs font-mono text-slate-500 border-t border-slate-800/40 pt-4">
        <div>Enterprise Zero-Trust SOC Authentication — MailSentinel AI Platform</div>
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            TLS 1.3
          </span>
          <span className="flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
            RS256 JWT
          </span>
          <span className="flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
            RBAC Enforced
          </span>
        </div>
      </footer>
    </div>
  );
};
