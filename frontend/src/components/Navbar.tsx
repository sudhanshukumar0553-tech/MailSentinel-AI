import React, { useEffect, useState, useRef } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  LayoutDashboard,
  BrainCircuit,
  Binary,
  History,
  MessageSquareCode,
  Sun,
  Moon,
  Menu,
  X,
  UserCheck,
  LogOut,
  ChevronDown,
  Sparkles
} from "lucide-react";
import { Show, UserButton } from "@clerk/react";
import { api } from "../api/client";
import { useTheme } from "../context/ThemeContext";
import { useAuthContext } from "../context/AuthContext";
import type { UserRole } from "../types";

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
}

const GoogleIcon: React.FC<{ className?: string }> = ({ className = "w-3.5 h-3.5" }) => (
  <svg className={className} viewBox="0 0 24 24" aria-hidden="true">
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
);

export const Navbar: React.FC<NavbarProps> = ({ activeTab, setActiveTab }) => {
  const { toggleTheme, isDark } = useTheme();
  const {
    isClerkConfigured,
    isDemoMode,
    isSignedIn,
    user,
    role,
    openSignIn,
    openSignUp,
    signOut,
    switchDemoRole
  } = useAuthContext();

  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [profileDropdownOpen, setProfileDropdownOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const [health, setHealth] = useState<{
    database: string;
    database_engine?: string;
    database_latency_ms?: number;
    hf_configured: boolean;
    status: string;
  } | null>(null);

  useEffect(() => {
    api.getHealth()
      .then(setHealth)
      .catch(() => setHealth({ status: "offline", database: "disconnected", hf_configured: false }));
  }, []);

  // Dismiss dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setProfileDropdownOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const navItems = [
    { id: "scanner", label: "Live Scanner", icon: ShieldCheck },
    { id: "copilot", label: "Sentinel Copilot", icon: MessageSquareCode },
    { id: "dashboard", label: "Security Dashboard", icon: LayoutDashboard },
    { id: "agent", label: "AI Investigation Agent", icon: BrainCircuit },
    { id: "models", label: "ML Model Hub", icon: Binary },
    { id: "history", label: "Detection History", icon: History }
  ];

  const handleSelectTab = (tabId: string) => {
    setActiveTab(tabId);
    setMobileMenuOpen(false);
  };

  const renderRoleBadge = (badgeRole: UserRole) => {
    let colorClasses = "";
    let Icon = ShieldCheck;
    if (badgeRole === "Admin") {
      colorClasses = isDark
        ? "bg-rose-500/15 text-rose-300 border-rose-500/40 shadow-[0_0_8px_rgba(244,63,94,0.15)]"
        : "bg-rose-50 text-rose-800 border-rose-300 font-semibold";
      Icon = ShieldAlert;
    } else if (badgeRole === "SOC Analyst") {
      colorClasses = isDark
        ? "bg-cyan-500/15 text-cyan-300 border-cyan-500/40 shadow-[0_0_8px_rgba(6,182,212,0.15)]"
        : "bg-sky-50 text-sky-800 border-sky-300 font-semibold";
      Icon = ShieldCheck;
    } else {
      colorClasses = isDark
        ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/40 shadow-[0_0_8px_rgba(16,185,129,0.15)]"
        : "bg-emerald-50 text-emerald-800 border-emerald-300 font-semibold";
      Icon = UserCheck;
    }

    return (
      <div
        className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-[11px] font-mono tracking-wide select-none ${colorClasses}`}
        title={`Authenticated Role: ${badgeRole}`}
      >
        <Icon className="w-3.5 h-3.5 shrink-0" />
        <span>{badgeRole}</span>
      </div>
    );
  };

  return (
    <header
      className={`border-b sticky top-0 z-50 transition-colors backdrop-blur-md ${
        isDark
          ? "border-cyan-500/20 bg-[#080D1A]/95 text-slate-100"
          : "border-slate-200 bg-white/95 text-slate-800 shadow-xs"
      }`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 gap-3">
          {/* Logo & Brand */}
          <div
            className="flex items-center gap-3 cursor-pointer group shrink-0"
            onClick={() => handleSelectTab("scanner")}
            role="button"
            tabIndex={0}
            aria-label="Go to Live Scanner"
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") handleSelectTab("scanner");
            }}
          >
            <div className="w-10 h-10 rounded-lg bg-gradient-to-tr from-purple-600 via-indigo-600 to-cyan-500 flex items-center justify-center shadow-[0_0_15px_rgba(6,182,212,0.4)] group-hover:scale-105 transition-transform">
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
                className={`text-[9px] sm:text-[10px] font-mono tracking-wider uppercase hidden sm:block ${
                  isDark ? "text-slate-400" : "text-slate-500 font-medium"
                }`}
              >
                SOC Defense Platform
              </p>
            </div>
          </div>

          {/* Desktop Navigation Links */}
          <nav
            className="hidden lg:flex items-center gap-1.5 xl:gap-2.5 overflow-x-auto no-scrollbar py-1"
            aria-label="Main Navigation"
          >
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => handleSelectTab(item.id)}
                  aria-current={isActive ? "page" : undefined}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs xl:text-sm font-medium transition-all duration-200 select-none cursor-pointer active:scale-95 shrink-0 ${
                    isActive
                      ? isDark
                        ? "bg-blue-600/15 text-cyan-300 border border-cyan-500/50 nav-active-glow-dark font-semibold"
                        : "bg-sky-50 text-sky-800 border border-sky-300 nav-active-glow-light font-bold"
                      : isDark
                      ? "text-slate-300 hover:text-white hover:bg-slate-800/60 border border-transparent"
                      : "text-slate-600 hover:text-slate-950 hover:bg-slate-100 border border-transparent"
                  }`}
                >
                  <Icon
                    className={`w-4 h-4 transition-colors shrink-0 ${
                      isActive
                        ? isDark
                          ? "text-cyan-400"
                          : "text-sky-600"
                        : isDark
                        ? "text-slate-400"
                        : "text-slate-500"
                    }`}
                  />
                  <span>{item.label}</span>
                  {isActive && (
                    <span
                      className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                        isDark ? "bg-emerald-400 shadow-[0_0_6px_#34d399]" : "bg-emerald-600"
                      }`}
                    />
                  )}
                </button>
              );
            })}
          </nav>

          {/* Right Controls: Auth, Status & Theme */}
          <div className="flex items-center gap-2 sm:gap-2.5 text-xs font-mono shrink-0">
            {/* Interview Demo Mode Badge (Local Development Only) */}
            {isDemoMode && import.meta.env.DEV && (
              <div
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-amber-500/40 bg-amber-500/10 text-amber-300 text-[11px] font-mono tracking-wide shadow-[0_0_12px_rgba(245,158,11,0.2)] select-none shrink-0"
                title="Interview Demonstration Mode: Direct SOC Analyst Access"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse"></span>
                <span className="font-bold">DEMO MODE</span>
              </div>
            )}

            {/* Enterprise Authentication Section */}
            <div className="flex items-center gap-2">
              {!isDemoMode && isClerkConfigured && user?.provider !== "api_key" && user?.provider !== "demo" ? (
                <>
                  <Show when="signed-in">
                    <div className="flex items-center gap-2">
                      <div className="hidden sm:block">{renderRoleBadge(role)}</div>
                      <UserButton
                        appearance={{
                          elements: {
                            avatarBox: "w-8 h-8 rounded-lg ring-1 ring-cyan-500/40 hover:scale-105 transition-transform"
                          }
                        }}
                      />
                    </div>
                  </Show>
                  <Show when="signed-out">
                    <div className="flex items-center gap-1.5 sm:gap-2">
                      <button
                        onClick={() => openSignIn()}
                        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold cursor-pointer transition-all ${
                          isDark
                            ? "bg-slate-900 border-slate-700 text-slate-200 hover:text-white hover:bg-slate-800"
                            : "bg-white border-slate-300 text-slate-700 hover:bg-slate-50"
                        }`}
                      >
                        <GoogleIcon className="w-3.5 h-3.5" />
                        <span className="hidden sm:inline">Sign In</span>
                      </button>
                      <button
                        onClick={() => openSignUp()}
                        className="px-3 py-1.5 rounded-lg border border-cyan-500/40 bg-gradient-to-r from-blue-600 via-indigo-600 to-cyan-500 text-white text-xs font-bold shadow-[0_0_12px_rgba(6,182,212,0.3)] hover:brightness-110 cursor-pointer transition-all"
                      >
                        Sign Up
                      </button>
                    </div>
                  </Show>
                </>
              ) : (
                /* Sandbox / Fallback Auth Controls */
                <div className="relative" ref={dropdownRef}>
                  {isSignedIn && user ? (
                    <div className="flex items-center gap-2">
                      <div className="hidden sm:block">{renderRoleBadge(role)}</div>
                      <button
                        onClick={() => setProfileDropdownOpen((prev) => !prev)}
                        className={`flex items-center gap-1.5 px-2 py-1.5 rounded-lg border transition-all cursor-pointer ${
                          isDark
                            ? "bg-slate-900 border-slate-700 text-slate-200 hover:border-cyan-500/50 hover:bg-slate-800"
                            : "bg-slate-50 border-slate-300 text-slate-800 hover:bg-slate-100"
                        }`}
                        title="User Account & Role Controls"
                      >
                        <div className="w-6 h-6 rounded-md bg-gradient-to-tr from-cyan-600 to-indigo-600 flex items-center justify-center text-white font-bold text-[11px] shadow-xs">
                          {user.firstName ? user.firstName[0].toUpperCase() : "A"}
                        </div>
                        {user.provider === "oauth_google" && <GoogleIcon className="w-3.5 h-3.5" />}
                        <span className="text-xs font-medium hidden md:inline max-w-[100px] truncate">
                          {user.firstName || user.fullName}
                        </span>
                        <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
                      </button>
                    </div>
                  ) : (
                    <div className="flex items-center gap-1.5 sm:gap-2">
                      <button
                        onClick={() => openSignIn()}
                        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold cursor-pointer transition-all ${
                          isDark
                            ? "bg-slate-900 border-slate-700 text-slate-200 hover:text-white hover:bg-slate-800"
                            : "bg-white border-slate-300 text-slate-700 hover:bg-slate-50"
                        }`}
                      >
                        <GoogleIcon className="w-3.5 h-3.5" />
                        <span>Sign In</span>
                      </button>
                      <button
                        onClick={() => openSignUp()}
                        className="px-3 py-1.5 rounded-lg border border-cyan-500/40 bg-gradient-to-r from-blue-600 via-indigo-600 to-cyan-500 text-white text-xs font-bold shadow-[0_0_12px_rgba(6,182,212,0.3)] hover:brightness-110 cursor-pointer transition-all"
                      >
                        Sign Up
                      </button>
                    </div>
                  )}

                  {/* Sandbox Profile Popover Dropdown */}
                  {profileDropdownOpen && user && (
                    <div
                      className={`absolute right-0 mt-2 w-72 rounded-2xl border p-4 shadow-2xl z-50 animate-fade-in ${
                        isDark
                          ? "bg-[#0D1527] border-cyan-500/30 text-slate-100 shadow-[0_0_30px_rgba(6,182,212,0.15)]"
                          : "bg-white border-slate-200 text-slate-900 shadow-xl"
                      }`}
                    >
                      <div className="flex items-center gap-3 pb-3 border-b border-slate-800">
                        <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-purple-600 via-indigo-600 to-cyan-500 flex items-center justify-center text-white font-bold text-sm shadow-[0_0_10px_rgba(6,182,212,0.4)]">
                          {user.firstName ? user.firstName[0].toUpperCase() : "A"}
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className="text-sm font-bold truncate flex items-center gap-1.5">
                            <span>{user.fullName}</span>
                            {user.provider === "oauth_google" && <GoogleIcon className="w-3.5 h-3.5 shrink-0" />}
                          </div>
                          <div className={`text-xs truncate ${isDark ? "text-slate-400" : "text-slate-500"}`}>
                            {user.email}
                          </div>
                        </div>
                      </div>

                      {/* Current Role Indicator */}
                      <div className="py-2.5 border-b border-slate-800 flex items-center justify-between">
                        <span className="text-[11px] text-slate-400">Current Role:</span>
                        {renderRoleBadge(role)}
                      </div>

                      {/* Quick Switch Role (Development Sandbox Feature Only) */}
                      {import.meta.env.DEV && (
                        isDemoMode ? (
                          <div className="py-2.5 border-b border-slate-800 space-y-1.5">
                            <div className="text-[10px] font-mono uppercase tracking-wider text-amber-400/90 flex items-center gap-1">
                              <Sparkles className="w-3 h-3 text-amber-400" />
                              <span>Interview Demo Restrictions</span>
                            </div>
                            <p className="text-[11px] text-slate-400 leading-relaxed">
                              Operating as <span className="text-cyan-300 font-semibold">SOC Analyst</span> with full investigative access. Administrative actions are locked for safety.
                            </p>
                          </div>
                        ) : (
                          <div className="py-2.5 border-b border-slate-800 space-y-1.5">
                            <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1">
                              <Sparkles className="w-3 h-3 text-cyan-400" />
                              <span>Simulate Enterprise Role (Dev Only)</span>
                            </div>
                            <div className="grid grid-cols-3 gap-1">
                              {(["Admin", "SOC Analyst", "Customer"] as UserRole[]).map((r) => (
                                <button
                                  key={r}
                                  onClick={() => {
                                    switchDemoRole?.(r);
                                    setProfileDropdownOpen(false);
                                  }}
                                  className={`px-1.5 py-1 rounded text-[10px] font-medium border text-center transition-all cursor-pointer ${
                                    role === r
                                      ? isDark
                                        ? "bg-cyan-500/20 border-cyan-500 text-cyan-300 font-bold"
                                        : "bg-sky-100 border-sky-400 text-sky-800 font-bold"
                                      : isDark
                                      ? "bg-slate-900 border-slate-800 text-slate-400 hover:text-white"
                                      : "bg-slate-50 border-slate-200 text-slate-600 hover:text-slate-900"
                                  }`}
                                >
                                  {r === "SOC Analyst" ? "Analyst" : r}
                                </button>
                              ))}
                            </div>
                          </div>
                        )
                      )}

                      {/* Sign Out Action */}
                      <div className="pt-2">
                        <button
                          onClick={() => {
                            if (isDemoMode) {
                              setProfileDropdownOpen(false);
                            } else {
                              signOut();
                              setProfileDropdownOpen(false);
                            }
                          }}
                          className={`w-full flex items-center justify-center gap-2 px-3 py-2 rounded-xl text-xs font-semibold border transition-all cursor-pointer ${
                            isDark
                              ? "bg-rose-500/10 border-rose-500/30 text-rose-300 hover:bg-rose-500/20"
                              : "bg-rose-50 border-rose-200 text-rose-800 hover:bg-rose-100"
                          }`}
                        >
                          <LogOut className="w-3.5 h-3.5" />
                          <span>{isDemoMode ? "Active Demo Session" : "Sign Out"}</span>
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Dedicated Divider */}
            <div className={`hidden sm:block h-6 w-px ${isDark ? "bg-slate-800" : "bg-slate-200"}`} />

            {/* Theme Toggle Button */}
            <div className="flex items-center">
              <button
                onClick={toggleTheme}
                aria-label={`Switch to ${isDark ? "light" : "dark"} mode`}
                title={`Switch to ${isDark ? "light" : "dark"} mode`}
                className={`p-2 rounded-lg border transition-all duration-200 flex items-center justify-center cursor-pointer active:scale-95 ${
                  isDark
                    ? "bg-slate-900 border-slate-700 text-amber-300 hover:bg-slate-800 hover:border-amber-400/50 hover:shadow-[0_0_10px_rgba(252,211,77,0.2)]"
                    : "bg-slate-100 border-slate-300 text-indigo-600 hover:bg-slate-200 hover:border-indigo-400/50 hover:shadow-xs"
                }`}
              >
                {isDark ? (
                  <Sun className="w-4 h-4 transition-transform hover:rotate-45" />
                ) : (
                  <Moon className="w-4 h-4 transition-transform hover:-rotate-12" />
                )}
              </button>
            </div>

            {/* Dedicated Divider */}
            <div className={`hidden sm:block h-6 w-px ${isDark ? "bg-slate-800" : "bg-slate-200"}`} />

            {/* Read-Only Database Status Badge */}
            <div
              className={`hidden sm:flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border cursor-default select-none ${
                isDark
                  ? "bg-slate-900/90 border-slate-800 text-slate-300"
                  : "bg-slate-50 border-slate-200 text-slate-700 shadow-xs"
              }`}
              title={`${health?.database_engine === "postgresql" ? "Neon PostgreSQL" : "SQLite"} Database Health Status`}
            >
              <span
                className={`w-2 h-2 rounded-full shrink-0 ${
                  health?.database === "connected"
                    ? "bg-emerald-400 animate-pulse shadow-[0_0_6px_#34d399]"
                    : "bg-rose-400"
                }`}
              />
              <span className="font-semibold">
                DB: {health?.database === "connected"
                  ? (health?.database_engine === "postgresql" ? "PostgreSQL OK" : "SQLite OK")
                  : "Offline"}
              </span>
            </div>

            {/* Dedicated Divider between Badges */}
            <div className={`hidden xl:block h-6 w-px ${isDark ? "bg-slate-800" : "bg-slate-200"}`} />

            {/* Read-Only AI Status Badge */}
            <div
              className={`hidden xl:flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border cursor-default select-none ${
                isDark
                  ? "bg-slate-900/90 border-slate-800 text-slate-300"
                  : "bg-slate-50 border-slate-200 text-slate-700 shadow-xs"
              }`}
              title="Copilot Intelligence Engine"
            >
              <span className="w-2 h-2 rounded-full bg-cyan-400 shadow-[0_0_6px_#22d3ee] shrink-0" />
              <span className="font-semibold">Copilot: Gemini 3.1</span>
            </div>

            {/* Mobile Navigation Menu Toggle Button */}
            <button
              onClick={() => setMobileMenuOpen((prev) => !prev)}
              aria-label="Toggle mobile navigation"
              className={`lg:hidden p-2 rounded-lg border transition-colors cursor-pointer ${
                isDark
                  ? "bg-slate-900 border-slate-700 text-slate-300 hover:text-white"
                  : "bg-slate-100 border-slate-300 text-slate-700 hover:text-slate-950"
              }`}
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Navigation Drawer / Dropdown */}
      {mobileMenuOpen && (
        <div
          className={`lg:hidden border-t px-4 pt-3 pb-5 space-y-2 animate-page-enter ${
            isDark ? "border-slate-800 bg-[#080D1A]/98" : "border-slate-200 bg-white/98 shadow-md"
          }`}
        >
          {/* Mobile Auth Status */}
          <div className="pb-2 border-b border-slate-800 flex items-center justify-between">
            <span className="text-xs text-slate-400">Security Identity:</span>
            {renderRoleBadge(role)}
          </div>

          <div className="grid grid-cols-1 gap-1.5">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => handleSelectTab(item.id)}
                  className={`flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all ${
                    isActive
                      ? isDark
                        ? "bg-blue-600/20 text-cyan-300 border border-cyan-500/40 font-bold"
                        : "bg-sky-50 text-sky-800 border border-sky-300 font-bold"
                      : isDark
                      ? "text-slate-300 hover:bg-slate-800/60"
                      : "text-slate-700 hover:bg-slate-100"
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <Icon className={`w-4 h-4 ${isActive ? "text-cyan-400" : "text-slate-400"}`} />
                    <span>{item.label}</span>
                  </div>
                  {isActive && (
                    <span
                      className={`w-2 h-2 rounded-full ${
                        isDark ? "bg-emerald-400 shadow-[0_0_6px_#34d399]" : "bg-emerald-600"
                      }`}
                    />
                  )}
                </button>
              );
            })}
          </div>

          {/* Mobile System Status Indicators */}
          <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-xs font-mono text-slate-400">
            <span className="flex items-center gap-1.5">
              <span
                className={`w-2 h-2 rounded-full ${
                  health?.database === "connected" ? "bg-emerald-400" : "bg-rose-400"
                }`}
              />
              DB: {health?.database === "connected"
                ? (health?.database_engine === "postgresql" ? "PostgreSQL OK" : "SQLite OK")
                : "Offline"}
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-cyan-400" />
              Copilot: Gemini 3.1
            </span>
          </div>
        </div>
      )}
    </header>
  );
};
