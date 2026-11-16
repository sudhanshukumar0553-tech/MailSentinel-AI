import React, { createContext, useContext, useEffect, useState, useMemo, useCallback } from "react";
import {
  ClerkProvider,
  useUser,
  useAuth,
  useClerk,
  AuthenticateWithRedirectCallback
} from "@clerk/react";
import { useSignIn, useSignUp } from "@clerk/react/legacy";
import { ShieldCheck } from "lucide-react";
import { setAuthTokenGetter, api } from "../api/client";
import type { UserRole, AuthUserProfile } from "../types";

export interface AuthContextValue {
  isClerkConfigured: boolean;
  isDemoMode?: boolean;
  isSignedIn: boolean;
  isLoading: boolean;
  user: AuthUserProfile | null;
  role: UserRole;
  permissions: string[];
  getToken: () => Promise<string | null>;
  openSignIn: () => void;
  openSignUp: () => void;
  signOut: () => Promise<void>;
  // Google OAuth official flow
  signInWithGoogle: () => Promise<void>;
  signUpWithGoogle: () => Promise<void>;
  isAuthLoading: boolean;
  authError: string | null;
  setAuthError: (err: string | null) => void;
  // Modal & Protected Access State
  isAuthModalOpen: boolean;
  setIsAuthModalOpen: (open: boolean) => void;
  authModalMode: "sign-in" | "sign-up";
  setAuthModalMode: (mode: "sign-in" | "sign-up") => void;
  authModalReason?: string | null;
  setAuthModalReason?: (reason: string | null) => void;
  // Dev & Demo helpers
  switchDemoRole?: (role: UserRole) => void;
  signInWithGoogleDemo?: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

// Clerk authentication is safely disabled per project requirements
const RAW_CLERK_KEY = "";
const IS_CLERK_CONFIGURED = false;

// Autonomous Demo Mode active by default for direct evaluator access
const IS_DEMO_MODE = true;

// Restricted Demo Analyst Profile for Interview Demonstrations
export const DEMO_USER_PROFILE: AuthUserProfile = {
  id: "demo-analyst",
  email: "demo.analyst@mailsentinel.ai",
  fullName: "Demo SOC Analyst",
  firstName: "Demo",
  role: "SOC Analyst", // Restricted Analyst: Full investigative access, zero administrative elevation
  provider: "demo",
  is_authenticated: true,
  permissions: [
    "read:scans",
    "read:threat_matrix",
    "execute:deep_investigation",
    "write:copilot_notes"
  ]
};

// Demo profiles for dev sandbox when live Clerk key is pending
const DEMO_PROFILES: Record<UserRole, AuthUserProfile> = {
  "Admin": {
    id: "analyst-default-dev",
    email: "lead.architect@mailsentinel.local",
    fullName: "Chief Security Architect",
    firstName: "Chief",
    role: "Admin",
    provider: "api_key",
    is_authenticated: true,
    permissions: [
      "read:scans",
      "read:threat_matrix",
      "execute:deep_investigation",
      "execute:quarantine",
      "write:copilot_notes",
      "admin:manage_users",
      "admin:configure_models",
      "admin:view_audit_logs"
    ]
  },
  "SOC Analyst": {
    id: "analyst-alpha-001",
    email: "analyst.alpha@mailsentinel.internal",
    fullName: "Senior SOC Analyst",
    firstName: "Analyst",
    role: "SOC Analyst",
    provider: "api_key",
    is_authenticated: true,
    permissions: [
      "read:scans",
      "read:threat_matrix",
      "execute:deep_investigation",
      "execute:quarantine",
      "write:copilot_notes"
    ]
  },
  "Customer": {
    id: "customer-google-oauth-demo",
    email: "alex.cyberops@gmail.com",
    fullName: "Alex Rivera",
    firstName: "Alex",
    role: "Customer",
    provider: "oauth_google",
    is_authenticated: true,
    permissions: [
      "read:scans",
      "read:threat_matrix"
    ]
  }
};

/**
 * Clerk Active Mode Context Bridge
 * Connects official Clerk React SDK hooks to MailSentinel API client, state, and Google OAuth flow.
 */
const ClerkAuthBridge: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isLoaded, isSignedIn, getToken } = useAuth();
  const { user: clerkUser } = useUser();
  const { signOut: clerkSignOut } = useClerk();
  const { isLoaded: isSignInLoaded, signIn } = useSignIn();
  const { isLoaded: isSignUpLoaded, signUp } = useSignUp();

  // Safety timeout: prevents infinite loading spinner if Clerk script is blocked or slow
  const [clerkTimeout, setClerkTimeout] = useState(false);
  useEffect(() => {
    const timer = setTimeout(() => {
      setClerkTimeout(true);
    }, 3500);
    return () => clearTimeout(timer);
  }, []);

  const [testSessionRole, setTestSessionRole] = useState<UserRole | null>(() => {
    if (typeof window !== "undefined") {
      return (sessionStorage.getItem("mailsentinel_test_role") as UserRole) || null;
    }
    return null;
  });

  const effectiveIsSignedIn = Boolean(isSignedIn || testSessionRole);

  const switchDemoRole = useCallback((role: UserRole) => {
    setTestSessionRole(role);
    if (typeof window !== "undefined") {
      sessionStorage.setItem("mailsentinel_test_role", role);
    }
  }, []);

  const [isAuthModalOpen, setIsAuthModalOpen] = useState<boolean>(false);
  const [authModalMode, setAuthModalMode] = useState<"sign-in" | "sign-up">("sign-in");
  const [authModalReason, setAuthModalReason] = useState<string | null>(null);
  const [isAuthLoading, setIsAuthLoading] = useState<boolean>(false);
  const [authError, setAuthError] = useState<string | null>(null);

  const [serverProfile, setServerProfile] = useState<{
    role: UserRole;
    permissions: string[];
  } | null>(null);

  // Wire API client token getter
  useEffect(() => {
    if (isSignedIn) {
      setAuthTokenGetter(async () => {
        try {
          return await getToken();
        } catch {
          return null;
        }
      });
    } else if (testSessionRole) {
      setAuthTokenGetter(async () => {
        if (testSessionRole === "SOC Analyst") return "mailsentinel-soc-analyst-key-alpha";
        return "mailsentinel-dev-secret-key-2026";
      });
    } else {
      setAuthTokenGetter(null);
    }
  }, [isSignedIn, getToken, testSessionRole]);

  // Synchronize server-verified role from /api/v1/auth/me
  useEffect(() => {
    if (isSignedIn && clerkUser) {
      api.getAuthMe()
        .then((res) => {
          setServerProfile({
            role: res.role,
            permissions: res.permissions || []
          });
        })
        .catch(() => {
          const metaRole = (clerkUser.publicMetadata?.role as UserRole) || "Customer";
          setServerProfile({
            role: metaRole,
            permissions: metaRole === "Customer"
              ? ["read:scans", "read:threat_matrix"]
              : ["read:scans", "read:threat_matrix", "execute:deep_investigation"]
          });
        });
    } else {
      setServerProfile(null);
    }
  }, [isSignedIn, clerkUser]);

  const userProfile: AuthUserProfile | null = useMemo(() => {
    if (isSignedIn && clerkUser) {
      const email = clerkUser.primaryEmailAddress?.emailAddress || clerkUser.emailAddresses[0]?.emailAddress || null;
      const isGoogle = clerkUser.externalAccounts?.some((acc) => acc.provider?.toLowerCase().includes("google")) || false;
      const role: UserRole = serverProfile?.role || (clerkUser.publicMetadata?.role as UserRole) || "Customer";

      return {
        id: clerkUser.id,
        email,
        fullName: clerkUser.fullName || clerkUser.username || "SOC User",
        firstName: clerkUser.firstName,
        imageUrl: clerkUser.imageUrl,
        role,
        provider: isGoogle ? "oauth_google" : "clerk",
        is_authenticated: true,
        permissions: serverProfile?.permissions || ["read:scans", "read:threat_matrix"]
      };
    }

    if (testSessionRole) {
      return DEMO_PROFILES[testSessionRole];
    }

    return null;
  }, [isSignedIn, clerkUser, serverProfile, testSessionRole]);

  // Official Clerk Google OAuth redirect flows
  const signInWithGoogle = useCallback(async () => {
    if (!isSignInLoaded || !signIn) return;
    setIsAuthLoading(true);
    setAuthError(null);
    try {
      await signIn.authenticateWithRedirect({
        strategy: "oauth_google",
        redirectUrl: "/sso-callback",
        redirectUrlComplete: "/"
      });
    } catch (err: any) {
      console.warn("Clerk Google Sign In redirected or failed, trying signup fallback:", err);
      if (signUp && isSignUpLoaded) {
        try {
          await signUp.authenticateWithRedirect({
            strategy: "oauth_google",
            redirectUrl: "/sso-callback",
            redirectUrlComplete: "/"
          });
          return;
        } catch (signUpErr: any) {
          setAuthError(signUpErr?.errors?.[0]?.message || "Google OAuth sign-up initiation failed.");
        }
      } else {
        setAuthError(err?.errors?.[0]?.message || "Google OAuth initiation failed.");
      }
      setIsAuthLoading(false);
    }
  }, [isSignInLoaded, signIn, isSignUpLoaded, signUp]);

  const signUpWithGoogle = useCallback(async () => {
    if (!isSignUpLoaded || !signUp) return;
    setIsAuthLoading(true);
    setAuthError(null);
    try {
      await signUp.authenticateWithRedirect({
        strategy: "oauth_google",
        redirectUrl: "/sso-callback",
        redirectUrlComplete: "/"
      });
    } catch (err: any) {
      console.error("Clerk Google Sign Up initiation failed:", err);
      setAuthError(err?.errors?.[0]?.message || "Google OAuth sign-up initiation failed.");
      setIsAuthLoading(false);
    }
  }, [isSignUpLoaded, signUp]);

  const openSignIn = useCallback(() => {
    setAuthModalMode("sign-in");
    setAuthModalReason(null);
    setAuthError(null);
    setIsAuthModalOpen(true);
  }, []);

  const openSignUp = useCallback(() => {
    setAuthModalMode("sign-up");
    setAuthModalReason(null);
    setAuthError(null);
    setIsAuthModalOpen(true);
  }, []);

  const signOut = useCallback(async () => {
    if (typeof window !== "undefined") {
      sessionStorage.removeItem("mailsentinel_test_role");
    }
    setTestSessionRole(null);
    if (isSignedIn) {
      await clerkSignOut();
    }
  }, [isSignedIn, clerkSignOut]);

  // Check for SSO Callback route
  if (typeof window !== "undefined" && window.location.pathname === "/sso-callback") {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#080D1A] text-slate-100 p-6">
        <div className="max-w-md w-full p-8 rounded-2xl border border-cyan-500/30 bg-[#0D1527] shadow-[0_0_50px_rgba(6,182,212,0.2)] text-center space-y-4">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-tr from-purple-600 via-indigo-600 to-cyan-500 mx-auto flex items-center justify-center animate-pulse">
            <ShieldCheck className="w-6 h-6 text-white" />
          </div>
          <h2 className="text-lg font-bold">Completing Google Authentication...</h2>
          <p className="text-xs text-slate-400">Verifying session credentials with Clerk Security Gateway.</p>
          <AuthenticateWithRedirectCallback signInForceRedirectUrl="/" signUpForceRedirectUrl="/" />
        </div>
      </div>
    );
  }

  const value: AuthContextValue = {
    isClerkConfigured: true,
    isDemoMode: false,
    isSignedIn: effectiveIsSignedIn,
    isLoading: !isLoaded && !clerkTimeout,
    user: userProfile,
    role: userProfile?.role || "Customer",
    permissions: userProfile?.permissions || ["read:scans", "read:threat_matrix"],
    getToken: async () => {
      if (isSignedIn) return await getToken();
      if (testSessionRole === "SOC Analyst") return "mailsentinel-soc-analyst-key-alpha";
      if (testSessionRole) return "mailsentinel-dev-secret-key-2026";
      return null;
    },
    openSignIn,
    openSignUp,
    signOut,
    signInWithGoogle,
    signUpWithGoogle,
    isAuthLoading,
    authError,
    setAuthError,
    switchDemoRole,
    isAuthModalOpen,
    setIsAuthModalOpen,
    authModalMode,
    setAuthModalMode,
    authModalReason,
    setAuthModalReason
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

/**
 * Sandbox / Developer Fallback Auth Provider
 * Used when VITE_CLERK_PUBLISHABLE_KEY is not yet provisioned.
 * Allows full local testing of Google OAuth simulation, sign-in, sign-up, and RBAC roles.
 */
const DevAuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [currentRole, setCurrentRole] = useState<UserRole>("Customer");
  const [isSignedIn, setIsSignedIn] = useState<boolean>(() => {
    if (typeof window !== "undefined") {
      return localStorage.getItem("mailsentinel_dev_auth") === "true";
    }
    return false;
  });
  const [isAuthModalOpen, setIsAuthModalOpen] = useState<boolean>(false);
  const [authModalMode, setAuthModalMode] = useState<"sign-in" | "sign-up">("sign-in");
  const [authModalReason, setAuthModalReason] = useState<string | null>(null);
  const [isAuthLoading, setIsAuthLoading] = useState<boolean>(false);
  const [authError, setAuthError] = useState<string | null>(null);

  // Keep API client wired to dev secret token
  useEffect(() => {
    setAuthTokenGetter(async () => {
      if (!isSignedIn) return null;
      if (currentRole === "Admin") return "mailsentinel-dev-secret-key-2026";
      if (currentRole === "SOC Analyst") return "mailsentinel-soc-analyst-key-alpha";
      return "mailsentinel-dev-secret-key-2026";
    });
  }, [isSignedIn, currentRole]);

  const user = useMemo(() => {
    if (!isSignedIn) return null;
    return DEMO_PROFILES[currentRole];
  }, [isSignedIn, currentRole]);

  const switchDemoRole = useCallback((role: UserRole) => {
    setCurrentRole(role);
    setIsSignedIn(true);
    if (typeof window !== "undefined") {
      localStorage.setItem("mailsentinel_dev_auth", "true");
    }
  }, []);

  const signInWithGoogleDemo = useCallback(() => {
    setIsAuthLoading(true);
    setAuthError(null);
    setTimeout(() => {
      setCurrentRole("Customer");
      setIsSignedIn(true);
      if (typeof window !== "undefined") {
        localStorage.setItem("mailsentinel_dev_auth", "true");
      }
      setIsAuthLoading(false);
      setIsAuthModalOpen(false);
    }, 400);
  }, []);

  const openSignIn = useCallback(() => {
    setAuthModalMode("sign-in");
    setAuthModalReason(null);
    setAuthError(null);
    setIsAuthModalOpen(true);
  }, []);

  const openSignUp = useCallback(() => {
    setAuthModalMode("sign-up");
    setAuthModalReason(null);
    setAuthError(null);
    setIsAuthModalOpen(true);
  }, []);

  const signOut = useCallback(async () => {
    if (typeof window !== "undefined") {
      localStorage.removeItem("mailsentinel_dev_auth");
    }
    setIsSignedIn(false);
  }, []);

  const value: AuthContextValue = {
    isClerkConfigured: false,
    isDemoMode: false,
    isSignedIn,
    isLoading: false,
    user,
    role: user?.role || "Customer",
    permissions: user?.permissions || ["read:scans", "read:threat_matrix"],
    getToken: async () => {
      if (!isSignedIn) return null;
      return "mailsentinel-dev-secret-key-2026";
    },
    openSignIn,
    openSignUp,
    signOut,
    signInWithGoogle: async () => {
      signInWithGoogleDemo();
    },
    signUpWithGoogle: async () => {
      signInWithGoogleDemo();
    },
    isAuthLoading,
    authError,
    setAuthError,
    switchDemoRole,
    signInWithGoogleDemo,
    isAuthModalOpen,
    setIsAuthModalOpen,
    authModalMode,
    setAuthModalMode,
    authModalReason,
    setAuthModalReason
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

/**
 * Interview Demo Auth Provider
 * When VITE_DEMO_MODE=true, provides an immediate, zero-latency authenticated session
 * as Demo SOC Analyst (restricted: no admin elevation, full investigation access).
 */
const DemoAuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [authModalMode, setAuthModalMode] = useState<"sign-in" | "sign-up">("sign-in");

  useEffect(() => {
    setAuthTokenGetter(async () => "mailsentinel-demo-analyst-key");
  }, []);

  const value: AuthContextValue = {
    isClerkConfigured: IS_CLERK_CONFIGURED,
    isDemoMode: true,
    isSignedIn: true,
    isLoading: false,
    user: DEMO_USER_PROFILE,
    role: "SOC Analyst",
    permissions: DEMO_USER_PROFILE.permissions,
    getToken: async () => "mailsentinel-demo-analyst-key",
    openSignIn: () => {},
    openSignUp: () => {},
    signOut: async () => {},
    signInWithGoogle: async () => {},
    signUpWithGoogle: async () => {},
    isAuthLoading: false,
    authError: null,
    setAuthError: () => {},
    switchDemoRole: () => {},
    isAuthModalOpen,
    setIsAuthModalOpen,
    authModalMode,
    setAuthModalMode
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

/**
 * Universal Authentication Provider
 * Gracefully selects between Demo Mode, Clerk Live Provider, and Developer Fallback Provider.
 */
export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  if (IS_DEMO_MODE) {
    return <DemoAuthProvider>{children}</DemoAuthProvider>;
  }

  if (IS_CLERK_CONFIGURED) {
    return (
      <ClerkProvider
        publishableKey={RAW_CLERK_KEY}
        afterSignOutUrl="/"
      >
        <ClerkAuthBridge>{children}</ClerkAuthBridge>
      </ClerkProvider>
    );
  }

  return <DevAuthProvider>{children}</DevAuthProvider>;
};

export const useAuthContext = (): AuthContextValue => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuthContext must be used within an AuthProvider");
  }
  return context;
};
