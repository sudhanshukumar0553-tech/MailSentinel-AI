import { useState } from "react";
import { Navbar } from "./components/Navbar";
import { ScannerPage } from "./components/ScannerPage";
import { DashboardPage } from "./components/DashboardPage";
import { AgentPage } from "./components/AgentPage";
import { ModelHubPage } from "./components/ModelHubPage";
import { HistoryPage } from "./components/HistoryPage";
import { ChatAssistantPage } from "./components/ChatAssistantPage";
import { ThemeProvider, useTheme } from "./context/ThemeContext";
import { AuthProvider, useAuthContext } from "./context/AuthContext";
import { AuthModal } from "./components/AuthModal";
import { LoginScreen } from "./components/LoginScreen";
import { LoadingScreen } from "./components/LoadingScreen";

function AppContent() {
  const { isDark } = useTheme();
  const { role, isSignedIn, isLoading, isDemoMode } = useAuthContext();
  const [activeTab, setActiveTab] = useState<string>("scanner");
  const [historyRefreshTrigger, setHistoryRefreshTrigger] = useState<number>(0);
  const [agentPayload, setAgentPayload] = useState<{
    content: string;
    headers?: string;
    scanId?: string;
  }>({ content: "", headers: "none" });
  const [copilotPayload, setCopilotPayload] = useState<{
    content: string;
    headers?: string;
    scanId?: string;
  }>({ content: "", headers: "none" });

  const handleTabChange = (tab: string) => {
    setActiveTab(tab);
    if (tab === "history") {
      setHistoryRefreshTrigger((prev) => prev + 1);
    }
  };

  const handleLaunchAgentFromScanner = (content: string, headers?: string, scanId?: string) => {
    setAgentPayload({ content, headers: headers || "none", scanId });
    setActiveTab("agent");
  };

  const handleLaunchCopilotFromScanner = (content: string, headers?: string, scanId?: string) => {
    setCopilotPayload({ content, headers: headers || "none", scanId });
    setActiveTab("copilot");
  };

  const handleScanCompleted = () => {
    setHistoryRefreshTrigger((prev) => prev + 1);
  };

  const handleNavigateToHistory = () => {
    setActiveTab("history");
    setHistoryRefreshTrigger((prev) => prev + 1);
  };

  // When DEMO_MODE is active, directly mount the SOC platform interface
  if (!isDemoMode) {
    // 1. While Clerk is loading, display the professional MailSentinel loading screen
    if (isLoading) {
      return <LoadingScreen />;
    }

    // 2. If the user is NOT authenticated, display the Global Authentication Gate
    if (!isSignedIn) {
      return <LoginScreen />;
    }
  }

  return (
    <div
      className={`min-h-screen flex flex-col font-sans transition-colors duration-200 ${
        isDark
          ? "bg-[#080D1A] text-slate-100 selection:bg-cyan-500/30 selection:text-cyan-200"
          : "bg-slate-50 text-slate-900 selection:bg-sky-500/30 selection:text-sky-900"
      }`}
    >
      {/* Navigation Header */}
      <Navbar activeTab={activeTab} setActiveTab={handleTabChange} />

      {/* Main Content Viewport - Optimized with smooth tab transitions and state preservation */}
      <main className={`flex-1 max-w-7xl w-full mx-auto px-3 sm:px-6 lg:px-8 ${activeTab === "copilot" ? "py-4 flex flex-col" : "py-8"}`}>
        <div className={`w-full ${activeTab === "scanner" ? "block animate-page-enter" : "hidden"}`}>
          <ScannerPage
            onLaunchAgent={handleLaunchAgentFromScanner}
            onLaunchCopilot={handleLaunchCopilotFromScanner}
            onScanCompleted={handleScanCompleted}
            onNavigateToHistory={handleNavigateToHistory}
          />
        </div>

        <div className={`w-full h-full flex-1 flex flex-col ${activeTab === "copilot" ? "flex animate-page-enter" : "hidden"}`}>
          <ChatAssistantPage
            initialEmailContent={copilotPayload.content}
            initialHeaders={copilotPayload.headers}
            initialScanId={copilotPayload.scanId}
          />
        </div>

        <div className={`w-full ${activeTab === "dashboard" ? "block animate-page-enter" : "hidden"}`}>
          <DashboardPage />
        </div>

        <div className={`w-full ${activeTab === "agent" ? "block animate-page-enter" : "hidden"}`}>
          {role === "Customer" && (
            <div className="mb-4 p-3 rounded-xl border border-amber-500/30 bg-amber-500/10 text-amber-300 text-xs flex items-center justify-between shadow-xs">
              <span className="font-mono">
                Customer Notice: Autonomous deep investigation operates in safe sandbox mode. Switch to SOC Analyst or Admin in Navbar for live forensic telemetry.
              </span>
            </div>
          )}
          <AgentPage
            initialContent={agentPayload.content}
            initialHeaders={agentPayload.headers}
            initialScanId={agentPayload.scanId}
          />
        </div>

        <div className={`w-full ${activeTab === "models" ? "block animate-page-enter" : "hidden"}`}>
          <ModelHubPage />
        </div>

        <div className={`w-full ${activeTab === "history" ? "block animate-page-enter" : "hidden"}`}>
          <HistoryPage
            isActive={activeTab === "history"}
            refreshTrigger={historyRefreshTrigger}
            onNavigateToScanner={() => setActiveTab("scanner")}
          />
        </div>
      </main>

      {/* Enterprise Authentication Modal */}
      <AuthModal />
    </div>
  );
}

export function App() {
  return (
    <AuthProvider>
      <ThemeProvider>
        <AppContent />
      </ThemeProvider>
    </AuthProvider>
  );
}

export default App;
