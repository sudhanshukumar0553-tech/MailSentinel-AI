/**
 * MailSentinel AI - API Client
 * Type-safe interface to the FastAPI backend.
 */

import type {
  ScanResult,
  AgentInvestigation,
  AnalyticsOverview,
  ModelBenchmarksResponse,
  ChatMessageResponse,
  ChatSessionSummary,
  ChatSessionDetail,
  UserProfileResponse
} from "../types";

function resolveApiBaseUrl(): string {
  const raw = (import.meta.env.VITE_API_URL || import.meta.env.VITE_BACKEND_URL || "").trim();
  const isBrowser = typeof window !== "undefined";
  const isHostedDomain = isBrowser && window.location.hostname !== "localhost" && window.location.hostname !== "127.0.0.1";
  
  // If hosted on Vercel or production domain, never allow localhost fallback
  if (isHostedDomain && (raw.includes("localhost") || raw.includes("127.0.0.1") || !raw)) {
    return "/api/v1";
  }

  if (raw) {
    return raw.endsWith("/api/v1") ? raw : `${raw.replace(/\/+$/, "")}/api/v1`;
  }
  return import.meta.env.PROD ? "/api/v1" : "http://localhost:8000/api/v1";
}

export const API_BASE_URL = resolveApiBaseUrl();

let activeAuthTokenGetter: (() => Promise<string | null> | string | null) | null = null;

/**
 * Connects Clerk's session token getter to outgoing API requests.
 */
export function setAuthTokenGetter(getter: (() => Promise<string | null> | string | null) | null) {
  activeAuthTokenGetter = getter;
}

/**
 * Resolves current authorization header, prioritizing active Clerk session token.
 */
export async function getAuthorizationHeader(): Promise<string | null> {
  if (activeAuthTokenGetter) {
    try {
      const token = await activeAuthTokenGetter();
      if (token) {
        return token.startsWith("Bearer ") ? token : `Bearer ${token}`;
      }
    } catch (e) {
      console.warn("Failed to get auth token from active getter:", e);
    }
  }
  return null;
}

async function request<T>(endpoint: string, options?: RequestInit, timeoutMs = 20000): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const authHeader = await getAuthorizationHeader();
    const reqHeaders: Record<string, string> = {
      "Content-Type": "application/json",
      ...(options?.headers as Record<string, string> || {})
    };
    if (authHeader) {
      reqHeaders["Authorization"] = authHeader;
    }

    const res = await fetch(url, {
      ...options,
      cache: "no-store",
      signal: options?.signal || controller.signal,
      headers: reqHeaders
    });

    clearTimeout(timer);

    if (!res.ok) {
      const errorBody = await res.json().catch(() => ({}));
      const msg = errorBody.detail || errorBody.message || `HTTP ${res.status}: ${res.statusText}`;
      if (res.status === 401) {
        const detailMsg = typeof msg === "string" && msg && !msg.startsWith("HTTP 401")
          ? msg
          : "Authentication required. Please sign in with your authorized analyst account.";
        throw new Error(detailMsg);
      } else if (res.status === 422) {
        throw new Error(`Validation error: ${typeof msg === 'string' ? msg : JSON.stringify(msg)}`);
      } else if (res.status === 500) {
        throw new Error("Internal security engine error. Please retry the investigation.");
      }
      throw new Error(typeof msg === 'string' ? msg : `Request failed with status ${res.status}`);
    }

    if (res.status === 204) {
      return {} as T;
    }

    return await res.json();
  } catch (err: any) {
    clearTimeout(timer);
    console.error(`Request to ${endpoint} failed:`, err);
    if (err.name === "AbortError") {
      throw new Error("Threat investigation timed out after 20 seconds. Please check backend connection and retry.");
    }
    if (err instanceof TypeError && (err.message.includes("fetch") || err.message.includes("NetworkError"))) {
      throw new Error(`Unable to connect to SOC backend (${API_BASE_URL}). Verify backend service is running.`);
    }
    throw err;
  }
}

export const api = {
  // System Health
  async getHealth() {
    return request<{ status: string; database: string; database_engine?: string; database_latency_ms?: number; hf_configured: boolean; hf_model: string }>("/health");
  },

  // Live Email Scanner
  async scanEmail(content: string, subject?: string, sender?: string): Promise<ScanResult> {
    return request<ScanResult>("/scan", {
      method: "POST",
      body: JSON.stringify({
        raw_content: content,
        subject,
        sender
      })
    });
  },

  // AI Agent Threat Investigation
  async investigateEmail(content: string, rawHeaders?: string, scanId?: string): Promise<AgentInvestigation> {
    return request<AgentInvestigation>("/agent/investigate", {
      method: "POST",
      body: JSON.stringify({
        email_content: content,
        raw_headers: rawHeaders || "none",
        scan_id: scanId
      })
    });
  },

  // Progressive SSE streaming for autonomous threat investigator
  async investigateEmailStream(
    content: string,
    rawHeaders: string = "none",
    onEvent: (event: { event: string; message?: string; step?: number; tool?: string; output?: any; data?: AgentInvestigation }) => void,
    scanId?: string,
    signal?: AbortSignal
  ): Promise<AgentInvestigation> {
    const url = `${API_BASE_URL}/agent/investigate/stream`;
    try {
      const authHeader = await getAuthorizationHeader();
      const res = await fetch(url, {
        method: "POST",
        signal,
        headers: {
          "Content-Type": "application/json",
          ...(authHeader ? { "Authorization": authHeader } : {})
        },
        body: JSON.stringify({
          email_content: content,
          raw_headers: rawHeaders || "none",
          scan_id: scanId
        })
      });

      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: Failed to initialize progressive investigation stream`);
      }

      if (!res.body) {
        throw new Error("ReadableStream not supported by browser runtime.");
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let completedData: AgentInvestigation | null = null;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed.startsWith("data: ")) {
            try {
              const parsed = JSON.parse(trimmed.substring(6));
              onEvent(parsed);
              if (parsed.event === "COMPLETED" && parsed.data) {
                completedData = parsed.data;
              }
            } catch (jsonErr) {
              console.warn("Could not parse SSE event chunk:", jsonErr);
            }
          }
        }
      }

      if (completedData) {
        return completedData;
      }

      // If stream ended without final payload, do standard query
      return await this.investigateEmail(content, rawHeaders, scanId);
    } catch (err: any) {
      if (err.name === "AbortError") {
        throw new Error("Threat investigation was aborted or timed out.");
      }
      if (err instanceof TypeError && (err.message.includes("fetch") || err.message.includes("NetworkError"))) {
        throw new Error(`Unable to connect to SOC backend (${API_BASE_URL}). Verify backend service is running.`);
      }
      // If streaming fails unexpectedly, fallback gracefully to non-streaming endpoint
      console.warn("SSE stream failed, falling back to synchronous investigate:", err);
      return await this.investigateEmail(content, rawHeaders, scanId);
    }
  },

  // Security Analytics Dashboard
  async getAnalytics(): Promise<AnalyticsOverview> {
    return request<AnalyticsOverview>("/analytics/overview");
  },

  // AI URL Threat Intelligence Engine
  async analyzeUrl(url: string, followRedirects: boolean = true) {
    return request<import("../types").UrlThreatIntelResponse>("/url/analyze", {
      method: "POST",
      body: JSON.stringify({ url, follow_redirects: followRedirects })
    });
  },

  async analyzeUrlBatch(urls: string[]) {
    return request<import("../types").UrlThreatIntelResponse[]>("/url/batch", {
      method: "POST",
      body: JSON.stringify({ urls })
    });
  },

  async extractAndAnalyzeUrls(content: string, followRedirects: boolean = true) {
    return request<import("../types").UrlThreatIntelResponse[]>("/url/extract", {
      method: "POST",
      body: JSON.stringify({ content, follow_redirects: followRedirects })
    });
  },

  async investigateCustomUrl(url: string, mode: "quick" | "deep" = "deep") {
    return request<import("../types").CustomUrlInvestigationResponse>("/url/investigate", {
      method: "POST",
      body: JSON.stringify({ url, mode })
    });
  },

  async getUrlProviders() {
    return request<{ status: string; providers: Record<string, any> }>("/url/providers");
  },

  // ML Models & Evaluation Benchmarks
  async getModelBenchmarks(): Promise<ModelBenchmarksResponse> {
    return request<ModelBenchmarksResponse>("/models/benchmarks");
  },

  // Scan History
  async getHistory(limit = 25, offset = 0, threatLevel?: string) {
    const query = new URLSearchParams({
      limit: String(limit),
      offset: String(offset),
      _t: Date.now().toString()
    });
    if (threatLevel) query.append("threat_level", threatLevel);
    return request<{ total_returned: number; scans: any[] }>(`/history?${query.toString()}`);
  },

  async getScanDetail(scanId: string): Promise<ScanResult> {
    return request<ScanResult>(`/history/${scanId}?_t=${Date.now()}`);
  },

  // Conversational Security Assistant (Sentinel Copilot)
  async sendChatMessage(
    message: string,
    sessionId?: string,
    emailContent?: string,
    rawHeaders?: string,
    scanId?: string,
    language?: string
  ): Promise<ChatMessageResponse> {
    return request<ChatMessageResponse>("/chat/message", {
      method: "POST",
      body: JSON.stringify({
        message,
        session_id: sessionId,
        email_content: emailContent,
        raw_headers: rawHeaders || "none",
        scan_id: scanId,
        language: language || "en-US"
      })
    });
  },

  async sendChatMessageStream(
    message: string,
    sessionId?: string,
    emailContent?: string,
    rawHeaders?: string,
    scanId?: string,
    onChunk?: (token: string) => void,
    language?: string
  ): Promise<ChatMessageResponse> {
    const authHeader = await getAuthorizationHeader();
    const res = await fetch(`${API_BASE_URL}/chat/message/stream`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(authHeader ? { "Authorization": authHeader } : {})
      },
      body: JSON.stringify({
        message,
        session_id: sessionId,
        email_content: emailContent,
        raw_headers: rawHeaders || "none",
        scan_id: scanId,
        language: language || "en-US"
      })
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Server error: ${res.status}`);
    }

    const reader = res.body?.getReader();
    const decoder = new TextDecoder("utf-8");
    let completePayload: ChatMessageResponse | null = null;

    if (reader) {
      let buffer = "";
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          if (line.startsWith("data: ")) {
            try {
              const event = JSON.parse(line.slice(6));
              if (event.type === "chunk" && onChunk) {
                onChunk(event.text);
              } else if (event.type === "complete") {
                completePayload = event as ChatMessageResponse;
              }
            } catch (e) {
              // Ignore partial parse errors during stream
            }
          }
        }
      }
    }

    if (!completePayload) {
      return this.sendChatMessage(message, sessionId, emailContent, rawHeaders, scanId);
    }

    return completePayload;
  },

  async getChatSessions(limit = 20, offset = 0): Promise<ChatSessionSummary[]> {
    const query = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    return request<ChatSessionSummary[]>(`/chat/sessions?${query.toString()}`);
  },

  async getChatSessionDetail(sessionId: string): Promise<ChatSessionDetail> {
    return request<ChatSessionDetail>(`/chat/sessions/${sessionId}`);
  },

  async deleteChatSession(sessionId: string): Promise<void> {
    return request<void>(`/chat/sessions/${sessionId}`, {
      method: "DELETE"
    });
  },

  // Enterprise Authentication Telemetry (Phase 5.1)
  async getAuthMe(): Promise<UserProfileResponse> {
    return request<UserProfileResponse>("/auth/me");
  },

  async verifyAdminAccess(): Promise<{ status: string; role: string; message: string }> {
    return request<{ status: string; role: string; message: string }>("/auth/admin-check");
  },

  async verifySocAccess(): Promise<{ status: string; role: string; message: string }> {
    return request<{ status: string; role: string; message: string }>("/auth/soc-check");
  },

  async verifyCustomerAccess(): Promise<{ status: string; role: string; message: string }> {
    return request<{ status: string; role: string; message: string }>("/auth/customer-check");
  }
};
