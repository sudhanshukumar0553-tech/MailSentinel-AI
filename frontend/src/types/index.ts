/**
 * MailSentinel AI - TypeScript Data Contracts
 * Exactly matches FastAPI backend Pydantic models.
 */

export type ThreatLevel = "SAFE" | "SUSPICIOUS" | "DANGEROUS" | "CRITICAL";

export interface DetectedUrl {
  defanged_url: string;
  domain?: string;
  tld?: string;
  entropy: number;
  is_suspicious: boolean;
  risk_score: number;
  risk_reasons: string[];
  verification_note: string;
}

export interface HeaderDetails {
  status: string;
  risk_score?: number;
  spf_status?: string;
  dkim_status?: string;
  dmarc_status?: string;
  hop_count?: number;
  findings?: string[];
  is_spoofed?: boolean;
  has_headers?: boolean;
}

export interface ScanResult {
  id: string;
  created_at: string;
  subject: string;
  sender: string;
  recipient: string;
  has_headers: boolean;
  risk_score: number;
  threat_level: ThreatLevel;
  verdict: string;
  theme_color: string;
  spam_probability: number;
  phishing_probability: number;
  header_risk_score: number;
  url_risk_score: number;
  detected_urls: DetectedUrl[];
  header_details: HeaderDetails;
  recommendations: string[];
  xai_report?: {
    factor_breakdown: {
      spam_contribution: number;
      phishing_contribution: number;
      url_contribution: number;
      header_contribution: number | null;
    };
    top_spam_words?: string[];
    top_phish_words?: string[];
  };
}

export interface AgentStep {
  step: number;
  tool: string;
  output: Record<string, any>;
}

export interface AgentInvestigation {
  status: string;
  model_used: string;
  agent_mode: string;
  steps_count: number;
  steps: AgentStep[];
  risk_score: number;
  threat_level: ThreatLevel;
  verdict: string;
  final_report: string;
  investigation_id?: string;
  created_at?: string;
}

export interface AnalyticsOverview {
  total_scans: number;
  clean_emails: number;
  threats_blocked: number;
  phishing_detected: number;
  spam_detected: number;
  malicious_urls_intercepted: number;
  average_risk_score: number;
  synced_at?: string;
  threat_distribution: Array<{
    tier: string;
    count: number;
    color: string;
  }>;
}

export interface ModelMetrics {
  model_name?: string;
  task?: string;
  dataset?: string;
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  evaluated_at?: string;
  confusion_matrix?: {
    true_negatives: number;
    false_positives: number;
    false_negatives: number;
    true_positives: number;
  };
  top_features?: {
    malicious_indicators: Array<{ token: string; weight: number }>;
    safe_indicators: Array<{ token: string; weight: number }>;
  };
}

export interface ModelBenchmarksResponse {
  status: string;
  models: Record<string, ModelMetrics>;
}

export interface ChatMessage {
  id: string;
  role: "user" | "assistant" | "system" | "tool";
  content: string;
  tool_calls?: Record<string, any>;
  created_at: string;
}

export interface ChatMessageResponse {
  session_id: string;
  role: string;
  reply: string;
  mode: string;
  is_llm_generated: boolean;
  operational_status: string;
  disclaimer?: string | null;
  model_used?: string | null;
  latency_ms?: number | null;
  tools_invoked: Array<{ tool: string; output: Record<string, any> }>;
  evidence: Record<string, any>;
  created_at: string;
}

export interface ChatSessionSummary {
  id: string;
  title: string;
  analyst_id: string;
  created_at: string;
  updated_at: string;
  associated_scan_id?: string | null;
  message_count: number;
}

export interface ChatSessionDetail {
  id: string;
  title: string;
  analyst_id: string;
  created_at: string;
  updated_at: string;
  associated_scan_id?: string | null;
  messages: ChatMessage[];
}

// URL Threat Intelligence Interfaces
export interface UrlProviderResult {
  provider: string;
  status: string;
  is_malicious: boolean;
  detections_count: number;
  total_engines: number;
  threat_tags: string[];
  message?: string | null;
}

export interface UrlHeuristicDetails {
  entropy: number;
  is_ip_address: boolean;
  has_suspicious_tld: boolean;
  is_shortener: boolean;
  is_typosquatting: boolean;
  impersonated_brand?: string | null;
  has_punycode: boolean;
  suspicious_keywords: string[];
  risk_reasons: string[];
  heuristic_score: number;
}

export interface UrlRedirectHop {
  hop: number;
  url: string;
  status_code: number;
  resolved_ip?: string | null;
}

export interface UrlThreatIntelResponse {
  original_url: string;
  normalized_url: string;
  defanged_url: string;
  domain: string;
  tld: string;
  verdict: "SAFE" | "SUSPICIOUS" | "MALICIOUS" | "UNKNOWN";
  confidence: number;
  threat_reasons: string[];
  reputation: Record<string, UrlProviderResult>;
  heuristics: UrlHeuristicDetails;
  redirect_chain: UrlRedirectHop[];
  final_destination?: string | null;
  ssrf_blocked: boolean;
  cached: boolean;
  analyzed_at: string;
}

export interface CheckStatusItem {
  status: "succeeded" | "failed" | "unavailable";
  message: string;
  details?: Record<string, any> | null;
}

export interface TlsCertificateDetails {
  has_tls: boolean;
  issuer?: string | null;
  subject?: string | null;
  valid_from?: string | null;
  valid_to?: string | null;
  is_expired?: boolean | null;
  cipher?: string | null;
  version?: string | null;
  error?: string | null;
}

export interface CustomUrlInvestigationResponse {
  original_url: string;
  normalized_url: string;
  defanged_url: string;
  is_defanged: boolean;
  domain: string;
  subdomain?: string | null;
  tld: string;
  path: string;
  query: string;
  threat_score: number;
  verdict: "MALICIOUS" | "SUSPICIOUS" | "CLEAN" | "UNKNOWN";
  mode: "quick" | "deep";
  heuristics: UrlHeuristicDetails;
  checks: Record<string, CheckStatusItem>;
  tls_details?: TlsCertificateDetails | null;
  redirect_chain: UrlRedirectHop[];
  final_destination?: string | null;
  ai_explanation: string;
  ai_model_used?: string | null;
  analyzed_at: string;
}

// Enterprise Authentication & RBAC Models (Phase 5.1)
export type UserRole = "Admin" | "SOC Analyst" | "Customer";

export interface AuthUserProfile {
  id: string;
  email?: string | null;
  fullName?: string | null;
  firstName?: string | null;
  imageUrl?: string | null;
  role: UserRole;
  provider: "oauth_google" | "clerk" | "api_key" | "demo";
  is_authenticated: boolean;
  permissions: string[];
}

export interface UserProfileResponse {
  id: string;
  email?: string | null;
  role: UserRole;
  provider: string;
  is_authenticated: boolean;
  permissions: string[];
}




