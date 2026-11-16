/**
 * MailSentinel AI - UI Utility Helpers & Color Formatters
 */

import type { ThreatLevel } from "../types";
import { formatIST, formatISTShort } from "./dateFormatter";

export { formatIST, formatISTShort };

export function getThreatLevelConfig(level: ThreatLevel) {
  switch (level) {
    case "CRITICAL":
      return {
        bg: "bg-rose-950/50",
        border: "border-rose-500/50",
        text: "text-rose-400",
        glow: "shadow-[0_0_15px_rgba(244,63,94,0.35)]",
        badgeBg: "bg-rose-500/20 text-rose-300 border-rose-500/30",
        label: "Critical Threat"
      };
    case "DANGEROUS":
      return {
        bg: "bg-orange-950/50",
        border: "border-orange-500/50",
        text: "text-orange-400",
        glow: "shadow-[0_0_15px_rgba(249,115,22,0.35)]",
        badgeBg: "bg-orange-500/20 text-orange-300 border-orange-500/30",
        label: "Dangerous"
      };
    case "SUSPICIOUS":
      return {
        bg: "bg-amber-950/50",
        border: "border-amber-500/50",
        text: "text-amber-400",
        glow: "shadow-[0_0_15px_rgba(245,158,11,0.35)]",
        badgeBg: "bg-amber-500/20 text-amber-300 border-amber-500/30",
        label: "Suspicious"
      };
    case "SAFE":
    default:
      return {
        bg: "bg-emerald-950/50",
        border: "border-emerald-500/50",
        text: "text-emerald-400",
        glow: "shadow-[0_0_15px_rgba(16,185,129,0.35)]",
        badgeBg: "bg-emerald-500/20 text-emerald-300 border-emerald-500/30",
        label: "Safe / Clean"
      };
  }
}

export function formatDate(isoString: string): string {
  return formatIST(isoString, { includeSeconds: true, includeTz: true });
}
