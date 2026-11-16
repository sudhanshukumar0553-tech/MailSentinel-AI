/**
 * MailSentinel AI - Global Date, Timezone & Timestamp Standardizer
 * Phase 3.8 Global Standard:
 * - Storage & API: Always UTC (ISO 8601 with trailing 'Z')
 * - User Display Timezone: Asia/Kolkata (IST - UTC+05:30)
 * - Standard Display Format: DD MMM YYYY, hh:mm:ss AM/PM IST
 *
 * Uses Intl.DateTimeFormat for native browser timezone conversion.
 * Never performs manual +5:30 arithmetic.
 * Prevents double-conversion and handles invalid/missing timestamps gracefully.
 */

export const DEFAULT_DISPLAY_TIMEZONE = "Asia/Kolkata";
export const DISPLAY_TIMEZONE_LABEL = "IST";
export const DISPLAY_TIMEZONE_FULL = "IST (UTC+05:30)";

/**
 * Safely parses any date input into a JavaScript Date object representing the exact UTC instant.
 * - If input is null/undefined/empty string: returns null.
 * - If input is already a Date: returns it if valid.
 * - If input is number: treats as epoch timestamp.
 * - If input is string:
 *   If it lacks timezone information (e.g. naive SQLite string "2026-11-16 08:59:25.661673"),
 *   it explicitly appends 'Z' because the backend stores pure UTC timestamps.
 */
export function parseUtcDate(input: string | number | Date | null | undefined): Date | null {
  if (input === null || input === undefined || input === "") {
    return null;
  }

  if (input instanceof Date) {
    return isNaN(input.getTime()) ? null : input;
  }

  if (typeof input === "number") {
    // If timestamp is in seconds instead of milliseconds (< 1e11), multiply by 1000
    const ms = input < 1e11 ? input * 1000 : input;
    const d = new Date(ms);
    return isNaN(d.getTime()) ? null : d;
  }

  if (typeof input === "string") {
    let s = input.trim();
    if (!s) return null;

    // Check if string is already an RFC 2822 or human format
    // If it's an ISO or SQLite timestamp string:
    // E.g. "2026-11-16 08:59:25.661673" or "2026-11-16T08:59:25"
    if (/^\d{4}-\d{2}-\d{2}/.test(s)) {
      // Normalize space between date and time to 'T'
      if (s.includes(" ") && !s.includes("T")) {
        s = s.replace(" ", "T");
      }
      // If it doesn't end with Z and doesn't contain a timezone offset like +05:30 or -04:00
      if (!s.endsWith("Z") && !/[+-]\d{2}:?\d{2}$/.test(s)) {
        s += "Z";
      }
    }

    const d = new Date(s);
    return isNaN(d.getTime()) ? null : d;
  }

  return null;
}

export interface FormatOptions {
  includeSeconds?: boolean;
  includeTz?: boolean;
  timeZone?: string;
}

/**
 * Formats a timestamp into the standard MailSentinel display format in Asia/Kolkata (IST):
 * Format: DD MMM YYYY, hh:mm:ss AM/PM IST
 * Example: 16 Nov 2026, 02:29:15 PM IST
 */
export function formatIST(
  input: string | number | Date | null | undefined,
  options: FormatOptions = {}
): string {
  const d = parseUtcDate(input);
  if (!d) {
    return typeof input === "string" && input ? input : "N/A";
  }

  const {
    includeSeconds = true,
    includeTz = true,
    timeZone = DEFAULT_DISPLAY_TIMEZONE
  } = options;

  try {
    const intlOptions: Intl.DateTimeFormatOptions = {
      timeZone,
      day: "2-digit",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hour12: true
    };

    if (includeSeconds) {
      intlOptions.second = "2-digit";
    }

    const formatter = new Intl.DateTimeFormat("en-IN", intlOptions);
    let formatted = formatter.format(d);

    // Standardize AM/PM to uppercase (e.g. "pm" -> "PM")
    formatted = formatted.replace(/\b(am|pm)\b/gi, (match) => match.toUpperCase());

    if (includeTz) {
      formatted = `${formatted} ${DISPLAY_TIMEZONE_LABEL}`;
    }

    return formatted;
  } catch (err) {
    console.error("formatIST error:", err);
    return d.toISOString();
  }
}

/**
 * Formats a timestamp into short date and time (without seconds):
 * Example: 16 Nov 2026, 02:29 PM IST
 */
export function formatISTShort(
  input: string | number | Date | null | undefined,
  includeTz = true
): string {
  return formatIST(input, { includeSeconds: false, includeTz });
}

/**
 * Formats only the time component in IST:
 * Example: 02:29:15 PM IST (or 02:29 PM IST without seconds)
 */
export function formatISTTimeOnly(
  input: string | number | Date | null | undefined,
  includeSeconds = false,
  includeTz = true
): string {
  const d = parseUtcDate(input);
  if (!d) return "N/A";

  try {
    const intlOptions: Intl.DateTimeFormatOptions = {
      timeZone: DEFAULT_DISPLAY_TIMEZONE,
      hour: "2-digit",
      minute: "2-digit",
      hour12: true
    };
    if (includeSeconds) {
      intlOptions.second = "2-digit";
    }

    const formatter = new Intl.DateTimeFormat("en-IN", intlOptions);
    let formatted = formatter.format(d);
    formatted = formatted.replace(/\b(am|pm)\b/gi, (match) => match.toUpperCase());

    if (includeTz) {
      formatted = `${formatted} ${DISPLAY_TIMEZONE_LABEL}`;
    }
    return formatted;
  } catch {
    return d.toLocaleTimeString();
  }
}

/**
 * Formats only the calendar date in IST:
 * Example: 16 Nov 2026
 */
export function formatISTDateOnly(
  input: string | number | Date | null | undefined
): string {
  const d = parseUtcDate(input);
  if (!d) return "N/A";

  try {
    const formatter = new Intl.DateTimeFormat("en-IN", {
      timeZone: DEFAULT_DISPLAY_TIMEZONE,
      day: "2-digit",
      month: "short",
      year: "numeric"
    });
    return formatter.format(d);
  } catch {
    return d.toLocaleDateString();
  }
}

/**
 * Formats a relative timestamp with IST time (e.g. "Today at 02:29 PM IST" or "16 Nov 2026, 02:29 PM IST").
 */
export function formatRelativeIST(
  input: string | number | Date | null | undefined
): string {
  const d = parseUtcDate(input);
  if (!d) return "N/A";

  const now = new Date();
  const todayStr = formatISTDateOnly(now);
  const targetDateStr = formatISTDateOnly(d);

  const timePart = formatISTTimeOnly(d, false, true);

  if (todayStr === targetDateStr) {
    return `Today at ${timePart}`;
  }

  // Calculate yesterday in IST
  const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  if (formatISTDateOnly(yesterday) === targetDateStr) {
    return `Yesterday at ${timePart}`;
  }

  return `${targetDateStr}, ${timePart}`;
}

/**
 * Converts any timestamp or date into canonical ISO 8601 UTC with 'Z' suffix.
 * Example: 2026-11-16T08:59:15.661Z
 */
export function safeIsoUtc(input: string | number | Date | null | undefined): string {
  const d = parseUtcDate(input);
  if (!d) return new Date().toISOString();
  return d.toISOString();
}

/**
 * Backward compatibility alias for legacy formatDate callers.
 */
export const formatDate = (isoString: string): string => {
  return formatIST(isoString, { includeSeconds: true, includeTz: true });
};

