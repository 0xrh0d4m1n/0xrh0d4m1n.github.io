import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Format a plain-date string (e.g. "2026-04-16" from markdown frontmatter)
 * without the off-by-one timezone bug.
 *
 * `new Date("2026-04-16")` parses the string as UTC midnight. Any browser in
 * a timezone west of UTC (e.g. America/Sao_Paulo, UTC-3) would then render
 * that instant as the previous day. Forcing `timeZone: "UTC"` in the
 * formatter keeps the displayed day identical to what the author wrote in
 * frontmatter, regardless of where the page is viewed.
 */
export function formatDate(
  input: string,
  options: Intl.DateTimeFormatOptions = {
    year: "numeric",
    month: "long",
    day: "numeric",
  },
  locale: string = "en-US",
): string {
  return new Date(input).toLocaleDateString(locale, {
    ...options,
    timeZone: "UTC",
  });
}
