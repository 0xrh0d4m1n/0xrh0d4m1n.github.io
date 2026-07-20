/**
 * Shape of the aggregated honeypot telemetry snapshot.
 * Produced by `export-stats.py` on the Mirage analysis host and served as a
 * static JSON (mock now; Cloudflare edge cache later). Contains only
 * AGGREGATED data — never the honeypot's own IP/hostname or raw secrets.
 */
export interface HoneypotStats {
  generated_at: string;
  window_days: number;
  totals: HoneypotTotals;
  top_ips: TopIp[];
  top_countries: Count[];
  top_asns: Count[];
  services: Count[];
  actors: Count[];
  top_usernames: Count[];
  top_passwords: Count[];
  timeline: TimelinePoint[];
  /** MITRE ATT&CK technique id -> observed event count. */
  mitre: Record<string, number>;
  top_cves: Cve[];
}

export interface Cve {
  cve: string;
  /** distinct attacker IPs exposing this CVE (Shodan InternetDB) */
  hosts: number;
  events: number;
  /** CVSS base severity from NVD (critical/high/medium/low/unknown) */
  severity: string;
  /** CVSS base score from NVD (0–10), or null if unrated */
  score: number | null;
  /** short NVD description */
  desc: string;
  /** primary CWE id from NVD (e.g. "CWE-78"), or "" */
  cwe: string;
}

export interface HoneypotTotals {
  events: number;
  unique_ips: number;
  countries: number;
  asns: number;
  malicious_pct: number;
}

export interface Count {
  key: string;
  count: number;
}

export interface TopIp {
  ip: string;
  events: number;
  score: number;
  country: string;
  actor: string;
  service: string;
}

export interface TimelinePoint {
  date: string;
  count: number;
}

export type ActorType = "malicious" | "tor" | "research" | "cloud" | "unknown";
