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
  /** Medium-interaction (Cowrie) malware & session intelligence. Optional:
   *  older snapshots predate it. */
  malware?: MalwareIntel;

  /* ── live-grid extensions (optional; older snapshots predate them) ── */
  /** live attack-rate counters (last 1m / 1h / 24h) */
  counters?: Counters;
  /** attack-volume series at 3 granularities (raw T-Pot, full volume) */
  activity?: Activity;
  /** 24h hourly intensity, for the heatmap stripe */
  heatmap_hourly?: ActivityPoint[];
  /** real honeypots (T-Pot sensors) event counts, for the performance chart */
  honeypots?: HoneypotCount[];
  /** attack-origin map: per-window clustered markers (hero map). */
  map?: HoneypotMap;
  /** per-window volume slices, driven by the global time-window selector.
   *  Volume-based sections read from here; malware/CVEs stay global. */
  windows?: Record<Win, WindowSlice>;
}

/** The global time-window selector's three positions. */
export type Win = "h1" | "h12" | "h24";

/**
 * A per-window slice of the volume-based sections. Every field here responds
 * to the global window selector; sections absent from this type (malware,
 * CVEs, heatmap, counters) are window-independent and read from the root.
 */
export interface WindowSlice {
  totals: HoneypotTotals;
  top_ips: TopIp[];
  top_countries: Count[];
  top_asns: Count[];
  services: Count[];
  actors: Count[];
  top_usernames: Count[];
  top_passwords: Count[];
  mitre: Record<string, number>;
  honeypots?: HoneypotCount[];
}

export interface Counters {
  m1: number;
  h1: number;
  h24: number;
}
export interface ActivityPoint {
  t: string;
  count: number;
}
export interface Activity {
  h1: ActivityPoint[];
  h12: ActivityPoint[];
  h24: ActivityPoint[];
}
export interface HoneypotCount {
  name: string;
  count: number;
}

/** A geo-clustered attacker marker for the hero map. Never a home/sensor point. */
export interface MapMarker {
  lat: number;
  lon: number;
  /** ISO-3166 alpha-2 country code */
  cc: string;
  /** dominant service/protocol at this cluster (drives the marker color) */
  proto: string;
  /** distinct attacker IPs in this cluster */
  ips: number;
  /** total attack events in this cluster */
  attacks: number;
  /** top source IPs with per-IP attack counts */
  top_ips: { ip: string; attacks: number }[];
  /** first event seen (ISO UTC) */
  first: string;
  /** last event seen (ISO UTC) */
  last: string;
}

export interface HoneypotMap {
  /** raw recent points (legacy; unused by the hero map) */
  recent?: { lat: number; lon: number; cc: string; proto: string }[];
  /** clustered markers per time-window, driven by the global selector */
  markers?: Record<Win, MapMarker[]>;
}

/**
 * Aggregated malware/session intelligence captured by the Cowrie sensor and
 * enriched (MalwareBazaar, Triage sandbox, Malpedia, URLhaus, …). Only
 * aggregates and public indicators — never raw samples.
 */
export interface MalwareIntel {
  /** distinct malware samples captured (unique SHA-256) */
  captured_samples: number;
  /** breakdown of captured files by classification */
  sample_counts: SampleCounts;
  /** distinct SSH client fingerprints (HASSH) */
  hassh_count: number;
  families: MalwareFamily[];
  /** most-run shell commands (whitespace-deduped) */
  top_commands: Count[];
  top_hashes: MalwareHash[];
  /** known malware-distribution / C2 hosts (URLhaus), enriched with ThreatFox + geo */
  distribution_hosts: C2Host[];
  /** direct-tcpip pivot/relay targets requested by attackers */
  pivot_targets: Count[];
  /** filesystem paths malware tried to drop into */
  filenames: Count[];
  /** SSH client versions seen (bot frameworks: Go, russh, PuTTY…) */
  ssh_clients: Count[];
  /** sandbox behavior tags (Triage): antivm, defense_evasion… */
  behavior: Count[];
}

export interface MalwareFamily {
  family: string;
  samples: number;
  /** last time a sample of this family was seen (UTC "YYYY-MM-DDTHH:mm"), for recency */
  last_seen?: string;
  /** alternative names (Malpedia alt_names) */
  aliases: string[];
  /** attributed threat actors/groups (Malpedia) */
  actors: string[];
  /** Malpedia family description */
  description: string;
  malpedia_url: string;
  /** sandbox behavior tags for a representative sample */
  behavior: string[];
  /** Triage sandbox score, e.g. "7" */
  sandbox_score: string | number;
  sandbox_url: string;
  /** cross-vendor verdicts, e.g. "ReversingLabs:Win32.Trojan.Malgent" */
  vendors: string[];
  /** a representative captured sample hash */
  sample_sha256: string;
}

export interface SampleCounts {
  total: number;
  /** captured files identified as known malware */
  classified: number;
  /** recon scripts, probes, empty files — not malware */
  unclassified: number;
}

/** A malware-distribution / C2 host, enriched with ThreatFox + geo/ASN intel. */
export interface C2Host {
  host: string;
  count: number;
  /** last time this host was contacted (UTC "YYYY-MM-DDTHH:mm"), for recency */
  last_seen?: string;
  /** ThreatFox threat type, e.g. "payload_delivery" */
  threat_type?: string;
  /** associated malware family, e.g. "Mirai" */
  malware?: string;
  /** ThreatFox confidence level 0–100 */
  confidence?: number;
  first_seen?: string;
  /** ThreatFox IOC id (deep link) */
  threatfox_id?: string;
  tags?: string[];
  reference?: string;
  country?: string;
  city?: string;
  /** ISP / hosting provider name */
  isp?: string;
  /** ASN string, e.g. "AS25198 ZetServers" */
  asn?: string;
  hosting?: boolean;
  proxy?: boolean;
  /** open ports on the host (Shodan InternetDB) */
  ports?: number[];
  /** exposed CVEs on the host (Shodan InternetDB) */
  vulns?: string[];
}

export interface MalwareHash {
  sha256: string;
  count: number;
  /** identified family, or "" if unknown */
  family: string;
  /** true when classified as known malware (family or vendor verdicts) */
  known: boolean;
  /** number of third-party vendor verdicts */
  vendors: number;
  /** payload size in bytes */
  size: number;
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
  /** origin network / ASN owner (ip-api), e.g. "Dm Auto Eood" */
  asn?: string;
  /** ISO-3166 alpha-2 country code, for the flag */
  cc?: string;
  /** DS Fusion Engine confidence 0–100 (Dempster-Shafer belief) */
  confidence?: number;
  /** DS Fusion Engine verdict (malicious/suspicious/…), drives the meter color */
  verdict?: string;
}

export interface TimelinePoint {
  date: string;
  count: number;
}

export type ActorType = "malicious" | "tor" | "research" | "cloud" | "unknown";
