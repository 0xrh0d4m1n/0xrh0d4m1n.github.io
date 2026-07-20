/**
 * Threat-intel platforms where the honeypot's findings are published.
 * Shared by the profile badges (links to my profile) and the Top Attacking
 * IPs table (links to each IP's report on the platform).
 *
 * Update `profileUrl` if a platform handle/id changes. The AbuseIPDB and OTX
 * ids were verified via API; the VirusTotal handle is the standard vanity URL.
 */
export interface ThreatPlatform {
  name: string;
  domain: string;
  color: string;
  profileUrl: string;
  ipUrl: (ip: string) => string;
}

export const HANDLE = "@0xrh0d4m1n";

export const THREAT_PLATFORMS: ThreatPlatform[] = [
  {
    name: "VirusTotal",
    domain: "virustotal.com",
    color: "#3b5bff",
    profileUrl: "https://www.virustotal.com/gui/user/0xrh0d4m1n",
    ipUrl: (ip) => `https://www.virustotal.com/gui/ip-address/${ip}`,
  },
  {
    name: "AbuseIPDB",
    domain: "abuseipdb.com",
    color: "#1e88e5",
    profileUrl: "https://www.abuseipdb.com/user/181631",
    ipUrl: (ip) => `https://www.abuseipdb.com/check/${ip}`,
  },
  {
    name: "OTX AlienVault",
    domain: "otx.alienvault.com",
    color: "#00a9a5",
    profileUrl: "https://otx.alienvault.com/user/0xrh0d4m1n",
    ipUrl: (ip) => `https://otx.alienvault.com/indicator/ip/${ip}`,
  },
];

/** Uniform, reliable favicon for any domain (real platform marks). */
export function faviconFor(domain: string): string {
  return `https://www.google.com/s2/favicons?sz=64&domain=${domain}`;
}
