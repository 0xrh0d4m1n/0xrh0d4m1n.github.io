"use client";

import { useMemo, useState } from "react";
import { MapContainer, TileLayer, CircleMarker, Tooltip } from "react-leaflet";
import { useLocale, useTranslations } from "next-intl";
import { ChevronRight, TriangleAlert } from "lucide-react";
import "leaflet/dist/leaflet.css";
import { flagUrl } from "@/lib/country-flags";
import type { MapMarker } from "@/types/honeypot";

/* ── service → color (T-Pot-ish palette over the protocols we actually see) ── */
const SERVICE_COLORS: Record<string, string> = {
  SSH: "#9fef00",
  Telnet: "#58a6ff",
  HTTP: "#f0883e",
  HTTPS: "#ffa657",
  FTP: "#d29922",
  "FTP-DATA": "#e3b341",
  RDP: "#bc8cff",
  VNC: "#db61a2",
  SMB: "#ff7b72",
  MySQL: "#3fb950",
  MSSQL: "#2ea043",
  Redis: "#f85149",
  MongoDB: "#ff6ac1",
  SIP: "#a5d6ff",
  ADB: "#ffd33d",
  SMTP: "#7ee787",
  Elasticsearch: "#ffcc00",
  SNMP: "#79c0ff",
  Modbus: "#d2a8ff",
  S7: "#f778ba",
  "IEC-104": "#56d364",
  BACnet: "#e3b341",
  IPMI: "#00d4ff",
  MongoDB2: "#ff6ac1",
  TCP: "#8b949e",
};

/* Stable fallback color for any protocol not in the map (hash → hue). */
function hashHue(s: string): string {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) % 360;
  return `hsl(${h} 70% 60%)`;
}
function svcColor(p: string): string {
  return SERVICE_COLORS[p] ?? hashHue(p || "TCP");
}

/* cc → English region name ("SC" → "Seychelles"), with a graceful fallback. */
function regionName(cc: string): string {
  if (!cc) return "Unknown";
  try {
    return new Intl.DisplayNames(["en"], { type: "region" }).of(cc) ?? cc;
  } catch {
    return cc;
  }
}

/* relative "Xh ago" from an ISO UTC string (client clock). */
function ago(iso: string): string {
  if (!iso) return "—";
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return "—";
  const s = Math.max(0, (Date.now() - then) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

/* marker radius scales with log(attacks) so a scanner cluster reads bigger. */
function radiusFor(attacks: number): number {
  return 3.5 + Math.min(11, Math.log10(Math.max(1, attacks)) * 2.4);
}

function MarkerTooltip({ m }: { m: MapMarker }) {
  const t = useTranslations("honeypot");
  const locale = useLocale();
  const nf = new Intl.NumberFormat(locale);
  const color = svcColor(m.proto);
  const flag = flagUrl(m.cc);
  const shown = m.top_ips.slice(0, 3);
  const more = Math.max(0, m.ips - shown.length);
  const multi = m.ips > 1;

  return (
    <div className="w-60 overflow-hidden rounded-lg border border-[#30363d] bg-[#0d1117] text-[#e6edf3] shadow-xl">
      {/* header */}
      <div
        className="flex items-center gap-2 px-3 py-2"
        style={{ background: multi ? "#3d1418" : "#161b22", borderBottom: "1px solid #30363d" }}
      >
        {flag ? (
          // eslint-disable-next-line @next/next/no-img-element
          <img src={flag} alt="" width={22} height={16} className="h-4 w-[22px] shrink-0 rounded-[2px] object-cover" />
        ) : null}
        <div className="min-w-0">
          <div className="flex items-center gap-1 text-sm font-semibold leading-tight">
            {multi ? <TriangleAlert className="h-3.5 w-3.5 text-[#f85149]" /> : null}
            <span className="truncate">
              {multi ? t("map.multipleAttackers") : m.top_ips[0]?.ip || t("map.attacker")}
            </span>
          </div>
          <div className="truncate text-[11px] text-[#8b949e]">{regionName(m.cc)}</div>
        </div>
      </div>

      {/* body */}
      <div className="flex flex-col gap-1.5 px-3 py-2 text-xs">
        <Row label={t("map.totalIps")} value={nf.format(m.ips)} />
        <Row label={t("map.totalAttacks")} value={nf.format(m.attacks)} />
        <div className="flex items-center justify-between gap-2">
          <span className="text-[#8b949e]">{t("map.topProtocol")}</span>
          <span
            className="rounded px-1.5 py-0.5 font-mono text-[10px] font-bold uppercase"
            style={{ color, backgroundColor: `${color}1f` }}
          >
            {m.proto}
          </span>
        </div>

        {shown.length ? (
          <div className="mt-1 rounded-md border border-[#30363d] bg-[#161b22] p-2">
            <div className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-[#8b949e]">
              {t("map.topSourceIps")}
            </div>
            <div className="flex flex-col gap-1">
              {shown.map((x) => (
                <div key={x.ip} className="flex items-center justify-between gap-2">
                  <span className="truncate font-mono text-[11px]">{x.ip}</span>
                  <span className="shrink-0 rounded bg-[#f85149] px-1.5 py-0.5 font-mono text-[10px] font-bold text-white">
                    {t("map.nAttacks", { n: nf.format(x.attacks) })}
                  </span>
                </div>
              ))}
              {more > 0 ? (
                <div className="border-t border-dashed border-[#30363d] pt-1 text-center text-[10px] text-[#8b949e]">
                  {t("map.andMore", { n: more })}
                </div>
              ) : null}
            </div>
          </div>
        ) : null}

        <div className="mt-0.5 flex items-center justify-between">
          <span className="text-[#8b949e]">{t("map.firstSeen")}</span>
          <span className="font-mono">{ago(m.first)}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-[#8b949e]">{t("map.lastSeen")}</span>
          <span className="font-mono">{ago(m.last)}</span>
        </div>
      </div>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-[#8b949e]">{label}</span>
      <span className="font-mono font-semibold tabular-nums">{value}</span>
    </div>
  );
}

export default function AttackMap({
  markers,
  height = 560,
}: {
  markers: MapMarker[];
  height?: number;
}) {
  const t = useTranslations("honeypot");
  const [open, setOpen] = useState(true);

  /* legend = the services actually present, sorted, biggest-first by volume. */
  const legend = useMemo(() => {
    const vol = new Map<string, number>();
    for (const m of markers) vol.set(m.proto, (vol.get(m.proto) ?? 0) + m.attacks);
    return [...vol.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([svc]) => svc);
  }, [markers]);

  return (
    <div className="relative isolate w-full overflow-hidden rounded-xl border border-border" style={{ height }}>
      <MapContainer
        center={[25, 8]}
        zoom={2}
        minZoom={2}
        maxZoom={8}
        worldCopyJump
        preferCanvas
        scrollWheelZoom={false}
        style={{ height: "100%", width: "100%" }}
      >
        <TileLayer
          url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> &copy; <a href="https://carto.com/attributions">CARTO</a>'
          subdomains="abcd"
        />
        {markers.map((m, i) => {
          const color = svcColor(m.proto);
          return (
            <CircleMarker
              key={`${m.lat},${m.lon},${i}`}
              center={[m.lat, m.lon]}
              radius={radiusFor(m.attacks)}
              pathOptions={{
                color,
                weight: 1,
                opacity: 0.9,
                fillColor: color,
                fillOpacity: 0.5,
              }}
            >
              <Tooltip className="hp-tt" direction="top" opacity={1} sticky>
                <MarkerTooltip m={m} />
              </Tooltip>
            </CircleMarker>
          );
        })}
      </MapContainer>

      {/* service-type legend (collapsible, top-right) */}
      <div className="absolute right-2 top-2 z-[500] flex items-start gap-1">
        {open ? (
          <div className="max-h-[calc(100%-1rem)] w-44 overflow-y-auto rounded-lg border border-border bg-[#0d1117]/90 p-2.5 backdrop-blur">
            <div className="mb-2 flex items-center justify-between">
              <span className="text-xs font-semibold text-foreground">
                {t("map.serviceTypes")}
              </span>
              <button
                type="button"
                onClick={() => setOpen(false)}
                aria-label="collapse legend"
                className="rounded p-0.5 text-muted-foreground hover:bg-accent"
              >
                <ChevronRight className="h-4 w-4" />
              </button>
            </div>
            <div className="flex flex-col gap-1.5">
              {legend.map((svc) => (
                <div key={svc} className="flex items-center gap-2 text-[11px]">
                  <span
                    className="h-2.5 w-2.5 shrink-0 rounded-full"
                    style={{ backgroundColor: svcColor(svc) }}
                  />
                  <span className="truncate text-foreground/80">{svc}</span>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <button
            type="button"
            onClick={() => setOpen(true)}
            aria-label="show legend"
            className="rounded-lg border border-border bg-[#0d1117]/90 p-1.5 text-muted-foreground backdrop-blur hover:bg-accent"
          >
            <ChevronRight className="h-4 w-4 rotate-180" />
          </button>
        )}
      </div>
    </div>
  );
}
