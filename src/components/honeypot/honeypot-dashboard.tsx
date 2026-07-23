"use client";

import { useEffect, useState, type ReactNode } from "react";
import dynamic from "next/dynamic";
import { useLocale, useTranslations } from "next-intl";
import {
  Activity,
  Globe2,
  Network,
  ShieldAlert,
  Users,
  RadioTower,
  KeyRound,
  User,
  TriangleAlert,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  PolarAngleAxis,
  PolarGrid,
  Radar,
  RadarChart,
  ResponsiveContainer,
  Tooltip as RTooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { usePaged, Pager } from "./pager";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { flagUrl } from "@/lib/country-flags";
import { cn } from "@/lib/utils";
import { THREAT_PLATFORMS, faviconFor } from "@/lib/threat-platforms";
import { ProfileBadges } from "@/components/honeypot/profile-badges";
import { MitreMatrix } from "@/components/honeypot/mitre-matrix";
import { TopCves } from "@/components/honeypot/top-cves";
import { MalwareIntel } from "@/components/honeypot/malware-intel";
import type {
  ActivityPoint,
  Count,
  HoneypotStats,
  TopIp,
  Win,
  WindowSlice,
} from "@/types/honeypot";

const STATS_URL =
  process.env.NEXT_PUBLIC_HONEYPOT_STATS_URL ?? "/data/honeypot-stats.json";

/* Leaflet touches `window`, so the map is client-only (never SSR/prerendered). */
const AttackMap = dynamic(() => import("./attack-map"), {
  ssr: false,
  loading: () => <Skeleton className="h-[560px] w-full rounded-xl" />,
});

/* Actor colors — GitHub-ish palette that reads on both light and dark. */
/* Actor palette follows a TLP-ish scheme:
 * malicious=red · suspicious=yellow · cloud/research (not malicious)=green ·
 * anonymity (tor/anonymizer)=purple · unknown=gray. */
const ACTOR_COLOR: Record<string, string> = {
  malicious: "#f85149",
  suspicious: "#d29922",
  cloud: "#3fb950",
  research: "#3fb950",
  tor: "#bc8cff",
  anonymizer: "#bc8cff",
  unknown: "#8b949e",
};

const SERVICE_COLOR: Record<string, string> = {
  ssh: "#9fef00",
  telnet: "#58a6ff",
  rdp: "#bc8cff",
  http: "#f0883e",
  https: "#f0883e",
  mysql: "#3fb950",
  mssql: "#3fb950",
  vnc: "#db61a2",
  redis: "#f85149",
  sip: "#a5d6ff",
  ftp: "#d29922",
};

function actorColor(a: string) {
  return ACTOR_COLOR[a] ?? ACTOR_COLOR.unknown;
}
function serviceColor(s: string) {
  return SERVICE_COLOR[s] ?? "#8b949e";
}

/* ── small presentational helpers ─────────────────────────────────── */

function Flag({ name }: { name: string }) {
  const url = flagUrl(name);
  if (!url) {
    return <Globe2 className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />;
  }
  return (
    // eslint-disable-next-line @next/next/no-img-element
    <img
      src={url}
      alt=""
      width={20}
      height={15}
      className="h-[15px] w-5 shrink-0 rounded-[2px] object-cover"
      loading="lazy"
    />
  );
}

function ActorChip({ actor }: { actor: string }) {
  const color = actorColor(actor);
  return (
    <span className="inline-flex items-center gap-1.5 text-xs">
      <span
        className="h-2 w-2 rounded-full"
        style={{ backgroundColor: color }}
      />
      <span className="capitalize text-foreground/80">{actor}</span>
    </span>
  );
}

/* ── DS Fusion Engine confidence meter ────────────────────────────── */
/* Color-graded belief bar — hue = TLP verdict, length = fused confidence.
 * The public label is "DS Fusion Engine"; the method stays unnamed. */
function DsMeter({
  confidence,
  verdict,
}: {
  confidence: number;
  verdict: string;
}) {
  const color = actorColor(verdict);
  const pct = Math.max(2, Math.min(100, confidence));
  return (
    <div className="flex items-center gap-2" title={`${verdict} · confidence ${confidence}`}>
      <div className="relative h-2 w-20 shrink-0 overflow-hidden rounded-full bg-muted">
        {/* faint full-width graticule so the scale reads even at low values */}
        <div
          className="absolute inset-0 opacity-[0.12]"
          style={{
            background: `repeating-linear-gradient(90deg, ${color} 0 1px, transparent 1px 25%)`,
          }}
        />
        <div
          className="relative h-full rounded-full"
          style={{
            width: `${pct}%`,
            background: `linear-gradient(90deg, ${color}66, ${color})`,
            boxShadow: `0 0 8px -2px ${color}`,
          }}
        />
      </div>
      <span
        className="font-mono text-xs font-semibold tabular-nums"
        style={{ color }}
      >
        {confidence}
      </span>
    </div>
  );
}

/* ── KPI card ──────────────────────────────────────────────────────── */

function StatCard({
  icon,
  label,
  value,
  hint,
  accent,
}: {
  icon: ReactNode;
  label: string;
  value: string;
  hint?: string;
  accent?: boolean;
}) {
  return (
    <Card className="gap-0 p-0">
      <CardContent className="flex flex-col gap-0.5 px-3.5 py-2.5">
        <div className="flex items-center gap-1.5 text-muted-foreground">
          {icon}
          <span className="text-[11px] font-medium uppercase tracking-wide">
            {label}
          </span>
        </div>
        <div
          className={cn(
            "font-heading text-2xl font-bold leading-tight tabular-nums sm:text-3xl",
            accent && "text-primary",
          )}
        >
          {value}
        </div>
        {hint ? (
          <div className="text-[11px] leading-tight text-muted-foreground">{hint}</div>
        ) : null}
      </CardContent>
    </Card>
  );
}

/* ── ranked horizontal bar list (countries / services / asns) ─────── */

function BarList({
  items,
  renderLabel,
  colorFor,
}: {
  items: Count[];
  renderLabel: (item: Count) => ReactNode;
  colorFor?: (item: Count) => string;
}) {
  const max = Math.max(1, ...items.map((i) => i.count));
  const nf = new Intl.NumberFormat();
  return (
    <div className="flex flex-col gap-2.5">
      {items.map((item) => {
        const pct = Math.max(2, Math.round((item.count / max) * 100));
        const color = colorFor?.(item) ?? "var(--primary)";
        return (
          <div key={item.key} className="flex flex-col gap-1">
            <div className="flex items-center justify-between gap-3 text-sm">
              <div className="flex min-w-0 items-center gap-2 truncate">
                {renderLabel(item)}
              </div>
              <span className="shrink-0 font-mono text-xs tabular-nums text-muted-foreground">
                {nf.format(item.count)}
              </span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
              <div
                className="h-full rounded-full transition-all"
                style={{ width: `${pct}%`, backgroundColor: color }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* ── credential chips ─────────────────────────────────────────────── */

function CredList({ items }: { items: Count[] }) {
  const nf = new Intl.NumberFormat();
  return (
    <div className="flex flex-wrap gap-2">
      {items.map((c, i) => (
        <span
          key={c.key}
          className="inline-flex items-center gap-2 rounded-md border border-border bg-muted/30 px-2 py-1"
        >
          <span className="font-mono text-xs text-muted-foreground">
            {String(i + 1).padStart(2, "0")}
          </span>
          <span className="font-mono text-sm text-foreground">{c.key}</span>
          <span className="font-mono text-xs tabular-nums text-primary">
            {nf.format(c.count)}
          </span>
        </span>
      ))}
    </div>
  );
}

/* ── per-IP report links (VirusTotal / AbuseIPDB / OTX) ───────────── */

function IpReports({ ip }: { ip: string }) {
  return (
    <div className="flex items-center justify-center gap-1">
      {THREAT_PLATFORMS.map((p) => (
        <a
          key={p.name}
          href={p.ipUrl(ip)}
          target="_blank"
          rel="noopener noreferrer"
          title={`${ip} · ${p.name}`}
          aria-label={`${ip} on ${p.name}`}
          className="flex h-6 w-6 items-center justify-center rounded-md border border-border bg-background/60 transition-colors hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img
            src={faviconFor(p.domain)}
            alt=""
            width={14}
            height={14}
            className="h-3.5 w-3.5 rounded-[2px]"
            loading="lazy"
          />
        </a>
      ))}
    </div>
  );
}

/* ── T-Pot-style heat stripe — a heat-encoded view of the SAME series the
 * Attack Volume chart plots for the selected window, so it reads as part of it.
 * Granularity follows the window: 1h → 60×1min, 12h → 12×1h, 24h → 24×1h. ─── */

const HEAT_UNIT: Record<Win, string> = { h1: "1 min", h12: "1 h", h24: "1 h" };

function HeatStripe({
  cells,
  win,
  title,
  nf,
}: {
  cells?: ActivityPoint[];
  win: Win;
  title: string;
  nf: Intl.NumberFormat;
}) {
  if (!cells?.length) return null;
  const max = Math.max(1, ...cells.map((c) => c.count));
  const peak = cells.reduce((a, c) => (c.count > a.count ? c : a), cells[0]);

  return (
    <div className="mt-4">
      <div className="mb-1.5 flex items-center justify-between text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
        <span>
          {title}
          <span className="ml-1.5 font-mono normal-case text-foreground/45">
            {cells.length} × {HEAT_UNIT[win]}
          </span>
        </span>
        <span className="flex items-center gap-1.5">
          low
          <span className="h-2 w-16 rounded-full bg-gradient-to-r from-muted to-primary" />
          high
        </span>
      </div>
      <div className="flex gap-[3px]">
        {cells.map((c) => {
          const v = c.count / max;
          return (
            <div
              key={c.t}
              title={`${c.t} — ${nf.format(c.count)} events · ${Math.round(v * 100)}% of peak`}
              className="h-7 flex-1 overflow-hidden rounded-[3px] bg-muted transition-transform hover:scale-y-125"
            >
              <div
                className="h-full w-full bg-primary"
                style={{ opacity: 0.08 + v * 0.92 }}
              />
            </div>
          );
        })}
      </div>
      <div className="mt-1 flex justify-between font-mono text-[10px] text-muted-foreground/55">
        <span>{cells[0]?.t}</span>
        <span className="text-primary/70">
          peak {peak.t} · {nf.format(peak.count)}
        </span>
        <span>{cells[cells.length - 1]?.t}</span>
      </div>
    </div>
  );
}

/* ── global activity window selector (1h / 12h / 24h) ─────────────── */
/* Lives in the header (top-right); every volume-based section reads the
 * matching per-window slice, so the whole page reacts to it at once. */

function WindowSelector({
  win,
  setWin,
  labels,
}: {
  win: Win;
  setWin: (w: Win) => void;
  labels: Record<Win, string>;
}) {
  return (
    <div className="inline-flex rounded-lg border border-border bg-muted/30 p-0.5">
      {(["h1", "h12", "h24"] as Win[]).map((k) => (
        <button
          key={k}
          type="button"
          onClick={() => setWin(k)}
          aria-pressed={win === k}
          className={cn(
            "rounded-md px-3 py-1 font-mono text-xs font-medium transition-colors",
            win === k
              ? "bg-primary/15 text-primary shadow-sm"
              : "text-muted-foreground hover:text-foreground",
          )}
        >
          {labels[k]}
        </button>
      ))}
    </div>
  );
}

/* ── loading skeleton ─────────────────────────────────────────────── */

function DashboardSkeleton() {
  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-24 w-full" />
        ))}
      </div>
      <Skeleton className="h-64 w-full" />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Skeleton className="h-72 w-full" />
        <Skeleton className="h-72 w-full" />
      </div>
    </div>
  );
}

/* ── main ─────────────────────────────────────────────────────────── */

export function HoneypotDashboard() {
  const t = useTranslations("honeypot");
  const locale = useLocale();
  const [data, setData] = useState<HoneypotStats | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [win, setWin] = useState<Win>("h1");
  /* Volume-based sections read this per-window slice; when a snapshot predates
   * the windows field, fall back to the root document. Cast away null: it is
   * only ever read in the data-present render branch (and the hook guards it). */
  const w = (data?.windows?.[win] ?? data) as WindowSlice & HoneypotStats;
  const topIps = usePaged(w?.top_ips ?? [], 8);

  useEffect(() => {
    let alive = true;
    fetch(STATS_URL, { cache: "no-store" })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json() as Promise<HoneypotStats>;
      })
      .then((d) => alive && setData(d))
      .catch((e) => alive && setError(e instanceof Error ? e.message : String(e)));
    return () => {
      alive = false;
    };
  }, []);

  const nf = new Intl.NumberFormat(locale);

  return (
    <div className="mx-auto w-[90vw] max-w-none py-6">
      {/* ── hero ─────────────────────────────────────────────────── */}
      <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-2">
            <RadioTower className="h-5 w-5 text-primary" />
            <h1 className="font-heading text-2xl font-bold tracking-tight sm:text-3xl">
              {t("title")}
            </h1>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-primary/30 bg-primary/10 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-primary">
              <span className="relative flex h-1.5 w-1.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary opacity-75" />
                <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-primary" />
              </span>
              {t("live")}
            </span>
          </div>
          <p className="max-w-prose text-sm text-muted-foreground">
            {t("subtitle")}
          </p>
        </div>
        {data ? (
          <div className="flex shrink-0 flex-col items-start gap-2 sm:items-end">
            <div className="flex items-center gap-3">
              <ProfileBadges compact />
              <WindowSelector
                win={win}
                setWin={setWin}
                labels={{
                  h1: t("window.h1"),
                  h12: t("window.h12"),
                  h24: t("window.h24"),
                }}
              />
            </div>
            <div className="font-mono text-xs text-muted-foreground">
              {t("updated", { time: data.generated_at })}
            </div>
          </div>
        ) : null}
      </div>

      {error ? (
        <Card className="border-destructive/40">
          <CardContent className="flex items-center gap-3 py-6 text-sm text-muted-foreground">
            <TriangleAlert className="h-5 w-5 text-destructive" />
            <span>{t("error", { message: error })}</span>
          </CardContent>
        </Card>
      ) : !data ? (
        <DashboardSkeleton />
      ) : (
        <div className="flex flex-col gap-4">
          {/* ── KPI row ──────────────────────────────────────────── */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
            <StatCard
              icon={<Activity className="h-4 w-4" />}
              label={t("kpi.events")}
              value={nf.format(w.totals.events)}
              accent
            />
            <StatCard
              icon={<Users className="h-4 w-4" />}
              label={t("kpi.attackers")}
              value={nf.format(w.totals.unique_ips)}
            />
            <StatCard
              icon={<Globe2 className="h-4 w-4" />}
              label={t("kpi.countries")}
              value={nf.format(w.totals.countries)}
            />
            <StatCard
              icon={<Network className="h-4 w-4" />}
              label={t("kpi.asns")}
              value={nf.format(w.totals.asns)}
            />
            <StatCard
              icon={<ShieldAlert className="h-4 w-4" />}
              label={t("kpi.malicious")}
              value={`${w.totals.malicious_pct}%`}
              hint={t("kpi.maliciousHint")}
            />
          </div>

          {/* ── attack-origin map (hero) ─────────────────────────── */}
          <Card className="gap-0 overflow-hidden p-0">
            <CardHeader className="flex-row items-center justify-between gap-2 space-y-0 px-4 py-3">
              <CardTitle className="flex items-center gap-2 text-base">
                <Globe2 className="h-4 w-4 text-primary" />
                {t("sections.map")}
              </CardTitle>
              <span className="font-mono text-xs text-muted-foreground">
                {t("map.summary", {
                  markers: (data.map?.markers?.[win] ?? []).length,
                })}
              </span>
            </CardHeader>
            <CardContent className="p-0">
              <AttackMap markers={data.map?.markers?.[win] ?? []} height={580} />
            </CardContent>
          </Card>

          {/* ── attack-volume stripe ─────────────────────────────── */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">
                {t("sections.timeline")}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="h-24 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart
                    data={
                      data.activity?.[win] ??
                      data.timeline.map((p) => ({ t: p.date, count: p.count }))
                    }
                    margin={{ top: 4, right: 8, left: -16, bottom: 0 }}
                  >
                    <defs>
                      <linearGradient id="hpFill" x1="0" y1="0" x2="0" y2="1">
                        <stop
                          offset="5%"
                          stopColor="var(--primary)"
                          stopOpacity={0.45}
                        />
                        <stop
                          offset="95%"
                          stopColor="var(--primary)"
                          stopOpacity={0}
                        />
                      </linearGradient>
                    </defs>
                    <CartesianGrid
                      strokeDasharray="3 3"
                      stroke="var(--border)"
                      vertical={false}
                    />
                    <XAxis
                      dataKey="t"
                      tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
                      tickLine={false}
                      axisLine={{ stroke: "var(--border)" }}
                      minTickGap={24}
                      tickFormatter={(d: string) =>
                        String(d).includes(" ") ? String(d).split(" ")[1] : String(d)
                      }
                    />
                    <YAxis
                      tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
                      tickLine={false}
                      axisLine={false}
                      width={44}
                      tickFormatter={(v: number) =>
                        v >= 1000 ? `${Math.round(v / 1000)}k` : `${v}`
                      }
                    />
                    <RTooltip
                      cursor={{ stroke: "var(--primary)", strokeOpacity: 0.3 }}
                      contentStyle={{
                        background: "var(--popover)",
                        border: "1px solid var(--border)",
                        borderRadius: 8,
                        fontSize: 12,
                      }}
                      labelStyle={{ color: "var(--foreground)" }}
                      itemStyle={{ color: "var(--primary)" }}
                      formatter={(v: number) => [nf.format(v), t("events")]}
                    />
                    <Area
                      type="monotone"
                      dataKey="count"
                      stroke="var(--primary)"
                      strokeWidth={2}
                      fill="url(#hpFill)"
                      dot={{ r: 3, fill: "var(--primary)", strokeWidth: 0 }}
                      activeDot={{ r: 5 }}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
              <HeatStripe
                cells={data.activity?.[win]}
                win={win}
                title={t("sections.heatmap")}
                nf={nf}
              />
            </CardContent>
          </Card>

          {/* ── top attacking IPs ────────────────────────────────── */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">
                {t("sections.topIps")}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-8 text-right">#</TableHead>
                      <TableHead>{t("table.ip")}</TableHead>
                      <TableHead>{t("table.ds")}</TableHead>
                      <TableHead>{t("table.actor")}</TableHead>
                      <TableHead>{t("table.country")}</TableHead>
                      <TableHead>{t("table.asn")}</TableHead>
                      <TableHead>{t("table.service")}</TableHead>
                      <TableHead className="text-right">
                        {t("table.events")}
                      </TableHead>
                      <TableHead className="text-center">
                        {t("table.reports")}
                      </TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {topIps.slice.map((ip: TopIp, i) => (
                      <TableRow key={ip.ip}>
                        <TableCell className="text-right font-mono text-xs text-muted-foreground">
                          {topIps.page * 8 + i + 1}
                        </TableCell>
                        <TableCell className="font-mono text-sm">
                          {ip.ip}
                        </TableCell>
                        <TableCell>
                          <DsMeter
                            confidence={ip.confidence ?? ip.score}
                            verdict={ip.verdict ?? ip.actor}
                          />
                        </TableCell>
                        <TableCell>
                          <ActorChip actor={ip.actor} />
                        </TableCell>
                        <TableCell>
                          <span className="flex items-center gap-2 text-sm">
                            <Flag name={ip.cc ?? ip.country} />
                            <span className="truncate text-foreground/80">
                              {ip.country}
                            </span>
                          </span>
                        </TableCell>
                        <TableCell>
                          <span
                            className="block max-w-[190px] truncate text-xs text-foreground/70"
                            title={ip.asn}
                          >
                            {ip.asn ?? "—"}
                          </span>
                        </TableCell>
                        <TableCell>
                          <span
                            className="font-mono text-xs"
                            style={{ color: serviceColor(ip.service) }}
                          >
                            {ip.service}
                          </span>
                        </TableCell>
                        <TableCell className="text-right font-mono text-sm tabular-nums">
                          {nf.format(ip.events)}
                        </TableCell>
                        <TableCell>
                          <IpReports ip={ip.ip} />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              <Pager page={topIps.page} pages={topIps.pages} setPage={topIps.setPage} />
            </CardContent>
          </Card>

          {/* ── countries / services ─────────────────────────────── */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">
                  {t("sections.countries")}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <BarList
                  items={w.top_countries}
                  renderLabel={(item) => (
                    <>
                      <Flag name={item.key} />
                      <span className="truncate text-foreground/90">
                        {item.key}
                      </span>
                    </>
                  )}
                />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">
                  {t("sections.services")}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <BarList
                  items={w.services}
                  colorFor={(item) => serviceColor(item.key)}
                  renderLabel={(item) => (
                    <span
                      className="font-mono text-sm"
                      style={{ color: serviceColor(item.key) }}
                    >
                      {item.key}
                    </span>
                  )}
                />
              </CardContent>
            </Card>
          </div>

          {/* ── honeypot performance (radar) ─────────────────────── */}
          {w.honeypots?.length ? (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">
                  {t("sections.honeypots")}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 items-center gap-8 lg:grid-cols-2">
                  <div className="h-80 w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <RadarChart
                        data={w.honeypots.slice(0, 8)}
                        outerRadius="95%"
                        margin={{ top: 8, right: 44, bottom: 8, left: 44 }}
                      >
                      <PolarGrid
                        stroke="var(--muted-foreground)"
                        strokeOpacity={0.4}
                      />
                      <PolarAngleAxis
                        dataKey="name"
                        tick={{
                          fill: "var(--foreground)",
                          fontSize: 11,
                          fontWeight: 500,
                        }}
                      />
                      <Radar
                        dataKey="count"
                        stroke="var(--primary)"
                        fill="var(--primary)"
                        fillOpacity={0.35}
                        strokeWidth={2}
                      />
                      <RTooltip
                        contentStyle={{
                          background: "var(--popover)",
                          border: "1px solid var(--border)",
                          borderRadius: 8,
                          fontSize: 12,
                        }}
                        labelStyle={{ color: "var(--foreground)" }}
                        formatter={(v: number) => [nf.format(v), t("events")]}
                      />
                      </RadarChart>
                    </ResponsiveContainer>
                  </div>
                  <BarList
                    items={w.honeypots.map((h) => ({
                      key: h.name,
                      count: h.count,
                    }))}
                    renderLabel={(item) => (
                      <span className="truncate font-mono text-sm text-foreground/90">
                        {item.key}
                      </span>
                    )}
                  />
                </div>
              </CardContent>
            </Card>
          ) : null}

          {/* ── actors donut / ASNs ──────────────────────────────── */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">
                  {t("sections.actors")}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-col items-center gap-6 sm:flex-row">
                  <div className="h-48 w-48 shrink-0">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={w.actors}
                          dataKey="count"
                          nameKey="key"
                          innerRadius={54}
                          outerRadius={84}
                          paddingAngle={2}
                          strokeWidth={0}
                        >
                          {w.actors.map((a) => (
                            <Cell key={a.key} fill={actorColor(a.key)} />
                          ))}
                        </Pie>
                        <RTooltip
                          contentStyle={{
                            background: "var(--popover)",
                            border: "1px solid var(--border)",
                            borderRadius: 8,
                            fontSize: 12,
                          }}
                          labelStyle={{ color: "var(--foreground)" }}
                          formatter={(v: number, n: string) => [
                            nf.format(v),
                            n,
                          ]}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="flex w-full flex-1 flex-col gap-3.5">
                    {w.actors.map((a) => {
                      const total =
                        w.actors.reduce((s, x) => s + x.count, 0) || 1;
                      const pct = (a.count / total) * 100;
                      return (
                        <div key={a.key} className="flex flex-col gap-1.5">
                          <div className="flex items-center justify-between gap-2 text-sm">
                            <span className="flex items-center gap-2">
                              <span
                                className="h-2.5 w-2.5 rounded-sm"
                                style={{ backgroundColor: actorColor(a.key) }}
                              />
                              <span className="capitalize text-foreground/90">
                                {a.key}
                              </span>
                            </span>
                            <span className="font-mono text-xs tabular-nums text-muted-foreground">
                              {nf.format(a.count)}
                              <span className="text-foreground/60">
                                {" · "}
                                {pct.toFixed(1)}%
                              </span>
                            </span>
                          </div>
                          <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
                            <div
                              className="h-full rounded-full transition-all"
                              style={{
                                width: `${Math.max(2, pct)}%`,
                                backgroundColor: actorColor(a.key),
                              }}
                            />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">
                  {t("sections.asns")}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <BarList
                  items={w.top_asns.slice(0, 8)}
                  renderLabel={(item) => (
                    <span className="truncate text-foreground/90">
                      {item.key}
                    </span>
                  )}
                />
              </CardContent>
            </Card>
          </div>

          {/* ── MITRE ATT&CK matrix ──────────────────────────────── */}
          <MitreMatrix mitre={w.mitre} />

          {/* ── top CVE exploit probes ───────────────────────────── */}
          <TopCves cves={data.top_cves} />

          {/* ── malware & session intelligence (Cowrie) ──────────── */}
          <MalwareIntel data={data.malware} />

          {/* ── credentials ──────────────────────────────────────── */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <User className="h-4 w-4 text-muted-foreground" />
                  {t("sections.usernames")}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <CredList items={w.top_usernames} />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <KeyRound className="h-4 w-4 text-muted-foreground" />
                  {t("sections.passwords")}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <CredList items={w.top_passwords} />
              </CardContent>
            </Card>
          </div>

          {/* ── footnote ─────────────────────────────────────────── */}
          <p className="text-center text-xs text-muted-foreground">
            {t("footnote")}
          </p>
        </div>
      )}
    </div>
  );
}
