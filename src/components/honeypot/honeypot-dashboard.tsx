"use client";

import { useEffect, useState, type ReactNode } from "react";
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
  ResponsiveContainer,
  Tooltip as RTooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
import type { Count, HoneypotStats, TopIp } from "@/types/honeypot";

const STATS_URL =
  process.env.NEXT_PUBLIC_HONEYPOT_STATS_URL ?? "/data/honeypot-stats.json";

/* Actor colors — GitHub-ish palette that reads on both light and dark. */
const ACTOR_COLOR: Record<string, string> = {
  malicious: "#f85149",
  tor: "#bc8cff",
  research: "#3fb950",
  cloud: "#58a6ff",
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

function ScoreBadge({ score }: { score: number }) {
  const tone =
    score >= 75
      ? "border-[#f85149]/40 bg-[#f85149]/10 text-[#f85149]"
      : score >= 40
        ? "border-[#d29922]/40 bg-[#d29922]/10 text-[#d29922]"
        : "border-border bg-muted/40 text-muted-foreground";
  return (
    <span
      className={cn(
        "inline-flex min-w-9 justify-center rounded-md border px-1.5 py-0.5 font-mono text-xs font-semibold tabular-nums",
        tone,
      )}
    >
      {score}
    </span>
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
      <CardContent className="flex flex-col gap-1 p-4">
        <div className="flex items-center gap-2 text-muted-foreground">
          {icon}
          <span className="text-xs font-medium uppercase tracking-wide">
            {label}
          </span>
        </div>
        <div
          className={cn(
            "font-heading text-2xl font-bold tabular-nums sm:text-3xl",
            accent && "text-primary",
          )}
        >
          {value}
        </div>
        {hint ? (
          <div className="text-xs text-muted-foreground">{hint}</div>
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
          <div className="shrink-0 font-mono text-xs text-muted-foreground">
            <div>{t("windowLabel", { days: data.window_days })}</div>
            <div>{t("updated", { time: data.generated_at })}</div>
          </div>
        ) : null}
      </div>

      {/* ── profile badges (stacked above the metrics) ───────────── */}
      <ProfileBadges />

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
              value={nf.format(data.totals.events)}
              accent
            />
            <StatCard
              icon={<Users className="h-4 w-4" />}
              label={t("kpi.attackers")}
              value={nf.format(data.totals.unique_ips)}
            />
            <StatCard
              icon={<Globe2 className="h-4 w-4" />}
              label={t("kpi.countries")}
              value={nf.format(data.totals.countries)}
            />
            <StatCard
              icon={<Network className="h-4 w-4" />}
              label={t("kpi.asns")}
              value={nf.format(data.totals.asns)}
            />
            <StatCard
              icon={<ShieldAlert className="h-4 w-4" />}
              label={t("kpi.malicious")}
              value={`${data.totals.malicious_pct}%`}
              hint={t("kpi.maliciousHint")}
            />
          </div>

          {/* ── timeline ─────────────────────────────────────────── */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">
                {t("sections.timeline")}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="h-56 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart
                    data={data.timeline}
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
                      dataKey="date"
                      tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
                      tickLine={false}
                      axisLine={{ stroke: "var(--border)" }}
                      tickFormatter={(d: string) => d.slice(5)}
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
                      <TableHead className="text-center">
                        {t("table.score")}
                      </TableHead>
                      <TableHead>{t("table.actor")}</TableHead>
                      <TableHead>{t("table.country")}</TableHead>
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
                    {data.top_ips.map((ip: TopIp, i) => (
                      <TableRow key={ip.ip}>
                        <TableCell className="text-right font-mono text-xs text-muted-foreground">
                          {i + 1}
                        </TableCell>
                        <TableCell className="font-mono text-sm">
                          {ip.ip}
                        </TableCell>
                        <TableCell className="text-center">
                          <ScoreBadge score={ip.score} />
                        </TableCell>
                        <TableCell>
                          <ActorChip actor={ip.actor} />
                        </TableCell>
                        <TableCell>
                          <span className="flex items-center gap-2 text-sm">
                            <Flag name={ip.country} />
                            <span className="truncate text-foreground/80">
                              {ip.country}
                            </span>
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
                  items={data.top_countries}
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
                  items={data.services}
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
                          data={data.actors}
                          dataKey="count"
                          nameKey="key"
                          innerRadius={54}
                          outerRadius={84}
                          paddingAngle={2}
                          strokeWidth={0}
                        >
                          {data.actors.map((a) => (
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
                    {data.actors.map((a) => {
                      const total =
                        data.actors.reduce((s, x) => s + x.count, 0) || 1;
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
                  items={data.top_asns.slice(0, 8)}
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
          <MitreMatrix mitre={data.mitre} />

          {/* ── top CVE exploit probes ───────────────────────────── */}
          <TopCves cves={data.top_cves} />

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
                <CredList items={data.top_usernames} />
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
                <CredList items={data.top_passwords} />
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
