"use client";

import { useLocale, useTranslations } from "next-intl";
import { RadarIcon, ExternalLink, Bug, Server } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Pager, usePaged } from "./pager";
import type { Cve } from "@/types/honeypot";

/* CVSS severity palette — reads on both light and dark grounds. */
const SEV_COLOR: Record<string, string> = {
  critical: "#f85149",
  high: "#f0883e",
  medium: "#d29922",
  low: "#58a6ff",
  unknown: "#8b949e",
};

/* Short names for the CWEs observed in the feed. */
const CWE_NAME: Record<string, string> = {
  "CWE-20": "Improper Input Validation",
  "CWE-78": "OS Command Injection",
  "CWE-200": "Information Exposure",
  "CWE-203": "Observable Discrepancy",
  "CWE-281": "Improper Preservation of Permissions",
  "CWE-287": "Improper Authentication",
  "CWE-354": "Improper Integrity-Check Validation",
  "CWE-362": "Race Condition",
  "CWE-420": "Unprotected Alternate Channel",
  "CWE-428": "Unquoted Search Path",
  "CWE-670": "Always-Incorrect Control Flow",
  "CWE-732": "Incorrect Permission Assignment",
};

function sevColor(s: string) {
  return SEV_COLOR[s] ?? SEV_COLOR.unknown;
}

function nvdUrl(cve: string) {
  return `https://nvd.nist.gov/vuln/detail/${cve}`;
}

export function TopCves({ cves }: { cves: Cve[] }) {
  const t = useTranslations("honeypot");
  const locale = useLocale();
  const nf = new Intl.NumberFormat(locale);
  const paged = usePaged(cves, 5);

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between gap-2 space-y-0">
        <CardTitle className="flex items-center gap-2 text-base">
          <Bug className="h-4 w-4 text-muted-foreground" />
          {t("sections.cves")}
        </CardTitle>
        {cves.length > 0 ? (
          <span className="font-mono text-xs text-muted-foreground">
            {t("cves.summary", { count: cves.length })}
          </span>
        ) : null}
      </CardHeader>
      <CardContent>
        {cves.length === 0 ? (
          <div className="flex items-center gap-3 rounded-lg border border-dashed border-border bg-muted/20 px-4 py-5">
            <span className="relative flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-border bg-background">
              <RadarIcon className="h-4 w-4 text-primary" />
              <span className="absolute inline-flex h-full w-full animate-ping rounded-md border border-primary/40 opacity-60" />
            </span>
            <div className="flex flex-col gap-0.5">
              <span className="text-sm text-foreground/90">{t("cves.empty")}</span>
              <span className="font-mono text-[11px] text-muted-foreground">
                {t("cves.emptyHint")}
              </span>
            </div>
          </div>
        ) : (
          <div className="flex flex-col gap-2">
            {paged.slice.map((c, i) => {
              const color = sevColor(c.severity);
              const cweName = c.cwe ? CWE_NAME[c.cwe] : undefined;
              return (
                <a
                  key={c.cve}
                  href={nvdUrl(c.cve)}
                  target="_blank"
                  rel="noopener noreferrer"
                  title={`${c.cve} — ${c.severity} ${c.score ?? ""}`}
                  className="group relative flex items-center gap-3 overflow-hidden rounded-lg border border-border bg-card/60 py-2.5 pl-2 pr-3 transition-all hover:border-transparent sm:gap-4"
                >
                  <span
                    aria-hidden
                    className="pointer-events-none absolute inset-0 rounded-lg opacity-0 transition-opacity group-hover:opacity-100"
                    style={{ boxShadow: `inset 0 0 0 1px ${color}, 0 0 22px -8px ${color}` }}
                  />
                  {/* rank */}
                  <span className="w-7 shrink-0 text-right font-mono text-sm font-bold tabular-nums text-muted-foreground">
                    {String(paged.page * 5 + i + 1).padStart(2, "0")}
                  </span>
                  {/* severity accent */}
                  <span
                    className="w-1 shrink-0 self-stretch rounded-full"
                    style={{ backgroundColor: color }}
                  />
                  {/* body */}
                  <span className="relative flex min-w-0 flex-1 flex-col gap-1">
                    <span className="flex flex-col gap-1.5 sm:flex-row sm:items-center sm:justify-between sm:gap-3">
                      <span className="flex min-w-0 flex-wrap items-center gap-2">
                        <span className="font-mono text-sm font-semibold text-foreground">
                          {c.cve}
                        </span>
                        {c.cwe ? (
                          <span className="rounded border border-border bg-muted/40 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
                            {c.cwe}
                            {cweName ? (
                              <span className="text-foreground/60">
                                {" · "}
                                {cweName}
                              </span>
                            ) : null}
                          </span>
                        ) : null}
                      </span>
                      <span className="flex shrink-0 items-center gap-3">
                        <span className="inline-flex items-center gap-1.5 font-mono text-[11px] text-muted-foreground">
                          <Server className="h-3 w-3" />
                          {t("cves.hosts", { count: nf.format(c.hosts) })}
                        </span>
                        <span
                          className="flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide"
                          style={{ color, backgroundColor: `${color}1a` }}
                        >
                          {c.severity}
                          {c.score != null ? (
                            <span className="tabular-nums opacity-90">
                              {c.score.toFixed(1)}
                            </span>
                          ) : null}
                        </span>
                        <ExternalLink className="h-3.5 w-3.5 text-muted-foreground transition-colors group-hover:text-foreground" />
                      </span>
                    </span>
                    {c.desc ? (
                      <span className="line-clamp-1 text-xs leading-snug text-muted-foreground">
                        {c.desc}
                      </span>
                    ) : null}
                  </span>
                </a>
              );
            })}
            <Pager
              page={paged.page}
              pages={paged.pages}
              setPage={paged.setPage}
            />
          </div>
        )}
      </CardContent>
    </Card>
  );
}
