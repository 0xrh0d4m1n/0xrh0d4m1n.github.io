"use client";

import { useLocale, useTranslations } from "next-intl";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface Technique {
  id: string;
  name: string;
}
interface Tactic {
  name: string;
  techniques: Technique[];
}

/**
 * Reference subset of the ATT&CK Enterprise matrix relevant to honeypot
 * activity. Columns are tactics; cells are techniques. A cell lights up when
 * the technique id appears in the observed `mitre` map (with its event count).
 */
const TACTICS: Tactic[] = [
  {
    name: "Reconnaissance",
    techniques: [
      { id: "T1595", name: "Active Scanning" },
      { id: "T1590", name: "Gather Victim Network Info" },
    ],
  },
  {
    name: "Initial Access",
    techniques: [
      { id: "T1190", name: "Exploit Public-Facing App" },
      { id: "T1133", name: "External Remote Services" },
      { id: "T1078", name: "Valid Accounts" },
    ],
  },
  {
    name: "Execution",
    techniques: [{ id: "T1059", name: "Command & Scripting Interpreter" }],
  },
  {
    name: "Credential Access",
    techniques: [
      { id: "T1110", name: "Brute Force" },
      { id: "T1110.001", name: "Password Guessing" },
      { id: "T1110.003", name: "Password Spraying" },
    ],
  },
  {
    name: "Discovery",
    techniques: [{ id: "T1046", name: "Network Service Discovery" }],
  },
  {
    name: "Lateral Movement",
    techniques: [
      { id: "T1021.001", name: "Remote Services: RDP" },
      { id: "T1021.004", name: "Remote Services: SSH" },
      { id: "T1021.005", name: "Remote Services: VNC" },
    ],
  },
  {
    name: "Command & Control",
    techniques: [{ id: "T1090", name: "Proxy" }],
  },
];

function attackUrl(id: string) {
  return `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
}

export function MitreMatrix({ mitre }: { mitre: Record<string, number> }) {
  const t = useTranslations("honeypot");
  const locale = useLocale();
  const nf = new Intl.NumberFormat(locale);

  const detectedIds = new Set(Object.keys(mitre).filter((k) => mitre[k] > 0));
  const detectedTactics = TACTICS.filter((tac) =>
    tac.techniques.some((tech) => detectedIds.has(tech.id)),
  ).length;

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between gap-2 space-y-0">
        <CardTitle className="text-base">{t("sections.mitre")}</CardTitle>
        <span className="font-mono text-xs text-muted-foreground">
          {t("mitre.summary", {
            techniques: detectedIds.size,
            tactics: detectedTactics,
          })}
        </span>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto pb-1">
          <div className="flex gap-2">
            {TACTICS.map((tac) => {
              const hits = tac.techniques.filter((te) =>
                detectedIds.has(te.id),
              ).length;
              return (
                <div key={tac.name} className="flex min-w-40 flex-1 flex-col gap-1.5">
                  <div className="flex items-center justify-between gap-1 border-b border-border pb-1.5">
                    <span className="text-[11px] font-semibold uppercase leading-tight tracking-wide text-foreground/80">
                      {tac.name}
                    </span>
                    {hits > 0 ? (
                      <span className="shrink-0 rounded-sm bg-primary/15 px-1 font-mono text-[10px] font-semibold text-primary">
                        {hits}
                      </span>
                    ) : null}
                  </div>

                  {tac.techniques.map((tech) => {
                    const count = mitre[tech.id] ?? 0;
                    const detected = count > 0;
                    return (
                      <a
                        key={tech.id}
                        href={attackUrl(tech.id)}
                        target="_blank"
                        rel="noopener noreferrer"
                        title={`${tech.id} · ${tech.name}`}
                        className={
                          detected
                            ? "group relative flex flex-col gap-1 rounded-md border border-primary/40 bg-primary/10 p-2 transition-all hover:border-primary hover:shadow-[0_0_18px_-6px_var(--primary)]"
                            : "flex flex-col gap-1 rounded-md border border-border bg-card/40 p-2 opacity-55 transition-opacity hover:opacity-90"
                        }
                      >
                        <div className="flex items-center justify-between gap-1">
                          <span
                            className={
                              detected
                                ? "font-mono text-[11px] font-semibold text-primary"
                                : "font-mono text-[11px] text-muted-foreground"
                            }
                          >
                            {tech.id}
                          </span>
                          {detected ? (
                            <span className="rounded-sm bg-primary px-1 font-mono text-[10px] font-bold tabular-nums text-primary-foreground">
                              {nf.format(count)}
                            </span>
                          ) : null}
                        </div>
                        <span
                          className={
                            detected
                              ? "text-[11px] leading-tight text-foreground/90"
                              : "text-[11px] leading-tight text-muted-foreground"
                          }
                        >
                          {tech.name}
                        </span>
                      </a>
                    );
                  })}
                </div>
              );
            })}
          </div>
        </div>

        {/* legend */}
        <div className="mt-3 flex items-center gap-4 text-[11px] text-muted-foreground">
          <span className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-sm border border-primary/40 bg-primary/20" />
            {t("mitre.legendDetected")}
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-sm border border-border bg-card/40 opacity-55" />
            {t("mitre.legendRef")}
          </span>
        </div>
      </CardContent>
    </Card>
  );
}
