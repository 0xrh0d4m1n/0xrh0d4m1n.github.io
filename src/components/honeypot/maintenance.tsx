import { getTranslations } from "next-intl/server";
import { Radar } from "lucide-react";

/**
 * Placeholder shown on /honeypot while the public dashboard is rebuilt.
 *
 * Three deliberate choices, and the first two are about honesty:
 *
 * 1. It is a SERVER component. The dashboard it replaces is a client component that
 *    fetches the stats worker and pulls in the charting libraries; none of that ships
 *    while this is up. A maintenance page that still downloads a megabyte of charting to
 *    render "we are under maintenance" is doing the opposite of what it claims.
 *
 * 2. The badge says the SENSORS ARE STILL RUNNING, because they are. A bare "under
 *    maintenance" would imply the honeypot network is down — it is not; only the
 *    presentation is paused. On a page whose whole subject is telemetry you are asked to
 *    trust, that ambiguity is the expensive kind.
 *
 * 3. Every animation is PURE CSS (see the block at the end of src/styles/globals.css).
 *    Reaching for an animation library here would spend the exact property that makes
 *    this page cheap. The theme is a radar sweep: the grid keeps scanning while the
 *    dashboard is rebuilt — the motion says the same thing the badge says.
 *
 * To revert: see src/app/[locale]/honeypot/page.tsx — it is a two-line swap.
 */
export async function HoneypotMaintenance({ locale }: { locale: string }) {
  const t = await getTranslations({ locale, namespace: "honeypot" });

  return (
    <div className="mx-auto w-[90vw] max-w-none py-6">
      <div className="relative mx-auto flex max-w-2xl flex-col items-center gap-7 overflow-hidden rounded-lg border border-border/60 bg-card/40 px-6 py-16 text-center">
        {/* Pacotes atravessando o cartão: a telemetria que continua chegando. */}
        <div aria-hidden className="pointer-events-none absolute inset-0">
          {[
            { top: "22%", delay: "0s", dur: "7s" },
            { top: "48%", delay: "2.4s", dur: "9s" },
            { top: "71%", delay: "4.1s", dur: "6.2s" },
            { top: "86%", delay: "1.2s", dur: "11s" },
          ].map((p, i) => (
            <span
              key={i}
              className="hpn-drift absolute h-px w-16 bg-gradient-to-r from-transparent via-emerald-400/50 to-transparent"
              style={{ top: p.top, animationDelay: p.delay, animationDuration: p.dur }}
            />
          ))}
        </div>

        {/* O radar. */}
        <div aria-hidden className="relative h-28 w-28 shrink-0">
          {/* anéis de eco, escalonados */}
          {["0s", "1.05s", "2.1s"].map((d) => (
            <span
              key={d}
              className="hpn-ring absolute inset-0 rounded-full border border-emerald-400/40"
              style={{ animationDelay: d }}
            />
          ))}
          {/* grade fixa */}
          <span className="absolute inset-0 rounded-full border border-border/70" />
          <span className="absolute inset-[18%] rounded-full border border-border/50" />
          <span className="absolute inset-[36%] rounded-full border border-border/40" />
          {/* a varredura */}
          <span
            className="hpn-sweep absolute inset-0 rounded-full"
            style={{
              background:
                "conic-gradient(from 0deg, transparent 0deg, transparent 300deg, color-mix(in oklab, var(--color-emerald-400, #34d399) 34%, transparent) 355deg, transparent 360deg)",
            }}
          />
          {/* o ícone, flutuando no centro */}
          <span className="hpn-float absolute inset-0 grid place-items-center">
            <Radar className="h-8 w-8 text-emerald-500/90 dark:text-emerald-400/90" />
          </span>
        </div>

        <div className="relative space-y-3">
          <h1 className="text-2xl font-semibold tracking-tight">
            {t("maintenance.title")}
          </h1>
          <p className="mx-auto max-w-prose text-sm leading-relaxed text-muted-foreground">
            {t("maintenance.body")}
          </p>
        </div>

        <p className="relative inline-flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs font-medium text-emerald-600 dark:text-emerald-400">
          <span
            aria-hidden
            className="hpn-blink h-1.5 w-1.5 rounded-full bg-emerald-500 dark:bg-emerald-400"
          />
          {t("maintenance.collecting")}
        </p>
      </div>
    </div>
  );
}
