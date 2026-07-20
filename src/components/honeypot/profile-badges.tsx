"use client";

import { useTranslations } from "next-intl";
import { BadgeCheck, ExternalLink } from "lucide-react";
import { HANDLE, THREAT_PLATFORMS, faviconFor } from "@/lib/threat-platforms";

export function ProfileBadges() {
  const t = useTranslations("honeypot");
  return (
    <div className="mb-4 flex flex-col gap-2">
      <span className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
        {"// "}
        {t("profiles.label")}
      </span>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
        {THREAT_PLATFORMS.map((p) => (
          <a
            key={p.name}
            href={p.profileUrl}
            target="_blank"
            rel="noopener noreferrer"
            aria-label={`${p.name} — ${HANDLE}`}
            className="group relative flex items-center gap-3 overflow-hidden rounded-lg border border-border bg-card/70 px-3 py-2.5 transition-colors hover:border-transparent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            {/* neon hover glow tinted to the platform brand */}
            <span
              aria-hidden
              className="pointer-events-none absolute inset-0 rounded-lg opacity-0 transition-opacity duration-200 group-hover:opacity-100"
              style={{
                boxShadow: `inset 0 0 0 1px ${p.color}, 0 0 24px -8px ${p.color}`,
              }}
            />
            <span
              className="relative flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-border bg-background"
              style={{ boxShadow: `0 0 0 1px ${p.color}22` }}
            >
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src={faviconFor(p.domain)}
                alt=""
                width={20}
                height={20}
                className="h-5 w-5 rounded-sm"
                loading="lazy"
              />
            </span>
            <span className="relative flex min-w-0 flex-col">
              <span className="flex items-center gap-1 text-sm font-semibold leading-tight">
                {p.name}
                <BadgeCheck
                  className="h-3.5 w-3.5 shrink-0"
                  style={{ color: p.color }}
                />
              </span>
              <span className="truncate font-mono text-[11px] text-muted-foreground">
                {HANDLE}
              </span>
            </span>
            <ExternalLink className="relative ml-auto h-3.5 w-3.5 shrink-0 text-muted-foreground transition-colors group-hover:text-foreground" />
          </a>
        ))}
      </div>
    </div>
  );
}
