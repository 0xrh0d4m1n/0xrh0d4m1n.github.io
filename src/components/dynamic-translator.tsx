"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";
import { Loader2 } from "lucide-react";
import { useTranslations } from "next-intl";
import { routing } from "@/i18n/routing";
import { translateMany } from "@/lib/translation-api";
import { getCached, setCached } from "@/lib/translation-cache";

interface Props {
  children: ReactNode;
  enabled: boolean;
  targetLocale: string;
  contentKey: string;
}

const SKIP_TAGS = new Set([
  "PRE",
  "CODE",
  "SCRIPT",
  "STYLE",
  "FIGCAPTION",
  "NOSCRIPT",
  "KBD",
  "SAMP",
  "VAR",
]);

const LOCALE_DISPLAY: Record<string, string> = {
  "pt-br": "PT-BR",
  es: "ES",
  en: "EN",
};

function collectTextNodes(root: Element): Text[] {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      const parent = node.parentElement;
      if (!parent) return NodeFilter.FILTER_REJECT;
      if (SKIP_TAGS.has(parent.tagName)) return NodeFilter.FILTER_REJECT;
      if (parent.closest("[data-notranslate]")) return NodeFilter.FILTER_REJECT;
      if (parent.closest("pre, code, kbd, samp")) return NodeFilter.FILTER_REJECT;
      const text = node.nodeValue?.trim() ?? "";
      if (text.length < 2) return NodeFilter.FILTER_REJECT;
      return NodeFilter.FILTER_ACCEPT;
    },
  });
  const nodes: Text[] = [];
  let n: Node | null;
  while ((n = walker.nextNode())) nodes.push(n as Text);
  return nodes;
}

export function DynamicTranslator({
  children,
  enabled,
  targetLocale,
  contentKey,
}: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [status, setStatus] = useState<"idle" | "running" | "done" | "error">(
    "idle",
  );
  const [progress, setProgress] = useState<{ done: number; total: number }>({
    done: 0,
    total: 0,
  });
  const t = useTranslations("translator");
  const localeLabel = LOCALE_DISPLAY[targetLocale] ?? targetLocale.toUpperCase();

  useEffect(() => {
    if (!enabled) {
      setStatus("idle");
      return;
    }
    const root = containerRef.current;
    if (!root) return;

    const controller = new AbortController();
    let cancelled = false;
    setStatus("running");
    setProgress({ done: 0, total: 0 });

    (async () => {
      try {
        const nodes = collectTextNodes(root);
        if (nodes.length === 0) {
          setStatus("done");
          return;
        }

        const originals = nodes.map((n) => (n.nodeValue ?? "").trim());

        // Phase 1: apply cached translations immediately, collect misses.
        const missNodes: Text[] = [];
        const missOriginals: string[] = [];
        await Promise.all(
          nodes.map(async (node, i) => {
            const trimmed = originals[i];
            if (!trimmed) return;
            const cached = await getCached(targetLocale, contentKey, trimmed);
            if (cached) {
              if (cancelled) return;
              const raw = node.nodeValue ?? "";
              node.nodeValue = raw.replace(trimmed, cached);
            } else {
              missNodes.push(node);
              missOriginals.push(trimmed);
            }
          }),
        );

        if (cancelled) return;
        if (missOriginals.length === 0) {
          setStatus("done");
          return;
        }

        // Phase 2: translate the misses in batched, parallel requests.
        const translated = await translateMany(
          missOriginals,
          routing.defaultLocale,
          targetLocale,
          {
            signal: controller.signal,
            onProgress: (done, total) => {
              if (!cancelled) setProgress({ done, total });
            },
          },
        );

        if (cancelled) return;

        await Promise.all(
          missNodes.map(async (node, i) => {
            const original = missOriginals[i];
            const result = translated[i];
            if (!result || result === original) return;
            const raw = node.nodeValue ?? "";
            node.nodeValue = raw.replace(original, result);
            await setCached(targetLocale, contentKey, original, result);
          }),
        );

        if (!cancelled) setStatus("done");
      } catch {
        if (!cancelled) setStatus("error");
      }
    })();

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [enabled, targetLocale, contentKey]);

  return (
    <>
      {enabled && status === "running" && (
        <div
          className="mb-4 flex items-center gap-2 rounded-md border border-primary/30 bg-primary/5 px-3 py-2 text-xs text-foreground/80"
          data-notranslate
          role="status"
          aria-live="polite"
        >
          <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin text-primary" />
          <span>
            {t("detected", { locale: localeLabel })}{" "}
            <span className="text-muted-foreground">
              {t("translating")}
              {progress.total > 0 && (
                <span className="ml-1 tabular-nums">
                  ({progress.done}/{progress.total})
                </span>
              )}
            </span>
          </span>
        </div>
      )}
      {enabled && status === "error" && (
        <div
          className="mb-4 rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-xs text-muted-foreground"
          data-notranslate
        >
          {t("translationFailed")}
        </div>
      )}
      <div ref={containerRef} style={{ display: "contents" }}>
        {children}
      </div>
    </>
  );
}
