"use client";

import { useEffect, useState } from "react";
import { useTranslations } from "next-intl";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface TocItem {
  id: string;
  text: string;
  level: number;
}

export function TableOfContents() {
  const t = useTranslations("sidebar");
  const [headings, setHeadings] = useState<TocItem[]>([]);
  const [activeId, setActiveId] = useState("");

  // Extract headings from the article on mount
  useEffect(() => {
    const article = document.querySelector("[data-prose-content]");
    if (!article) return;

    const elements = article.querySelectorAll("h1, h2, h3");
    const items: TocItem[] = [];

    elements.forEach((el) => {
      // Skip auto-generated footnotes heading
      if (el.closest(".footnotes")) return;

      // Generate an ID if the heading doesn't have one
      if (!el.id) {
        el.id = el.textContent
          ?.toLowerCase()
          .replace(/[^a-z0-9]+/g, "-")
          .replace(/(^-|-$)/g, "") ?? "";
      }

      const tag = el.tagName;
      const level = tag === "H1" ? 1 : tag === "H2" ? 2 : 3;

      items.push({
        id: el.id,
        text: el.textContent ?? "",
        level,
      });
    });

    setHeadings(items);
  }, []);

  // Track which heading is currently in view
  useEffect(() => {
    if (headings.length === 0) return;

    const observer = new IntersectionObserver(
      (entries) => {
        // Find the first visible heading
        const visible = entries.find((e) => e.isIntersecting);
        if (visible) {
          setActiveId(visible.target.id);
        }
      },
      { rootMargin: "-80px 0px -70% 0px", threshold: 0 }
    );

    headings.forEach(({ id }) => {
      const el = document.getElementById(id);
      if (el) observer.observe(el);
    });

    return () => observer.disconnect();
  }, [headings]);

  if (headings.length === 0) return null;

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-semibold">
          {t("tableOfContents")}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <nav className="space-y-1">
          {headings.map((h, i) => (
            <a
              key={h.id}
              href={`#${h.id}`}
              onClick={(e) => {
                e.preventDefault();
                document.getElementById(h.id)?.scrollIntoView({ behavior: "smooth" });
              }}
              className={cn(
                "block text-xs leading-relaxed transition-colors hover:text-primary",
                // H1 → top-level topic: subtle top margin (except the first item)
                h.level === 1 && i > 0 && "mt-3",
                h.level === 1 && "font-semibold",
                // H2 → slight indent
                h.level === 2 && "pl-3",
                // H3 → deeper indent
                h.level === 3 && "pl-6",
                activeId === h.id
                  ? "text-primary"
                  : h.level === 1
                    ? "text-foreground/80"
                    : "text-muted-foreground"
              )}
            >
              {h.text}
            </a>
          ))}
        </nav>
      </CardContent>
    </Card>
  );
}
