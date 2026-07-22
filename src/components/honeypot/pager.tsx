"use client";

import { useState } from "react";
import { ChevronLeft, ChevronRight } from "lucide-react";

/**
 * Client-side pagination for the honeypot lists. Only kicks in when a list has
 * more than one page (`hasPages`) — small lists render untouched.
 */
export function usePaged<T>(items: T[], pageSize: number) {
  const [page, setPage] = useState(0);
  const pages = Math.max(1, Math.ceil(items.length / pageSize));
  const current = Math.min(page, pages - 1);
  const slice = items.slice(current * pageSize, current * pageSize + pageSize);
  return { slice, page: current, pages, setPage, hasPages: pages > 1 };
}

export function Pager({
  page,
  pages,
  setPage,
}: {
  page: number;
  pages: number;
  setPage: (p: number) => void;
}) {
  if (pages <= 1) return null;
  const btn =
    "inline-flex h-6 w-6 items-center justify-center rounded-md border border-border bg-card/50 text-muted-foreground transition-colors enabled:hover:text-primary disabled:opacity-40";
  return (
    <div className="mt-2 flex items-center justify-center gap-3 font-mono text-[11px] text-muted-foreground">
      <button
        type="button"
        aria-label="previous page"
        className={btn}
        disabled={page === 0}
        onClick={() => setPage(page - 1)}
      >
        <ChevronLeft className="h-3.5 w-3.5" />
      </button>
      <span className="tabular-nums">
        {page + 1} / {pages}
      </span>
      <button
        type="button"
        aria-label="next page"
        className={btn}
        disabled={page >= pages - 1}
        onClick={() => setPage(page + 1)}
      >
        <ChevronRight className="h-3.5 w-3.5" />
      </button>
    </div>
  );
}
