"use client";

import { useRef, useState, type ReactNode } from "react";
import { Check, Copy, Eye, EyeOff } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * Hides a fenced code block behind a blur until the reader clicks the eye icon.
 * Intended for writeups where the solution/flag should not be visible by default.
 *
 * Usage in MDX/Markdown:
 *
 *   <Spoiler>
 *
 *   ```bash
 *   cat /root/root.txt
 *   ```
 *
 *   </Spoiler>
 */
export function Spoiler({
  children,
  label = "Click to reveal",
}: {
  children: ReactNode;
  label?: string;
}) {
  const [revealed, setRevealed] = useState(false);
  const [copied, setCopied] = useState(false);
  const wrapperRef = useRef<HTMLDivElement>(null);

  const handleCopy = async () => {
    const pre = wrapperRef.current?.querySelector("pre");
    const text = pre?.textContent ?? "";
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked — silently ignore */
    }
  };

  return (
    <div
      ref={wrapperRef}
      className="group/spoiler relative my-4 overflow-hidden rounded-lg border border-border"
    >
      {/* Floating action buttons (top-right) */}
      <div className="absolute right-2 top-2 z-20 flex gap-1">
        <button
          type="button"
          onClick={() => setRevealed((v) => !v)}
          aria-label={revealed ? "Hide answer" : "Reveal answer"}
          title={revealed ? "Hide" : "Reveal"}
          className="inline-flex h-7 w-7 items-center justify-center rounded-md border border-border/60 bg-background/80 text-muted-foreground backdrop-blur-sm transition-colors hover:border-primary hover:bg-primary/10 hover:text-primary"
        >
          {revealed ? <EyeOff size={14} /> : <Eye size={14} />}
        </button>
        <button
          type="button"
          onClick={handleCopy}
          aria-label="Copy to clipboard"
          title={copied ? "Copied!" : "Copy"}
          className="inline-flex h-7 w-7 items-center justify-center rounded-md border border-border/60 bg-background/80 text-muted-foreground backdrop-blur-sm transition-colors hover:border-primary hover:bg-primary/10 hover:text-primary"
        >
          {copied ? (
            <Check size={14} className="text-primary" />
          ) : (
            <Copy size={14} />
          )}
        </button>
      </div>

      {/* Code content — blurred until revealed */}
      <div
        className={cn(
          "transition-[filter] duration-200",
          !revealed && "pointer-events-none select-none blur-md",
          // Strip the inner code block's default margin so it sits flush inside the wrapper
          "[&>figure]:my-0 [&>pre]:my-0"
        )}
        aria-hidden={!revealed}
      >
        {children}
      </div>

      {/* Overlay prompt shown while hidden */}
      {!revealed && (
        <button
          type="button"
          onClick={() => setRevealed(true)}
          className="absolute inset-0 z-10 flex items-center justify-center bg-background/20 text-sm font-medium text-foreground/90 transition-colors hover:bg-background/30"
        >
          <span className="inline-flex items-center gap-2 rounded-md border border-border bg-background/90 px-3 py-1.5 shadow-sm backdrop-blur-sm">
            <Eye size={14} className="text-primary" />
            {label}
          </span>
        </button>
      )}
    </div>
  );
}
