"use client";

import { useEffect, useState } from "react";
import {
  Download,
  Maximize,
  Minimize,
  RotateCcw,
  ZoomIn,
  ZoomOut,
  X,
} from "lucide-react";
import { useTranslations } from "next-intl";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

function clamp(n: number, min: number, max: number) {
  return Math.max(min, Math.min(max, n));
}

function getDownloadName(src: string) {
  try {
    const u = new URL(src, window.location.origin);
    return u.pathname.split("/").pop() ?? "image";
  } catch {
    return "image";
  }
}

interface ImageLightboxProps {
  open: boolean;
  onClose: () => void;
  src: string;
  alt?: string;
}

export function ImageLightbox({ open, onClose, src, alt }: ImageLightboxProps) {
  const t = useTranslations("lightbox");
  const [zoom, setZoom] = useState(1);
  const [fullscreen, setFullscreen] = useState(false);

  useEffect(() => {
    if (!open) return;
    setZoom(1);
    setFullscreen(false);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
      if (e.key === "+" || e.key === "=")
        setZoom((z) => clamp(z + 0.25, 0.5, 4));
      if (e.key === "-" || e.key === "_")
        setZoom((z) => clamp(z - 0.25, 0.5, 4));
    };

    window.addEventListener("keydown", onKeyDown);
    return () => {
      document.body.style.overflow = prevOverflow;
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      className={cn(
        "fixed inset-0 z-[100] flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-in fade-in-0 duration-200",
        fullscreen && "p-0"
      )}
      onClick={onClose}
    >
      <div
        className={cn(
          "relative mx-auto flex min-h-0 w-full max-w-5xl flex-col overflow-hidden rounded-xl border bg-background shadow-2xl",
          "max-h-[92vh]",
          fullscreen &&
            "h-full max-h-none max-w-none rounded-none border-0 shadow-none"
        )}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Toolbar */}
        <div className="flex shrink-0 items-center justify-between border-b bg-background/70 px-4 py-2">
          <span className="truncate text-sm font-medium text-muted-foreground">
            {alt || "Image"}
          </span>

          <div className="flex items-center gap-1">
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setZoom((z) => clamp(z - 0.25, 0.5, 4))}
              aria-label={t("zoomOut")}
              disabled={zoom <= 0.5}
              className="h-8 w-8"
            >
              <ZoomOut className="h-4 w-4" />
            </Button>
            <span className="w-12 text-center text-xs text-muted-foreground">
              {Math.round(zoom * 100)}%
            </span>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setZoom((z) => clamp(z + 0.25, 0.5, 4))}
              aria-label={t("zoomIn")}
              disabled={zoom >= 4}
              className="h-8 w-8"
            >
              <ZoomIn className="h-4 w-4" />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setZoom(1)}
              aria-label={t("resetZoom")}
              disabled={zoom === 1}
              className="h-8 w-8"
            >
              <RotateCcw className="h-4 w-4" />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => {
                setFullscreen((f) => !f);
                setZoom(1);
              }}
              aria-label={fullscreen ? t("exitFullscreen") : t("fullscreen")}
              className="h-8 w-8"
            >
              {fullscreen ? (
                <Minimize className="h-4 w-4" />
              ) : (
                <Maximize className="h-4 w-4" />
              )}
            </Button>
            <Button
              variant="ghost"
              size="icon"
              asChild
              aria-label={t("download")}
              className="h-8 w-8"
            >
              <a href={src} download={getDownloadName(src)}>
                <Download className="h-4 w-4" />
              </a>
            </Button>
            <Button
              variant="ghost"
              size="icon"
              onClick={onClose}
              aria-label={t("close")}
              className="h-8 w-8"
            >
              <X className="h-4 w-4" />
            </Button>
          </div>
        </div>

        {/* Image */}
        <div
          className={cn(
            "min-h-0 flex-1 overflow-auto p-4",
            fullscreen && "p-2"
          )}
        >
          <div
            className={cn(
              "flex min-h-full justify-center",
              fullscreen ? "items-center py-2" : "items-start py-2"
            )}
          >
            <div
              className="inline-block max-w-full"
              style={{
                transform: `scale(${zoom})`,
                transformOrigin: "top center",
              }}
            >
              <img
                src={src}
                alt={alt ?? ""}
                className={cn(
                  "block h-auto w-auto max-w-full object-contain",
                  fullscreen
                    ? "max-h-[calc(100dvh-4rem)]"
                    : "max-h-[calc(92vh-6rem)]"
                )}
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
