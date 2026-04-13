"use client";

import { useCallback, useState, type ReactNode, type MouseEvent } from "react";
import { ImageLightbox } from "@/components/image-lightbox";

/**
 * Wraps MDX prose content and intercepts clicks on <img> elements
 * to open them in a lightbox modal.
 */
export function ProseImageLightbox({ children }: { children: ReactNode }) {
  const [lightbox, setLightbox] = useState<{
    src: string;
    alt: string;
  } | null>(null);

  const handleClick = useCallback((e: MouseEvent<HTMLDivElement>) => {
    const target = e.target as HTMLElement;
    if (target.tagName === "IMG") {
      const img = target as HTMLImageElement;
      // Skip tiny images (icons, badges, etc.)
      if (img.naturalWidth < 100 && img.naturalHeight < 100) return;
      e.preventDefault();
      setLightbox({ src: img.src, alt: img.alt || "" });
    }
  }, []);

  return (
    <>
      <div onClick={handleClick} className="[&_img]:cursor-zoom-in">
        {children}
      </div>

      {lightbox && (
        <ImageLightbox
          open
          onClose={() => setLightbox(null)}
          src={lightbox.src}
          alt={lightbox.alt}
        />
      )}
    </>
  );
}
