"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";

export function ScrollToTop() {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const onScroll = () => {
      setVisible(window.scrollY > 400);
    };

    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  const handleClick = () => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  if (!visible) return null;

  return (
    <Button
      variant="outline"
      size="icon"
      onClick={handleClick}
      aria-label="Scroll to top"
      className="fixed bottom-6 right-6 z-50 h-10 w-10 rounded-full border-primary/30 bg-background/90 shadow-lg backdrop-blur-sm transition-all hover:border-primary hover:bg-primary/10 hover:shadow-primary/20"
    >
      <svg
        xmlns="http://www.w3.org/2000/svg"
        width="18"
        height="18"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        className="text-primary"
      >
        <path d="m18 15-6-6-6 6" />
      </svg>
    </Button>
  );
}
