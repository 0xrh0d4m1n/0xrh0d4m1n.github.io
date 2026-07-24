import type { Metadata } from "next";
import Script from "next/script";
import { ThemeProvider } from "@/components/theme-provider";
import { TooltipProvider } from "@/components/ui/tooltip";
import "@/styles/globals.css";

export const metadata: Metadata = {
  title: {
    default: "0xrh0d4m1n",
    template: "%s — 0xrh0d4m1n",
  },
  description: "Hacking and general cybersecurity.",
  metadataBase: new URL("https://0xrh0d4m1n.tech"),
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning className="scroll-smooth">
      <head>
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
        <link
          href="https://fonts.googleapis.com/css2?family=Heebo:wght@400;600&family=Signika:wght@500;700&family=JetBrains+Mono:wght@400;500&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="flex min-h-dvh flex-col">
        <ThemeProvider
          attribute="class"
          defaultTheme="dark"
          enableSystem
          disableTransitionOnChange
        >
          <TooltipProvider>{children}</TooltipProvider>
        </ThemeProvider>
        {/* Cloudflare Web Analytics — privacy-first, sem cookies (token é público) */}
        <Script
          src="https://static.cloudflareinsights.com/beacon.min.js"
          data-cf-beacon='{"token": "37b1237d22b541b0b5c229c2f94b1fb6"}'
          strategy="afterInteractive"
        />
      </body>
    </html>
  );
}
