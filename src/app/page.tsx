import type { Metadata } from "next";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export const metadata: Metadata = {
  title: "0xrh0d4m1n",
  description:
    "Security research & defensive hacking. Notes, writeups, and tools for red team, blue team, and building safer systems.",
};

const HERO = {
  title: "0xrh0d4m1n",
  video: "/vid/hero/912938669731443170483.mp4",
  description:
    "Security research & defensive hacking. Notes, writeups, and tools for red team, blue team, and building safer systems.",
} as const;

const SECTIONS = [
  {
    href: "/blog/",
    label: "Blog",
    description:
      "Articles and notes on pentesting, DFIR, and security engineering.",
  },
  {
    href: "/writeups/",
    label: "Writeups",
    description:
      "HackTheBox, CyberDefenders, and PortSwigger walkthroughs.",
  },
  {
    href: "/codex/",
    label: "Codex",
    description:
      "Networking, protocols, programming, and SOC reference.",
  },
  {
    href: "/toolbox/",
    label: "Toolbox",
    description: "Curated tools for offensive and defensive security.",
  },
  {
    href: "/glossary/",
    label: "Glossary",
    description: "Key cybersecurity terms and definitions.",
  },
] as const;

export default function HomePage() {
  return (
    <div>
      {/* Hero: viewport height minus navbar (h-14 = 3.5rem), video as background */}
      <section className="relative min-h-[calc(100dvh-3.5rem)] flex flex-col items-center justify-center overflow-hidden px-4">
        <video
          autoPlay
          muted
          loop
          playsInline
          aria-hidden
          className="absolute inset-0 h-full w-full object-cover"
          src={HERO.video}
        />
        <div className="absolute inset-0 bg-background/60 dark:bg-background/70" aria-hidden />
        <div className="relative z-10 mx-auto max-w-2xl text-center">
          <h1 className="mb-4 text-4xl font-bold font-heading sm:text-5xl">
            {HERO.title}
          </h1>
          <p className="mx-auto text-lg text-muted-foreground">
            {HERO.description}
          </p>
          <div className="mt-8">
            <Button asChild size="lg">
              <Link href="/blog/">Go to Blog</Link>
            </Button>
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-4 py-16 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
        {SECTIONS.map(({ href, label, description }) => (
          <Link key={href} href={href} className="group block">
            <Card className="h-full transition-colors hover:border-primary/40 hover:bg-accent">
              <CardHeader>
                <CardTitle className="font-heading text-xl text-card-foreground group-hover:text-primary">
                  {label}
                </CardTitle>
                <CardDescription>{description}</CardDescription>
              </CardHeader>
            </Card>
          </Link>
        ))}
      </section>
    </div>
  );
}
