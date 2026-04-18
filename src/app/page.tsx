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
  video: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/video/upload/q_auto/f_auto/v1776380472/Website/Homepage/912938669731443170483_b9tluh.mp4",
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
    href: "/toolbox/",
    label: "Toolbox",
    description: "Curated tools for offensive and defensive security.",
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
        <div className="relative z-10 mx-auto max-w-2xl text-center flex flex-col items-center">
          {/* Animated GIF avatar */}
          <img
            src="https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776380450/Website/Homepage/54879845732140987541253743874983361_hfxt3v.gif"
            alt="0xrh0d4m1n"
            className="mb-6 h-56 w-56 sm:h-72 sm:w-72 aspect-square rounded-full object-cover border-4 border-primary shadow-[0_0_40px_rgba(159,239,0,0.3)]"
          />

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
