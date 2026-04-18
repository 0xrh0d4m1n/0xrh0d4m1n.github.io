import type { Metadata } from "next";
import Link from "next/link";
import path from "path";
import fs from "fs";
import { getAllSlugs } from "@/lib/content";
import { formatDate } from "@/lib/utils";

interface Props {
  params: Promise<{ slug: string }>;
}

const CONTENT_WRITEUPS = path.join(process.cwd(), "content", "writeups");

/* ── Static params ────────────────────────────────────────────── */

export async function generateStaticParams() {
  return getAllSlugs("writeups").map((slug) => ({ slug }));
}

/* ── Metadata ─────────────────────────────────────────────────── */

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params;
  const mod = await import(`@content/writeups/${slug}.md`);
  const title = (mod.frontmatter?.title as string) ?? slug;
  return { title };
}

/* ── Page ─────────────────────────────────────────────────────── */

export default async function WriteupPage({ params }: Props) {
  const { slug } = await params;
  const articlePath = path.join(CONTENT_WRITEUPS, `${slug}.md`);

  if (!fs.existsSync(articlePath)) {
    const { notFound } = await import("next/navigation");
    notFound();
  }

  const mod = await import(`@content/writeups/${slug}.md`);
  const Content = mod.default;
  const frontmatter = (mod.frontmatter ?? {}) as {
    title?: string;
    date?: string;
    tags?: string[];
  };

  return (
    <article className="mx-auto w-[90vw] max-w-none px-4 py-12">
      <Link
        href="/writeups/"
        className="mb-6 inline-flex items-center text-sm text-muted-foreground hover:text-foreground transition-colors"
      >
        &larr; Back to Writeups
      </Link>

      <h1 className="mb-2 text-3xl font-bold font-heading">
        {frontmatter.title}
      </h1>

      {frontmatter.date && (
        <time className="mb-4 block text-sm text-muted-foreground">
          {formatDate(frontmatter.date, {
            year: "numeric",
            month: "long",
            day: "numeric",
          })}
        </time>
      )}

      {frontmatter.tags && (
        <div className="mb-8 flex flex-wrap gap-2">
          {frontmatter.tags.map((tag) => (
            <span
              key={tag}
              className="rounded-full bg-muted px-2.5 py-0.5 text-xs text-muted-foreground"
            >
              {tag}
            </span>
          ))}
        </div>
      )}

      <div className="prose max-w-none">
        <Content />
      </div>
    </article>
  );
}
