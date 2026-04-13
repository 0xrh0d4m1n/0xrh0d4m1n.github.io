import type { Metadata } from "next";
import Link from "next/link";
import { getAllSlugs, getSubsections } from "@/lib/content";

interface Props {
  params: Promise<{ category: string; slug: string }>;
}

export async function generateStaticParams() {
  const categories = getSubsections("codex")
    .filter((s) => s.name !== "glossary")
    .map((s) => s.name);

  return categories.flatMap((category) =>
    getAllSlugs(`codex/${category}`).map((slug) => ({ category, slug })),
  );
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { category, slug } = await params;
  const mod = await import(`@content/codex/${category}/${slug}.md`);
  const title = (mod.frontmatter?.title as string) ?? slug;
  return { title };
}

export default async function CodexArticlePage({ params }: Props) {
  const { category, slug } = await params;
  const mod = await import(`@content/codex/${category}/${slug}.md`);
  const Content = mod.default;
  const frontmatter = (mod.frontmatter ?? {}) as {
    title?: string;
    tags?: string[];
  };

  return (
    <article className="mx-auto w-[90vw] max-w-none px-4 py-12">
      <Link
        href={`/codex/${category}/`}
        className="mb-6 inline-flex items-center text-sm text-muted-foreground hover:text-foreground transition-colors"
      >
        &larr; Back to {category}
      </Link>
      <h1 className="mb-4 text-3xl font-bold font-heading">
        {frontmatter.title}
      </h1>
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
