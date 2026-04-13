import type { Metadata } from "next";
import Link from "next/link";
import { getSectionIndex, getContentList, getSubsections } from "@/lib/content";

interface Props {
  params: Promise<{ category: string }>;
}

export async function generateStaticParams() {
  return getSubsections("codex")
    .filter((s) => s.name !== "glossary")
    .map((s) => ({ category: s.name }));
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { category } = await params;
  const section = getSectionIndex(`codex/${category}`);
  return { title: section?.meta.title ?? category };
}

export default async function CodexCategoryPage({ params }: Props) {
  const { category } = await params;
  const section = getSectionIndex(`codex/${category}`);
  const articles = getContentList(`codex/${category}`);

  return (
    <div className="mx-auto w-[90vw] max-w-none px-4 py-12">
      <Link
        href="/codex/"
        className="mb-6 inline-flex items-center text-sm text-muted-foreground hover:text-foreground transition-colors"
      >
        &larr; Back to Codex
      </Link>
      <h1 className="mb-2 text-3xl font-bold font-heading">
        {section?.meta.title ?? category}
      </h1>
      {section?.meta.description && (
        <p className="mb-8 text-muted-foreground">
          {section.meta.description}
        </p>
      )}

      <div className="space-y-3">
        {articles.map((article) => (
          <Link
            key={article.slug}
            href={`/codex/${category}/${article.slug}/`}
            className="group flex items-center justify-between rounded-lg border border-border bg-card px-5 py-4 transition-colors hover:border-primary/40"
          >
            <span className="font-medium text-card-foreground group-hover:text-primary transition-colors">
              {article.meta.title}
            </span>
            {article.meta.tags && (
              <div className="ml-4 hidden flex-wrap gap-1 sm:flex">
                {article.meta.tags.slice(0, 3).map((tag) => (
                  <span
                    key={tag}
                    className="rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            )}
          </Link>
        ))}
      </div>
    </div>
  );
}
