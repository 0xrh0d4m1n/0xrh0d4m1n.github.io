import type { Metadata } from "next";
import Link from "next/link";
import path from "path";
import fs from "fs";
import { getAllSlugs } from "@/lib/content";
import { formatDate } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { TableOfContents } from "@/components/blog/table-of-contents";
import { ProseImageLightbox } from "@/components/blog/prose-image-lightbox";
import { ReadingProgress } from "@/components/blog/reading-progress";
import { ScrollToTop } from "@/components/blog/scroll-to-top";

interface Props {
  params: Promise<{ slug: string }>;
}

const CONTENT_WRITEUPS = path.join(process.cwd(), "content", "writeups");

export async function generateStaticParams() {
  return getAllSlugs("writeups").map((slug) => ({ slug }));
}

async function importWriteup(slug: string) {
  if (fs.existsSync(path.join(CONTENT_WRITEUPS, `${slug}.mdx`))) {
    return import(`@content/writeups/${slug}.mdx`);
  }
  return import(`@content/writeups/${slug}.md`);
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params;
  const mod = await importWriteup(slug);
  const title = (mod.frontmatter?.title as string) ?? slug;
  return { title };
}

export default async function WriteupPage({ params }: Props) {
  const { slug } = await params;
  const mdPath = path.join(CONTENT_WRITEUPS, `${slug}.md`);
  const mdxPath = path.join(CONTENT_WRITEUPS, `${slug}.mdx`);

  if (!fs.existsSync(mdPath) && !fs.existsSync(mdxPath)) {
    const { notFound } = await import("next/navigation");
    notFound();
  }

  const mod = await importWriteup(slug);
  const Content = mod.default;
  const fm = (mod.frontmatter ?? {}) as {
    title?: string;
    date?: string;
    tags?: string[];
    platform?: string;
    category?: string;
    difficulty?: string;
    image?: string;
    description?: string;
  };

  return (
    <>
      <ReadingProgress />

      <div className="mx-auto w-[90vw] max-w-[1200px] px-4 py-8">
        <Link
          href="/writeups/"
          className="mb-6 inline-flex items-center text-sm text-muted-foreground transition-colors hover:text-primary"
        >
          &larr; Back to Writeups
        </Link>

        {fm.image && (
          <div className="mb-6 overflow-hidden rounded-xl">
            <img
              src={fm.image}
              alt=""
              className="h-64 w-full object-cover sm:h-80 lg:h-96"
            />
          </div>
        )}

        <header className="mb-8">
          <div className="mb-3 flex flex-wrap gap-2">
            {fm.platform && (
              <Badge variant="default" className="text-xs uppercase">
                {fm.platform}
              </Badge>
            )}
            {fm.category && (
              <Badge variant="secondary" className="text-xs capitalize">
                {fm.category}
              </Badge>
            )}
            {fm.difficulty && (
              <Badge variant="outline" className="text-xs">
                {fm.difficulty}
              </Badge>
            )}
          </div>

          <h1 className="mb-4 text-3xl font-bold font-heading leading-tight sm:text-4xl">
            {fm.title}
          </h1>

          {fm.description && (
            <p className="mb-4 text-lg text-muted-foreground leading-relaxed">
              {fm.description}
            </p>
          )}

          {fm.date && (
            <div className="flex flex-wrap items-center gap-3 text-sm text-muted-foreground">
              <time>
                {formatDate(fm.date, {
                  year: "numeric",
                  month: "long",
                  day: "numeric",
                })}
              </time>
            </div>
          )}

          {fm.tags && fm.tags.length > 0 && (
            <div className="mt-4 flex flex-wrap gap-2">
              {fm.tags.map((tag) => (
                <Badge key={tag} variant="outline" className="text-xs">
                  {tag}
                </Badge>
              ))}
            </div>
          )}
        </header>

        <div className="flex flex-col gap-8 lg:flex-row">
          <article className="w-full min-w-0 lg:w-[70%]">
            <ProseImageLightbox>
              <div
                data-prose-content
                className="prose prose-neutral max-w-none dark:prose-invert"
              >
                <Content />
              </div>
            </ProseImageLightbox>
          </article>

          <aside className="w-full lg:w-[30%]">
            <div className="space-y-4 lg:sticky lg:top-20">
              <TableOfContents />

              {fm.tags && fm.tags.length > 0 && (
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-semibold">
                      Tags
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="flex flex-wrap gap-2">
                      {fm.tags.map((tag) => (
                        <Badge
                          key={tag}
                          variant="secondary"
                          className="text-[11px]"
                        >
                          {tag}
                        </Badge>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          </aside>
        </div>
      </div>

      <ScrollToTop />
    </>
  );
}
