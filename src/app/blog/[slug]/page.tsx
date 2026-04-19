import type { Metadata } from "next";
import Link from "next/link";
import path from "path";
import fs from "fs";
import { getAllSlugs, getContent, getRelatedPosts } from "@/lib/content";
import { formatDate } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { PostSidebar } from "@/components/blog/post-sidebar";
import { ProseImageLightbox } from "@/components/blog/prose-image-lightbox";
import { ReadingProgress } from "@/components/blog/reading-progress";
import { ScrollToTop } from "@/components/blog/scroll-to-top";
import type { SerializedPost } from "@/components/blog/types";

interface Props {
  params: Promise<{ slug: string }>;
}

export async function generateStaticParams() {
  return getAllSlugs("blog").map((slug) => ({ slug }));
}

const CONTENT_BLOG = path.join(process.cwd(), "content", "blog");

async function importPost(slug: string) {
  if (fs.existsSync(path.join(CONTENT_BLOG, `${slug}.mdx`))) {
    return import(`@content/blog/${slug}.mdx`);
  }
  return import(`@content/blog/${slug}.md`);
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params;
  const mod = await importPost(slug);
  const title = (mod.frontmatter?.title as string) ?? slug;
  return { title };
}

function serialize(item: NonNullable<ReturnType<typeof getContent>>): SerializedPost {
  return {
    slug: item.slug,
    title: item.meta.title,
    description: item.meta.description,
    date: item.meta.date,
    tags: item.meta.tags,
    categories: item.meta.categories,
    image: item.meta.image,
    readingTime: item.readingTime,
    href: item.href,
  };
}

export default async function BlogPostPage({ params }: Props) {
  const { slug } = await params;
  const mod = await importPost(slug);
  const Content = mod.default;
  const fm = (mod.frontmatter ?? {}) as {
    title?: string;
    date?: string;
    tags?: string[];
    categories?: string[];
    image?: string;
    description?: string;
    authors?: Array<{ name: string; link?: string; image?: string }>;
    relatedTopics?: string[];
  };

  // Get current post metadata for reading time
  const currentPost =
    getContent(`blog/${slug}.mdx`) ?? getContent(`blog/${slug}.md`);
  const readingTime = currentPost?.readingTime ?? 1;

  // Related posts & tags
  const relatedItems = getRelatedPosts("blog", slug, fm.tags ?? [], 4);
  const relatedPosts = relatedItems.map(serialize);

  // Related Topics:
  //   • If `relatedTopics` is explicitly set in frontmatter, use it verbatim
  //     (author-controlled, no sorting — respect the order they wrote).
  //   • Otherwise, auto-aggregate from current post tags + related posts' tags.
  const relatedTags =
    fm.relatedTopics && fm.relatedTopics.length > 0
      ? fm.relatedTopics
      : Array.from(
          new Set([
            ...(fm.tags ?? []),
            ...relatedItems.flatMap((p) => p.meta.tags ?? []),
          ])
        ).sort();

  const author = fm.authors?.[0];

  return (
    <>
      {/* Reading progress bar */}
      <ReadingProgress />

      <div className="mx-auto w-[90vw] max-w-[1200px] px-4 py-8">
        {/* Back link */}
        <Link
          href="/blog/"
          className="mb-6 inline-flex items-center text-sm text-muted-foreground transition-colors hover:text-primary"
        >
          &larr; Back to Blog
        </Link>

        {/* Hero image */}
        {fm.image && (
          <div className="mb-6 overflow-hidden rounded-xl">
            <img
              src={fm.image}
              alt=""
              className="h-64 w-full object-cover sm:h-80 lg:h-96"
            />
          </div>
        )}

        {/* Post header */}
        <header className="mb-8">
          {/* Categories */}
          {fm.categories && fm.categories.length > 0 && (
            <div className="mb-3 flex flex-wrap gap-2">
              {fm.categories.map((cat) => (
                <Badge key={cat} variant="default" className="text-xs">
                  {cat}
                </Badge>
              ))}
            </div>
          )}

          {/* Title */}
          <h1 className="mb-4 text-3xl font-bold font-heading leading-tight sm:text-4xl">
            {fm.title}
          </h1>

          {/* Description */}
          {fm.description && (
            <p className="mb-4 text-lg text-muted-foreground leading-relaxed">
              {fm.description}
            </p>
          )}

          {/* Meta row: author, date, reading time */}
          <div className="flex flex-wrap items-center gap-3 text-sm text-muted-foreground">
            {author && (
              <div className="flex items-center gap-2">
                {author.image && (
                  <img
                    src={author.image}
                    alt=""
                    className="h-8 w-8 rounded-full object-cover"
                  />
                )}
                {author.link ? (
                  <a
                    href={author.link}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-medium text-foreground hover:text-primary transition-colors"
                  >
                    {author.name}
                  </a>
                ) : (
                  <span className="font-medium text-foreground">{author.name}</span>
                )}
              </div>
            )}
            {fm.date && (
              <>
                <span>&middot;</span>
                <time>
                  {formatDate(fm.date, {
                    year: "numeric",
                    month: "long",
                    day: "numeric",
                  })}
                </time>
              </>
            )}
            <span>&middot;</span>
            <span>{readingTime} min read</span>
          </div>

          {/* Tags */}
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

        {/* Two-column layout: content + sidebar */}
        <div className="flex flex-col gap-8 lg:flex-row">
          {/* Main content */}
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

          {/* Right sidebar */}
          <aside className="w-full lg:w-[30%]">
            <div className="lg:sticky lg:top-20">
              <PostSidebar
                relatedPosts={relatedPosts}
                relatedTags={relatedTags}
              />
            </div>
          </aside>
        </div>
      </div>

      {/* Scroll to top button */}
      <ScrollToTop />
    </>
  );
}
