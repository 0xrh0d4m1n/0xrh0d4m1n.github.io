/**
 * Listing & discovery only. Reads content/*.md frontmatter for indexes and section meta.
 * MDX body is rendered via dynamic import (@next/mdx), not from here.
 */
import fs from "fs";
import path from "path";
import matter from "gray-matter";

const CONTENT_DIR = path.join(process.cwd(), "content");

/**
 * Frontmatter metadata parsed from a content `.md` file.
 */
export interface ContentMeta {
  title: string;
  date?: string;
  description?: string;
  tags?: string[];
  categories?: string[];
  weight?: number;
  authors?: Array<{ name: string; link?: string; image?: string }>;
  image?: string;
  difficulty?: string;
  [key: string]: unknown;
}

/**
 * Listing entry for a content file: slug, frontmatter meta, and URL path.
 */
export interface ContentItem {
  slug: string;
  meta: ContentMeta;
  href: string;
  readingTime: number;
}

/**
 * Reads a single content file and returns its frontmatter and listing data (no body).
 *
 * @param relativePath - Path relative to `content/` (e.g. `blog/my-post.md`, `about/_index.md`).
 * @returns The item with slug, meta, and href, or null if the file does not exist.
 */
export function getContent(relativePath: string): ContentItem | null {
  const fullPath = path.join(CONTENT_DIR, relativePath);
  if (!fs.existsSync(fullPath)) return null;

  const raw = fs.readFileSync(fullPath, "utf-8");
  const { data, content: body } = matter(raw);
  const slug = path.basename(relativePath, ".md").replace(/^_index$/, "");
  const wordCount = body.split(/\s+/).filter(Boolean).length;
  const readingTime = Math.max(1, Math.ceil(wordCount / 200));

  return {
    slug,
    meta: data as ContentMeta,
    href: "/" + path.dirname(relativePath).replace(/\\/g, "/") + (slug ? `/${slug}/` : "/"),
    readingTime,
  };
}

/**
 * Returns the section index entry for a given section (its `_index.md`).
 * Used for section title and description on index/listing pages.
 *
 * @param section - Section path under `content/` (e.g. `blog`, `codex/networking`, `writeups/blueteam`).
 * @returns The index item or null if `_index.md` is missing.
 */
export function getSectionIndex(section: string): ContentItem | null {
  return getContent(path.join(section, "_index.md"));
}

/**
 * Lists all content files in a section (excluding `_index.md`), sorted by weight, then date, then title.
 * Used to build blog post lists, codex article lists, and writeup lists.
 *
 * @param section - Section path under `content/` (e.g. `blog`, `codex/soc`).
 * @returns Array of items (slug, meta, href) for each `.md` file in that directory.
 */
export function getContentList(section: string): ContentItem[] {
  const dirPath = path.join(CONTENT_DIR, section);
  if (!fs.existsSync(dirPath)) return [];

  return fs
    .readdirSync(dirPath)
    .filter((f) => f.endsWith(".md") && f !== "_index.md")
    .map((f) => getContent(path.join(section, f)))
    .filter((item): item is ContentItem => item !== null)
    .sort((a, b) => {
      if (a.meta.weight !== undefined && b.meta.weight !== undefined)
        return a.meta.weight - b.meta.weight;
      if (a.meta.date && b.meta.date)
        return new Date(b.meta.date).getTime() - new Date(a.meta.date).getTime();
      return a.meta.title.localeCompare(b.meta.title);
    });
}

/**
 * Lists direct subdirectories of a section, each with the meta from its `_index.md`.
 * Used to build category/team cards (e.g. codex categories, writeups blueteam/redteam).
 *
 * @param section - Section path under `content/` (e.g. `codex`, `writeups`).
 * @returns Array of { name, meta } for each subdirectory, sorted by weight then title.
 */
export function getSubsections(
  section: string,
): Array<{ name: string; meta: ContentMeta }> {
  const dirPath = path.join(CONTENT_DIR, section);
  if (!fs.existsSync(dirPath)) return [];

  return fs
    .readdirSync(dirPath, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => {
      const index = getSectionIndex(path.join(section, d.name));
      return { name: d.name, meta: index?.meta ?? { title: d.name } };
    })
    .sort((a, b) => {
      if (a.meta.weight !== undefined && b.meta.weight !== undefined)
        return a.meta.weight - b.meta.weight;
      return a.meta.title.localeCompare(b.meta.title);
    });
}

/**
 * Returns related posts from the same section, ranked by shared tag count.
 *
 * @param section - Section path (e.g. `blog`).
 * @param currentSlug - Slug to exclude from results.
 * @param tags - Tags of the current post to match against.
 * @param limit - Max results to return (default 4).
 */
export function getRelatedPosts(
  section: string,
  currentSlug: string,
  tags: string[],
  limit = 4,
): ContentItem[] {
  const all = getContentList(section).filter((p) => p.slug !== currentSlug);
  if (tags.length === 0) return all.slice(0, limit);

  const tagSet = new Set(tags.map((t) => t.toLowerCase()));
  return all
    .map((p) => ({
      item: p,
      score: (p.meta.tags ?? []).filter((t) => tagSet.has(t.toLowerCase())).length,
    }))
    .sort((a, b) => b.score - a.score)
    .slice(0, limit)
    .map((e) => e.item);
}

/* ── Writeup helpers ────────────────────────────────────────────── */

/**
 * Flat writeup entry enriched with source / category from directory path.
 */
export interface WriteupItem {
  slug: string;
  name: string;
  source: string;
  sourceKey: string;
  category: string;
  categoryKey: string;
  difficulty: string;
  tags: string[];
  date: string;
  href: string;
}

const SOURCE_NAMES: Record<string, string> = {
  htb: "HackTheBox",
  thm: "TryHackMe",
  vulnhub: "VulnHub",
  cyberdefenders: "CyberDefenders",
  letsdefend: "LetsDefend",
  portswigger: "PortSwigger",
};

const CATEGORY_NAMES: Record<string, string> = {
  blueteam: "Blue Team",
  redteam: "Red Team",
  web: "Web Security",
};

/**
 * Reads all writeups from the flat `content/writeups/` directory.
 * Each file must have `platform` and `category` in its frontmatter.
 */
export function getAllWriteups(): WriteupItem[] {
  const writeupsDir = path.join(CONTENT_DIR, "writeups");
  if (!fs.existsSync(writeupsDir)) return [];

  const files = fs
    .readdirSync(writeupsDir)
    .filter((f) => f.endsWith(".md") && f !== "_index.md");

  const items: WriteupItem[] = files.map((file) => {
    const raw = fs.readFileSync(path.join(writeupsDir, file), "utf-8");
    const { data } = matter(raw);
    const meta = data as ContentMeta;
    const slug = file.replace(/\.md$/, "");

    const platformKey = (meta.platform as string) ?? "";
    const categoryKey = (meta.category as string) ?? "";

    // Normalise date
    let dateStr = "";
    const rawDate = meta.date;
    if (rawDate) {
      const d = rawDate as unknown;
      dateStr = d instanceof Date ? d.toISOString().split("T")[0] : String(rawDate);
    }

    return {
      slug,
      name: meta.title ?? slug,
      source: SOURCE_NAMES[platformKey] ?? platformKey,
      sourceKey: platformKey,
      category: CATEGORY_NAMES[categoryKey] ?? categoryKey,
      categoryKey,
      difficulty: meta.difficulty ?? "Unknown",
      tags: meta.tags ?? [],
      date: dateStr,
      href: `/writeups/${slug}/`,
    };
  });

  // Default sort: newest first
  return items.sort((a, b) => {
    if (a.date && b.date)
      return new Date(b.date).getTime() - new Date(a.date).getTime();
    return a.name.localeCompare(b.name);
  });
}

/**
 * Returns the list of content slugs in a section (filenames without `.md`, excluding `_index`).
 * Used by `generateStaticParams` for blog and codex dynamic routes.
 *
 * @param section - Section path under `content/` (e.g. `blog`, `codex/infra`).
 * @returns Array of slug strings.
 */
export function getAllSlugs(section: string): string[] {
  const dirPath = path.join(CONTENT_DIR, section);
  if (!fs.existsSync(dirPath)) return [];

  return fs
    .readdirSync(dirPath)
    .filter((f) => f.endsWith(".md") && f !== "_index.md")
    .map((f) => f.replace(/\.md$/, ""));
}
