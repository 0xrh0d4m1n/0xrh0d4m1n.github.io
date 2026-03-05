import { test, expect } from "@playwright/test";
import * as fs from "fs";
import * as path from "path";

/**
 * File structure — section indexes
 *
 * Ensures all content section _index.md files exist, have required front matter
 * (and body content), and that their URLs are reachable and render content.
 * Without correct front matter and content, the page can show only title and
 * breadcrumb with nothing displayed below (see About-style sections).
 */

const CONTENT_DIR = path.join(process.cwd(), "content");

/** Sections that must have an _index.md (path segment and expected URL path). */
const SECTION_INDEXES = [
  { segment: "about", url: "/about/" },
  { segment: "blog", url: "/blog/" },
  { segment: "codex", url: "/codex/" },
  { segment: "skills", url: "/skills/" },
  { segment: "toolbox", url: "/toolbox/" },
  { segment: "writeups", url: "/writeups/" },
] as const;

/** Sections that are content pages: _index.md must have body content after front matter. */
const SECTIONS_WITH_BODY = ["about", "codex", "skills", "toolbox", "writeups"] as const;

/** Minimum length of visible text in main to consider "body content" displayed. */
const MIN_MAIN_CONTENT_LENGTH = 80;

interface FrontMatterResult {
  title?: string;
  hasValidFence: boolean;
  hasBodyContent: boolean;
}

function readFrontMatter(filePath: string): FrontMatterResult | null {
  if (!fs.existsSync(filePath)) return null;
  const raw = fs.readFileSync(filePath, "utf8");
  const fenceMatch = raw.match(/^---\s*\n([\s\S]*?)\n---\s*([\s\S]*)$/);
  if (!fenceMatch) {
    const onlyFence = raw.match(/^---\s*\n[\s\S]*\n---/);
    return onlyFence
      ? { hasValidFence: true, hasBodyContent: false }
      : { hasValidFence: false, hasBodyContent: false };
  }
  const block = fenceMatch[1];
  const body = fenceMatch[2].trim();
  const titleMatch = block.match(/^title:\s*["']?([^"'\n]+)["']?/m);
  return {
    title: titleMatch ? titleMatch[1].trim() : undefined,
    hasValidFence: true,
    hasBodyContent: body.length >= 10,
  };
}

test.describe("File structure — section indexes", () => {
  test.describe("content files", () => {
    for (const { segment } of SECTION_INDEXES) {
      test(`${segment}/_index.md exists`, () => {
        const indexPath = path.join(CONTENT_DIR, segment, "_index.md");
        expect(fs.existsSync(indexPath), `${segment}/_index.md should exist`).toBe(true);
      });

      test(`${segment}/_index.md has valid front matter fence (---)`, () => {
        const indexPath = path.join(CONTENT_DIR, segment, "_index.md");
        const fm = readFrontMatter(indexPath);
        expect(fm, `${segment}/_index.md should be readable`).not.toBeNull();
        expect(fm!.hasValidFence, `${segment}/_index.md should have opening and closing ---`).toBe(true);
      });

      test(`${segment}/_index.md has title in front matter`, () => {
        const indexPath = path.join(CONTENT_DIR, segment, "_index.md");
        const fm = readFrontMatter(indexPath);
        expect(fm, `${segment}/_index.md should have valid front matter`).not.toBeNull();
        expect(fm!.title, `${segment}/_index.md should have a non-empty title`).toBeTruthy();
      });

      test(`${segment}/_index.md has body content after front matter (content pages only)`, () => {
        if (!SECTIONS_WITH_BODY.includes(segment as (typeof SECTIONS_WITH_BODY)[number])) return;
        const indexPath = path.join(CONTENT_DIR, segment, "_index.md");
        const fm = readFrontMatter(indexPath);
        expect(fm, `${segment}/_index.md should have valid front matter`).not.toBeNull();
        expect(
          fm!.hasBodyContent,
          `${segment}/_index.md should have body content after --- so the page can display something (not only title/breadcrumb)`
        ).toBe(true);
      });
    }
  });

  test.describe("section URLs reachable", () => {
    for (const { segment, url } of SECTION_INDEXES) {
      test(`${segment} (${url}) loads and has main element`, async ({ page }) => {
        const res = await page.goto(url);
        expect(res?.status(), `${url} should return 200`).toBe(200);
        await expect(page.locator("body")).toBeVisible();
        const main = page.locator("main").first();
        await expect(main).toBeVisible();
      });

      test(`${segment} (${url}) displays body content in main (not only title/breadcrumb)`, async ({
        page,
      }) => {
        const res = await page.goto(url);
        expect(res?.status()).toBe(200);
        const main = page.locator("main").first();
        await expect(main).toBeVisible();
        const mainText = (await main.innerText()).trim();
        expect(
          mainText.length >= MIN_MAIN_CONTENT_LENGTH,
          `main should show body content (got ${mainText.length} chars; need >= ${MIN_MAIN_CONTENT_LENGTH}). If only title and breadcrumb show, check front matter and that the theme renders section content.`
        ).toBe(true);
      });
    }
  });
});
