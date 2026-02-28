import { test, expect } from "@playwright/test";

/**
 * Home page tests — validates hero content, title, cards, and structure.
 */

test.describe("Home Page – title and heading", () => {
  test("page title is '0xrh0d4m1n'", async ({ page }) => {
    await page.goto("/");
    await expect(page).toHaveTitle("0xrh0d4m1n");
  });

  test("H1 'Hello, World!' is rendered", async ({ page }) => {
    await page.goto("/");
    // Hextra injects a title <h1> before content; the Markdown h1 is the second one
    const h1 = page.locator("h1").filter({ hasText: "Hello" });
    await expect(h1).toBeVisible();
    await expect(h1).toContainText("Hello, World!");
  });

  test("welcome heading is rendered", async ({ page }) => {
    await page.goto("/");
    const heading = page.locator("h2").first();
    await expect(heading).toContainText("Welcome to my world");
  });
});

test.describe("Home Page – cards", () => {
  const CARDS = [
    { title: "Blog", link: "/blog" },
    { title: "Practice", link: "/writeups" },
    { title: "Codex", link: "/codex" },
    { title: "Toolbox", link: "/toolbox" },
    { title: "Glossary", link: "/glossary" },
  ];

  for (const card of CARDS) {
    test(`card "${card.title}" is visible`, async ({ page }) => {
      await page.goto("/");
      // Hextra renders shortcode cards with class "hextra-card" — avoids matching nav links
      const cardEl = page.locator(`a.hextra-card[href="${card.link}"]`);
      await expect(cardEl).toBeVisible();
    });
  }

  test("all 5 home cards are rendered", async ({ page }) => {
    await page.goto("/");
    // All cards use class "hextra-card" — count should be exactly 5
    const allCards = page.locator("a.hextra-card");
    await expect(allCards).toHaveCount(5);
  });
});

test.describe("Home Page – sidebar hidden", () => {
  test("sidebar is hidden on home (toc: false)", async ({ page }) => {
    await page.goto("/");
    // The TOC/sidebar should not display on the home page
    const toc = page.locator(".toc, aside#toc, nav[aria-label='Table of contents']");
    const count = await toc.count();
    if (count > 0) {
      await expect(toc.first()).not.toBeVisible();
    }
  });
});

test.describe("Home Page – Glider link", () => {
  test("Gliders text links to catb.org hacker emblem FAQ", async ({ page }) => {
    await page.goto("/");
    const gliderLink = page.locator('a[href="http://www.catb.org/hacker-emblem/faqs.html"]');
    await expect(gliderLink).toBeVisible();
    await expect(gliderLink).toContainText("Gliders");
  });
});
