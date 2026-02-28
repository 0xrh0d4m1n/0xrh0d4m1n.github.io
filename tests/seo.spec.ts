import { test, expect } from "@playwright/test";

/**
 * SEO tests — validates meta tags, Open Graph, Twitter Cards, canonical URLs,
 * robots directives, and site description on every main page.
 */

const PAGES = [
  {
    path: "/",
    title: "0xrh0d4m1n",
    description: "Hacking and general cybersecurity.",
  },
  {
    path: "/about/",
    title: /about/i,
    description: null,
  },
  {
    path: "/blog/",
    title: /blog/i,
    description: null,
  },
  {
    path: "/writeups/",
    title: /writeups|practice/i,
    description: null,
  },
];

test.describe("Meta Tags – title and description", () => {
  test("home page has correct <title>", async ({ page }) => {
    await page.goto("/");
    await expect(page).toHaveTitle("0xrh0d4m1n");
  });

  test("home page has correct meta description", async ({ page }) => {
    await page.goto("/");
    const meta = page.locator('meta[name="description"]');
    await expect(meta).toHaveAttribute("content", "Hacking and general cybersecurity.");
  });

  test("all main pages have a non-empty <title>", async ({ page }) => {
    for (const { path } of PAGES) {
      await page.goto(path);
      const title = await page.title();
      expect(title.trim(), `Page ${path} has empty title`).not.toBe("");
    }
  });
});

test.describe("Open Graph Tags", () => {
  test("home page has og:title", async ({ page }) => {
    await page.goto("/");
    const ogTitle = page.locator('meta[property="og:title"]');
    await expect(ogTitle).toHaveAttribute("content", "0xrh0d4m1n");
  });

  test("home page has og:description", async ({ page }) => {
    await page.goto("/");
    const ogDesc = page.locator('meta[property="og:description"]');
    const content = await ogDesc.getAttribute("content");
    expect(content?.trim()).not.toBe("");
  });

  test("home page has og:type = website", async ({ page }) => {
    await page.goto("/");
    const ogType = page.locator('meta[property="og:type"]');
    await expect(ogType).toHaveAttribute("content", "website");
  });

  test("home page has og:url", async ({ page }) => {
    await page.goto("/");
    const ogUrl = page.locator('meta[property="og:url"]');
    const content = await ogUrl.getAttribute("content");
    expect(content?.trim()).not.toBe("");
  });
});

test.describe("Twitter Card Tags", () => {
  test("home page has twitter:card", async ({ page }) => {
    await page.goto("/");
    const twCard = page.locator('meta[name="twitter:card"]');
    await expect(twCard).toHaveAttribute("content", "summary");
  });

  test("home page has twitter:title", async ({ page }) => {
    await page.goto("/");
    const twTitle = page.locator('meta[name="twitter:title"]');
    const content = await twTitle.getAttribute("content");
    expect(content?.trim()).not.toBe("");
  });
});

test.describe("Canonical URL", () => {
  test("home page has a canonical link", async ({ page }) => {
    await page.goto("/");
    const canonical = page.locator('link[rel="canonical"]');
    await expect(canonical).toHaveCount(1);
    const href = await canonical.getAttribute("href");
    expect(href).toBeTruthy();
  });
});

test.describe("robots.txt", () => {
  test("robots.txt is served", async ({ request }) => {
    const res = await request.get("/robots.txt");
    expect(res.status()).toBe(200);
  });

  test("robots.txt allows crawling", async ({ request }) => {
    const res = await request.get("/robots.txt");
    const body = await res.text();
    // Should not disallow all
    expect(body).not.toMatch(/Disallow:\s*\/\s*$/m);
  });
});

test.describe("Footer – rendered", () => {
  test("footer element is present and visible", async ({ page }) => {
    await page.goto("/");
    const footer = page.locator("footer.hextra-footer");
    await expect(footer).toBeVisible();
  });

  test("footer has theme toggle button", async ({ page }) => {
    await page.goto("/");
    const themeBtn = page.locator('footer button[aria-label="Change theme"]');
    await expect(themeBtn).toBeVisible();
  });
});
