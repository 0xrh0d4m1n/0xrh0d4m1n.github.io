import { test, expect } from "@playwright/test";

/**
 * Asset tests — validates that static files (favicons, logo, compiled CSS) are served correctly.
 * CSS is now compiled from SCSS via Hugo Pipes: assets/scss/main.scss → /scss/main.css
 */

const STATIC_ASSETS = [
  { name: "favicon.svg",       path: "/favicon.svg",          type: "image/svg+xml" },
  { name: "favicon-dark.svg",  path: "/favicon-dark.svg",     type: "image/svg+xml" },
  { name: "logo.svg",          path: "/img/logos/logo.svg",   type: "image/svg+xml" },
  { name: "site.webmanifest",  path: "/site.webmanifest",     type: "application/manifest+json" },
];

test.describe("Static Assets – HTTP 200 and correct content-type", () => {
  for (const { name, path, type } of STATIC_ASSETS) {
    test(`${name} is served (200) with content-type ${type}`, async ({ request }) => {
      const res = await request.get(path);
      expect(res.status(), `${name} returned ${res.status()}`).toBe(200);
      expect(res.headers()["content-type"]).toContain(type.split("/")[0]);
    });
  }
});

test.describe("Favicon – declared in <head>", () => {
  test("favicon.svg is referenced in <head>", async ({ page }) => {
    await page.goto("/");
    const svgFavicon = page.locator('link[rel="icon"][href="/favicon.svg"]');
    await expect(svgFavicon).toHaveCount(1);
  });

  test("dark favicon is referenced in <head>", async ({ page }) => {
    await page.goto("/");
    const darkFavicon = page.locator('link[href="/favicon-dark.svg"]');
    await expect(darkFavicon).toHaveCount(1);
  });

  test("site.webmanifest is linked in <head>", async ({ page }) => {
    await page.goto("/");
    const manifest = page.locator('link[rel="manifest"]');
    await expect(manifest).toHaveCount(1);
  });
});

test.describe("Logo – visible in navbar", () => {
  test("logo image is visible in desktop navbar", async ({ page }) => {
    await page.goto("/");
    // In dark mode (default), Hextra shows the second logo img (dark:hx-block)
    const logo = page.locator('nav img[src="/img/logos/logo.svg"]').last();
    await expect(logo).toBeVisible();
  });

  test("logo alt text is set correctly", async ({ page }) => {
    await page.goto("/");
    const logo = page.locator('nav img[alt="0xrh0d4m1n"]').last();
    await expect(logo).toBeVisible();
  });

  test("logo links to home page", async ({ page }) => {
    await page.goto("/about/");
    const logoLink = page.locator('nav a[href="/"]').first();
    await logoLink.click();
    await expect(page).toHaveURL("/");
  });
});

test.describe("Hero Image – visible on home page", () => {
  test("Conway's Game of Life hero image loads", async ({ page }) => {
    await page.goto("/");
    const heroImg = page.locator('img[alt="Conway\'s Game of Life"]');
    await expect(heroImg).toBeVisible();
    const loaded = await heroImg.evaluate(
      (img: HTMLImageElement) => img.naturalWidth > 0,
    );
    expect(loaded, "Hero image failed to load (naturalWidth = 0)").toBe(true);
  });
});

test.describe("CSS – SCSS pipeline output applied", () => {
  test("Hextra compiled Tailwind CSS is loaded", async ({ page }) => {
    await page.goto("/");
    // Hextra serves /css/compiled/main*.css — 1 link in dev, 2 (preload+link) in production
    const mainCss = page.locator('link[href*="compiled/main"]');
    const count = await mainCss.count();
    expect(count, "Expected at least 1 Hextra CSS link").toBeGreaterThanOrEqual(1);
  });

  test("custom SCSS is compiled and loaded (non-empty)", async ({ page, request }) => {
    await page.goto("/");
    // Our SCSS is compiled via head-end.html hook and fingerprinted
    const scssLink = page.locator('link[rel="stylesheet"][href*="custom.min"]').last();
    await expect(scssLink).toHaveCount(1);
    // Fetch the CSS file and verify it has actual content
    const href = await scssLink.getAttribute("href");
    if (href) {
      const res = await request.get(href);
      expect(res.status()).toBe(200);
      const body = await res.text();
      expect(body.length, "Custom SCSS compiled to empty CSS").toBeGreaterThan(100);
    }
  });

  test(".social-links component styles are applied (not inline)", async ({ page }) => {
    await page.goto("/skills/");
    const socialLinks = page.locator(".social-links");
    await expect(socialLinks).toHaveCount(1);
    // Verify there are no remnant style= attributes on the container
    const styleAttr = await socialLinks.getAttribute("style");
    expect(styleAttr).toBeNull();
  });

  test(".social-link icons have correct dimensions via CSS", async ({ page }) => {
    await page.goto("/skills/");
    const firstIcon = page.locator(".social-link svg").first();
    await expect(firstIcon).toBeVisible();
    const box = await firstIcon.boundingBox();
    expect(box?.width).toBeGreaterThanOrEqual(18);
    expect(box?.height).toBeGreaterThanOrEqual(18);
  });
});
