import { test, expect } from "@playwright/test";

/**
 * Search tests — validates the Hextra search widget.
 *
 * NOTE: In Hextra, the search input lives inside the sidebar which uses
 * `md:hx-hidden` (hidden at ≥768px desktop). Tests that interact with the
 * input use a mobile viewport so the sidebar and search are naturally visible.
 */

test.describe("Search – input present", () => {
  test("search input is in the DOM", async ({ page }) => {
    await page.goto("/");
    const input = page.locator('input[type="search"].search-input');
    await expect(input).toHaveCount(1);
  });

  test("search input placeholder is 'Search...'", async ({ page }) => {
    await page.goto("/");
    const input = page.locator('input[type="search"].search-input').first();
    await expect(input).toHaveAttribute("placeholder", "Search...");
  });

  test("Ctrl+K hint exists in the DOM", async ({ page, isMobile }) => {
    // Touch devices have no physical keyboard so the hint is not rendered
    test.skip(isMobile, "Ctrl+K hint not applicable on touch/mobile browsers");
    await page.goto("/");
    const kbd = page.locator("kbd").filter({ hasText: /ctrl\s*k/i });
    await expect(kbd.first()).toBeAttached();
  });
});

test.describe("Search – keyboard shortcut Ctrl+K", () => {
  // Use mobile viewport where the sidebar search is accessible
  test.use({ viewport: { width: 390, height: 844 } });

  test("opening sidebar exposes search input", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    const burger = page.locator('button[aria-label="Menu"]');
    await burger.click();
    await page.waitForTimeout(300);
    const input = page.locator('input[type="search"].search-input').first();
    await expect(input).toBeVisible();
  });
});

test.describe("Search – typing a query", () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test("typing 'linux' populates the search input", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await page.locator('button[aria-label="Menu"]').click();
    await page.waitForTimeout(300);
    const input = page.locator('input[type="search"].search-input').first();
    await input.click();
    await input.fill("linux");
    await page.waitForTimeout(800);
    await expect(input).toHaveValue("linux");
  });

  test("clearing search input restores empty state", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await page.locator('button[aria-label="Menu"]').click();
    await page.waitForTimeout(300);
    const input = page.locator('input[type="search"].search-input').first();
    await input.click();
    await input.fill("hacking");
    await page.waitForTimeout(400);
    await input.fill("");
    await page.waitForTimeout(200);
    await expect(input).toHaveValue("");
  });
});
