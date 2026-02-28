import { test, expect } from "@playwright/test";

/**
 * Theme tests — validates dark/light mode toggle behavior.
 * Hextra sets `class="dark"` on <html> and uses localStorage key "color-theme".
 */

test.describe("Default Theme – dark mode", () => {
  test("page loads in dark mode by default", async ({ page }) => {
    await page.goto("/");
    // Default is "dark" per hugo.toml params.theme.default = "dark"
    const htmlClass = await page.locator("html").getAttribute("class");
    expect(htmlClass, "Expected 'dark' in html class").toContain("dark");
  });

  test("color-scheme is 'dark' by default", async ({ page }) => {
    await page.goto("/");
    const colorScheme = await page.locator("html").evaluate(
      (el) => el.style.colorScheme,
    );
    expect(colorScheme).toBe("dark");
  });
});

test.describe("Theme Toggle – switching modes", () => {
  test("theme toggle button is visible in footer", async ({ page }) => {
    await page.goto("/");
    // Hextra renders the theme toggle in the footer (always visible on desktop)
    // The sidebar toggle is hidden at md+ breakpoints
    const themeToggle = page.locator('footer button[aria-label="Change theme"]');
    await expect(themeToggle).toBeVisible();
  });

  test("clicking theme toggle switches to light mode", async ({ page }) => {
    await page.goto("/");
    // Use the footer theme toggle which is always visible on desktop
    const themeBtn = page.locator('footer button[aria-label="Change theme"]');
    await expect(themeBtn).toBeVisible();
    await themeBtn.click();
    // After click, dark class should be removed
    const htmlClass = await page.locator("html").getAttribute("class");
    expect(htmlClass ?? "", "Expected dark mode to turn off").not.toContain("dark");
  });

  test("theme preference is persisted in localStorage", async ({ page }) => {
    await page.goto("/");
    // Manually set light theme via localStorage
    await page.evaluate(() => {
      localStorage.setItem("color-theme", "light");
    });
    await page.reload();
    const htmlClass = await page.locator("html").getAttribute("class");
    expect(htmlClass ?? "", "Expected light mode after reload").not.toContain("dark");
  });

  test("dark theme preference persists across pages", async ({ page }) => {
    await page.goto("/");
    // Ensure dark mode is on (default)
    const isDark = await page.locator("html").evaluate(
      (el) => el.classList.contains("dark"),
    );
    expect(isDark).toBe(true);
    // Navigate to another page
    await page.goto("/about/");
    const stillDark = await page.locator("html").evaluate(
      (el) => el.classList.contains("dark"),
    );
    expect(stillDark, "Dark mode should persist across navigation").toBe(true);
  });
});
