import { test, expect } from "@playwright/test";
import * as fs from "fs";
import * as path from "path";

/**
 * Expected HackTheBox colors for dark theme (from data/theme.json darkmode).
 */
const HTB_DARK_HEX = [
  "#9FEF00",
  "#0d1117",
  "#161b22",
  "#21262d",
  "#c9d1d9",
  "#8b949e",
] as const;

test.describe("Dark theme — HackTheBox colors", () => {
  test("data/theme.json defines HackTheBox dark mode colors", () => {
    const themePath = path.join(process.cwd(), "data", "theme.json");
    const raw = fs.readFileSync(themePath, "utf8");
    const theme = JSON.parse(raw);
    expect(theme.colors?.darkmode?.theme_color?.primary).toBe("#9FEF00");
    expect(theme.colors?.darkmode?.theme_color?.body).toBe("#0d1117");
    expect(theme.colors?.darkmode?.theme_color?.border).toBe("#21262d");
    expect(theme.colors?.darkmode?.theme_color?.light).toBe("#161b22");
    expect(theme.colors?.darkmode?.text_color?.text).toBe("#c9d1d9");
    expect(theme.colors?.darkmode?.text_color?.text_dark).toBe("#ffffff");
    expect(theme.colors?.darkmode?.text_color?.text_light).toBe("#8b949e");
    expect(theme.colors?.darkmode?.theme_color?.dark).toBe("#ffffff");
  });

  test("generated-theme.css (after build) contains HackTheBox hex values", () => {
    const generatedPath = path.join(
      process.cwd(),
      "themes",
      "hugoplate",
      "assets",
      "css",
      "generated-theme.css",
    );
    expect(fs.existsSync(generatedPath)).toBe(true);
    const css = fs.readFileSync(generatedPath, "utf8");
    for (const hex of HTB_DARK_HEX) {
      expect(css, `generated-theme.css should contain ${hex}`).toContain(hex);
    }
  });

  test("built site CSS (served) includes HackTheBox dark theme colors", async ({
    page,
    request,
  }) => {
    await page.goto("/");
    const mainCssLink = page.locator(
      'link[rel="stylesheet"][href*="/css/style"]:not([href*="lazy"])',
    ).first();
    await expect(mainCssLink).toBeAttached();
    const href = await mainCssLink.getAttribute("href");
    expect(href).toBeTruthy();
    const base = new URL(page.url()).origin;
    const url = href!.startsWith("http") ? href! : `${base}${href}`;
    const res = await request.get(url);
    expect(res.ok()).toBe(true);
    const cssText = await res.text();
    for (const hex of HTB_DARK_HEX) {
      expect(cssText, `Served CSS should contain ${hex}`).toContain(hex);
    }
  });

  test("dark mode: adding .dark to html does not break page; theme switcher exists", async ({
    page,
  }) => {
    await page.goto("/");
    await page.evaluate(() =>
      document.documentElement.classList.add("dark"),
    );
    await page.waitForTimeout(100);
    await expect(page.locator("body")).toBeVisible();
    const themeSwitcher = page.locator("#theme-switcher, [aria-label*='theme'], .theme-switcher").first();
    await expect(themeSwitcher).toBeAttached();
  });
});
