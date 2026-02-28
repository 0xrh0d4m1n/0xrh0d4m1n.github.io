import { test, expect } from "@playwright/test";

/**
 * Smoke tests — validates every main page returns HTTP 200 and renders without errors.
 * Run these first; if any of these fail, everything else is pointless.
 */

const MAIN_PAGES = [
  { name: "Home", path: "/" },
  { name: "About", path: "/about/" },
  { name: "Skills", path: "/skills/" },
  { name: "Blog", path: "/blog/" },
  { name: "Writeups", path: "/writeups/" },
  { name: "Codex", path: "/codex/" },
  { name: "Toolbox", path: "/toolbox/" },
  { name: "Glossary", path: "/glossary/" },
];

const WRITEUPS_PAGES = [
  { name: "Writeups – Red Team", path: "/writeups/redteam/" },
  { name: "Writeups – Blue Team", path: "/writeups/blueteam/" },
  { name: "Writeups – Web", path: "/writeups/web/" },
  { name: "Writeups – HTB", path: "/writeups/redteam/htb/" },
  { name: "Writeups – THM", path: "/writeups/redteam/thm/" },
  { name: "Writeups – VulnHub", path: "/writeups/redteam/vulnhub/" },
  { name: "Writeups – CyberDefenders", path: "/writeups/blueteam/cyberdefenders/" },
  { name: "Writeups – LetsDefend", path: "/writeups/blueteam/letsdefend/" },
  { name: "Writeups – PortSwigger", path: "/writeups/web/portswigger/" },
];

const CODEX_PAGES = [
  { name: "Codex – Systems", path: "/codex/systems/" },
  { name: "Codex – Networking", path: "/codex/networking/" },
  { name: "Codex – Protocols", path: "/codex/protocols/" },
  { name: "Codex – SOC", path: "/codex/soc/" },
  { name: "Codex – Programming", path: "/codex/programming/" },
  { name: "Codex – Infra", path: "/codex/infra/" },
];

test.describe("Smoke – HTTP 200 for every page", () => {
  for (const { name, path } of MAIN_PAGES) {
    test(`${name} (${path}) returns 200`, async ({ request }) => {
      const res = await request.get(path);
      expect(res.status(), `${name} returned ${res.status()}`).toBe(200);
    });
  }

  for (const { name, path } of WRITEUPS_PAGES) {
    test(`${name} (${path}) returns 200`, async ({ request }) => {
      const res = await request.get(path);
      expect(res.status(), `${name} returned ${res.status()}`).toBe(200);
    });
  }

  for (const { name, path } of CODEX_PAGES) {
    test(`${name} (${path}) returns 200`, async ({ request }) => {
      const res = await request.get(path);
      expect(res.status(), `${name} returned ${res.status()}`).toBe(200);
    });
  }
});

test.describe("Smoke – Pages render visible content", () => {
  for (const { name, path } of MAIN_PAGES) {
    test(`${name} renders navbar and main content`, async ({ page }) => {
      await page.goto(path);
      // Hextra renders the top navbar inside .nav-container
      await expect(page.locator(".nav-container").first()).toBeVisible();
      // Hextra wraps page content in <article> → <main> → .content
      await expect(page.locator("main .content, main").first()).toBeVisible();
    });
  }
});

test.describe("Smoke – No console errors on main pages", () => {
  for (const { name, path } of MAIN_PAGES) {
    test(`${name} has no JS console errors`, async ({ page }) => {
      const errors: string[] = [];
      page.on("console", (msg) => {
        if (msg.type() === "error") errors.push(msg.text());
      });
      await page.goto(path);
      // Wait for page to fully settle
      await page.waitForLoadState("networkidle");
      expect(errors, `JS errors on ${name}: ${errors.join(", ")}`).toHaveLength(0);
    });
  }
});
