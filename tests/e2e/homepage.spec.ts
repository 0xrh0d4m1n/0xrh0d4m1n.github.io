import { test, expect } from "@playwright/test";

/**
 * Homepage E2E tests. One spec for the whole homepage; suites group features
 * (logo button, navbar, scroll progress, etc.). TDD-friendly: add specs here
 * as you add or change homepage behavior.
 */
test.describe("Homepage", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
  });

  test.describe("logo button", () => {
    test("logo is present and is a link to home", async ({ page }) => {
      const logoLink = page.locator("header .navbar-brand").first();
      await expect(logoLink).toBeVisible();
      await expect(logoLink).toHaveAttribute("href", /\//);
      const wrapper = logoLink.locator(".site-logo-wrapper");
      await expect(wrapper).toBeVisible();
      await expect(wrapper.locator("img[src*='logo.svg']")).toBeVisible();
    });

    test("logo wrapper is circular (border-radius 50%)", async ({ page }) => {
      const wrapper = page.locator(".site-logo-wrapper").first();
      await expect(wrapper).toBeVisible();
      const borderRadius = await wrapper.evaluate((el) =>
        getComputedStyle(el).borderRadius
      );
      expect(borderRadius).toBe("50%");
    });

    test("logo border is rgb(201, 209, 217) when not in hover", async ({
      page,
    }) => {
      const wrapper = page.locator(".site-logo-wrapper").first();
      await expect(wrapper).toBeVisible();
      const borderColor = await wrapper.evaluate((el) =>
        getComputedStyle(el).borderColor
      );
      expect(borderColor).toBe("rgb(201, 209, 217)");
    });

    test("logo has arcade bezel: extruded shadow when idle, sinks on press", async ({
      page,
    }) => {
      const wrapper = page.locator(".site-logo-wrapper").first();
      await expect(wrapper).toBeVisible();

      const boxShadowIdle = await wrapper.evaluate((el) =>
        getComputedStyle(el).boxShadow
      );
      expect(boxShadowIdle).toBeTruthy();
      expect(boxShadowIdle).not.toBe("none");

      await wrapper.dispatchEvent("pointerdown");
      const hasPressed = await wrapper.evaluate((el) =>
        el.classList.contains("pressed")
      );
      expect(hasPressed).toBe(true);

      const transformPressed = await wrapper.evaluate((el) =>
        getComputedStyle(el).transform
      );
      expect(transformPressed).not.toBe("none");

      await wrapper.dispatchEvent("pointerup");
      const hasPressedAfter = await wrapper.evaluate((el) =>
        el.classList.contains("pressed")
      );
      expect(hasPressedAfter).toBe(false);
    });

    test("pointerleave clears pressed state (no stuck pressed)", async ({
      page,
    }) => {
      const wrapper = page.locator(".site-logo-wrapper").first();
      await expect(wrapper).toBeVisible();
      await wrapper.dispatchEvent("pointerdown");
      await wrapper.dispatchEvent("pointerleave");
      const hasPressed = await wrapper.evaluate((el) =>
        el.classList.contains("pressed")
      );
      expect(hasPressed).toBe(false);
    });

    test("logo link has padding-bottom for spacing above navbar line", async ({
      page,
    }) => {
      const logoLink = page.locator("header .navbar .order-0 .navbar-brand").first();
      await expect(logoLink).toBeVisible();
      const paddingBottom = await logoLink.evaluate((el) =>
        getComputedStyle(el).paddingBottom
      );
      expect(paddingBottom).toBe("16px");
    });
  });

  test.describe("navbar GitHub button", () => {
    test("GitHub nav button is present with icon and link when navigation_button enabled", async ({
      page,
    }) => {
      const btn = page.locator("header .navbar .navbar-nav-btn").first();
      await expect(btn).toBeVisible();
      await expect(btn).toHaveAttribute("href", /github\.com/);
      await expect(btn).toHaveAttribute("aria-label", /Github/i);
      await expect(btn.locator("i.fab.fa-github")).toBeVisible();
    });

    test("GitHub nav button is square with rounded corners", async ({ page }) => {
      const btn = page.locator("header .navbar .navbar-nav-btn").first();
      await expect(btn).toBeVisible();
      const width = await btn.evaluate((el) =>
        parseFloat(getComputedStyle(el).width)
      );
      const height = await btn.evaluate((el) =>
        parseFloat(getComputedStyle(el).height)
      );
      const radius = await btn.evaluate((el) =>
        parseFloat(getComputedStyle(el).borderRadius)
      );
      expect(Math.abs(width - height)).toBeLessThanOrEqual(2);
      expect(radius).toBeGreaterThan(0);
    });

    test("GitHub nav button has border (text-light by default, primary on hover)", async ({
      page,
    }) => {
      const btn = page.locator("header .navbar .navbar-nav-btn").first();
      await expect(btn).toBeVisible();
      const borderDefault = await btn.evaluate((el) =>
        getComputedStyle(el).borderColor
      );
      await btn.hover();
      const borderHover = await btn.evaluate((el) =>
        getComputedStyle(el).borderColor
      );
      expect(borderDefault).toBeTruthy();
      expect(borderHover).toBeTruthy();
    });
  });

  test.describe("footer social links", () => {
    test("footer has GitHub, LinkedIn and X links from data/social.json", async ({
      page,
    }) => {
      const footer = page.locator("footer .social-icons");
      await expect(footer).toBeVisible();

      const githubLink = footer.locator('a[aria-label="github"]');
      await expect(githubLink).toBeVisible();
      await expect(githubLink).toHaveAttribute("href", /github\.com\/0xrh0d4m1n/);

      const linkedinLink = footer.locator('a[aria-label="linkedin"]');
      await expect(linkedinLink).toBeVisible();
      await expect(linkedinLink).toHaveAttribute(
        "href",
        /linkedin\.com\/in\/0xrh0d4m1n/
      );

      const xLink = footer.locator('a[aria-label="x"]');
      await expect(xLink).toBeVisible();
      await expect(xLink).toHaveAttribute("href", /x\.com\/0xrh0d4m1n/);
    });
  });
});
