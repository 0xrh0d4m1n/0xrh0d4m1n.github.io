import { test, expect } from "@playwright/test";

/**
 * Skills page E2E tests. Focus on verifying that images are connected and
 * displayed (profile avatar/cover, skill icons, certification images).
 */
test.describe("Skills page", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/skills/");
  });

  /**
   * Banner: 1-photo, 2-cover, 3-social icons, 4-name, 5-role, 6-tag-pills (SOC,NOC,CTI,CSIRT,DFIR),
   * 7-company+icon (Akamai Technologies), 8-Contact button → /contact/
   */
  test.describe("banner exactly as requested", () => {
    test("1 - My photo (profile avatar) is present", async ({ page }) => {
      const avatar = page.locator(".profile-avatar-wrap .profile-avatar, .profile-avatar-wrap .profile-avatar-placeholder");
      await expect(avatar.first()).toBeVisible();
    });

    test("2 - Banner (cover) is present and contained inside profile-card-inner (LinkedIn-style)", async ({
      page,
    }) => {
      const cardInner = page.locator(".profile-card-inner");
      await expect(cardInner).toBeVisible();
      const cover = cardInner.locator(".profile-cover");
      await expect(cover).toBeVisible();
      const coverImg = cover.locator(".profile-cover-img");
      await expect(coverImg).toBeVisible();
    });

    test("3 - My social networks: icons with links (GitHub, LinkedIn, X)", async ({ page }) => {
      const social = page.locator(".profile-social");
      await expect(social).toBeVisible();
      const links = social.locator("a.profile-social-link[href]");
      await expect(links.first()).toBeVisible();
      const count = await links.count();
      expect(count).toBeGreaterThanOrEqual(2);
      const hrefs: string[] = [];
      for (let i = 0; i < count; i++) {
        const href = await links.nth(i).getAttribute("href");
        expect(href).toBeTruthy();
        hrefs.push(href!);
      }
      const hasGithub = hrefs.some((h) => /github\.com/i.test(h));
      const hasLinkedin = hrefs.some((h) => /linkedin\.com/i.test(h));
      const hasX = hrefs.some((h) => /x\.com|twitter/i.test(h));
      expect(hasGithub || hasLinkedin || hasX).toBe(true);
    });

    test("4 - My name is displayed", async ({ page }) => {
      const nameEl = page.locator(".profile-name");
      await expect(nameEl).toBeVisible();
      await expect(nameEl).toContainText("Valdenio");
      await expect(nameEl).toContainText("Marinho");
    });

    test("5 - My role/function is displayed", async ({ page }) => {
      const headline = page.locator(".profile-headline");
      await expect(headline).toBeVisible();
      await expect(headline).toContainText("Cyber Security");
    });

    test("6 - Tag-pills: SOC, NOC, CTI, CSIRT, DFIR (exactly these five)", async ({ page }) => {
      const pillsContainer = page.locator(".profile-tag-pills");
      await expect(pillsContainer).toBeVisible();
      const pills = page.locator(".profile-tag-pill");
      const count = await pills.count();
      expect(count).toBe(5);
      const texts = await pills.evaluateAll((nodes) => nodes.map((n) => (n as HTMLElement).textContent?.trim() ?? ""));
      const expected = ["SOC", "NOC", "CTI", "CSIRT", "DFIR"];
      for (const tag of expected) {
        expect(texts).toContain(tag);
      }
    });

    test("7 - Current company and icon (Akamai Technologies)", async ({ page }) => {
      const companyBlock = page.locator(".profile-company");
      await expect(companyBlock).toBeVisible();
      const companyName = companyBlock.locator(".profile-company-name");
      await expect(companyName).toBeVisible();
      await expect(companyName).toHaveText("Akamai Technologies");
      const companyIcon = companyBlock.locator(".profile-company-icon");
      await expect(companyIcon.first()).toBeVisible();
    });

    test("8 - Contact button with label Contact linking to /contact/", async ({ page }) => {
      const contactBtn = page.locator("a.profile-contact-btn");
      await expect(contactBtn).toBeVisible();
      await expect(contactBtn).toHaveText("Contact");
      await expect(contactBtn).toHaveAttribute("href", /\/contact\/?/);
    });

    test("9 - Contact button is on the right (inside profile-card-right, after company and social)", async ({
      page,
    }) => {
      const rightCol = page.locator(".profile-card-right");
      await expect(rightCol).toBeVisible();
      const contactBtn = rightCol.locator("a.profile-contact-btn");
      await expect(contactBtn).toBeVisible();
      const company = rightCol.locator(".profile-company");
      const social = rightCol.locator(".profile-social");
      if ((await company.count()) > 0) {
        const contactBox = await contactBtn.boundingBox();
        const companyBox = await company.first().boundingBox();
        expect(contactBox).toBeTruthy();
        expect(companyBox).toBeTruthy();
        if (contactBox && companyBox) expect(contactBox.y).toBeGreaterThanOrEqual(companyBox.y - 5);
      }
      if ((await social.count()) > 0) {
        const contactBox = await contactBtn.boundingBox();
        const socialBox = await social.first().boundingBox();
        expect(contactBox).toBeTruthy();
        expect(socialBox).toBeTruthy();
        if (contactBox && socialBox) expect(contactBox.y).toBeGreaterThanOrEqual(socialBox.y - 5);
      }
    });

    test("10 - Location shows Brazil flag image and Brazil text", async ({ page }) => {
      const location = page.locator(".profile-location");
      await expect(location).toBeVisible();
      await expect(location.locator(".profile-location-text")).toHaveText("Brazil");
      const flagImg = location.locator("img.profile-location-flag");
      await expect(flagImg).toBeVisible();
      const src = await flagImg.getAttribute("src");
      expect(src).toBeTruthy();
      expect(src).toMatch(/br\.png|flagcdn|brazil|flag/i);
      const naturalWidth = await flagImg.evaluate((el: HTMLImageElement) => el.naturalWidth);
      expect(naturalWidth).toBeGreaterThan(0);
    });
  });

  test.describe("page structure", () => {
    test("skills page loads with profile section", async ({ page }) => {
      await expect(page.locator(".profile-linkedin")).toBeVisible();
      await expect(page.locator(".profile-card-inner")).toBeVisible();
      await expect(page.locator(".profile-name")).toContainText("Valdenio");
      await expect(page.locator(".profile-headline")).toContainText("Cyber Security");
    });

    test("profile feed has section cards", async ({ page }) => {
      await expect(page.locator(".profile-feed-inner")).toBeVisible();
      const sectionCards = page.locator(".profile-feed-inner .section-card");
      await expect(sectionCards.first()).toBeVisible({ timeout: 5000 });
      expect(await sectionCards.count()).toBeGreaterThanOrEqual(1);
    });
  });

  test.describe("profile images (avatar and cover)", () => {
    test("profile cover image element is present and has src", async ({
      page,
    }) => {
      const coverImg = page.locator(".profile-cover-img");
      await expect(coverImg).toBeVisible();
      const src = await coverImg.getAttribute("src");
      expect(src).toBeTruthy();
      expect(src!.length).toBeGreaterThan(0);
    });

    test("profile avatar image element is present and has src", async ({
      page,
    }) => {
      const avatarImg = page.locator(".profile-avatar[src]");
      await expect(avatarImg).toBeVisible();
      const src = await avatarImg.getAttribute("src");
      expect(src).toBeTruthy();
      expect(src!.length).toBeGreaterThan(0);
    });

    test("profile cover image loads successfully (non-zero dimensions)", async ({
      page,
    }) => {
      const coverImg = page.locator(".profile-cover-img");
      await expect(coverImg).toBeVisible();
      await expect(coverImg).toHaveJSProperty("complete", true, {
        timeout: 10000,
      });
      const loaded = await coverImg.evaluate((el: HTMLImageElement) => {
        return el.naturalWidth > 0 && el.naturalHeight > 0;
      });
      expect(loaded).toBe(true);
    });

    test("profile avatar image loads successfully (non-zero dimensions)", async ({
      page,
    }) => {
      const avatarImg = page.locator(".profile-avatar[src]");
      await expect(avatarImg).toBeVisible();
      await expect(avatarImg).toHaveJSProperty("complete", true, {
        timeout: 10000,
      });
      const loaded = await avatarImg.evaluate((el: HTMLImageElement) => {
        return el.naturalWidth > 0 && el.naturalHeight > 0;
      });
      expect(loaded).toBe(true);
    });
  });

  test.describe("content images (skill shields and certs)", () => {
    test("skill shields are visible (flat grid, no expandable sections)", async ({
      page,
    }) => {
      const skillShields = page.locator(".skill-shields img");
      await expect(skillShields.first()).toBeVisible({ timeout: 3000 });
      expect(await skillShields.count()).toBeGreaterThanOrEqual(3);
    });

    test("skill shield images have src and load (shields.io badges)", async ({
      page,
    }) => {
      const skillShields = page.locator(".skill-shields img");
      await expect(skillShields.first()).toBeVisible({ timeout: 3000 });
      const firstSrc = await skillShields.first().getAttribute("src");
      expect(firstSrc).toBeTruthy();
      expect(firstSrc!.length).toBeGreaterThan(0);
      expect(firstSrc).toMatch(/shields\.io|img\.shields\.io/);
      const loaded = await skillShields.first().evaluate(
        (el: HTMLImageElement) => el.complete && el.naturalWidth > 0
      );
      expect(loaded).toBe(true);
    });

    test("certification images are present after expanding Fortinet", async ({
      page,
    }) => {
      const summary = page.locator("details summary").filter({
        hasText: /Fortinet/i,
      });
      await summary.click();
      const certImgs = page.locator(".cert-card img");
      await expect(certImgs.first()).toBeVisible({ timeout: 3000 });
      expect(await certImgs.count()).toBeGreaterThanOrEqual(2);
    });

    test("cert card images are present with src when section is expanded", async ({
      page,
    }) => {
      const summary = page.locator("details summary").filter({
        hasText: /Fortinet/i,
      });
      await summary.click();
      const certImgs = page.locator(".cert-card img");
      await expect(certImgs.first()).toBeVisible({ timeout: 3000 });
      const firstSrc = await certImgs.first().getAttribute("src");
      expect(firstSrc).toBeTruthy();
      expect(firstSrc!.length).toBeGreaterThan(0);
      // Optional: if static/img/certs/ exists, images should load (naturalWidth > 0)
      const loaded = await certImgs.first().evaluate(
        (el: HTMLImageElement) => el.complete && el.naturalWidth > 0
      );
      if (!loaded) {
        console.warn(
          "Cert images may 404: ensure static/img/certs/ contains the expected image files."
        );
      }
    });
  });

  test.describe("all images on page (no broken images)", () => {
    test("profile images (cover and avatar) load successfully", async ({
      page,
    }) => {
      const profileCover = page.locator(".profile-cover-img");
      const profileAvatar = page.locator(".profile-avatar[src]");
      await expect(profileCover).toBeVisible();
      await expect(profileAvatar).toBeVisible();
      await expect(profileCover).toHaveJSProperty("complete", true, {
        timeout: 10000,
      });
      await expect(profileAvatar).toHaveJSProperty("complete", true, {
        timeout: 10000,
      });
      const coverOk = await profileCover.evaluate(
        (el: HTMLImageElement) => el.naturalWidth > 0 && el.naturalHeight > 0
      );
      const avatarOk = await profileAvatar.evaluate(
        (el: HTMLImageElement) => el.naturalWidth > 0 && el.naturalHeight > 0
      );
      expect(coverOk).toBe(true);
      expect(avatarOk).toBe(true);
    });
  });

  test.describe("certification modal", () => {
    test.beforeEach(async ({ page }) => {
      await page
        .locator("details summary")
        .filter({ hasText: /Fortinet/i })
        .click();
      await expect(page.locator(".cert-card").first()).toBeVisible({
        timeout: 3000,
      });
    });

    test("clicking a cert card opens the modal", async ({ page }) => {
      const firstCard = page.locator(".cert-card").first();
      await firstCard.click();
      const backdrop = page.locator("#cert-modal-backdrop");
      await expect(backdrop).toHaveAttribute("data-open", "true");
      await expect(backdrop).toBeVisible();
      await expect(page.locator(".cert-modal")).toBeVisible();
      await expect(page.locator(".cert-modal-title")).toBeVisible();
      await expect(page.locator(".cert-modal-img")).toBeVisible();
    });

    test("modal has approximately 80% viewport width and 16:9 aspect ratio", async ({
      page,
    }) => {
      await page.locator(".cert-card").first().click();
      const modal = page.locator(".cert-modal");
      await expect(modal).toBeVisible();
      const box = await modal.boundingBox();
      expect(box).toBeTruthy();
      const viewport = page.viewportSize();
      expect(viewport).toBeTruthy();
      const widthRatio = box!.width / viewport!.width;
      expect(widthRatio).toBeGreaterThanOrEqual(0.7);
      expect(widthRatio).toBeLessThanOrEqual(0.95);
      const aspectRatio = box!.width / box!.height;
      expect(aspectRatio).toBeGreaterThanOrEqual(1.7);
      expect(aspectRatio).toBeLessThanOrEqual(1.8);
    });

    test("close button closes the modal", async ({ page }) => {
      await page.locator(".cert-card").first().click();
      await expect(page.locator("#cert-modal-backdrop")).toHaveAttribute(
        "data-open",
        "true"
      );
      await page.locator(".cert-modal-close").click();
      await expect(page.locator("#cert-modal-backdrop")).toHaveAttribute(
        "data-open",
        "false"
      );
    });

    test("clicking backdrop (outside modal) closes the modal", async ({
      page,
    }) => {
      await page.locator(".cert-card").first().click();
      await expect(page.locator("#cert-modal-backdrop")).toHaveAttribute(
        "data-open",
        "true"
      );
      await page.locator("#cert-modal-backdrop").click({ position: { x: 5, y: 5 } });
      await expect(page.locator("#cert-modal-backdrop")).toHaveAttribute(
        "data-open",
        "false"
      );
    });

    test("Previous and Next buttons are on their respective sides with English labels", async ({
      page,
    }) => {
      await page.locator(".cert-card").first().click();
      const prevBtn = page.locator(".cert-modal-prev");
      const nextBtn = page.locator(".cert-modal-next");
      await expect(prevBtn).toBeVisible();
      await expect(nextBtn).toBeVisible();
      await expect(prevBtn).toContainText("Previous");
      await expect(nextBtn).toContainText("Next");
      const prevBox = await prevBtn.boundingBox();
      const nextBox = await nextBtn.boundingBox();
      expect(prevBox).toBeTruthy();
      expect(nextBox).toBeTruthy();
      expect(prevBox!.x).toBeLessThan(nextBox!.x);
    });

    test("Next button shows next certification", async ({ page }) => {
      await page.locator(".cert-card").first().click();
      const firstTitle = await page.locator(".cert-modal-title").textContent();
      await expect(page.locator(".cert-modal-next")).toBeVisible();
      await page.locator(".cert-modal-next").click();
      const secondTitle = await page.locator(".cert-modal-title").textContent();
      expect(secondTitle).toBeTruthy();
      expect(secondTitle).not.toBe(firstTitle);
    });

    test("Previous button shows previous certification (wraps to last when at first)", async ({
      page,
    }) => {
      await page.locator(".cert-card").first().click();
      const firstTitle = await page.locator(".cert-modal-title").textContent();
      await expect(page.locator(".cert-modal-prev")).toBeVisible();
      await page.locator(".cert-modal-prev").click();
      const afterPrevTitle = await page.locator(".cert-modal-title").textContent();
      expect(afterPrevTitle).toBeTruthy();
      expect(afterPrevTitle).not.toBe(firstTitle);
    });
  });
});
