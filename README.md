# 0xrh0d4m1n.tech

Personal site and blog focused on hacking and cybersecurity.  
Built with **Next.js 15**, **shadcn/ui**, **Tailwind CSS v4**, and **MDX**.

---

## Tech stack

| Layer | Technology |
|-------|------------|
| Framework | Next.js 15 (App Router, static export) |
| Language | TypeScript |
| UI | shadcn/ui + Tailwind CSS v4 |
| Icons | Font Awesome (SVG, free solid + brands) |
| Content | Markdown → MDX (@next/mdx, dynamic import + remark-mdx-frontmatter) |
| Hosting | GitHub Pages |
| CI/CD | GitHub Actions |
| Testing | Playwright |

---

## Project structure

```
.
├── .github/workflows/deploy.yml   # CI/CD
├── content/                       # All Markdown content (80 files)
│   ├── _index.md                  # Homepage data
│   ├── about/                     # About page
│   ├── blog/                      # Blog posts
│   ├── codex/                     # Reference articles (infra, networking, protocols, soc, etc.)
│   ├── skills/                    # Skills & certifications
│   ├── toolbox/                   # Security tools
│   └── writeups/                  # CTF writeups (blueteam, redteam, web)
├── data/                          # Site metadata
│   ├── social.json                # Social links
│   └── theme.json                 # Color palette & fonts
├── public/                        # Static assets (images, docs, favicons)
├── src/
│   ├── app/                       # Next.js App Router pages
│   │   ├── layout.tsx             # Root layout (header, footer, theme)
│   │   ├── page.tsx               # Homepage
│   │   ├── about/page.tsx
│   │   ├── blog/page.tsx          # Blog listing
│   │   ├── blog/[slug]/page.tsx   # Blog post
│   │   ├── codex/page.tsx         # Codex index
│   │   ├── codex/[category]/      # Category listing + article
│   │   ├── glossary/page.tsx
│   │   ├── skills/page.tsx
│   │   ├── toolbox/page.tsx
│   │   └── writeups/              # Writeups (catch-all route)
│   ├── components/                # React components
│   │   ├── site-header.tsx        # Navigation header
│   │   ├── site-footer.tsx        # Footer
│   │   ├── theme-provider.tsx     # Dark/light mode provider
│   │   └── theme-toggle.tsx       # Theme switch button
│   ├── mdx-components.tsx         # MDX global components (@next/mdx)
│   └── lib/
│       ├── content.ts             # Content loading (reads content/*.md)
│       ├── icons.ts               # Font Awesome icon registry (site default)
│       └── utils.ts               # shadcn utility (cn)
├── components.json                # shadcn/ui config
├── next.config.ts                 # Static export + image config
├── postcss.config.mjs
├── tsconfig.json
├── package.json
└── CNAME
```

---

## Local development

```bash
npm install
npm run dev
```

Open http://localhost:3000.

---

## Build (static export)

```bash
npm run build
```

Output: `out/` directory with static HTML/CSS/JS ready for GitHub Pages.

---

## Deploy

Push to `main` or `master`. GitHub Actions will:
1. `npm ci`
2. `npm run build`
3. Upload `out/` to GitHub Pages

---

## Adding content

Drop a `.md` file in the appropriate `content/` directory with frontmatter:

```yaml
---
title: "My New Post"
date: 2024-03-15
tags: [cybersecurity, SOC]
categories: [SOC]
---

Your content here...
```

The content pipeline reads `content/`, parses frontmatter with `gray-matter`, and renders via `next-mdx-remote`.

---

## Color palette

### Dark mode (default)
| Role | Hex |
|------|-----|
| Primary (accent) | `#9FEF00` |
| Background | `#0d1117` |
| Surface | `#161b22` |
| Border | `#21262d` |
| Text | `#c9d1d9` |
| Headings | `#ffffff` |

### Light mode
| Role | Hex |
|------|-----|
| Primary | `#121212` |
| Background | `#ffffff` |
| Surface | `#f6f6f6` |
| Border | `#eaeaea` |
| Text | `#444444` |
