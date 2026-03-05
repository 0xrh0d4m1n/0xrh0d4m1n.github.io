# 0xrh0d4m1n.tech

Personal site and blog focused on hacking and cybersecurity. Built with [Hugo](https://gohugo.io/) and the [Hugoplate](https://github.com/zeon-studio/hugoplate) theme (Tailwind CSS v4, dark/light mode, search). Deployed to [GitHub Pages](https://pages.github.com/).

---

## Tech stack

| Layer        | Technology |
|-------------|------------|
| Static site | Hugo (extended) |
| Theme       | [Hugoplate](https://github.com/zeon-studio/hugoplate) (Zeon Studio) |
| Styling     | Tailwind CSS v4, theme colors/fonts via `data/theme.json` |
| CI/CD       | GitHub Actions (deploy to GitHub Pages) |
| Custom domain | `0xrh0d4m1n.tech` (via `CNAME`) |

---

## Prerequisites

- **Hugo Extended** v0.144+  
- **Node.js** v22+ (for theme CSS generator)  
- **Go** v1.21+ (for Hugo modules)

**Windows:** Use a project path **without spaces** (e.g. `C:\dev\0xrh0d4m1n.github.io`). Paths like `...\Cloned Repositories\...` break the Tailwind step and can trigger group policy blocks. Clone or move the repo to a folder without spaces and run `npm run dev` from there.

---

## Project structure

```
.
├── .github/workflows/   # CI/CD (deploy-hugo.yml)
├── assets/              # Site assets (images, docs) — mounted at /assets
├── config/_default/     # params.toml (logo, search, SEO, etc.)
├── content/             # All site content (Markdown)
├── data/                # theme.json (colors, fonts), social.json
├── static/              # Static files (CNAME, favicon, images)
├── themes/hugoplate/    # Hugoplate theme (layouts, scripts, assets)
├── hugo.toml            # Site config, module imports, params
├── go.mod / go.sum      # Hugo module dependencies
├── package.json         # npm scripts (build, dev)
├── CNAME                # Custom domain for GitHub Pages
└── README.md
```

Generated at build time (gitignored): `public/`, `resources/_gen/`, `node_modules/`.

---

## Local development

```bash
# Install npm deps
npm install

# Download Hugo modules
hugo mod get

# Generate theme CSS and run dev server
npm run dev
```

Then open http://localhost:1313.

---

## Build (production)

```bash
npm run build
```

This:

1. Copies `data/theme.json` into the theme (for the generator).
2. Runs the theme’s CSS generator (`themes/hugoplate/scripts/themeGenerator.js`).
3. Runs `hugo --gc --minify --templateMetrics --templateMetricsHints --forceSyncStatic`.

Output is in `public/`.

---

## Customization

| What | Where |
|------|--------|
| **Site title, menu, base URL** | `hugo.toml` |
| **Logo, favicon, search, SEO** | `config/_default/params.toml` |
| **Colors and fonts** | `data/theme.json` (then run `npm run build` or `npm run dev`) |
| **Social links** | `data/social.json` |

Logo/favicon paths in `params.toml` point to `images/` (i.e. `static/images/`). Add `static/images/logo.png`, `favicon.png`, etc., or rely on `logo_text` in params.

---

## Palette (dark theme)

Reference for CSS variables and hex values. Source: `data/theme.json` → `themes/hugoplate/assets/css/generated-theme.css`.

| Uso | Variável CSS | Valor |
|-----|----------------|--------|
| Primary (acento) | `--color-darkmode-primary` | `#9FEF00` |
| Body (fundo) | `--color-darkmode-body` | `#0d1117` |
| Border | `--color-darkmode-border` | `#21262d` |
| Light (superfícies) | `--color-darkmode-light` | `#161b22` |
| Dark (ênfase) | `--color-darkmode-dark` | `#ffffff` |
| Text | `--color-darkmode-text` | `#c9d1d9` (rgb(201, 209, 217)) |
| Text dark (títulos) | `--color-darkmode-text-dark` | `#ffffff` |
| Text light (secundário) | `--color-darkmode-text-light` | `#8b949e` |

---

## Content

- **Home** — `content/_index.md`
- **Sections** — `content/about/`, `content/blog/`, `content/writeups/`, `content/codex/`, `content/toolbox/`, `content/glossary/`, `content/skills/`
- **Blog** — `content/blog/` (list) and `content/blog/posts/` (single posts)

Structure is compatible with Hugoplate’s list/single and taxonomies (tags, categories).

---

## Deploy (GitHub Pages)

Push to `main` or `master`. The workflow:

1. Installs Node, Go, Hugo Extended.
2. Runs `npm ci` and `hugo mod get`.
3. Runs `npm run build` with `HUGO_BASEURL` from GitHub Pages.
4. Uploads `public/` and deploys.

Ensure **Settings → Pages** uses “GitHub Actions” as the source.

---

## License and theme

- Site content: yours.
- [Hugoplate](https://github.com/zeon-studio/hugoplate) theme: [MIT](https://github.com/zeon-studio/hugoplate/blob/main/LICENSE) (Zeon Studio).
