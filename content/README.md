# Content directory

Source of truth for blog posts and writeups, organized per locale.

## Layout

```
content/
  en/
    blog/       <- canonical English posts (MDX or MD)
    writeups/   <- canonical English writeups
  pt-br/
    blog/
    writeups/
  es/
    blog/
    writeups/
```

English (`en`) is the **default locale** and the canonical source. Every post
must exist in `content/en/`. Portuguese (`pt-br`) and Spanish (`es`) are
optional overrides: if a file with the same slug exists in that locale's
folder, it wins over dynamic translation.

## Override flow

At runtime, visiting `/pt-br/blog/my-post/`:

1. The page checks `content/pt-br/blog/my-post.{md,mdx}` via `hasLocaleOverride`.
2. **If present:** the manual translation renders as-is — no API calls.
3. **If absent:** the English file is imported and `<DynamicTranslator>` wraps
   `<Content />`, translating text nodes in-browser via Google Translate
   (falling back to MyMemory). Blocks inside `<pre>`, `<code>`, and
   `[data-notranslate]` (including `<Spoiler>`) are never touched.

## Why the empty locale folders exist

The `[slug]` pages contain `import(\`@content/pt-br/blog/${slug}.mdx\`)` etc.
Webpack resolves these as **context modules at build time** — it needs the
directory to exist even when empty. Git does not track empty directories,
so each locale subfolder contains a `.gitkeep` file as an anchor.

Deleting any `.gitkeep` before the folder contains real content will break
the production build (`Module not found: Can't resolve '@content/...'`).

## Adding a manual translation

1. Copy the English source, e.g. `content/en/blog/my-post.md`
   → `content/pt-br/blog/my-post.md`.
2. Translate title, description, and body. Keep the same slug and
   frontmatter shape.
3. The `.gitkeep` can be removed from that folder once a real file is
   committed alongside it (optional — keeping it is harmless).
