import type { NextConfig } from "next";
import createMDX from "@next/mdx";
import createNextIntlPlugin from "next-intl/plugin";
import remarkFrontmatter from "remark-frontmatter";
import remarkMdxFrontmatter from "remark-mdx-frontmatter";
import remarkGfm from "remark-gfm";
import remarkEmoji from "remark-emoji";
import remarkBreaks from "remark-breaks";
import rehypePrettyCode from "rehype-pretty-code";
import { visit } from "unist-util-visit";
import type { Root, Html, Paragraph, RootContent, Parent } from "mdast";

/**
 * Custom remark plugin that converts standalone raw `<br>` HTML nodes
 * (any variant: <br>, <br/>, <br />, <br></br>) into visible spacer
 * paragraphs. Without this, MDX silently strips standalone <br> elements
 * between paragraphs because they are not valid JSX on their own.
 *
 * Example transformation:
 *   <p>First paragraph.</p>
 *   <br>                     →  <p>&nbsp;</p>   (adds visual vertical space)
 *   <p>Second paragraph.</p>
 */
function remarkHtmlBreaksToSpacer() {
  return (tree: Root) => {
    visit(tree, "html", (node: Html, index, parent) => {
      if (!parent || typeof index !== "number") return;
      if (/^<br\s*\/?>(\s*<\/br>)?$/i.test(node.value.trim())) {
        const spacer: Paragraph = {
          type: "paragraph",
          children: [{ type: "text", value: "\u00a0" }],
        };
        parent.children[index] = spacer;
      }
    });
  };
}

/**
 * Converts raw `<spoiler>...</spoiler>` HTML blocks in plain markdown into the
 * React `<Spoiler>` component (registered in `src/mdx-components.tsx`).
 *
 * Supports both forms:
 *
 *   Tight form — content between tags becomes a single text block:
 *     <spoiler>
 *     the answer is 42
 *     </spoiler>
 *
 *   Block form — blank lines let markdown/code inside parse normally:
 *     <spoiler>
 *
 *     ```bash
 *     cat /root/root.txt
 *     ```
 *
 *     </spoiler>
 *
 * Writers can keep authoring in `.md` without touching MDX syntax.
 */
function remarkSpoiler() {
  const OPEN_RE = /^<spoiler>/i;
  const CLOSE_RE = /<\/spoiler>\s*$/i;
  const SELF_CONTAINED_RE = /^<spoiler>([\s\S]*?)<\/spoiler>\s*$/i;

  // mdxJsxFlowElement is a node type provided by the MDX pipeline; the mdast
  // typings don't include it, so we cast locally.
  type SpoilerNode = RootContent & {
    type: "mdxJsxFlowElement";
    name: "Spoiler";
    attributes: [];
    children: RootContent[];
  };

  const makeSpoiler = (children: RootContent[]): SpoilerNode =>
    ({
      type: "mdxJsxFlowElement",
      name: "Spoiler",
      attributes: [],
      children,
    }) as SpoilerNode;

  const wrap = (parent: Parent) => {
    const kids = parent.children;
    for (let i = 0; i < kids.length; i++) {
      const node = kids[i];

      if (node.type === "html" && OPEN_RE.test(node.value)) {
        const selfMatch = SELF_CONTAINED_RE.exec(node.value.trim());
        if (selfMatch) {
          // Single html block contains both open and close tags. Treat the
          // inner as plain text (markdown isn't parsed inside raw HTML blocks).
          const inner = selfMatch[1].trim();
          const textPara: Paragraph = {
            type: "paragraph",
            children: [{ type: "text", value: inner }],
          };
          kids[i] = makeSpoiler([textPara]) as unknown as RootContent;
          continue;
        }

        // Opening tag only — find the matching closing html node.
        let closeAt = -1;
        for (let j = i + 1; j < kids.length; j++) {
          const candidate = kids[j];
          if (candidate.type === "html" && CLOSE_RE.test(candidate.value)) {
            closeAt = j;
            break;
          }
        }
        if (closeAt > i) {
          const inner = kids.slice(i + 1, closeAt);
          kids.splice(
            i,
            closeAt - i + 1,
            makeSpoiler(inner) as unknown as RootContent,
          );
          continue;
        }
      }

      if ("children" in node && Array.isArray((node as Parent).children)) {
        wrap(node as Parent);
      }
    }
  };

  return (tree: Root) => {
    wrap(tree);
  };
}

const nextConfig: NextConfig = {
  output: "export",
  trailingSlash: true,
  pageExtensions: ["js", "jsx", "md", "mdx", "ts", "tsx"],
  images: {
    unoptimized: true,
  },
  /**
   * Public build-time values, inlined into the client bundle.
   *
   * 🔑 This lives here and NOT in a committed `.env.production` on purpose. That file was
   * harmless — it held one `NEXT_PUBLIC_*` URL — but it was a TRAP for later: an env file
   * tracked in a PUBLIC repo is the obvious place someone drops the next variable, and the
   * next variable is the one with a secret in it. `next.config.ts` is code; nobody pastes a
   * token into a config object by reflex.
   *
   * ⚠️ Everything here is PUBLIC by construction — `NEXT_PUBLIC_*` is inlined into the
   * JavaScript the browser downloads. A secret placed here is a secret published, and no
   * amount of "it's just a build variable" changes that. Secrets belong in
   * `.env.local` (gitignored) or in the deploy environment.
   */
  env: {
    // Live honeypot stats API — Cloudflare Worker, public read-only.
    // Unset (e.g. a fork with no worker), the dashboard falls back to the bundled mock at
    // /data/honeypot-stats.json — see honeypot-dashboard.tsx:61.
    NEXT_PUBLIC_HONEYPOT_STATS_URL: "https://honeypot-stats.valdeniomarinho.workers.dev/stats",
  },
};

const withMDX = createMDX({
  extension: /\.(md|mdx)$/,
  options: {
    remarkPlugins: [
      remarkGfm,
      remarkBreaks,
      remarkHtmlBreaksToSpacer,
      remarkSpoiler,
      remarkEmoji,
      remarkFrontmatter,
      remarkMdxFrontmatter,
    ],
    rehypePlugins: [
      [
        rehypePrettyCode,
        {
          theme: "github-dark-default",
          keepBackground: true,
          defaultLang: "plaintext",
        },
      ],
    ],
  },
});

const withNextIntl = createNextIntlPlugin("./src/i18n/request.ts");

export default withNextIntl(withMDX(nextConfig));
