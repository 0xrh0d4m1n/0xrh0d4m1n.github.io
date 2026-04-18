import type { NextConfig } from "next";
import createMDX from "@next/mdx";
import remarkFrontmatter from "remark-frontmatter";
import remarkMdxFrontmatter from "remark-mdx-frontmatter";
import remarkGfm from "remark-gfm";
import remarkEmoji from "remark-emoji";
import remarkBreaks from "remark-breaks";
import rehypePrettyCode from "rehype-pretty-code";
import { visit } from "unist-util-visit";
import type { Root, Html, Paragraph } from "mdast";

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

const nextConfig: NextConfig = {
  output: "export",
  trailingSlash: true,
  pageExtensions: ["js", "jsx", "md", "mdx", "ts", "tsx"],
  images: {
    unoptimized: true,
  },
};

const withMDX = createMDX({
  extension: /\.(md|mdx)$/,
  options: {
    remarkPlugins: [
      remarkGfm,
      remarkBreaks,
      remarkHtmlBreaksToSpacer,
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

export default withMDX(nextConfig);
