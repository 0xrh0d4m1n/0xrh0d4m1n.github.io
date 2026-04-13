import type { NextConfig } from "next";
import createMDX from "@next/mdx";
import remarkFrontmatter from "remark-frontmatter";
import remarkMdxFrontmatter from "remark-mdx-frontmatter";
import remarkGfm from "remark-gfm";
import remarkEmoji from "remark-emoji";
import rehypePrettyCode from "rehype-pretty-code";

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
    remarkPlugins: [remarkGfm, remarkEmoji, remarkFrontmatter, remarkMdxFrontmatter],
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
