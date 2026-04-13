/**
 * Augments MDX/MD module types to include frontmatter exported by remark-mdx-frontmatter.
 */
declare module "*.md" {
  const frontmatter: Record<string, unknown> | undefined;
  export { frontmatter };
}

declare module "*.mdx" {
  const frontmatter: Record<string, unknown> | undefined;
  export { frontmatter };
}
