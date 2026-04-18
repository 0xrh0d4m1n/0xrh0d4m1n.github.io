import type { MDXComponents } from "mdx/types";
import type { ReactNode } from "react";

/** Generate a URL-friendly ID from heading text for in-page anchor navigation. */
function slugify(children: ReactNode): string {
  const text = typeof children === "string"
    ? children
    : Array.isArray(children)
      ? children.map((c) => (typeof c === "string" ? c : "")).join("")
      : "";
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");
}

/**
 * Custom MDX component overrides.
 *
 * Each heading wrapper injects a slugified `id` so the table of contents
 * and in-page anchor links work. All visual styling (colors, sizes,
 * spacing, hover states, etc.) lives in `src/styles/globals.css` under
 * the `.prose` selectors so both light and dark themes can be themed
 * from a single source of truth.
 */
const components: MDXComponents = {
  h1: ({ children, ...props }) => (
    <h1 id={slugify(children)} {...props}>
      {children}
    </h1>
  ),
  h2: ({ children, ...props }) => (
    <h2 id={slugify(children)} {...props}>
      {children}
    </h2>
  ),
  h3: ({ children, ...props }) => (
    <h3 id={slugify(children)} {...props}>
      {children}
    </h3>
  ),
  h4: ({ children, ...props }) => (
    <h4 id={slugify(children)} {...props}>
      {children}
    </h4>
  ),
  h5: ({ children, ...props }) => (
    <h5 id={slugify(children)} {...props}>
      {children}
    </h5>
  ),
  h6: ({ children, ...props }) => (
    <h6 id={slugify(children)} {...props}>
      {children}
    </h6>
  ),
};

export function useMDXComponents(componentsOverrides?: MDXComponents): MDXComponents {
  return {
    ...components,
    ...componentsOverrides,
  };
}
