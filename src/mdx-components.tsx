import type { MDXComponents } from "mdx/types";
import type { ReactNode } from "react";

/** Generate a URL-friendly ID from heading text */
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

const components: MDXComponents = {
  h1: ({ children, ...props }) => (
    <h1
      id={slugify(children)}
      className="mt-10 mb-4 text-3xl font-bold font-heading scroll-mt-20"
      {...props}
    >
      {children}
    </h1>
  ),
  h2: ({ children, ...props }) => (
    <h2
      id={slugify(children)}
      className="mt-10 mb-4 text-2xl font-bold font-heading scroll-mt-20"
      {...props}
    >
      {children}
    </h2>
  ),
  h3: ({ children, ...props }) => (
    <h3
      id={slugify(children)}
      className="mt-8 mb-3 text-xl font-semibold font-heading scroll-mt-20"
      {...props}
    >
      {children}
    </h3>
  ),
  h4: ({ children, ...props }) => (
    <h4
      id={slugify(children)}
      className="mt-6 mb-2 text-lg font-semibold font-heading scroll-mt-20"
      {...props}
    >
      {children}
    </h4>
  ),
};

export function useMDXComponents(componentsOverrides?: MDXComponents): MDXComponents {
  return {
    ...components,
    ...componentsOverrides,
  };
}
