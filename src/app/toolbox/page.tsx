import type { Metadata } from "next";

export async function generateMetadata(): Promise<Metadata> {
  const mod = await import("@content/toolbox/_index.md");
  const title = (mod.frontmatter?.title as string) ?? "Toolbox";
  return { title };
}

export default async function ToolboxPage() {
  const mod = await import("@content/toolbox/_index.md");
  const Content = mod.default;
  const frontmatter = (mod.frontmatter ?? {}) as { title?: string };

  return (
    <div className="mx-auto w-[90vw] max-w-none px-4 py-12">
      <h1 className="mb-8 text-3xl font-bold font-heading">
        {frontmatter.title}
      </h1>
      <div className="prose max-w-none">
        <Content />
      </div>
    </div>
  );
}
