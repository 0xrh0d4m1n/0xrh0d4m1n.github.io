import type { Metadata } from "next";
import Link from "next/link";
import { getSectionIndex, getSubsections } from "@/lib/content";

export const metadata: Metadata = { title: "Codex" };

export default function CodexPage() {
  const section = getSectionIndex("codex");
  const subs = getSubsections("codex").filter((s) => s.name !== "glossary");

  return (
    <div className="mx-auto w-[90vw] max-w-none px-4 py-12">
      <h1 className="mb-2 text-3xl font-bold font-heading">
        {section?.meta.title ?? "Codex"}
      </h1>
      {section?.meta.description && (
        <p className="mb-8 text-muted-foreground">
          {section.meta.description}
        </p>
      )}

      <div className="grid gap-4 sm:grid-cols-2">
        {subs.map(({ name, meta }) => (
          <Link
            key={name}
            href={`/codex/${name}/`}
            className="group rounded-lg border border-border bg-card p-5 transition-colors hover:border-primary/40"
          >
            <h2 className="font-heading text-lg font-semibold text-card-foreground group-hover:text-primary transition-colors">
              {meta.title}
            </h2>
            {meta.description && (
              <p className="mt-1 text-sm text-muted-foreground">
                {meta.description}
              </p>
            )}
          </Link>
        ))}
      </div>
    </div>
  );
}
