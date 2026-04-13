import type { Metadata } from "next";
import { getAllWriteups } from "@/lib/content";
import { WriteupDataGrid } from "@/components/writeups/writeup-data-grid";
import type { WriteupEntry } from "@/components/writeups/writeup-data-grid";

export const metadata: Metadata = { title: "Writeups" };

export default function WriteupsPage() {
  const items = getAllWriteups();

  const writeups: WriteupEntry[] = items.map((w) => ({
    slug: w.slug,
    name: w.name,
    source: w.source,
    sourceKey: w.sourceKey,
    category: w.category,
    categoryKey: w.categoryKey,
    difficulty: w.difficulty,
    tags: w.tags,
    date: w.date,
    href: w.href,
  }));

  return (
    <div className="mx-auto w-[90vw] max-w-[1400px] px-4 py-8">
      {/* Page header */}
      <div className="mb-6">
        <h1 className="mb-1 text-3xl font-bold font-heading">Writeups</h1>
        <p className="text-muted-foreground">
          Chronicles of my Cyber Battles &mdash; sortable &amp; searchable archive of CTF and lab writeups.
        </p>
      </div>

      {/* Data grid */}
      <WriteupDataGrid writeups={writeups} />
    </div>
  );
}
