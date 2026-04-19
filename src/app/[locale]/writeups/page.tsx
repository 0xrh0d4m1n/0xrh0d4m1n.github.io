import type { Metadata } from "next";
import { getTranslations, setRequestLocale } from "next-intl/server";
import { getAllWriteups } from "@/lib/content";
import { WriteupDataGrid } from "@/components/writeups/writeup-data-grid";
import type { WriteupEntry } from "@/components/writeups/writeup-data-grid";

interface Props {
  params: Promise<{ locale: string }>;
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { locale } = await params;
  const t = await getTranslations({ locale, namespace: "writeups" });
  return { title: t("title") };
}

export default async function WriteupsPage({ params }: Props) {
  const { locale } = await params;
  setRequestLocale(locale);
  const t = await getTranslations({ locale, namespace: "writeups" });

  const items = getAllWriteups(locale);

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
      <div className="mb-6">
        <h1 className="mb-1 text-3xl font-bold font-heading">{t("title")}</h1>
        <p className="text-muted-foreground">{t("subtitle")}</p>
      </div>

      <WriteupDataGrid writeups={writeups} />
    </div>
  );
}
