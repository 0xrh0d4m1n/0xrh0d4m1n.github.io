import type { Metadata } from "next";
import { getTranslations, setRequestLocale } from "next-intl/server";
import { ToolboxLayout } from "@/components/toolbox/toolbox-layout";

interface Props {
  params: Promise<{ locale: string }>;
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { locale } = await params;
  const t = await getTranslations({ locale, namespace: "toolbox" });
  return { title: t("title") };
}

export default async function ToolboxPage({ params }: Props) {
  const { locale } = await params;
  setRequestLocale(locale);
  const t = await getTranslations({ locale, namespace: "toolbox" });

  return (
    <div className="mx-auto w-[90vw] max-w-[1600px] px-4 py-8">
      <div className="mb-6">
        <h1 className="mb-1 text-3xl font-bold font-heading">{t("title")}</h1>
        <p className="text-muted-foreground">{t("subtitle")}</p>
      </div>

      <ToolboxLayout />
    </div>
  );
}
