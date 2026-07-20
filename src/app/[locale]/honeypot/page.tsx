import type { Metadata } from "next";
import { getTranslations, setRequestLocale } from "next-intl/server";
import { HoneypotDashboard } from "@/components/honeypot/honeypot-dashboard";

interface Props {
  params: Promise<{ locale: string }>;
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { locale } = await params;
  const t = await getTranslations({ locale, namespace: "honeypot" });
  return {
    title: t("title"),
    description: t("subtitle"),
  };
}

export default async function HoneypotPage({ params }: Props) {
  const { locale } = await params;
  setRequestLocale(locale);
  return <HoneypotDashboard />;
}
