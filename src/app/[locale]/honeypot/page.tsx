import type { Metadata } from "next";
import { getTranslations, setRequestLocale } from "next-intl/server";
import { HoneypotMaintenance } from "@/components/honeypot/maintenance";

// ⏸️ EM MANUTENÇÃO — o dashboard público está desligado enquanto o pipeline de
// inteligência é reconstruído (MISP no lugar do OpenCTI, ponte simétrica em Go).
//
// PARA VOLTAR, são duas linhas: descomente o import abaixo e troque o `return`.
// Nada mais foi tocado — o componente do dashboard está intacto, com as 994 linhas.
// import { HoneypotDashboard } from "@/components/honeypot/honeypot-dashboard";

interface Props {
  params: Promise<{ locale: string }>;
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { locale } = await params;
  const t = await getTranslations({ locale, namespace: "honeypot" });
  return {
    // O título e a descrição continuam os do dashboard: a rota é a mesma e o que
    // mudou é o estado dela, não o assunto. Trocar a metadata faria a página sumir
    // de busca e de link compartilhado por um motivo temporário.
    title: t("title"),
    description: t("subtitle"),
  };
}

export default async function HoneypotPage({ params }: Props) {
  const { locale } = await params;
  setRequestLocale(locale);
  return <HoneypotMaintenance locale={locale} />;
  // return <HoneypotDashboard />;
}
