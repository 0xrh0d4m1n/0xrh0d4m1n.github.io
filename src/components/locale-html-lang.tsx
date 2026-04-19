"use client";

import { useEffect } from "react";

/**
 * Updates `document.documentElement.lang` to match the current locale so that
 * browser features (spellcheck, hyphenation, screen readers) and Lingva
 * translation requests have the correct source language. Root `<html>` is
 * rendered once with `lang="en"` on the server; this client effect swaps it on
 * mount of each [locale] route.
 */
export function LocaleHtmlLang({ locale }: { locale: string }) {
  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);
  return null;
}
