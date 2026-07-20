/**
 * Maps the human country names emitted by the GeoIP enrichment to ISO 3166-1
 * alpha-2 codes, so we can render flags via flagcdn (same source the About
 * page already uses). Returns `null` for unknown names — callers should fall
 * back to a neutral globe glyph.
 */
const NAME_TO_ISO2: Record<string, string> = {
  "united states": "us",
  "the netherlands": "nl",
  netherlands: "nl",
  china: "cn",
  bulgaria: "bg",
  kazakhstan: "kz",
  pakistan: "pk",
  sweden: "se",
  romania: "ro",
  iran: "ir",
  ukraine: "ua",
  russia: "ru",
  "russian federation": "ru",
  germany: "de",
  france: "fr",
  "united kingdom": "gb",
  india: "in",
  brazil: "br",
  canada: "ca",
  vietnam: "vn",
  "south korea": "kr",
  "korea, republic of": "kr",
  "hong kong": "hk",
  singapore: "sg",
  japan: "jp",
  indonesia: "id",
  turkey: "tr",
  "türkiye": "tr",
  poland: "pl",
  spain: "es",
  italy: "it",
  taiwan: "tw",
  thailand: "th",
  "united arab emirates": "ae",
  "hong kong sar china": "hk",
  moldova: "md",
  lithuania: "lt",
  latvia: "lv",
  estonia: "ee",
  finland: "fi",
  norway: "no",
  denmark: "dk",
  ireland: "ie",
  switzerland: "ch",
  austria: "at",
  belgium: "be",
  portugal: "pt",
  "czech republic": "cz",
  czechia: "cz",
  seychelles: "sc",
  panama: "pa",
  mexico: "mx",
  argentina: "ar",
  colombia: "co",
  chile: "cl",
  egypt: "eg",
  "south africa": "za",
  nigeria: "ng",
  israel: "il",
  "saudi arabia": "sa",
  malaysia: "my",
  philippines: "ph",
  bangladesh: "bd",
  australia: "au",
  "new zealand": "nz",
  greece: "gr",
  hungary: "hu",
  serbia: "rs",
  croatia: "hr",
  slovakia: "sk",
  slovenia: "si",
  belarus: "by",
  georgia: "ge",
  armenia: "am",
  azerbaijan: "az",
  iraq: "iq",
  luxembourg: "lu",
  cyprus: "cy",
  gibraltar: "gi",
};

export function iso2ForCountry(name: string): string | null {
  return NAME_TO_ISO2[name.trim().toLowerCase()] ?? null;
}

export function flagUrl(name: string, size: 24 | 48 = 24): string | null {
  const iso = iso2ForCountry(name);
  if (!iso) return null;
  const h = size === 24 ? 18 : 36;
  return `https://flagcdn.com/${size}x${h}/${iso}.png`;
}
