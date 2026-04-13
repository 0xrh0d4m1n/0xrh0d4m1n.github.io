export interface SerializedPost {
  slug: string;
  title: string;
  description?: string;
  date?: string;
  tags?: string[];
  categories?: string[];
  image?: string;
  readingTime: number;
  href: string;
}
