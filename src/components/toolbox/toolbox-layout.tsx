"use client";

import { useState, useMemo } from "react";
import { cn } from "@/lib/utils";
import { TOOLBOX_DATA, type Tool, type ToolCategory } from "@/data/toolbox";

/* ── Helpers ──────────────────────────────────────────────────── */

function getFavicon(url: string) {
  try {
    const domain = new URL(url).hostname;
    return `https://www.google.com/s2/favicons?domain=${domain}&sz=32`;
  } catch {
    return "";
  }
}

/** Flatten every tool with its parent category/subcategory labels. */
interface FlatTool extends Tool {
  category: string;
  subcategory: string;
}

function flattenAll(): FlatTool[] {
  const out: FlatTool[] = [];
  for (const cat of TOOLBOX_DATA) {
    for (const sub of cat.subcategories) {
      for (const tool of sub.tools) {
        out.push({ ...tool, category: cat.name, subcategory: sub.name });
      }
    }
  }
  return out;
}

const ALL_TOOLS = flattenAll();

/* ── Tool Card ────────────────────────────────────────────────── */

function ToolCard({ tool }: { tool: Tool }) {
  return (
    <a
      href={tool.url}
      target="_blank"
      rel="noopener noreferrer"
      className="group flex items-start gap-3 rounded-lg border border-border bg-card p-4 transition-all hover:border-primary/40 hover:bg-primary/[0.03]"
    >
      {/* Favicon */}
      <img
        src={getFavicon(tool.url)}
        alt=""
        width={28}
        height={28}
        className="mt-0.5 h-7 w-7 shrink-0 rounded"
        loading="lazy"
      />

      {/* Text */}
      <div className="min-w-0">
        <h3 className="text-sm font-semibold text-foreground group-hover:text-primary transition-colors truncate">
          {tool.name}
        </h3>
        <p className="mt-0.5 text-xs text-muted-foreground line-clamp-2 leading-relaxed">
          {tool.description}
        </p>
      </div>
    </a>
  );
}

/* ── Category Grid Section ────────────────────────────────────── */

function SubcategorySection({
  name,
  emoji,
  tools,
}: {
  name: string;
  emoji: string;
  tools: Tool[];
}) {
  return (
    <section>
      <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
        <span>{emoji}</span>
        {name}
      </h3>
      <div className="grid gap-3 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        {tools.map((tool) => (
          <ToolCard key={`${tool.url}-${tool.name}`} tool={tool} />
        ))}
      </div>
    </section>
  );
}

/* ── Main Layout ──────────────────────────────────────────────── */

export function ToolboxLayout() {
  const [activeCategory, setActiveCategory] = useState<string>("All");
  const [search, setSearch] = useState("");

  /* Search results */
  const searchResults = useMemo(() => {
    if (!search.trim()) return null;
    const q = search.toLowerCase().trim();
    return ALL_TOOLS.filter(
      (t) =>
        t.name.toLowerCase().includes(q) ||
        t.description.toLowerCase().includes(q) ||
        t.category.toLowerCase().includes(q) ||
        t.subcategory.toLowerCase().includes(q)
    );
  }, [search]);

  const isSearching = searchResults !== null;

  /* Current category data */
  const currentCategory: ToolCategory | null = useMemo(() => {
    if (activeCategory === "All") return null;
    return TOOLBOX_DATA.find((c) => c.name === activeCategory) ?? null;
  }, [activeCategory]);

  /* Sidebar items */
  const sidebarItems = [
    { name: "All", emoji: "🏠", count: ALL_TOOLS.length },
    ...TOOLBOX_DATA.map((c) => ({
      name: c.name,
      emoji: c.emoji,
      count: c.subcategories.reduce((s, sub) => s + sub.tools.length, 0),
    })),
  ];

  return (
    <div className="flex flex-col gap-4 lg:flex-row lg:gap-6">
      {/* ── Left Sidebar ──────────────────────────────────────── */}
      <aside className="shrink-0 lg:w-56">
        {/* Search */}
        <div className="relative mb-4">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground pointer-events-none"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2}
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
            />
          </svg>
          <input
            type="text"
            placeholder="Search tools..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="h-10 w-full rounded-lg border border-border bg-card pl-10 pr-4 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary transition-colors"
          />
        </div>

        {/* Category nav */}
        <nav className="flex flex-row gap-1 overflow-x-auto pb-2 lg:flex-col lg:overflow-visible lg:pb-0">
          {sidebarItems.map((item) => (
            <button
              key={item.name}
              onClick={() => {
                setActiveCategory(item.name);
                setSearch("");
              }}
              className={cn(
                "flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium transition-colors whitespace-nowrap",
                !isSearching && activeCategory === item.name
                  ? "bg-primary/10 text-primary border border-primary/30"
                  : "text-muted-foreground hover:bg-muted hover:text-foreground border border-transparent"
              )}
            >
              <span className="text-base">{item.emoji}</span>
              <span className="flex-1 text-left">{item.name}</span>
              <span
                className={cn(
                  "text-[11px] font-mono rounded-full px-1.5 py-0.5",
                  !isSearching && activeCategory === item.name
                    ? "bg-primary/20 text-primary"
                    : "bg-muted text-muted-foreground"
                )}
              >
                {item.count}
              </span>
            </button>
          ))}
        </nav>
      </aside>

      {/* ── Main Content ──────────────────────────────────────── */}
      <main className="min-w-0 flex-1 space-y-8">
        {/* Search mode */}
        {isSearching ? (
          <>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-semibold text-foreground">
                Results
              </h2>
              <span className="rounded-full bg-primary/10 px-2 py-0.5 text-xs font-mono font-semibold text-primary">
                {searchResults.length}
              </span>
            </div>
            {searchResults.length === 0 ? (
              <div className="flex flex-col items-center gap-2 py-16 text-muted-foreground">
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  className="h-10 w-10 opacity-40"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                  strokeWidth={1.5}
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    d="M9.75 9.75l4.5 4.5m0-4.5l-4.5 4.5M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                  />
                </svg>
                <p className="text-base font-medium">No tools found</p>
                <p className="text-sm">Try a different search term</p>
              </div>
            ) : (
              <div className="grid gap-3 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                {searchResults.map((tool) => (
                  <ToolCard key={`${tool.url}-${tool.name}`} tool={tool} />
                ))}
              </div>
            )}
          </>
        ) : activeCategory === "All" ? (
          /* All categories */
          TOOLBOX_DATA.map((cat) => (
            <div key={cat.name} className="space-y-6">
              <h2 className="flex items-center gap-2 text-xl font-bold font-heading text-foreground border-b border-border pb-2">
                <span>{cat.emoji}</span>
                {cat.name}
              </h2>
              {cat.subcategories.map((sub) => (
                <SubcategorySection
                  key={sub.name}
                  name={sub.name}
                  emoji={sub.emoji}
                  tools={sub.tools}
                />
              ))}
            </div>
          ))
        ) : currentCategory ? (
          /* Single category */
          <div className="space-y-6">
            <h2 className="flex items-center gap-2 text-xl font-bold font-heading text-foreground border-b border-border pb-2">
              <span>{currentCategory.emoji}</span>
              {currentCategory.name}
            </h2>
            {currentCategory.subcategories.map((sub) => (
              <SubcategorySection
                key={sub.name}
                name={sub.name}
                emoji={sub.emoji}
                tools={sub.tools}
              />
            ))}
          </div>
        ) : null}
      </main>
    </div>
  );
}
