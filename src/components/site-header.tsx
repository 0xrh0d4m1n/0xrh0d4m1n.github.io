"use client";

/**
 * Site header with main navigation, theme toggle, and responsive mobile menu.
 * Uses shadcn Button, Sheet, and Separator. Desktop: horizontal nav + theme.
 * Mobile: theme + hamburger that opens a Sheet from the right with nav links.
 */
import Link from "next/link";
import Image from "next/image";
import { usePathname } from "next/navigation";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useState } from "react";
import { icons } from "@/lib/icons";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { Separator } from "@/components/ui/separator";
import { cn } from "@/lib/utils";

/** Main navigation entries: label and href for each site section. */
const NAV_ITEMS = [
  { label: "Home", href: "/" },
  { label: "About", href: "/about/" },
  { label: "Blog", href: "/blog/" },
  { label: "Writeups", href: "/writeups/" },
  { label: "Codex", href: "/codex/" },
  { label: "Toolbox", href: "/toolbox/" },
  { label: "Glossary", href: "/glossary/" },
];

/**
 * Single nav link as a ghost Button wrapping Next.js Link.
 * Highlights when active (current path). Optional onClick (e.g. close mobile sheet).
 *
 * @param href - Destination path.
 * @param label - Link text.
 * @param isActive - Whether the current route matches this link.
 * @param onClick - Optional callback (e.g. close mobile menu on click).
 * @param className - Optional extra class names.
 */
function NavLink({
  href,
  label,
  isActive,
  onClick,
  className,
}: {
  href: string;
  label: string;
  isActive: boolean;
  onClick?: () => void;
  className?: string;
}) {
  return (
    <Button
      variant="ghost"
      size="sm"
      className={cn(
        "font-medium",
        isActive
          ? "bg-accent text-accent-foreground"
          : "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
        className,
      )}
      asChild
      onClick={onClick}
    >
      <Link href={href}>{label}</Link>
    </Button>
  );
}

/**
 * Sticky site header: logo, desktop nav (links + theme), and mobile menu (Sheet).
 * Active link is derived from pathname (exact match or prefix for non-home).
 */
export function SiteHeader() {
  const pathname = usePathname();
  const isHome = pathname === "/";
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <header className="sticky top-0 z-50 w-full border-b border-border bg-background/80 backdrop-blur-md">
      <div
        className={`mx-auto flex h-14 items-center justify-between px-4 ${
          isHome ? "max-w-6xl" : "w-[90vw] max-w-none"
        }`}
      >
        <Button variant="ghost" size="sm" className="font-heading text-lg font-bold tracking-tight text-primary px-2 gap-2" asChild>
          <Link href="/" className="flex items-center gap-2">
            <span className="relative h-8 w-8 shrink-0 overflow-hidden rounded-full border-[3px] border-muted-foreground bg-muted dark:border-primary">
              <Image
                src="/img/logos/logo.svg"
                alt=""
                width={32}
                height={32}
                className="h-full w-full object-cover"
              />
            </span>
            <span>0xrh0d4m1n</span>
          </Link>
        </Button>

        {/* Desktop nav */}
        <nav className="hidden items-center gap-1 md:flex">
          {NAV_ITEMS.map(({ label, href }) => (
            <NavLink
              key={href}
              href={href}
              label={label}
              isActive={
                pathname === href ||
                (href !== "/" && pathname.startsWith(href))
              }
            />
          ))}
          <Separator orientation="vertical" className="h-5 mx-1" />
          <ThemeToggle />
        </nav>

        {/* Mobile: theme + sheet trigger */}
        <div className="flex items-center gap-2 md:hidden">
          <ThemeToggle />
          <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
            <SheetTrigger asChild>
              <Button
                variant="outline"
                size="icon"
                aria-label="Toggle menu"
              >
                <FontAwesomeIcon icon={icons.bars} className="h-4 w-4" />
              </Button>
            </SheetTrigger>
            <SheetContent side="right" className="w-64">
              <SheetHeader>
                <SheetTitle className="font-heading">Menu</SheetTitle>
              </SheetHeader>
              <Separator />
              <nav className="flex flex-col gap-1 pt-4">
                {NAV_ITEMS.map(({ label, href }) => (
                  <NavLink
                    key={href}
                    href={href}
                    label={label}
                    isActive={
                      pathname === href ||
                      (href !== "/" && pathname.startsWith(href))
                    }
                    onClick={() => setMobileOpen(false)}
                    className="justify-start w-full"
                  />
                ))}
              </nav>
            </SheetContent>
          </Sheet>
        </div>
      </div>
    </header>
  );
}
