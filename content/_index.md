---
# ─────────────────────────────────────────────────────────────────────────────
# Homepage — front matter do tema Hugoplate
# O tema não exibe o corpo do markdown na home; só usa banner, features e
# (via outras páginas) testimonial e call-to-action. Edite os valores abaixo.
# ─────────────────────────────────────────────────────────────────────────────

title: "0xrh0d4m1n"
description: "Hacking and general cybersecurity."

# Banner (topo da homepage): título, texto, imagem e botão opcional
banner:
  title: "Security research & defensive hacking"
  content: "Notes, writeups, and tools for red team, blue team, and building safer systems."
  image: "img/hero/banner.png"
  button:
    enable: true
    label: "Go to Blog"
    link: "/blog/"

# Features: blocos alternados com imagem (title, content, image, bulletpoints, button)
features:
  - title: "Blog"
    content: "Articles and notes on pentesting, DFIR, and security engineering."
    image: "img/features/blog.png"
    bulletpoints:
      - "Writeups and how-tos"
      - "Tool reviews and automation"
    button:
      enable: true
      label: "→ Blog"
      link: "/blog/"
  - title: "Writeups"
    content: "Walkthroughs from HTB, THM, VulnHub, and other labs."
    image: "img/features/writeups.png"
    bulletpoints:
      - "HTB, THM, VulnHub"
      - "Blue team challenges"
    button:
      enable: true
      label: "→ Writeups"
      link: "/writeups/"
  - title: "Codex"
    content: "Reference notes on networking, systems, and scripting."
    image: "img/features/codex.png"
    bulletpoints:
      - "Networking and protocols"
      - "Linux and scripting"
    button:
      enable: true
      label: "→ Codex"
      link: "/codex/"
  - title: "Toolbox"
    content: "Curated tools and one-liners for day-to-day ops."
    image: "img/features/toolbox.png"
    bulletpoints:
      - "CLI and web tools"
      - "Cheat sheets"
    button:
      enable: true
      label: "→ Toolbox"
      link: "/toolbox/"
  - title: "Glossary"
    content: "Definitions and concepts in cybersecurity."
    image: "img/features/glossary.png"
    bulletpoints:
      - "Terms and acronyms"
      - "Quick reference"
    button:
      enable: true
      label: "→ Glossary"
      link: "/glossary/"

# Testimonials e Call-to-action vêm de outras páginas:
#   • content/sections/testimonial.md  → enable, title, description, testimonials[]
#   • content/sections/call-to-action.md → enable, title, description, image, button
---
