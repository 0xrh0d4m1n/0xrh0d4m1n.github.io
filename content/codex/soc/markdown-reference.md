---
title: "Markdown Reference — Codex Showcase for All Elements"
tags:
  - showcase
  - markdown
  - reference
---

This **codex article** is a dummy reference page to test how every Markdown element renders in the codex section.

---

# Level 1 — Codex article title

Intro paragraph with **bold**, *italic*, and `inline code`. Links: [internal](/toolbox/) and [external](https://commonmark.org/).

## Level 2 — Major section

Content under h2. We can use ~~strikethrough~~ and **_combined emphasis_**.

### Level 3 — Subsection

Short paragraph.

#### Level 4

Even smaller.

##### Level 5

##### Level 6 — Minimum

---

## Unordered lists

- First bullet
- Second with **bold**
- Third with `code`
  - Nested level
  - Another nested
    - Deep nested

Alternative markers:

* Asterisk list
+ Plus list

---

## Ordered lists

1. First
2. Second
3. Third
   1. Nested ordered
   2. Second nested
4. Fourth

---

## Blockquotes

> Single blockquote. **Bold** and *italic* and `code` work here.

> Multi-paragraph blockquote.
>
> Second paragraph in same block.

> Nested:
> > Inner blockquote.

---

## Code blocks

**Bash:**

```bash
echo "Hello"
cat /etc/passwd | grep root
```

**Python:**

```python
def hello():
    print("World")
```

**JSON:**

```json
{"key": "value", "num": 42}
```

**YAML:**

```yaml
key: value
list:
  - a
  - b
```

**SQL:**

```sql
SELECT * FROM table WHERE id = 1;
```

**Plain:**

```
No language specified.
  Indented line.
```

---

## Tables

| Column A | Column B | Column C |
| -------- | -------- | -------- |
| Data 1   | Data 2   | Data 3   |
| **Bold** | `code`   | Normal   |

Alignment:

| Left   | Center | Right  |
| :----- | :----: | -----: |
| a      | b      | c      |

---

## Horizontal rules

Three styles:

---

***

___

---

## Task lists

- [ ] Todo item one
- [x] Done item one
- [ ] Todo with **bold**

---

## Links and images

- [About](/about/)
- [Blog](/blog/)
- [Link with title](https://example.com "Tooltip")

Image:

![Codex placeholder](/img/hero/b0740b2a8afc9453749b5e013a2db6fb.png)

---

## HTML: details/summary

<details>
<summary>Expand for reference</summary>

**Content** with *formatting* and `code`. [Link](/glossary/).
</details>

---

## Definition-style content (paragraphs with terms)

**SIEM** — Security Information and Event Management. Centralized logging and correlation.

**SOAR** — Security Orchestration, Automation and Response. Workflow and playbook automation.

**EDR** — Endpoint Detection and Response. Endpoint visibility and response.

---

## Mixed section

1. **Step**: Run the tool.
   ```bash
   tool --option value
   ```
2. **Step**: Check output.
   - Item A
   - Item B

| Result | Status |
| ------ | ------ |
| OK     | Pass   |

---

## Long paragraph

This is a long paragraph to test how the codex layout handles continuous text. In a real article you might explain a concept in detail, list prerequisites, or describe a procedure. The container should wrap the text comfortably and keep line length readable. No manual line breaks here—only the natural flow determined by the CSS and viewport.

---

## Summary

This codex showcase includes: **headings** (h1–h6), **paragraphs**, **bold**, *italic*, ~~strikethrough~~, `inline code`, [links](/), images, **unordered** and **ordered** lists (nested), **blockquotes** (single and nested), **fenced code blocks** (bash, python, json, yaml, sql, plain), **tables** (with alignment), **horizontal rules**, **task lists**, and **HTML** `<details>`/`<summary>`. Use it to verify codex article rendering.
