# Zlodev Promotion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prepare zlodev for its first public launch — optimize discoverability, add visual polish, create launch content, then execute a coordinated launch across Hacker News and Reddit.

**Architecture:** Four phases executed sequentially: GitHub repo prep (Tasks 1-4), website SEO + comparison (Tasks 5-6), launch content drafting (Tasks 7-8), and manual launch execution (Task 9). Phases 1-2 produce automatable file changes. Phase 3 produces draft text for the user to review. Phase 4 is a manual checklist.

**Tech Stack:** Markdown (README, CONTRIBUTING), HTML/CSS (website), GitHub CLI (`gh`), terminal recording (`vhs` or `asciinema`)

---

### Task 1: Add badges to README

**Files:**
- Modify: `README.md:1-2`

- [x] **Step 1: Add badge row after the H1 heading**

Insert this line immediately after `# zlodev`:

```markdown
[![CI](https://github.com/vandot/zlodev/actions/workflows/ci.yml/badge.svg)](https://github.com/vandot/zlodev/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Release](https://img.shields.io/github/v/release/vandot/zlodev)](https://github.com/vandot/zlodev/releases) ![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey)
```

- [x] **Step 2: Verify badges render correctly**

Run: `open https://github.com/vandot/zlodev` (after push) or preview locally with a Markdown renderer.

Expected: Four badges in a row — green CI, blue MIT, version number, platform list.

- [x] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: add CI, license, release, and platform badges to README"
```

---

### Task 2: Record and add TUI demo GIF to README

**Files:**
- Create: `docs/demo.gif` (or `docs/demo.svg` if using `vhs`)
- Modify: `README.md:5` (after the description paragraph)

This is the **highest-impact change** in the entire plan and a **hard prerequisite for launch**.

- [x] **Step 1: Record a TUI demo**

Option A — Using [vhs](https://github.com/charmbracelet/vhs) (produces SVG/GIF from a script):

Create a file `demo.tape`:
```
Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 600
Set Theme "Dracula"

Type "zlodev start --port=3000"
Enter
Sleep 3s

# Generate some traffic in background so the TUI populates
Type@100ms ""
Sleep 5s
```

Before recording, set up a background script that curls the proxy to generate visible traffic:
```bash
# Run in a separate terminal before starting vhs
for i in $(seq 1 10); do curl -sk https://dev.lo/api/users; curl -sk https://dev.lo/health; sleep 0.5; done
```

Run: `vhs demo.tape -o docs/demo.gif`

Option B — Manual screenshot:
1. Start zlodev with some traffic flowing
2. Take a screenshot of the TUI showing a populated request list
3. Save as `docs/demo.png`

Option C — Using `asciinema`:
1. `asciinema rec demo.cast`
2. Start zlodev, generate some traffic, show the TUI
3. Convert to GIF with `agg` or use asciinema player embed

**The demo should show:** The TUI with 5-10 requests visible, showing method colors, paths, status codes, and timing. The goal is to make someone think "that looks useful" in 2 seconds.

- [x] **Step 2: Add the GIF/image to README**

Insert after the description paragraph (line 5), before `## Features`:

```markdown

<p align="center">
  <img src="docs/demo.gif" alt="zlodev TUI demo" width="800">
</p>

```

If using a PNG screenshot instead:
```markdown

<p align="center">
  <img src="docs/demo.png" alt="zlodev TUI" width="800">
</p>

```

- [x] **Step 3: Commit**

```bash
git add docs/demo.gif README.md   # or docs/demo.png
git commit -m "docs: add TUI demo GIF to README"
```

---

### Task 3: Create CONTRIBUTING.md

**Files:**
- Create: `CONTRIBUTING.md`

- [x] **Step 1: Write a short contributing guide**

```markdown
# Contributing to zlodev

Thanks for your interest in contributing!

## Getting started

1. Install [Zig 0.15.1](https://ziglang.org/download/)
2. Clone the repo and build:
   ```sh
   git clone https://github.com/vandot/zlodev.git
   cd zlodev
   zig build
   ```
3. Run tests per-file:
   ```sh
   zig test src/dns.zig
   zig test src/proxy.zig
   zig test src/requests.zig
   ```

## How to contribute

- **Bug reports**: Open an issue with steps to reproduce
- **Feature requests**: Open an issue describing the use case
- **Pull requests**: Fork, create a branch, make your changes, and open a PR

## Code style

- Follow existing patterns in the codebase
- Use structured log format: `component=X op=Y field=value`
- Run relevant tests before submitting

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
```

- [x] **Step 2: Commit**

```bash
git add CONTRIBUTING.md
git commit -m "docs: add CONTRIBUTING.md"
```

---

### Task 4: Set GitHub repo topics and description

**Files:** None (GitHub API only)

- [x] **Step 1: Set repository description**

```bash
gh repo edit vandot/zlodev --description "Local HTTPS reverse proxy with auto-certificates, custom DNS, and a terminal UI — one command to get https://dev.lo"
```

- [x] **Step 2: Add repository topics**

```bash
gh repo edit vandot/zlodev --add-topic https,tls,reverse-proxy,local-development,localhost,developer-tools,zig,tui,certificate,dns,macos,linux,windows
```

- [x] **Step 3: Enable GitHub Discussions**

```bash
gh repo edit vandot/zlodev --enable-discussions
```

- [x] **Step 4: Verify**

Run: `gh repo view vandot/zlodev`

Expected: Description and topics shown. Discussions enabled.

---

### Task 5: Improve website SEO meta tags

**Files:**
- Modify: `docs/index.html:8` (meta description)

- [x] **Step 1: Update the meta description**

Replace the existing meta description (line 8):

```html
  <meta name="description" content="Free local HTTPS reverse proxy for developers. Auto-generated certificates, custom DNS, terminal UI. One command setup on macOS, Linux, and Windows.">
```

- [x] **Step 2: Add additional meta keywords tag**

After the meta description, add:

```html
  <meta name="keywords" content="local HTTPS, localhost SSL, dev server HTTPS, reverse proxy, TLS certificates, developer tools, mkcert alternative, ngrok alternative">
```

- [x] **Step 3: Commit**

```bash
git add docs/index.html
git commit -m "docs: improve website meta description and add keywords for SEO"
```

---

### Task 6: Add comparison section to website

**Files:**
- Modify: `docs/index.html` (insert new section before footer, line 982)

- [x] **Step 1: Add comparison section HTML**

Insert before the `<footer>` tag (before line 983):

```html
<section class="details" id="compare">
  <div class="container">
    <div class="section-label reveal">Comparison</div>
    <div class="section-title reveal">How zlodev compares</div>
    <p class="section-subtitle reveal">zlodev replaces multiple tools with a single binary. Here's how it stacks up.</p>
    <div class="compare-table-wrap reveal">
      <table class="compare-table">
        <thead>
          <tr>
            <th></th>
            <th>zlodev</th>
            <th>mkcert</th>
            <th>Caddy</th>
            <th>ngrok</th>
          </tr>
        </thead>
        <tbody>
          <tr><td>Local HTTPS with auto-certs</td><td class="cmp-yes">&#10003;</td><td class="cmp-yes">&#10003;</td><td class="cmp-yes">&#10003;</td><td class="cmp-yes">&#10003;</td></tr>
          <tr><td>Custom local DNS (*.lo)</td><td class="cmp-yes">&#10003;</td><td class="cmp-no">&#10007;</td><td class="cmp-no">&#10007;</td><td class="cmp-no">&#10007;</td></tr>
          <tr><td>Terminal UI for traffic</td><td class="cmp-yes">&#10003;</td><td class="cmp-no">&#10007;</td><td class="cmp-no">&#10007;</td><td class="cmp-yes">&#10003;</td></tr>
          <tr><td>Request interception &amp; editing</td><td class="cmp-yes">&#10003;</td><td class="cmp-no">&#10007;</td><td class="cmp-no">&#10007;</td><td class="cmp-no">&#10007;</td></tr>
          <tr><td>Multi-app routing</td><td class="cmp-yes">&#10003;</td><td class="cmp-no">&#10007;</td><td class="cmp-yes">&#10003;</td><td class="cmp-no">&#10007;</td></tr>
          <tr><td>Single binary, no dependencies</td><td class="cmp-yes">&#10003;</td><td class="cmp-yes">&#10003;</td><td class="cmp-yes">&#10003;</td><td class="cmp-no">&#10007;</td></tr>
          <tr><td>Free &amp; open source</td><td class="cmp-yes">&#10003;</td><td class="cmp-yes">&#10003;</td><td class="cmp-yes">&#10003;</td><td class="cmp-no">&#10007;</td></tr>
          <tr><td>No account required</td><td class="cmp-yes">&#10003;</td><td class="cmp-yes">&#10003;</td><td class="cmp-yes">&#10003;</td><td class="cmp-no">&#10007;</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</section>

```

- [x] **Step 2: Add comparison table CSS**

Add the following CSS inside the existing `<style>` block, before the closing `</style>` tag:

```css
    .compare-table-wrap { overflow-x: auto; margin-top: 2rem; }
    .compare-table { width: 100%; border-collapse: collapse; font-family: var(--font-body); font-size: 0.95rem; }
    .compare-table th, .compare-table td { padding: 0.75rem 1rem; text-align: center; border-bottom: 1px solid var(--border); }
    .compare-table th:first-child, .compare-table td:first-child { text-align: left; }
    .compare-table th { color: var(--text-muted); font-weight: 500; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }
    .compare-table th:nth-child(2) { color: var(--accent); }
    .compare-table td { color: var(--text); }
    .cmp-yes { color: var(--green); font-weight: 700; }
    .cmp-no { color: var(--text-dim); }
```

- [x] **Step 3: Add "Compare" link to navigation**

In `docs/index.html`, find the nav links (around line 663-665):

```html
      <a href="#features">Features</a>
      <a href="#why-https">Why HTTPS?</a>
      <a href="#quickstart">Quick start</a>
```

Add after the last link:

```html
      <a href="#compare">Compare</a>
```

- [x] **Step 4: Verify locally**

Open `docs/index.html` in a browser. The comparison table should:
- Match the dark theme
- Highlight zlodev column header in accent blue
- Show green checkmarks and dim X marks
- Be responsive (horizontal scroll on mobile)

- [x] **Step 5: Commit**

```bash
git add docs/index.html
git commit -m "docs: add tool comparison section to website"
```

---

### Task 7: Draft Hacker News "Show HN" post

**Files:**
- Create: `docs/superpowers/launch/hn-post.md` (draft, not committed to main)

- [ ] **Step 1: Write the HN post draft**

```markdown
# Show HN: Zlodev – Local HTTPS reverse proxy with auto-certs and a terminal UI

**URL to submit:** https://zlodev.vandot.rs

**Text body (paste into the HN text field):**

I built zlodev to replace my setup of mkcert + manual /etc/hosts editing + nginx for local HTTPS. It's a single binary that gives you `https://dev.lo` with one command — auto-generates a CA, installs it in your system trust store, runs a DNS server for `*.lo`, and proxies to your local dev server with TLS termination.

It also has a terminal UI for inspecting traffic in real time — you can intercept and edit requests/responses before they reach your backend, replay requests, and export to HAR. Routing supports subdomains (`api.dev.lo → :3001`), path prefixes (`/api → :3001`), and external upstreams.

Written in Zig, works on macOS, Linux, and Windows. MIT licensed.

GitHub: https://github.com/vandot/zlodev
```

- [ ] **Step 2: Review and personalize**

The draft above is a starting point. Personalize it:
- Why did you specifically build this? What was the pain point?
- Any interesting technical decisions worth mentioning?
- Keep it to 3-4 short paragraphs max

---

### Task 8: Draft Reddit posts

**Files:**
- Create: `docs/superpowers/launch/reddit-posts.md` (draft, not committed to main)

- [ ] **Step 1: Write the /r/webdev post draft**

```markdown
# /r/webdev

**Title:** I built a local HTTPS reverse proxy that gives you https://dev.lo with one command

**Body:**

I got tired of juggling mkcert + /etc/hosts + nginx configs every time I needed HTTPS locally, so I built zlodev — a single binary that handles all of it.

Run `zlodev install && zlodev start --port=3000` and you get `https://dev.lo` pointing at your local server. It auto-generates certificates, installs them in your system trust store, and runs its own DNS so `*.lo` resolves to localhost.

It also has a TUI for live traffic inspection — you can intercept requests, edit them before they hit your backend, replay them, and export to HAR. Supports routing by subdomain (`api.dev.lo`) or path prefix (`/api`).

Website: https://zlodev.vandot.rs
GitHub: https://github.com/vandot/zlodev

Happy to answer any questions!
```

- [ ] **Step 2: Write the /r/selfhosted post draft**

```markdown
# /r/selfhosted

**Title:** zlodev — self-hosted local HTTPS proxy with auto-certs, DNS, and a terminal UI

**Body:**

I built a local dev proxy that replaces the typical mkcert + hosts file + nginx setup with a single binary. It generates its own CA, manages DNS for `*.lo`, and gives you a TUI for inspecting and intercepting traffic.

No cloud, no accounts, no dependencies. Single binary, MIT licensed. Works on macOS, Linux, and Windows.

Website: https://zlodev.vandot.rs
GitHub: https://github.com/vandot/zlodev
```

---

### Task 9: Launch execution checklist (manual)

This task is a manual checklist — no code changes. Execute on launch day (Tuesday–Thursday, 8-10am US Eastern).

- [ ] **Step 1: Verify all prep is complete**

Before launching, confirm:
- [ ] Badges visible on GitHub README
- [ ] Demo GIF/screenshot in README
- [ ] CONTRIBUTING.md exists
- [ ] Repo description and topics set
- [ ] GitHub Discussions enabled
- [ ] Website meta tags updated
- [ ] Comparison table on website
- [ ] All changes pushed to `main`

- [ ] **Step 2: Submit to Hacker News**

Go to https://news.ycombinator.com/submit
- Title: `Show HN: Zlodev – Local HTTPS reverse proxy with auto-certs and a terminal UI`
- URL: `https://zlodev.vandot.rs`
- Text: Paste the body from `docs/superpowers/launch/hn-post.md`

Stay online for ~2 hours to answer comments.

- [ ] **Step 3: Submit to /r/webdev (next day)**

Post to https://www.reddit.com/r/webdev/submit using the draft from Task 8.

- [ ] **Step 4: Submit to /r/selfhosted (day after)**

Post to https://www.reddit.com/r/selfhosted/submit using the draft from Task 8.

- [ ] **Step 5: Submit to /r/programming (only if HN got 50+ upvotes)**

Cross-post or write a new post for https://www.reddit.com/r/programming/submit.

- [ ] **Step 6: Submit to tool directories**

- [ ] Open PR to [awesome-selfhosted](https://github.com/awesome-selfhosted/awesome-selfhosted)
- [ ] Open PR to [awesome-developer-tools](https://github.com/moimikey/awesome-developer-tools)
- [ ] Open PR to [awesome-zig](https://github.com/catdevnull/awesome-zig)
- [ ] Submit to [alternativeto.com](https://alternativeto.net) as an alternative to mkcert, Caddy, ngrok

---

### Task 10: Set up weekly monitoring routine

This is a recurring manual process, not a code task. Set a weekly 30-minute calendar reminder.

- [ ] **Step 1: Bookmark search queries**

Save these searches in your browser:
- Reddit: `site:reddit.com "local HTTPS" OR "localhost SSL" OR "dev server certificate"`
- Stack Overflow: `[https] localhost certificate development`
- GitHub: `local HTTPS proxy` (in issues/discussions across repos)

- [ ] **Step 2: Weekly routine**

Each week (~30 min):
1. Check GitHub issues and Discussions for new activity — respond to everything
2. Run the saved searches — if someone is asking for exactly what zlodev does, reply helpfully (don't spam)
3. If you've shipped an update, write release notes on the GitHub release
