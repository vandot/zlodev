# Zlodev Promotion Plan

**Goal:** Grow real users — developers actually using zlodev day-to-day for local HTTPS development.

**Strategy:** One coordinated launch across Hacker News and Reddit, preceded by SEO and discoverability prep. Sustained with ~30 min/week of low-effort community monitoring.

**Target audience:** All web developers who run local dev servers and want HTTPS without hassle.

---

## Phase 1: Pre-Launch — GitHub & SEO Prep (~2 hours)

### GitHub repo improvements

- **Repository topics**: Add `https`, `tls`, `reverse-proxy`, `local-development`, `localhost`, `developer-tools`, `zig`, `tui`, `certificate`, `dns`, `macos`, `linux`, `windows`.
- **About description** (repo sidebar one-liner): "Local HTTPS reverse proxy with auto-certificates, custom DNS, and a terminal UI — one command to get https://dev.lo"
- **Badges** at the top of README: CI status, license, latest release, platform support.
- **Demo GIF or screenshot** of the TUI in the README. This is the single highest-impact change — people scroll past text, they stop at visuals. **This is a hard prerequisite for Phase 2 launch.**
- **CONTRIBUTING.md**: Even a short one signals the project is alive and welcoming.

### Website SEO

- Add `<meta name="description">` targeted at search queries: "Free local HTTPS reverse proxy for developers. Auto-generated certificates, custom DNS, terminal UI. One command setup on macOS, Linux, and Windows."
- Add keyword-rich headings that match common searches: "Local HTTPS for development", "localhost SSL certificates".

### Tool directories (submit once, forget)

- Submit to awesome-lists: `awesome-selfhosted`, `awesome-developer-tools`, `awesome-zig`.
- Submit to alternativeto.com as an alternative to mkcert, Caddy, ngrok (for local use).

---

## Phase 2: Launch Day — Coordinated Posts (~1-2 hours)

### Hacker News (Show HN)

- **Title**: `Show HN: Zlodev – Local HTTPS reverse proxy with auto-certs and a terminal UI`
- **URL**: Post the website (zlodev.vandot.rs), not the GitHub repo. GitHub link goes in the text body.
- **Text body**: 3-4 sentences — what it does, why you built it, what makes it different from mkcert/Caddy/ngrok. End with the GitHub link.
- **Timing**: Tuesday–Thursday, 8-10am US Eastern.
- Be online ~2 hours after posting to answer comments.

### Reddit (2-3 subreddits, spaced 1-2 days apart)

- `/r/webdev` (~2M members) — primary target. Title: "I built a local HTTPS reverse proxy that gives you https://dev.lo with one command"
- `/r/selfhosted` — smaller but highly engaged.
- `/r/programming` — only if the HN post does well (50+ upvotes or reaches front page). Skip otherwise.

### What NOT to do

- Don't post on the same day as major tech news events.
- Don't use clickbait or oversell.
- Don't post the GitHub repo URL as the primary link (landing page converts better).
- Don't post all Reddit submissions on the same day.

---

## Phase 3: Ongoing Maintenance (~30 min/week)

### Weekly routine

- **Monitor and respond**: Check GitHub issues/discussions, reply to HN/Reddit comments. Responsiveness signals the project is alive — the #1 trust signal for dev tools.
- **Answer existing questions**: Search Reddit/Stack Overflow/GitHub for "local HTTPS development", "localhost SSL certificate", "dev server HTTPS". Reply only when zlodev genuinely fits.
- **Release notes**: Write clear release notes for updates. GitHub notifies starred/watched users. Good notes remind existing users the project is active.

### What NOT to do

- Don't re-post to HN/Reddit. Organic user mentions are worth 10x self-promotion.
- Don't chase vanity metrics (stars). Users opening issues means they're actually using it.

---

## Phase 4: Quick Wins That Compound (one-time, passive payoff)

- **GitHub Discussions**: Enable on the repo. Gives users a question space without cluttering issues. Discussions appear in Google search results.
- **Homebrew tap**: `brew install vandot/tap/zlodev` — the most trusted macOS install method. Removes friction for the largest target audience segment. (Note: this requires creating the tap repo first — it's a separate implementation task, not a quick config change.)
- **Comparison section on the website**: Honest table comparing zlodev to mkcert, Caddy, and ngrok. Developers frequently search "mkcert vs" and "ngrok alternative" — appearing in that comparison drives organic discovery. Keep it factual, not salesy.
- **"Used by" / "Works with" section**: Add once there are a few known users. Social proof is the strongest adoption driver for dev tools.

---

## Timeline

| When | What | Time |
|------|------|------|
| Day 1-2 | Phase 1: GitHub prep, SEO, directory submissions | ~2 hours |
| Day 3-5 | Phase 2: HN launch (Tue-Thu morning ET), then Reddit over next 2 days | ~1-2 hours |
| Week 2+ | Phase 3: Weekly monitoring and question-answering | ~30 min/week |
| When ready | Phase 4: Homebrew tap, comparison table, GitHub Discussions | ~2-3 hours total |

## Success signals

- GitHub issues from people you don't know (means real usage).
- Questions in GitHub Discussions or on Reddit/SO referencing zlodev.
- Organic mentions you didn't write.
- Install script / release download counts increasing.
