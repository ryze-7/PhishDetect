# PhishDetect

A Chrome extension that detects phishing websites in real time using client-side heuristics — no ML, no external API calls, no data leaving your browser.
PhishDetect does not collect, transmit, or store any user data outside the browser

## How it works

Every URL you visit gets scored against a set of detection rules. If the score crosses a threshold, the extension flags it as suspicious or blocks it outright.

**URL analysis (background.js)**
- Subdomain depth
- Brand spoofing
- Suspicious TLDs
- IP as hostname
- HTTPS check

**DOM inspection (content.js)**
- Form action mismatch — if a login form submits credentials to a different domain than the page you're on, that's a red flag
- Dead link ratio — phishing pages often fake a full website but leave all nav links pointing to `#`

**Local lists**
- Allowlist — top 100,000 domains from the Tranco list, skips scanning entirely for trusted sites
- Blocklist — 33,000+ verified phishing domains from PhishTank, instantly blocked on match

## Scoring

| Score | Verdict |
|-------|---------|
| 0–3 | Safe |
| 4–7 | Warn |
| 8+ | Block |

## Installation

1. Clone the repo
2. Open `chrome://extensions`
3. Enable Developer Mode
4. Click Load Unpacked and select the project folder

## Stack

Chrome Extensions (Manifest V3) · JavaScript · Chrome Storage API · declarativeNetRequest

## Limitations

- Brand list is currently limited to 10 major targets
- DOM flags (form action mismatch) are visible in the page console, not the popup, due to Chrome popup lifecycle constraints
- Blocklist is a static snapshot, phishing domains change daily
