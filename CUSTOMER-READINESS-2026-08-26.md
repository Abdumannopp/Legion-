# Customer readiness — what was done and what remains

**Date:** 2026-08-26

This document is the result of the task "prepare the project for real
customers". The code's security had already been audited ([AUDIT-2.md](AUDIT-2.md));
what was missing this time was **the layer around the product** — the licence,
documentation that matches reality, and a guide the customer reads.

---

## Most important finding: the legal pages were not telling the truth

When opened on a customer's server, the `/privacy` page claimed:

- "what data we collect"
- "we may disclose data if required by law"
- "we may use limited analytics cookies"

The code was checked: **none of this was true.** Legion has no analytics, no
telemetry and no automatic update check. The whole code base sends data to only
three destinations: Groq (only if the customer provides a key), Paddle (switched
off entirely in self-hosted mode) and SMTP (the customer's own mail server).

So the page told the customer something false *about itself* — and in a security
product, that is the worst place to make this mistake. If the customer's lawyer
read it and concluded "so you collect our data", the sale is lost; if they
believed it, that is worse.

**Fixed.** Both pages were rewritten and now tell the truth: the customer runs
the installation, data does not leave their database, and data requests go to
the customer, not the vendor.

New mechanism: `{operator}` on the pages is replaced with the customer's
organisation name, via `NEXT_PUBLIC_OPERATOR_NAME`. If it is empty, the page
says so openly (`[the organisation running this installation]`) — it never
silently writes the wrong party's name.

---

## Other fixes

| What | Status |
|---|---|
| The version differed in four places (`/health` said "2.0.0", the packages "1.0.0") | Now read from one source — `package.json` — so they cannot drift apart again |
| There was no `LICENSE` file at all | A draft was written (see below) |
| Third-party licences were not listed anywhere | `NOTICE` — 327 packages |
| No installation guide for customers (the local-testing guide was for the owner's laptop) | `INSTALL.md` — 15 sections, in English |
| `npm run setup` did not write the frontend settings | It now creates `frontend/.env.local` too |

**Verified:** 119 tests passed, both typechecks clean, the server was started
from a clean build and `/health` was measured to really return
`"version":"1.0.0"`, and the operator-name substitution was tested in a real build.

---

## LICENSE — read carefully

The file starts with a large warning block, **on purpose**:

> DRAFT — NOT YET VALID. DO NOT GIVE THIS FILE TO A CUSTOMER AS-IS.

Two reasons:

1. **The company is not registered yet.** Software cannot be licensed in the
   name of a legal entity that does not exist. Fields such as
   `[LEGAL ENTITY NAME]` and `[JURISDICTION]` are empty for that reason.
2. **This is not legal advice.** The most important parts of a licence are the
   limitation of liability and the disclaimer of warranty — exactly the clauses
   a court may find weak if badly written. In a security product the question is:
   **who is responsible if an attack goes undetected?** A lawyer has to write that answer.

The conservative option was chosen — "all rights reserved", internal use for one
installation. Reason: it can be relaxed at any time later, but an open licence
cannot be taken back.

`NOTICE` lists three items to raise with a lawyer (sharp/libvips LGPL,
lightningcss MPL, caniuse-lite CC-BY). None of them prevents selling — but that
is an engineering assessment, not a legal opinion.

---

## Still not verified

These two were unchanged and only the owner can close them:

1. **Testing with a real Wazuh.** Not available at the time. This was the
   biggest unknown — the whole point of the product is this integration.
2. **A full test on Windows.** Everything was measured on Linux.

## Small, but visible in a sale

The default support address was a personal Gmail address with a typo in it.
Customers see it. Move to `support@` or `security@` on your own domain once you have one.
