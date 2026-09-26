---
version: 1
slug: "web-src"
primary_target: "web/src"
related_targets: []
---

Scope: the whole Retune admin console (web/src), every route. Mode: Operate.
Audience and job: enterprise desktop/endpoint engineers in long daily sessions; helpdesk for tier-1 actions. Task first; density is a feature.
Constraints (confirmed by the user, 2026-09-26): keep information architecture, every function and today's density; must not turn bubbly or consumer-app; must not wash out contrast or status colour; dark mode designed as carefully as light. Chosen: light header instead of the indigo bar; a warmer UI face (Figtree) with identifiers kept monospaced.

## Direction contract

THESIS: The same working console, re-materialised from hard Fluent chrome into a soft, calm studio: tonal layers and gentle depth replace hairlines and the saturated band. It refuses the Intune admin-center clone look (indigo top band, 2px corners, grey ramps, borders everywhere) without losing a single row of density.

OWN-WORLD: Lilac-tinted near-white page, white panes floating on soft two-layer shadows, 12px pane / 8px control corners, pill chips on status washes. Indigo lives only in the mark, the active nav pill, focus and primary actions. Figtree for all UI text, JetBrains Mono for identifiers. Dark: indigo-tinted charcoal lifted by tone, not by borders.

STORY: An engineer opens it for the day and it feels like a place, not a form: the fleet's state is readable at a glance, actions are obvious, nothing shouts except status.

FIRST VIEWPORT: Light header (mark tile, name, search centred, avatar) with a soft bottom shadow; borderless tinted nav rail with a pill for the active item; page title on the page ground; KPI tiles and chart panes as white floating panes on a 16px gutter.

FORM: Evolution of the incumbent world at the user's request (refinement-led redesign); no concept roll: the user pinned "I like how everything looks now". Seed key: none (pinned).

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
