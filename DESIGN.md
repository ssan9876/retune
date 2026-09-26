---
name: Retune
description: A self-hosted Windows fleet console, re-materialised as a soft, calm studio that keeps every row of admin-center density.
colors:
  paper: "#f6f5fa"
  surface: "#ffffff"
  surface-sunken: "#f1eff7"
  surface-hover: "#f7f6fc"
  ink: "#1e1c2a"
  ink-muted: "#5e5a72"
  ink-faint: "#6b6782"
  rule: "#e7e4f0"
  rule-strong: "#d6d2e3"
  primary: "#5552d4"
  primary-hover: "#4744c2"
  primary-ink: "#ffffff"
  primary-wash: "#eceafd"
  primary-wash-strong: "#dedbfb"
  mark-start: "#6d6af0"
  mark-end: "#4a46c9"
  nav-ink: "#3d3a4e"
  status-active: "#13794a"
  status-active-wash: "#e3f4ea"
  status-stale: "#9a5b07"
  status-stale-wash: "#fbefd9"
  status-retired: "#c13b35"
  status-retired-wash: "#fce6e4"
  status-neutral: "#5d6275"
  status-neutral-wash: "#eeedf3"
  paper-dark: "#15141c"
  surface-dark: "#1e1c28"
  surface-sunken-dark: "#282634"
  surface-hover-dark: "#242230"
  ink-dark: "#eeecf6"
  ink-muted-dark: "#aca8c0"
  ink-faint-dark: "#8d89a3"
  rule-dark: "#302d3d"
  rule-strong-dark: "#3d3a4c"
  pane-border-dark: "#2b2938"
  primary-dark: "#a09df7"
  primary-hover-dark: "#b4b2fa"
  primary-ink-dark: "#16151d"
  primary-wash-dark: "#2a2850"
  primary-wash-strong-dark: "#34315f"
  header-dark: "#1a1923"
  nav-active-dark: "#262435"
  status-active-dark: "#4cc795"
  status-active-wash-dark: "#173327"
  status-stale-dark: "#e0a54c"
  status-stale-wash-dark: "#3a2c14"
  status-retired-dark: "#f07a72"
  status-retired-wash-dark: "#3d1d1c"
  status-neutral-dark: "#9aa0b3"
  status-neutral-wash-dark: "#2b2a36"
typography:
  display:
    fontFamily: "Figtree, system-ui, sans-serif"
    fontSize: "1.625rem"
    fontWeight: 700
    lineHeight: 1.3
    letterSpacing: "-0.025em"
  figure:
    fontFamily: "Figtree, system-ui, sans-serif"
    fontSize: "2rem"
    fontWeight: 700
    lineHeight: 1.1
    letterSpacing: "-0.02em"
    fontFeature: "tnum"
  headline:
    fontFamily: "Figtree, system-ui, sans-serif"
    fontSize: "1.375rem"
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: "-0.015em"
  title:
    fontFamily: "Figtree, system-ui, sans-serif"
    fontSize: "1.125rem"
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: "-0.015em"
  pane-title:
    fontFamily: "Figtree, system-ui, sans-serif"
    fontSize: "0.9375rem"
    fontWeight: 600
    lineHeight: 1.3
  body:
    fontFamily: "Figtree, system-ui, sans-serif"
    fontSize: "0.9375rem"
    fontWeight: 400
    lineHeight: 1.55
  body-sm:
    fontFamily: "Figtree, system-ui, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.55
    fontFeature: "tnum"
  label:
    fontFamily: "Figtree, system-ui, sans-serif"
    fontSize: "0.8125rem"
    fontWeight: 600
    lineHeight: 1.6
    letterSpacing: "0.01em"
  mono:
    fontFamily: "JetBrains Mono, ui-monospace, Cascadia Mono, monospace"
    fontSize: "0.88em"
    fontWeight: 400
    letterSpacing: "-0.01em"
    fontFeature: "tnum"
rounded:
  control: "8px"
  pane: "12px"
  overlay: "16px"
  pill: "999px"
spacing:
  "1": "4px"
  "2": "8px"
  "3": "12px"
  "4": "16px"
  "5": "20px"
  "6": "24px"
  "8": "32px"
  pane-padding: "20px"
  cell-padding: "16px"
  row-height: "44px"
  topbar-height: "56px"
  rail-width: "240px"
  rail-width-collapsed: "56px"
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.primary-ink}"
    typography: "{typography.body-sm}"
    rounded: "{rounded.control}"
    padding: "0 16px"
    height: "36px"
  button-primary-hover:
    backgroundColor: "{colors.primary-hover}"
    textColor: "{colors.primary-ink}"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.body-sm}"
    rounded: "{rounded.control}"
    padding: "0 16px"
    height: "36px"
  button-secondary-hover:
    backgroundColor: "{colors.surface-hover}"
    textColor: "{colors.primary}"
  button-quiet:
    backgroundColor: "transparent"
    textColor: "{colors.ink-muted}"
    rounded: "{rounded.control}"
    height: "36px"
  button-quiet-hover:
    backgroundColor: "{colors.primary-wash}"
    textColor: "{colors.primary}"
  button-danger:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.status-retired}"
    rounded: "{rounded.control}"
    height: "36px"
  button-danger-hover:
    backgroundColor: "{colors.status-retired-wash}"
    textColor: "{colors.status-retired}"
  input:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.body-sm}"
    rounded: "{rounded.control}"
    padding: "8px 12px"
    height: "36px"
  header-search:
    backgroundColor: "{colors.surface-sunken}"
    textColor: "{colors.ink-muted}"
    rounded: "{rounded.pill}"
    padding: "0 12px"
    height: "36px"
    width: "440px"
  pane:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.pane}"
    padding: "{spacing.pane-padding}"
  dialog:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.overlay}"
    padding: "24px"
    width: "560px"
  nav-item:
    backgroundColor: "transparent"
    textColor: "{colors.nav-ink}"
    typography: "{typography.body-sm}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "36px"
  nav-item-active:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.primary}"
  status-chip-active:
    backgroundColor: "{colors.status-active-wash}"
    textColor: "{colors.status-active}"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    padding: "1px 10px 1px 8px"
  status-chip-stale:
    backgroundColor: "{colors.status-stale-wash}"
    textColor: "{colors.status-stale}"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    padding: "1px 10px 1px 8px"
  status-chip-retired:
    backgroundColor: "{colors.status-retired-wash}"
    textColor: "{colors.status-retired}"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    padding: "1px 10px 1px 8px"
  status-chip-neutral:
    backgroundColor: "{colors.status-neutral-wash}"
    textColor: "{colors.status-neutral}"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    padding: "1px 10px 1px 8px"
  table-header:
    backgroundColor: "{colors.surface-sunken}"
    textColor: "{colors.ink-muted}"
    typography: "{typography.label}"
    padding: "12px 16px"
  table-row:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.body-sm}"
    padding: "8px 16px"
    height: "{spacing.row-height}"
---

# Design System: Retune

## Overview

**Creative North Star: "The Calm Studio"**

Retune is the same working console an endpoint engineer lives in all day, re-materialised from hard Fluent chrome into a soft, calm studio. Tonal layers and gentle depth do the work that hairlines and a saturated top band used to do: a lilac-tinted near-white page, white panes floating on soft two-layer shadows, and a sunken tone for wells, tracks and table heads. It should feel like a place, not a form. The fleet's state reads at a glance, actions are obvious, and nothing shouts except status.

Density is not negotiable. Tables keep 44px rows, identifiers never wrap, the nav rail keeps every destination visible, and KPI tiles and chart panes pack on a 16px gutter. Softness comes from material (tone, shadow, 12px pane and 8px control corners, pill chips), never from padding bloat or a consumer-app bounce. The system rejects the Intune admin-center clone look: no indigo top band, no 2px corners, no grey ramps, no borders drawn around everything.

Dark mode is designed, not inverted: an indigo-tinted charcoal where the page is the deepest layer, panes a step up and wells a step further, lifted by tone. Where soft shadows cannot read on the dark ground, a single 1px pane edge takes over.

**Provenance.** This world is an evolution of the incumbent console, pinned by the user's own words ("i like how everything looks now but I want it to look more inviting and softer"). FORM was fixed by that request; no concept roll ran, by design. Future work extends this world; it does not re-roll it.

**Key Characteristics:**
- Lilac-tinted page ground with white panes that float on soft, indigo-tinted two-layer shadows.
- Light header with a single saturated object, the indigo mark tile; no colour band.
- Borderless tinted nav rail; the current page is a raised white pill.
- Indigo is scarce: mark, active nav pill, focus, primary actions, text links, single-series data.
- Status is always a word plus a dot on its own wash, never colour alone.
- Figtree for every UI word, JetBrains Mono for every identifier.
- Admin-center density held intact: 44px rows, nowrap identifiers, 16px gutters.

## Colors

A cool, indigo-tinted neutral family carries almost everything; one indigo primary and four status hues are the only saturated colour, and each is rationed.

### Primary
- **Retune Indigo** (primary): the colour of doing and of being here. Primary buttons, the active nav pill's label, focus rings and focused-control borders, text links, the selected fleet filter, and single-series data bars (the Enrollments columns, the failed-deployments bar list). Hover goes deeper (primary-hover), never brighter: a brightened indigo turns lilac and reads as disabled. In dark it lifts to a soft periwinkle (primary-dark) with a near-black label (primary-ink-dark).
- **Indigo Wash** (primary-wash) and **Strong Indigo Wash** (primary-wash-strong): quiet-button and search-result hover, the avatar disc, the header badge, the update banner, the selected filter pill, and text selection.
- **Mark Gradient** (mark-start to mark-end, 145deg): only on the mark tile in the header and on the login panel. The one saturated object in the chrome.

### Neutral
- **Lilac Paper** (paper): the page ground, the header's scroll ground, and the nav rail. Every chrome surface shares it, so the white panes are what the eye lands on.
- **Pane White** (surface): panes, KPI tiles, tables, dialogs, menus, the active nav pill, controls.
- **Sunken Lilac** (surface-sunken): table header rows, notes, chart tracks, the header search field, meter tracks.
- **Hover Lilac** (surface-hover): secondary-button hover; table rows hover with a 4% primary mix over the surface instead.
- **Ink** (ink): primary text. **Muted Ink** (ink-muted): secondary text, column heads, hints, legends. **Faint Ink** (ink-faint): rail section labels, placeholders, crumb separators, the version line.
- **Rule** (rule): table row dividers and the menu head divider only. **Strong Rule** (rule-strong): control borders and the suite-name divider in the header.
- **Nav Ink** (nav-ink): resting rail link text.

### Status
- **Active Green**, **Stale Amber**, **Retired Red**, **Neutral Slate** (status-active / stale / retired / neutral), each with its own wash. The strong hue draws dots, meter segments, chart slices and chip text (mixed 80-85% with ink); the wash is the chip ground. Retired red doubles as the danger colour for destructive buttons and field errors.

### Named Rules
**The Rationed Indigo Rule.** Indigo appears only on the mark, the active nav pill, focus, primary actions, text links (which need an affordance) and single-series data such as the Enrollments bar chart. Anything else that wants indigo is either one of those or does not get it.

**The Status Is Meaning Rule.** The four status hues carry state and nothing else. Never use them for decoration, category colour or emphasis.

**The Tinted Neutral Rule.** Every neutral carries a little of the mark's indigo. No pure greys, light or dark.

**The Contrast Floor Rule.** Every text token clears 4.5:1 against the page and pane grounds it sits on: ink-faint is #6b6782 in light (4.98:1 on paper) and #8d89a3 in dark (4.98:1 on the dark pane); status-neutral is #5d6275 in light. A lighter "faint" is a defect, not a style.

## Typography

**Display Font:** Figtree (with system-ui, sans-serif), bundled at 400/500/600/700 via @fontsource
**Body Font:** Figtree
**Label/Mono Font:** JetBrains Mono (with ui-monospace, Cascadia Mono, monospace), bundled at 400/500

**Character:** Figtree's open, rounded forms make a dense console friendly to live in all day; JetBrains Mono holds every identifier, version and output where 0/O and 1/l/I must never collide. The scale sits one step above the admin centre's own 12/14: the density is worth copying, the eye strain is not.

### Hierarchy
- **Display** (700, 1.625rem, 1.3, -0.025em): the page title in each page's command bar, on the page ground.
- **Figure** (700, 2rem, 1.1, -0.02em, tabular): KPI tile values. Donut centres use 600 at 1.5rem.
- **Headline** (600, 1.375rem, 1.3): the default h1 outside the command bar (empty states, service-unavailable).
- **Title** (600, 1.125rem, 1.3): h2 section heads and dialog titles. The header product name uses 700 at 1.125rem, -0.02em.
- **Pane title** (600, 0.9375rem): the head of each chart pane or tile.
- **Body** (400, 0.9375rem, 1.55): running text. Empty-state copy caps at 52ch.
- **Body small** (400-600, 0.875rem): table cells, controls, buttons (600), nav links (500, active 600), legends, notes. The first cell of a table row is 500 in full ink: it is what the row is called.
- **Label** (600, 0.8125rem, 0.01em): column heads, status chips, rail section labels, hints and crumbs. Sentence case; never uppercase.
- **Mono** (400, 0.88em of its context, -0.01em): hostnames, serials, versions, tokens, script bodies and textareas.

### Named Rules
**The Tabular Figures Rule.** Every table cell, count and figure uses tabular numerals, so numbers are read against each other in a column.

**The Identifier Rule.** Anything a machine issued (hostname, serial, version, token, hash) is set in JetBrains Mono and never wraps.

## Layout

A fixed frame: a 56px header across the top, a 240px nav rail (56px collapsed, icons only with titles) on the left, and the content in the remaining corner, padded 20px/24px/32px. Header, rail and content ground share the paper tone; content lives in panes.

Spacing is a 4px base (4, 8, 12, 16, 20, 24, 32). Every pane, tile and dialog gives its contents the same pane padding (20px); table cells pad 16px horizontally. Panes sit on a 16px gutter: KPI tiles auto-fit at a 180px minimum, chart tiles at 320px, and the trend chart spans the full row.

The page head is the command bar: crumbs, then the display title on the left and the page's actions on the right, on the page ground with no rule beneath it.

Tables keep 44px rows at every width. Headers stick to the top of the window on wide screens. At 720px and below the shell becomes a single column: the rail turns into one horizontally scrolling strip of pills with section labels dropped, content padding drops to 16px, and each table scrolls sideways inside its own pane with nowrap cells rather than widening the page. On coarse pointers, buttons, fields, rail links and header controls grow to 44px minimum.

## Elevation & Depth

A hybrid of tonal layering and soft ambient shadow. In light, the page is tinted and panes are white; a pane's edge is its shadow, so light panes carry no border (pane-border is transparent). Shadows are two layers tinted with the ink's hue (rgba(38, 30, 90, ...)): a tight contact shadow and a wide ambient one. In dark, depth is carried by tone (page, pane, well each a step lighter), shadows go neutral black, and because soft shadows do not read on the dark ground, panes draw a 1px edge in pane-border-dark (#2b2938).

### Shadow Vocabulary
- **Card** (`box-shadow: 0 1px 3px rgba(38, 30, 90, 0.08), 0 4px 14px rgba(38, 30, 90, 0.07)`): every resting pane, KPI tile, table pane, empty state, and the active nav pill. Dark: `0 1px 2px rgba(0, 0, 0, 0.35), 0 4px 14px rgba(0, 0, 0, 0.22)`.
- **Raised** (`box-shadow: 0 2px 6px rgba(38, 30, 90, 0.08), 0 12px 32px rgba(38, 30, 90, 0.12)`): dialogs, menus, search results, the login panel, and a linked KPI tile on hover (with a 1px lift). Dark: `0 2px 8px rgba(0, 0, 0, 0.45), 0 16px 40px rgba(0, 0, 0, 0.4)`.
- **Bar** (`box-shadow: 0 1px 0 rgba(38, 30, 90, 0.06), 0 4px 16px rgba(38, 30, 90, 0.05)`): the header's bottom edge only, over an 88% translucent header with a 12px backdrop blur.
- **Focus ring** (`box-shadow: 0 0 0 3px color-mix(in srgb, var(--primary) 28%, transparent)`): focused controls and buttons; other focusable elements get a 2px primary outline at 2px offset.

### Named Rules
**The Edge Is The Shadow Rule.** In light, a pane is separated from the page by tone and shadow, never by a border. Hairlines are reserved for table row dividers and control borders.

**The Dark Edge Exception.** In dark, and only in dark, panes draw a 1px pane-border edge, because soft shadows vanish on the charcoal ground. It is a single quiet line, never a light glowing border.

**The One Ambient Glow.** The login screen carries a faint radial wash of the mark's own indigo (12%, `radial-gradient(60rem 36rem at 50% -10%, ...)`) behind the panel. First screen only; no other surface gets a gradient ground.

## Shapes

Soft, not bubbly. Controls, buttons, nav items, notes and search results round to 8px; panes, tiles, table panes, menus and the update banner to 12px; dialogs and the login panel to 16px; status chips, the header search, meters and fleet filters are full pills. The mark tile rounds to 8px (10px on the login panel). Chart bars round their tops at 4px, legend swatches at 3px. Large enough that nothing reads as a cut rectangle, small enough that a dense table still looks like a table. Panes clip their contents so a tinted table head never pokes past a rounded corner.

## Components

### Buttons
Calm and tactile: a gentle shadow at rest, a 1px press on active.
- **Shape:** gently rounded (8px), 36px tall, 16px horizontal padding, 600-weight small body text, never wrapping.
- **Primary:** indigo ground, white label, with an indigo-tinted glow shadow (`0 1px 2px rgba(38,30,90,0.12), 0 4px 12px` primary at 28%). One per context; the login sign-in spans the panel at 40px.
- **Hover / Focus:** primary deepens to primary-hover with a slightly larger glow. Focus-visible replaces the outline with the 3px focus ring. Active presses down 1px and drops the shadow. Transitions run on the shared 180ms curve.
- **Secondary:** white ground, strong-rule border, ink label, faint shadow; on hover the border tints toward indigo and the label turns indigo.
- **Quiet:** no border or ground, muted label; indigo wash and indigo label on hover.
- **Danger:** secondary shape with a retired-red label and a red-tinted border; retired wash on hover.
- **Disabled:** 50% opacity, no shadow, not-allowed cursor.

### Status chips
- **Style:** a pill on its own status wash, 600-weight label text in the status hue mixed 80-85% with ink, led by a 7px dot in the full hue. Active adds a soft 3px halo around its dot.
- **State:** four tones only (active, stale, retired, neutral). Charts, meters and legends map every state onto the same four tones.

### Fleet meter and filter pills
A slim 10px pill meter of status segments separated by 3px of the track's tint, never a slab. Its legend doubles as the filter: each entry is a pill with the count in bold; hover lifts it onto a white card shadow, and the applied filter sits on an indigo wash with an indigo edge.

### Cards / Containers (panes)
- **Corner Style:** 12px.
- **Background:** pane white on the lilac page.
- **Shadow Strategy:** Card shadow at rest; Raised on hover only when the whole pane is a link.
- **Border:** pane-border (transparent in light, #2b2938 in dark).
- **Internal Padding:** 20px. Pane heads pair a pane title with a muted hint on the right; footnotes sit in label-size muted text.

### Tables
Every table lives in a pane. The header row is a sunken-tone band of label-size, 600-weight muted column names, sticky to the window top. Rows are 44px with a rule divider (none after the last), hover with a 4% indigo tint, and grow vertically when a cell holds two lines. Numeric columns right-align. Identifiers never wrap; on mobile every cell is nowrap and the pane scrolls sideways.

### Inputs / Fields
- **Style:** white ground, strong-rule border, 8px corners, 36px minimum (38px inside a form field), small body text. Every select, textarea and text input gets this style, including those outside a form field, through a zero-specificity base rule, so component rules (the header search, form fields) still decide their own look. Selects drop the native arrow for a drawn chevron in muted ink, redrawn per theme.
- **Focus:** border shifts 60% toward indigo and the 3px focus ring appears; hover shifts it 25%.
- **Error / Disabled:** errors are label-size, 500-weight retired-red text under the field; disabled controls sit at 55% opacity. Form labels are 600 small body; hints are label-size muted. Textareas are monospaced.

### Notes and banners
A note is a tinted well, not a bordered box: sunken tone by default, or a status wash (error, pending, success) with text mixed 45% toward the status hue. The server-update banner is a 12px indigo-wash strip above the page.

### Navigation
- **Header:** light, translucent over the paper, with the Bar shadow. Burger, the indigo mark tile, the product name (700), a muted suite name behind a strong-rule divider (dropped below 900px), a centred pill search field on the sunken tone that turns white with a focus ring when active, and an initials avatar on an indigo-wash disc.
- **Rail:** borderless on the paper tone. Sentence-case section labels in faint ink; 36px links in nav ink with 70%-opacity icons. Hover lays a 60% indigo wash; the current page is a raised white pill with an indigo 600-weight label and full-opacity icon, carrying the Card shadow.
- **Mobile:** the rail becomes a single horizontally scrolling strip of pills under the header, with section labels and the version line hidden.
- **Crumbs:** label-size muted trail; the last crumb is ink at 500; links turn indigo on hover.

### Dialogs
A 560px white surface at 16px corners with the Raised shadow and a hairline edge, over a 45% indigo-black backdrop with a 3px blur. It rises 8px (and scales from 98.5%) on open over 220ms on the shared curve; reduced motion removes the animation.

### Charts
Donuts (140px), stacked bars, bar lists and daily columns share one grammar: sunken-tone tracks, status tones for state series, and indigo for single-series counts. A day with nothing enrolled still draws a sliver in rule tone. Bars grow in on first paint. Legends use 10px rounded swatches with right-aligned tabular figures.

### Motion
One curve for everything: 180ms `cubic-bezier(0.2, 0.8, 0.2, 1)` on background, border, shadow, colour and the rail collapse. Dialogs rise 8px on open. Reduced motion zeroes the transition token and removes the dialog animation.

## Do's and Don'ts

### Do:
- **Do** set every page on the lilac paper and put content in white panes at 12px corners with the Card shadow and 20px padding.
- **Do** keep tables at 44px rows inside their own pane, with tabular figures, nowrap identifiers in JetBrains Mono, and sideways scrolling on narrow screens.
- **Do** show status as the word plus a dot on its wash, in one of the four status tones.
- **Do** reserve indigo for the mark, the active nav pill, focus, primary actions, text links and single-series data.
- **Do** let dark mode separate layers by tone, and draw the 1px pane-border edge on dark panes only.
- **Do** use the shared 180ms curve for every state change and honour reduced motion.
- **Do** hold every text token at 4.5:1 or better on its ground.

### Don't:
- **Don't** bring back the indigo top band, 2px corners, grey ramps, or borders around every pane: the Intune admin-center clone look.
- **Don't** draw pane borders in light mode; the shadow is the edge.
- **Don't** use a status colour for decoration or show state by colour alone.
- **Don't** trade density for softness: no taller rows, no looser tables, no fewer nav items.
- **Don't** go bubbly or consumer-app: no radii beyond 16px on containers, no bouncy motion, no playful illustration.
- **Don't** put gradient or glow grounds on any screen but login.
- **Don't** set UI text in the monospace or identifiers in Figtree.
- **Don't** set labels, column heads or section names in uppercase or as eyebrow kickers over titles.
