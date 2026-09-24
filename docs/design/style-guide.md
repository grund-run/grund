# Style guide

Status: normative for grund's product pages. The reference is Kasper's
dashboard design (grund/website `design/reference/dashboard-overview.png`,
the Overview screen). The implementation is
`crates/grund-server/assets/grund.css`, and every component below is
rendered by `/style-guide` on any running instance, with example data.

## The idea

**A calm, dark, green-tinted surface where the only bright things are the
state of your apps and the one thing you might want to do next.** Colour
means state (serving, updating, attention); everything else is quiet
greys on a near-black green. There is one primary action per page, in the
pale-green button. The page reads top to bottom as: where you are, how
things are, what needs you, the list, the small print.

## Tokens

Colours are CSS custom properties on `:root`. They are grund/website's
tokens, so the site and the product read as one thing. Never write a raw
hex value in a component; add a token instead.

| Token | Value | Use |
|---|---|---|
| `--bg` | `#141c18` | page background |
| `--bg-raised` | `#18201c` | sidebar, inputs |
| `--surface` | `#1f2722` | cards, callouts, secondary buttons |
| `--surface-hover` | `#253029` | hover on surfaces |
| `--active` | `#28352c` | the selected nav item, avatars, success banners |
| `--border` | `#262f29` | dividers between rows, card borders |
| `--border-strong` | `#313c35` | input borders, tags |
| `--text` | `#eef3ef` | titles, names, body text |
| `--text-2` | `#c3ccc6` | secondary text, descriptions, statuses |
| `--muted` | `#8a948e` | counts, hints, separators |
| `--accent` | `#b8dab3` | primary buttons, the brand mark, focus rings |
| `--accent-text` | `#b5d8a8` | links and "View all →" |
| `--accent-ink` | `#0e1710` | text on the accent |
| `--ok` | `#a9d8a0` | serving, done, the check in status lines |
| `--blue` | `#7fb6ea` | in progress (the rollout spinner), charts |
| `--orange` | `#e8a57a` | updates available, needs attention |
| `--violet` | `#b48fe6` | code, APIs, devices |
| `--danger` | `#ef9a8f` on `--danger-surface` `#2c1f1d` | errors, destructive actions |

Icon tones (`tone-ok`, `tone-blue`, `tone-orange`, `tone-violet`,
`tone-muted`) colour an icon by what it stands for, as the design does for
app icons. The tone is decided by the kind of thing, never at random.

**Type.** Inter for everything (`--sans`), JetBrains Mono (`--mono`) for
anything a person might copy: addresses, hosts, ids, commands. Both fonts
are self-hosted (the CSP allows no other origin), and their licenses are
at `/licenses`.

| Role | Size | Weight |
|---|---|---|
| Page title (`.page-title`) | 2.25–3 rem, tight tracking | 600 |
| Section title (`.section-title`) | 1.875 rem | 600 |
| Card and row names | 1.1875 rem | 500–600 |
| Body | 1 rem, line height 1.55 | 400 |
| Status line | 1.1875 rem, `--text-2` | 400 |
| Hints and tags | 0.75–0.875 rem, `--muted` | 400–500 |

**Shape.** Radii are `--radius-sm` (8 px) for buttons and inputs, `--radius`
(12 px) for cards and callouts, and full round for tags and avatars.
Shadows are not used: depth comes from the three surface steps (`--bg`,
`--bg-raised`, `--surface`).

**Space.** The sidebar is 256 px. The top bar is 74 px. Content is at most
1160 px wide with a responsive gutter (`--gutter`, 1.25–3.75 rem).
Sections are 4 rem apart.

## Layout

- **App shell** (`.shell`): the sidebar (`.sidebar`) on the left, then the
  top bar (`.topbar`) and the content (`.content`). Below 900 px the
  sidebar becomes a bar across the top and hides unavailable items.
- **Sidebar**: the brand (the mark and "grund"), the main nav, then at the
  bottom the docs link, settings and the avatar (initials).
  - A nav item (`.nav-item`) is an icon plus a label.
  - The current one is `.is-active` with `aria-current="page"`.
  - Something not built yet is shown `aria-disabled="true"` with a
    `Soon` tag. It is never a link to nothing.
- **Top bar**: breadcrumbs (`.crumbs`, organisation / place), with actions
  (sign out, later search) at the end.
- **Signed-out pages** (`.auth`, `.auth-card`): one centred column, 27 rem
  wide, with the brand, a title, one line of lede, and the form.

## Components

| Component | Classes | Rules |
|---|---|---|
| Page head | `.page-head`, `.page-title`, `.status-line` | Title and one status line that says how things are ("All applications are serving traffic."), with a toned icon. The page's one primary button sits at the right |
| Buttons | `.btn` with `.btn-primary`, `.btn-secondary`, `.btn-danger`, `.btn-ghost`; `.btn-block`, `.btn-sm` | One primary per page. Destructive actions are `.btn-danger` and say what they do ("Sign out"), never "OK" |
| Links onward | `.link-more` | Accent text plus an arrow: "View all →", "View rollout →" |
| Callout | `.callout`, `.callout-title`, `.callout-text`, `.spinner` | Something happening now or needing attention: an icon or spinner, a title that names the thing, one sentence of detail, and one onward link. `.callout-danger` for failures |
| Section head | `.section-head`, `.section-title`, `.count` | Title, then a muted count, then "View all →" at the right |
| Resource rows | `.rows`, `.row`, `.row-icon`, `.row-name`, `.row-sub`, `.row-status`, `.row-end` | Icon, name over its address in mono, a status (toned check plus word), and a chevron or an action at the end. Rows are divided by `--border`, with no boxes |
| Notice | `.notice` | A one-line fact with an icon and an onward link at the right ("An update is available for Plausible.") |
| Stats | `.stats` | Small print at the foot: icon plus fact, separated by dots |
| Tags | `.tag`, `.tag-ok` | Tiny, rounded, muted. "Soon", "Current" |
| Empty state | `.empty` | A dashed box: a bold line saying what is missing, and one sentence saying how it will appear |
| Forms | `.form`, `.field`, `.hint`, `.field-error`, `.form-error`, `.form-ok`, `.form-foot`, `.or`, `.providers` | Label above the input. A hint under it until there is an error, which replaces the hint (`aria-invalid`, `aria-describedby`). One banner for the whole form above the fields. Secondary links go in the foot |

## Icons

One inline SVG sprite at the top of every page (`templates/base.html.jinja`),
used as `<svg class="icon"><use href="#i-name"/></svg>` through the
`ui.icon` macro. They are 24-unit stroke icons (1.75 stroke, round caps and
joins) drawn for grund, the same set as grund.sh. The brand mark is
`#mark`. SVG presentation attributes are not inline styles, so the CSP
allows them. Add an icon to the sprite; never inline one ad hoc.

## Words

The product skill's voice applies: plain and short, saying what you get,
with no infrastructure lingo.

- Status lines are sentences with a full stop ("All applications are
  serving traffic.").
- Buttons are verbs ("Deploy application", "Sign out everywhere else").
- Errors say what happened and what to do next ("That email, username or
  password is not right.", "Try again in 15 minutes, or reset your
  password."). Never an error code or a stack trace; the page shows a
  reference id when something broke.
- Anything unbuilt says so: a `Soon` tag, or a callout "… is in
  development".

## Rules the build enforces

- The CSP (`crates/grund-server/src/web/mod.rs`) allows scripts, styles,
  fonts and images from this origin only. **No inline `<script>`,
  `<style>`, `style=` or `on*=`.** The accepttest
  `every_page_is_html_that_needs_nothing_the_csp_forbids_and_is_never_cached`
  fails the build on any of them.
- Templates are `.html.jinja`, so they autoescape. Nothing is marked
  `|safe` except the stylesheet link, which is a constant.
- The stylesheet is linked with a content hash (`/static/grund.css?v=`) and
  cached for a year, so an edit is picked up by the next build with no
  renaming.
- Look at a change in a real browser against the real server, so the CSP
  applies: headless Chrome at 1440 px and 390 px wide, with the console
  checked for "Content Security Policy" (skills `testing`).
