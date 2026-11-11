# Accessibility

The site should work for everyone: keyboard users, screen reader
users, and people who need strong contrast or less motion. The
template starts with this baseline. Keep it when you change things.

## The baseline

- Semantic HTML: `header`, `nav`, `main`, `footer`, real `button` and
  `a` elements, headings in order.
- A skip link as the first thing on each page. It jumps to `main`. It
  is part of `src/components/header.html`. It stays hidden until it has
  keyboard focus. Then it appears at the very top of the page and
  pushes the header down, so it never covers another control.
- The menu marks the link to the current page with
  `aria-current="page"`. The `current=` setting in each page's header
  line adds it to every link whose `href` is exactly that address. A
  link that already has an `aria-current` attribute is left alone: the
  site name carries `aria-current="false"`, so on the home page only
  the menu link "Home" is marked. `404.html` marks no link.
- Visible focus: you can always see which element the keyboard is on.
  The ring uses the focus tokens in `design/tokens/tokens.css`.
- The theme switch is a `fieldset` with a `legend`, and its buttons
  show the chosen theme with `aria-pressed`.
- Labels: every form field has a `label`, and every icon-only button
  has an accessible name.
- Alt text: every image has a useful `alt`, or `alt=""` if it is only
  decoration. An SVG that carries meaning has a `<title>`.
- Contrast: text and background colours pass WCAG AA in light and dark
  mode. WCAG is the common set of web accessibility rules, and AA is
  its middle level: at least 4.5 to 1 for normal text, and 3 to 1 for
  large text and controls.
- Reduced motion: when the user asks for less motion
  (`prefers-reduced-motion`), the duration tokens become `0ms`, so
  transitions stop. There are no animations.
- Language: each page sets `lang` on the `html` element.
- One `h1` per page.

## Re-checking contrast

The colours live in `design/tokens/tokens.css`, and the colour pairs
to check live in `src/lib/contrast-pairs.ts`. After you change a
colour, run:

```bash
pnpm contrast
```

It prints the contrast ratio of each colour pair in both themes and
exits with a non-zero code if a pair fails. Each problem it finds is
one line that starts with `check-contrast: `. Inside `pnpm xtask ci`,
the unit tests list every colour pair the stylesheet declares, check
its contrast, and fail when a rule uses colour in a way they cannot
read.

## Colour rules

The unit tests in `tests/unit/stylesheet.test.ts` read
`src/styles/main.css` and `design/tokens/tokens.css` and enforce these
rules. When one fails, the message says what to change.

- Every rule that sets a background also sets `color`.
- Colour properties use only `var(--color-*)` tokens, plus
  `transparent`, `inherit`, `none`, and `currentColor` in a rule that
  also sets `color`.
- No gradients or images in backgrounds.
- `main.css` defines no custom properties. Tokens are defined only in
  `tokens.css`, and `tokens.css` gives no colour token a second name.
- Inside `@media (forced-colors: active)`, only system colours such as
  `Highlight` are used.
- Plain rules only, optionally inside `@media`, `@supports`, `@layer`
  or `@container`. No CSS nesting and no `@keyframes`.
- A new selector that uses colour must be added to the map `PLACES` in
  `tests/unit/stylesheet.test.ts`, which says what background it is
  drawn on. Its colour pairs must be added to
  `src/lib/contrast-pairs.ts`.

## Checklist for a new page

- [ ] The page has the head, header and footer includes, and its header
  line sets `current=` to the page's own address.
- [ ] The menu in `src/components/header.html` has a link with that
  address.
- [ ] `html` has `lang`, and the page has a `title` and a description.
- [ ] There is exactly one `h1`, and headings do not skip levels.
- [ ] Every image has `width`, `height` and `alt`.
- [ ] Every form field has a label.
- [ ] You can reach and use everything with the keyboard alone.
- [ ] New colours come from the tokens and pass the contrast check.
