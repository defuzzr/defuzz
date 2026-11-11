# Components

Include shared HTML with `<!-- include: footer.html -->`; invalid includes
produce one plain error line.
`<!-- include: header.html current=/about/ -->` marks matching links,
preserving existing `aria-current` attributes.
Import component scripts from `site.ts`;
`theme-init.html` applies the saved theme before rendering.
