import { yearText } from "../lib/year.ts";

// Fills every <span data-current-year> with the current year. Without JavaScript the
// span stays empty and the rest of the footer still reads correctly.
for (const element of document.querySelectorAll<HTMLElement>("[data-current-year]")) {
  element.textContent = yearText(new Date());
}
