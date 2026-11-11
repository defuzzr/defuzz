import {
  nextState,
  parseChoice,
  readStoredChoice,
  type ThemeChoice,
  writeStoredChoice,
} from "../lib/theme.ts";

// Wires the buttons in theme-switch.html. The switch is hidden in the HTML and only
// shown here, so without JavaScript there is no control that does nothing.

const storage = (): Storage => localStorage;

function apply(buttons: readonly HTMLButtonElement[], choice: ThemeChoice): void {
  const state = nextState(choice);
  const root = document.documentElement;
  if (state.dataTheme === null) {
    delete root.dataset["theme"];
  } else {
    root.dataset["theme"] = state.dataTheme;
  }
  for (const button of buttons) {
    const own = parseChoice(button.dataset["themeChoice"] ?? null);
    button.setAttribute("aria-pressed", String(state.pressed[own]));
  }
}

for (const container of document.querySelectorAll<HTMLElement>("[data-theme-switch]")) {
  const buttons = [...container.querySelectorAll<HTMLButtonElement>("button[data-theme-choice]")];
  apply(buttons, parseChoice(readStoredChoice(storage)));
  for (const button of buttons) {
    button.addEventListener("click", () => {
      const choice = parseChoice(button.dataset["themeChoice"] ?? null);
      // When storage is blocked, the choice lasts until the page is left.
      writeStoredChoice(storage, nextState(choice).stored);
      apply(buttons, choice);
    });
  }
  container.hidden = false;
}
