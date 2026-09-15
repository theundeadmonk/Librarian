import { originFromBrowserUrl } from "./origin.js";

export interface FillTargets {
  readonly username: HTMLInputElement | null;
  readonly password: HTMLInputElement;
  readonly form: HTMLFormElement | null;
  readonly action: string;
}

/** Conservative sign-in recognition; page labels never confer origin authority. */
export function findFillTargets(document: Document): FillTargets | null {
  const view = document.defaultView;
  const origin = originFromBrowserUrl(document.URL);
  if (view === null || origin === null || document.visibilityState !== "visible") return null;
  const inputs = document.querySelectorAll("input");
  if (inputs.length > 128) return null;
  const visible = Array.from(inputs).filter((input) => writableVisible(input, view));
  const passwords = visible.filter((input) => input.type === "password");
  if (passwords.length !== 1) return null;
  const password = passwords[0]!;
  if (password.autocomplete.toLowerCase().split(/\s+/u).includes("new-password")) return null;
  const form = password.form;
  const group = visible.filter((input) => input.form === form);
  if (group.some((input) => input.autocomplete.toLowerCase().split(/\s+/u).includes("new-password"))) return null;
  const hasCurrentPassword = password.autocomplete.toLowerCase().split(/\s+/u).includes("current-password");
  if (!hasCurrentPassword) {
    // An unlabeled password box could be registration or password change.
    // Require a clear login submit control in its form instead of guessing.
    if (form === null) return null;
    const controls = Array.from(form.elements).filter((element) =>
      (element instanceof view.HTMLButtonElement && element.type === "submit") ||
      (element instanceof view.HTMLInputElement && element.type === "submit"));
    if (controls.length !== 1) return null;
    const control = controls[0]!;
    const label = (control instanceof view.HTMLInputElement ? control.value : control.textContent ?? "").trim();
    if (!/^(sign\s*in|log\s*in|login)$/iu.test(label)) return null;
  }
  const action = form?.action ?? document.URL;
  if (originFromBrowserUrl(action) !== origin) return null;
  if (form !== null) {
    for (const element of form.elements) {
      if ((element instanceof view.HTMLButtonElement || element instanceof view.HTMLInputElement)
        && element.hasAttribute("formaction") && originFromBrowserUrl(element.formAction) !== origin) return null;
    }
  }
  const usernames = group.filter((input) => {
    if (input.type !== "text" && input.type !== "email") return false;
    const autocomplete = input.autocomplete.toLowerCase().split(/\s+/u);
    return autocomplete.includes("username") || input.type === "email"
      || /^(user(name)?|email|login|identifier)$/iu.test(input.name || input.id);
  });
  if (usernames.length > 1) return null;
  // Password-only steps need an explicit current-password semantic.
  if (usernames.length === 0 && !hasCurrentPassword) return null;
  return { username: usernames[0] ?? null, password, form, action };
}

function writableVisible(input: HTMLInputElement, view: Window): boolean {
  if (input.disabled || input.readOnly || input.matches(":disabled") || input.type === "hidden"
    || input.getClientRects().length === 0) return false;
  const rect = input.getBoundingClientRect();
  if (rect.width <= 0 || rect.height <= 0 || rect.bottom <= 0 || rect.right <= 0
    || rect.top >= view.innerHeight || rect.left >= view.innerWidth) return false;
  let element: Element | null = input;
  for (let depth = 0; element !== null; depth += 1, element = element.parentElement) {
    if (depth >= 64 || element.hasAttribute("inert") || element.hasAttribute("hidden")
      || element.getAttribute("aria-hidden") === "true") return false;
    const style = view.getComputedStyle(element);
    if (style.display === "none" || style.visibility !== "visible" || Number(style.opacity) === 0) return false;
  }
  return true;
}
