import assert from "node:assert/strict";
import test from "node:test";
import { findFillTargets } from "../dist/forms.js";

// A narrow unit fixture for form ownership. Real browser DOM tests separately
// exercise layout, HTML ownership, events, and content-script filling.
class Input {
  constructor(type, autocomplete, form = null) {
    Object.assign(this, { type, autocomplete, form, disabled: false, readOnly: false,
      parentElement: null, name: "", id: "" });
  }
  matches() { return false; }
  getClientRects() { return [{}]; }
  getBoundingClientRect() { return { width: 100, height: 20, top: 0, left: 0, bottom: 20, right: 100 }; }
  hasAttribute() { return false; }
  getAttribute() { return null; }
}
function documentWith(inputs) {
  return { URL: "https://librarian.test/login", visibilityState: "visible",
    querySelectorAll: () => inputs,
    defaultView: { innerHeight: 800, innerWidth: 1200, HTMLInputElement: Input,
      HTMLButtonElement: class {},
      getComputedStyle: () => ({ display: "block", visibility: "visible", opacity: "1" }) } };
}

for (const autocomplete of ["email", "username"]) {
  test(`null form owners do not associate an unrelated ${autocomplete} field`, () => {
    const unrelated = new Input("email", autocomplete);
    const password = new Input("password", "current-password");
    const found = findFillTargets(documentWith([unrelated, password]));
    assert.equal(found?.password, password);
    assert.equal(found.username, null);
    assert.equal(found.form, null);
  });
}

test("a shared real form owner still associates username and password", () => {
  const form = { action: "https://librarian.test/session", elements: [] };
  const username = new Input("text", "username", form);
  const password = new Input("password", "current-password", form);
  form.elements.push(username, password);
  const found = findFillTargets(documentWith([new Input("email", "email"), username, password]));
  assert.equal(found?.username, username);
  assert.equal(found.password, password);
  assert.equal(found.form, form);
});

test("a form-less password without current-password semantics is not a login", () => {
  assert.equal(findFillTargets(documentWith([new Input("email", "username"), new Input("password", "")])), null);
});
