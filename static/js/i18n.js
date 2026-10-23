// Frontend translations. Texts live in static/locales/<lang>.json; keys must be
// identical in every file (tests/test_i18n.py checks that).
//
// Static HTML uses data attributes:
//   data-i18n="key"              -> textContent
//   data-i18n-placeholder="key"  -> placeholder
//   data-i18n-title="key"        -> title
//   data-i18n-content="key"      -> content (meta tags)

export const LANGUAGES = { en: "English", de: "Deutsch" };
const FALLBACK = "en";
const STORAGE_KEY = "seccheck.lang";

let current = FALLBACK;
let messages = {};

function readStored() {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

/** Language from the user's choice, else from the browser. */
export function preferredLanguage() {
  const stored = readStored();
  if (stored && LANGUAGES[stored]) return stored;
  for (const tag of navigator.languages || [navigator.language || FALLBACK]) {
    const code = String(tag).toLowerCase().split("-")[0];
    if (LANGUAGES[code]) return code;
  }
  return FALLBACK;
}

export async function loadLanguage(lang = preferredLanguage()) {
  const res = await fetch(`locales/${lang}.json`);
  messages = res.ok ? await res.json() : {};
  current = res.ok ? lang : FALLBACK;
  document.documentElement.lang = current;
  applyStatic();
}

export function lang() {
  return current;
}

/** Remember the choice and reload, so every view and cached API answer switches. */
export function switchLanguage(lang) {
  try {
    localStorage.setItem(STORAGE_KEY, lang);
  } catch { /* still switch for this page load */ }
  location.reload();
}

export function t(key, params = {}) {
  const text = messages[key] ?? key;
  return text.replace(/\{(\w+)\}/g, (match, name) => (name in params ? String(params[name]) : match));
}

export function applyStatic(root = document) {
  for (const node of root.querySelectorAll("[data-i18n]")) node.textContent = t(node.dataset.i18n);
  for (const node of root.querySelectorAll("[data-i18n-placeholder]")) node.placeholder = t(node.dataset.i18nPlaceholder);
  for (const node of root.querySelectorAll("[data-i18n-title]")) node.title = t(node.dataset.i18nTitle);
  for (const node of root.querySelectorAll("[data-i18n-content]")) node.setAttribute("content", t(node.dataset.i18nContent));
}

/** Locale for Intl/Date formatting. */
export function locale() {
  return current === "de" ? "de-DE" : "en-GB";
}
