// Shared helpers: DOM, API, formatting, clipboard.

import { lang, locale, t } from "./i18n.js";

export const STATUS_ICONS = { pass: "✓", warn: "!", fail: "✕", info: "i", skip: "–", error: "?", accepted: "≈" };
export const statusLabel = (status) => t(`status.${status}`);
export const severityLabel = (severity) => t(`severity.${severity}`);
export const SCHEDULES = ["off", "6h", "daily", "weekly"];
export const scheduleLabel = (schedule) => t(`schedule.${schedule}`);

export const $ = (sel, root = document) => root.querySelector(sel);

/** Tiny DOM helper. Text is always set via textContent, never as HTML. */
export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value == null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat()) {
    if (child == null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

const SVG_NS = "http://www.w3.org/2000/svg";
export function svg(tag, attrs = {}, ...children) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "text") node.textContent = value;
    else if (value != null) node.setAttribute(key, value);
  }
  node.append(...children.flat().filter(Boolean));
  return node;
}

export function storage(key, value) {
  try {
    if (value === undefined) return localStorage.getItem(key);
    localStorage.setItem(key, value);
  } catch {
    return null;
  }
  return null;
}

export async function api(path, options = {}) {
  // The server answers (check texts, errors, labels) in the UI language.
  const headers = { "Accept-Language": lang(), ...(options.headers || {}) };
  const res = await fetch(path, { ...options, headers });
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") detail = body.detail;
      else if (Array.isArray(body.detail)) detail = body.detail.map((d) => d.msg).join(", ");
    } catch { /* not JSON */ }
    throw new Error(detail);
  }
  return res;
}

export async function apiJson(path, { method = "GET", body } = {}) {
  const res = await api(path, {
    method,
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return res.status === 204 ? null : res.json();
}

let catalogPromise = null;
const checkCache = new Map();

/** Apps and categories, loaded once. */
export function catalog() {
  catalogPromise ||= Promise.all([apiJson("api/apps"), apiJson("api/categories")]).then(([apps, categories]) => ({
    apps,
    categories,
  }));
  return catalogPromise;
}

export function checksFor(appId) {
  if (!checkCache.has(appId)) checkCache.set(appId, apiJson(`api/apps/${encodeURIComponent(appId)}/checks`));
  return checkCache.get(appId);
}

export function groupBy(items, key) {
  const out = {};
  for (const item of items) (out[key(item)] ||= []).push(item);
  return out;
}

export function formatDate(iso, withTime = true) {
  if (!iso) return "–";
  return new Date(iso).toLocaleString(locale(), withTime ? { dateStyle: "medium", timeStyle: "short" } : { dateStyle: "medium" });
}

export function relativeTime(iso) {
  if (!iso) return t("time.never");
  const minutes = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (minutes < 1) return t("time.justNow");
  if (minutes < 60) return t("time.minutes", { count: minutes });
  const hours = Math.round(minutes / 60);
  if (hours < 24) return t("time.hours", { count: hours });
  const days = Math.round(hours / 24);
  return days === 1 ? t("time.day") : t("time.days", { count: days });
}

export function gradeBadge(grade) {
  return el("span", { class: "grade-badge", "data-grade": grade || "", text: grade || "–" });
}

export async function copyText(text) {
  // The Clipboard API needs a secure context (https or localhost); fall back
  // for plain-HTTP access via LAN IP.
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const area = el("textarea", { readonly: true });
  area.value = text;
  area.style.setProperty("position", "fixed");
  area.style.setProperty("opacity", "0");
  document.body.append(area);
  area.select();
  const ok = document.execCommand("copy");
  area.remove();
  if (!ok) throw new Error(t("common.copyUnsupported"));
}

/** Temporarily replace a button label, e.g. "Copied ✓". */
export function flash(button, text, ok = true) {
  const label = button.dataset.label || button.textContent;
  button.dataset.label = label;
  button.textContent = text;
  button.classList.toggle("copied", ok);
  clearTimeout(button._flashTimer);
  button._flashTimer = setTimeout(() => {
    button.textContent = label;
    button.classList.remove("copied");
  }, 2000);
}

export function downloadJson(data, filename) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const link = el("a", { href: URL.createObjectURL(blob), download: filename });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}
