// Scan view: choose app (or detect it), enter URL, run a live scan.

import { t } from "./i18n.js";
import { addResult, beginReport, currentReport, finishReport, showReport } from "./report.js";
import { $, api, apiJson, catalog, checksFor, el, groupBy, storage } from "./util.js";

const state = { apps: [], categories: {}, app: null, checks: [], running: false };

export async function initScan() {
  const { apps, categories } = await catalog();
  state.apps = apps;
  state.categories = categories;
  renderApps();
  const initial = storage("seccheck.app") || "nextcloud";
  await selectApp(apps.some((a) => a.id === initial) ? initial : apps[0].id, { keepUrl: false });

  $("#scan-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const url = validatedUrl();
    if (url) startScan(state.app.id, url);
  });
  $("#detect").addEventListener("click", detect);
}

/** Route handler for #/ and #/scan?app=…&url=…&run=1 */
export async function showScanView(params) {
  if (params.get("app") && state.apps.some((a) => a.id === params.get("app"))) {
    await selectApp(params.get("app"));
  }
  if (params.get("url")) $("#url").value = params.get("url");
  showReport(currentReport().source === "live");
  if (params.get("run") === "1" && params.get("url") && !state.running) {
    // Re-scans from the dashboard: the target was scanned with consent before.
    $("#consent").checked = true;
    history.replaceState(null, "", "#/");
    startScan(state.app.id, params.get("url"));
  }
}

function renderApps() {
  $("#apps").replaceChildren(
    ...state.apps.map((app) => {
      const logo = el("span", { class: "app-logo", text: app.short });
      logo.style.setProperty("background", app.color);
      return el(
        "button",
        {
          type: "button",
          class: "app-card",
          role: "radio",
          "aria-checked": "false",
          "data-app": app.id,
          onclick: () => selectApp(app.id),
        },
        logo,
        el("div", {}, el("strong", { text: app.name }), el("span", { class: "app-desc", text: app.description })),
      );
    }),
  );
}

async function selectApp(id, { keepUrl = true } = {}) {
  state.app = state.apps.find((a) => a.id === id);
  storage("seccheck.app", id);
  for (const card of document.querySelectorAll(".app-card")) {
    card.setAttribute("aria-checked", String(card.dataset.app === id));
  }
  const input = $("#url");
  input.placeholder = state.app.url_hint;
  const remembered = storage("seccheck.url." + id);
  if (remembered && (!input.value || !keepUrl)) input.value = remembered;

  state.checks = await checksFor(id);
  renderCheckPreview();
}

function renderCheckPreview() {
  $("#check-count").textContent = `(${state.checks.length})`;
  const groups = groupBy(state.checks, (c) => c.category);
  $("#check-list").replaceChildren(
    ...Object.keys(state.categories)
      .filter((cat) => groups[cat])
      .flatMap((cat) => [
        el("h3", { text: state.categories[cat] }),
        el(
          "ul",
          {},
          groups[cat].map((c) =>
            el("li", {}, c.title, c.description ? el("span", { class: "muted", text: " – " + c.description }) : null),
          ),
        ),
      ]),
  );
}

function validatedUrl() {
  $("#form-error").hidden = true;
  const url = $("#url").value.trim();
  if (!url) return showFormError(t("scan.urlMissing"));
  if (!$("#consent").checked) return showFormError(t("scan.consentMissing"));
  return url;
}

function showFormError(message) {
  const error = $("#form-error");
  error.textContent = message;
  error.hidden = false;
  return null;
}

function note(message) {
  const box = $("#detect-note");
  box.textContent = message;
  box.hidden = !message;
}

async function detect() {
  const url = validatedUrl();
  if (!url) return;
  const button = $("#detect");
  button.disabled = true;
  note(t("scan.detecting"));
  try {
    const result = await apiJson("api/detect", { method: "POST", body: { url } });
    if (!result.apps.length) {
      await selectApp("generic");
      note(t("scan.detectNone"));
    } else {
      const [first, ...rest] = result.apps;
      await selectApp(first.id);
      const label = (a) => `${a.product}${a.version ? " " + a.version : ""}`;
      note(
        rest.length
          ? t("scan.detectedMore", { app: label(first), others: rest.map(label).join(", ") })
          : t("scan.detected", { app: label(first) }),
      );
    }
  } catch (err) {
    note("");
    showFormError(err.message);
  } finally {
    button.disabled = false;
  }
}

export async function startScan(appId, url) {
  if (state.running) return;
  if (state.app?.id !== appId) await selectApp(appId);
  storage("seccheck.url." + appId, url);
  state.running = true;
  $("#start").disabled = true;
  $("#form-error").hidden = true;

  let res;
  try {
    res = await api("api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ app: appId, url }),
    });
  } catch (err) {
    showFormError(err.message);
    state.running = false;
    $("#start").disabled = false;
    return;
  }

  let done = false;
  const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
  let buffer = "";
  try {
    for (;;) {
      const { value, done: finished } = await reader.read();
      if (finished) break;
      buffer += value;
      let nl;
      while ((nl = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, nl).trim();
        buffer = buffer.slice(nl + 1);
        if (!line) continue;
        const event = JSON.parse(line);
        if (event.type === "start") {
          const descriptions = Object.fromEntries((await checksFor(appId)).map((c) => [c.id, c.description]));
          beginReport(
            { ...event, target: event.target, target_id: event.target_id },
            { source: "live", canAccept: true, descriptions },
          );
          $("#report").scrollIntoView({ behavior: "smooth", block: "start" });
        } else if (event.type === "result") {
          addResult(event.result);
        } else if (event.type === "done") {
          finishReport(event);
          done = true;
        }
      }
    }
    if (!done) throw new Error(t("scan.disconnected"));
  } catch (err) {
    showFormError(err.message);
  } finally {
    state.running = false;
    $("#start").disabled = false;
  }
}
