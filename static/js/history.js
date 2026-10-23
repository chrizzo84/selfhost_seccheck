// Target history (#/target/:id) and stored scan reports (#/scan/:id).

import { scoreChart } from "./charts.js";
import { scheduleSelect } from "./dashboard.js";
import { t } from "./i18n.js";
import { addResult, beginReport, finishReport } from "./report.js";
import { $, apiJson, catalog, checksFor, el, formatDate, gradeBadge } from "./util.js";


export async function showTarget(id) {
  const root = $("#target-view");
  let data;
  try {
    data = await apiJson(`api/targets/${id}/scans`);
  } catch (err) {
    root.replaceChildren(el("p", { class: "form-error", text: err.message }));
    return;
  }
  const { target, scans } = data;
  const { apps } = await catalog();
  const appName = apps.find((a) => a.id === target.app)?.name || target.app;
  const points = [...scans].reverse();

  const label = el("input", {
    type: "text",
    value: target.label,
    placeholder: t("history.namePlaceholder"),
    maxlength: "200",
    "aria-label": t("history.name"),
  });
  label.addEventListener("change", async () => {
    await apiJson(`api/targets/${id}`, { method: "PATCH", body: { label: label.value.trim() } });
  });
  const notifyBox = el("input", { type: "checkbox", checked: target.notify });
  notifyBox.addEventListener("change", () =>
    apiJson(`api/targets/${id}`, { method: "PATCH", body: { notify: notifyBox.checked } }),
  );
  const remove = el("button", {
    type: "button",
    class: "btn danger",
    text: t("history.delete"),
    onclick: async (e) => {
      const button = e.currentTarget;
      if (button.dataset.confirm !== "1") {
        button.dataset.confirm = "1";
        button.textContent = t("history.deleteConfirm");
        return;
      }
      await apiJson(`api/targets/${id}`, { method: "DELETE" });
      location.hash = "#/dashboard";
    },
  });

  const scanUrl = `#/scan?app=${encodeURIComponent(target.app)}&url=${encodeURIComponent(target.url)}&run=1`;
  root.replaceChildren(
    el("p", { class: "crumbs" }, el("a", { href: "#/dashboard", text: "Dashboard" }), " / ", target.label || target.url),
    el(
      "div",
      { class: "panel target-settings" },
      el("div", {}, el("div", { class: "muted small", text: appName }), el("div", { class: "target", text: target.url })),
      el("label", { class: "field" }, el("span", { text: t("history.name") }), label),
      el("label", { class: "field" }, el("span", { text: t("dashboard.schedule") }), scheduleSelect(target)),
      el("label", { class: "toggle" }, notifyBox, " " + t("history.notify")),
      el(
        "div",
        { class: "actions" },
        el("a", { class: "btn primary", href: scanUrl, text: t("dashboard.scanNow") }),
        remove,
      ),
      target.accepted.length
        ? el("p", { class: "muted small", text: t("history.accepted", { checks: target.accepted.join(", ") }) })
        : null,
    ),
    el(
      "div",
      { class: "panel" },
      el("h2", { text: t("history.chart") }),
      points.length
        ? scoreChart(points, { onSelect: (p) => (location.hash = `#/scan/${p.id}`) })
        : el("p", { class: "muted", text: t("history.noScans") }),
    ),
    el(
      "div",
      { class: "panel" },
      el("h2", { text: t("history.scans", { count: scans.length }) }),
      el(
        "table",
        { class: "scan-table" },
        el("thead", {}, el("tr", {}, ["colDate", "colGrade", "colScore", "colProblems", "colTrigger"].map((h) => el("th", { text: t(`history.${h}`) })))),
        el(
          "tbody",
          {},
          scans.map((s) =>
            el(
              "tr",
              {},
              el("td", {}, el("a", { href: `#/scan/${s.id}`, text: formatDate(s.finished_at) })),
              el("td", {}, gradeBadge(s.grade)),
              el("td", { text: String(s.score) }),
              el("td", { text: `${s.rating.counts.fail || 0} ✕ · ${s.rating.counts.warn || 0} !` }),
              el("td", { class: "muted", text: t(`trigger.${s.trigger}`) }),
            ),
          ),
        ),
      ),
    ),
  );
}

export async function showStoredScan(id) {
  const scan = await apiJson(`api/scans/${id}`);
  const { categories } = await catalog();
  const checks = scan.app ? await checksFor(scan.app.id) : [];
  const descriptions = Object.fromEntries(checks.map((c) => [c.id, c.description]));
  const latest = await apiJson(`api/targets/${scan.target_id}/scans`);
  const isLatest = latest.scans[0]?.id === scan.id;

  beginReport(
    {
      app: scan.app || { id: "generic", name: "?" },
      target: scan.target?.url || "",
      target_id: scan.target_id,
      scan_id: scan.id,
      started_at: scan.started_at,
      categories,
      checks: scan.results.map((r) => ({ id: r.id, title: r.title, category: r.category })),
    },
    // Accepting a risk re-rates the latest scan only, so older scans stay read-only.
    { source: "stored", canAccept: isLatest, descriptions },
  );
  for (const r of scan.results) addResult(r);
  finishReport({ rating: scan.rating, fixes: scan.fixes, diff: scan.diff, finished_at: scan.finished_at, scan_id: scan.id, target_id: scan.target_id });
}
