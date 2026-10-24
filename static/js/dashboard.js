// Dashboard: all scanned targets with grade, trend and schedule.

import { sparkline } from "./charts.js";
import { t } from "./i18n.js";
import { $, SCHEDULES, STATUS_ICONS, apiJson, el, gradeBadge, relativeTime, scheduleLabel } from "./util.js";

export async function showDashboard() {
  const root = $("#dashboard");
  root.classList.add("loading");
  let targets;
  try {
    targets = await apiJson("api/targets");
  } catch (err) {
    root.replaceChildren(el("p", { class: "form-error", text: err.message }));
    return;
  } finally {
    root.classList.remove("loading");
  }

  if (!targets.length) {
    root.replaceChildren(
      el(
        "div",
        { class: "panel empty" },
        el("p", { text: t("dashboard.empty") }),
        el("a", { class: "btn primary", href: "#/", text: t("dashboard.firstScan") }),
      ),
    );
    return;
  }
  root.replaceChildren(el("div", { class: "target-list" }, targets.map(targetCard)));
}

export function scheduleSelect(target, onChange) {
  return el(
    "select",
    {
      "aria-label": t("dashboard.schedule"),
      onchange: async (e) => {
        const updated = await apiJson(`api/targets/${target.id}`, { method: "PATCH", body: { schedule: e.target.value } });
        onChange?.(updated);
      },
    },
    SCHEDULES.map((value) => el("option", { value, selected: value === target.schedule, text: scheduleLabel(value) })),
  );
}

function targetCard(target) {
  const last = target.last_scan;
  const scanUrl = `#/scan?app=${encodeURIComponent(target.app)}&url=${encodeURIComponent(target.url)}&run=1`;
  const counts = last
    ? ["fail", "warn"].filter((s) => last.counts[s]).map((s) =>
        el("span", { class: `count st-${s}`, text: `${STATUS_ICONS[s]} ${last.counts[s]}` }),
      )
    : [];
  return el(
    "article",
    { class: "panel target-card" },
    gradeBadge(last?.grade),
    el(
      "div",
      { class: "target-main" },
      el("a", { class: "target-name", href: `#/target/${target.id}`, text: target.label || target.url }),
      el("div", { class: "muted small" }, target.label ? `${target.url} · ` : "", target.app_name),
      el(
        "div",
        { class: "target-stats" },
        ...counts,
        target.cves?.total
          ? el("a", {
              class: `count cve-count-chip${target.cves.kev ? " kev" : ""}`,
              href: `#/cves?subject=target:${target.id}`,
              text: t(target.cves.kev ? "dashboard.cvesKev" : "dashboard.cves", { count: target.cves.total, kev: target.cves.kev }),
            })
          : null,
        el("span", { class: "muted small", text: t("dashboard.lastScan", { when: relativeTime(last?.finished_at) }) }),
      ),
    ),
    el(
      "div",
      { class: "target-trend" },
      sparkline(target.history),
      el("span", { class: "trend-score", text: last ? String(last.score) : "–" }),
    ),
    el(
      "div",
      { class: "target-actions" },
      el(
        "label",
        { class: "inline-field" },
        el("span", { class: "muted small", text: t("dashboard.schedule") }),
        scheduleSelect(target),
      ),
      el("a", { class: "btn", href: scanUrl, text: t("dashboard.scanNow") }),
    ),
  );
}
