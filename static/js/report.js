// Renders one scan report (live or stored) into #report.

import { t } from "./i18n.js";
import {
  $,
  STATUS_ICONS,
  apiJson,
  copyText,
  downloadJson,
  el,
  flash,
  formatDate,
  groupBy,
  severityLabel,
  statusLabel,
  storage,
} from "./util.js";

const RING_LENGTH = 2 * Math.PI * 52;
const SERVER_LABELS = { nginx: "nginx", apache: "Apache", caddy: "Caddy", traefik: "Traefik" };
const PROBLEMS = new Set(["fail", "warn", "error"]);

const report = {
  source: null, // "live" | "stored"
  meta: null, // app, target, target_id, scan_id, started_at, finished_at, duration_ms, categories, checks
  descriptions: {},
  results: new Map(),
  rating: null,
  fixes: {},
  diff: null,
  canAccept: false,
  fixServer: storage("seccheck.fixServer") || "nginx",
  onRescan: null,
};

export const currentReport = () => report;

export function initReport({ onRescan }) {
  report.onRescan = onRescan;
  $("#only-issues").addEventListener("change", (e) => {
    $("#categories").classList.toggle("only-issues", e.target.checked);
    storage("seccheck.onlyIssues", e.target.checked ? "1" : "0");
  });
  if (storage("seccheck.onlyIssues") === "1") {
    $("#only-issues").checked = true;
    $("#categories").classList.add("only-issues");
  }
  $("#export").addEventListener("click", exportJson);
  $("#copy-md").addEventListener("click", async (e) => {
    try {
      await copyText(buildMarkdown());
      flash(e.currentTarget, t("common.copied"));
    } catch (err) {
      console.error(err);
      flash(e.currentTarget, t("common.copyFailed"), false);
    }
  });
  $("#rescan").addEventListener("click", () => report.meta && report.onRescan?.(report.meta.app.id, report.meta.target));
  $("#fix-copy").addEventListener("click", async (e) => {
    try {
      await copyText(report.fixes[report.fixServer] || "");
      flash(e.currentTarget, t("common.copied"));
    } catch {
      flash(e.currentTarget, t("common.failed"), false);
    }
  });
}

export function showReport(visible) {
  $("#report").hidden = !visible;
}

// --- lifecycle ----------------------------------------------------------------

/** Start a new report. ``meta.checks`` defines rows and order. */
export function beginReport(meta, { source, canAccept, descriptions }) {
  Object.assign(report, {
    source,
    meta,
    descriptions: descriptions || {},
    results: new Map(),
    rating: null,
    fixes: {},
    diff: null,
    canAccept,
  });
  showReport(true);
  for (const id of ["#export", "#copy-md", "#rescan"]) $(id).disabled = true;
  $("#sum-app").textContent = meta.app.name;
  $("#sum-target").textContent = meta.target;
  $("#sum-when").textContent = meta.started_at ? t("report.started", { date: formatDate(meta.started_at) }) : "";
  $("#counts").replaceChildren();
  $("#caps").replaceChildren();
  $("#cat-scores").replaceChildren();
  $("#diff").hidden = true;
  $("#fixes").hidden = true;
  $(".progress").classList.remove("done");
  $("#progress-bar").style.setProperty("width", "0%");

  const ring = $("#grade-ring");
  ring.dataset.grade = "";
  ring.classList.add("running");
  $("#grade").textContent = t("report.scanning");
  $("#score").textContent = `0 / ${meta.checks.length}`;
  $("#grade-bar").style.setProperty("stroke-dashoffset", RING_LENGTH);

  const groups = groupBy(meta.checks, (c) => c.category);
  $("#categories").replaceChildren(
    ...Object.keys(meta.categories)
      .filter((cat) => groups[cat])
      .map((cat) =>
        el(
          "section",
          { class: "category", "data-category": cat },
          el("h3", {}, meta.categories[cat], el("span", { class: "muted cat-count" })),
          el("div", { class: "checks" }, groups[cat].map(pendingRow)),
        ),
      ),
  );
}

export function addResult(result) {
  report.results.set(result.id, result);
  renderResult(result);
  const total = report.meta.checks.length;
  const done = report.results.size;
  $("#progress-bar").style.setProperty("width", `${(done / total) * 100}%`);
  if (!report.rating) $("#score").textContent = `${done} / ${total}`;
}

export function finishReport({ rating, fixes, diff, finished_at, duration_ms, scan_id, target_id }) {
  Object.assign(report.meta, {
    finished_at,
    duration_ms,
    scan_id: scan_id ?? report.meta.scan_id,
    target_id: target_id ?? report.meta.target_id,
  });
  report.fixes = fixes || {};
  report.diff = diff || null;
  if (finished_at) $("#sum-when").textContent = t("report.scanned", { date: formatDate(finished_at) });
  renderRating(rating);
  renderFixes();
  renderDiff();
  // Accept buttons need the target id that only arrives with "done".
  if (report.canAccept) for (const r of report.results.values()) renderResult(r);
  for (const id of ["#export", "#copy-md", "#rescan"]) $(id).disabled = false;
}

// --- rows -------------------------------------------------------------------------

function pendingRow(check) {
  return el(
    "details",
    { class: "check", id: "check-" + check.id, "data-status": "pending" },
    el(
      "summary",
      {},
      el("span", { class: "icon st-pending", "aria-label": t("status.pending") }),
      el("div", {}, el("div", { class: "check-title", text: check.title }), el("div", { class: "check-summary", text: t("report.checking") })),
    ),
  );
}

function renderResult(r) {
  const row = document.getElementById("check-" + r.id);
  if (!row) return;
  const wasOpen = row.open;
  const isProblem = r.status === "fail" || r.status === "warn";
  const status = r.accepted ? "accepted" : r.status;
  const description = report.descriptions[r.id];

  row.dataset.status = r.status;
  row.classList.toggle("accepted", Boolean(r.accepted));
  row.replaceChildren(
    el(
      "summary",
      {},
      el("span", { class: `icon st-${status}`, title: statusLabel(status), text: STATUS_ICONS[status] }),
      el("div", {}, el("div", { class: "check-title", text: r.title }), el("div", { class: "check-summary", text: r.summary })),
      r.accepted
        ? el("span", { class: "badge sev-accepted", text: statusLabel("accepted") })
        : isProblem
          ? el("span", { class: `badge sev-${r.severity}`, text: severityLabel(r.severity) })
          : null,
    ),
    el(
      "div",
      { class: "check-body" },
      description ? el("p", { class: "desc", text: description }) : null,
      r.recommendation ? el("p", { class: "rec" }, el("strong", { text: t("report.recommendation") }), r.recommendation) : null,
      renderDetails(r.details),
      r.references?.length
        ? el("div", { class: "refs" }, t("report.moreInfo"), r.references.map((href, i) => [i ? ", " : "", safeLink(href)]))
        : null,
      el(
        "div",
        { class: "meta" },
        el("span", { text: `${r.id} · ${r.duration_ms} ms` }),
        isProblem && report.canAccept && report.meta.target_id ? acceptButton(r) : null,
      ),
    ),
  );
  row.open = wasOpen;
  updateCategory(row.closest(".category"));
}

function acceptButton(r) {
  return el("button", {
    type: "button",
    class: "btn link-btn",
    text: r.accepted ? t("report.unaccept") : t("report.acceptRisk"),
    title: r.accepted ? t("report.unacceptHint") : t("report.acceptHint"),
    onclick: (e) => toggleAccepted(r, e.currentTarget),
  });
}

async function toggleAccepted(r, button) {
  button.disabled = true;
  try {
    const updated = await apiJson(`api/targets/${report.meta.target_id}/accepted/${encodeURIComponent(r.id)}`, {
      method: r.accepted ? "DELETE" : "PUT",
    });
    if (updated?.results) {
      for (const result of updated.results) report.results.set(result.id, result);
      for (const result of updated.results) renderResult(result);
      report.fixes = updated.fixes || {};
      renderRating(updated.rating);
      renderFixes();
    }
  } catch (err) {
    button.disabled = false;
    button.textContent = err.message;
  }
}

function safeLink(href) {
  return /^https:\/\//.test(href)
    ? el("a", { href, target: "_blank", rel: "noopener noreferrer", text: href })
    : el("span", { text: href });
}

function renderDetails(details) {
  if (details == null || details === "") return null;
  if (Array.isArray(details)) {
    return details.length ? el("ul", { class: "list" }, details.map((d) => el("li", { text: String(d) }))) : null;
  }
  if (typeof details === "object") {
    return el(
      "table",
      { class: "kv" },
      el(
        "tbody",
        {},
        Object.entries(details).map(([k, v]) =>
          el("tr", {}, el("th", { text: k }), el("td", { text: Array.isArray(v) ? v.join(", ") : String(v) })),
        ),
      ),
    );
  }
  return el("p", { text: String(details) });
}

function updateCategory(section) {
  if (!section) return;
  const rows = [...section.querySelectorAll(".check")];
  const issues = rows.filter((r) => PROBLEMS.has(r.dataset.status) && !r.classList.contains("accepted")).length;
  const pending = rows.filter((r) => r.dataset.status === "pending").length;
  section.classList.toggle("no-issues", pending === 0 && issues === 0);
  section.querySelector(".cat-count").textContent = pending
    ? `${rows.length - pending}/${rows.length}`
    : issues
      ? issues === 1
        ? t("report.problemOne")
        : t("report.problemMany", { count: issues })
      : t("report.allOk");
}

// --- summary, diff, fixes ---------------------------------------------------------

function renderRating(rating) {
  report.rating = rating;
  const ring = $("#grade-ring");
  ring.classList.remove("running");
  ring.dataset.grade = rating.grade;
  $("#grade").textContent = rating.grade;
  $("#score").textContent = `${rating.score} / 100`;
  $("#grade-bar").style.setProperty("stroke-dashoffset", RING_LENGTH * (1 - rating.score / 100));
  $(".progress").classList.add("done");

  $("#counts").replaceChildren(
    ...["fail", "warn", "pass", "info", "skip", "error", "accepted"]
      .filter((s) => rating.counts[s])
      .map((s) => el("span", { class: `count st-${s}` }, `${STATUS_ICONS[s]} ${rating.counts[s]} ${statusLabel(s)}`)),
  );
  $("#caps").replaceChildren(...rating.caps.map((c) => el("li", { text: c })));
  $("#cat-scores").replaceChildren(
    ...Object.values(rating.categories).map((cat) => {
      const bar = el("div");
      bar.style.setProperty("width", `${cat.score}%`);
      bar.style.setProperty("background", cat.score >= 90 ? "var(--pass)" : cat.score >= 65 ? "var(--warn)" : "var(--fail)");
      return el(
        "div",
        { class: "cat-score" },
        el("div", { class: "label" }, el("span", { text: cat.label }), el("span", { text: String(cat.score) })),
        el("div", { class: "meter" }, bar),
      );
    }),
  );
}

function renderDiff() {
  const box = $("#diff");
  const diff = report.diff;
  if (!diff) {
    box.hidden = true;
    return;
  }
  box.hidden = false;
  const historyLink = report.meta.target_id
    ? el("a", { href: `#/target/${report.meta.target_id}`, text: t("diff.history") })
    : null;
  if (diff.first_scan) {
    box.replaceChildren(
      el("p", {}, el("strong", { text: t("diff.first") }), t("diff.firstHint"), historyLink),
    );
    return;
  }
  const grade =
    diff.grade_before === diff.grade_after
      ? t("diff.gradeSame", { grade: diff.grade_after })
      : t("diff.gradeChange", { before: diff.grade_before, after: diff.grade_after });
  const list = (items, cls) =>
    items.length
      ? el("ul", { class: `diff-list ${cls}` }, items.map((i) => el("li", {}, el("span", { class: "check-title", text: i.title }), " – ", i.summary)))
      : null;
  box.replaceChildren(
    el(
      "p",
      { class: "diff-head" },
      el("strong", { text: t("diff.since") }),
      `${grade} (${diff.score_before} → ${diff.score_after}) · `,
      el("span", { class: diff.new.length ? "neg" : "", text: t("diff.new", { count: diff.new.length }) }),
      " · ",
      el("span", { class: diff.resolved.length ? "pos" : "", text: t("diff.resolved", { count: diff.resolved.length }) }),
      " · ",
      historyLink,
    ),
    // replaceChildren() would print null as text; el() skips it.
    ...[list(diff.new, "new"), list(diff.resolved, "resolved")].filter(Boolean),
  );
}

function renderFixes() {
  const servers = Object.keys(report.fixes || {});
  $("#fixes").hidden = servers.length === 0;
  if (!servers.length) return;
  if (!servers.includes(report.fixServer)) report.fixServer = servers[0];
  $("#fix-tabs").replaceChildren(
    ...servers.map((s) =>
      el("button", {
        type: "button",
        role: "tab",
        class: "tab",
        "aria-selected": String(s === report.fixServer),
        text: SERVER_LABELS[s] || s,
        onclick: () => {
          report.fixServer = s;
          storage("seccheck.fixServer", s);
          renderFixes();
        },
      }),
    ),
  );
  $("#fix-code").textContent = report.fixes[report.fixServer];
}

// --- export ---------------------------------------------------------------------

function orderedResults() {
  return report.meta.checks.map((c) => report.results.get(c.id)).filter(Boolean);
}

function exportJson() {
  const { meta } = report;
  downloadJson(
    {
      app: meta.app,
      target: meta.target,
      started_at: meta.started_at,
      finished_at: meta.finished_at,
      rating: report.rating,
      diff: report.diff,
      fixes: report.fixes,
      results: orderedResults(),
    },
    `seccheck-${meta.app.id}-${new URL(meta.target).hostname}.json`,
  );
}

const MD_STATUS = { pass: "✅", warn: "⚠️", fail: "❌", info: "ℹ️", skip: "⏭️", error: "❓", accepted: "☑️" };
const SEVERITY_RANK = ["critical", "high", "medium", "low", "info"];
const mdCell = (text) => String(text ?? "").replace(/\|/g, "\\|").replace(/\s*\n\s*/g, " ");

function mdDetails(details) {
  if (details == null || details === "") return [];
  if (Array.isArray(details)) return details.map((d) => `- ${mdCell(d)}`);
  if (typeof details === "object") {
    return Object.entries(details).map(([k, v]) => `- **${k}:** ${mdCell(Array.isArray(v) ? v.join(", ") : v)}`);
  }
  return [String(details)];
}

export function buildMarkdown() {
  const { meta, rating, diff } = report;
  const results = orderedResults();
  const lines = [];

  lines.push(`# ${t("md.title", { target: meta.target })}`, "");
  lines.push(`- **${t("md.app")}:** ${meta.app.name}`);
  lines.push(`- **${t("md.target")}:** ${meta.target}`);
  const duration = meta.duration_ms ? ` (${(meta.duration_ms / 1000).toFixed(1)} s)` : "";
  lines.push(`- **${t("md.scan")}:** ${formatDate(meta.finished_at || meta.started_at)}${duration}`);
  lines.push(`- **${t("md.grade")}:** **${rating.grade}** (${rating.score}/100)`);
  const counts = ["fail", "warn", "pass", "info", "skip", "error", "accepted"]
    .filter((s) => rating.counts[s])
    .map((s) => `${MD_STATUS[s]} ${rating.counts[s]} ${statusLabel(s)}`);
  lines.push(`- **${t("md.results")}:** ${counts.join(" · ")}`);
  if (diff && !diff.first_scan) {
    const since = t("md.sinceLastValue", {
      before: diff.grade_before,
      after: diff.grade_after,
      new: diff.new.length,
      resolved: diff.resolved.length,
    });
    lines.push(`- **${t("md.sinceLast")}:** ${since}`);
  }
  lines.push("");

  if (rating.caps.length) {
    lines.push(`> **${t("md.caps")}**`, ...rating.caps.map((c) => `> - ${c}`), "");
  }

  lines.push(`## ${t("md.categories")}`, "", `| ${t("md.category")} | ${t("md.points")} |`, "|---|---:|");
  for (const cat of Object.values(rating.categories)) lines.push(`| ${cat.label} | ${cat.score} |`);
  lines.push("");

  const issues = results
    .filter((r) => (r.status === "fail" || r.status === "warn") && !r.accepted)
    .sort(
      (a, b) =>
        SEVERITY_RANK.indexOf(a.severity) - SEVERITY_RANK.indexOf(b.severity) ||
        (a.status === "fail" ? 0 : 1) - (b.status === "fail" ? 0 : 1),
    );
  lines.push(`## ${t("md.problems", { count: issues.length })}`, "");
  if (!issues.length) lines.push(t("md.noProblems"), "");
  for (const r of issues) {
    lines.push(`### ${MD_STATUS[r.status]} ${r.title} – ${severityLabel(r.severity)}`, "", r.summary, "");
    if (r.recommendation) lines.push(`**${t("md.recommendation")}:** ${r.recommendation}`, "");
    const details = mdDetails(r.details);
    if (details.length) lines.push(...details, "");
    if (r.references?.length) lines.push(t("md.more", { links: r.references.join(", ") }), "");
  }

  const accepted = results.filter((r) => r.accepted);
  if (accepted.length) {
    lines.push(`## ${t("md.accepted", { count: accepted.length })}`, "");
    for (const r of accepted) lines.push(`- ${r.title} – ${r.summary}`);
    lines.push("");
  }

  const servers = Object.keys(report.fixes || {});
  if (servers.length) {
    lines.push(`## ${t("md.snippets")}`, "");
    for (const s of servers) {
      lines.push(`### ${SERVER_LABELS[s] || s}`, "", "```" + (s === "traefik" ? "yaml" : ""), report.fixes[s].trimEnd(), "```", "");
    }
  }

  lines.push(`## ${t("md.allChecks")}`, "");
  const byCategory = groupBy(results, (r) => r.category);
  for (const [cat, label] of Object.entries(meta.categories)) {
    if (!byCategory[cat]) continue;
    lines.push(`### ${label}`, "", `| | ${t("md.check")} | ${t("md.result")} |`, "|---|---|---|");
    for (const r of byCategory[cat]) {
      lines.push(`| ${MD_STATUS[r.accepted ? "accepted" : r.status]} | ${mdCell(r.title)} | ${mdCell(r.summary)} |`);
    }
    lines.push("");
  }

  lines.push("---", `_${t("md.footer")}_`);
  return lines.join("\n");
}
