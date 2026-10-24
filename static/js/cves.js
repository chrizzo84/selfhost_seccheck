// Vulnerability feed (#/cves): monitored systems, watchlist and the CVE list.
//
//   #/cves?subject=target:3&product=nginx&severity=high&affected=1&kev=1&q=…

import { t } from "./i18n.js";
import { $, apiJson, el, formatDate, relativeTime, severityLabel } from "./util.js";

const PAGE = 50;
const SEVERITIES = ["critical", "high", "medium", "low"];
const POLL_MS = 3000;

let filters = {};
let overview = null;
let pollTimer = null;

export async function showCves(params) {
  filters = {
    subject: params.get("subject") || "",
    product: params.get("product") || "",
    severity: params.get("severity") || "",
    affected: params.get("affected") === "1",
    kev: params.get("kev") === "1",
    q: params.get("q") || "",
  };
  const root = $("#cves");
  root.classList.add("loading");
  try {
    overview = await apiJson("api/cve/overview");
  } catch (err) {
    root.replaceChildren(el("p", { class: "form-error", text: err.message }));
    return;
  } finally {
    root.classList.remove("loading");
  }
  root.replaceChildren(
    el("div", { class: "panel cve-status", id: "cve-status" }),
    el("section", { class: "panel", id: "cve-systems" }),
    el("section", { id: "cve-feed" }),
  );
  renderStatus();
  renderSystems();
  await renderFeed();
  if (overview.status.running) startPolling();
}

// --- status ------------------------------------------------------------------------

function renderStatus() {
  const { status } = overview;
  const box = $("#cve-status");
  const when = status.last_sync ? t("cve.updated", { when: relativeTime(status.last_sync) }) : t("cve.neverUpdated");
  const schedule = status.interval_hours > 0 ? t("cve.interval", { hours: status.interval_hours }) : t("cve.manualOnly");
  const button = el("button", {
    class: "btn",
    type: "button",
    disabled: status.running || !overview.subjects.length,
    text: t("cve.update"),
    onclick: startSync,
  });
  const line = status.running
    ? el("span", { class: "cve-running" }, el("span", { class: "spinner", "aria-hidden": "true" }), t("cve.updating", { current: status.current || "" }))
    : el("span", {}, el("strong", { text: when }), " · ", schedule);
  const children = [el("div", { class: "cve-status-main" }, el("div", {}, line, el("div", { class: "muted small", text: t("cve.sources") })), button)];
  if (status.running && !status.last_sync && !status.nvd_api_key) {
    children.push(el("p", { class: "muted small", text: t("cve.updatingFirst") }));
  }
  if (status.errors.length) {
    children.push(
      el(
        "details",
        { class: "cve-errors" },
        el("summary", { text: t("cve.errors", { count: status.errors.length }) }),
        el(
          "ul",
          { class: "list" },
          status.errors.map((e) => el("li", { text: `${productName(e.product) || e.source}: ${e.source} – ${e.error}` })),
        ),
      ),
    );
  }
  box.replaceChildren(...children);
}

async function startSync() {
  try {
    await apiJson("api/cve/sync", { method: "POST" });
  } catch (err) {
    $("#cve-status").append(el("p", { class: "form-error", text: err.message }));
    return;
  }
  overview.status.running = true;
  renderStatus();
  startPolling();
}

function startPolling() {
  clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    if (!location.hash.startsWith("#/cves")) {
      clearInterval(pollTimer);
      return;
    }
    try {
      overview = await apiJson("api/cve/overview");
    } catch {
      return;
    }
    renderStatus();
    if (!overview.status.running) {
      clearInterval(pollTimer);
      renderSystems();
      await renderFeed();
    }
  }, POLL_MS);
}

// --- systems & watchlist -------------------------------------------------------------

function productName(id) {
  return overview.products.find((p) => p.id === id)?.name;
}

function severityChips(counts) {
  return SEVERITIES.filter((s) => counts[s]).map((s) => el("span", { class: `badge sev-${s}`, text: `${counts[s]} ${severityLabel(s)}` }));
}

function systemRow(subject) {
  const version = subject.version
    ? el("span", { class: "cve-version", text: `${subject.product_name} ${subject.version}` })
    : el("span", { class: "muted", text: `${subject.product_name} · ${t("cve.versionUnknown")}` });
  let state;
  if (!subject.version) state = null;
  else if (!subject.affected) state = el("span", { class: "cve-ok", text: `✓ ${t("cve.noneKnown")}` });
  else {
    state = el(
      "span",
      { class: "cve-chips" },
      el("strong", { text: subject.affected === 1 ? t("cve.countOne") : t("cve.count", { count: subject.affected }) }),
      subject.possible ? el("span", { class: "muted small", text: `(${t("cve.possibly")})` }) : null,
      ...severityChips(subject.counts),
      subject.kev ? el("span", { class: "badge kev", text: t("cve.kevCount", { count: subject.kev }) }) : null,
    );
  }
  const name =
    subject.kind === "target"
      ? el("a", { class: "target-name", href: `#/target/${subject.id}`, text: subject.name })
      : el("span", { class: "target-name", text: subject.name });
  const actions = [];
  if (subject.affected) {
    actions.push(
      el("button", {
        type: "button",
        class: "btn small-btn",
        text: t("cve.show"),
        onclick: () => setFilters({ subject: subject.key, affected: false, product: "" }),
      }),
    );
  }
  if (subject.kind === "watch") {
    actions.push(
      el("button", {
        type: "button",
        class: "btn small-btn danger",
        text: t("cve.remove"),
        onclick: async () => {
          if (!confirm(t("cve.removeConfirm", { name: `${subject.product_name} ${subject.version}` }))) return;
          await apiJson(`api/cve/watch/${subject.id}`, { method: "DELETE" });
          await refreshOverview();
        },
      }),
    );
  }
  return el(
    "li",
    { class: "cve-system", "data-selected": filters.subject === subject.key ? "true" : null },
    el(
      "div",
      { class: "cve-system-main" },
      el("div", {}, name, " ", el("span", { class: "muted small", text: subject.kind === "target" ? t("cve.scanned") : t("cve.watchlist") })),
      el("div", { class: "cve-system-state" }, version, state),
    ),
    el("div", { class: "cve-system-actions" }, actions),
  );
}

function watchForm() {
  const product = el(
    "select",
    { required: true },
    overview.products.map((p) => el("option", { value: p.id, text: p.name })),
  );
  const version = el("input", { type: "text", placeholder: "1.26.2", required: true, spellcheck: "false", autocomplete: "off" });
  const label = el("input", { type: "text", placeholder: t("cve.labelPlaceholder"), autocomplete: "off" });
  const error = el("p", { class: "form-error", role: "alert", hidden: true });
  const form = el(
    "form",
    { class: "cve-watch-form", novalidate: true },
    el("label", { class: "field" }, el("span", { text: t("cve.product") }), product),
    el("label", { class: "field" }, el("span", { text: t("cve.version") }), version),
    el("label", { class: "field" }, el("span", { text: t("cve.label") }), label),
    el("button", { type: "submit", class: "btn", text: t("cve.add") }),
  );
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    error.hidden = true;
    if (!/^\s*v?\d[\w.+~-]*\s*$/.test(version.value)) {
      error.textContent = t("cve.versionInvalid");
      error.hidden = false;
      return;
    }
    try {
      await apiJson("api/cve/watch", { method: "POST", body: { product: product.value, version: version.value.trim(), label: label.value.trim() } });
    } catch (err) {
      error.textContent = err.message;
      error.hidden = false;
      return;
    }
    await refreshOverview();
    // The server syncs a new product within seconds; show the progress.
    setTimeout(async () => {
      overview = await apiJson("api/cve/overview");
      renderStatus();
      if (overview.status.running) startPolling();
      else {
        renderSystems();
        await renderFeed();
      }
    }, 1500);
  });
  return el(
    "details",
    { class: "cve-add", open: !overview.subjects.length },
    el("summary", { text: t("cve.addTitle") }),
    el("p", { class: "muted small", text: t("cve.addHint") }),
    form,
    error,
  );
}

function renderSystems() {
  const box = $("#cve-systems");
  const subjects = overview.subjects;
  const children = [
    el("h2", { text: t("cve.systems") }),
    subjects.length
      ? el("ul", { class: "cve-systems" }, subjects.map(systemRow))
      : el("p", { class: "muted", text: t("cve.noSystems") }),
    subjects.some((s) => s.possible && s.affected) ? el("p", { class: "muted small", text: t("cve.possibleHint") }) : null,
    watchForm(),
  ];
  box.replaceChildren(...children.filter(Boolean));
}

async function refreshOverview() {
  overview = await apiJson("api/cve/overview");
  renderStatus();
  renderSystems();
  await renderFeed();
}

// --- feed ----------------------------------------------------------------------------

function setFilters(changes) {
  filters = { ...filters, ...changes };
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (value === true) params.set(key, "1");
    else if (value) params.set(key, value);
  }
  const query = params.toString();
  // replaceState does not fire hashchange, so the page is not rebuilt.
  history.replaceState(null, "", `#/cves${query ? `?${query}` : ""}`);
  renderSystems();
  renderFeed();
}

function filterBar() {
  const monitored = overview.products.filter((p) => p.monitored);
  const product = el(
    "select",
    { "aria-label": t("cve.product"), onchange: (e) => setFilters({ product: e.target.value }) },
    el("option", { value: "", text: t("cve.allProducts") }),
    monitored.map((p) => el("option", { value: p.id, selected: p.id === filters.product, text: p.name })),
  );
  const severity = el(
    "select",
    { "aria-label": t("cve.severity"), onchange: (e) => setFilters({ severity: e.target.value }) },
    el("option", { value: "", text: t("cve.anySeverity") }),
    SEVERITIES.map((s) => el("option", { value: s, selected: s === filters.severity, text: t("cve.minSeverity", { severity: severityLabel(s) }) })),
  );
  const toggle = (key, label) =>
    el(
      "label",
      { class: "toggle" },
      el("input", { type: "checkbox", checked: filters[key], onchange: (e) => setFilters({ [key]: e.target.checked }) }),
      ` ${label}`,
    );
  const search = el("input", { type: "search", class: "cve-search", placeholder: t("cve.search"), "aria-label": t("cve.search") });
  search.value = filters.q;
  let timer;
  search.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(() => setFilters({ q: search.value.trim() }), 300);
  });
  const subject = overview.subjects.find((s) => s.key === filters.subject);
  return el(
    "div",
    { class: "cve-filters" },
    subject
      ? el(
          "span",
          { class: "filter-chip" },
          t("cve.systemFilter", { name: `${subject.name} (${subject.product_name} ${subject.version})` }),
          el("button", { type: "button", class: "btn link-btn", text: t("cve.clearFilter"), onclick: () => setFilters({ subject: "" }) }),
        )
      : [product, toggle("affected", t("cve.onlyAffected"))],
    severity,
    toggle("kev", t("cve.onlyKev")),
    search,
  );
}

async function renderFeed() {
  const box = $("#cve-feed");
  if (!box) return;
  if (!overview.subjects.length) {
    box.replaceChildren();
    return;
  }
  const list = el("div", { class: "checks cve-list" });
  const count = el("p", { class: "muted small cve-count", role: "status" });
  const more = el("button", { type: "button", class: "btn", hidden: true, text: t("cve.more") });
  box.replaceChildren(el("h2", { class: "cve-feed-title", text: t("cve.feed") }), filterBar(), count, list, el("div", { class: "cve-more" }, more));

  const load = async (offset) => {
    const params = new URLSearchParams({ offset, limit: PAGE });
    for (const key of ["subject", "product", "severity", "q"]) if (filters[key]) params.set(key, filters[key]);
    if (filters.affected) params.set("affected", "true");
    if (filters.kev) params.set("kev", "true");
    let page;
    try {
      page = await apiJson(`api/cve/feed?${params}`);
    } catch (err) {
      count.textContent = err.message;
      return;
    }
    count.textContent = page.total === 1 ? t("cve.countOne") : t("cve.count", { count: page.total });
    if (!page.total) {
      list.replaceChildren(el("p", { class: "cve-empty muted", text: filters.affected || filters.subject ? t("cve.emptyAffected") : t("cve.empty") }));
    } else {
      list.append(...page.items.map(vulnItem));
    }
    more.hidden = offset + page.items.length >= page.total;
    more.onclick = () => load(offset + PAGE);
  };
  await load(0);
}

function percent(value) {
  if (value >= 0.1) return `${Math.round(value * 100)} %`;
  if (value >= 0.001) return `${(value * 100).toFixed(1)} %`;
  return "< 0.1 %";
}

function vulnItem(vuln) {
  const severity = vuln.severity;
  const link = vuln.urls[0];
  const head = el(
    "div",
    { class: "cve-head" },
    el("span", { class: `badge sev-${severity === "unknown" ? "info" : severity}`, text: severityLabel(severity) }),
    link
      ? el("a", { class: "cve-id", href: link, target: "_blank", rel: "noopener noreferrer", text: vuln.id })
      : el("span", { class: "cve-id", text: vuln.id }),
    el("span", { class: "muted small", text: vuln.product_name }),
    el("span", { class: "muted small", text: t("cve.published", { date: formatDate(vuln.published || vuln.first_seen, false) }) }),
    el(
      "span",
      { class: "cve-scores" },
      vuln.cvss ? el("span", { class: "small", text: `CVSS ${vuln.cvss.toFixed(1)}` }) : null,
      vuln.epss
        ? el("span", {
            class: "small",
            title: t("cve.epssTitle", { percentile: percent(vuln.epss.percentile) }),
            text: t("cve.epss", { value: percent(vuln.epss.score) }),
          })
        : null,
      vuln.kev
        ? el("span", { class: "badge kev", title: t("cve.kevTitle", { date: formatDate(vuln.kev.date_added, false) }), text: t("cve.kev") })
        : null,
    ),
  );
  const affects = vuln.affects.length
    ? el(
        "div",
        { class: "cve-affects" },
        vuln.affects.map((a) =>
          el(
            "span",
            { class: `cve-affect ${a.possible ? "possible" : ""}` },
            el("span", { "aria-hidden": "true", text: a.possible ? "! " : "✕ " }),
            `${a.name} ${a.version}`,
            a.possible ? ` (${t("cve.possibly")})` : "",
            el("span", { class: "muted", text: ` · ${a.fixed ? t("cve.fixedIn", { version: a.fixed }) : t("cve.noFix")}` }),
          ),
        ),
      )
    : null;
  const details = [];
  if (vuln.description && vuln.description !== vuln.summary) details.push(el("p", { class: "desc", text: vuln.description }));
  if (vuln.kev) {
    details.push(
      el(
        "p",
        { class: "rec" },
        el("strong", { text: t("cve.kevTitle", { date: formatDate(vuln.kev.date_added, false) }) }),
        vuln.kev.ransomware ? ` · ${t("cve.ransomware")}` : "",
      ),
    );
  }
  if (vuln.aliases.length) details.push(el("p", { class: "small" }, el("span", { class: "muted", text: `${t("cve.aliases")}: ` }), vuln.aliases.join(", ")));
  if (vuln.urls.length) {
    details.push(
      el(
        "ul",
        { class: "refs" },
        vuln.urls.map((u) => el("li", {}, el("a", { href: u, target: "_blank", rel: "noopener noreferrer", text: u }))),
      ),
    );
  }
  details.push(el("p", { class: "meta", text: `${t("cve.sourcesUsed")}: ${vuln.sources.map((s) => t(`cve.source.${s}`)).join(", ")}` }));
  return el(
    "details",
    { class: "check cve-item", "data-affected": vuln.affects.length ? "true" : null },
    el("summary", {}, el("div", { class: "cve-body" }, head, el("div", { class: "check-title", text: vuln.summary || vuln.id }), affects)),
    el("div", { class: "check-body cve-details" }, details),
  );
}
