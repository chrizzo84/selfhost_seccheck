// Entry point: hash router.
//
//   #/                     scan (setup + live report)
//   #/scan?app=&url=&run=1 scan, prefilled (and started)
//   #/scan/:id             stored scan report
//   #/dashboard            all targets
//   #/target/:id           history of one target
//   #/settings             notifications

import { showDashboard } from "./dashboard.js";
import { showStoredScan, showTarget } from "./history.js";
import { LANGUAGES, lang, loadLanguage, switchLanguage, t } from "./i18n.js";
import { initReport, showReport } from "./report.js";
import { initScan, showScanView } from "./scan.js";
import { showSettings } from "./settings.js";
import { $ } from "./util.js";

function setView(view, nav) {
  for (const section of document.querySelectorAll("[data-view]")) section.hidden = section.dataset.view !== view;
  for (const link of document.querySelectorAll("[data-nav]")) {
    if (link.dataset.nav === nav) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  $("#chart-tip").hidden = true;
}

async function route() {
  const hash = location.hash.replace(/^#/, "") || "/";
  const [path, query = ""] = hash.split("?");
  const params = new URLSearchParams(query);
  const parts = path.split("/").filter(Boolean);

  try {
    if (parts[0] === "dashboard") {
      setView("dashboard", "dashboard");
      showReport(false);
      await showDashboard();
    } else if (parts[0] === "target" && parts[1]) {
      setView("target", "dashboard");
      showReport(false);
      await showTarget(Number(parts[1]));
    } else if (parts[0] === "scan" && parts[1]) {
      setView("report-only", "dashboard");
      await showStoredScan(Number(parts[1]));
    } else if (parts[0] === "settings") {
      setView("settings", "settings");
      showReport(false);
      await showSettings();
    } else {
      setView("scan", "scan");
      await showScanView(params);
    }
  } catch (err) {
    console.error(err);
  }
  window.scrollTo({ top: 0 });
}

function initLanguageSwitch() {
  const select = $("#lang-switch");
  for (const [code, name] of Object.entries(LANGUAGES)) {
    const option = document.createElement("option");
    option.value = code;
    option.textContent = name;
    option.selected = code === lang();
    select.append(option);
  }
  select.addEventListener("change", () => switchLanguage(select.value));
}

async function main() {
  await loadLanguage();
  initLanguageSwitch();
  initReport({ onRescan: (app, url) => (location.hash = `#/scan?app=${encodeURIComponent(app)}&url=${encodeURIComponent(url)}&run=1`) });
  await initScan();
  // Old links: ?app=…&url=…
  const legacy = new URLSearchParams(location.search);
  if (legacy.get("app") || legacy.get("url")) {
    history.replaceState(null, "", location.pathname + "#/scan?" + legacy.toString());
  }
  window.addEventListener("hashchange", route);
  await route();
}

main().catch((err) => {
  const box = $("#form-error");
  box.textContent = t("init.failed", { error: err.message });
  box.hidden = false;
});
