// Score-over-time charts: a compact sparkline and the history line chart.
// Single series (score 0–100), so no legend; the title/heading names it.

import { t } from "./i18n.js";
import { $, el, formatDate, svg } from "./util.js";

/** Tiny trend line for dashboard rows. The current score is printed next to it. */
export function sparkline(history, { width = 96, height = 28 } = {}) {
  const pad = 3;
  const box = svg("svg", { class: "sparkline", viewBox: `0 0 ${width} ${height}`, width, height, role: "img" });
  const label = history.length
    ? t("chart.sparkline", { scores: history.map((h) => h.score).join(", ") })
    : t("chart.noHistory");
  box.append(svg("title", { text: label }));
  if (history.length < 2) return box;
  const x = (i) => pad + (i * (width - 2 * pad)) / (history.length - 1);
  const y = (score) => pad + ((100 - score) * (height - 2 * pad)) / 100;
  box.append(
    svg("polyline", { class: "spark-line", points: history.map((h, i) => `${x(i)},${y(h.score)}`).join(" ") }),
    svg("circle", { class: "spark-dot", cx: x(history.length - 1), cy: y(history.at(-1).score), r: 2.5 }),
  );
  return box;
}

/**
 * Line chart of scores over time with a snapping crosshair and tooltip.
 * ``points``: [{finished_at, score, grade}] oldest first.
 */
export function scoreChart(points, { onSelect } = {}) {
  const width = 720;
  const height = 220;
  const m = { top: 12, right: 16, bottom: 28, left: 36 };
  const innerW = width - m.left - m.right;
  const innerH = height - m.top - m.bottom;
  const x = (i) => m.left + (points.length === 1 ? innerW / 2 : (i * innerW) / (points.length - 1));
  const y = (score) => m.top + ((100 - score) * innerH) / 100;

  const root = svg("svg", {
    class: "score-chart",
    viewBox: `0 0 ${width} ${height}`,
    role: "img",
    "aria-label": t("chart.label", { count: points.length, score: points.at(-1)?.score ?? "–" }),
  });

  // Recessive grid at the grade-relevant levels.
  for (const level of [0, 50, 65, 80, 90, 100]) {
    root.append(
      svg("line", { class: "grid", x1: m.left, x2: width - m.right, y1: y(level), y2: y(level) }),
      svg("text", { class: "axis", x: m.left - 8, y: y(level) + 4, "text-anchor": "end", text: String(level) }),
    );
  }
  // First and last date only; the table below lists every scan.
  if (points.length) {
    root.append(
      svg("text", { class: "axis", x: x(0), y: height - 8, "text-anchor": points.length === 1 ? "middle" : "start", text: formatDate(points[0].finished_at, false) }),
    );
    if (points.length > 1) {
      root.append(svg("text", { class: "axis", x: x(points.length - 1), y: height - 8, "text-anchor": "end", text: formatDate(points.at(-1).finished_at, false) }));
    }
  }

  root.append(svg("polyline", { class: "line", points: points.map((p, i) => `${x(i)},${y(p.score)}`).join(" ") }));
  const dots = points.map((p, i) => svg("circle", { class: "dot", cx: x(i), cy: y(p.score), r: 4 }));
  root.append(...dots);

  const crosshair = svg("line", { class: "crosshair", y1: m.top, y2: m.top + innerH, visibility: "hidden" });
  const hit = svg("rect", { class: "hit", x: m.left - 8, y: 0, width: innerW + 16, height, tabindex: "0" });
  root.append(crosshair, hit);

  const tip = $("#chart-tip");
  let active = -1;
  const show = (i) => {
    if (i < 0 || i >= points.length) return;
    active = i;
    const p = points[i];
    crosshair.setAttribute("x1", x(i));
    crosshair.setAttribute("x2", x(i));
    crosshair.setAttribute("visibility", "visible");
    dots.forEach((d, j) => d.classList.toggle("active", j === i));
    tip.replaceChildren(
      el("strong", { text: t("chart.tooltip", { score: p.score, grade: p.grade }) }),
      el("span", { text: formatDate(p.finished_at) }),
    );
    tip.hidden = false;
    const rect = root.getBoundingClientRect();
    const px = rect.left + (x(i) / width) * rect.width;
    const py = rect.top + (y(p.score) / height) * rect.height;
    const left = Math.min(Math.max(8, px - tip.offsetWidth / 2), window.innerWidth - tip.offsetWidth - 8);
    tip.style.setProperty("left", `${left}px`);
    tip.style.setProperty("top", `${py - tip.offsetHeight - 12 + window.scrollY}px`);
  };
  const hide = () => {
    active = -1;
    crosshair.setAttribute("visibility", "hidden");
    dots.forEach((d) => d.classList.remove("active"));
    tip.hidden = true;
  };
  const nearest = (event) => {
    const rect = root.getBoundingClientRect();
    const sx = ((event.clientX - rect.left) / rect.width) * width;
    let best = 0;
    points.forEach((_, i) => {
      if (Math.abs(x(i) - sx) < Math.abs(x(best) - sx)) best = i;
    });
    return best;
  };
  hit.addEventListener("pointermove", (e) => show(nearest(e)));
  hit.addEventListener("pointerleave", hide);
  hit.addEventListener("blur", hide);
  hit.addEventListener("focus", () => show(points.length - 1));
  hit.addEventListener("keydown", (e) => {
    if (e.key === "ArrowLeft") show(Math.max(0, active - 1));
    else if (e.key === "ArrowRight") show(Math.min(points.length - 1, active + 1));
    else if (e.key === "Enter" && active >= 0) onSelect?.(points[active]);
    else return;
    e.preventDefault();
  });
  hit.addEventListener("click", (e) => onSelect?.(points[nearest(e)]));
  return root;
}
