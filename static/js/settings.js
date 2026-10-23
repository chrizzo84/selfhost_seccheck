// Notification settings (#/settings).

import { LANGUAGES, t } from "./i18n.js";
import { $, apiJson, el, flash } from "./util.js";

// Field: [name, type, placeholder, placeholderKey?]. Labels come from "<channel>.<name>".
const CHANNELS = {
  ntfy: [
    ["server", "url", "https://ntfy.sh"],
    ["topic", "text", "my-seccheck-topic"],
    ["token", "password", ""],
  ],
  gotify: [
    ["url", "url", "https://gotify.example.com"],
    ["token", "password", ""],
  ],
  pushover: [
    ["token", "password", ""],
    ["user", "password", ""],
    ["device", "text", "", "pushover.devicePlaceholder"],
  ],
  email: [
    ["host", "text", "smtp.example.com"],
    ["port", "number", "587"],
    ["security", "select", ""],
    ["username", "text", ""],
    ["password", "password", ""],
    ["sender", "email", "seccheck@example.com"],
    ["recipient", "email", "admin@example.com"],
  ],
};

export async function showSettings() {
  const form = $("#settings-form");
  const settings = await apiJson("api/settings/notifications");
  const inputs = {};

  const input = (channel, [name, type, placeholder, placeholderKey]) => {
    const value = settings[channel][name] ?? "";
    let node;
    if (type === "select") {
      node = el(
        "select",
        {},
        ["starttls", "ssl", "none"].map((v) => el("option", { value: v, selected: v === value, text: t(`email.${v}`) })),
      );
    } else {
      const hint = placeholderKey ? t(placeholderKey) : placeholder;
      node = el("input", { type, placeholder: hint, autocomplete: type === "password" ? "new-password" : "off" });
      node.value = value;
    }
    (inputs[channel] ||= {})[name] = node;
    return node;
  };

  const publicUrl = el("input", { type: "url", placeholder: "http://seccheck.lan:8001" });
  publicUrl.value = settings.public_url || "";
  const language = el(
    "select",
    {},
    Object.entries(LANGUAGES).map(([code, name]) => el("option", { value: code, selected: code === settings.language, text: name })),
  );
  const status = el("p", { class: "form-note", role: "status" });

  form.replaceChildren(
    el(
      "div",
      { class: "field-grid general" },
      el("label", { class: "field" }, el("span", { text: t("settings.publicUrl") }), publicUrl),
      el("label", { class: "field" }, el("span", { text: t("settings.language") }), language),
    ),
    ...Object.entries(CHANNELS).map(([channel, fields]) => {
      const enabled = el("input", { type: "checkbox", checked: settings[channel].enabled });
      (inputs[channel] ||= {}).enabled = enabled;
      return el(
        "fieldset",
        { class: "channel" },
        el("legend", {}, el("label", { class: "toggle" }, enabled, ` ${t(`${channel}.title`)}`)),
        el("p", { class: "muted small", text: t(`${channel}.hint`) }),
        el(
          "div",
          { class: "field-grid" },
          fields.map((f) => el("label", { class: "field" }, el("span", { text: t(`${channel}.${f[0]}`) }), input(channel, f))),
        ),
      );
    }),
    el(
      "div",
      { class: "actions" },
      el("button", { type: "submit", class: "btn primary", text: t("settings.save") }),
      el("button", { type: "button", class: "btn", id: "notify-test", text: t("settings.test") }),
    ),
    status,
    el("p", { class: "muted small", text: t("settings.secretsNote") }),
  );

  const collect = () => {
    const body = { public_url: publicUrl.value.trim(), language: language.value };
    for (const [channel, fields] of Object.entries(inputs)) {
      body[channel] = {};
      for (const [name, node] of Object.entries(fields)) {
        body[channel][name] = node.type === "checkbox" ? node.checked : node.type === "number" ? Number(node.value) : node.value.trim();
      }
    }
    return body;
  };

  form.onsubmit = async (event) => {
    event.preventDefault();
    const button = form.querySelector("button[type=submit]");
    try {
      await apiJson("api/settings/notifications", { method: "PUT", body: collect() });
      flash(button, t("settings.saved"));
    } catch (err) {
      status.textContent = err.message;
    }
  };
  $("#notify-test").onclick = async (event) => {
    const button = event.currentTarget;
    status.textContent = "";
    try {
      await apiJson("api/settings/notifications", { method: "PUT", body: collect() });
      const result = await apiJson("api/settings/notifications/test", { method: "POST" });
      const failed = Object.entries(result).filter(([, v]) => v !== "ok");
      status.textContent = Object.entries(result)
        .map(([channel, v]) => (v === "ok" ? t("settings.channelSent", { channel: t(`${channel}.title`) }) : `${t(`${channel}.title`)}: ${v}`))
        .join(" · ");
      flash(button, failed.length ? t("settings.partial") : t("settings.sent"), !failed.length);
    } catch (err) {
      status.textContent = err.message;
    }
  };
}
