// Tiny vanilla-JS controller for the detour web UI. The whole admin
// surface is the same JSON API the CLI uses; the page just renders
// `/rules` and `/hosts`, posts forms back, and polls.
//
// No frameworks on purpose: zero build step, zero supply-chain, and a
// 4-second polling refresh is plenty for an admin pane that mutates
// on operator action.

(function () {
  "use strict";

  const refreshMs = 4000;

  function $(sel) { return document.querySelector(sel); }

  function rowsHTML(table, items, render) {
    const tbody = table.querySelector("tbody");
    tbody.innerHTML = "";
    if (!items || items.length === 0) {
      const tr = document.createElement("tr");
      tr.className = "empty";
      const td = document.createElement("td");
      td.colSpan = table.querySelectorAll("thead th").length;
      td.textContent = "(no entries)";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    for (const it of items) tbody.appendChild(render(it));
  }

  function cell(text) {
    const td = document.createElement("td");
    td.textContent = text;
    return td;
  }

  function deleteButton(label, handler) {
    const td = document.createElement("td");
    const btn = document.createElement("button");
    btn.textContent = label;
    btn.className = "danger";
    btn.addEventListener("click", handler);
    td.appendChild(btn);
    return td;
  }

  async function api(method, path, body) {
    const opts = { method, headers: { "Accept": "application/json" } };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const resp = await fetch(path, opts);
    if (resp.status === 204) return null;
    const text = await resp.text();
    let parsed = null;
    if (text) {
      try { parsed = JSON.parse(text); } catch (_) { parsed = { error: text }; }
    }
    if (!resp.ok) {
      const msg = (parsed && parsed.error) || ("HTTP " + resp.status);
      throw new Error(msg);
    }
    return parsed;
  }

  async function refreshHealth() {
    const dot = $("#status-dot");
    const txt = $("#status-text");
    try {
      await api("GET", "/healthz");
      dot.className = "dot dot-ok";
      txt.textContent = "ok";
    } catch (e) {
      dot.className = "dot dot-down";
      txt.textContent = "unreachable";
    }
  }

  async function refreshRules() {
    try {
      const rules = await api("GET", "/rules");
      rowsHTML($("#rules-table"), rules, (r) => {
        const tr = document.createElement("tr");
        tr.appendChild(cell(r.id));
        tr.appendChild(cell(r.from));
        tr.appendChild(cell(r.to));
        tr.appendChild(cell(r.proto));
        tr.appendChild(deleteButton("Delete", async () => {
          if (!confirm("Delete rule " + r.id + "?")) return;
          try { await api("DELETE", "/rules/" + encodeURIComponent(r.id)); await refreshRules(); }
          catch (e) { $("#rule-error").textContent = e.message; }
        }));
        return tr;
      });
    } catch (e) {
      $("#rule-error").textContent = "load: " + e.message;
    }
  }

  async function refreshHosts() {
    try {
      const hosts = await api("GET", "/hosts");
      rowsHTML($("#hosts-table"), hosts, (h) => {
        const tr = document.createElement("tr");
        tr.appendChild(cell(h.id));
        tr.appendChild(cell(h.hostname));
        tr.appendChild(cell(h.ip));
        tr.appendChild(deleteButton("Delete", async () => {
          if (!confirm("Delete host " + h.hostname + "?")) return;
          try { await api("DELETE", "/hosts/" + encodeURIComponent(h.id)); await refreshHosts(); }
          catch (e) { $("#host-error").textContent = e.message; }
        }));
        return tr;
      });
    } catch (e) {
      // /hosts may legitimately 503 if the daemon was started with
      // --no-hosts. Surface it once but don't keep retrying loudly.
      $("#host-error").textContent = "load: " + e.message;
    }
  }

  function bindForm(formSel, errSel, mapFn, path, refreshFn) {
    $(formSel).addEventListener("submit", async (ev) => {
      ev.preventDefault();
      $(errSel).textContent = "";
      const fd = new FormData(ev.target);
      const body = mapFn(fd);
      try {
        await api("POST", path, body);
        ev.target.reset();
        await refreshFn();
      } catch (e) {
        $(errSel).textContent = e.message;
      }
    });
  }

  function init() {
    bindForm("#rule-form", "#rule-error", (fd) => ({
      from: fd.get("from"), to: fd.get("to"), proto: fd.get("proto"),
    }), "/rules", refreshRules);
    bindForm("#host-form", "#host-error", (fd) => ({
      hostname: fd.get("hostname"), ip: fd.get("ip"),
    }), "/hosts", refreshHosts);

    refreshHealth();
    refreshRules();
    refreshHosts();
    setInterval(() => {
      refreshHealth();
      refreshRules();
      refreshHosts();
    }, refreshMs);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
