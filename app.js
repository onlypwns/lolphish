/* LOLPHISH — renderer: filterable accordion table + sticky detail panel */

(function () {
  const catColor = {
    "Identity Flow Abuse": "var(--c-identity)",
    "User-Assisted Execution": "var(--c-execution)",
    "Trusted Delivery": "var(--c-delivery)",
    "Reputation Laundering": "var(--c-reputation)"
  };

  const $ = (sel) => document.querySelector(sel);
  const tableEl = $("#table");
  const detailEl = $("#detail-inner");
  const searchEl = $("#search");
  const catEl = $("#f-category");
  const venEl = $("#f-vendor");
  const countEl = $("#count");

  let activeId = null;
  let state = { q: "", category: "", vendor: "" };

  /* ---- populate filter options ---- */
  STATS.categories.forEach(c => {
    const o = document.createElement("option");
    o.value = c; o.textContent = c;
    catEl.appendChild(o);
  });
  const vendors = [...new Set(ENTRIES.flatMap(e => e.vendors))].sort();
  vendors.forEach(v => {
    const o = document.createElement("option");
    o.value = v; o.textContent = v;
    venEl.appendChild(o);
  });

  /* ---- header stats ---- */
  $("#stat-entries").textContent = STATS.entries;
  $("#stat-variants").textContent = STATS.variants;
  $("#stat-kits").textContent = STATS.kits;

  /* ---- filtering ---- */
  function matches(e) {
    if (state.category && e.category !== state.category) return false;
    if (state.vendor && !e.vendors.includes(state.vendor)) return false;
    if (state.q) {
      const codeHay = (e.detection_code || []).map(c => [c.lang, c.query, c.description].join(" ")).join(" ");
      const hay = [
        e.name, e.category, e.vendors.join(" "), e.summary, e.abuse,
        e.variants.join(" "), e.kits.join(" "), e.surfaces.join(" "),
        e.attack.join(" "), e.detections.join(" "), e.mitigations.join(" "), codeHay
      ].join(" ").toLowerCase();
      if (!hay.includes(state.q)) return false;
    }
    return true;
  }

  /* ---- detail panel ---- */
  function renderDetail(e) {
    if (!e) {
      detailEl.innerHTML =
        '<div class="d-empty">SELECT AN ENTRY<span class="blink">_</span><br><br>' +
        "Click any row to pin it here and expand its full record inline.</div>";
      return;
    }
    detailEl.innerHTML = `
      <div class="d-kicker">${esc(e.category)}</div>
      <div class="d-name">${esc(e.name)}</div>
      <div class="d-meta">
        <span class="cat-pill" style="color:${catColor[e.category]}">${esc(e.category)}</span>
      </div>
      <div class="d-summary">${esc(e.summary)}</div>
      <div class="d-abuse">${esc(e.abuse.slice(0, 220))}${e.abuse.length > 220 ? "…" : ""}</div>
      <div class="d-counts">
        <span><b>${e.variants.length}</b>Variants</span>
        <span><b>${e.kits.length}</b>Kits/Actors</span>
        <span><b>${e.detections.length}</b>Detections</span>
      </div>`;
  }

  /* ---- expandable body ---- */
  function bodyHTML(e) {
    const sect = (title, inner, wide) =>
      `<div class="sect${wide ? " wide" : ""}"><h4><span class="tick">#</span>${title}</h4>${inner}</div>`;
    const list = (arr) => `<ul class="ticklist">${arr.map(x => `<li>${esc(x)}</li>`).join("")}</ul>`;
    const tags = (arr, cls) => `<div class="tagrow">${arr.map(x => `<span class="tag ${cls}">${esc(x)}</span>`).join("")}</div>`;
    const codeBlock = (snip) => {
      const meta = [snip.lang.toUpperCase(), snip.source].filter(Boolean).join(" · ");
      return `<div class="code-wrap">
        <div class="code-meta">${esc(meta)}</div>
        ${snip.description ? `<p class="code-desc">${esc(snip.description)}</p>` : ""}
        <pre><code>${esc(snip.query)}</code></pre>
      </div>`;
    };

    return `
      <div class="body-inner">
        ${sect("Legitimate purpose", `<p>${esc(e.summary)}</p>`, true)}
        ${sect("Abuse primitive", `<p>${esc(e.abuse)}</p>`, true)}
        ${sect(`Variants (${e.variants.length})`, list(e.variants))}
        ${sect("Kits / Actors / Tooling", tags(e.kits, "kit"))}
        ${sect("Detection & hunting", list(e.detections))}
        ${e.detection_code && e.detection_code.length ? sect(`Detection code (${e.detection_code.length})`, e.detection_code.map(codeBlock).join(""), true) : ""}
        ${sect("Structural mitigations", list(e.mitigations))}
        ${sect("Trust surfaces", tags(e.surfaces, "surface"))}
        ${sect("ATT&CK", list(e.attack))}
        ${sect("References", `<ul class="reflist">${e.refs.map(r =>
          `<li><a href="${r.url}" target="_blank" rel="noopener">${esc(r.title)}</a></li>`).join("")}</ul>
          <div class="since">First documented: <b>${esc(e.since)}</b></div>`, true)}
      </div>`;
  }

  /* ---- rows ---- */
  function render() {
    const visible = ENTRIES.filter(matches);
    countEl.innerHTML = `<b>${visible.length}</b> / ${ENTRIES.length} entries`;

    tableEl.innerHTML = "";
    visible.forEach(e => {
      const wrap = document.createElement("div");
      wrap.className = "entry" + (e.id === activeId ? " active" : "");
      wrap.dataset.id = e.id;
      wrap.innerHTML = `
        <div class="row" role="button" tabindex="0">
          <span class="c-name"><span class="arrow">▸</span>${esc(e.name)}</span>
          <span class="c-cat"><span class="cat-pill" style="color:${catColor[e.category]}">${esc(shortCat(e.category))}</span></span>
          <span class="c-vendor">${esc(e.vendors.slice(0, 2).join(", "))}${e.vendors.length > 2 ? " +" + (e.vendors.length - 2) : ""}</span>
          <span class="c-variants"><b>${e.variants.length}</b> var</span>
        </div>
        <div class="body">${e.id === activeId ? bodyHTML(e) : ""}</div>`;
      tableEl.appendChild(wrap);

      const body = wrap.querySelector(".body");
      if (e.id === activeId) requestAnimationFrame(() => {
        body.style.maxHeight = body.scrollHeight + "px";
      });
    });

    if (!visible.length) {
      tableEl.innerHTML = '<div style="padding:32px 24px;color:var(--muted)">// no entries match — loosen the filters</div>';
    }
  }

  function shortCat(c) {
    return { "Identity Flow Abuse": "Identity Flow",
             "User-Assisted Execution": "User-Assisted Exec",
             "Trusted Delivery": "Trusted Delivery",
             "Reputation Laundering": "Reputation Laundering" }[c] || c;
  }

  /* ---- interactions ---- */
  tableEl.addEventListener("click", (ev) => {
    const row = ev.target.closest(".row");
    if (!row) return;
    toggle(row.parentElement);
  });
  tableEl.addEventListener("keydown", (ev) => {
    if (ev.key !== "Enter" && ev.key !== " ") return;
    const row = ev.target.closest(".row");
    if (!row) return;
    ev.preventDefault();
    toggle(row.parentElement);
  });

  function toggle(entryEl) {
    const id = entryEl.dataset.id;
    const e = ENTRIES.find(x => x.id === id);
    const body = entryEl.querySelector(".body");

    if (activeId === id) {
      body.style.maxHeight = "0px";
      entryEl.classList.remove("active");
      activeId = null;
      renderDetail(null);
      setTimeout(() => { if (activeId !== id) body.innerHTML = ""; }, 360);
      return;
    }

    // collapse previous
    const prev = document.querySelector(".entry.active");
    if (prev) {
      prev.classList.remove("active");
      const pb = prev.querySelector(".body");
      pb.style.maxHeight = "0px";
      const pid = prev.dataset.id;
      setTimeout(() => { if (activeId !== pid) pb.innerHTML = ""; }, 360);
    }

    activeId = id;
    entryEl.classList.add("active");
    body.innerHTML = bodyHTML(e);
    requestAnimationFrame(() => { body.style.maxHeight = body.scrollHeight + "px"; });
    renderDetail(e);
  }

  searchEl.addEventListener("input", () => {
    state.q = searchEl.value.trim().toLowerCase();
    render();
  });
  catEl.addEventListener("change", () => { state.category = catEl.value; render(); });
  venEl.addEventListener("change", () => { state.vendor = venEl.value; render(); });

  function esc(s) {
    return String(s).replace(/[&<>"']/g, c =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  render();
  renderDetail(null);
})();
