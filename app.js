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
  const themeBtn = $("#theme-toggle");
  const clearBtn = $("#clear-filters");

  let activeId = null;
  let state = { q: "", category: "", vendor: "" };
  let searchTimer = null;

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
  $("#stat-vendors").textContent = vendors.length;

  /* ---- URL state helpers ---- */
  function readUrlState() {
    const params = new URLSearchParams(location.search);
    state.q = (params.get("q") || "").toLowerCase();
    state.category = params.get("cat") || "";
    state.vendor = params.get("vendor") || "";
    searchEl.value = state.q;
    catEl.value = state.category;
    venEl.value = state.vendor;
  }

  function writeUrlState() {
    const params = new URLSearchParams();
    if (state.q) params.set("q", state.q);
    if (state.category) params.set("cat", state.category);
    if (state.vendor) params.set("vendor", state.vendor);
    const search = params.toString();
    const url = location.pathname + (search ? "?" + search : "") + (activeId ? "#" + activeId : "");
    history.replaceState(null, "", url);
  }

  function setHash(id) {
    activeId = id;
    writeUrlState();
  }

  /* ---- theme toggle ---- */
  function getSavedTheme() {
    try { return localStorage.getItem("lolphish-theme"); } catch (e) { return null; }
  }
  function saveTheme(theme) {
    try { localStorage.setItem("lolphish-theme", theme); } catch (e) { /* ignore */ }
  }

  function initTheme() {
    const saved = getSavedTheme();
    const systemLight = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches;
    const theme = saved || (systemLight ? "light" : "dark");
    document.documentElement.setAttribute("data-theme", theme);
    updateThemeIcon(theme);
  }

  function cycleTheme() {
    const current = document.documentElement.getAttribute("data-theme") || "dark";
    const next = current === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    saveTheme(next);
    updateThemeIcon(next);
  }

  const sunIcon = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>`;
  const moonIcon = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`;

  function updateThemeIcon(theme) {
    themeBtn.innerHTML = theme === "dark" ? sunIcon : moonIcon;
    themeBtn.setAttribute("title", theme === "dark" ? "Switch to light theme" : "Switch to dark theme");
  }

  /* ---- filtering ---- */
  function matches(e) {
    if (state.category && e.category !== state.category) return false;
    if (state.vendor && !e.vendors.includes(state.vendor)) return false;
    if (state.q) {
      const codeHay = (e.detection_code || []).map(c => [c.lang, c.query, c.description].join(" ")).join(" ");
      const hay = [
        e.id, e.name, e.category, e.vendors.join(" "), e.summary, e.abuse,
        e.variants.join(" "), e.kits.join(" "), e.surfaces.join(" "),
        e.attack.join(" "), e.detections.join(" "), e.mitigations.join(" "), codeHay
      ].join(" ").toLowerCase();
      if (!hay.includes(state.q)) return false;
    }
    return true;
  }

  /* ---- detail panel ---- */
  function detailHTML(e) {
    const vendorChips = e.vendors.map(v =>
      `<span class="v-chip" data-vendor="${esc(v)}">${esc(v)}</span>`).join("");
    return `
      <div class="d-kicker">${esc(e.category)}</div>
      <div class="d-name">${esc(e.name)}</div>
      <div class="d-meta">
        <span class="cat-pill" style="color:${catColor[e.category]}">${esc(e.category)}</span>
        ${vendorChips}
        <a class="permalink" href="#${esc(e.id)}" title="Permalink to this entry">#${esc(e.id)}</a>
      </div>
      <div class="d-summary">${esc(e.summary)}</div>
      <div class="d-abuse">${esc(e.abuse.slice(0, 220))}${e.abuse.length > 220 ? "…" : ""}</div>
      <div class="d-counts">
        <span><b>${e.variants.length}</b>Variants</span>
        <span><b>${e.kits.length}</b>Kits/Actors</span>
        <span><b>${e.detections.length}</b>Detections</span>
      </div>`;
  }

  function renderDetail(e) {
    if (!e) {
      detailEl.innerHTML =
        '<div class="d-empty"><b>Select an entry</b><br><br>' +
        "Click any row to see its full record, detection guidance, and references here.</div>";
      return;
    }
    detailEl.innerHTML = detailHTML(e);
  }

  /* ---- expandable body ---- */
  function bodyHTML(e) {
    const sect = (title, inner, wide) =>
      `<div class="sect${wide ? " wide" : ""}"><h4>${title}</h4>${inner}</div>`;
    const list = (arr) => `<ul class="ticklist">${arr.map(x => `<li>${esc(x)}</li>`).join("")}</ul>`;
    const tags = (arr, cls) => `<div class="tagrow">${arr.map(x => `<span class="tag ${cls}">${esc(x)}</span>`).join("")}</div>`;
    const codeBlock = (snip, idx) => {
      const meta = [snip.lang.toUpperCase(), snip.source].filter(Boolean).join(" · ");
      const desc = snip.description ? `<p class="code-desc">${esc(snip.description)}</p>` : "";
      return `<div class="code-wrap" data-idx="${idx}">
        <div class="code-meta">
          <span>${esc(meta)}</span>
          <button class="copy-btn" type="button" aria-label="Copy query">copy</button>
        </div>
        ${desc}
        <pre><code>${esc(snip.query)}</code></pre>
      </div>`;
    };

    return `
      <div class="body-inner">
        <div class="mobile-detail">${detailHTML(e)}</div>
        ${sect("Legitimate purpose", `<p>${esc(e.summary)}</p>`, true)}
        ${sect("Abuse primitive", `<p>${esc(e.abuse)}</p>`, true)}
        ${sect(`Variants (${e.variants.length})`, list(e.variants))}
        ${sect("Kits / Actors / Tooling", tags(e.kits, "kit"))}
        ${sect("Detection & hunting", list(e.detections))}
        ${e.detection_code && e.detection_code.length ? sect(`Detection code (${e.detection_code.length})`, e.detection_code.map((c, i) => codeBlock(c, i)).join(""), true) : ""}
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
          <span class="c-vendor">${esc(e.vendors.join(", "))}</span>
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
      tableEl.innerHTML = `
        <div class="empty-state">
          <b>No entries match</b>
          Try loosening the filters or <a href="#" class="clear-link">clear all filters</a>.
        </div>`;
      tableEl.querySelector(".clear-link").addEventListener("click", (ev) => {
        ev.preventDefault();
        clearBtn.click();
      });
    }
  }

  function shortCat(c) {
    return { "Identity Flow Abuse": "Identity Flow",
             "User-Assisted Execution": "User-Assisted Exec",
             "Trusted Delivery": "Trusted Delivery",
             "Reputation Laundering": "Reputation Laundering" }[c] || c;
  }

  /* ---- copy-to-clipboard for code blocks ---- */
  tableEl.addEventListener("click", (ev) => {
    const btn = ev.target.closest(".copy-btn");
    if (!btn) return;
    const wrap = btn.closest(".code-wrap");
    const code = wrap.querySelector("code").textContent;
    navigator.clipboard.writeText(code).then(() => {
      const original = btn.textContent;
      btn.textContent = "copied";
      btn.classList.add("copied");
      setTimeout(() => { btn.textContent = original; btn.classList.remove("copied"); }, 1500);
    }).catch(() => {
      btn.textContent = "failed";
      setTimeout(() => { btn.textContent = "copy"; }, 1500);
    });
  });

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
      setHash(null);
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

    setHash(id);
    entryEl.classList.add("active");
    body.innerHTML = bodyHTML(e);
    requestAnimationFrame(() => { body.style.maxHeight = body.scrollHeight + "px"; });
    renderDetail(e);

    // on desktop, scroll selected row into view gently
    if (window.innerWidth > 960) {
      entryEl.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }

  function applyFilters() {
    render();
    writeUrlState();
  }

  searchEl.addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.q = searchEl.value.trim().toLowerCase();
      applyFilters();
    }, 150);
  });
  catEl.addEventListener("change", () => { state.category = catEl.value; applyFilters(); });
  venEl.addEventListener("change", () => { state.vendor = venEl.value; applyFilters(); });
  themeBtn.addEventListener("click", cycleTheme);
  clearBtn.addEventListener("click", () => {
    state.q = ""; state.category = ""; state.vendor = "";
    searchEl.value = ""; catEl.value = ""; venEl.value = "";
    applyFilters();
  });

  /* ---- vendor chip click-to-filter ---- */
  document.addEventListener("click", (ev) => {
    const chip = ev.target.closest(".v-chip");
    if (!chip) return;
    const v = chip.dataset.vendor;
    if (!v) return;
    venEl.value = v;
    state.vendor = v;
    applyFilters();
    window.scrollTo({ top: 0, behavior: "smooth" });
  });

  function esc(s) {
    return String(s).replace(/[&<>"']/g, c =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  /* ---- init ---- */
  initTheme();
  readUrlState();
  render();

  // open hash target after first render
  const hashId = (location.hash || "").replace(/^#/, "");
  if (hashId) {
    const target = ENTRIES.find(x => x.id === hashId);
    if (target) {
      const el = document.querySelector(`.entry[data-id="${CSS.escape(hashId)}"] .row`);
      if (el) {
        activeId = hashId; // setHash writes URL, but hash already matches
        el.parentElement.classList.add("active");
        const body = el.parentElement.querySelector(".body");
        body.innerHTML = bodyHTML(target);
        requestAnimationFrame(() => { body.style.maxHeight = body.scrollHeight + "px"; });
        renderDetail(target);
        el.scrollIntoView({ behavior: "auto", block: "center" });
      }
    }
  } else {
    renderDetail(null);
  }
})();
