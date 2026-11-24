const $ = (id) => document.getElementById(id);
const names = {
  password_spray: "Password spray", mfa_push: "MFA push activity", new_country: "New country sign-in",
  impossible_travel: "Impossible travel", inbox_rule: "Suspicious inbox rule",
  risky_signin: "High-risk sign-in", file_detection: "File detection", unknown: "Unmapped alert",
  vt_ip: "VirusTotal IP", vt_hash: "VirusTotal hash", abuseipdb: "AbuseIPDB",
};
const title = (value) => names[value] || value.replaceAll("_", " ").replace(/^./, (letter) => letter.toUpperCase());
const view = {source: "demo", rows: [], selected: null, details: null, page: 0, loading: false, writing: false, csrf: ""};
const PAGE_SIZE = 8;
const element = (name, text, className) => {
  const node = document.createElement(name);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
};
const badge = (text, kind) => element("span", text, "badge " + kind);

async function api(path, payload) {
  const options = payload ? {method: "POST", headers: {
    "Content-Type": "application/json", "X-Triage-Token": view.csrf,
  }, body: JSON.stringify(payload)} : {};
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Request failed.");
  return data;
}

function query(source, id) {
  return new URLSearchParams({source, ...(id ? {id} : {})});
}

function renderQueue() {
  const reviewed = view.rows.filter((row) => row.review).length;
  $("count-total").textContent = view.rows.length;
  $("count-pending").textContent = view.rows.length - reviewed;
  $("count-approved").textContent = reviewed;
  $("count-high").textContent = view.rows.filter((row) => row.severity === "high").length;
  const term = $("search").value.trim().toLowerCase();
  const severity = $("severity").value;
  const review = $("review-filter").value;
  const filtered = view.rows.filter((row) =>
    (!severity || severity === row.severity)
    && (!review || (row.review ? "approved" : "pending") === review)
    && (!term || (title(row.category) + " " + row.id).toLowerCase().includes(term)));
  view.page = Math.min(view.page, Math.max(0, Math.ceil(filtered.length / PAGE_SIZE) - 1));
  const start = view.page * PAGE_SIZE;
  const items = filtered.slice(start, start + PAGE_SIZE);
  const rows = items.map((row) => {
    const tr = element("tr", undefined, row.id === view.selected ? "selected" : "");
    const label = element("button", title(row.category), "alert-name");
    label.type = "button";
    label.setAttribute("aria-pressed", String(row.id === view.selected));
    label.setAttribute("aria-label", title(row.category) + ", " + row.id);
    label.addEventListener("click", () => selectAlert(row.id));
    const identity = element("td");
    identity.append(label, element("span", row.id, "mono cell-id"));
    const severityCell = element("td");
    severityCell.append(badge(title(row.severity), row.severity));
    const reviewCell = element("td");
    reviewCell.append(row.review ? badge(title(row.review.verdict), "approved") : badge("Pending", "pending"));
    tr.append(identity, severityCell, element("td", row.indicators), reviewCell);
    return tr;
  });
  $("alerts").replaceChildren(...rows);
  $("empty").hidden = Boolean(filtered.length) || view.loading;
  $("pagination-label").textContent = view.loading ? "Loading alerts…" :
    filtered.length ? `${start + 1}–${start + items.length} of ${filtered.length} alerts` : "0 alerts";
  $("prev").disabled = view.page === 0;
  $("next").disabled = start + PAGE_SIZE >= filtered.length;
  $("source-note").textContent = view.source === "demo" ? "Synthetic data" : "Wazuh manager";
}

function setMessage(text, error = false) {
  $("review-message").textContent = text;
  $("review-message").classList.toggle("error", error);
}

function renderDetail() {
  const row = view.rows.find((item) => item.id === view.selected);
  const details = view.details;
  const ready = Boolean(row && details);
  $("detail").hidden = !ready;
  $("detail-empty").hidden = ready;
  $("detail-status").className = "badge " + (ready ? row.review ? "approved" : "pending" : "neutral");
  $("detail-status").textContent = ready ? row.review ? "Approved" : "Pending review" : "Select an alert";
  if (!ready) return;
  $("detail-id").textContent = row.id;
  $("detail-category").textContent = title(row.category);
  $("attack-tags").replaceChildren(...(details.draft.techniques.length ?
    details.draft.techniques.map((item) => element("span", item, "tag")) :
    [element("span", "No MITRE technique mapped", "muted")]));
  const fields = [["Severity", title(row.severity)], ["IP addresses", details.ips.join(", ") || "None"],
    ["File hashes", details.hashes.join(", ") || "None"]];
  for (const [key, value] of Object.entries(details.facts.counts)) fields.push([title(key), String(value)]);
  for (const [key, value] of Object.entries(details.facts.signals)) fields.push([title(key), value ? "Yes" : "No"]);
  for (const rep of details.facts.reputation) {
    const label = rep.status !== "ok" ? title(rep.status) :
      rep.score !== undefined ? `Score ${rep.score}/100` : `${rep.malicious} malicious detections`;
    fields.push([title(rep.provider), label]);
  }
  $("evidence").replaceChildren(...fields.flatMap(([key, value]) => [element("dt", key), element("dd", value)]));
  $("engine-tag").textContent = details.engine === "baseline" ? "Reference policy" : details.engine;
  $("draft-verdict").textContent = title(details.draft.verdict);
  $("draft-summary").textContent = details.draft.summary;
  const opinion = details.draft.model_verdict;
  $("model-opinion").hidden = !opinion;
  $("model-opinion").textContent = opinion ?
    `Model opinion: ${title(opinion)}${opinion !== details.draft.verdict ? " (disagrees with the rules: check before approving)" : ""}` : "";
  $("rule-reason").hidden = !details.draft.rule_reason;
  $("rule-reason").textContent = details.draft.rule_reason ? "Rule reason: " + details.draft.rule_reason : "";
  $("draft-steps").replaceChildren(...details.step_labels.map((step) => element("li", step)));
  $("enrich-label").hidden = view.source === "demo" || !!row.review;
  $("final-verdict").value = row.review?.verdict || details.draft.verdict;
  $("final-verdict").disabled = !!row.review || view.writing;
  $("generate").disabled = view.writing || !!row.review;
  $("approve").disabled = view.writing || !!row.review || !$("final-verdict").value;
  if (row.review) {
    const date = new Date(row.review.reviewed_at);
    setMessage(`Approved locally · ${date.toLocaleString()}`);
  }
}

async function selectAlert(id) {
  const source = view.source;
  view.selected = id;
  view.details = null;
  $("enrich").checked = false;
  setMessage("");
  renderQueue();
  renderDetail();
  try {
    const details = await api("/api/alert?" + query(source, id));
    if (view.selected === id && view.source === source) {
      view.details = details;
      renderDetail();
    }
  } catch (error) {
    if (view.selected === id && view.source === source) {
      $("detail-empty").textContent = error.message;
      $("detail-empty").hidden = false;
    }
  }
}

async function loadQueue(refresh = false) {
  const source = view.source;
  view.loading = true;
  $("queue-error").hidden = true;
  $("detail-empty").textContent = "Select an alert to review its evidence.";
  $("refresh").disabled = true;
  renderQueue();
  renderDetail();
  const args = query(source);
  if (refresh) args.set("refresh", "1");
  try {
    const rows = await api("/api/queue?" + args);
    if (view.source !== source) return;
    view.rows = rows;
    view.loading = false;
    const current = rows.some((row) => row.id === view.selected) ? view.selected : rows[0]?.id;
    if (current) await selectAlert(current);
    else {
      view.selected = null;
      view.details = null;
      renderQueue();
      renderDetail();
    }
  } catch (error) {
    if (view.source !== source) return;
    view.rows = [];
    view.selected = null;
    view.details = null;
    view.loading = false;
    $("queue-error").textContent = error.message;
    $("queue-error").hidden = false;
    renderQueue();
    renderDetail();
  } finally {
    if (view.source === source) $("refresh").disabled = false;
  }
}

$("source").addEventListener("change", (event) => {
  view.source = event.target.value;
  view.selected = null;
  view.details = null;
  view.rows = [];
  view.page = 0;
  $("search").value = "";
  $("severity").value = "";
  $("review-filter").value = "";
  loadQueue();
});
$("refresh").addEventListener("click", () => loadQueue(true));
for (const id of ["search", "severity", "review-filter"]) {
  $(id).addEventListener("input", () => { view.page = 0; renderQueue(); });
}
$("prev").addEventListener("click", () => { view.page -= 1; renderQueue(); });
$("next").addEventListener("click", () => { view.page += 1; renderQueue(); });
$("final-verdict").addEventListener("change", (event) => { $("approve").disabled = !event.target.value; });

async function updateAlert(route, values) {
  const source = view.source, id = view.selected;
  if (!id || view.writing) return;
  view.writing = true;
  renderDetail();
  setMessage(route === "draft" ? "Generating locally…" : "Saving approval…");
  try {
    const result = await api("/api/" + route, {source, id, ...values});
    if (source === view.source) {
      if (route === "review") {
        view.rows = view.rows.map((row) => row.id === id ? {...row, review: result} : row);
        renderQueue();
      }
      if (id === view.selected) {
        if (route === "draft") view.details = result;
        setMessage(route === "draft" ? "Draft ready for review." : "");
      }
    }
  } catch (error) {
    if (id === view.selected && source === view.source) setMessage(error.message, true);
  } finally {
    view.writing = false;
    renderDetail();
  }
}
$("generate").addEventListener("click", () => updateAlert("draft", {enrich: $("enrich").checked}));
$("approve").addEventListener("click", () => updateAlert("review", {approve: true, verdict: $("final-verdict").value}));

async function loadBenchmarks() {
  if ($("benchmark-cards").childElementCount) return;
  try {
    const results = await api("/api/benchmarks");
    const verdicts = ["malicious", "benign", "needs_review"];
    const cards = results.map((record) => {
      const card = element("article", undefined, "panel bench-card");
      const score = Math.round(record.accuracy * 100);
      const progress = element("progress");
      progress.value = score;
      progress.max = 100;
      progress.setAttribute("aria-label", "Verdict accuracy");
      const track = element("div", undefined, "progress");
      track.append(progress);
      const matrix = element("table", undefined, "matrix");
      const head = element("tr");
      head.append(...["Actual / drafted", ...verdicts.map(title)].map((item) => {
        const th = element("th", item);
        th.scope = "col";
        return th;
      }));
      const matrixHead = element("thead");
      matrixHead.append(head);
      const matrixBody = element("tbody");
      matrixBody.append(...verdicts.map((actual) => {
        const row = element("tr");
        const th = element("th", title(actual));
        th.scope = "row";
        row.append(th, ...verdicts.map((predicted) => element("td", record.confusion_actual_by_predicted[actual][predicted])));
        return row;
      }));
      matrix.append(matrixHead, matrixBody);
      const matrixWrap = element("div", undefined, "table-wrap");
      matrixWrap.append(matrix);
      const runtime = ["ollama", "hybrid"].includes(record.engine) ? ` · ${record.average_draft_seconds.toFixed(2)} s mean draft time` : "";
      const engine = record.engine === "hybrid" ? `Rules + ${record.model}` : record.model || "Decision rules";
      card.append(element("h2", `${engine} · ${title(record.dataset || "")}`), element("div", score + "%", "bench-number"),
        element("p", `${record.correct} of ${record.alerts} correct${runtime}`), track, matrixWrap);
      if (record.assist) {
        const assist = record.assist;
        card.append(element("p", `Model opinion: ${Math.round(assist.model_accuracy * 100)}% accurate · ${assist.model_right_rules_wrong} rule misses caught · ${assist.rules_right_model_wrong} correct rule calls challenged`));
      }
      return card;
    });
    $("benchmark-cards").replaceChildren(...cards);
  } catch (error) {
    $("benchmark-cards").replaceChildren(element("p", error.message, "message"));
  }
}

for (const nav of document.querySelectorAll("[data-view]")) {
  nav.addEventListener("click", () => {
    const benchmark = nav.dataset.view === "benchmark";
    $("queue-view").hidden = benchmark;
    $("benchmark-view").hidden = !benchmark;
    $("crumb").textContent = benchmark ? "Benchmarks" : "Alert queue";
    for (const item of document.querySelectorAll("[data-view]")) {
      item.classList.toggle("active", item === nav);
      if (item === nav) item.setAttribute("aria-current", "page");
      else item.removeAttribute("aria-current");
    }
    if (benchmark) loadBenchmarks();
  });
}

try {
  const config = await api("/api/config");
  view.csrf = config.csrf;
  await loadQueue();
} catch (error) {
  $("queue-error").textContent = error.message;
  $("queue-error").hidden = false;
}
