"use strict";
(() => {
  const $ = id => document.getElementById(id);
  const json = value => JSON.stringify(value, null, 2);
  const el = (tag, text, className) => {
    const n = document.createElement(tag);
    if (text !== undefined) n.textContent = text;
    if (className) n.className = className;
    return n;
  };
  const option = (value, text) => {
    const n = el("option", text);
    n.value = value;
    return n;
  };
  const action = (text, fn, className = "quiet") => {
    const n = el("button", text, className);
    n.type = "button";
    n.addEventListener("click", () => attempt(fn));
    return n;
  };
  let token = sessionStorage.getItem("drill-session"),
    state, draft, dirty = false,
    advanced = false,
    stale = false,
    busy = false,
    research, runsJSON = "",
    pendingRun = null;

  function notice(message, error = false) {
    $("notice").hidden = false;
    $("notice").textContent = message;
    $("notice").className = error ? "error" : "success";
  }
  async function api(path, data, bootstrap = false) {
    const headers = {};
    if (token && !bootstrap) headers.Authorization = "Bearer " + token;
    if (data !== undefined) headers["Content-Type"] = "application/json";
    const response = await fetch(path, {
      method: data === undefined ? "GET" : "POST",
      headers,
      body: data === undefined ? undefined : JSON.stringify(data),
      credentials: "omit",
      redirect: "error"
    });
    const result = await response.json();
    if (!response.ok) {
      if (response.status === 409 && !path.startsWith("/api/research")) {
        stale = true;
        controls();
      }
      throw new Error(result.error || "Request failed");
    }
    return result;
  }
  async function attempt(fn) {
    try {
      await fn();
    } catch (error) {
      notice(error.message, true);
    }
  }

  function selectPanel(id) {
    document.querySelectorAll(".panel").forEach(n => n.hidden = n.id !== id);
    document.querySelectorAll(".tab").forEach(n => {
      n.classList.toggle("active", n.dataset.panel === id);
      if (n.dataset.panel === id) n.setAttribute("aria-current", "page");
      else n.removeAttribute("aria-current");
    });
  }

  function suiteAccepted() {
    const record = [...state.decisions].reverse().find(r => r.kind === "suite" && r.subject_id === state
      .suite.id);
    return record && record.decision === "accepted" && record.artifact_digest === state.plan.content_digest;
  }

  function controls() {
    if (!state) return;
    document.querySelectorAll("[data-mutate]").forEach(n => n.disabled = busy || stale || dirty);
    $("save-suite").disabled = busy || stale || !dirty;
    $("lock").disabled ||= !state.plan.ready || !suiteAccepted();
    $("run").disabled ||= !state.lock_digest;
    $("dirty-status").textContent = stale ? "State changed — reload required" : dirty ?
      "Unsaved draft — save before review or execution" : "Saved inputs";
  }

  function markDirty() {
    dirty = true;
    controls();
  }
  async function mutate(path, body) {
    if (stale || dirty || busy) throw new Error(
      "Save your draft or reload the latest state before this action");
    busy = true;
    controls();
    try {
      setState(await api(path, {
        ...body,
        expected_revision: state.revision
      }));
    } finally {
      busy = false;
      controls();
    }
  }

  function setState(value) {
    state = value;
    draft = structuredClone(state.suite);
    dirty = advanced = stale = false;
    render();
  }

  function render() {
    $("suite-id").value = draft.id;
    $("target-kind").value = draft.target.kind;
    $("target-binding").replaceChildren(...state.bindings.filter(b => b.role === "target").map(b => option(b
      .id, b.id)));
    if (![...$("target-binding").options].some(o => o.value === draft.target.binding)) $("target-binding")
      .append(option(draft.target.binding, draft.target.binding));
    $("target-binding").value = draft.target.binding;
    $("seeds").value = draft.seeds.join(", ");
    $("concurrency").value = draft.concurrency;
    $("models").value = json(draft.models);
    $("suite-json").value = json(draft);
    for (const [id, key] of [
        ["model-calls", "model_calls"],
        ["tool-steps", "tool_steps"],
        ["iterations", "strategy_iterations"],
        ["wall-seconds", "wall_seconds"]
      ]) $(id).value = draft.case_limits[key];
    renderSelections();
    renderPlan();
    renderArtifacts();
    renderReview();
    controls();
    $("revision-label").textContent = "Workspace " + state.revision.slice(7, 19);
  }

  function renderSelections() {
    $("selections").replaceChildren();
    draft.selections.forEach((selection, index) => {
      const card = el("div", undefined, "selection"),
        fields = el("div", undefined, "selection-fields");
      const label = (title, field) => {
        const n = el("label", title);
        n.append(field);
        fields.append(n);
      };
      const id = el("input");
      id.value = selection.id;
      id.addEventListener("input", () => {
        selection.id = id.value;
        markDirty();
      });
      label("Selection ID", id);
      const source = el("select");
      source.append(...state.sources.map(s => option(s.id, s.id)));
      if (!state.sources.some(s => s.id === selection.source)) source.append(option(selection.source,
        selection.source + " (missing)"));
      source.value = selection.source;
      source.addEventListener("change", () => {
        selection.source = source.value;
        selection.scenarios = ["*"];
        markDirty();
        renderSelections();
      });
      label("Scenario source", source);
      const strategy = el("select");
      strategy.append(option("", "Direct scenario"), ...state.bindings.filter(b => b.role ===
        "attack_strategy").map(b => option(b.id, b.id)), ...state.artifacts.filter(a => a.kind ===
        "plugin" && a.document.roles.includes("attack_strategy")).map(a => option(a.id, a.id + (a
        .current_acceptance ? " (accepted)" : " (review required)"))));
      if (selection.strategy && ![...strategy.options].some(o => o.value === selection.strategy))
        strategy.append(option(selection.strategy, selection.strategy + " (missing)"));
      strategy.value = selection.strategy || "";
      strategy.addEventListener("change", () => {
        selection.strategy = strategy.value || null;
        markDirty();
      });
      label("Strategy", strategy);
      const required = el("input");
      required.type = "checkbox";
      required.checked = selection.required;
      required.addEventListener("change", () => {
        selection.required = required.checked;
        markDirty();
      });
      label("Required case", required);
      card.append(fields);
      const choices = el("div", undefined, "scenario-choice"),
        allLabel = el("label", undefined, "check"),
        all = el("input");
      all.type = "checkbox";
      all.checked = selection.scenarios.includes("*");
      allLabel.append(all, document.createTextNode("All scenarios in this source"));
      choices.append(allLabel);
      all.addEventListener("change", () => {
        selection.scenarios = all.checked ? ["*"] : [];
        markDirty();
        renderSelections();
      });
      const list = el("select");
      list.multiple = true;
      list.size = 5;
      list.setAttribute("aria-label", "Scenarios for " + selection.id);
      list.disabled = all.checked;
      list.append(...(state.sources.find(s => s.id === selection.source)?.scenarios || []).map(s => {
        const o = option(s.id, s.id + " · " + s.category);
        o.selected = selection.scenarios.includes(s.id);
        return o;
      }));
      list.addEventListener("change", () => {
        selection.scenarios = [...list.selectedOptions].map(o => o.value);
        markDirty();
      });
      choices.append(list);
      card.append(choices);
      card.append(action("Remove selection", () => {
        draft.selections.splice(index, 1);
        markDirty();
        renderSelections();
      }));
      $("selections").append(card);
    });
  }

  function renderPlan() {
    const plan = state.plan.plan,
      cases = plan.cases || [];
    $("metric-cases").textContent = cases.length;
    $("metric-ready").textContent = cases.filter(c => c.disposition === "ready").length + " / " + cases
      .filter(c => c.disposition !== "ready").length;
    $("metric-plugins").textContent = state.artifacts.filter(a => a.kind === "plugin").length;
    $("metric-lock").textContent = state.lock_digest ? state.lock_digest.slice(7, 19) : "Not created";
    $("plan-status").textContent = state.plan.ready ? "Ready for acceptance" : "Blocked";
    $("plan-status").className = "badge " + (state.plan.ready ? "good" : "bad");
    $("plan-json").textContent = json(state.plan);
    $("case-rows").replaceChildren();
    $("diagnostics").replaceChildren();
    for (const diagnostic of plan.diagnostics || []) $("diagnostics").append(el("p", typeof diagnostic ===
      "string" ? diagnostic : json(diagnostic), "diagnostic"));
    for (const c of cases) {
      const tr = el("tr");
      for (const value of [c.scenario_id || c.scenario?.id || c.case_id, c.strategy || "Direct", c
          .required ? "Yes" : "No", c.disposition
        ]) tr.append(el("td", value));
      $("case-rows").append(tr);
      for (const d of c.diagnostics || []) $("diagnostics").append(el("p", (c.scenario_id || c.case_id) +
        ": " + (typeof d === "string" ? d : json(d)), "diagnostic"));
    }
  }

  function renderArtifacts() {
    $("artifact-cards").replaceChildren();
    for (const a of state.artifacts) {
      const card = el("div", undefined, "card"),
        heading = el("div", undefined, "artifact-heading");
      heading.append(el("h3", a.id), el("span", a.current_acceptance ? "Accepted current bytes" :
        "Review required", "badge " + (a.current_acceptance ? "good" : "warn")));
      card.append(heading);
      card.append(el("p", a.kind + " · " + a.review_digest, "digest"));
      if (a.kind === "plugin") {
        card.append(el("p", "License: " + a.document.license + " · Access: " + (a.document.access_requests
          .join(", ") || "none")));
        const button = action("Check local image availability", () => mutate("/api/probe", {
          plugin_id: a.id
        }));
        button.dataset.mutate = "";
        card.append(button);
        const probe = state.probes.find(p => p.plugin_id === a.id);
        if (probe) card.append(el("p", probe.available ?
          "Image observed locally; execution rechecks isolation." : "Image unavailable locally.",
          "muted"));
      }
      const details = el("details"),
        summary = el("summary", a.previous ? "Changed fields and complete metadata" : "Complete metadata");
      details.append(summary);
      if (a.previous) {
        const changed = [...new Set([...Object.keys(a.previous), ...Object.keys(a.document)])].filter(k =>
          json(a.previous[k]) !== json(a.document[k]));
        details.append(el("p", "Changed: " + changed.join(", "), "diff"), el("pre", json({
          previous: a.previous,
          current: a.document
        })));
      } else details.append(el("pre", json(a.document)));
      card.append(details);
      $("artifact-cards").append(card);
    }
    const chosen = $("review-subject").value;
    $("review-subject").replaceChildren(option("suite", "Suite · " + state.suite.id), ...state.artifacts
      .map((a, i) => option(String(i), a.kind + " · " + a.id)));
    if ([...$("review-subject").options].some(o => o.value === chosen)) $("review-subject").value = chosen;
    $("decision-history").replaceChildren(...[...state.decisions].reverse().map(d => el("p",
      `${d.kind} ${d.subject_id}: ${d.decision} · ${d.actor} · ${d.decided_at || d.recorded_at || ""}\n${d.rationale}\n${d.artifact_digest}`,
      "history-entry")));
  }

  function subject() {
    if ($("review-subject").value === "suite") return {
      kind: "suite",
      id: state.suite.id,
      review_digest: state.plan.content_digest,
      grants: []
    };
    const a = state.artifacts[Number($("review-subject").value)];
    return {
      ...a,
      grants: a.kind === "plugin" ? a.document.access_requests : []
    };
  }

  function renderReview() {
    const a = subject();
    $("review-digest").textContent = "Exact reviewed digest: " + a.review_digest;
    $("grants").replaceChildren(el("legend", "Explicit plugin access"));
    $("grants").hidden = !a.grants.length;
    for (const grant of a.grants) {
      const label = el("label", undefined, "check"),
        check = el("input");
      check.type = "checkbox";
      check.value = grant;
      label.append(check, document.createTextNode(grant));
      $("grants").append(label);
    }
  }
  async function decide(decision) {
    const a = subject(),
      actor = $("reviewer").value.trim(),
      rationale = $("reason").value.trim();
    if (!actor || !rationale) throw new Error("Enter the reviewer and reason for this decision");
    const grants = decision === "accepted" ? [...document.querySelectorAll("#grants input:checked")].map(
      n => n.value) : a.grants;
    await mutate("/api/decision", {
      kind: a.kind,
      subject: a.id,
      expected_digest: a.review_digest,
      actor,
      rationale,
      decision,
      grants
    });
    notice("Recorded " + decision + " decision for " + a.id);
  }
  async function loadRuns() {
    if (!state) return;
    const data = await api("/api/runs"),
      encoded = json(data);
    if (encoded === runsJSON) return;
    runsJSON = encoded;
    $("signing-status").textContent = data.configured_signing ? "Configured signing key" :
      "Advisory evidence";
    $("run-list").replaceChildren();
    for (const job of [...data.jobs].reverse()) {
      const card = el("div", undefined, "card"),
        heading = el("div", undefined, "run-heading");
      heading.append(el("h3", job.run_id || "Starting run"), el("span", job.active ? "Active" : job
        .error ? "Failed" : "Finished", "badge"));
      card.append(heading);
      if (job.error) card.append(el("p", job.error));
      if (job.active) card.append(action("Stop run", async () => {
        await api("/api/cancel", {
          job_id: job.job_id
        });
        notice("Stop requested independently of the agent");
        await loadRuns();
      }, "danger"));
      $("run-list").append(card);
    }
    for (const run of data.runs) {
      const card = el("div", undefined, "card");
      card.append(el("h3", run.run_id), el("p", "Reported state: " + run.status +
        ". Verify before relying on its result.", "muted"));
      const details = el("details");
      details.append(el("summary", "Reported run inventory"), el("pre", json(run)));
      card.append(details, action("Verify evidence", async () => {
        const report = await api("/api/verify", {
          run_id: run.run_id
        });
        $("verification-card").hidden = false;
        $("verification-status").textContent =
          `${report.trusted ? "Trusted signature" : "Advisory signature"} · ${report.replayed ? "Replay complete" : "Replay incomplete"} · ${report.security_passed ? "Security checks passed" : "No security pass"} · ${report.attested_pass ? "Attested pass" : "No attested pass"}`;
        $("verified-cases").replaceChildren(...report.cases.map(c => {
          const row = el("tr");
          row.append(el("td", (c.source_id || "Unknown source") + " / " + (c.scenario_id ||
            c.case_id)), el("td", c.result?.security || "Incomplete"), el("td", c
            .diagnostics.join("; ") || "None"));
          return row;
        }));
        $("verification-json").textContent = json(report);
      }));
      $("run-list").append(card);
    }
    if (!data.runs.length && !data.jobs.length) $("run-list").append(el("p",
      "No runs yet. Accept the suite, create its lock, then start a bounded run.", "muted"));
  }
  async function loadResearch() {
    research = await api("/api/research");
    $("research-content").replaceChildren();
    if (!research.available) {
      $("research-content").append(el("p", research.reason, "card"));
      return;
    }
    for (const paper of research.papers) {
      const card = el("div", undefined, "card paper");
      card.append(el("h3", paper.metadata.title), el("p", paper.id + " · " + (paper.review_status ||
        "unreviewed"), "muted"), el("p", paper.metadata.summary || ""));
      const details = el("details");
      details.append(el("summary", "Paper, implementation claims and history"), el("pre", json({
        paper,
        implementations: research.implementations.filter(i => i.paper_id === paper.id),
        events: research.events.filter(e => e.paper_id === paper.id)
      })));
      card.append(details);
      const fields = el("div", undefined, "research-review"),
        status = el("select"),
        actor = el("input"),
        note = el("input");
      status.setAttribute("aria-label", "Research status for " + paper.id);
      status.append(...["unreviewed", "reviewed", "selected", "rejected", "deferred"].map(s => option(s,
        s)));
      actor.placeholder = "Reviewer";
      actor.setAttribute("aria-label", "Research reviewer for " + paper.id);
      note.placeholder = "Review note";
      note.setAttribute("aria-label", "Research note for " + paper.id);
      fields.append(status, actor, note, action("Save research review", async () => {
        if (!actor.value.trim() || !note.value.trim()) throw new Error(
          "Enter a research reviewer and note");
        await api("/api/research/review", {
          paper_id: paper.id,
          status: status.value,
          actor: actor.value.trim(),
          note: note.value.trim(),
          expected_revision: research.revision
        });
        await loadResearch();
        notice("Research review saved; suite acceptance remains separate");
      }));
      card.append(fields);
      $("research-content").append(card);
    }
    if (!research.papers.length) $("research-content").append(el("p",
      "No papers in the selected Scout database.", "card"));
  }
  $("reload").addEventListener("click", () => attempt(async () => {
    setState(await api("/api/state"));
    notice("Loaded latest saved inputs");
  }));
  document.querySelectorAll(".tab").forEach(n => n.addEventListener("click", () => {
    selectPanel(n.dataset.panel);
    if (n.dataset.panel === "research") attempt(loadResearch);
    if (n.dataset.panel === "runs") attempt(loadRuns);
  }));
  for (const id of ["suite-id", "target-kind", "target-binding", "seeds", "concurrency", "models",
      "model-calls", "tool-steps", "iterations", "wall-seconds"
    ]) $(id).addEventListener("input", markDirty);
  $("suite-json").addEventListener("input", () => {
    advanced = true;
    markDirty();
  });
  $("add-selection").addEventListener("click", () => {
    let i = draft.selections.length + 1;
    while (draft.selections.some(s => s.id === "selection-" + i)) i++;
    draft.selections.push({
      id: "selection-" + i,
      source: state.sources[0].id,
      scenarios: ["*"],
      required: true,
      strategy: null
    });
    markDirty();
    renderSelections();
  });
  $("save-suite").addEventListener("click", () => attempt(async () => {
    if (stale || busy) throw new Error("Reload the latest state before saving");
    let document;
    if (advanced) document = JSON.parse($("suite-json").value);
    else {
      document = structuredClone(draft);
      document.id = $("suite-id").value;
      document.target = {
        kind: $("target-kind").value,
        binding: $("target-binding").value
      };
      document.seeds = $("seeds").value.split(",").map(s => {
        if (!/^\d+$/.test(s.trim())) throw new Error(
          "Seeds must be comma-separated whole numbers");
        return Number(s.trim());
      });
      document.concurrency = Number($("concurrency").value);
      document.models = JSON.parse($("models").value);
      for (const [id, key] of [
          ["model-calls", "model_calls"],
          ["tool-steps", "tool_steps"],
          ["iterations", "strategy_iterations"],
          ["wall-seconds", "wall_seconds"]
        ]) document.case_limits[key] = Number($(id).value);
    }
    busy = true;
    controls();
    try {
      setState(await api("/api/suite", {
        document,
        expected_revision: state.revision
      }));
      notice("Suite saved and preflight refreshed");
    } finally {
      busy = false;
      controls();
    }
  }));
  $("review-subject").addEventListener("change", renderReview);
  for (const [id, decision] of [
      ["accept", "accepted"],
      ["reject", "rejected"],
      ["revoke", "revoked"]
    ]) $(id).addEventListener("click", () => attempt(() => decide(decision)));
  $("import-file").addEventListener("change", () => attempt(async () => {
    const file = $("import-file").files[0];
    if (!file) return;
    if (file.size > 2 * 1024 * 1024) throw new Error("Metadata file exceeds 2 MiB");
    $("import-json").value = await file.text();
  }));
  $("import-artifact").addEventListener("click", () => attempt(async () => {
    await mutate("/api/import", {
      kind: $("import-kind").value,
      document: JSON.parse($("import-json").value)
    });
    notice("Metadata imported for review");
  }));
  $("lock").addEventListener("click", () => attempt(async () => {
    await mutate("/api/lock", {});
    notice("Created a lock for the accepted exact plan");
  }));
  $("run").addEventListener("click", () => attempt(async () => {
    if (busy || dirty || stale) throw new Error("Save or reload before running");
    const seconds = $("retain").checked ? 3600 : null;
    if (!pendingRun || pendingRun.expected_revision !== state.revision || pendingRun
      .raw_retention_seconds !== seconds) pendingRun = {
      expected_revision: state.revision,
      request_id: crypto.randomUUID().replaceAll("-", ""),
      raw_retention_seconds: seconds
    };
    busy = true;
    controls();
    try {
      await api("/api/run", pendingRun);
      pendingRun = null;
      await loadRuns();
      notice("Bounded run started");
    } finally {
      busy = false;
      controls();
    }
  }));
  $("export").addEventListener("click", () => attempt(async () => {
    const data = await api("/api/export"),
      url = URL.createObjectURL(new Blob([json(data)], {
        type: "application/json"
      })),
      link = el("a");
    link.href = url;
    link.download = "drill-workbench-inputs.json";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }));
  $("refresh-research").addEventListener("click", () => attempt(loadResearch));
  $("load-mappings").addEventListener("click", () => attempt(async () => {
    const data = await api("/api/mappings");
    $("mapping-list").replaceChildren(el("p", "Checked local origin/main " + data
      .checked_main_commit, "digest"));
    for (const mapping of data.mappings) {
      const detail = el("details");
      detail.append(el("summary", mapping.mapping_id + (mapping.git_and_reviews_current ?
        " · Current Git and reviews" : " · Review diagnostics")), el("pre", json(mapping)));
      $("mapping-list").append(detail);
    }
    if (!data.mappings.length) $("mapping-list").append(el("p",
      "No recorded mappings for this repository."));
    if (data.database_divergence.length) $("mapping-list").append(el("p",
      "Recorded database state differs: " + data.database_divergence.join(", "), "diagnostic"));
  }));
  attempt(async () => {
    const bootstrap = new URLSearchParams(location.hash.slice(1)).get("session");
    history.replaceState(null, "", "/");
    if (bootstrap) {
      const result = await api("/api/session", {
        token: bootstrap
      }, true);
      token = result.token;
      sessionStorage.setItem("drill-session", token);
    }
    if (!token) throw new Error("Open the authenticated launch link printed by the CLI");
    setState(await api("/api/state"));
    await loadRuns();
    setInterval(() => {
      if (!document.hidden) attempt(loadRuns);
    }, 2000);
  });
})();
