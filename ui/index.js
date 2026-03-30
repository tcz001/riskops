async function request(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json();
}

function fmtTs(ts) {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleString();
}

function cardTag(value) {
  return `<span class="tag ${value}">${value}</span>`;
}

function displayToolName(item) {
  return item.tool_name || item.raw_event?.tool_name_candidates?.toolName || "unknown_tool";
}

function displayPrompt(item) {
  if (item.user_prompt) {
    return item.user_prompt;
  }
  if (typeof item.params?.query === "string" && item.params.query) {
    return item.params.query;
  }
  return "-";
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function renderAudit(items) {
  const root = document.querySelector("#audit-list");
  root.innerHTML = items.map((item) => `
    <article class="card">
      <div class="card-head">
        <strong>${displayToolName(item)}</strong>
        ${cardTag(item.decision)}
      </div>
      <div class="meta">${fmtTs(item.created_at)} · source=${item.source} · severity=${item.severity}${item.approval_status ? ` · approval=${item.approval_status}` : ""}</div>
      <p>${item.user_message}</p>
      <div class="mini">prompt: ${displayPrompt(item)}\nparams: ${JSON.stringify(item.params, null, 2)}\nsignals: ${JSON.stringify(item.signals, null, 2)}\nraw_event: ${JSON.stringify(item.raw_event || {}, null, 2)}</div>
    </article>
  `).join("") || `<p class="muted">暂无记录</p>`;
}

function renderApprovals(items) {
  const root = document.querySelector("#approvals-list");
  root.innerHTML = items.map((item) => `
    <article class="card">
      <div class="card-head">
        <strong>${item.payload.tool_name || "unknown"}</strong>
        <span class="tag ${item.status === "pending" ? "confirm" : item.status.includes("allow") ? "allow" : "block"}">${item.status}</span>
      </div>
      <div class="meta">created=${fmtTs(item.created_at)} · expires=${fmtTs(item.expires_at)}</div>
      <p>${item.payload.summary || "-"}</p>
      <div class="mini">${JSON.stringify(item.payload.signals || [], null, 2)}</div>
      ${item.status === "pending" ? `
        <div class="actions">
          <button class="primary approval-action" data-id="${escapeHtml(item.id)}" data-decision="allow-once">批准一次</button>
          <button class="approval-action" data-id="${escapeHtml(item.id)}" data-decision="allow-always">总是允许</button>
          <button class="danger approval-action" data-id="${escapeHtml(item.id)}" data-decision="deny">拒绝</button>
        </div>
      ` : ""}
    </article>
  `).join("") || `<p class="muted">暂无审批记录</p>`;

  root.querySelectorAll(".approval-action").forEach((button) => {
    button.addEventListener("click", () => {
      confirmApproval(button.dataset.id, button.dataset.decision).catch((error) => {
        alert(error.message);
      });
    });
  });
}

async function loadHealth() {
  const badge = document.querySelector("#health-badge");
  try {
    await request("/health");
    badge.textContent = "服务在线";
    badge.className = "badge allow";
  } catch (error) {
    badge.textContent = `服务异常: ${error.message}`;
    badge.className = "badge block";
  }
}

async function loadPolicy() {
  const policy = await request("/v1/policy");
  document.querySelector("#policy-editor").value = JSON.stringify(policy, null, 2);
}

async function loadAudit() {
  const decision = document.querySelector("#decision-filter").value;
  const query = decision ? `?decision=${encodeURIComponent(decision)}` : "";
  const payload = await request(`/v1/audit${query}`);
  renderAudit(payload.items);
}

async function loadApprovals() {
  const payload = await request("/v1/approvals");
  renderApprovals(payload.items);
}

async function confirmApproval(confirmationId, decision) {
  await request("/v1/confirm", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      confirmation_id: confirmationId,
      decision,
    }),
  });
  await Promise.all([loadAudit(), loadApprovals()]);
}

async function runEval() {
  const result = await request("/v1/evaluate", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      tool_name: document.querySelector("#tool-name").value,
      source: document.querySelector("#tool-source").value,
      namespace: document.querySelector("#tool-namespace").value || undefined,
      user_prompt: document.querySelector("#tool-prompt").value,
      params: JSON.parse(document.querySelector("#tool-params").value || "{}"),
    }),
  });
  document.querySelector("#eval-result").textContent = JSON.stringify(result, null, 2);
  await Promise.all([loadAudit(), loadApprovals()]);
}

async function savePolicy() {
  const value = document.querySelector("#policy-editor").value;
  const payload = JSON.parse(value);
  await request("/v1/policy", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  await loadPolicy();
}

document.querySelector("#refresh-all").addEventListener("click", async () => {
  await Promise.all([loadHealth(), loadPolicy(), loadAudit(), loadApprovals()]);
});
document.querySelector("#refresh-approvals").addEventListener("click", loadApprovals);
document.querySelector("#decision-filter").addEventListener("change", loadAudit);
document.querySelector("#run-eval").addEventListener("click", () => runEval().catch((error) => {
  document.querySelector("#eval-result").textContent = error.stack || error.message;
}));
document.querySelector("#save-policy").addEventListener("click", () => savePolicy().catch((error) => {
  alert(error.message);
}));

Promise.all([loadHealth(), loadPolicy(), loadAudit(), loadApprovals()]).catch((error) => {
  console.error(error);
});
