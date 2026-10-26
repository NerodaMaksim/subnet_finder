const subnetsEl = document.getElementById("subnets");
const emptyEl = document.getElementById("subnet-empty");
const warningEl = document.getElementById("large-warning");
const refreshBtn = document.getElementById("refresh");
const scanBtn = document.getElementById("scan");
const cancelBtn = document.getElementById("cancel");
const progressLabel = document.getElementById("progress-label");
const barFill = document.getElementById("bar-fill");
const statusEl = document.getElementById("status");
const resultsEl = document.getElementById("results");
const liveCountEl = document.getElementById("live-count");

let abortScan = null;
// Hostnames arrive after the host itself, so rows are keyed by IP and updated
// in place rather than appended twice.
const hostRows = new Map();

function prefixLen(cidr) {
  const parts = cidr.split("/");
  return Number(parts[1]);
}

function selectedCIDRs() {
  return [...subnetsEl.querySelectorAll("input[type=checkbox]:checked")].map((el) => el.value);
}

function updateWarning() {
  const large = selectedCIDRs().some((cidr) => prefixLen(cidr) < 22);
  warningEl.classList.toggle("hidden", !large);
}

function setBusy(busy) {
  scanBtn.disabled = busy || selectedCIDRs().length === 0;
  cancelBtn.disabled = !busy;
  refreshBtn.disabled = busy;
  subnetsEl.querySelectorAll("input").forEach((el) => {
    el.disabled = busy;
  });
}

function setStatus(text, isError) {
  statusEl.textContent = text || "";
  statusEl.classList.toggle("error", Boolean(isError));
}

function setProgress(scanned, total, extra) {
  const pct = total > 0 ? Math.min(100, (scanned / total) * 100) : 0;
  barFill.style.width = `${pct}%`;
  progressLabel.textContent = extra || (total > 0 ? `${scanned} / ${total}` : "Idle");
}

function cell(text, asCode) {
  const td = document.createElement("td");
  if (asCode) {
    const code = document.createElement("code");
    code.textContent = text;
    td.appendChild(code);
  } else {
    td.textContent = text;
  }
  return td;
}

function renderHost(host) {
  let tr = hostRows.get(host.ip);
  if (!tr) {
    tr = document.createElement("tr");
    hostRows.set(host.ip, tr);
    resultsEl.appendChild(tr);
  }

  const ports = (host.ports || []).slice().sort((a, b) => a - b).join(", ") || "—";
  const hostnameCell = cell(host.hostname || "—");
  if (host.hostname_source) {
    hostnameCell.title = `resolved via ${host.hostname_source}`;
  }

  tr.replaceChildren(
    cell(host.ip, true),
    hostnameCell,
    cell(host.method),
    cell(ports)
  );
}

function renderSubnets(subnets) {
  subnetsEl.innerHTML = "";
  emptyEl.classList.toggle("hidden", subnets.length > 0);
  for (const s of subnets) {
    const label = document.createElement("label");
    label.className = "subnet";

    const input = document.createElement("input");
    input.type = "checkbox";
    input.value = s.cidr;
    input.addEventListener("change", () => {
      scanBtn.disabled = selectedCIDRs().length === 0;
      updateWarning();
    });

    const meta = document.createElement("span");
    meta.className = "meta";
    const cidrEl = document.createElement("span");
    cidrEl.className = "cidr";
    cidrEl.textContent = s.cidr;
    const ifaceEl = document.createElement("span");
    ifaceEl.className = "iface";
    ifaceEl.textContent = `${s.interface} · ${s.address}`;
    meta.append(cidrEl, ifaceEl);

    label.append(input, meta);
    subnetsEl.appendChild(label);
  }
  scanBtn.disabled = true;
  updateWarning();
}

async function loadSubnets() {
  setStatus("");
  try {
    const res = await fetch("/api/subnets");
    if (!res.ok) {
      throw new Error(await res.text());
    }
    const data = await res.json();
    renderSubnets(data.subnets || []);
    if (!(data.subnets || []).length) {
      setStatus("No interfaces with IPv4 subnets are available.", true);
    }
  } catch (err) {
    console.error(err);
    renderSubnets([]);
    setStatus("Failed to load subnets.", true);
  }
}

async function readSSE(response, onEvent) {
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";

  while (true) {
    const { value, done } = await reader.read();
    if (done) {
      break;
    }
    buf += decoder.decode(value, { stream: true });
    buf = buf.replace(/\r\n/g, "\n");

    let idx;
    while ((idx = buf.indexOf("\n\n")) !== -1) {
      const raw = buf.slice(0, idx);
      buf = buf.slice(idx + 2);
      let event = "message";
      const dataLines = [];
      for (const line of raw.split("\n")) {
        if (line.startsWith("event:")) {
          event = line.slice(6).trim();
        } else if (line.startsWith("data:")) {
          dataLines.push(line.slice(5).trim());
        }
      }
      if (!dataLines.length) {
        continue;
      }
      onEvent(event, JSON.parse(dataLines.join("\n")));
    }
  }
}

async function startScan() {
  const cidrs = selectedCIDRs();
  if (!cidrs.length) {
    return;
  }

  abortScan = new AbortController();
  hostRows.clear();
  resultsEl.innerHTML = "";
  liveCountEl.textContent = "0 found";
  setProgress(0, 0, "Starting…");
  setStatus("");
  setBusy(true);

  let live = 0;
  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "text/event-stream" },
      body: JSON.stringify({ cidrs }),
      signal: abortScan.signal,
    });
    if (!res.ok) {
      throw new Error((await res.text()) || `scan failed (${res.status})`);
    }

    await readSSE(res, (event, data) => {
      const p = data.progress;
      if (p) {
        setProgress(p.scanned, p.total);
        live = p.live;
        liveCountEl.textContent = `${live} found`;
      }
      if (event === "host" && data.host) {
        renderHost(data.host);
      }
      if (event === "resolving") {
        setProgress(p ? p.scanned : 0, p ? p.total : 0, data.message || "Resolving hostnames…");
      }
      if (event === "error") {
        setStatus(data.message || "Scan failed.", true);
      }
      if (event === "done" && p) {
        setProgress(p.scanned, p.total, `Done · ${p.live} live of ${p.total}`);
      }
    });
  } catch (err) {
    if (err.name === "AbortError") {
      setStatus("Scan cancelled.");
    } else {
      console.error(err);
      setStatus(err.message || "Scan failed.", true);
    }
  } finally {
    abortScan = null;
    setBusy(false);
    scanBtn.disabled = selectedCIDRs().length === 0;
  }
}

refreshBtn.addEventListener("click", loadSubnets);
scanBtn.addEventListener("click", startScan);
cancelBtn.addEventListener("click", () => {
  if (abortScan) {
    abortScan.abort();
  }
});

loadSubnets();
