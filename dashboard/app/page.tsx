"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { io } from "socket.io-client";
import { parsePacketLog, type PacketLog } from "../lib/packet-log";

const MAX_ROWS = 500;
const FLUSH_INTERVAL_MS = 200;
const ROW_ANIM_MS = 700;

type StreamStatus = {
  status: "connected" | "healthy" | "degraded";
  message: string;
  at: string;
};

type UiPacketLog = PacketLog & { id: string; isNew: boolean; ingested_at?: string };

type AlertEvent = {
  alert_id: string;
  severity: "high" | "critical";
  kind: string;
  site: string;
  segment: string;
  src_ip: string;
  dst_ip: string;
  risk_score: number;
  created_at: string;
  summary: string;
};

type AuditEvent = {
  audit_id: string;
  action: "BLOCK_IP" | "QUARANTINE" | "ESCALATE";
  target_ip: string;
  site: string;
  segment: string;
  reason: string;
  status: string;
  created_at: string;
};

type FilterState = {
  site: string;
  segment: string;
  src: string;
  dst: string;
  protocol: "ALL" | "TCP" | "UDP";
  minRisk: number;
  minutes: number;
};

const INITIAL_FILTERS: FilterState = {
  site: "Factory-A",
  segment: "ALL",
  src: "",
  dst: "",
  protocol: "ALL",
  minRisk: 0,
  minutes: 60,
};

export default function Home() {
  const [logs, setLogs] = useState<UiPacketLog[]>([]);
  const [alerts, setAlerts] = useState<AlertEvent[]>([]);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [selected, setSelected] = useState<UiPacketLog | null>(null);
  const [filters, setFilters] = useState<FilterState>(INITIAL_FILTERS);
  const [status, setStatus] = useState<StreamStatus>({
    status: "connected",
    message: "Connecting to stream...",
    at: "",
  });
  const [actionMessage, setActionMessage] = useState("");
  const [nowSec, setNowSec] = useState(() => Math.floor(Date.now() / 1000));

  const pendingRef = useRef<UiPacketLog[]>([]);
  const sequenceRef = useRef(0);

  useEffect(() => {
    const socket = io(window.location.origin, {
      transports: ["websocket", "polling"],
      path: "/socket.io",
    });

    const flushHandle = window.setInterval(() => {
      if (pendingRef.current.length === 0) return;
      const batch = pendingRef.current.splice(0, pendingRef.current.length);
      const batchIds = new Set(batch.map((packet) => packet.id));
      setLogs((prev) => [...batch, ...prev].slice(0, MAX_ROWS));
      window.setTimeout(() => {
        setLogs((prev) =>
          prev.map((packet) =>
            batchIds.has(packet.id) ? { ...packet, isNew: false } : packet,
          ),
        );
      }, ROW_ANIM_MS);
    }, FLUSH_INTERVAL_MS);

    socket.on("connect", () => {
      setStatus({
        status: "connected",
        message: "Connected to PacketPrism live stream",
        at: new Date().toISOString(),
      });
    });

    socket.on("stream_status", (streamStatus: StreamStatus) => setStatus(streamStatus));

    socket.on("bootstrap", (data: { packets: unknown[]; alerts: AlertEvent[]; audit: AuditEvent[] }) => {
      const bootstrapPackets: UiPacketLog[] = [];
      for (const packet of data.packets || []) {
        try {
          sequenceRef.current += 1;
          const parsed = parsePacketLog(packet) as UiPacketLog;
          const id = (parsed.event_id || "evt") + `-${sequenceRef.current}`;
          bootstrapPackets.push({ ...parsed, id, isNew: false });
        } catch {}
      }
      setLogs(bootstrapPackets.slice(0, MAX_ROWS));
      setAlerts((data.alerts || []).slice(0, 100));
      setAudit((data.audit || []).slice(0, 200));
    });

    socket.on("new_packet", (message: unknown) => {
      try {
        const log = parsePacketLog(message) as UiPacketLog;
        sequenceRef.current += 1;
        const id = (log.event_id || "evt") + `-${sequenceRef.current}`;
        pendingRef.current.push({ ...log, id, isNew: true });
      } catch {}
    });

    socket.on("new_alert", (alert: AlertEvent) => {
      setAlerts((prev) => [alert, ...prev].slice(0, 100));
    });

    socket.on("audit_event", (event: AuditEvent) => {
      setAudit((prev) => [event, ...prev].slice(0, 200));
      setActionMessage(`${event.action} accepted for ${event.target_ip}`);
      window.setTimeout(() => setActionMessage(""), 2800);
    });

    socket.on("disconnect", () => {
      setStatus({
        status: "degraded",
        message: "Socket disconnected. Reconnecting...",
        at: new Date().toISOString(),
      });
    });

    return () => {
      socket.close();
      window.clearInterval(flushHandle);
    };
  }, []);

  useEffect(() => {
    const ticker = window.setInterval(() => setNowSec(Math.floor(Date.now() / 1000)), 1000);
    return () => window.clearInterval(ticker);
  }, []);

  const filteredLogs = useMemo(() => {
    const maxAgeSec = filters.minutes * 60;
    return logs.filter((pkt) => {
      if (filters.site && pkt.site !== filters.site) return false;
      if (filters.segment !== "ALL" && pkt.segment !== filters.segment) return false;
      if (filters.protocol !== "ALL" && pkt.protocol !== filters.protocol) return false;
      if (filters.src && !pkt.src_ip.includes(filters.src)) return false;
      if (filters.dst && !pkt.dst_ip.includes(filters.dst)) return false;
      if (pkt.risk_score < filters.minRisk) return false;
      const ts = Number(pkt.timestamp || 0);
      if (maxAgeSec > 0 && nowSec - ts > maxAgeSec) return false;
      return true;
    });
  }, [logs, filters, nowSec]);

  const metrics = useMemo(() => {
    const tcp = filteredLogs.filter((p) => p.protocol === "TCP").length;
    const udp = filteredLogs.filter((p) => p.protocol === "UDP").length;
    const highRisk = filteredLogs.filter((p) => p.risk_score >= 80).length;
    return { total: filteredLogs.length, tcp, udp, highRisk, alerts: alerts.length };
  }, [filteredLogs, alerts]);

  const historyForSelected = useMemo(() => {
    if (!selected) return [];
    return logs
      .filter(
        (pkt) =>
          pkt.src_ip === selected.src_ip ||
          pkt.dst_ip === selected.dst_ip ||
          pkt.src_ip === selected.dst_ip ||
          pkt.dst_ip === selected.src_ip,
      )
      .slice(0, 12);
  }, [selected, logs]);

  async function triggerAction(action: "BLOCK_IP" | "QUARANTINE" | "ESCALATE") {
    if (!selected) return;
    const response = await fetch("/api/actions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action,
        target_ip: selected.src_ip,
        site: selected.site || filters.site,
        segment: selected.segment || "IT VLAN",
        reason: `Operator action from dashboard on packet ${selected.event_id || selected.id}`,
      }),
    });

    const result = (await response.json()) as { message: string };
    setActionMessage(result.message);
    window.setTimeout(() => setActionMessage(""), 2800);
  }

  return (
    <main className="dashboard-shell">
      <section className="hero">
        <h1 className="title">PacketPrism Factory Network Operations Console</h1>
        <p className="subtitle">
          Live telemetry streams automatically from deployed PacketPrism agents. Investigate suspicious
          traffic, triage high-risk flows, and execute approved containment actions with full audit trace.
        </p>
      </section>

      <section className="status-grid">
        <article className="card pulse-in">
          <h3>Telemetry Health</h3>
          <p className={`status-text status-${status.status}`}>{status.message}</p>
          <span className="card-meta" suppressHydrationWarning>
            Updated: {status.at ? new Date(status.at).toLocaleTimeString() : "--:--:--"}
          </span>
        </article>
        <article className="card rise-in">
          <h3>Visible Flows</h3>
          <p className="metric">{metrics.total}</p>
          <span className="card-meta">TCP {metrics.tcp} / UDP {metrics.udp}</span>
        </article>
        <article className="card rise-in delay-1">
          <h3>High Risk / Alerts</h3>
          <p className="metric danger">{metrics.highRisk} / {metrics.alerts}</p>
          <span className="card-meta">Risk score 80+ is highlighted</span>
        </article>
      </section>

      <section className="card filter-panel fade-in">
        <h3>Operations Filters</h3>
        <div className="filters-grid">
          <label>Site<select value={filters.site} onChange={(e) => setFilters((f) => ({ ...f, site: e.target.value }))}><option>Factory-A</option><option>Factory-B</option></select></label>
          <label>Segment<select value={filters.segment} onChange={(e) => setFilters((f) => ({ ...f, segment: e.target.value }))}><option value="ALL">ALL</option><option>OT VLAN</option><option>IT VLAN</option><option>DMZ</option></select></label>
          <label>Protocol<select value={filters.protocol} onChange={(e) => setFilters((f) => ({ ...f, protocol: e.target.value as FilterState["protocol"] }))}><option value="ALL">ALL</option><option value="TCP">TCP</option><option value="UDP">UDP</option></select></label>
          <label>Source IP<input value={filters.src} onChange={(e) => setFilters((f) => ({ ...f, src: e.target.value.trim() }))} placeholder="10.0.1.174" /></label>
          <label>Destination IP<input value={filters.dst} onChange={(e) => setFilters((f) => ({ ...f, dst: e.target.value.trim() }))} placeholder="20.207.70.99" /></label>
          <label>Min Risk ({filters.minRisk})<input type="range" min={0} max={100} value={filters.minRisk} onChange={(e) => setFilters((f) => ({ ...f, minRisk: Number(e.target.value) }))} /></label>
          <label>Time Window<select value={filters.minutes} onChange={(e) => setFilters((f) => ({ ...f, minutes: Number(e.target.value) }))}><option value={5}>Last 5 min</option><option value={15}>Last 15 min</option><option value={60}>Last 60 min</option><option value={180}>Last 3 hours</option></select></label>
        </div>
      </section>

      {actionMessage && <section className="action-toast">{actionMessage}</section>}

      <section className="split-grid fade-in delay-2">
        <article className="card table-wrap">
          <h3>Live Packet Stream</h3>
          <div className="table-scroll">
            <table className="packet-table">
              <thead><tr><th>Timestamp</th><th>Site</th><th>Segment</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Ports</th><th>Risk</th><th>Length</th></tr></thead>
              <tbody>
                {filteredLogs.length === 0 ? <tr><td colSpan={9} className="empty-row">No packets match current filters.</td></tr> : filteredLogs.map((pkt) => (
                  <tr key={pkt.id} className={`${pkt.isNew ? "row-animate" : ""} ${pkt.risk_score >= 80 ? "row-risk" : ""}`} onClick={() => setSelected(pkt)}>
                    <td>{pkt.timestamp}</td><td>{pkt.site || "Factory-A"}</td><td>{pkt.segment || "IT VLAN"}</td><td>{pkt.src_ip}</td><td>{pkt.dst_ip}</td>
                    <td><span className={`pill ${pkt.protocol === "TCP" ? "pill-tcp" : "pill-udp"}`}>{pkt.protocol}</span></td>
                    <td>{pkt.src_port} → {pkt.dst_port}</td>
                    <td><span className={`risk-badge risk-${pkt.risk_score >= 80 ? "high" : pkt.risk_score >= 50 ? "mid" : "low"}`}>{pkt.risk_score}</span></td>
                    <td>{pkt.length}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </article>

        <aside className="card side-panel">
          <h3>Incident Workbench</h3>
          {!selected ? <p className="card-meta">Select a packet row to inspect details and trigger approved actions.</p> : <>
            <div className="selected-card">
              <p><strong>Flow:</strong> {selected.src_ip}:{selected.src_port} → {selected.dst_ip}:{selected.dst_port}</p>
              <p><strong>Site/Segment:</strong> {selected.site || "Factory-A"} / {selected.segment || "IT VLAN"}</p>
              <p><strong>Risk:</strong> {selected.risk_score}</p>
              <p><strong>Protocol:</strong> {selected.protocol}</p>
            </div>
            <div className="action-row">
              <button onClick={() => triggerAction("BLOCK_IP")} className="btn btn-danger">Block IP</button>
              <button onClick={() => triggerAction("QUARANTINE")} className="btn btn-warning">Quarantine</button>
              <button onClick={() => triggerAction("ESCALATE")} className="btn btn-neutral">Escalate</button>
            </div>
            <h4>Related History</h4>
            <ul className="history-list">{historyForSelected.map((pkt) => <li key={`${pkt.id}-history`}>{pkt.timestamp} | {pkt.src_ip} → {pkt.dst_ip} | risk {pkt.risk_score}</li>)}</ul>
          </>}

          <h4>Audit Log</h4>
          <ul className="history-list audit-list">{audit.slice(0, 10).map((event) => <li key={event.audit_id}>{new Date(event.created_at).toLocaleTimeString()} | {event.action} | {event.target_ip}</li>)}</ul>

          <h4>Latest Alerts</h4>
          <ul className="history-list">{alerts.slice(0, 8).map((alert) => <li key={alert.alert_id}>[{alert.severity}] {alert.src_ip} → {alert.dst_ip} (risk {alert.risk_score})</li>)}</ul>
        </aside>
      </section>
    </main>
  );
}
