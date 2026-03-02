/* eslint-disable @typescript-eslint/no-require-imports */
const fs = require("fs");
const path = require("path");
const http = require("http");
const crypto = require("crypto");
const next = require("next");
const express = require("express");
const { Server } = require("socket.io");
const { createClient } = require("redis");
const { z } = require("zod");

const dev = process.env.NODE_ENV !== "production";
const hostname = process.env.HOSTNAME || "0.0.0.0";
const port = Number(process.env.PORT || 3000);
const redisUrl = process.env.REDIS_URL || "redis://127.0.0.1:6379";
const defaultSite = process.env.DEFAULT_SITE || "Factory-A";
const defaultSegment = process.env.DEFAULT_SEGMENT || "IT VLAN";

const PACKET_LIMIT = 5000;
const ALERT_LIMIT = 500;
const AUDIT_LIMIT = 2000;

const packetLogSchema = z.object({
  src_ip: z.string(),
  dst_ip: z.string(),
  protocol: z.enum(["TCP", "UDP"]),
  src_port: z.number(),
  dst_port: z.number(),
  risk_score: z.number().min(0).max(100),
  length: z.number(),
  timestamp: z.string(),
  site: z.string().optional(),
  segment: z.string().optional(),
  event_id: z.string().optional()
});

const actionSchema = z.object({
  action: z.enum(["BLOCK_IP", "QUARANTINE", "ESCALATE"]),
  target_ip: z.string(),
  site: z.string().min(1),
  segment: z.string().min(1),
  reason: z.string().min(3).max(500).default("Analyst requested containment")
});

const streamStore = { packets: [], alerts: [], audit: [] };

const dataDir = path.join(__dirname, "data");
const files = {
  packets: path.join(dataDir, "packets.jsonl"),
  alerts: path.join(dataDir, "alerts.jsonl"),
  audit: path.join(dataDir, "audit.jsonl")
};

function ensureDataFiles() {
  fs.mkdirSync(dataDir, { recursive: true });
  Object.values(files).forEach((filepath) => {
    if (!fs.existsSync(filepath)) fs.writeFileSync(filepath, "", "utf8");
  });
}

function appendJsonl(filepath, entry) {
  fs.appendFile(filepath, `${JSON.stringify(entry)}\n`, (err) => {
    if (err) console.error("Failed writing JSONL:", err.message);
  });
}

function pushCapped(arr, item, limit) {
  arr.unshift(item);
  if (arr.length > limit) arr.length = limit;
}

function createEventId() {
  return `${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
}

function packetToAlert(packet) {
  if (packet.risk_score < 80) return null;
  return {
    alert_id: `alert-${packet.event_id}`,
    severity: packet.risk_score >= 90 ? "critical" : "high",
    kind: "HIGH_RISK_PACKET",
    site: packet.site,
    segment: packet.segment,
    src_ip: packet.src_ip,
    dst_ip: packet.dst_ip,
    risk_score: packet.risk_score,
    created_at: new Date().toISOString(),
    summary: `High-risk flow ${packet.src_ip}:${packet.src_port} -> ${packet.dst_ip}:${packet.dst_port}`
  };
}

function filterPackets(packets, query) {
  const nowSec = Math.floor(Date.now() / 1000);
  const minRisk = query.min_risk ? Number(query.min_risk) : 0;
  const maxRisk = query.max_risk ? Number(query.max_risk) : 100;
  const maxAgeSec = query.minutes ? Number(query.minutes) * 60 : null;
  const cap = Math.min(Number(query.limit || 200), 1000);

  return packets
    .filter((packet) => (query.site ? packet.site === query.site : true))
    .filter((packet) => (query.segment ? packet.segment === query.segment : true))
    .filter((packet) => (query.src_ip ? packet.src_ip.includes(query.src_ip) : true))
    .filter((packet) => (query.dst_ip ? packet.dst_ip.includes(query.dst_ip) : true))
    .filter((packet) => (query.protocol ? packet.protocol === query.protocol : true))
    .filter((packet) => packet.risk_score >= minRisk && packet.risk_score <= maxRisk)
    .filter((packet) => {
      if (!maxAgeSec) return true;
      const packetTs = Number(packet.timestamp || 0);
      return nowSec - packetTs <= maxAgeSec;
    })
    .slice(0, cap);
}

const app = next({ dev, hostname, port });
const handle = app.getRequestHandler();

async function startServer() {
  ensureDataFiles();
  await app.prepare();

  const expressApp = express();
  expressApp.use(express.json({ limit: "1mb" }));

  const httpServer = http.createServer(expressApp);
  const io = new Server(httpServer, {
    cors: { origin: "*" },
    transports: ["websocket", "polling"]
  });

  const subscriber = createClient({
    url: redisUrl,
    socket: { reconnectStrategy: (retries) => Math.min(retries * 250, 2000) }
  });

  const publisher = createClient({
    url: redisUrl,
    socket: { reconnectStrategy: (retries) => Math.min(retries * 250, 2000) }
  });

  subscriber.on("error", (err) => {
    io.emit("stream_status", {
      status: "degraded",
      message: `Redis error: ${err.message}`,
      at: new Date().toISOString()
    });
  });

  subscriber.on("ready", () => {
    io.emit("stream_status", {
      status: "healthy",
      message: "Live telemetry stream healthy",
      at: new Date().toISOString()
    });
  });

  io.on("connection", (socket) => {
    socket.emit("stream_status", {
      status: "connected",
      message: "Connected to PacketPrism stream",
      at: new Date().toISOString()
    });

    socket.emit("bootstrap", {
      packets: streamStore.packets.slice(0, 120),
      alerts: streamStore.alerts.slice(0, 40),
      audit: streamStore.audit.slice(0, 60)
    });
  });

  await subscriber.connect();
  await publisher.connect();

  await subscriber.subscribe("packet_stream", (payload) => {
    try {
      const parsedPayload = JSON.parse(payload);
      const basePacket = packetLogSchema.parse(parsedPayload);
      const packet = {
        ...basePacket,
        event_id: basePacket.event_id || createEventId(),
        site: basePacket.site || defaultSite,
        segment: basePacket.segment || defaultSegment,
        ingested_at: new Date().toISOString()
      };

      pushCapped(streamStore.packets, packet, PACKET_LIMIT);
      appendJsonl(files.packets, packet);
      io.emit("new_packet", packet);

      const alert = packetToAlert(packet);
      if (alert) {
        pushCapped(streamStore.alerts, alert, ALERT_LIMIT);
        appendJsonl(files.alerts, alert);
        io.emit("new_alert", alert);
      }
    } catch (err) {
      console.error("Dropped invalid packet payload:", err.message);
    }
  });

  expressApp.get("/health", (_req, res) => {
    res.status(200).json({ ok: true, service: "packetprism-dashboard" });
  });

  expressApp.get("/api/packets", (req, res) => {
    const data = filterPackets(streamStore.packets, req.query);
    res.status(200).json({ data, count: data.length });
  });

  expressApp.get("/api/alerts", (_req, res) => {
    res.status(200).json({ data: streamStore.alerts, count: streamStore.alerts.length });
  });

  expressApp.get("/api/audit", (_req, res) => {
    res.status(200).json({ data: streamStore.audit, count: streamStore.audit.length });
  });

  expressApp.post("/api/actions", async (req, res) => {
    try {
      const action = actionSchema.parse(req.body);
      const auditEntry = {
        audit_id: `audit-${createEventId()}`,
        action: action.action,
        target_ip: action.target_ip,
        site: action.site,
        segment: action.segment,
        reason: action.reason,
        status: "accepted",
        created_at: new Date().toISOString()
      };

      await publisher.publish("firewall_commands", JSON.stringify({
        command_id: auditEntry.audit_id,
        action: action.action,
        target_ip: action.target_ip,
        site: action.site,
        segment: action.segment,
        reason: action.reason,
        requested_at: auditEntry.created_at
      }));

      pushCapped(streamStore.audit, auditEntry, AUDIT_LIMIT);
      appendJsonl(files.audit, auditEntry);
      io.emit("audit_event", auditEntry);

      res.status(200).json({
        ok: true,
        message: `${action.action} submitted for ${action.target_ip}`,
        data: auditEntry
      });
    } catch (err) {
      res.status(400).json({ ok: false, message: err.message });
    }
  });

  expressApp.all("*", (req, res) => handle(req, res));

  httpServer.listen(port, hostname, () => {
    console.log(`> Dashboard ready on http://${hostname}:${port}`);
    console.log(`> Redis subscriber channel: packet_stream (${redisUrl})`);
  });
}

startServer().catch((err) => {
  console.error("Failed to start dashboard server:", err);
  process.exit(1);
});
