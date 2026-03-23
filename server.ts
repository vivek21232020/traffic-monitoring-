import express from "express";
import { createServer as createViteServer } from "vite";
import { WebSocketServer, WebSocket } from "ws";
import { createServer } from "http";
import path from "path";

// --- Types ---
interface Packet {
  id: string;
  timestamp: number;
  sourceIp: string;
  destIp: string;
  protocol: "TCP" | "UDP" | "ICMP";
  packetSize: number;
  duration: number;
  status: "Normal" | "Suspicious" | "Attack";
  attackType?: string;
  riskLevel: "Low" | "Medium" | "High";
  confidence?: number;
  location?: {
    country: string;
    city: string;
    isp: string;
    lat: number;
    lng: number;
  };
  isBlocked?: boolean;
}

interface BlockedIp {
  ip: string;
  timeBlocked: number;
  reason: string;
  country?: string;
  isp?: string;
  attempts: number;
}

// --- Constants & State ---
const PORT = 3000;
const MAX_HISTORY = 500;
let packetHistory: Packet[] = [];
let blockedIps: BlockedIp[] = [];
let systemHealth = {
  cpu: 12,
  memory: 45,
  storage: 28,
  uptime: 0,
  temp: 42
};
const clients = new Set<WebSocket>();
const startTime = Date.now();

// --- Traffic Simulation Logic ---
const IP_POOL = [
  "192.168.1.10", "192.168.1.15", "10.0.0.5", "172.16.0.2",
  "45.33.22.11", "185.12.34.56", "203.0.113.42", "8.8.8.8",
  "192.168.1.45", "185.34.22.10", "103.22.11.5", "91.22.33.44"
];

const ATTACK_TYPES = ["DDoS", "Port Scan", "Brute Force", "SQL Injection", "Probe", "DoS Attempt"];

const GEOLOCATIONS = [
  { country: "United States", city: "New York", isp: "Verizon", lat: 40.7128, lng: -74.0060 },
  { country: "Russia", city: "Moscow", isp: "Rostelecom", lat: 55.7558, lng: 37.6173 },
  { country: "China", city: "Beijing", isp: "China Telecom", lat: 39.9042, lng: 116.4074 },
  { country: "Germany", city: "Berlin", isp: "Deutsche Telekom", lat: 52.5200, lng: 13.4050 },
  { country: "Brazil", city: "São Paulo", isp: "Vivo", lat: -23.5505, lng: -46.6333 },
  { country: "North Korea", city: "Pyongyang", isp: "Star JV", lat: 39.0392, lng: 125.7625 }
];

function generatePacket(forceAttack?: string): Packet {
  const isAttack = forceAttack ? true : Math.random() < 0.08;
  const isSuspicious = !isAttack && Math.random() < 0.15;
  
  const protocol: "TCP" | "UDP" | "ICMP" = ["TCP", "UDP", "ICMP"][Math.floor(Math.random() * 3)] as any;
  const sourceIp = isAttack ? GEOLOCATIONS[Math.floor(Math.random() * GEOLOCATIONS.length)].city === "New York" ? "45.33.22.11" : "185.12.34.56" : IP_POOL[Math.floor(Math.random() * IP_POOL.length)];
  const destIp = "192.168.1.1";
  
  let status: "Normal" | "Suspicious" | "Attack" = "Normal";
  let attackType: string | undefined;
  let riskLevel: "Low" | "Medium" | "High" = "Low";
  let confidence: number | undefined;
  let location;

  if (isAttack) {
    status = "Attack";
    attackType = forceAttack || ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)];
    riskLevel = "High";
    confidence = 0.85 + Math.random() * 0.14;
    location = GEOLOCATIONS[Math.floor(Math.random() * GEOLOCATIONS.length)];
    
    // Auto-blocking logic for High risk
    if (!blockedIps.find(b => b.ip === sourceIp)) {
      blockedIps.push({ 
        ip: sourceIp, 
        timeBlocked: Date.now(), 
        reason: `Auto-blocked: ${attackType} detected`,
        country: location.country,
        isp: location.isp,
        attempts: 1
      });
    } else {
      const blocked = blockedIps.find(b => b.ip === sourceIp);
      if (blocked) blocked.attempts++;
    }
  } else if (isSuspicious) {
    status = "Suspicious";
    riskLevel = "Medium";
    confidence = 0.6 + Math.random() * 0.25;
    if (Math.random() > 0.5) {
      location = GEOLOCATIONS[Math.floor(Math.random() * GEOLOCATIONS.length)];
    }
  }

  const isBlocked = blockedIps.some(b => b.ip === sourceIp);

  return {
    id: Math.random().toString(36).substring(7),
    timestamp: Date.now(),
    sourceIp,
    destIp,
    protocol,
    packetSize: Math.floor(Math.random() * 1500) + 40,
    duration: Math.random() * 2,
    status,
    attackType,
    riskLevel,
    confidence,
    location,
    isBlocked
  };
}

// Pre-populate history
for (let i = 0; i < 300; i++) {
  const p = generatePacket();
  p.timestamp = Date.now() - (300 - i) * 1000;
  packetHistory.push(p);
}

// --- Server Setup ---
async function startServer() {
  const app = express();
  app.use(express.json());
  const server = createServer(app);
  const wss = new WebSocketServer({ server });

  // API Routes
  app.get("/api/stats", (req, res) => {
    const total = packetHistory.length;
    const normal = packetHistory.filter(p => p.status === "Normal").length;
    const suspicious = packetHistory.filter(p => p.status === "Suspicious").length;
    const attacks = packetHistory.filter(p => p.status === "Attack").length;
    
    res.json({ total, normal, suspicious, attacks });
  });

  app.get("/api/history", (req, res) => {
    res.json(packetHistory);
  });

  app.get("/api/blocked", (req, res) => {
    res.json(blockedIps);
  });

  app.post("/api/block", (req, res) => {
    const { ip, reason } = req.body;
    if (!ip) return res.status(400).json({ error: "IP required" });
    
    const existing = blockedIps.find(b => b.ip === ip);
    if (!existing) {
      blockedIps.push({ 
        ip, 
        timeBlocked: Date.now(), 
        reason: reason || "Manual block by administrator",
        attempts: 1
      });
    }
    res.json({ success: true, blockedIps });
  });

  app.post("/api/unblock", (req, res) => {
    const { ip } = req.body;
    blockedIps = blockedIps.filter(b => b.ip !== ip);
    res.json({ success: true, blockedIps });
  });

  app.get("/api/ai-metrics", (req, res) => {
    res.json({
      accuracy: 96.2,
      precision: 95.7,
      recall: 94.9,
      f1: 95.3,
      confusionMatrix: [
        [450, 10, 5, 2],
        [8, 120, 12, 5],
        [3, 15, 98, 4],
        [1, 2, 3, 85]
      ]
    });
  });

  app.get("/api/threat-intel", (req, res) => {
    res.json([
      { id: 1, title: "New Mirai Variant Detected", severity: "High", time: "2h ago" },
      { id: 2, title: "Global Increase in SQL Injection", severity: "Medium", time: "5h ago" },
      { id: 3, title: "Zero-day vulnerability in popular router", severity: "Critical", time: "8h ago" },
      { id: 4, title: "Botnet activity spike in SE Asia", severity: "Low", time: "12h ago" }
    ]);
  });

  app.post("/api/simulate-attack", (req, res) => {
    const { type } = req.body;
    const packet = generatePacket(type);
    packetHistory.push(packet);
    if (packetHistory.length > MAX_HISTORY) packetHistory.shift();
    
    const message = JSON.stringify({ type: "PACKET", data: packet });
    clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) client.send(message);
    });
    
    res.json({ success: true, packet });
  });

  app.get("/api/playbooks", (req, res) => {
    res.json([
      {
        id: "ddos-mitigation",
        title: "DDoS Mitigation Protocol",
        steps: [
          "Identify attack vector (UDP/TCP/ICMP flood)",
          "Enable rate limiting on edge routers",
          "Redirect traffic through scrubbing center",
          "Blacklist high-volume malicious source IPs",
          "Monitor latency and throughput recovery"
        ],
        severity: "High"
      },
      {
        id: "brute-force",
        title: "Brute Force Response",
        steps: [
          "Identify targeted accounts and services",
          "Enforce account lockout policies",
          "Enable multi-factor authentication (MFA)",
          "Analyze source IP for botnet signatures",
          "Reset credentials for compromised accounts"
        ],
        severity: "Medium"
      },
      {
        id: "sql-injection",
        title: "SQL Injection Remediation",
        steps: [
          "Isolate affected database server",
          "Review application logs for payload patterns",
          "Implement parameterized queries/prepared statements",
          "Update Web Application Firewall (WAF) rules",
          "Perform full security audit of data access layer"
        ],
        severity: "High"
      }
    ]);
  });

  app.get("/api/report", (req, res) => {
    const totalTraffic = packetHistory.reduce((acc, p) => acc + p.packetSize, 0);
    const attackCounts = packetHistory.filter(p => p.status === "Attack").length;
    const suspiciousIps = Array.from(new Set(packetHistory.filter(p => p.status !== "Normal").map(p => p.sourceIp)));
    const attackTypes = packetHistory.reduce((acc: any, p) => {
      if (p.attackType) acc[p.attackType] = (acc[p.attackType] || 0) + 1;
      return acc;
    }, {});

    res.json({
      date: new Date().toLocaleDateString(),
      summary: {
        totalPackets: packetHistory.length,
        totalTrafficBytes: totalTraffic,
        attacksDetected: attackCounts,
        suspiciousNodes: suspiciousIps.length,
        blockedNodes: blockedIps.length
      },
      threatDistribution: {
        low: packetHistory.filter(p => p.riskLevel === "Low").length,
        medium: packetHistory.filter(p => p.riskLevel === "Medium").length,
        high: packetHistory.filter(p => p.riskLevel === "High").length,
      },
      attackTypes,
      suspiciousIps: suspiciousIps.slice(0, 10)
    });
  });

  // WebSocket Handling
  wss.on("connection", (ws) => {
    clients.add(ws);
    // Send initial history
    ws.send(JSON.stringify({ type: "INIT", data: packetHistory }));
    
    ws.on("close", () => clients.delete(ws));
  });

  // Traffic Generation Loop
  setInterval(() => {
    const packet = generatePacket();
    packetHistory.push(packet);
    if (packetHistory.length > MAX_HISTORY) {
      packetHistory.shift();
    }
    
    // Update system health
    systemHealth = {
      cpu: Math.min(100, Math.max(5, systemHealth.cpu + (Math.random() * 10 - 5))),
      memory: Math.min(100, Math.max(20, systemHealth.memory + (Math.random() * 2 - 1))),
      storage: Math.min(100, systemHealth.storage + 0.001),
      uptime: Math.floor((Date.now() - startTime) / 1000),
      temp: Math.min(90, Math.max(35, systemHealth.temp + (Math.random() * 4 - 2)))
    };
    
    const message = JSON.stringify({ 
      type: "TICK", 
      packet, 
      health: systemHealth 
    });
    
    clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    });
  }, 1000);

  // Vite Integration
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, "dist")));
    app.get("*", (req, res) => {
      res.sendFile(path.join(__dirname, "dist", "index.html"));
    });
  }

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
