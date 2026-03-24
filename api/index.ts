import express from "express";
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
// Note: In serverless environments, this state is NOT persistent across requests.
const MAX_HISTORY = 100;
let packetHistory: Packet[] = [];
let blockedIps: BlockedIp[] = [];
let systemHealth = {
  cpu: 12,
  memory: 45,
  storage: 28,
  uptime: 0,
  temp: 42
};

// --- Traffic Simulation Logic ---
const IP_POOL = [
  "192.168.1.10", "192.168.1.15", "10.0.0.5", "172.16.0.2",
  "45.33.22.11", "185.12.34.56", "203.0.113.42", "8.8.8.8"
];

const ATTACK_TYPES = ["DDoS", "Port Scan", "Brute Force", "SQL Injection"];

const GEOLOCATIONS = [
  { country: "United States", city: "New York", isp: "Verizon", lat: 40.7128, lng: -74.0060 },
  { country: "Russia", city: "Moscow", isp: "Rostelecom", lat: 55.7558, lng: 37.6173 },
  { country: "China", city: "Beijing", isp: "China Telecom", lat: 39.9042, lng: 116.4074 }
];

function generatePacket(forceAttack?: string): Packet {
  const isAttack = forceAttack ? true : Math.random() < 0.08;
  const isSuspicious = !isAttack && Math.random() < 0.15;
  
  const protocol: "TCP" | "UDP" | "ICMP" = ["TCP", "UDP", "ICMP"][Math.floor(Math.random() * 3)] as any;
  const sourceIp = isAttack ? "45.33.22.11" : IP_POOL[Math.floor(Math.random() * IP_POOL.length)];
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
  } else if (isSuspicious) {
    status = "Suspicious";
    riskLevel = "Medium";
    confidence = 0.6 + Math.random() * 0.25;
  }

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
    isBlocked: false
  };
}

// Pre-populate some history for the demo
for (let i = 0; i < 50; i++) {
  packetHistory.push(generatePacket());
}

const app = express();
app.use(express.json());

// API Routes
app.get("/api/stats", (req, res) => {
  const total = packetHistory.length;
  const normal = packetHistory.filter(p => p.status === "Normal").length;
  const suspicious = packetHistory.filter(p => p.status === "Suspicious").length;
  const attacks = packetHistory.filter(p => p.status === "Attack").length;
  res.json({ total, normal, suspicious, attacks });
});

app.get("/api/history", (req, res) => {
  // Simulate some dynamic health data
  const health = {
    cpu: Math.min(100, Math.max(5, systemHealth.cpu + (Math.random() * 10 - 5))),
    memory: Math.min(100, Math.max(20, systemHealth.memory + (Math.random() * 2 - 1))),
    storage: systemHealth.storage,
    uptime: Math.floor(Date.now() / 1000) % 100000,
    temp: Math.min(90, Math.max(35, systemHealth.temp + (Math.random() * 4 - 2)))
  };
  
  // Add a new random packet to history on each poll to simulate activity
  if (packetHistory.length < MAX_HISTORY) {
    packetHistory.push(generatePacket());
  } else {
    packetHistory.shift();
    packetHistory.push(generatePacket());
  }

  res.json({ 
    packets: packetHistory,
    health: health
  });
});

app.get("/api/blocked", (req, res) => {
  res.json(blockedIps);
});

app.post("/api/block", (req, res) => {
  const { ip, reason } = req.body;
  if (!ip) return res.status(400).json({ error: "IP required" });
  blockedIps.push({ ip, timeBlocked: Date.now(), reason: reason || "Manual block", attempts: 1 });
  res.json({ success: true, blockedIps });
});

app.post("/api/unblock", (req, res) => {
  const { ip } = req.body;
  blockedIps = blockedIps.filter(b => b.ip !== ip);
  res.json({ success: true, blockedIps });
});

app.get("/api/ai-metrics", (req, res) => {
  res.json({ accuracy: 96.2, precision: 95.7, recall: 94.9, f1: 95.3 });
});

app.get("/api/threat-intel", (req, res) => {
  res.json([
    { id: 1, title: "New Mirai Variant Detected", severity: "High", time: "2h ago" },
    { id: 2, title: "Global Increase in SQL Injection", severity: "Medium", time: "5h ago" }
  ]);
});

app.post("/api/simulate-attack", (req, res) => {
  const { type } = req.body;
  const packet = generatePacket(type);
  packetHistory.push(packet);
  res.json({ success: true, packet });
});

app.get("/api/playbooks", (req, res) => {
  res.json([
    { id: "ddos-mitigation", title: "DDoS Mitigation Protocol", severity: "High", steps: ["Identify vector", "Rate limit"] }
  ]);
});

app.get("/api/report", (req, res) => {
  res.json({ date: new Date().toLocaleDateString(), summary: { totalPackets: packetHistory.length } });
});

// Export the app for Vercel
export default app;
