import React, { useState, useEffect, useMemo, useRef } from 'react';
import { 
  Shield, 
  Activity, 
  AlertTriangle, 
  Zap, 
  Globe, 
  Server, 
  Clock, 
  Database,
  ChevronRight,
  Search,
  Filter,
  Bell,
  Cpu,
  Terminal as TerminalIcon,
  Lock,
  Wifi,
  BarChart3,
  Layers,
  Settings,
  LogOut,
  Maximize2,
  Play,
  FileText,
  AlertCircle,
  MapPin,
  Target,
  Crosshair,
  MessageSquare,
  Send,
  BookOpen,
  HardDrive,
  Thermometer
} from 'lucide-react';
import { GoogleGenAI } from "@google/genai";
import { 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer, 
  PieChart, 
  Pie, 
  Cell,
  AreaChart,
  Area,
  BarChart,
  Bar
} from 'recharts';
import { motion, AnimatePresence } from 'motion/react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

// --- Utility ---
function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// --- Types ---
interface Packet {
  id: string;
  timestamp: number;
  sourceIp: string;
  destIp: string;
  protocol: 'TCP' | 'UDP' | 'ICMP';
  packetSize: number;
  duration: number;
  status: 'Normal' | 'Suspicious' | 'Attack';
  attackType?: string;
  riskLevel: 'Low' | 'Medium' | 'High';
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

interface AIMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  confusionMatrix: number[][];
}

interface ThreatIntel {
  id: number;
  title: string;
  severity: string;
  time: string;
}

interface Playbook {
  id: string;
  title: string;
  steps: string[];
  severity: string;
}

interface SystemHealth {
  cpu: number;
  memory: number;
  storage: number;
  uptime: number;
  temp: number;
}

// --- Components ---
const AI_MODEL = "gemini-3-flash-preview";

const CyberAssistant = ({ packets }: { packets: Packet[] }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState<{role: 'user' | 'ai', text: string}[]>([
    { role: 'ai', text: "Neural Link established. I am NetSentinel AI. How can I assist your security analysis today?" }
  ]);
  const [input, setInput] = useState("");
  const [isTyping, setIsTyping] = useState(false);
  const chatEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSend = async () => {
    if (!input.trim()) return;
    
    const userMsg = input;
    setInput("");
    setMessages(prev => [...prev, { role: 'user', text: userMsg }]);
    setIsTyping(true);

    try {
      const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY! });
      const context = `
        Current Security State:
        - Total Packets in buffer: ${packets.length}
        - Attacks detected: ${packets.filter(p => p.status === 'Attack').length}
        - Suspicious activity: ${packets.filter(p => p.status === 'Suspicious').length}
        - Recent attack types: ${packets.filter(p => p.attackType).map(p => p.attackType).join(', ')}
      `;

      const response = await ai.models.generateContent({
        model: AI_MODEL,
        contents: `You are a SOC (Security Operations Center) AI assistant. 
        Context: ${context}
        User Question: ${userMsg}`,
        config: {
          systemInstruction: "You are a professional cybersecurity analyst assistant. Be concise, technical, and helpful. Use markdown for lists or code snippets if needed."
        }
      });

      setMessages(prev => [...prev, { role: 'ai', text: response.text || "I encountered an error processing that request." }]);
    } catch (error) {
      setMessages(prev => [...prev, { role: 'ai', text: "Neural connection error. Please verify API configuration." }]);
    } finally {
      setIsTyping(false);
    }
  };

  return (
    <div className="fixed bottom-8 right-8 z-[100]">
      <AnimatePresence>
        {isOpen && (
          <motion.div 
            initial={{ opacity: 0, scale: 0.9, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.9, y: 20 }}
            className="w-96 h-[500px] bg-cyber-card border border-cyber-border rounded-2xl shadow-2xl flex flex-col overflow-hidden mb-4"
          >
            <div className="p-4 border-b border-cyber-border bg-cyber-sidebar flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-cyber-accent animate-pulse" />
                <span className="text-xs font-mono text-cyber-accent uppercase tracking-widest">NetSentinel AI</span>
              </div>
              <button onClick={() => setIsOpen(false)} className="text-cyber-text-secondary hover:text-cyber-text-primary">
                <Maximize2 size={16} />
              </button>
            </div>
            
            <div className="flex-1 overflow-y-auto p-4 space-y-4 font-mono text-xs">
              {messages.map((m, i) => (
                <div key={i} className={cn(
                  "p-3 rounded-xl max-w-[85%]",
                  m.role === 'ai' ? "bg-cyber-sidebar border border-cyber-border text-cyber-text-primary" : "bg-cyber-accent text-cyber-bg ml-auto"
                )}>
                  {m.text}
                </div>
              ))}
              {isTyping && (
                <div className="bg-cyber-sidebar border border-cyber-border p-3 rounded-xl w-12 flex gap-1">
                  <div className="w-1 h-1 bg-cyber-accent rounded-full animate-bounce" />
                  <div className="w-1 h-1 bg-cyber-accent rounded-full animate-bounce [animation-delay:0.2s]" />
                  <div className="w-1 h-1 bg-cyber-accent rounded-full animate-bounce [animation-delay:0.4s]" />
                </div>
              )}
              <div ref={chatEndRef} />
            </div>

            <div className="p-4 border-t border-cyber-border bg-cyber-sidebar/50">
              <div className="relative">
                <input 
                  type="text" 
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleSend()}
                  placeholder="Ask security assistant..."
                  className="w-full bg-cyber-bg border border-cyber-border rounded-xl px-4 py-2 text-xs text-cyber-text-primary outline-none focus:border-cyber-accent pr-10"
                />
                <button onClick={handleSend} className="absolute right-2 top-1/2 -translate-y-1/2 text-cyber-accent hover:text-cyber-accent/80">
                  <Send size={16} />
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <button 
        onClick={() => setIsOpen(!isOpen)}
        className="w-14 h-14 bg-cyber-accent rounded-2xl flex items-center justify-center text-cyber-bg shadow-lg shadow-cyber-accent/20 hover:scale-105 transition-transform"
      >
        <MessageSquare size={28} />
      </button>
    </div>
  );
};

const Terminal = () => {
  const [history, setHistory] = useState<string[]>([
    "NetSentinel OS v5.0.0 (Neural Link Active)",
    "Type 'help' for available commands.",
    ""
  ]);
  const [input, setInput] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo(0, scrollRef.current.scrollHeight);
  }, [history]);

  const handleCommand = (cmd: string) => {
    const c = cmd.toLowerCase().trim();
    let response = "";

    if (c === 'help') {
      response = "Available commands: help, status, scan, clear, whoami, ping [ip]";
    } else if (c === 'status') {
      response = "System: ONLINE | Firewall: ACTIVE | AI: NEURAL_READY";
    } else if (c === 'scan') {
      response = "Scanning local network... [192.168.1.0/24] Found 12 active nodes.";
    } else if (c === 'clear') {
      setHistory([]);
      return;
    } else if (c === 'whoami') {
      response = "root@netsentinel-soc";
    } else if (c.startsWith('ping')) {
      response = `PING ${c.split(' ')[1] || '8.8.8.8'} (56 bytes of data): 64 bytes from ... time=12.4ms`;
    } else {
      response = `Command not found: ${c}`;
    }

    setHistory(prev => [...prev, `> ${cmd}`, response, ""]);
  };

  return (
    <CyberCard title="Neural Terminal Emulator" icon={TerminalIcon} className="h-[600px] flex flex-col">
      <div ref={scrollRef} className="flex-1 overflow-y-auto font-mono text-xs text-cyber-accent space-y-1 mb-4">
        {history.map((line, i) => (
          <div key={i}>{line}</div>
        ))}
      </div>
      <div className="flex items-center gap-2 border-t border-cyber-border pt-4">
        <span className="text-cyber-accent font-mono text-xs">root@soc:~$</span>
        <input 
          type="text" 
          autoFocus
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              handleCommand(input);
              setInput("");
            }
          }}
          className="flex-1 bg-transparent outline-none font-mono text-xs text-cyber-text-primary"
        />
      </div>
    </CyberCard>
  );
};
const CyberCard = ({ children, className, title, icon: Icon, badge }: { 
  children: React.ReactNode; 
  className?: string; 
  title?: string;
  icon?: any;
  badge?: string;
  key?: any;
}) => (
  <motion.div 
    initial={{ opacity: 0, y: 20 }}
    animate={{ opacity: 1, y: 0 }}
    className={cn("glass-panel relative overflow-hidden group bg-cyber-card border-cyber-border shadow-[0_0_20px_rgba(0,229,255,0.05)]", className)}
  >
    <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-cyber-accent/30 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
    
    {(title || Icon) && (
      <div className="px-6 py-4 border-b border-cyber-border flex items-center justify-between bg-cyber-sidebar/50">
        <div className="flex items-center gap-3">
          {Icon && <Icon size={18} className="text-cyber-accent" />}
          <h3 className="text-xs font-mono uppercase tracking-[0.2em] text-cyber-text-secondary">{title}</h3>
        </div>
        {badge && (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyber-accent/10 text-cyber-accent border border-cyber-accent/20">
            {badge}
          </span>
        )}
      </div>
    )}
    <div className="p-6">
      {children}
    </div>
  </motion.div>
);

const StatWidget = ({ title, value, icon: Icon, color, trend, subValue }: { 
  title: string; 
  value: string | number; 
  icon: any; 
  color: string;
  trend?: string;
  subValue?: string;
}) => (
  <div className="relative group">
    <div className={cn("absolute inset-0 blur-2xl opacity-0 group-hover:opacity-10 transition-opacity duration-500", color)} />
    <div className="glass-panel p-6 relative z-10 bg-cyber-card border-cyber-border shadow-[0_0_20px_rgba(0,229,255,0.05)]">
      <div className="flex justify-between items-start mb-6">
        <div className={cn("p-3 rounded-xl bg-cyber-sidebar border border-cyber-border", color.replace('bg-', 'text-'))}>
          <Icon size={22} />
        </div>
        {trend && (
          <div className="flex flex-col items-end">
            <span className={cn(
              "text-[10px] font-mono px-2 py-1 rounded",
              trend.startsWith('+') ? "text-cyber-success bg-cyber-success/10" : "text-cyber-danger bg-cyber-danger/10"
            )}>
              {trend}
            </span>
          </div>
        )}
      </div>
      <div>
        <p className="text-cyber-text-secondary text-[10px] font-mono uppercase tracking-[0.2em] mb-2">{title}</p>
        <div className="flex items-baseline gap-2">
          <h3 className="text-3xl font-bold text-cyber-text-primary tracking-tight tracking-tight">{value}</h3>
          {subValue && <span className="text-xs text-cyber-text-secondary font-mono">{subValue}</span>}
        </div>
      </div>
    </div>
  </div>
);

const RiskBadge = ({ level }: { level: Packet['riskLevel'] }) => {
  const styles = {
    Low: "text-cyber-success bg-cyber-success/10 border-cyber-success/20",
    Medium: "text-cyber-warning bg-cyber-warning/10 border-cyber-warning/20",
    High: "text-cyber-danger bg-cyber-danger/10 border-cyber-danger/20"
  };
  return (
    <span className={cn("px-2 py-0.5 rounded text-[10px] font-mono border uppercase tracking-widest", styles[level])}>
      {level}
    </span>
  );
};

export default function App() {
  const [packets, setPackets] = useState<Packet[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [alerts, setAlerts] = useState<Packet[]>([]);
  const [blockedIps, setBlockedIps] = useState<BlockedIp[]>([]);
  const [activeTab, setActiveTab] = useState('overview');
  const [showReport, setShowReport] = useState(false);
  const [reportData, setReportData] = useState<any>(null);
  const [aiMetrics, setAiMetrics] = useState<AIMetrics | null>(null);
  const [threatIntel, setThreatIntel] = useState<ThreatIntel[]>([]);
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [systemHealth, setSystemHealth] = useState<SystemHealth>({
    cpu: 0, memory: 0, storage: 0, uptime: 0, temp: 0
  });
  const [selectedIp, setSelectedIp] = useState<BlockedIp | null>(null);
  const [settings, setSettings] = useState({
    captureInterface: 'eth0',
    packetLimit: 1000,
    monitoringMode: 'Active',
    aiModel: 'Random Forest',
    alerts: { email: true, dashboard: true, sms: false }
  });
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let pollInterval: NodeJS.Timeout;
    let ws: WebSocket | null = null;

    const startPolling = () => {
      pollInterval = setInterval(async () => {
        try {
          const res = await fetch('/api/history');
          const data = await res.json();
          if (data.packets) {
            setPackets(data.packets.slice(0, 200));
          } else {
            setPackets(data.slice(0, 200));
          }
          if (data.health) {
            setSystemHealth(data.health);
          }
          setIsConnected(true);
        } catch (err) {
          setIsConnected(false);
        }
      }, 3000);
    };

    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      ws = new WebSocket(`${protocol}//${window.location.host}`);

      ws.onopen = () => {
        setIsConnected(true);
        if (pollInterval) clearInterval(pollInterval);
      };
      ws.onclose = () => {
        setIsConnected(false);
        startPolling();
      };
      ws.onerror = () => {
        ws?.close();
      };
      ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        if (msg.type === 'INIT') {
          setPackets(msg.data);
        } else if (msg.type === 'TICK') {
          setPackets(prev => [msg.packet, ...prev].slice(0, 200));
          setSystemHealth(msg.health);
          if (msg.packet.status !== 'Normal') {
            setAlerts(prev => [msg.packet, ...prev].slice(0, 10));
          }
        }
      };
    } catch (e) {
      startPolling();
    }

    fetchBlocked();
    fetchAIMetrics();
    fetchThreatIntel();
    fetchPlaybooks();
    
    return () => {
      ws?.close();
      if (pollInterval) clearInterval(pollInterval);
    };
  }, []);

  const fetchPlaybooks = async () => {
    const res = await fetch('/api/playbooks');
    const data = await res.json();
    setPlaybooks(data);
  };

  const fetchBlocked = async () => {
    const res = await fetch('/api/blocked');
    const data = await res.json();
    setBlockedIps(data);
  };

  const fetchAIMetrics = async () => {
    const res = await fetch('/api/ai-metrics');
    const data = await res.json();
    setAiMetrics(data);
  };

  const fetchThreatIntel = async () => {
    const res = await fetch('/api/threat-intel');
    const data = await res.json();
    setThreatIntel(data);
  };

  const simulateAttack = async (type: string) => {
    await fetch('/api/simulate-attack', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type })
    });
  };

  const blockIp = async (ip: string, reason?: string) => {
    await fetch('/api/block', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, reason })
    });
    fetchBlocked();
  };

  const unblockIp = async (ip: string) => {
    await fetch('/api/unblock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip })
    });
    fetchBlocked();
  };

  const generateReport = async () => {
    const res = await fetch('/api/report');
    const data = await res.json();
    setReportData(data);
    setShowReport(true);
  };

  // --- Derived Stats ---
  const stats = useMemo(() => {
    const total = packets.length;
    const attacks = packets.filter(p => p.status === 'Attack').length;
    const suspicious = packets.filter(p => p.status === 'Suspicious').length;
    const normal = total - attacks - suspicious;
    
    const protocolData = [
      { name: 'TCP', value: packets.filter(p => p.protocol === 'TCP').length },
      { name: 'UDP', value: packets.filter(p => p.protocol === 'UDP').length },
      { name: 'ICMP', value: packets.filter(p => p.protocol === 'ICMP').length },
    ];

    // Attack Timeline Data
    const attackTimeline = packets.reduce((acc: any[], p) => {
      if (p.status === 'Attack') {
        const time = new Date(p.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const existing = acc.find(a => a.time === time);
        if (existing) existing.count++;
        else acc.push({ time, count: 1 });
      }
      return acc;
    }, []).slice(-15);

    const trafficOverTime = packets.slice(0, 30).reverse().map(p => ({
      time: new Date(p.timestamp).toLocaleTimeString([], { hour12: false, minute: '2-digit', second: '2-digit' }),
      size: p.packetSize,
      incoming: p.destIp === '192.168.1.1' ? p.packetSize : 0,
      outgoing: p.destIp !== '192.168.1.1' ? p.packetSize : 0,
      threat: p.status === 'Attack' ? 1000 : p.status === 'Suspicious' ? 500 : 0
    }));

    const topIps = Array.from(
      packets.reduce((acc, p) => {
        acc.set(p.sourceIp, (acc.get(p.sourceIp) || 0) + 1);
        return acc;
      }, new Map<string, number>())
    ).sort((a, b) => b[1] - a[1]).slice(0, 6);

    const geoData = packets
      .filter(p => p.location)
      .map(p => ({
        ip: p.sourceIp,
        country: p.location?.country,
        city: p.location?.city,
        isp: p.location?.isp,
        timestamp: p.timestamp,
        lat: p.location?.lat,
        lng: p.location?.lng
      }))
      .slice(0, 10);

    const countryStats = packets.reduce((acc: any, p) => {
      if (p.location) {
        acc[p.location.country] = (acc[p.location.country] || 0) + 1;
      }
      return acc;
    }, {});

    const heatmapData = packets.reduce((acc: any[], p) => {
      const hour = new Date(p.timestamp).getHours();
      const existing = acc.find(a => a.hour === hour);
      if (existing) {
        existing.total++;
        if (p.status === 'Attack') existing.attacks++;
      } else {
        acc.push({ hour, total: 1, attacks: p.status === 'Attack' ? 1 : 0 });
      }
      return acc;
    }, []).sort((a, b) => a.hour - b.hour);

    return { total, attacks, suspicious, normal, protocolData, trafficOverTime, topIps, attackTimeline, geoData, countryStats, heatmapData };
  }, [packets]);

  return (
    <div className="min-h-screen cyber-grid relative">
      <div className="scanline" />
      
      {/* Navigation Rail */}
      <nav className="fixed left-0 top-0 bottom-0 w-20 bg-cyber-sidebar border-r border-cyber-border flex flex-col items-center py-8 gap-10 z-50">
        <div className="relative group">
          <div className="absolute -inset-2 bg-cyber-accent blur-lg opacity-20 group-hover:opacity-40 transition-opacity" />
          <div className="w-12 h-12 bg-cyber-accent rounded-2xl flex items-center justify-center relative z-10 shadow-lg shadow-cyber-accent/20">
            <Shield size={28} className="text-cyber-bg" />
          </div>
        </div>

        <div className="flex flex-col gap-8 text-cyber-text-secondary">
          {[
            { id: 'overview', icon: BarChart3 },
            { id: 'network', icon: Activity },
            { id: 'security', icon: Lock },
            { id: 'nodes', icon: Globe },
            { id: 'blacklist', icon: Shield },
            { id: 'terminal', icon: TerminalIcon },
            { id: 'playbooks', icon: BookOpen },
            { id: 'settings', icon: Settings }
          ].map((item) => (
            <button 
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={cn(
                "p-3 rounded-xl transition-all relative group",
                activeTab === item.id ? "text-cyber-accent bg-cyber-accent/10" : "hover:text-cyber-text-primary hover:bg-cyber-sidebar-hover"
              )}
            >
              <item.icon size={22} />
              {activeTab === item.id && (
                <motion.div layoutId="nav-indicator" className="absolute -left-8 w-1 h-8 bg-cyber-accent rounded-r-full" />
              )}
            </button>
          ))}
        </div>

        <div className="mt-auto flex flex-col gap-6 items-center">
          <div className="relative">
            <div className={cn(
              "w-2.5 h-2.5 rounded-full", 
              isConnected ? "bg-cyber-success shadow-[0_0_12px_rgba(34,197,94,0.6)]" : "bg-cyber-danger"
            )} />
          </div>
          <button className="text-cyber-text-disabled hover:text-cyber-danger transition-colors">
            <LogOut size={22} />
          </button>
        </div>
      </nav>

      {/* Main Content Area */}
      <main className="pl-20 min-h-screen">
        <div className="max-w-[1800px] mx-auto p-8 lg:p-12">
          
          {/* Top Header Section */}
          <header className="flex flex-col lg:flex-row lg:items-center justify-between gap-8 mb-12">
            <div>
              <div className="flex items-center gap-3 text-cyber-accent mb-3">
                <div className="w-2 h-2 rounded-full bg-cyber-accent animate-pulse shadow-[0_0_8px_currentColor]" />
                <span className="text-[10px] font-mono uppercase tracking-[0.4em] font-bold">Neural Link Active • v5.0.0</span>
              </div>
              <div className="flex flex-col gap-1">
                <h1 className="text-4xl lg:text-5xl font-bold tracking-tighter text-cyber-text-primary flex items-center gap-4">
                  NET<span className="text-cyber-accent">SENTINEL</span> IDS
                  <span className="text-xs font-mono bg-cyber-sidebar border border-cyber-border px-3 py-1 rounded-full text-cyber-text-secondary tracking-widest">ENTERPRISE</span>
                </h1>
                <p className="text-cyber-text-secondary text-sm font-mono tracking-wider">
                  AI Network Intrusion Detection & Traffic Monitoring System
                </p>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <button 
                onClick={generateReport}
                className="bg-cyber-accent hover:bg-cyber-accent/80 text-cyber-bg px-6 py-3 rounded-xl text-xs font-bold uppercase tracking-widest transition-all flex items-center gap-2"
              >
                <Database size={16} />
                Generate Security Report
              </button>
              
              <button className="glass-panel p-3 hover:bg-cyber-sidebar-hover transition-colors">
                <Maximize2 size={20} className="text-cyber-text-secondary" />
              </button>
            </div>
          </header>

          {activeTab === 'overview' && (
            <>
              {/* Stats Overview */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
                <StatWidget title="Total Throughput" value={stats.total} subValue="pkts" icon={Activity} color="bg-cyber-accent" trend="+14.2%" />
                <StatWidget title="Secure Traffic" value={stats.normal} subValue="pkts" icon={Shield} color="bg-cyber-success" trend="+2.1%" />
                <StatWidget title="Anomalies" value={stats.suspicious} subValue="pkts" icon={AlertTriangle} color="bg-cyber-warning" trend="-5.4%" />
                <StatWidget title="Threats Neutralized" value={stats.attacks} subValue="pkts" icon={Zap} color="bg-cyber-danger" trend="CRITICAL" />
              </div>

              {/* System Health Overview */}
              <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-6 mb-12">
                <div className="glass-panel p-4 bg-cyber-card border-cyber-border flex items-center gap-4">
                  <div className="p-2 rounded-lg bg-cyber-accent/10 text-cyber-accent"><Cpu size={18} /></div>
                  <div>
                    <p className="text-[10px] font-mono text-cyber-text-secondary uppercase">CPU Load</p>
                    <p className="text-sm font-bold text-cyber-text-primary">{systemHealth.cpu.toFixed(1)}%</p>
                  </div>
                </div>
                <div className="glass-panel p-4 bg-cyber-card border-cyber-border flex items-center gap-4">
                  <div className="p-2 rounded-lg bg-cyber-success/10 text-cyber-success"><HardDrive size={18} /></div>
                  <div>
                    <p className="text-[10px] font-mono text-cyber-text-secondary uppercase">Memory</p>
                    <p className="text-sm font-bold text-cyber-text-primary">{systemHealth.memory.toFixed(1)}%</p>
                  </div>
                </div>
                <div className="glass-panel p-4 bg-cyber-card border-cyber-border flex items-center gap-4">
                  <div className="p-2 rounded-lg bg-cyber-warning/10 text-cyber-warning"><Layers size={18} /></div>
                  <div>
                    <p className="text-[10px] font-mono text-cyber-text-secondary uppercase">Storage</p>
                    <p className="text-sm font-bold text-cyber-text-primary">{systemHealth.storage.toFixed(2)}%</p>
                  </div>
                </div>
                <div className="glass-panel p-4 bg-cyber-card border-cyber-border flex items-center gap-4">
                  <div className="p-2 rounded-lg bg-cyber-danger/10 text-cyber-danger"><Thermometer size={18} /></div>
                  <div>
                    <p className="text-[10px] font-mono text-cyber-text-secondary uppercase">Temp</p>
                    <p className="text-sm font-bold text-cyber-text-primary">{systemHealth.temp.toFixed(1)}°C</p>
                  </div>
                </div>
                <div className="glass-panel p-4 bg-cyber-card border-cyber-border flex items-center gap-4">
                  <div className="p-2 rounded-lg bg-cyber-accent/10 text-cyber-accent"><Clock size={18} /></div>
                  <div>
                    <p className="text-[10px] font-mono text-cyber-text-secondary uppercase">Uptime</p>
                    <p className="text-sm font-bold text-cyber-text-primary">{Math.floor(systemHealth.uptime / 3600)}h {Math.floor((systemHealth.uptime % 3600) / 60)}m</p>
                  </div>
                </div>
              </div>

              {/* Main Dashboard Grid */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 mb-12">
                
                {/* Traffic Analysis Chart */}
                <CyberCard 
                  className="lg:col-span-8" 
                  title="Neural Traffic Analysis" 
                  icon={BarChart3}
                  badge="Live Stream"
                >
                  <div className="h-[400px] w-full mt-4">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={stats.trafficOverTime}>
                        <defs>
                          <linearGradient id="cyberGradient" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#00E5FF" stopOpacity={0.2}/>
                            <stop offset="95%" stopColor="#00E5FF" stopOpacity={0}/>
                          </linearGradient>
                          <linearGradient id="incomingGradient" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#22C55E" stopOpacity={0.2}/>
                            <stop offset="95%" stopColor="#22C55E" stopOpacity={0}/>
                          </linearGradient>
                          <linearGradient id="outgoingGradient" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#F59E0B" stopOpacity={0.2}/>
                            <stop offset="95%" stopColor="#F59E0B" stopOpacity={0}/>
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" vertical={false} />
                        <XAxis 
                          dataKey="time" 
                          stroke="rgba(255,255,255,0.3)" 
                          fontSize={10} 
                          tickLine={false} 
                          axisLine={false}
                          dy={10}
                        />
                        <YAxis 
                          stroke="rgba(255,255,255,0.3)" 
                          fontSize={10} 
                          tickLine={false} 
                          axisLine={false}
                          tickFormatter={(val) => `${val}B`}
                        />
                        <Tooltip 
                          contentStyle={{ 
                            backgroundColor: '#111827', 
                            border: '1px solid #374151', 
                            borderRadius: '12px',
                            backdropFilter: 'blur(10px)',
                            boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.5)'
                          }}
                          itemStyle={{ fontSize: '12px', fontFamily: 'JetBrains Mono' }}
                        />
                        <Area 
                          type="monotone" 
                          dataKey="incoming" 
                          stroke="#22C55E" 
                          strokeWidth={2}
                          fillOpacity={1} 
                          fill="url(#incomingGradient)" 
                          name="Incoming"
                        />
                        <Area 
                          type="monotone" 
                          dataKey="outgoing" 
                          stroke="#F59E0B" 
                          strokeWidth={2}
                          fillOpacity={1} 
                          fill="url(#outgoingGradient)" 
                          name="Outgoing"
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </CyberCard>

                {/* Threat Intelligence Feed */}
                <CyberCard 
                  className="lg:col-span-4" 
                  title="Threat Intelligence" 
                  icon={Bell}
                  badge="Global Feed"
                >
                  <div className="space-y-4 mt-4">
                    {threatIntel.map((intel) => (
                      <div key={intel.id} className="p-4 rounded-xl bg-cyber-sidebar border border-cyber-border hover:bg-cyber-sidebar-hover transition-all cursor-pointer group">
                        <div className="flex justify-between items-start mb-2">
                          <h4 className="text-xs font-bold text-cyber-text-primary group-hover:text-cyber-accent transition-colors">{intel.title}</h4>
                          <span className={cn(
                            "text-[8px] font-mono px-1.5 py-0.5 rounded border",
                            intel.severity === 'Critical' ? "text-cyber-danger border-cyber-danger/30 bg-cyber-danger/10" :
                            intel.severity === 'High' ? "text-cyber-warning border-cyber-warning/30 bg-cyber-warning/10" :
                            "text-cyber-success border-cyber-success/30 bg-cyber-success/10"
                          )}>
                            {intel.severity}
                          </span>
                        </div>
                        <div className="flex justify-between items-center text-[10px] font-mono text-cyber-text-secondary">
                          <span>Source: Global Intel</span>
                          <span>{intel.time}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </CyberCard>
              </div>

              {/* Second Row: Timeline & Alerts */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 mb-12">
                <CyberCard 
                  className="lg:col-span-8" 
                  title="Live Threat Alerts" 
                  icon={AlertCircle}
                  badge="Real-time"
                >
                  <div className="space-y-4 mt-4">
                    {alerts.length === 0 ? (
                      <div className="py-20 text-center text-cyber-text-disabled font-mono text-xs">No active threats detected</div>
                    ) : (
                      alerts.map((alert) => (
                        <motion.div 
                          key={alert.id}
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          className={cn(
                            "flex items-center gap-6 p-4 rounded-2xl border transition-all",
                            alert.riskLevel === 'High' ? "bg-cyber-danger/5 border-cyber-danger/20" : "bg-cyber-warning/5 border-cyber-warning/20"
                          )}
                        >
                          <div className={cn(
                            "w-12 h-12 rounded-xl flex items-center justify-center shrink-0",
                            alert.riskLevel === 'High' ? "bg-cyber-danger/20 text-cyber-danger" : "bg-cyber-warning/20 text-cyber-warning"
                          )}>
                            <Zap size={24} />
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex justify-between items-center mb-1">
                              <span className="text-sm font-bold text-cyber-text-primary uppercase tracking-tight">⚠ {alert.riskLevel} THREAT DETECTED</span>
                              <span className="text-[10px] font-mono text-cyber-text-secondary">{new Date(alert.timestamp).toLocaleTimeString()}</span>
                            </div>
                            <div className="grid grid-cols-3 gap-4 text-[10px] font-mono">
                              <div><span className="text-cyber-text-secondary">Source IP:</span> <span className="text-cyber-accent">{alert.sourceIp}</span></div>
                              <div><span className="text-cyber-text-secondary">Attack Type:</span> <span className="text-cyber-text-primary">{alert.attackType}</span></div>
                              <div><span className="text-cyber-text-secondary">Confidence:</span> <span className="text-cyber-success">{(alert.confidence! * 100).toFixed(1)}%</span></div>
                            </div>
                          </div>
                          <button 
                            onClick={() => blockIp(alert.sourceIp)}
                            className="px-4 py-2 rounded-lg bg-cyber-danger text-white text-[10px] font-bold uppercase tracking-widest hover:bg-cyber-danger/80 transition-all"
                          >
                            Block IP
                          </button>
                        </motion.div>
                      ))
                    )}
                  </div>
                </CyberCard>

                <CyberCard 
                  className="lg:col-span-4" 
                  title="Attack Timeline" 
                  icon={Clock}
                >
                  <div className="h-[300px] w-full mt-4">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={stats.attackTimeline}>
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" vertical={false} />
                        <XAxis dataKey="time" stroke="rgba(255,255,255,0.3)" fontSize={10} tickLine={false} axisLine={false} />
                        <YAxis stroke="rgba(255,255,255,0.3)" fontSize={10} tickLine={false} axisLine={false} />
                        <Tooltip contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', borderRadius: '12px' }} />
                        <Bar dataKey="count" fill="#EF4444" radius={[4, 4, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </CyberCard>
              </div>
            </>
          )}

          {activeTab === 'network' && (
            <div className="space-y-8">
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                <CyberCard className="lg:col-span-8" title="Live Packet Monitor" icon={Activity} badge="Real-time Stream">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-[10px] font-mono">
                      <thead className="bg-cyber-sidebar text-cyber-text-secondary uppercase">
                        <tr>
                          <th className="px-6 py-3">Time</th>
                          <th className="px-6 py-3">Source IP</th>
                          <th className="px-6 py-3">Destination</th>
                          <th className="px-6 py-3">Protocol</th>
                          <th className="px-6 py-3">Size</th>
                          <th className="px-6 py-3">Status</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-cyber-border">
                        {packets.slice(0, 15).map((p) => (
                          <tr key={p.id} className="hover:bg-cyber-sidebar-hover transition-colors">
                            <td className="px-6 py-3 text-cyber-text-secondary">{new Date(p.timestamp).toLocaleTimeString()}</td>
                            <td className="px-6 py-3 text-cyber-accent">{p.sourceIp}</td>
                            <td className="px-6 py-3 text-cyber-text-secondary">{p.destIp}</td>
                            <td className="px-6 py-3"><span className="px-1.5 py-0.5 rounded bg-cyber-sidebar border border-cyber-border">{p.protocol}</span></td>
                            <td className="px-6 py-3 text-cyber-text-secondary">{p.packetSize}B</td>
                            <td className="px-6 py-3">
                              <span className={cn(
                                "px-1.5 py-0.5 rounded border",
                                p.status === 'Attack' ? "text-cyber-danger border-cyber-danger/30 bg-cyber-danger/10" :
                                p.status === 'Suspicious' ? "text-cyber-warning border-cyber-warning/30 bg-cyber-warning/10" :
                                "text-cyber-success border-cyber-success/30 bg-cyber-success/10"
                              )}>
                                {p.status}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </CyberCard>

                <div className="lg:col-span-4 space-y-8">
                  <CyberCard title="Protocol Distribution" icon={PieChart}>
                    <div className="h-[250px] w-full">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={stats.protocolData}
                            cx="50%"
                            cy="50%"
                            innerRadius={60}
                            outerRadius={80}
                            paddingAngle={5}
                            dataKey="value"
                          >
                            {stats.protocolData.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={['#3b82f6', '#10b981', '#f97316'][index % 3]} />
                            ))}
                          </Pie>
                          <Tooltip 
                            contentStyle={{ 
                              backgroundColor: '#111827', 
                              border: '1px solid #374151', 
                              borderRadius: '12px',
                              backdropFilter: 'blur(10px)',
                              boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.5)'
                            }}
                            itemStyle={{ fontSize: '12px', fontFamily: 'JetBrains Mono' }}
                          />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                    <div className="flex justify-center gap-6 mt-4">
                      {stats.protocolData.map((p, i) => (
                        <div key={p.name} className="flex items-center gap-2">
                          <div className="w-2 h-2 rounded-full" style={{ backgroundColor: ['#3b82f6', '#10b981', '#f97316'][i % 3] }} />
                          <span className="text-[10px] font-mono text-cyber-text-secondary">{p.name}</span>
                        </div>
                      ))}
                    </div>
                  </CyberCard>

                  <CyberCard title="Top Talkers" icon={Target}>
                    <div className="space-y-4">
                      {stats.topIps.map(([ip, count], i) => (
                        <div key={ip} className="flex items-center justify-between p-3 rounded-xl bg-cyber-sidebar border border-cyber-border">
                          <div className="flex items-center gap-3">
                            <span className="text-[10px] font-mono text-cyber-text-secondary">0{i+1}</span>
                            <span className="text-xs font-bold text-cyber-text-primary">{ip}</span>
                          </div>
                          <span className="text-[10px] font-mono text-cyber-accent">{count} pkts</span>
                        </div>
                      ))}
                    </div>
                  </CyberCard>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'security' && (
            <div className="space-y-8">
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                <div className="lg:col-span-8 space-y-8">
                  <CyberCard title="AI Intrusion Detection" icon={Cpu} badge="Neural Model v2.4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                      <div className="space-y-6">
                        <div className="p-6 rounded-2xl bg-cyber-sidebar border border-cyber-border">
                          <h4 className="text-xs font-mono text-cyber-text-secondary uppercase tracking-widest mb-4">Latest Classification</h4>
                          {alerts[0] ? (
                            <div className="space-y-4">
                              <div className="flex justify-between items-center">
                                <span className="text-sm font-bold text-cyber-text-primary">Detected Attack:</span>
                                <span className="text-sm font-bold text-cyber-danger">{alerts[0].attackType}</span>
                              </div>
                              <div className="flex justify-between items-center">
                                <span className="text-xs text-cyber-text-secondary">Confidence:</span>
                                <span className="text-xs font-mono text-cyber-success">{(alerts[0].confidence! * 100).toFixed(2)}%</span>
                              </div>
                              <div className="flex justify-between items-center">
                                <span className="text-xs text-cyber-text-secondary">Source IP:</span>
                                <span className="text-xs font-mono text-cyber-accent">{alerts[0].sourceIp}</span>
                              </div>
                            </div>
                          ) : (
                            <p className="text-xs text-cyber-text-disabled italic">Waiting for suspicious activity...</p>
                          )}
                        </div>

                        <div className="p-6 rounded-2xl bg-cyber-sidebar border border-cyber-border">
                          <h4 className="text-xs font-mono text-cyber-text-secondary uppercase tracking-widest mb-4">AI Model Performance</h4>
                          <div className="grid grid-cols-2 gap-4">
                            {[
                              { label: 'Accuracy', value: aiMetrics?.accuracy },
                              { label: 'Precision', value: aiMetrics?.precision },
                              { label: 'Recall', value: aiMetrics?.recall },
                              { label: 'F1 Score', value: aiMetrics?.f1 }
                            ].map((m) => (
                              <div key={m.label} className="p-3 rounded-xl bg-cyber-card border border-cyber-border">
                                <p className="text-[10px] text-cyber-text-secondary mb-1">{m.label}</p>
                                <p className="text-lg font-bold text-cyber-accent">{m.value}%</p>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>

                      <div className="p-6 rounded-2xl bg-cyber-sidebar border border-cyber-border">
                        <h4 className="text-xs font-mono text-cyber-text-secondary uppercase tracking-widest mb-4">Confusion Matrix</h4>
                        <div className="grid grid-cols-4 gap-2">
                          {aiMetrics?.confusionMatrix.flat().map((val, i) => (
                            <div key={i} className={cn(
                              "aspect-square flex items-center justify-center rounded-lg text-[10px] font-mono",
                              i % 5 === 0 ? "bg-cyber-success/20 text-cyber-success border border-cyber-success/30" : "bg-cyber-card text-cyber-text-disabled border border-cyber-border"
                            )}>
                              {val}
                            </div>
                          ))}
                        </div>
                        <div className="mt-4 flex justify-between text-[8px] font-mono text-cyber-text-secondary uppercase">
                          <span>Normal</span>
                          <span>DoS</span>
                          <span>Probe</span>
                          <span>Scan</span>
                        </div>
                      </div>
                    </div>
                  </CyberCard>

                  <CyberCard title="Attack Replay Simulation" icon={Play} badge="Demo Mode">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      {['DDoS', 'Port Scan', 'Brute Force', 'SQL Injection'].map((type) => (
                        <button 
                          key={type}
                          onClick={() => simulateAttack(type)}
                          className="p-4 rounded-xl bg-cyber-sidebar border border-cyber-border hover:bg-cyber-sidebar-hover hover:border-cyber-accent transition-all group"
                        >
                          <Play size={16} className="text-cyber-accent mb-2 group-hover:scale-110 transition-transform" />
                          <p className="text-[10px] font-mono text-cyber-text-primary uppercase tracking-widest">Simulate {type}</p>
                        </button>
                      ))}
                    </div>
                  </CyberCard>
                </div>

                <div className="lg:col-span-4 space-y-8">
                  <CyberCard title="Threat Heatmap" icon={Layers}>
                    <div className="h-[300px] w-full mt-4">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={stats.heatmapData}>
                          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" vertical={false} />
                          <XAxis dataKey="hour" stroke="rgba(255,255,255,0.3)" fontSize={10} tickLine={false} axisLine={false} tickFormatter={(h) => `${h}h`} />
                          <YAxis stroke="rgba(255,255,255,0.3)" fontSize={10} tickLine={false} axisLine={false} />
                          <Tooltip contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', borderRadius: '12px' }} />
                          <Bar dataKey="attacks" fill="#F59E0B" radius={[4, 4, 0, 0]} />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                    <p className="text-[10px] font-mono text-cyber-text-secondary text-center mt-4 uppercase tracking-widest">Attack Intensity by Hour</p>
                  </CyberCard>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'nodes' && (
            <div className="space-y-8">
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                <CyberCard className="lg:col-span-8" title="Attack Origin Map" icon={Globe} badge="Global Tracking">
                  <div className="aspect-video w-full bg-cyber-bg rounded-2xl border border-cyber-border relative overflow-hidden flex items-center justify-center">
                    <div className="absolute inset-0 opacity-10 pointer-events-none">
                      <div className="w-full h-full cyber-grid" />
                    </div>
                    <div className="relative z-10 text-center">
                      <Globe size={64} className="text-cyber-accent mx-auto mb-4 animate-pulse" />
                      <p className="text-xs font-mono text-cyber-text-secondary uppercase tracking-[0.3em]">Neural Map Interface Active</p>
                    </div>
                    {stats.geoData.map((geo, i) => (
                      <motion.div 
                        key={i}
                        initial={{ scale: 0 }}
                        animate={{ scale: 1 }}
                        className="absolute w-3 h-3 bg-cyber-danger rounded-full shadow-[0_0_12px_#ef4444]"
                        style={{ 
                          left: `${((geo.lng! + 180) / 360) * 100}%`, 
                          top: `${((90 - geo.lat!) / 180) * 100}%` 
                        }}
                      >
                        <div className="absolute inset-0 animate-ping bg-cyber-danger rounded-full opacity-75" />
                      </motion.div>
                    ))}
                  </div>
                </CyberCard>

                <CyberCard className="lg:col-span-4" title="Regional Statistics" icon={MapPin}>
                  <div className="space-y-4">
                    {Object.entries(stats.countryStats).map(([country, count]: any) => (
                      <div key={country} className="flex items-center justify-between p-4 rounded-xl bg-cyber-sidebar border border-cyber-border">
                        <div className="flex items-center gap-3">
                          <MapPin size={14} className="text-cyber-accent" />
                          <span className="text-xs font-bold text-cyber-text-primary">{country}</span>
                        </div>
                        <span className="text-xs font-mono text-cyber-danger">{count} Attacks</span>
                      </div>
                    ))}
                  </div>
                </CyberCard>
              </div>
            </div>
          )}

          {activeTab === 'terminal' && (
            <div className="max-w-4xl mx-auto">
              <Terminal />
            </div>
          )}

          {activeTab === 'playbooks' && (
            <div className="space-y-8">
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                {playbooks.map((playbook) => (
                  <CyberCard key={playbook.id} title={playbook.title} icon={BookOpen} badge={playbook.severity}>
                    <div className="space-y-4">
                      {playbook.steps.map((step, i) => (
                        <div key={i} className="flex gap-3 items-start p-3 rounded-xl bg-cyber-sidebar border border-cyber-border">
                          <span className="text-[10px] font-mono text-cyber-accent">0{i+1}</span>
                          <p className="text-xs text-cyber-text-secondary">{step}</p>
                        </div>
                      ))}
                      <button className="w-full py-3 rounded-xl bg-cyber-accent/10 text-cyber-accent border border-cyber-accent/20 text-[10px] font-bold uppercase tracking-widest hover:bg-cyber-accent/20 transition-all">
                        Initiate Response
                      </button>
                    </div>
                  </CyberCard>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'settings' && (
            <div className="max-w-4xl mx-auto space-y-8">
              <CyberCard title="System Configuration" icon={Settings}>
                <div className="space-y-8">
                  <section>
                    <h4 className="text-xs font-mono text-cyber-accent uppercase tracking-widest mb-6 flex items-center gap-2">
                      <Wifi size={14} /> Traffic Capture Settings
                    </h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div className="space-y-2">
                        <label className="text-[10px] font-mono text-cyber-text-secondary uppercase">Capture Interface</label>
                        <select 
                          value={settings.captureInterface}
                          onChange={(e) => setSettings({...settings, captureInterface: e.target.value})}
                          className="w-full bg-cyber-sidebar border border-cyber-border rounded-xl px-4 py-3 text-sm text-cyber-text-primary focus:border-cyber-accent outline-none transition-all"
                        >
                          <option value="eth0">eth0 (Ethernet)</option>
                          <option value="wlan0">wlan0 (Wireless)</option>
                          <option value="lo">lo (Loopback)</option>
                        </select>
                      </div>
                      <div className="space-y-2">
                        <label className="text-[10px] font-mono text-cyber-text-secondary uppercase">Packet Limit</label>
                        <input 
                          type="number" 
                          value={settings.packetLimit}
                          onChange={(e) => setSettings({...settings, packetLimit: parseInt(e.target.value)})}
                          className="w-full bg-cyber-sidebar border border-cyber-border rounded-xl px-4 py-3 text-sm text-cyber-text-primary focus:border-cyber-accent outline-none transition-all"
                        />
                      </div>
                    </div>
                  </section>

                  <section>
                    <h4 className="text-xs font-mono text-cyber-accent uppercase tracking-widest mb-6 flex items-center gap-2">
                      <Cpu size={14} /> AI Model Settings
                    </h4>
                    <div className="space-y-2">
                      <label className="text-[10px] font-mono text-cyber-text-secondary uppercase">Detection Model</label>
                      <div className="grid grid-cols-3 gap-4">
                        {['Random Forest', 'Decision Tree', 'SVM'].map((model) => (
                          <button 
                            key={model}
                            onClick={() => setSettings({...settings, aiModel: model})}
                            className={cn(
                              "px-4 py-3 rounded-xl border text-xs font-mono transition-all",
                              settings.aiModel === model ? "bg-cyber-accent text-cyber-bg border-cyber-accent" : "bg-cyber-sidebar border-cyber-border text-cyber-text-secondary hover:bg-cyber-sidebar-hover"
                            )}
                          >
                            {model}
                          </button>
                        ))}
                      </div>
                    </div>
                  </section>

                  <section>
                    <h4 className="text-xs font-mono text-cyber-accent uppercase tracking-widest mb-6 flex items-center gap-2">
                      <Bell size={14} /> Alert Notifications
                    </h4>
                    <div className="space-y-4">
                      {Object.entries(settings.alerts).map(([key, val]) => (
                        <div key={key} className="flex items-center justify-between p-4 rounded-xl bg-cyber-sidebar border border-cyber-border">
                          <span className="text-xs font-bold text-cyber-text-primary uppercase tracking-widest">{key} Alerts</span>
                          <button 
                            onClick={() => setSettings({...settings, alerts: {...settings.alerts, [key]: !val}})}
                            className={cn(
                              "w-12 h-6 rounded-full relative transition-all",
                              val ? "bg-cyber-accent" : "bg-cyber-text-disabled"
                            )}
                          >
                            <div className={cn(
                              "absolute top-1 w-4 h-4 rounded-full bg-white transition-all shadow-sm",
                              val ? "right-1" : "left-1"
                            )} />
                          </button>
                        </div>
                      ))}
                    </div>
                  </section>
                </div>
              </CyberCard>
            </div>
          )}

          {activeTab === 'blacklist' && (
            <div className="space-y-8">
              <CyberCard title="IP Blacklist Management" icon={Shield} badge={`${blockedIps.length} Nodes`}>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-cyber-sidebar text-cyber-text-secondary uppercase tracking-tighter">
                      <tr>
                        <th className="px-8 py-4 font-medium">IP Address</th>
                        <th className="px-8 py-4 font-medium">Origin</th>
                        <th className="px-8 py-4 font-medium">Attempts</th>
                        <th className="px-8 py-4 font-medium">Reason</th>
                        <th className="px-8 py-4 text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-cyber-border">
                      {blockedIps.length === 0 ? (
                        <tr>
                          <td colSpan={5} className="px-8 py-20 text-center text-cyber-text-disabled">No IPs currently blacklisted</td>
                        </tr>
                      ) : (
                        blockedIps.map((b) => (
                          <tr key={b.ip} className="hover:bg-cyber-sidebar-hover transition-colors cursor-pointer group" onClick={() => setSelectedIp(b)}>
                            <td className="px-8 py-4 font-medium text-cyber-danger">{b.ip}</td>
                            <td className="px-8 py-4 text-cyber-text-secondary">{b.country || 'Unknown'}</td>
                            <td className="px-8 py-4 text-cyber-warning font-bold">{b.attempts}</td>
                            <td className="px-8 py-4 text-cyber-text-secondary italic truncate max-w-[200px]">"{b.reason}"</td>
                            <td className="px-8 py-4 text-right">
                              <button 
                                onClick={(e) => { e.stopPropagation(); unblockIp(b.ip); }}
                                className="text-cyber-success hover:bg-cyber-success/10 px-3 py-1 rounded border border-cyber-success/20 transition-all font-bold"
                              >
                                UNBLOCK
                              </button>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </CyberCard>

              <AnimatePresence>
                {selectedIp && (
                  <motion.div 
                    initial={{ opacity: 0, x: 100 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: 100 }}
                    className="fixed right-0 top-0 bottom-0 w-96 bg-cyber-sidebar backdrop-blur-xl border-l border-cyber-border z-[60] p-8 shadow-2xl"
                  >
                      <div className="flex justify-between items-center mb-8">
                        <h3 className="text-xl font-bold text-cyber-text-primary">Node Intelligence</h3>
                        <button onClick={() => setSelectedIp(null)} className="text-cyber-text-secondary hover:text-cyber-text-primary"><Maximize2 size={20} /></button>
                      </div>

                    <div className="space-y-8">
                      <div className="p-6 rounded-2xl bg-cyber-danger/5 border border-cyber-danger/20 text-center">
                        <div className="w-16 h-16 bg-cyber-danger/20 rounded-2xl flex items-center justify-center text-cyber-danger mx-auto mb-4">
                          <Shield size={32} />
                        </div>
                        <h4 className="text-2xl font-bold text-cyber-text-primary mb-1">{selectedIp.ip}</h4>
                        <p className="text-xs font-mono text-cyber-danger uppercase tracking-widest">Status: Blacklisted</p>
                      </div>

                      <div className="space-y-4">
                        <div className="flex justify-between p-3 rounded-xl bg-cyber-card border border-cyber-border">
                          <span className="text-[10px] font-mono text-cyber-text-secondary uppercase">Country</span>
                          <span className="text-xs font-bold text-cyber-text-primary">{selectedIp.country}</span>
                        </div>
                        <div className="flex justify-between p-3 rounded-xl bg-cyber-card border border-cyber-border">
                          <span className="text-[10px] font-mono text-cyber-text-secondary uppercase">ISP</span>
                          <span className="text-xs font-bold text-cyber-text-primary">{selectedIp.isp}</span>
                        </div>
                        <div className="flex justify-between p-3 rounded-xl bg-cyber-card border border-cyber-border">
                          <span className="text-[10px] font-mono text-cyber-text-secondary uppercase">Total Attempts</span>
                          <span className="text-xs font-bold text-cyber-warning">{selectedIp.attempts}</span>
                        </div>
                        <div className="flex justify-between p-3 rounded-xl bg-cyber-card border border-cyber-border">
                          <span className="text-[10px] font-mono text-cyber-text-secondary uppercase">Blocked Since</span>
                          <span className="text-xs font-bold text-cyber-text-secondary">{new Date(selectedIp.timeBlocked).toLocaleString()}</span>
                        </div>
                      </div>

                      <div className="p-4 rounded-xl bg-cyber-card border border-cyber-border">
                        <h5 className="text-[10px] font-mono text-cyber-text-secondary uppercase mb-2">Block Reason</h5>
                        <p className="text-xs text-cyber-text-primary italic">"{selectedIp.reason}"</p>
                      </div>

                      <button 
                        onClick={() => { unblockIp(selectedIp.ip); setSelectedIp(null); }}
                        className="w-full py-4 rounded-xl bg-cyber-success text-cyber-bg font-bold uppercase tracking-widest hover:bg-cyber-success/80 transition-all"
                      >
                        Authorize Node (Unblock)
                      </button>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          )}
        </div>
      </main>

      {/* Security Report Modal */}
      <AnimatePresence>
        {showReport && reportData && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-[100] flex items-center justify-center p-8 bg-cyber-bg/90 backdrop-blur-md"
          >
            <motion.div 
              initial={{ scale: 0.9, y: 20 }}
              animate={{ scale: 1, y: 0 }}
              className="glass-panel w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col bg-cyber-card border-cyber-border"
            >
              <div className="p-8 border-b border-cyber-border flex justify-between items-center bg-cyber-sidebar/50">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 bg-cyber-accent/10 rounded-2xl flex items-center justify-center text-cyber-accent">
                    <Database size={24} />
                  </div>
                  <div>
                    <h2 className="text-2xl font-bold text-cyber-text-primary">Security Intelligence Report</h2>
                    <p className="text-xs font-mono text-cyber-text-secondary uppercase tracking-widest">Generated: {new Date().toLocaleString()}</p>
                  </div>
                </div>
                <button onClick={() => setShowReport(false)} className="text-cyber-text-secondary hover:text-cyber-text-primary transition-colors">
                  <Maximize2 size={24} />
                </button>
              </div>

              <div className="p-8 overflow-y-auto flex-1 space-y-12">
                {/* Summary Section */}
                <section>
                  <h3 className="text-xs font-mono text-cyber-accent uppercase tracking-[0.3em] mb-6">01. Network Traffic Summary</h3>
                  <div className="grid grid-cols-2 md:grid-cols-5 gap-6">
                    <div className="p-4 rounded-xl bg-cyber-sidebar border border-cyber-border">
                      <p className="text-[10px] text-cyber-text-secondary uppercase mb-1">Total Packets</p>
                      <p className="text-xl font-bold text-cyber-text-primary">{reportData.summary.totalPackets}</p>
                    </div>
                    <div className="p-4 rounded-xl bg-cyber-sidebar border border-cyber-border">
                      <p className="text-[10px] text-cyber-text-secondary uppercase mb-1">Data Analyzed</p>
                      <p className="text-xl font-bold text-cyber-text-primary">{(reportData.summary.totalTrafficBytes / 1024).toFixed(2)} KB</p>
                    </div>
                    <div className="p-4 rounded-xl bg-cyber-sidebar border border-cyber-border">
                      <p className="text-[10px] text-cyber-text-secondary uppercase mb-1">Attacks Detected</p>
                      <p className="text-xl font-bold text-cyber-danger">{reportData.summary.attacksDetected}</p>
                    </div>
                    <div className="p-4 rounded-xl bg-cyber-sidebar border border-cyber-border">
                      <p className="text-[10px] text-cyber-text-secondary uppercase mb-1">Suspicious Nodes</p>
                      <p className="text-xl font-bold text-cyber-warning">{reportData.summary.suspiciousNodes}</p>
                    </div>
                    <div className="p-4 rounded-xl bg-cyber-sidebar border border-cyber-border">
                      <p className="text-[10px] text-cyber-text-secondary uppercase mb-1">Blocked IPs</p>
                      <p className="text-xl font-bold text-cyber-danger">{reportData.summary.blockedNodes}</p>
                    </div>
                  </div>
                </section>

                {/* Threat Distribution */}
                <section>
                  <h3 className="text-xs font-mono text-cyber-accent uppercase tracking-[0.3em] mb-6">02. Risk Level Distribution</h3>
                  <div className="grid grid-cols-3 gap-6">
                    <div className="p-6 rounded-2xl bg-cyber-success/5 border border-cyber-success/10">
                      <p className="text-xs font-mono text-cyber-success mb-2">LOW RISK</p>
                      <p className="text-3xl font-bold text-cyber-text-primary">{reportData.threatDistribution.low}</p>
                    </div>
                    <div className="p-6 rounded-2xl bg-cyber-warning/5 border border-cyber-warning/10">
                      <p className="text-xs font-mono text-cyber-warning mb-2">MEDIUM RISK</p>
                      <p className="text-3xl font-bold text-cyber-text-primary">{reportData.threatDistribution.medium}</p>
                    </div>
                    <div className="p-6 rounded-2xl bg-cyber-danger/5 border border-cyber-danger/10">
                      <p className="text-xs font-mono text-cyber-danger mb-2">HIGH RISK</p>
                      <p className="text-3xl font-bold text-cyber-text-primary">{reportData.threatDistribution.high}</p>
                    </div>
                  </div>
                </section>

                {/* Attack Types */}
                <section>
                  <h3 className="text-xs font-mono text-cyber-accent uppercase tracking-[0.3em] mb-6">03. Attack Vector Analysis</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {Object.entries(reportData.attackTypes).map(([type, count]: any) => (
                      <div key={type} className="flex items-center justify-between p-4 rounded-xl bg-cyber-sidebar border border-cyber-border">
                        <span className="text-sm font-bold text-cyber-text-primary">{type}</span>
                        <span className="text-xs font-mono text-cyber-danger">{count} INCIDENTS</span>
                      </div>
                    ))}
                  </div>
                </section>

                {/* Top Malicious IPs */}
                <section>
                  <h3 className="text-xs font-mono text-cyber-accent uppercase tracking-[0.3em] mb-6">04. Top Malicious IPs</h3>
                  <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                    {reportData.suspiciousIps.map((ip: string) => (
                      <div key={ip} className="p-3 rounded-xl bg-cyber-sidebar border border-cyber-border text-center">
                        <p className="text-xs font-mono text-cyber-danger">{ip}</p>
                      </div>
                    ))}
                  </div>
                </section>
              </div>

              <div className="p-8 border-t border-cyber-border flex justify-end gap-4 bg-cyber-sidebar/50">
                <button className="px-6 py-3 rounded-xl border border-cyber-border text-xs font-mono uppercase tracking-widest hover:bg-cyber-sidebar-hover transition-all text-cyber-text-secondary">
                  Export as CSV
                </button>
                <button className="px-6 py-3 rounded-xl bg-cyber-accent text-cyber-bg text-xs font-bold uppercase tracking-widest hover:bg-cyber-accent/80 transition-all">
                  Export as PDF
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      <CyberAssistant packets={packets} />
    </div>
  );
}
