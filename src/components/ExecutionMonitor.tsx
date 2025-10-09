import { useState, useEffect } from "react";
import { Terminal, CheckCircle, XCircle, AlertCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";

interface LogEntry {
  timestamp: string;
  endpoint: string;
  payload: string;
  status: "success" | "failure" | "error";
  response: string;
  latency: number;
}

const ExecutionMonitor = () => {
  const [logs, setLogs] = useState<LogEntry[]>([
    {
      timestamp: "14:32:45.123",
      endpoint: "/api/login",
      payload: "' OR '1'='1",
      status: "success",
      response: "HTTP 200 - Reflection detected",
      latency: 124
    },
    {
      timestamp: "14:32:46.891",
      endpoint: "/search?q=",
      payload: "<script>alert(1)</script>",
      status: "success",
      response: "HTTP 200 - XSS vector confirmed",
      latency: 87
    },
    {
      timestamp: "14:32:48.234",
      endpoint: "/api/products",
      payload: "1' UNION SELECT NULL--",
      status: "failure",
      response: "HTTP 403 - WAF blocked",
      latency: 45
    },
    {
      timestamp: "14:32:49.567",
      endpoint: "/admin/dashboard",
      payload: "../../etc/passwd",
      status: "error",
      response: "HTTP 500 - Server error",
      latency: 201
    },
  ]);

  const [isLive, setIsLive] = useState(true);

  useEffect(() => {
    if (!isLive) return;

    const interval = setInterval(() => {
      const newLog: LogEntry = {
        timestamp: new Date().toLocaleTimeString('en-US', { hour12: false }) + '.' + Math.floor(Math.random() * 1000),
        endpoint: ["/api/users", "/api/orders", "/search", "/login"][Math.floor(Math.random() * 4)],
        payload: ["' OR 1=1--", "<img src=x>", "admin'--", "UNION SELECT"][Math.floor(Math.random() * 4)],
        status: ["success", "failure", "error"][Math.floor(Math.random() * 3)] as LogEntry["status"],
        response: "HTTP " + [200, 403, 500][Math.floor(Math.random() * 3)] + " - " + ["Detected", "Blocked", "Error"][Math.floor(Math.random() * 3)],
        latency: Math.floor(Math.random() * 300) + 20
      };
      setLogs(prev => [newLog, ...prev].slice(0, 20));
    }, 2000);

    return () => clearInterval(interval);
  }, [isLive]);

  const getStatusIcon = (status: LogEntry["status"]) => {
    switch (status) {
      case "success":
        return <CheckCircle className="w-4 h-4 text-primary" />;
      case "failure":
        return <XCircle className="w-4 h-4 text-muted-foreground" />;
      case "error":
        return <AlertCircle className="w-4 h-4 text-destructive" />;
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-primary flex items-center gap-3">
          <Terminal className="w-7 h-7" />
          Execution Monitor
        </h2>
        <p className="text-muted-foreground mt-1">
          Real-time payload execution and response analysis
        </p>
      </div>

      {/* Live Feed */}
      <Card className="border-primary/20 bg-card">
        <CardHeader>
          <CardTitle className="text-lg text-primary flex items-center justify-between">
            <span className="flex items-center gap-2">
              <Terminal className="w-5 h-5" />
              Live Execution Log
            </span>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-primary animate-pulse"></div>
              <span className="text-sm text-primary font-mono">STREAMING</span>
            </div>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[500px] w-full rounded border border-border bg-terminal-bg p-4">
            <div className="space-y-2 font-mono text-sm">
              {logs.map((log, idx) => (
                <div
                  key={idx}
                  className={`flex items-start gap-3 p-2 rounded transition-all ${
                    idx === 0 ? 'bg-primary/10 border border-primary/30' : ''
                  }`}
                >
                  <div className="flex-shrink-0 mt-0.5">
                    {getStatusIcon(log.status)}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-muted-foreground text-xs">{log.timestamp}</span>
                      <Badge
                        variant="outline"
                        className={
                          log.status === "success"
                            ? "border-primary/50 text-primary"
                            : log.status === "error"
                            ? "border-destructive/50 text-destructive"
                            : "border-muted-foreground/30 text-muted-foreground"
                        }
                      >
                        {log.status.toUpperCase()}
                      </Badge>
                      <span className="text-xs text-muted-foreground">{log.latency}ms</span>
                    </div>
                    <div className="text-foreground break-all">
                      <span className="text-primary">TARGET:</span> {log.endpoint}
                    </div>
                    <div className="text-muted-foreground break-all">
                      <span className="text-warning">PAYLOAD:</span> {log.payload}
                    </div>
                    <div className="text-muted-foreground text-xs mt-1">
                      {log.response}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>

      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="border-primary/20">
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-3xl font-bold text-primary mb-1">
                {logs.filter(l => l.status === "success").length}
              </div>
              <div className="text-sm text-muted-foreground">Successful Detections</div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-muted-foreground/20">
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-3xl font-bold text-muted-foreground mb-1">
                {logs.filter(l => l.status === "failure").length}
              </div>
              <div className="text-sm text-muted-foreground">Blocked Attempts</div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-destructive/20">
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-3xl font-bold text-destructive mb-1">
                {logs.filter(l => l.status === "error").length}
              </div>
              <div className="text-sm text-muted-foreground">Errors</div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default ExecutionMonitor;
