import { Terminal, CheckCircle, XCircle, AlertCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useScan } from "@/contexts/ScanContext";

const ExecutionMonitor = () => {
  const { scanState } = useScan();

  const getStatusIcon = (status: 'success' | 'failed' | 'error') => {
    switch (status) {
      case "success":
        return <CheckCircle className="w-4 h-4 text-primary" />;
      case "failed":
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
            {scanState.logs.length === 0 ? (
              <div className="flex items-center justify-center h-full text-muted-foreground">
                No execution logs yet. Start testing to see results.
              </div>
            ) : (
              <div className="space-y-2 font-mono text-sm">
                {scanState.logs.map((log, idx) => (
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
            )}
          </ScrollArea>
        </CardContent>
      </Card>

      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="border-primary/20">
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-3xl font-bold text-primary mb-1">
                {scanState.logs.filter(l => l.status === "success").length}
              </div>
              <div className="text-sm text-muted-foreground">Successful Detections</div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-muted-foreground/20">
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-3xl font-bold text-muted-foreground mb-1">
                {scanState.logs.filter(l => l.status === "failed").length}
              </div>
              <div className="text-sm text-muted-foreground">Blocked Attempts</div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-destructive/20">
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-3xl font-bold text-destructive mb-1">
                {scanState.logs.filter(l => l.status === "error").length}
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
