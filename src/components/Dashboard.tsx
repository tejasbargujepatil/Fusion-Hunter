import { Activity, Shield, Target, Zap, AlertTriangle, CheckCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

const Dashboard = () => {
  const systemStats = {
    endpointsScanned: 247,
    vulnerabilitiesFound: 12,
    payloadsGenerated: 1543,
    successRate: 78.4,
    activeScans: 3,
    lastScanTime: "2m ago"
  };

  const recentFindings = [
    { type: "SQLi", endpoint: "/api/login", severity: "critical", time: "1m ago" },
    { type: "XSS", endpoint: "/search?q=", severity: "high", time: "3m ago" },
    { type: "Auth Bypass", endpoint: "/admin/dashboard", severity: "critical", time: "5m ago" },
    { type: "SQLi", endpoint: "/products/view", severity: "medium", time: "8m ago" },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-primary flex items-center gap-3">
            <Shield className="w-8 h-8" />
            FusionHunter Command Center
          </h1>
          <p className="text-muted-foreground mt-1">
            Automated Penetration Testing System
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-primary glow-active"></div>
          <span className="text-sm text-primary font-semibold">SYSTEM ACTIVE</span>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="border-primary/20 bg-card">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Endpoints Scanned
            </CardTitle>
            <Target className="w-4 h-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-primary">{systemStats.endpointsScanned}</div>
            <p className="text-xs text-muted-foreground mt-1">
              Last scan: {systemStats.lastScanTime}
            </p>
          </CardContent>
        </Card>

        <Card className="border-destructive/20 bg-card">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Vulnerabilities Found
            </CardTitle>
            <AlertTriangle className="w-4 h-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-destructive">{systemStats.vulnerabilitiesFound}</div>
            <p className="text-xs text-muted-foreground mt-1">
              {recentFindings.filter(f => f.severity === 'critical').length} critical
            </p>
          </CardContent>
        </Card>

        <Card className="border-primary/20 bg-card">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Payloads Generated
            </CardTitle>
            <Zap className="w-4 h-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-primary">{systemStats.payloadsGenerated}</div>
            <p className="text-xs text-muted-foreground mt-1">
              Mutation-based adaptation
            </p>
          </CardContent>
        </Card>

        <Card className="border-primary/20 bg-card">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Success Rate
            </CardTitle>
            <Activity className="w-4 h-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-primary">{systemStats.successRate}%</div>
            <p className="text-xs text-muted-foreground mt-1">
              UCB1 algorithm learning
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Recent Findings */}
      <Card className="border-primary/20">
        <CardHeader>
          <CardTitle className="text-lg text-primary flex items-center gap-2">
            <AlertTriangle className="w-5 h-5" />
            Recent Vulnerability Detections
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {recentFindings.map((finding, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between p-3 rounded border border-border bg-terminal-bg hover:border-primary/40 transition-colors"
              >
                <div className="flex items-center gap-3">
                  <Badge
                    variant={finding.severity === 'critical' ? 'destructive' : 'secondary'}
                    className={finding.severity === 'critical' ? 'bg-destructive text-destructive-foreground' : 'bg-warning text-warning-foreground'}
                  >
                    {finding.type}
                  </Badge>
                  <code className="text-sm text-muted-foreground font-mono">
                    {finding.endpoint}
                  </code>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-muted-foreground">{finding.time}</span>
                  <Badge variant="outline" className="border-primary/30 text-primary">
                    {finding.severity}
                  </Badge>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Active Scans */}
      <Card className="border-primary/20">
        <CardHeader>
          <CardTitle className="text-lg text-primary flex items-center gap-2">
            <Activity className="w-5 h-5 animate-pulse" />
            Active Scanning Operations ({systemStats.activeScans})
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <div className="flex items-center gap-3 p-2 border border-primary/30 rounded bg-primary/5">
              <div className="w-2 h-2 rounded-full bg-primary animate-pulse"></div>
              <span className="text-sm font-mono">Crawler: Mapping /api/** endpoints</span>
            </div>
            <div className="flex items-center gap-3 p-2 border border-primary/30 rounded bg-primary/5">
              <div className="w-2 h-2 rounded-full bg-primary animate-pulse"></div>
              <span className="text-sm font-mono">Payload Gen: Mutating SQLi variants</span>
            </div>
            <div className="flex items-center gap-3 p-2 border border-primary/30 rounded bg-primary/5">
              <div className="w-2 h-2 rounded-full bg-primary animate-pulse"></div>
              <span className="text-sm font-mono">Bandit: Adapting strategy for /login</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default Dashboard;
