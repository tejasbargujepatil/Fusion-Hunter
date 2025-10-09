import { Brain, TrendingUp, BarChart3 } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend
} from "recharts";

const LearningEngine = () => {
  // Simulated UCB1 learning data
  const successRateData = [
    { iteration: 1, rate: 23, sqli: 18, xss: 28 },
    { iteration: 5, rate: 34, sqli: 31, xss: 37 },
    { iteration: 10, rate: 48, sqli: 45, xss: 51 },
    { iteration: 15, rate: 59, sqli: 57, xss: 61 },
    { iteration: 20, rate: 67, sqli: 65, xss: 69 },
    { iteration: 25, rate: 73, sqli: 71, xss: 75 },
    { iteration: 30, rate: 78, sqli: 76, xss: 80 },
  ];

  const strategyPerformance = [
    { strategy: "Basic OR Injection", attempts: 487, success: 92, ucbScore: 0.89 },
    { strategy: "Union-based SQLi", attempts: 231, success: 67, ucbScore: 0.73 },
    { strategy: "Error-based SQLi", attempts: 356, success: 89, ucbScore: 0.86 },
    { strategy: "Classic XSS", attempts: 412, success: 78, ucbScore: 0.81 },
    { strategy: "Event Handler XSS", attempts: 298, success: 82, ucbScore: 0.84 },
  ];

  const endpointAdaptation = [
    { endpoint: "/api/login", adaptations: 14, currentStrategy: "Error-based SQLi", confidence: 0.91 },
    { endpoint: "/search", adaptations: 8, currentStrategy: "Event Handler XSS", confidence: 0.87 },
    { endpoint: "/api/users", adaptations: 12, currentStrategy: "Union-based SQLi", confidence: 0.79 },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-primary flex items-center gap-3">
          <Brain className="w-7 h-7" />
          Adaptive Learning Engine
        </h2>
        <p className="text-muted-foreground mt-1">
          UCB1 bandit algorithm with per-endpoint strategy optimization
        </p>
      </div>

      {/* Success Rate Chart */}
      <Card className="border-primary/20">
        <CardHeader>
          <CardTitle className="text-lg text-primary flex items-center gap-2">
            <TrendingUp className="w-5 h-5" />
            Detection Success Rate Over Time
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={successRateData}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
              <XAxis
                dataKey="iteration"
                stroke="hsl(var(--muted-foreground))"
                label={{ value: 'Iteration', position: 'insideBottom', offset: -5, fill: 'hsl(var(--muted-foreground))' }}
              />
              <YAxis
                stroke="hsl(var(--muted-foreground))"
                label={{ value: 'Success Rate (%)', angle: -90, position: 'insideLeft', fill: 'hsl(var(--muted-foreground))' }}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: 'hsl(var(--card))',
                  border: '1px solid hsl(var(--border))',
                  borderRadius: '6px',
                  color: 'hsl(var(--foreground))'
                }}
              />
              <Legend />
              <Area
                type="monotone"
                dataKey="rate"
                stroke="hsl(var(--primary))"
                fill="hsl(var(--primary) / 0.2)"
                name="Overall Success"
              />
              <Area
                type="monotone"
                dataKey="sqli"
                stroke="hsl(var(--warning))"
                fill="hsl(var(--warning) / 0.1)"
                name="SQLi Success"
              />
              <Area
                type="monotone"
                dataKey="xss"
                stroke="hsl(var(--destructive))"
                fill="hsl(var(--destructive) / 0.1)"
                name="XSS Success"
              />
            </AreaChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* Strategy Performance */}
      <Card className="border-primary/20">
        <CardHeader>
          <CardTitle className="text-lg text-primary flex items-center gap-2">
            <BarChart3 className="w-5 h-5" />
            Strategy Performance (UCB1 Scores)
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {strategyPerformance.map((item, idx) => (
              <div
                key={idx}
                className="p-3 border border-border rounded bg-terminal-bg"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium text-foreground">{item.strategy}</span>
                  <Badge
                    variant="outline"
                    className={
                      item.ucbScore > 0.85
                        ? "border-primary/50 text-primary"
                        : item.ucbScore > 0.75
                        ? "border-warning/50 text-warning"
                        : "border-muted-foreground/30 text-muted-foreground"
                    }
                  >
                    UCB: {item.ucbScore.toFixed(2)}
                  </Badge>
                </div>
                <div className="flex items-center gap-4 text-sm">
                  <span className="text-muted-foreground">
                    Attempts: <span className="text-foreground font-mono">{item.attempts}</span>
                  </span>
                  <span className="text-muted-foreground">
                    Success: <span className="text-primary font-mono">{item.success}%</span>
                  </span>
                </div>
                <div className="w-full h-2 bg-muted rounded-full overflow-hidden mt-2">
                  <div
                    className="h-full bg-primary transition-all duration-500"
                    style={{ width: `${item.ucbScore * 100}%` }}
                  ></div>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Per-Endpoint Adaptation */}
      <Card className="border-primary/20">
        <CardHeader>
          <CardTitle className="text-lg text-primary">
            Per-Endpoint Strategy Adaptation
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {endpointAdaptation.map((item, idx) => (
              <div
                key={idx}
                className="p-3 border border-border rounded bg-terminal-bg hover:border-primary/40 transition-colors"
              >
                <div className="flex items-center justify-between mb-2">
                  <code className="text-sm font-mono text-foreground">{item.endpoint}</code>
                  <Badge variant="outline" className="border-primary/50 text-primary">
                    {item.adaptations} adaptations
                  </Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">
                    Strategy: <span className="text-foreground">{item.currentStrategy}</span>
                  </span>
                  <span className="text-sm text-muted-foreground">
                    Confidence: <span className="text-primary font-mono">{(item.confidence * 100).toFixed(0)}%</span>
                  </span>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default LearningEngine;
