import { Zap, Copy, RefreshCw, Settings } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

const PayloadGenerator = () => {
  const sqlPayloads = [
    { payload: "' OR '1'='1", strategy: "Basic OR", success: 94 },
    { payload: "'; DROP TABLE users--", strategy: "Destructive", success: 12 },
    { payload: "1' UNION SELECT NULL,NULL--", strategy: "Union-based", success: 67 },
    { payload: "' AND 1=CONVERT(int, (SELECT @@version))--", strategy: "Error-based", success: 89 },
  ];

  const xssPayloads = [
    { payload: "<script>alert('XSS')</script>", strategy: "Classic", success: 78 },
    { payload: "<img src=x onerror=alert(1)>", strategy: "Event handler", success: 82 },
    { payload: "javascript:alert(document.cookie)", strategy: "Protocol", success: 45 },
    { payload: "<svg/onload=alert(1)>", strategy: "SVG-based", success: 91 },
  ];

  const mutationStrategies = [
    { name: "URL Encoding", active: true, weight: 0.82 },
    { name: "Hex Encoding", active: true, weight: 0.67 },
    { name: "Double Encoding", active: true, weight: 0.73 },
    { name: "Unicode Escaping", active: false, weight: 0.45 },
    { name: "Case Variation", active: true, weight: 0.88 },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-primary flex items-center gap-3">
          <Zap className="w-7 h-7" />
          Payload Generation Engine
        </h2>
        <p className="text-muted-foreground mt-1">
          Grammar-driven mutation with adaptive strategy selection
        </p>
      </div>

      {/* Mutation Strategies */}
      <Card className="border-primary/20">
        <CardHeader>
          <CardTitle className="text-lg text-primary flex items-center justify-between">
            <span className="flex items-center gap-2">
              <Settings className="w-5 h-5" />
              Mutation Strategies
            </span>
            <Button size="sm" variant="outline" className="border-primary/30 text-primary">
              <RefreshCw className="w-4 h-4 mr-2" />
              Recalculate Weights
            </Button>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {mutationStrategies.map((strategy, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between p-3 border border-border rounded bg-terminal-bg"
              >
                <div className="flex items-center gap-3">
                  <div
                    className={`w-2 h-2 rounded-full ${
                      strategy.active ? "bg-primary glow-active" : "bg-muted-foreground"
                    }`}
                  ></div>
                  <span className="font-medium text-foreground">{strategy.name}</span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="w-32 h-2 bg-muted rounded-full overflow-hidden">
                    <div
                      className="h-full bg-primary"
                      style={{ width: `${strategy.weight * 100}%` }}
                    ></div>
                  </div>
                  <span className="text-sm text-muted-foreground font-mono w-12 text-right">
                    {(strategy.weight * 100).toFixed(0)}%
                  </span>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Generated Payloads */}
      <Card className="border-primary/20">
        <CardHeader>
          <CardTitle className="text-lg text-primary">Generated Payloads</CardTitle>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="sqli" className="w-full">
            <TabsList className="grid w-full grid-cols-2 bg-secondary">
              <TabsTrigger value="sqli" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
                SQL Injection
              </TabsTrigger>
              <TabsTrigger value="xss" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
                XSS Vectors
              </TabsTrigger>
            </TabsList>
            
            <TabsContent value="sqli" className="space-y-2 mt-4">
              {sqlPayloads.map((item, idx) => (
                <div
                  key={idx}
                  className="p-3 border border-border rounded bg-terminal-bg hover:border-primary/40 transition-colors"
                >
                  <div className="flex items-center justify-between mb-2">
                    <Badge variant="outline" className="border-primary/50 text-primary">
                      {item.strategy}
                    </Badge>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-muted-foreground">
                        Success: {item.success}%
                      </span>
                      <Button size="sm" variant="ghost" className="h-6 w-6 p-0">
                        <Copy className="w-3 h-3 text-muted-foreground" />
                      </Button>
                    </div>
                  </div>
                  <code className="text-sm font-mono text-foreground break-all">
                    {item.payload}
                  </code>
                </div>
              ))}
            </TabsContent>

            <TabsContent value="xss" className="space-y-2 mt-4">
              {xssPayloads.map((item, idx) => (
                <div
                  key={idx}
                  className="p-3 border border-border rounded bg-terminal-bg hover:border-primary/40 transition-colors"
                >
                  <div className="flex items-center justify-between mb-2">
                    <Badge variant="outline" className="border-warning/50 text-warning">
                      {item.strategy}
                    </Badge>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-muted-foreground">
                        Success: {item.success}%
                      </span>
                      <Button size="sm" variant="ghost" className="h-6 w-6 p-0">
                        <Copy className="w-3 h-3 text-muted-foreground" />
                      </Button>
                    </div>
                  </div>
                  <code className="text-sm font-mono text-foreground break-all">
                    {item.payload}
                  </code>
                </div>
              ))}
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default PayloadGenerator;
