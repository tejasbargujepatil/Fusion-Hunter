import { useState } from "react";
import { Globe, Play, Pause, Download, RefreshCw } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";

const CrawlerModule = () => {
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [targetUrl, setTargetUrl] = useState("http://localhost:3000");

  const discoveredEndpoints = [
    { url: "/api/users", method: "GET", params: ["id", "email"], forms: 0 },
    { url: "/api/login", method: "POST", params: ["username", "password"], forms: 1 },
    { url: "/api/products", method: "GET", params: ["category", "search"], forms: 0 },
    { url: "/search", method: "GET", params: ["q", "filter"], forms: 1 },
    { url: "/admin/dashboard", method: "GET", params: ["token"], forms: 0 },
    { url: "/api/orders", method: "POST", params: ["product_id", "quantity"], forms: 1 },
  ];

  const handleStartScan = () => {
    setIsScanning(true);
    let currentProgress = 0;
    const interval = setInterval(() => {
      currentProgress += 5;
      setProgress(currentProgress);
      if (currentProgress >= 100) {
        clearInterval(interval);
        setIsScanning(false);
        setProgress(100);
      }
    }, 200);
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-primary flex items-center gap-3">
          <Globe className="w-7 h-7" />
          Web Crawler & Discovery
        </h2>
        <p className="text-muted-foreground mt-1">
          Autonomous endpoint mapping and parameter extraction
        </p>
      </div>

      {/* Scanner Control */}
      <Card className="border-primary/20">
        <CardHeader>
          <CardTitle className="text-lg text-primary">Scan Configuration</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-3">
            <Input
              placeholder="Target URL (e.g., https://example.com)"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              disabled={isScanning}
              className="font-mono bg-terminal-bg border-primary/30"
            />
            <Button
              onClick={handleStartScan}
              disabled={isScanning}
              className="bg-primary text-primary-foreground hover:bg-primary/90"
            >
              {isScanning ? (
                <>
                  <Pause className="w-4 h-4 mr-2" />
                  Scanning...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 mr-2" />
                  Start Crawl
                </>
              )}
            </Button>
          </div>

          {isScanning && (
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Scanning {targetUrl}...</span>
                <span className="text-primary font-mono">{progress}%</span>
              </div>
              <Progress value={progress} className="h-2" />
            </div>
          )}

          <div className="flex gap-2">
            <Button variant="outline" size="sm" className="border-primary/30 text-primary">
              <RefreshCw className="w-4 h-4 mr-2" />
              Reset
            </Button>
            <Button variant="outline" size="sm" className="border-primary/30 text-primary">
              <Download className="w-4 h-4 mr-2" />
              Export discovery.json
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Discovered Endpoints */}
      <Card className="border-primary/20">
        <CardHeader>
          <CardTitle className="text-lg text-primary flex items-center justify-between">
            <span>Discovered Endpoints ({discoveredEndpoints.length})</span>
            <Badge className="bg-primary text-primary-foreground">
              {discoveredEndpoints.reduce((acc, e) => acc + e.params.length, 0)} parameters
            </Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {discoveredEndpoints.map((endpoint, idx) => (
              <div
                key={idx}
                className="p-3 border border-border rounded bg-terminal-bg hover:border-primary/40 transition-colors"
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-3">
                    <Badge
                      variant="outline"
                      className={
                        endpoint.method === "POST"
                          ? "border-warning/50 text-warning"
                          : "border-primary/50 text-primary"
                      }
                    >
                      {endpoint.method}
                    </Badge>
                    <code className="text-sm font-mono text-foreground">{endpoint.url}</code>
                  </div>
                  <div className="flex gap-2">
                    {endpoint.forms > 0 && (
                      <Badge variant="secondary" className="text-xs">
                        {endpoint.forms} form{endpoint.forms > 1 ? 's' : ''}
                      </Badge>
                    )}
                  </div>
                </div>
                <div className="flex gap-2 flex-wrap">
                  {endpoint.params.map((param, pidx) => (
                    <Badge
                      key={pidx}
                      variant="outline"
                      className="text-xs border-muted-foreground/30 text-muted-foreground font-mono"
                    >
                      {param}
                    </Badge>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default CrawlerModule;
