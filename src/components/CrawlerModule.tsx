import { useState } from "react";
import { Globe, Play, Pause, Download, RefreshCw, AlertCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { useScan } from "@/contexts/ScanContext";
import { crawlTarget, isValidUrl } from "@/lib/scanEngine";
import { useToast } from "@/hooks/use-toast";

const CrawlerModule = () => {
  const { scanState, updateScanState } = useScan();
  const { toast } = useToast();
  const [targetUrl, setTargetUrl] = useState("http://localhost:3000");

  const handleStartScan = async () => {
    if (!isValidUrl(targetUrl)) {
      toast({
        title: "Invalid URL",
        description: "Please enter a valid URL (e.g., http://localhost:3000)",
        variant: "destructive",
      });
      return;
    }

    updateScanState({
      isScanning: true,
      targetUrl,
      progress: 0,
      endpoints: [],
      statistics: {
        ...scanState.statistics,
        activeScans: 1,
      },
    });

    toast({
      title: "Scan Started",
      description: `Crawling ${targetUrl}...`,
    });

    try {
      await crawlTarget(targetUrl, (progress, endpoints) => {
        updateScanState({
          progress,
          endpoints,
          statistics: {
            ...scanState.statistics,
            endpointsScanned: endpoints.length,
          },
        });
      });

      updateScanState({
        isScanning: false,
        progress: 100,
        statistics: {
          ...scanState.statistics,
          activeScans: 0,
        },
      });

      toast({
        title: "Scan Complete",
        description: `Discovered ${scanState.endpoints.length} endpoints`,
      });
    } catch (error) {
      updateScanState({ isScanning: false });
      toast({
        title: "Scan Failed",
        description: "Failed to crawl target. Check the URL and try again.",
        variant: "destructive",
      });
    }
  };

  const handleReset = () => {
    updateScanState({
      progress: 0,
      endpoints: [],
      isScanning: false,
    });
    toast({
      title: "Reset Complete",
      description: "Endpoint discovery has been cleared",
    });
  };

  const handleExport = () => {
    const data = {
      target: scanState.targetUrl,
      timestamp: new Date().toISOString(),
      endpoints: scanState.endpoints,
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `discovery-${Date.now()}.json`;
    a.click();
    toast({
      title: "Export Complete",
      description: "Discovery data exported successfully",
    });
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
              disabled={scanState.isScanning}
              className="font-mono bg-terminal-bg border-primary/30"
            />
            <Button
              onClick={handleStartScan}
              disabled={scanState.isScanning}
              className="bg-primary text-primary-foreground hover:bg-primary/90"
            >
              {scanState.isScanning ? (
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

          {scanState.isScanning && (
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Scanning {scanState.targetUrl}...</span>
                <span className="text-primary font-mono">{Math.round(scanState.progress)}%</span>
              </div>
              <Progress value={scanState.progress} className="h-2" />
            </div>
          )}

          {!scanState.isScanning && scanState.endpoints.length > 0 && (
            <div className="flex items-center gap-2 p-2 bg-primary/10 border border-primary/30 rounded">
              <AlertCircle className="w-4 h-4 text-primary" />
              <span className="text-sm text-primary">
                Discovery complete! Found {scanState.endpoints.length} endpoints
              </span>
            </div>
          )}

          <div className="flex gap-2">
            <Button 
              variant="outline" 
              size="sm" 
              className="border-primary/30 text-primary"
              onClick={handleReset}
              disabled={scanState.isScanning}
            >
              <RefreshCw className="w-4 h-4 mr-2" />
              Reset
            </Button>
            <Button 
              variant="outline" 
              size="sm" 
              className="border-primary/30 text-primary"
              onClick={handleExport}
              disabled={scanState.endpoints.length === 0}
            >
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
            <span>Discovered Endpoints ({scanState.endpoints.length})</span>
            <Badge className="bg-primary text-primary-foreground">
              {scanState.endpoints.reduce((acc, e) => acc + e.params.length, 0)} parameters
            </Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {scanState.endpoints.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              No endpoints discovered yet. Start a crawl to begin.
            </div>
          ) : (
            <div className="space-y-2">
              {scanState.endpoints.map((endpoint, idx) => (
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
                    {endpoint.status !== undefined && (
                      <Badge 
                        variant={endpoint.status === 200 ? "default" : "secondary"} 
                        className="text-xs"
                      >
                        {endpoint.status === 0 ? 'CORS' : endpoint.status}
                      </Badge>
                    )}
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
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default CrawlerModule;
