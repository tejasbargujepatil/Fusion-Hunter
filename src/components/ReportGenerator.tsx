import { FileText, Download, Eye, RefreshCw } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

const ReportGenerator = () => {
  const reportSummary = {
    scanDate: "2025-10-09",
    duration: "12m 34s",
    endpointsScanned: 247,
    vulnerabilities: {
      critical: 3,
      high: 5,
      medium: 4,
      low: 2
    },
    totalPayloads: 1543,
    successRate: 78.4
  };

  const criticalFindings = [
    {
      type: "SQL Injection",
      endpoint: "/api/login",
      payload: "' OR '1'='1",
      cve: "CWE-89",
      remediation: "Implement parameterized queries and input validation"
    },
    {
      type: "Authentication Bypass",
      endpoint: "/admin/dashboard",
      payload: "admin'--",
      cve: "CWE-287",
      remediation: "Enforce proper session management and access controls"
    },
    {
      type: "Reflected XSS",
      endpoint: "/search?q=",
      payload: "<script>alert(1)</script>",
      cve: "CWE-79",
      remediation: "Sanitize user input and implement Content Security Policy"
    }
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-primary flex items-center gap-3">
          <FileText className="w-7 h-7" />
          Vulnerability Report Generator
        </h2>
        <p className="text-muted-foreground mt-1">
          Comprehensive security assessment documentation
        </p>
      </div>

      {/* Report Actions */}
      <Card className="border-primary/20">
        <CardHeader>
          <CardTitle className="text-lg text-primary">Export Options</CardTitle>
        </CardHeader>
        <CardContent className="flex gap-3">
          <Button className="bg-primary text-primary-foreground hover:bg-primary/90">
            <Download className="w-4 h-4 mr-2" />
            Export as PDF
          </Button>
          <Button variant="outline" className="border-primary/30 text-primary">
            <Download className="w-4 h-4 mr-2" />
            Export as Markdown
          </Button>
          <Button variant="outline" className="border-primary/30 text-primary">
            <Eye className="w-4 h-4 mr-2" />
            Preview Report
          </Button>
          <Button variant="outline" className="border-primary/30 text-primary">
            <RefreshCw className="w-4 h-4 mr-2" />
            Regenerate
          </Button>
        </CardContent>
      </Card>

      {/* Executive Summary */}
      <Card className="border-primary/20">
        <CardHeader>
          <CardTitle className="text-lg text-primary">Executive Summary</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div className="p-3 border border-border rounded bg-terminal-bg">
              <div className="text-sm text-muted-foreground mb-1">Scan Date</div>
              <div className="text-lg font-mono text-foreground">{reportSummary.scanDate}</div>
            </div>
            <div className="p-3 border border-border rounded bg-terminal-bg">
              <div className="text-sm text-muted-foreground mb-1">Duration</div>
              <div className="text-lg font-mono text-foreground">{reportSummary.duration}</div>
            </div>
            <div className="p-3 border border-border rounded bg-terminal-bg">
              <div className="text-sm text-muted-foreground mb-1">Endpoints</div>
              <div className="text-lg font-mono text-foreground">{reportSummary.endpointsScanned}</div>
            </div>
            <div className="p-3 border border-border rounded bg-terminal-bg">
              <div className="text-sm text-muted-foreground mb-1">Success Rate</div>
              <div className="text-lg font-mono text-primary">{reportSummary.successRate}%</div>
            </div>
          </div>

          <div className="space-y-2">
            <h4 className="text-sm font-semibold text-foreground mb-3">Vulnerability Distribution</h4>
            <div className="flex items-center gap-3">
              <Badge variant="destructive" className="bg-destructive text-destructive-foreground">
                {reportSummary.vulnerabilities.critical} Critical
              </Badge>
              <Badge className="bg-warning text-warning-foreground">
                {reportSummary.vulnerabilities.high} High
              </Badge>
              <Badge variant="outline" className="border-warning/50 text-warning">
                {reportSummary.vulnerabilities.medium} Medium
              </Badge>
              <Badge variant="outline" className="border-muted-foreground/30 text-muted-foreground">
                {reportSummary.vulnerabilities.low} Low
              </Badge>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Detailed Findings */}
      <Card className="border-primary/20">
        <CardHeader>
          <CardTitle className="text-lg text-primary">Critical Findings</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {criticalFindings.map((finding, idx) => (
              <div
                key={idx}
                className="p-4 border border-destructive/30 rounded bg-destructive/5"
              >
                <div className="flex items-start justify-between mb-3">
                  <div>
                    <h4 className="text-lg font-semibold text-foreground mb-1">
                      {finding.type}
                    </h4>
                    <code className="text-sm font-mono text-muted-foreground">
                      {finding.endpoint}
                    </code>
                  </div>
                  <Badge variant="destructive" className="bg-destructive text-destructive-foreground">
                    CRITICAL
                  </Badge>
                </div>

                <div className="space-y-2 text-sm">
                  <div>
                    <span className="text-muted-foreground">CVE Reference: </span>
                    <Badge variant="outline" className="border-muted-foreground/30 text-muted-foreground font-mono">
                      {finding.cve}
                    </Badge>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Successful Payload: </span>
                    <code className="text-foreground bg-terminal-bg px-2 py-1 rounded">
                      {finding.payload}
                    </code>
                  </div>
                  <div className="pt-2 border-t border-border">
                    <span className="text-muted-foreground font-semibold">Remediation: </span>
                    <p className="text-foreground mt-1">{finding.remediation}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Technical Details */}
      <Card className="border-primary/20">
        <CardHeader>
          <CardTitle className="text-lg text-primary">Technical Appendix</CardTitle>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="methodology" className="w-full">
            <TabsList className="grid w-full grid-cols-3 bg-secondary">
              <TabsTrigger value="methodology" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
                Methodology
              </TabsTrigger>
              <TabsTrigger value="learning" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
                Learning Curve
              </TabsTrigger>
              <TabsTrigger value="audit" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
                Audit Trail
              </TabsTrigger>
            </TabsList>

            <TabsContent value="methodology" className="mt-4">
              <div className="p-4 bg-terminal-bg rounded border border-border">
                <h4 className="font-semibold text-foreground mb-2">Scanning Methodology</h4>
                <ul className="space-y-2 text-sm text-muted-foreground">
                  <li>• Automated web crawler with recursive endpoint discovery</li>
                  <li>• Grammar-driven payload generation with 5 mutation strategies</li>
                  <li>• UCB1 bandit algorithm for adaptive strategy selection</li>
                  <li>• Per-endpoint learning with confidence tracking</li>
                  <li>• Sandboxed execution with rate limiting and timeout controls</li>
                </ul>
              </div>
            </TabsContent>

            <TabsContent value="learning" className="mt-4">
              <div className="p-4 bg-terminal-bg rounded border border-border">
                <h4 className="font-semibold text-foreground mb-2">Learning Algorithm Performance</h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Initial Success Rate:</span>
                    <span className="text-foreground font-mono">23%</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Final Success Rate:</span>
                    <span className="text-primary font-mono">78.4%</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Improvement:</span>
                    <span className="text-primary font-mono">+55.4%</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Total Adaptations:</span>
                    <span className="text-foreground font-mono">34</span>
                  </div>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="audit" className="mt-4">
              <div className="p-4 bg-terminal-bg rounded border border-border">
                <h4 className="font-semibold text-foreground mb-2">Audit Information</h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Total Requests Logged:</span>
                    <span className="text-foreground font-mono">1,543</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Log File:</span>
                    <code className="text-foreground">logs/attempts.jsonl</code>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Reproducibility:</span>
                    <Badge variant="outline" className="border-primary/50 text-primary">
                      VERIFIED
                    </Badge>
                  </div>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default ReportGenerator;
