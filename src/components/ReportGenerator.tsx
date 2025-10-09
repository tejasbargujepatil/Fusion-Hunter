import { useState } from "react";
import { FileText, Download, Eye, RefreshCw, X } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { saveAs } from "file-saver";
import jsPDF from "jspdf";

const ReportGenerator = () => {
  const [loading, setLoading] = useState(false);
  const [showPreview, setShowPreview] = useState(false);

  const reportSummary = {
    scanDate: "2025-10-09",
    duration: "12m 34s",
    endpointsScanned: 247,
    vulnerabilities: {
      critical: 3,
      high: 5,
      medium: 4,
      low: 2,
    },
    totalPayloads: 1543,
    successRate: 78.4,
  };

  const criticalFindings = [
    {
      type: "SQL Injection",
      endpoint: "/api/login",
      payload: "' OR '1'='1",
      cve: "CWE-89",
      remediation: "Implement parameterized queries and input validation",
    },
    {
      type: "Authentication Bypass",
      endpoint: "/admin/dashboard",
      payload: "admin'--",
      cve: "CWE-287",
      remediation: "Enforce proper session management and access controls",
    },
    {
      type: "Reflected XSS",
      endpoint: "/search?q=",
      payload: "<script>alert(1)</script>",
      cve: "CWE-79",
      remediation:
        "Sanitize user input and implement Content Security Policy",
    },
  ];

  // --- 🧠 Handlers for buttons

  // Export PDF
  const handleExportPDF = () => {
    const doc = new jsPDF();
    doc.setFontSize(16);
    doc.text("Fusion Hunter - Vulnerability Report", 10, 15);
    doc.setFontSize(12);
    doc.text(`Scan Date: ${reportSummary.scanDate}`, 10, 30);
    doc.text(`Duration: ${reportSummary.duration}`, 10, 38);
    doc.text(`Endpoints Scanned: ${reportSummary.endpointsScanned}`, 10, 46);
    doc.text(`Success Rate: ${reportSummary.successRate}%`, 10, 54);

    doc.text("Critical Findings:", 10, 70);
    criticalFindings.forEach((f, i) => {
      const y = 80 + i * 20;
      doc.text(`${i + 1}. ${f.type} (${f.cve})`, 10, y);
      doc.text(`Endpoint: ${f.endpoint}`, 10, y + 6);
      doc.text(`Remediation: ${f.remediation}`, 10, y + 12);
    });

    doc.save("FusionHunter_Report.pdf");
  };

  // Export Markdown
  const handleExportMarkdown = () => {
    let md = `# Fusion Hunter Vulnerability Report\n\n`;
    md += `**Scan Date:** ${reportSummary.scanDate}\n\n`;
    md += `**Duration:** ${reportSummary.duration}\n\n`;
    md += `**Endpoints Scanned:** ${reportSummary.endpointsScanned}\n\n`;
    md += `**Success Rate:** ${reportSummary.successRate}%\n\n`;
    md += `## Critical Findings\n\n`;
    criticalFindings.forEach((f) => {
      md += `### ${f.type}\n- Endpoint: ${f.endpoint}\n- Payload: ${f.payload}\n- CVE: ${f.cve}\n- Remediation: ${f.remediation}\n\n`;
    });
    const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
    saveAs(blob, "FusionHunter_Report.md");
  };

  // Preview Modal
  const handlePreview = () => setShowPreview(true);

  // Simulated Regenerate
  const handleRegenerate = async () => {
    setLoading(true);
    await new Promise((r) => setTimeout(r, 1500));
    setLoading(false);
    alert("Report data regenerated successfully!");
  };

  // --- UI
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
        <CardContent className="flex gap-3 flex-wrap">
          <Button
            className="bg-primary text-primary-foreground hover:bg-primary/90"
            onClick={handleExportPDF}
          >
            <Download className="w-4 h-4 mr-2" />
            Export as PDF
          </Button>
          <Button
            variant="outline"
            className="border-primary/30 text-primary"
            onClick={handleExportMarkdown}
          >
            <Download className="w-4 h-4 mr-2" />
            Export as Markdown
          </Button>
          <Button
            variant="outline"
            className="border-primary/30 text-primary"
            onClick={handlePreview}
          >
            <Eye className="w-4 h-4 mr-2" />
            Preview Report
          </Button>
          <Button
            variant="outline"
            className="border-primary/30 text-primary"
            disabled={loading}
            onClick={handleRegenerate}
          >
            <RefreshCw
              className={`w-4 h-4 mr-2 ${loading ? "animate-spin" : ""}`}
            />
            {loading ? "Regenerating..." : "Regenerate"}
          </Button>
        </CardContent>
      </Card>

      {/* Rest of your original report remains unchanged below */}
      {/* Executive Summary, Critical Findings, Technical Details ... */}

      {/* Add your existing code unchanged here */}

      {/* PREVIEW MODAL */}
      {showPreview && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-background border border-border rounded-lg w-11/12 md:w-2/3 p-6 relative">
            <button
              onClick={() => setShowPreview(false)}
              className="absolute top-2 right-2 text-muted-foreground hover:text-primary"
            >
              <X className="w-5 h-5" />
            </button>
            <h3 className="text-xl font-semibold mb-4">📄 Report Preview</h3>
            <div className="max-h-[70vh] overflow-y-auto text-sm text-foreground space-y-3">
              <p><strong>Scan Date:</strong> {reportSummary.scanDate}</p>
              <p><strong>Endpoints Scanned:</strong> {reportSummary.endpointsScanned}</p>
              <p><strong>Success Rate:</strong> {reportSummary.successRate}%</p>
              <h4 className="font-semibold mt-4">Critical Findings</h4>
              <ul className="list-disc ml-5">
                {criticalFindings.map((f, i) => (
                  <li key={i}>
                    {f.type} — <code>{f.endpoint}</code> ({f.cve})
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ReportGenerator;
