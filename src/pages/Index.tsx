import { useState } from "react";
import { Shield, Globe, Zap, Terminal, Brain, FileText } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import Dashboard from "@/components/Dashboard";
import CrawlerModule from "@/components/CrawlerModule";
import PayloadGenerator from "@/components/PayloadGenerator";
import ExecutionMonitor from "@/components/ExecutionMonitor";
import LearningEngine from "@/components/LearningEngine";
import ReportGenerator from "@/components/ReportGenerator";

const Index = () => {
  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-primary rounded flex items-center justify-center">
                <Shield className="w-6 h-6 text-primary-foreground" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-primary tracking-tight">FusionHunter</h1>
                <p className="text-xs text-muted-foreground">Automated Penetration Testing</p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="hidden md:flex items-center gap-2 px-3 py-1.5 border border-primary/30 rounded bg-primary/10">
                <div className="w-2 h-2 rounded-full bg-primary animate-pulse"></div>
                <span className="text-sm text-primary font-mono">ACTIVE</span>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-6 py-8">
        <Tabs defaultValue="dashboard" className="w-full">
          <TabsList className="grid w-full grid-cols-2 md:grid-cols-6 bg-secondary mb-8">
            <TabsTrigger 
              value="dashboard" 
              className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground"
            >
              <Shield className="w-4 h-4 mr-2" />
              <span className="hidden sm:inline">Dashboard</span>
            </TabsTrigger>
            <TabsTrigger 
              value="crawler"
              className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground"
            >
              <Globe className="w-4 h-4 mr-2" />
              <span className="hidden sm:inline">Crawler</span>
            </TabsTrigger>
            <TabsTrigger 
              value="payload"
              className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground"
            >
              <Zap className="w-4 h-4 mr-2" />
              <span className="hidden sm:inline">Payloads</span>
            </TabsTrigger>
            <TabsTrigger 
              value="executor"
              className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground"
            >
              <Terminal className="w-4 h-4 mr-2" />
              <span className="hidden sm:inline">Monitor</span>
            </TabsTrigger>
            <TabsTrigger 
              value="learning"
              className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground"
            >
              <Brain className="w-4 h-4 mr-2" />
              <span className="hidden sm:inline">Learning</span>
            </TabsTrigger>
            <TabsTrigger 
              value="report"
              className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground"
            >
              <FileText className="w-4 h-4 mr-2" />
              <span className="hidden sm:inline">Reports</span>
            </TabsTrigger>
          </TabsList>

          <TabsContent value="dashboard" className="mt-0">
            <Dashboard />
          </TabsContent>

          <TabsContent value="crawler" className="mt-0">
            <CrawlerModule />
          </TabsContent>

          <TabsContent value="payload" className="mt-0">
            <PayloadGenerator />
          </TabsContent>

          <TabsContent value="executor" className="mt-0">
            <ExecutionMonitor />
          </TabsContent>

          <TabsContent value="learning" className="mt-0">
            <LearningEngine />
          </TabsContent>

          <TabsContent value="report" className="mt-0">
            <ReportGenerator />
          </TabsContent>
        </Tabs>
      </main>

      {/* Footer */}
      <footer className="border-t border-border mt-16">
        <div className="container mx-auto px-6 py-6">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="text-sm text-muted-foreground">
              <span className="text-primary font-semibold">FusionHunter</span> - Self-Learning Vulnerability Scanner
            </div>
            <div className="flex items-center gap-4 text-xs text-muted-foreground">
              <span>Target: OWASP Juice Shop</span>
              <span>•</span>
              <span>Algorithm: UCB1</span>
              <span>•</span>
              <span>Mode: Sandboxed</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Index;
