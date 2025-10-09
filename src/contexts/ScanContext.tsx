import { createContext, useContext, useState, ReactNode } from 'react';
import { ScanState, Endpoint, Vulnerability, ExecutionLog } from '@/lib/scanEngine';

interface ScanContextType {
  scanState: ScanState;
  updateScanState: (updates: Partial<ScanState>) => void;
  addEndpoint: (endpoint: Endpoint) => void;
  addVulnerability: (vuln: Vulnerability) => void;
  addLog: (log: ExecutionLog) => void;
  resetScan: () => void;
}

const initialState: ScanState = {
  isScanning: false,
  targetUrl: '',
  progress: 0,
  endpoints: [],
  vulnerabilities: [],
  logs: [],
  statistics: {
    endpointsScanned: 0,
    vulnerabilitiesFound: 0,
    payloadsGenerated: 0,
    successRate: 0,
    activeScans: 0,
  },
  learningData: [],
};

const ScanContext = createContext<ScanContextType | undefined>(undefined);

export const ScanProvider = ({ children }: { children: ReactNode }) => {
  const [scanState, setScanState] = useState<ScanState>(initialState);

  const updateScanState = (updates: Partial<ScanState>) => {
    setScanState(prev => ({ ...prev, ...updates }));
  };

  const addEndpoint = (endpoint: Endpoint) => {
    setScanState(prev => ({
      ...prev,
      endpoints: [...prev.endpoints, endpoint],
      statistics: {
        ...prev.statistics,
        endpointsScanned: prev.statistics.endpointsScanned + 1,
      },
    }));
  };

  const addVulnerability = (vuln: Vulnerability) => {
    setScanState(prev => ({
      ...prev,
      vulnerabilities: [...prev.vulnerabilities, vuln],
      statistics: {
        ...prev.statistics,
        vulnerabilitiesFound: prev.statistics.vulnerabilitiesFound + 1,
      },
    }));
  };

  const addLog = (log: ExecutionLog) => {
    setScanState(prev => {
      const newLogs = [...prev.logs, log];
      const successCount = newLogs.filter(l => l.status === 'success').length;
      const successRate = (successCount / newLogs.length) * 100;

      return {
        ...prev,
        logs: newLogs.slice(-100), // Keep last 100 logs
        statistics: {
          ...prev.statistics,
          successRate: Math.round(successRate),
        },
      };
    });
  };

  const resetScan = () => {
    setScanState(initialState);
  };

  return (
    <ScanContext.Provider
      value={{
        scanState,
        updateScanState,
        addEndpoint,
        addVulnerability,
        addLog,
        resetScan,
      }}
    >
      {children}
    </ScanContext.Provider>
  );
};

export const useScan = () => {
  const context = useContext(ScanContext);
  if (!context) {
    throw new Error('useScan must be used within ScanProvider');
  }
  return context;
};
