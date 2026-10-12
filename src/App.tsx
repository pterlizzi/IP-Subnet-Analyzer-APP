import React, { useState, useMemo } from 'react';
import { Navbar } from './components/Navbar.tsx';
import { SingleAnalysis } from './components/SingleAnalysis.tsx';
import { BitVisualizer } from './components/BitVisualizer.tsx';
import { SubnetSlicer } from './components/SubnetSlicer.tsx';
import { CidrCheatSheet } from './components/CidrCheatSheet.tsx';
import { BatchAnalyzer } from './components/BatchAnalyzer.tsx';
import { RawJsonView } from './components/RawJsonView.tsx';
import { analyzeIP } from './utils/ipEngine.ts';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('analyzer');
  const [input, setInput] = useState<string>('192.168.1.45/24');
  const [ipv4Default, setIpv4Default] = useState<'32' | 'classful'>('32');
  const [ipv6Default, setIpv6Default] = useState<'128' | '64'>('128');
  const [copied, setCopied] = useState<boolean>(false);

  // Compute analysis output reactively
  const { result, advanced } = useMemo(() => {
    return analyzeIP(input, {
      ipv4DefaultPrefix: ipv4Default,
      ipv6DefaultPrefix: ipv6Default,
    });
  }, [input, ipv4Default, ipv6Default]);

  // Global Copy JSON
  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(result, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  // Adjust CIDR prefix from visualizer
  const handlePrefixChange = (newPrefix: number) => {
    const baseIp = result.input_ip || input.split('/')[0].trim();
    setInput(`${baseIp}/${newPrefix}`);
  };

  // Select subnet from slicer
  const handleSelectSlice = (cidr: string) => {
    setInput(cidr);
    setActiveTab('analyzer');
  };

  // Apply CIDR prefix from cheat sheet
  const handleSelectCidr = (prefix: number) => {
    const baseIp = result.input_ip || (input.includes('/') ? input.split('/')[0].trim() : '192.168.1.1');
    setInput(`${baseIp}/${prefix}`);
    setActiveTab('analyzer');
  };

  // Select IP from batch mode
  const handleSelectBatchIp = (selectedIp: string) => {
    setInput(selectedIp);
    setActiveTab('analyzer');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-indigo-500 selection:text-white">
      {/* Top Bar Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onCopyJson={handleCopyJson}
        copied={copied}
      />

      {/* Main Content Viewport */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'analyzer' && (
          <SingleAnalysis
            input={input}
            setInput={setInput}
            result={result}
            advanced={advanced}
            ipv4Default={ipv4Default}
            setIpv4Default={setIpv4Default}
            ipv6Default={ipv6Default}
            setIpv6Default={setIpv6Default}
          />
        )}

        {activeTab === 'visualizer' && (
          <BitVisualizer
            result={result}
            advanced={advanced}
            onPrefixChange={handlePrefixChange}
          />
        )}

        {activeTab === 'slicer' && (
          <SubnetSlicer
            result={result}
            advanced={advanced}
            onSelectSlice={handleSelectSlice}
          />
        )}

        {activeTab === 'cheatsheet' && (
          <CidrCheatSheet onSelectCidr={handleSelectCidr} />
        )}

        {activeTab === 'batch' && (
          <BatchAnalyzer onSelectIp={handleSelectBatchIp} />
        )}

        {activeTab === 'raw_json' && (
          <RawJsonView result={result} />
        )}
      </main>

      {/* Clean Editorial Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 py-5 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span>RFC Network Specifications</span>
            <span>·</span>
            <span>RFC 791</span>
            <span>·</span>
            <span>RFC 1918</span>
            <span>·</span>
            <span>RFC 4193</span>
            <span>·</span>
            <span>RFC 4291</span>
            <span>·</span>
            <span>RFC 6598</span>
          </div>
          <div>
            <span>Deterministic IEEE &amp; IETF Networking Architecture</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
