import React, { useState } from 'react';
import { ListOrdered, Download, Play, CheckCircle2, XCircle, ArrowUpRight, Copy, Check } from 'lucide-react';
import { analyzeIP, IPAnalysisResult } from '../utils/ipEngine.ts';

interface BatchAnalyzerProps {
  onSelectIp: (ip: string) => void;
}

const DEFAULT_BATCH_INPUT = `192.168.1.45/24
10.0.0.1/8
172.16.50.1/20
100.64.1.1/10
169.254.1.1/16
1.1.1.1/32
8.8.8.8/32
2001:db8::1/64
fd12:3456:789a:1::1/64
fe80::1/64
::ffff:192.168.1.1/120
999.999.999.999/24`;

export const BatchAnalyzer: React.FC<BatchAnalyzerProps> = ({ onSelectIp }) => {
  const [rawText, setRawText] = useState<string>(DEFAULT_BATCH_INPUT);
  const [results, setResults] = useState<IPAnalysisResult[]>(() => {
    return DEFAULT_BATCH_INPUT.split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0)
      .map((line) => analyzeIP(line).result);
  });
  const [copiedJson, setCopiedJson] = useState(false);

  const runBatch = () => {
    const lines = rawText
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0);

    const analyzed = lines.map((line) => analyzeIP(line).result);
    setResults(analyzed);
  };

  const validCount = results.filter((r) => r.status === 'valid').length;
  const invalidCount = results.length - validCount;
  const ipv4Count = results.filter((r) => r.status === 'valid' && r.ip_version === 'IPv4').length;
  const ipv6Count = results.filter((r) => r.status === 'valid' && r.ip_version === 'IPv6').length;

  const exportJson = () => {
    const jsonStr = JSON.stringify(results, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `batch_ip_analysis_${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const copyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(results, null, 2));
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 1500);
  };

  const exportCsv = () => {
    const headers = [
      'Status',
      'Version',
      'Input IP',
      'CIDR Notation',
      'Network Address',
      'Subnet Mask',
      'Wildcard Mask',
      'Broadcast',
      'Usable Start',
      'Usable End',
      'Total IPs',
      'Usable Hosts',
      'Scope',
      'RFC Reference',
    ];

    const rows = results.map((r) => [
      r.status,
      r.ip_version,
      r.input_ip,
      r.cidr_notation,
      r.network_address,
      r.subnet_mask,
      r.wildcard_mask || '',
      r.broadcast_address || '',
      r.usable_host_range.start,
      r.usable_host_range.end,
      r.total_ips,
      r.usable_hosts,
      r.scope,
      r.rfc_reference,
    ]);

    const csvContent = [headers.join(','), ...rows.map((row) => row.map((v) => `"${v}"`).join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `batch_ip_analysis_${Date.now()}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Input card */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-3">
          <div>
            <div className="flex items-center gap-2">
              <ListOrdered className="w-5 h-5 text-indigo-400" />
              <h2 className="text-base font-bold text-white tracking-tight">Bulk &amp; Batch IP Analyzer</h2>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Paste a multi-line list of IPv4 and IPv6 addresses or CIDR blocks to batch validate and compute.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={runBatch}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md bg-indigo-600 hover:bg-indigo-500 text-white transition-colors cursor-pointer shadow-sm"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Analyze List</span>
            </button>
            <button
              onClick={copyJson}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
            >
              {copiedJson ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>Copy JSON</span>
            </button>
            <button
              onClick={exportCsv}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>CSV</span>
            </button>
          </div>
        </div>

        <textarea
          rows={6}
          value={rawText}
          onChange={(e) => setRawText(e.target.value)}
          placeholder="Paste IPv4 or IPv6 addresses (one per line)..."
          className="w-full p-3 bg-slate-950 border border-slate-800 rounded-lg text-white font-mono text-xs placeholder-slate-500 focus:outline-none focus:border-indigo-500 leading-relaxed"
        />

        {/* Metrics Strip */}
        <div className="mt-4 grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          <div className="bg-slate-950 p-2.5 rounded border border-slate-800 flex items-center justify-between">
            <span className="text-slate-400">Total Entries:</span>
            <span className="font-mono text-white font-bold">{results.length}</span>
          </div>
          <div className="bg-slate-950 p-2.5 rounded border border-slate-800 flex items-center justify-between">
            <span className="text-emerald-400">Valid:</span>
            <span className="font-mono text-emerald-300 font-bold">{validCount}</span>
          </div>
          <div className="bg-slate-950 p-2.5 rounded border border-slate-800 flex items-center justify-between">
            <span className="text-rose-400">Invalid:</span>
            <span className="font-mono text-rose-300 font-bold">{invalidCount}</span>
          </div>
          <div className="bg-slate-950 p-2.5 rounded border border-slate-800 flex items-center justify-between">
            <span className="text-slate-400">IPv4 / IPv6:</span>
            <span className="font-mono text-indigo-300 font-bold">
              {ipv4Count} / {ipv6Count}
            </span>
          </div>
        </div>
      </div>

      {/* Results Table */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 font-medium border-b border-slate-800">
              <tr>
                <th className="px-4 py-2.5 w-16">Status</th>
                <th className="px-4 py-2.5">Input IP</th>
                <th className="px-4 py-2.5">Network / CIDR</th>
                <th className="px-4 py-2.5">Subnet Mask</th>
                <th className="px-4 py-2.5 text-right">Usable Hosts</th>
                <th className="px-4 py-2.5">Scope</th>
                <th className="px-4 py-2.5">RFC Reference</th>
                <th className="px-4 py-2.5 text-right w-16">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 font-mono">
              {results.map((r, i) => (
                <tr key={i} className="hover:bg-slate-800/40 transition-colors">
                  <td className="px-4 py-2.5">
                    {r.status === 'valid' ? (
                      <span className="flex items-center gap-1 text-emerald-400 text-2xs font-semibold">
                        <CheckCircle2 className="w-3.5 h-3.5" /> OK
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 text-rose-400 text-2xs font-semibold">
                        <XCircle className="w-3.5 h-3.5" /> ERR
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-2.5 font-bold text-white break-all">{r.input_ip}</td>
                  <td className="px-4 py-2.5 text-indigo-300 break-all">{r.cidr_notation || '—'}</td>
                  <td className="px-4 py-2.5 text-slate-300 break-all">{r.subnet_mask || '—'}</td>
                  <td className="px-4 py-2.5 text-right text-emerald-400 font-bold tabular-nums">
                    {r.status === 'valid'
                      ? typeof r.usable_hosts === 'number'
                        ? r.usable_hosts.toLocaleString()
                        : r.usable_hosts
                      : '—'}
                  </td>
                  <td className="px-4 py-2.5 text-slate-300 font-sans">{r.status === 'valid' ? r.scope : '—'}</td>
                  <td className="px-4 py-2.5 text-slate-400 text-2xs">{r.status === 'valid' ? r.rfc_reference : r.error_message}</td>
                  <td className="px-4 py-2.5 text-right font-sans">
                    {r.status === 'valid' && (
                      <button
                        onClick={() => onSelectIp(r.input_ip)}
                        className="p-1 text-indigo-400 hover:text-indigo-300 rounded hover:bg-slate-800 transition-colors"
                        title="Analyze in Engine"
                      >
                        <ArrowUpRight className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
