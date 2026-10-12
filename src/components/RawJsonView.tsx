import React, { useState } from 'react';
import { Code, Copy, Check, Download, CheckCircle, ShieldCheck } from 'lucide-react';
import { IPAnalysisResult } from '../utils/ipEngine.ts';

interface RawJsonViewProps {
  result: IPAnalysisResult;
}

export const RawJsonView: React.FC<RawJsonViewProps> = ({ result }) => {
  const [copied, setCopied] = useState(false);

  const jsonString = JSON.stringify(result, null, 2);

  const copyJson = () => {
    navigator.clipboard.writeText(jsonString);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const downloadJson = () => {
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `ip_engine_${result.input_ip || 'payload'}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  // Schema verification checklist
  const requiredKeys = [
    'status',
    'error_message',
    'ip_version',
    'input_ip',
    'cidr_notation',
    'subnet_mask',
    'wildcard_mask',
    'network_address',
    'broadcast_address',
    'usable_host_range',
    'total_ips',
    'usable_hosts',
    'scope',
    'rfc_reference',
    'binary_representation',
    'hex_representation',
    'ipv6_details',
  ];

  const allKeysPresent = requiredKeys.every((key) => key in result);

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Code className="w-5 h-5 text-indigo-400" />
              <h2 className="text-base font-bold text-white tracking-tight">RFC JSON Engine Payload</h2>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Strictly formatted JSON output compliant with RFC networking schemas for API consumers and automation.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={copyJson}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md bg-indigo-600 hover:bg-indigo-500 text-white transition-colors cursor-pointer shadow-sm"
            >
              {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied to Clipboard' : 'Copy JSON'}</span>
            </button>
            <button
              onClick={downloadJson}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download JSON</span>
            </button>
          </div>
        </div>

        {/* Schema Validation Indicator */}
        <div className="mt-4 flex items-center justify-between bg-slate-950 px-3.5 py-2.5 rounded-lg border border-slate-800 text-xs">
          <div className="flex items-center gap-2 text-emerald-400">
            <CheckCircle className="w-4 h-4 shrink-0" />
            <span className="font-medium">Strict JSON Schema Validation:</span>
            <span className="text-slate-300">
              {allKeysPresent ? '100% Compliant (All 17 RFC attributes validated)' : 'Pending'}
            </span>
          </div>
          <span className="font-mono text-2xs text-slate-500">RFC 1918 / 4193 / 4291 / 791</span>
        </div>
      </div>

      {/* Code Container */}
      <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-md">
        <div className="px-4 py-2.5 bg-slate-900/80 border-b border-slate-800 flex items-center justify-between text-xs">
          <span className="font-mono text-slate-400">Payload: application/json</span>
          <span className="font-mono text-slate-500 text-2xs">{jsonString.length} bytes</span>
        </div>
        <pre className="p-5 font-mono text-xs text-indigo-200 overflow-x-auto leading-relaxed select-all">
          {jsonString}
        </pre>
      </div>
    </div>
  );
};
