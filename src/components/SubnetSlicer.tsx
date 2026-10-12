import React, { useState } from 'react';
import { Layers, Copy, Check, Download, ArrowUpRight } from 'lucide-react';
import { IPAnalysisResult, AdvancedNetworkDetails, calculateSubnetSlices } from '../utils/ipEngine.ts';

interface SubnetSlicerProps {
  result: IPAnalysisResult;
  advanced: AdvancedNetworkDetails | null;
  onSelectSlice: (cidr: string) => void;
}

export const SubnetSlicer: React.FC<SubnetSlicerProps> = ({
  result,
  advanced,
  onSelectSlice,
}) => {
  const isIPv4 = result.ip_version === 'IPv4';
  const basePrefix = advanced ? advanced.prefix_length : 24;

  const [targetPrefix, setTargetPrefix] = useState<number>(Math.min(basePrefix + 1, 30));
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  if (!isIPv4 || result.status !== 'valid' || !advanced) {
    return (
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-8 text-center text-slate-400">
        <Layers className="w-10 h-10 mx-auto text-slate-600 mb-3" />
        <p className="text-sm font-medium text-slate-300">IPv4 Subnet Slicer</p>
        <p className="text-xs text-slate-500 mt-1">
          {result.ip_version === 'IPv6'
            ? 'IPv6 hierarchical delegation is typically done by 4-bit nibble boundaries (/48, /52, /56, /60, /64). Please analyze an IPv4 subnet to slice.'
            : 'Enter a valid IPv4 network in the analyzer to slice it into smaller subnets.'}
        </p>
      </div>
    );
  }

  // Ensure targetPrefix is greater than basePrefix
  const validTarget = Math.max(targetPrefix, basePrefix + 1);
  const slices = calculateSubnetSlices(result.network_address, basePrefix, validTarget, 64);
  const totalSubnets = Math.pow(2, validTarget - basePrefix);

  const copySlice = (cidr: string, idx: number) => {
    navigator.clipboard.writeText(cidr);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 1500);
  };

  const exportCsv = () => {
    const headers = ['Subnet #', 'CIDR', 'Network Address', 'Broadcast Address', 'Usable Start', 'Usable End', 'Usable Hosts'];
    const rows = slices.map((s) => [
      s.index,
      s.cidr,
      s.network_address,
      s.broadcast_address,
      s.usable_start,
      s.usable_end,
      s.usable_hosts,
    ]);

    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `subnets_${result.network_address}_slash${validTarget}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="space-y-6">
      {/* Configuration Card */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
          <div>
            <div className="flex items-center gap-2">
              <Layers className="w-5 h-5 text-indigo-400" />
              <h2 className="text-base font-bold text-white tracking-tight">Subnet Slicer (VLSM Partitioning)</h2>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Partition <span className="font-mono text-indigo-300 font-semibold">{result.cidr_notation}</span> into smaller subnets for departments, DMZs, or VLANs.
            </p>
          </div>

          <button
            onClick={exportCsv}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors shrink-0"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </button>
        </div>

        {/* Slice Target Prefix Selector */}
        <div className="flex flex-wrap items-center gap-2 pt-2">
          <span className="text-xs text-slate-400 font-medium">Slice Into:</span>
          {Array.from({ length: 32 - basePrefix }, (_, i) => basePrefix + 1 + i).map((p) => {
            const count = Math.pow(2, p - basePrefix);
            const isSelected = p === validTarget;
            return (
              <button
                key={p}
                onClick={() => setTargetPrefix(p)}
                className={`px-3 py-1.5 rounded-md text-xs font-mono font-medium transition-colors ${
                  isSelected
                    ? 'bg-indigo-600 text-white shadow-xs'
                    : 'bg-slate-950 text-slate-300 hover:bg-slate-800 border border-slate-800'
                }`}
              >
                /{p} ({count.toLocaleString()} {count === 1 ? 'subnet' : 'subnets'})
              </button>
            );
          })}
        </div>
      </div>

      {/* Slices Table */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="px-5 py-3 border-b border-slate-800 bg-slate-950/50 flex items-center justify-between">
          <span className="text-xs font-semibold text-slate-300">
            Generated Subnets ({slices.length} of {totalSubnets.toLocaleString()})
          </span>
          <span className="text-xs text-slate-500 font-mono">
            {slices[0]?.usable_hosts} usable hosts per subnet
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 font-medium border-b border-slate-800">
              <tr>
                <th className="px-4 py-2.5 w-16">#</th>
                <th className="px-4 py-2.5">Subnet CIDR</th>
                <th className="px-4 py-2.5">Usable Host Range</th>
                <th className="px-4 py-2.5">Broadcast</th>
                <th className="px-4 py-2.5 text-right">Usable Hosts</th>
                <th className="px-4 py-2.5 text-right w-24">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 font-mono">
              {slices.map((slice) => (
                <tr key={slice.index} className="hover:bg-slate-800/40 transition-colors">
                  <td className="px-4 py-2.5 text-slate-500">{slice.index}</td>
                  <td className="px-4 py-2.5 text-indigo-300 font-semibold">{slice.cidr}</td>
                  <td className="px-4 py-2.5 text-slate-300">
                    {slice.usable_start} &rarr; {slice.usable_end}
                  </td>
                  <td className="px-4 py-2.5 text-slate-400">{slice.broadcast_address}</td>
                  <td className="px-4 py-2.5 text-right text-emerald-400 font-bold tabular-nums">
                    {typeof slice.usable_hosts === 'number'
                      ? slice.usable_hosts.toLocaleString()
                      : slice.usable_hosts}
                  </td>
                  <td className="px-4 py-2.5 text-right">
                    <div className="flex items-center justify-end gap-1 font-sans">
                      <button
                        onClick={() => copySlice(slice.cidr, slice.index)}
                        className="p-1 text-slate-400 hover:text-white rounded hover:bg-slate-800 transition-colors"
                        title="Copy CIDR"
                      >
                        {copiedIndex === slice.index ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                      <button
                        onClick={() => onSelectSlice(slice.cidr)}
                        className="p-1 text-indigo-400 hover:text-indigo-300 rounded hover:bg-slate-800 transition-colors"
                        title="Analyze in Engine"
                      >
                        <ArrowUpRight className="w-3.5 h-3.5" />
                      </button>
                    </div>
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
