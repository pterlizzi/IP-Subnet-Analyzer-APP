import React, { useState } from 'react';
import { Table, Search, Copy, Check, ArrowUpRight } from 'lucide-react';
import { getIPv4CidrTable, CIDRTableEntry } from '../utils/ipEngine.ts';

interface CidrCheatSheetProps {
  onSelectCidr: (prefix: number) => void;
}

export const CidrCheatSheet: React.FC<CidrCheatSheetProps> = ({ onSelectCidr }) => {
  const [search, setSearch] = useState('');
  const [filterClass, setFilterClass] = useState<string>('all');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const fullTable = getIPv4CidrTable();

  const filtered = fullTable.filter((item) => {
    const matchesSearch =
      item.prefix.toString().includes(search) ||
      item.subnetMask.includes(search) ||
      item.wildcardMask.includes(search) ||
      item.usageNotes.toLowerCase().includes(search.toLowerCase());

    const matchesClass =
      filterClass === 'all' ||
      (filterClass === 'Class A' && item.classType === 'Class A') ||
      (filterClass === 'Class B' && item.classType === 'Class B') ||
      (filterClass === 'Class C' && item.classType === 'Class C');

    return matchesSearch && matchesClass;
  });

  const copyText = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1500);
  };

  return (
    <div className="space-y-6">
      {/* Search and Filters */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Table className="w-5 h-5 text-indigo-400" />
              <h2 className="text-base font-bold text-white tracking-tight">IPv4 Subnet &amp; CIDR Cheat Sheet</h2>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Complete reference matrix from /0 to /32 with subnet masks, wildcard masks, and host capacities.
            </p>
          </div>

          <div className="flex items-center gap-2">
            {['all', 'Class A', 'Class B', 'Class C'].map((cls) => (
              <button
                key={cls}
                onClick={() => setFilterClass(cls)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                  filterClass === cls
                    ? 'bg-indigo-600 text-white'
                    : 'bg-slate-950 text-slate-400 hover:text-white border border-slate-800'
                }`}
              >
                {cls === 'all' ? 'All Prefixes' : cls}
              </button>
            ))}
          </div>
        </div>

        <div className="mt-4 relative">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
            <Search className="w-3.5 h-3.5" />
          </div>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by prefix (/24), subnet mask (255.255...), or use case..."
            className="w-full pl-9 pr-4 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white font-mono text-xs placeholder-slate-500 focus:outline-none focus:border-indigo-500"
          />
        </div>
      </div>

      {/* Table */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 font-medium border-b border-slate-800">
              <tr>
                <th className="px-4 py-3 w-16">CIDR</th>
                <th className="px-4 py-3">Subnet Mask</th>
                <th className="px-4 py-3">Wildcard Mask</th>
                <th className="px-4 py-3 text-right">Total IPs</th>
                <th className="px-4 py-3 text-right">Usable Hosts</th>
                <th className="px-4 py-3">Use Case &amp; Notes</th>
                <th className="px-4 py-3 text-right w-20">Select</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 font-mono">
              {filtered.map((item) => {
                const isHighlight = item.prefix === 24 || item.prefix === 16 || item.prefix === 8;
                return (
                  <tr
                    key={item.prefix}
                    className={`hover:bg-slate-800/40 transition-colors ${
                      isHighlight ? 'bg-indigo-950/10' : ''
                    }`}
                  >
                    <td className="px-4 py-2.5 font-bold text-indigo-300">
                      /{item.prefix}
                    </td>
                    <td className="px-4 py-2.5 text-slate-200">
                      <div className="flex items-center gap-1.5">
                        <span>{item.subnetMask}</span>
                        <button
                          onClick={() => copyText(item.subnetMask, `sm_${item.prefix}`)}
                          className="text-slate-500 hover:text-slate-300 p-0.5"
                          title="Copy Subnet Mask"
                        >
                          {copiedKey === `sm_${item.prefix}` ? (
                            <Check className="w-3 h-3 text-emerald-400" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      </div>
                    </td>
                    <td className="px-4 py-2.5 text-amber-300">
                      <div className="flex items-center gap-1.5">
                        <span>{item.wildcardMask}</span>
                        <button
                          onClick={() => copyText(item.wildcardMask, `wc_${item.prefix}`)}
                          className="text-slate-500 hover:text-slate-300 p-0.5"
                          title="Copy Wildcard Mask"
                        >
                          {copiedKey === `wc_${item.prefix}` ? (
                            <Check className="w-3 h-3 text-emerald-400" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      </div>
                    </td>
                    <td className="px-4 py-2.5 text-right text-slate-400 tabular-nums">
                      {typeof item.totalIps === 'number'
                        ? item.totalIps.toLocaleString()
                        : item.totalIps}
                    </td>
                    <td className="px-4 py-2.5 text-right text-emerald-400 font-bold tabular-nums">
                      {typeof item.usableHosts === 'number'
                        ? item.usableHosts.toLocaleString()
                        : item.usableHosts}
                    </td>
                    <td className="px-4 py-2.5 font-sans text-slate-400 text-2xs">
                      {item.usageNotes}
                    </td>
                    <td className="px-4 py-2.5 text-right font-sans">
                      <button
                        onClick={() => onSelectCidr(item.prefix)}
                        className="px-2 py-1 rounded bg-slate-800 hover:bg-indigo-600 text-slate-300 hover:text-white transition-colors text-2xs flex items-center gap-1 ml-auto"
                      >
                        <span>Apply</span>
                        <ArrowUpRight className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
