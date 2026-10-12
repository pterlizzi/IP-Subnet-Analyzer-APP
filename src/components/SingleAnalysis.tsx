import React, { useState } from 'react';
import {
  Copy,
  Check,
  Globe,
  ShieldCheck,
  Terminal,
  Share2,
  FileCode2,
  AlertCircle,
  HelpCircle,
  ArrowRight,
  Database,
  Search,
  RotateCcw,
} from 'lucide-react';
import { IPAnalysisResult, AdvancedNetworkDetails } from '../utils/ipEngine.ts';

interface SingleAnalysisProps {
  input: string;
  setInput: (val: string) => void;
  result: IPAnalysisResult;
  advanced: AdvancedNetworkDetails | null;
  ipv4Default: "32" | "classful";
  setIpv4Default: (val: "32" | "classful") => void;
  ipv6Default: "128" | "64";
  setIpv6Default: (val: "128" | "64") => void;
}

const PRESETS = [
  { label: '192.168.1.45/24', desc: 'RFC 1918 Private C' },
  { label: '10.0.0.1/8', desc: 'RFC 1918 Enterprise A' },
  { label: '172.16.50.1/20', desc: 'RFC 1918 Subnet B' },
  { label: '100.64.1.1/10', desc: 'RFC 6598 CGNAT' },
  { label: '169.254.10.20/16', desc: 'RFC 3927 APIPA' },
  { label: '1.1.1.1/32', desc: 'Public DNS Host' },
  { label: '2001:db8::1/64', desc: 'RFC 3849 IPv6 Doc' },
  { label: 'fd12:3456:789a:1::1/64', desc: 'RFC 4193 IPv6 ULA' },
  { label: 'fe80::1/64', desc: 'RFC 4291 Link-Local' },
  { label: '::ffff:192.168.1.45/120', desc: 'IPv4-Mapped IPv6' },
];

export const SingleAnalysis: React.FC<SingleAnalysisProps> = ({
  input,
  setInput,
  result,
  advanced,
  ipv4Default,
  setIpv4Default,
  ipv6Default,
  setIpv6Default,
}) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => {
      setCopiedKey((prev) => (prev === key ? null : prev));
    }, 1800);
  };

  const getScopeBadgeColor = (scope: string) => {
    switch (scope) {
      case 'Private':
        return 'text-emerald-400 border-emerald-500/30 bg-emerald-950/20';
      case 'Public':
        return 'text-sky-400 border-sky-500/30 bg-sky-950/20';
      case 'Loopback':
        return 'text-amber-400 border-amber-500/30 bg-amber-950/20';
      case 'Link-Local':
        return 'text-purple-400 border-purple-500/30 bg-purple-950/20';
      case 'Multicast':
        return 'text-rose-400 border-rose-500/30 bg-rose-950/20';
      default:
        return 'text-slate-400 border-slate-700 bg-slate-900/50';
    }
  };

  return (
    <div className="space-y-6">
      {/* Search and Input Bar */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
          <div>
            <h1 className="text-xl font-bold text-white tracking-tight">IP Analysis &amp; Subnet Engine</h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Parse, validate, and compute RFC-compliant network parameters, wildcard masks, and reverse PTR records.
            </p>
          </div>

          {/* Engine Context Defaults */}
          <div className="flex flex-wrap items-center gap-3 text-xs">
            <div className="flex items-center gap-1.5 bg-slate-950 px-2.5 py-1.5 rounded-lg border border-slate-800">
              <span className="text-slate-400">IPv4 Default:</span>
              <button
                onClick={() => setIpv4Default('32')}
                className={`px-2 py-0.5 rounded text-xs font-medium transition-colors ${
                  ipv4Default === '32'
                    ? 'bg-indigo-600 text-white'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                /32 (Host)
              </button>
              <button
                onClick={() => setIpv4Default('classful')}
                className={`px-2 py-0.5 rounded text-xs font-medium transition-colors ${
                  ipv4Default === 'classful'
                    ? 'bg-indigo-600 text-white'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Classful
              </button>
            </div>

            <div className="flex items-center gap-1.5 bg-slate-950 px-2.5 py-1.5 rounded-lg border border-slate-800">
              <span className="text-slate-400">IPv6 Default:</span>
              <button
                onClick={() => setIpv6Default('128')}
                className={`px-2 py-0.5 rounded text-xs font-medium transition-colors ${
                  ipv6Default === '128'
                    ? 'bg-indigo-600 text-white'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                /128 (Host)
              </button>
              <button
                onClick={() => setIpv6Default('64')}
                className={`px-2 py-0.5 rounded text-xs font-medium transition-colors ${
                  ipv6Default === '64'
                    ? 'bg-indigo-600 text-white'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                /64 (Subnet)
              </button>
            </div>
          </div>
        </div>

        {/* Input Box */}
        <div className="relative">
          <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
            <Search className="w-4 h-4" />
          </div>
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Enter IP or CIDR (e.g. 192.168.1.45/24, 10.0.0.1, 2001:db8::1/64)"
            className="w-full pl-10 pr-24 py-3 bg-slate-950 border border-slate-700 rounded-lg text-white font-mono text-sm placeholder-slate-500 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-colors"
          />
          {input && (
            <div className="absolute inset-y-0 right-0 pr-2.5 flex items-center gap-1">
              <button
                onClick={() => setInput('')}
                className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded transition-colors"
                title="Clear input"
              >
                <RotateCcw className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
        </div>

        {/* Presets Strip */}
        <div className="mt-3 flex items-center gap-1.5 overflow-x-auto pb-1 text-xs">
          <span className="text-slate-400 shrink-0 mr-1 font-medium">Quick Presets:</span>
          {PRESETS.map((preset) => (
            <button
              key={preset.label}
              onClick={() => setInput(preset.label)}
              className="px-2.5 py-1 bg-slate-950 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 hover:border-slate-700 rounded font-mono text-xs transition-colors shrink-0 whitespace-nowrap cursor-pointer"
            >
              {preset.label}
            </button>
          ))}
        </div>
      </div>

      {/* Validation Error State */}
      {result.status === 'invalid' && (
        <div className="bg-rose-950/30 border border-rose-800/60 rounded-xl p-5 text-rose-200">
          <div className="flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            <div>
              <h2 className="text-sm font-semibold text-rose-300">Invalid IP Address / Notation</h2>
              <p className="text-xs text-rose-200/90 mt-1 font-mono">{result.error_message}</p>
              <p className="text-xs text-slate-400 mt-2">
                Examples of valid input formats:
                <span className="block mt-1 font-mono text-slate-300">
                  IPv4: 192.168.1.1, 192.168.1.45/24, 10.0.0.1/8, 172.16.0.1 255.255.0.0
                </span>
                <span className="block font-mono text-slate-300">
                  IPv6: 2001:db8::1, 2001:db8::1/64, fe80::1, ::1/128, ::ffff:192.168.1.1/120
                </span>
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Valid Analysis Overview */}
      {result.status === 'valid' && (
        <>
          {/* Classification & RFC Banner */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <span
                className={`px-3 py-1 text-xs font-semibold rounded-md border ${getScopeBadgeColor(
                  result.scope
                )}`}
              >
                {result.scope} Scope
              </span>
              <div className="text-xs text-slate-400">
                <span className="font-semibold text-slate-200">{result.ip_version}</span>
                <span className="mx-2">·</span>
                <span className="text-indigo-400 font-mono font-medium">{result.rfc_reference}</span>
                {advanced && (
                  <>
                    <span className="mx-2">·</span>
                    <span className="text-slate-300">{advanced.classification_details.category}</span>
                  </>
                )}
              </div>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400 font-mono">
                Prefix: /{advanced?.prefix_length} ({advanced?.host_bits} host bits)
              </span>
            </div>
          </div>

          {/* Primary Metrics Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Network Address & CIDR */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
              <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                <span>Network Address</span>
                <button
                  onClick={() => copyToClipboard(result.network_address, 'net')}
                  className="hover:text-slate-200 transition-colors"
                  title="Copy"
                >
                  {copiedKey === 'net' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
              <div className="font-mono text-base font-bold text-white break-all">{result.network_address}</div>
              <div className="mt-2 text-xs text-indigo-400 font-mono flex items-center justify-between">
                <span>CIDR: {result.cidr_notation}</span>
                <button
                  onClick={() => copyToClipboard(result.cidr_notation, 'cidr')}
                  className="hover:text-indigo-300 transition-colors"
                >
                  {copiedKey === 'cidr' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                </button>
              </div>
            </div>

            {/* Usable Host Range */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
              <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                <span>Usable Host Range</span>
                <button
                  onClick={() => copyToClipboard(`${result.usable_host_range.start} - ${result.usable_host_range.end}`, 'range')}
                  className="hover:text-slate-200 transition-colors"
                  title="Copy Range"
                >
                  {copiedKey === 'range' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
              <div className="font-mono text-xs font-semibold text-slate-200 truncate">
                <span className="text-slate-400">From:</span> {result.usable_host_range.start || 'N/A'}
              </div>
              <div className="font-mono text-xs font-semibold text-slate-200 truncate mt-1">
                <span className="text-slate-400">To:</span> {result.usable_host_range.end || 'N/A'}
              </div>
              <div className="mt-2 text-xs text-slate-400">
                Range excludes network and broadcast
              </div>
            </div>

            {/* Usable Hosts / Total Capacity */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
              <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                <span>Usable Hosts</span>
                <span className="text-slate-500 font-mono">
                  {typeof result.total_ips === 'number'
                    ? `${result.total_ips.toLocaleString()} Total`
                    : 'Total IPs'}
                </span>
              </div>
              <div className="font-mono text-lg font-bold text-emerald-400 tabular-nums">
                {typeof result.usable_hosts === 'number'
                  ? result.usable_hosts.toLocaleString()
                  : result.usable_hosts}
              </div>
              <div className="mt-1.5 text-xs text-slate-400 font-mono truncate">
                Total IPs: {typeof result.total_ips === 'number' ? result.total_ips.toLocaleString() : result.total_ips}
              </div>
            </div>

            {/* Subnet Mask & Wildcard */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
              <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                <span>Subnet Mask</span>
                <button
                  onClick={() => copyToClipboard(result.subnet_mask, 'mask')}
                  className="hover:text-slate-200 transition-colors"
                >
                  {copiedKey === 'mask' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
              <div className="font-mono text-xs font-bold text-white break-all">{result.subnet_mask}</div>
              <div className="mt-2 flex items-center justify-between text-xs text-amber-400 font-mono">
                <span>Wildcard: {result.wildcard_mask || 'N/A (IPv6)'}</span>
                {result.wildcard_mask && (
                  <button
                    onClick={() => copyToClipboard(result.wildcard_mask!, 'wildcard')}
                    className="hover:text-amber-300 transition-colors"
                    title="Copy Wildcard Mask"
                  >
                    {copiedKey === 'wildcard' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Secondary Details Table */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Hardware & Cisco ACL Box */}
            <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-indigo-400" />
                  <h3 className="text-sm font-semibold text-white">Hardware ACL &amp; Routing Statements</h3>
                </div>
                <span className="text-xs text-slate-400">Cisco IOS / Juniper</span>
              </div>

              {/* Wildcard Mask Statement */}
              {result.wildcard_mask && (
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                    <span>Cisco Wildcard Mask (OSPF / ACL)</span>
                    <button
                      onClick={() => copyToClipboard(result.wildcard_mask!, 'wc_stmt')}
                      className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1"
                    >
                      {copiedKey === 'wc_stmt' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>Copy</span>
                    </button>
                  </div>
                  <div className="font-mono text-xs text-emerald-300 font-semibold">{result.wildcard_mask}</div>
                </div>
              )}

              {/* Cisco ACL Standard */}
              {advanced && (
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                    <span>Cisco Access-List Statement</span>
                    <button
                      onClick={() => copyToClipboard(advanced.cisco_acl_standard, 'cisco_std')}
                      className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1"
                    >
                      {copiedKey === 'cisco_std' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>Copy</span>
                    </button>
                  </div>
                  <div className="font-mono text-xs text-slate-200 select-all">{advanced.cisco_acl_standard}</div>
                </div>
              )}

              {/* Cisco OSPF */}
              {advanced && (
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                    <span>Cisco OSPF Statement</span>
                    <button
                      onClick={() => copyToClipboard(advanced.cisco_ospf_statement, 'cisco_ospf')}
                      className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1"
                    >
                      {copiedKey === 'cisco_ospf' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>Copy</span>
                    </button>
                  </div>
                  <div className="font-mono text-xs text-slate-200 select-all">{advanced.cisco_ospf_statement}</div>
                </div>
              )}

              {/* Juniper */}
              {advanced && (
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                    <span>Juniper Route Prefix</span>
                    <button
                      onClick={() => copyToClipboard(advanced.juniper_syntax, 'juniper')}
                      className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1"
                    >
                      {copiedKey === 'juniper' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>Copy</span>
                    </button>
                  </div>
                  <div className="font-mono text-xs text-slate-200 select-all">{advanced.juniper_syntax}</div>
                </div>
              )}
            </div>

            {/* DNS, Database & Format Conversions */}
            <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Globe className="w-4 h-4 text-indigo-400" />
                  <h3 className="text-sm font-semibold text-white">DNS &amp; Integer Representations</h3>
                </div>
                <span className="text-xs text-slate-400">PTR / DB Int / Hex</span>
              </div>

              {/* Reverse DNS PTR Record */}
              {advanced && (
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                    <span>Reverse DNS (PTR Record)</span>
                    <button
                      onClick={() => copyToClipboard(advanced.reverse_dns_ptr, 'ptr')}
                      className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1"
                    >
                      {copiedKey === 'ptr' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>Copy</span>
                    </button>
                  </div>
                  <div className="font-mono text-xs text-sky-300 break-all select-all">
                    {advanced.reverse_dns_ptr}
                  </div>
                </div>
              )}

              {/* Hex and Integer Values */}
              {advanced && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                      <span>Hexadecimal</span>
                      <button
                        onClick={() => copyToClipboard(result.hex_representation, 'hex')}
                        className="text-xs text-indigo-400 hover:text-indigo-300"
                      >
                        {copiedKey === 'hex' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>
                    <div className="font-mono text-xs text-amber-300 truncate font-semibold">
                      {result.hex_representation}
                    </div>
                    <div className="text-2xs text-slate-500 font-mono mt-0.5">{advanced.hex_prefixed}</div>
                  </div>

                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                      <span>Integer (Decimal)</span>
                      <button
                        onClick={() => copyToClipboard(advanced.integer_value, 'int_val')}
                        className="text-xs text-indigo-400 hover:text-indigo-300"
                      >
                        {copiedKey === 'int_val' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>
                    <div className="font-mono text-xs text-emerald-300 truncate font-semibold">
                      {advanced.integer_value}
                    </div>
                    <div className="text-2xs text-slate-500 mt-0.5">Database storage format</div>
                  </div>
                </div>
              )}

              {/* 6to4 & IPv4-Mapped Check */}
              {advanced?.ipv4_mapped_ipv6 && (
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                    <span>IPv4-Mapped IPv6 Representation</span>
                    <button
                      onClick={() => copyToClipboard(advanced.ipv4_mapped_ipv6!, 'mapped')}
                      className="text-xs text-indigo-400 hover:text-indigo-300"
                    >
                      {copiedKey === 'mapped' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                  <div className="font-mono text-xs text-slate-200 select-all">
                    {advanced.ipv4_mapped_ipv6}
                  </div>
                  {advanced.six_to_four_prefix && (
                    <div className="mt-2 pt-2 border-t border-slate-900 text-xs text-slate-400 font-mono">
                      <span className="text-slate-500">6to4 Prefix: </span>
                      <span className="text-slate-300">{advanced.six_to_four_prefix}</span>
                    </div>
                  )}
                </div>
              )}

              {/* If IPv6: Show Compressed vs Expanded */}
              {result.ip_version === 'IPv6' && result.ipv6_details && (
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-2">
                  <div>
                    <div className="flex items-center justify-between text-xs text-slate-400 mb-0.5">
                      <span>RFC 5952 Compressed Form</span>
                      <button
                        onClick={() => copyToClipboard(result.ipv6_details.compressed || '', 'v6_comp')}
                        className="text-xs text-indigo-400 hover:text-indigo-300"
                      >
                        {copiedKey === 'v6_comp' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>
                    <div className="font-mono text-xs text-indigo-300 break-all select-all">
                      {result.ipv6_details.compressed}
                    </div>
                  </div>

                  <div className="pt-2 border-t border-slate-900">
                    <div className="flex items-center justify-between text-xs text-slate-400 mb-0.5">
                      <span>Expanded Form (Log Matching)</span>
                      <button
                        onClick={() => copyToClipboard(result.ipv6_details.expanded || '', 'v6_exp')}
                        className="text-xs text-indigo-400 hover:text-indigo-300"
                      >
                        {copiedKey === 'v6_exp' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>
                    <div className="font-mono text-xs text-slate-300 break-all select-all">
                      {result.ipv6_details.expanded}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Binary Bitstream Breakdown */}
          <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-5">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <FileCode2 className="w-4 h-4 text-indigo-400" />
                <h3 className="text-sm font-semibold text-white">Binary Representation</h3>
              </div>
              <button
                onClick={() => copyToClipboard(result.binary_representation, 'bin_rep')}
                className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1"
              >
                {copiedKey === 'bin_rep' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>Copy Binary</span>
              </button>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-xs text-slate-300 break-all tracking-wider select-all">
              {result.binary_representation}
            </div>
          </div>
        </>
      )}
    </div>
  );
};
