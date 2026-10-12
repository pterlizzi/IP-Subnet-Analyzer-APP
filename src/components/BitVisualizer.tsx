import React from 'react';
import { Binary, Sliders, Info } from 'lucide-react';
import { IPAnalysisResult, AdvancedNetworkDetails } from '../utils/ipEngine.ts';

interface BitVisualizerProps {
  result: IPAnalysisResult;
  advanced: AdvancedNetworkDetails | null;
  onPrefixChange: (newPrefix: number) => void;
}

export const BitVisualizer: React.FC<BitVisualizerProps> = ({
  result,
  advanced,
  onPrefixChange,
}) => {
  if (result.status !== 'valid' || !advanced) {
    return (
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-8 text-center text-slate-400">
        <Binary className="w-10 h-10 mx-auto text-slate-600 mb-3" />
        <p className="text-sm font-medium text-slate-300">No Valid IP Analyzed</p>
        <p className="text-xs text-slate-500 mt-1">Please enter a valid IP address in the analyzer first.</p>
      </div>
    );
  }

  const isIPv4 = result.ip_version === 'IPv4';
  const prefix = advanced.prefix_length;
  const maxPrefix = isIPv4 ? 32 : 128;

  // Extract raw bit strings without separators
  const rawBits = result.binary_representation.replace(/[.:]/g, '');

  return (
    <div className="space-y-6">
      {/* Header and Controller */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-5">
          <div>
            <div className="flex items-center gap-2">
              <Binary className="w-5 h-5 text-indigo-400" />
              <h2 className="text-base font-bold text-white tracking-tight">Interactive Bit-Level Visualizer</h2>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Visualize exact bit allocation between Network Prefix ({prefix} bits) and Host Identifier ({advanced.host_bits} bits).
            </p>
          </div>

          <div className="flex items-center gap-4 text-xs font-mono bg-slate-950 px-3 py-2 rounded-lg border border-slate-800">
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-xs bg-indigo-500"></span>
              <span className="text-indigo-300 font-semibold">Network: /{prefix}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-xs bg-emerald-500"></span>
              <span className="text-emerald-300 font-semibold">Host: {advanced.host_bits} bits</span>
            </div>
          </div>
        </div>

        {/* Interactive Prefix Slider */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span className="flex items-center gap-1">
              <Sliders className="w-3.5 h-3.5" /> Adjust CIDR Prefix Length
            </span>
            <span className="font-mono text-indigo-400 font-bold text-sm">/{prefix}</span>
          </div>
          <input
            type="range"
            min={0}
            max={maxPrefix}
            value={prefix}
            onChange={(e) => onPrefixChange(parseInt(e.target.value, 10))}
            className="w-full h-2 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-indigo-500"
          />
          <div className="flex justify-between text-2xs text-slate-500 font-mono">
            <span>/0 (Internet)</span>
            {isIPv4 ? (
              <>
                <span>/8 (Class A)</span>
                <span>/16 (Class B)</span>
                <span>/24 (Class C)</span>
                <span>/30 (P2P)</span>
                <span>/32 (Host)</span>
              </>
            ) : (
              <>
                <span>/32 (ISP)</span>
                <span>/48 (Site)</span>
                <span>/64 (Standard SLAAC)</span>
                <span>/128 (Host)</span>
              </>
            )}
          </div>
        </div>
      </div>

      {/* IPv4 Bit Matrix */}
      {isIPv4 && (
        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-5 space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[0, 1, 2, 3].map((octetIdx) => {
              const octetBits = rawBits.slice(octetIdx * 8, (octetIdx + 1) * 8);
              const octetVal = parseInt(octetBits, 10);
              const decVal = parseInt(octetBits, 2);

              return (
                <div key={octetIdx} className="bg-slate-950 p-3.5 rounded-lg border border-slate-800">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
                    <span className="font-medium">Octet {octetIdx + 1}</span>
                    <span className="font-mono text-white font-bold">{decVal}</span>
                  </div>

                  {/* 8 Bits Grid */}
                  <div className="grid grid-cols-8 gap-1 text-center font-mono">
                    {octetBits.split('').map((bit, bitIdx) => {
                      const absoluteBitPos = octetIdx * 8 + bitIdx;
                      const isNetworkBit = absoluteBitPos < prefix;
                      const placeValue = Math.pow(2, 7 - bitIdx);

                      return (
                        <div
                          key={bitIdx}
                          className={`p-1 rounded text-xs flex flex-col items-center justify-center transition-colors ${
                            isNetworkBit
                              ? 'bg-indigo-950/80 border border-indigo-700/60 text-indigo-200'
                              : 'bg-emerald-950/80 border border-emerald-700/60 text-emerald-200'
                          }`}
                          title={`Bit ${31 - absoluteBitPos}: Value ${placeValue} (${isNetworkBit ? 'Network' : 'Host'})`}
                        >
                          <span className="text-2xs text-slate-400 mb-0.5">{placeValue}</span>
                          <span className="font-bold text-sm">{bit}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Mask vs Wildcard Bit Alignment Comparison */}
          <div className="space-y-3 pt-2">
            <h3 className="text-xs font-semibold text-slate-300">Bit Mask Alignment Comparison</h3>
            <div className="grid grid-cols-1 gap-2 font-mono text-xs">
              {/* IP */}
              <div className="bg-slate-950 p-2.5 rounded border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <span className="text-slate-400 text-xs w-32 shrink-0">IP Address:</span>
                <span className="text-slate-200 tracking-wider truncate select-all">{result.binary_representation}</span>
                <span className="text-slate-400 text-xs shrink-0 font-medium">{result.input_ip}</span>
              </div>
              {/* Subnet Mask */}
              <div className="bg-slate-950 p-2.5 rounded border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <span className="text-indigo-400 text-xs w-32 shrink-0">Subnet Mask:</span>
                <span className="text-indigo-300 tracking-wider truncate select-all">
                  {[0, 1, 2, 3]
                    .map((o) => {
                      let s = '';
                      for (let b = 0; b < 8; b++) {
                        s += o * 8 + b < prefix ? '1' : '0';
                      }
                      return s;
                    })
                    .join('.')}
                </span>
                <span className="text-indigo-400 text-xs shrink-0 font-medium">{result.subnet_mask}</span>
              </div>
              {/* Wildcard Mask */}
              <div className="bg-slate-950 p-2.5 rounded border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <span className="text-amber-400 text-xs w-32 shrink-0">Wildcard Mask:</span>
                <span className="text-amber-300 tracking-wider truncate select-all">
                  {[0, 1, 2, 3]
                    .map((o) => {
                      let s = '';
                      for (let b = 0; b < 8; b++) {
                        s += o * 8 + b < prefix ? '0' : '1';
                      }
                      return s;
                    })
                    .join('.')}
                </span>
                <span className="text-amber-400 text-xs shrink-0 font-medium">{result.wildcard_mask}</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* IPv6 Bit Matrix */}
      {!isIPv4 && (
        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>128-Bit IPv6 Address Space Breakdown</span>
            <span>Standard SLAAC interface boundary at /64</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            {[0, 1, 2, 3, 4, 5, 6, 7].map((hextetIdx) => {
              const startBit = hextetIdx * 16;
              const endBit = startBit + 16;
              const isAllNetwork = endBit <= prefix;
              const isAllHost = startBit >= prefix;
              const isSplit = !isAllNetwork && !isAllHost;

              const hextetBits = rawBits.slice(startBit, endBit);
              const hexVal = parseInt(hextetBits, 2).toString(16).padStart(4, '0');

              return (
                <div key={hextetIdx} className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="text-slate-400">Hextet {hextetIdx + 1}</span>
                    <span className="font-mono text-white font-bold">{hexVal}</span>
                  </div>
                  <div className="font-mono text-2xs tracking-wider break-all p-1.5 rounded bg-slate-900 text-slate-300">
                    {hextetBits.slice(0, 8)} {hextetBits.slice(8, 16)}
                  </div>
                  <div className="mt-1 text-2xs font-mono">
                    {isAllNetwork && <span className="text-indigo-400">Network Prefix</span>}
                    {isAllHost && <span className="text-emerald-400">Interface / Host ID</span>}
                    {isSplit && <span className="text-amber-400">Boundary Hextet</span>}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
