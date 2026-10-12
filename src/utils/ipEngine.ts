/**
 * RFC-Compliant IP Address & Networking Analysis Engine
 * Complies with RFC 791, RFC 1918, RFC 3021, RFC 3927, RFC 4193, RFC 4291, RFC 5952, RFC 6598
 */

export type IPScope = "Public" | "Private" | "Loopback" | "Link-Local" | "Multicast" | "Reserved";

export interface IPAnalysisResult {
  status: "valid" | "invalid";
  error_message: null | string;
  ip_version: "IPv4" | "IPv6";
  input_ip: string;
  cidr_notation: string;
  subnet_mask: string;
  wildcard_mask: string | null;
  network_address: string;
  broadcast_address: string | null;
  usable_host_range: {
    start: string;
    end: string;
  };
  total_ips: number | string;
  usable_hosts: number | string;
  scope: IPScope;
  rfc_reference: string;
  binary_representation: string;
  hex_representation: string;
  ipv6_details: {
    compressed: string | null;
    expanded: string | null;
  };
}

export interface AdvancedNetworkDetails {
  integer_value: string;
  hex_prefixed: string;
  reverse_dns_ptr: string;
  cisco_acl_standard: string;
  cisco_acl_extended: string;
  cisco_ospf_statement: string;
  juniper_syntax: string;
  ipv4_mapped_ipv6?: string;
  six_to_four_prefix?: string;
  embedded_ipv4?: string | null;
  classification_details: {
    category: string;
    description: string;
    rfcs: string[];
    is_special_use: boolean;
  };
  prefix_length: number;
  host_bits: number;
}

export interface SubnetSlice {
  index: number;
  network_address: string;
  cidr: string;
  broadcast_address: string | null;
  usable_start: string;
  usable_end: string;
  usable_hosts: number | string;
}

// ---------------- IPv4 Logic ----------------

function isValidIPv4Octet(val: string): boolean {
  if (!/^\d+$/.test(val)) return false;
  const num = parseInt(val, 10);
  return num >= 0 && num <= 255 && num.toString() === val;
}

export function parseIPv4(ipStr: string): number[] | null {
  const parts = ipStr.trim().split(".");
  if (parts.length !== 4) return null;
  for (const part of parts) {
    if (!isValidIPv4Octet(part)) return null;
  }
  return parts.map((p) => parseInt(p, 10));
}

function ipv4ToUint32(octets: number[]): number {
  return ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
}

function uint32ToIPv4(uint: number): string {
  return [
    (uint >>> 24) & 255,
    (uint >>> 16) & 255,
    (uint >>> 8) & 255,
    uint & 255,
  ].join(".");
}

export function cidrToSubnetMaskIPv4(prefix: number): number[] {
  if (prefix === 0) return [0, 0, 0, 0];
  const mask = (~0 << (32 - prefix)) >>> 0;
  return [
    (mask >>> 24) & 255,
    (mask >>> 16) & 255,
    (mask >>> 8) & 255,
    mask & 255,
  ];
}

function subnetMaskToPrefixIPv4(maskStr: string): number | null {
  const octets = parseIPv4(maskStr);
  if (!octets) return null;
  const uint = ipv4ToUint32(octets);
  // Check contiguous 1s from MSB
  let prefix = 0;
  let seenZero = false;
  for (let i = 31; i >= 0; i--) {
    const bit = (uint >>> i) & 1;
    if (bit === 1) {
      if (seenZero) return null; // non-contiguous
      prefix++;
    } else {
      seenZero = true;
    }
  }
  return prefix;
}

function getClassfulPrefixIPv4(firstOctet: number): number {
  if (firstOctet >= 1 && firstOctet <= 126) return 8; // Class A
  if (firstOctet >= 128 && firstOctet <= 191) return 16; // Class B
  if (firstOctet >= 192 && firstOctet <= 223) return 24; // Class C
  if (firstOctet >= 224 && firstOctet <= 239) return 4; // Class D Multicast
  return 32; // Class E or loopback
}

export interface IPv4ScopeInfo {
  scope: IPScope;
  rfc: string;
  category: string;
  description: string;
  isSpecial: boolean;
}

export function getIPv4Scope(uint: number): IPv4ScopeInfo {
  const o1 = (uint >>> 24) & 255;
  const o2 = (uint >>> 16) & 255;

  // 0.0.0.0/8 - This host on this network
  if (o1 === 0) {
    return {
      scope: "Reserved",
      rfc: "RFC 1122",
      category: "This Network (Local Host)",
      description: "Source address only; reserved for initialization (RFC 1122).",
      isSpecial: true,
    };
  }

  // 10.0.0.0/8 - Private-Use
  if (o1 === 10) {
    return {
      scope: "Private",
      rfc: "RFC 1918",
      category: "Private-Use Networks (Class A)",
      description: "Allocated for private enterprise networks; not routable on the public Internet.",
      isSpecial: true,
    };
  }

  // 100.64.0.0/10 - Shared Address Space / CGNAT
  if (o1 === 100 && o2 >= 64 && o2 <= 127) {
    return {
      scope: "Private",
      rfc: "RFC 6598",
      category: "Carrier-Grade NAT (CGNAT / Shared Address Space)",
      description: "Reserved for service provider NAT deployments to prevent collision with RFC 1918.",
      isSpecial: true,
    };
  }

  // 127.0.0.0/8 - Loopback
  if (o1 === 127) {
    return {
      scope: "Loopback",
      rfc: "RFC 1122",
      category: "Loopback Address Block",
      description: "Host internal communication only; datagrams never leave local device.",
      isSpecial: true,
    };
  }

  // 169.254.0.0/16 - Link-Local / APIPA
  if (o1 === 169 && o2 === 254) {
    return {
      scope: "Link-Local",
      rfc: "RFC 3927",
      category: "Link-Local / APIPA",
      description: "Automatic Private IP Addressing used when DHCP is unavailable.",
      isSpecial: true,
    };
  }

  // 172.16.0.0/12 - Private-Use
  if (o1 === 172 && o2 >= 16 && o2 <= 31) {
    return {
      scope: "Private",
      rfc: "RFC 1918",
      category: "Private-Use Networks (Class B)",
      description: "Allocated for private enterprise networks (RFC 1918).",
      isSpecial: true,
    };
  }

  // 192.0.0.0/24 - IETF Protocol Assignments
  if (o1 === 192 && o2 === 0 && ((uint >>> 8) & 255) === 0) {
    return {
      scope: "Reserved",
      rfc: "RFC 6890",
      category: "IETF Protocol Assignments",
      description: "Reserved for specialized IETF protocol assignments and testing.",
      isSpecial: true,
    };
  }

  // 192.0.2.0/24 - TEST-NET-1 (Documentation)
  if (o1 === 192 && o2 === 0 && ((uint >>> 8) & 255) === 2) {
    return {
      scope: "Reserved",
      rfc: "RFC 5737",
      category: "Documentation (TEST-NET-1)",
      description: "Reserved for documentation and example code; not routable.",
      isSpecial: true,
    };
  }

  // 192.88.99.0/24 - 6to4 Anycast Relay (RFC 7526 Deprecated)
  if (o1 === 192 && o2 === 88 && ((uint >>> 8) & 255) === 99) {
    return {
      scope: "Reserved",
      rfc: "RFC 7526",
      category: "6to4 Relay Anycast (Deprecated)",
      description: "Formerly used for 6to4 relay anycast, deprecated by RFC 7526.",
      isSpecial: true,
    };
  }

  // 192.168.0.0/16 - Private-Use
  if (o1 === 192 && o2 === 168) {
    return {
      scope: "Private",
      rfc: "RFC 1918",
      category: "Private-Use Networks (Class C)",
      description: "Standard private IP block for home and office local area networks.",
      isSpecial: true,
    };
  }

  // 198.18.0.0/15 - Benchmarking
  if (o1 === 198 && (o2 === 18 || o2 === 19)) {
    return {
      scope: "Reserved",
      rfc: "RFC 2544",
      category: "Network Interconnect Device Benchmark Testing",
      description: "Reserved for measuring performance and latency between network devices.",
      isSpecial: true,
    };
  }

  // 198.51.100.0/24 - TEST-NET-2 (Documentation)
  if (o1 === 198 && o2 === 51 && ((uint >>> 8) & 255) === 100) {
    return {
      scope: "Reserved",
      rfc: "RFC 5737",
      category: "Documentation (TEST-NET-2)",
      description: "Reserved for documentation and technical examples.",
      isSpecial: true,
    };
  }

  // 203.0.113.0/24 - TEST-NET-3 (Documentation)
  if (o1 === 203 && o2 === 0 && ((uint >>> 8) & 255) === 113) {
    return {
      scope: "Reserved",
      rfc: "RFC 5737",
      category: "Documentation (TEST-NET-3)",
      description: "Reserved for documentation and technical examples.",
      isSpecial: true,
    };
  }

  // 224.0.0.0/4 - Multicast
  if (o1 >= 224 && o1 <= 239) {
    return {
      scope: "Multicast",
      rfc: "RFC 5771",
      category: "IPv4 Multicast Address Space",
      description: "Used for one-to-many communication groups (RFC 5771 / RFC 1112).",
      isSpecial: true,
    };
  }

  // 240.0.0.0/4 - Reserved (Former Class E)
  if (o1 >= 240) {
    if (uint === 0xffffffff) {
      return {
        scope: "Reserved",
        rfc: "RFC 919",
        category: "Limited Broadcast",
        description: "Local area network limited broadcast address.",
        isSpecial: true,
      };
    }
    return {
      scope: "Reserved",
      rfc: "RFC 1112",
      category: "Reserved for Future Use (Class E)",
      description: "Reserved address space per RFC 1112.",
      isSpecial: true,
    };
  }

  // Public Unicast
  return {
    scope: "Public",
    rfc: "RFC 791",
    category: "Public Internet Unicast",
    description: "Globally routable public Internet IPv4 address.",
    isSpecial: false,
  };
}

// ---------------- IPv6 Logic ----------------

export function parseIPv6(ipStr: string): bigint | null {
  let clean = ipStr.trim().toLowerCase();
  // Strip enclosing brackets if [2001:db8::1]
  if (clean.startsWith("[") && clean.endsWith("]")) {
    clean = clean.slice(1, -1);
  }

  // Check for IPv4-mapped or embedded IPv4, e.g. ::ffff:192.168.1.1
  const lastColon = clean.lastIndexOf(":");
  if (lastColon !== -1) {
    const potentialIpv4 = clean.substring(lastColon + 1);
    if (potentialIpv4.includes(".")) {
      const ipv4Parts = parseIPv4(potentialIpv4);
      if (!ipv4Parts) return null;
      const hex1 = ((ipv4Parts[0] << 8) | ipv4Parts[1]).toString(16);
      const hex2 = ((ipv4Parts[2] << 8) | ipv4Parts[3]).toString(16);
      clean = clean.substring(0, lastColon) + `:${hex1}:${hex2}`;
    }
  }

  if (clean.indexOf(":::") !== -1) return null;

  const doubleColonParts = clean.split("::");
  if (doubleColonParts.length > 2) return null;

  let hextets: number[] = [];

  if (doubleColonParts.length === 2) {
    const leftStr = doubleColonParts[0];
    const rightStr = doubleColonParts[1];

    const left = leftStr ? leftStr.split(":") : [];
    const right = rightStr ? rightStr.split(":") : [];

    for (const h of [...left, ...right]) {
      if (!/^[0-9a-f]{1,4}$/.test(h)) return null;
    }

    const missingCount = 8 - (left.length + right.length);
    if (missingCount < 1) return null;

    const mid = new Array(missingCount).fill(0);
    const leftNums = left.map((h) => parseInt(h, 16));
    const rightNums = right.map((h) => parseInt(h, 16));
    hextets = [...leftNums, ...mid, ...rightNums];
  } else {
    const parts = clean.split(":");
    if (parts.length !== 8) return null;
    for (const h of parts) {
      if (!/^[0-9a-f]{1,4}$/.test(h)) return null;
      hextets.push(parseInt(h, 16));
    }
  }

  if (hextets.length !== 8) return null;

  let result = 0n;
  for (let i = 0; i < 8; i++) {
    result = (result << 16n) | BigInt(hextets[i]);
  }
  return result;
}

export function bigintToIPv6Hextets(val: bigint): number[] {
  const hextets: number[] = [];
  for (let i = 7; i >= 0; i--) {
    const shift = BigInt(i * 16);
    hextets.unshift(Number((val >> shift) & 0xffffn));
  }
  return hextets;
}

export function formatIPv6Expanded(val: bigint): string {
  const hextets = bigintToIPv6Hextets(val);
  return hextets.map((h) => h.toString(16).padStart(4, "0")).join(":");
}

export function formatIPv6Compressed(val: bigint): string {
  const hextets = bigintToIPv6Hextets(val);
  const hexStrings = hextets.map((h) => h.toString(16));

  // Find longest run of consecutive zeroes (RFC 5952: must be at least 2 zeroes)
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;

  for (let i = 0; i < 8; i++) {
    if (hextets[i] === 0) {
      if (curStart === -1) {
        curStart = i;
        curLen = 1;
      } else {
        curLen++;
      }
    } else {
      if (curLen > bestLen) {
        bestStart = curStart;
        bestLen = curLen;
      }
      curStart = -1;
      curLen = 0;
    }
  }
  if (curLen > bestLen) {
    bestStart = curStart;
    bestLen = curLen;
  }

  if (bestLen < 2) {
    return hexStrings.join(":");
  }

  const left = hexStrings.slice(0, bestStart).join(":");
  const right = hexStrings.slice(bestStart + bestLen).join(":");
  return `${left}::${right}`;
}

export interface IPv6ScopeInfo {
  scope: IPScope;
  rfc: string;
  category: string;
  description: string;
  isSpecial: boolean;
}

export function getIPv6Scope(val: bigint): IPv6ScopeInfo {
  // ::1/128 Loopback
  if (val === 1n) {
    return {
      scope: "Loopback",
      rfc: "RFC 4291",
      category: "Loopback Address",
      description: "IPv6 loopback address for local device traffic (::1).",
      isSpecial: true,
    };
  }

  // ::/128 Unspecified
  if (val === 0n) {
    return {
      scope: "Reserved",
      rfc: "RFC 4291",
      category: "Unspecified Address",
      description: "Indicates the absence of an address (::).",
      isSpecial: true,
    };
  }

  // ::ffff:0:0/96 IPv4-mapped
  const top96 = val >> 32n;
  if (top96 === 0xffffn) {
    return {
      scope: "Reserved",
      rfc: "RFC 4291",
      category: "IPv4-Mapped IPv6 Address",
      description: "Represents an IPv4 address inside an IPv6 socket.",
      isSpecial: true,
    };
  }

  const top16 = Number(val >> 112n) & 0xffff;
  const top32 = Number(val >> 96n) & 0xffffffff;

  // 64:ff9b::/96 NAT64
  if (top32 === 0x0064ff9b) {
    return {
      scope: "Public",
      rfc: "RFC 6052",
      category: "Well-Known NAT64 Prefix",
      description: "Used by stateful NAT64 translation gateways.",
      isSpecial: true,
    };
  }

  // 2001:0000::/32 Teredo
  if (top32 === 0x20010000) {
    return {
      scope: "Reserved",
      rfc: "RFC 4380",
      category: "Teredo Tunneling",
      description: "IPv6 tunneling over IPv4 UDP.",
      isSpecial: true,
    };
  }

  // 2001:db8::/32 Documentation
  if (top32 === 0x20010db8) {
    return {
      scope: "Reserved",
      rfc: "RFC 3849",
      category: "Documentation Address Block",
      description: "Allocated strictly for documentation and examples (RFC 3849).",
      isSpecial: true,
    };
  }

  // 2002::/16 6to4
  if (top16 === 0x2002) {
    return {
      scope: "Reserved",
      rfc: "RFC 3056",
      category: "6to4 Transition Mechanism",
      description: "Encapsulates IPv6 packets within IPv4 for automated tunneling.",
      isSpecial: true,
    };
  }

  // fc00::/7 (fc00::/8 and fd00::/8) - Unique Local Address (ULA)
  const top8 = Number(val >> 120n) & 0xff;
  if ((top8 & 0xfe) === 0xfc) {
    return {
      scope: "Private",
      rfc: "RFC 4193",
      category: "Unique Local Address (ULA)",
      description: "Globally unique private IPv6 address for local communications (RFC 4193).",
      isSpecial: true,
    };
  }

  // fe80::/10 Link-Local
  const top10 = Number(val >> 118n) & 0x3ff;
  if (top10 === 0x3e8 || top10 === 0x3e9 || top10 === 0x3ea || top10 === 0x3eb) {
    return {
      scope: "Link-Local",
      rfc: "RFC 4291",
      category: "Link-Local Unicast",
      description: "Valid only for communications on a single local link/segment (RFC 4291).",
      isSpecial: true,
    };
  }

  // ff00::/8 Multicast
  if (top8 === 0xff) {
    return {
      scope: "Multicast",
      rfc: "RFC 4291",
      category: "IPv6 Multicast Address",
      description: "Delivers datagrams to all interfaces subscribed to the multicast group.",
      isSpecial: true,
    };
  }

  // 2000::/3 Global Unicast (001...)
  const top3 = Number(val >> 125n) & 0x7;
  if (top3 === 1) {
    return {
      scope: "Public",
      rfc: "RFC 4291",
      category: "Global Unicast Address (GUA)",
      description: "Globally routable public IPv6 unicast address.",
      isSpecial: false,
    };
  }

  return {
    scope: "Reserved",
    rfc: "RFC 4291",
    category: "Reserved / Unassigned",
    description: "Reserved address space per IANA IPv6 Special-Purpose Address Registry.",
    isSpecial: true,
  };
}

// ---------------- Reverse DNS PTR Logic ----------------

export function generateReverseDnsPtr(version: "IPv4" | "IPv6", ipInput: string, val: number | bigint): string {
  if (version === "IPv4") {
    const octets = parseIPv4(ipInput);
    if (!octets) return "";
    return `${octets[3]}.${octets[2]}.${octets[1]}.${octets[0]}.in-addr.arpa`;
  } else {
    // IPv6 nibble format, 32 hex nibbles reversed separated by dots
    const expanded = formatIPv6Expanded(val as bigint).replace(/:/g, "");
    const nibbles = expanded.split("").reverse().join(".");
    return `${nibbles}.ip6.arpa`;
  }
}

// ---------------- Main Analysis Engine ----------------

export interface EngineOptions {
  ipv4DefaultPrefix?: "32" | "classful";
  ipv6DefaultPrefix?: "128" | "64";
}

export function analyzeIP(
  rawInput: string,
  options: EngineOptions = { ipv4DefaultPrefix: "32", ipv6DefaultPrefix: "128" }
): { result: IPAnalysisResult; advanced: AdvancedNetworkDetails | null } {
  const trimmed = rawInput.trim();

  if (!trimmed) {
    return {
      result: {
        status: "invalid",
        error_message: "Input string is empty. Please provide an IPv4 or IPv6 address.",
        ip_version: "IPv4",
        input_ip: "",
        cidr_notation: "",
        subnet_mask: "",
        wildcard_mask: null,
        network_address: "",
        broadcast_address: null,
        usable_host_range: { start: "", end: "" },
        total_ips: 0,
        usable_hosts: 0,
        scope: "Reserved",
        rfc_reference: "RFC 791",
        binary_representation: "",
        hex_representation: "",
        ipv6_details: { compressed: null, expanded: null },
      },
      advanced: null,
    };
  }

  // Separate IP part and prefix / netmask part
  // Format could be: "192.168.1.1/24", "192.168.1.1 255.255.255.0", "192.168.1.1/255.255.255.0", or "2001:db8::1/64"
  let ipPart = trimmed;
  let prefixPart: string | null = null;

  if (trimmed.includes("/")) {
    const parts = trimmed.split("/");
    ipPart = parts[0].trim();
    prefixPart = parts[1]?.trim() || null;
  } else if (trimmed.includes(" ")) {
    const parts = trimmed.split(/\s+/);
    ipPart = parts[0].trim();
    prefixPart = parts[1]?.trim() || null;
  }

  // Remove IPv6 brackets if any
  if (ipPart.startsWith("[") && ipPart.endsWith("]")) {
    ipPart = ipPart.slice(1, -1);
  }

  // Detect IPv4 vs IPv6
  const isIPv6 = ipPart.includes(":");

  if (!isIPv6) {
    // ---------------- Process IPv4 ----------------
    const octets = parseIPv4(ipPart);
    if (!octets) {
      return {
        result: {
          status: "invalid",
          error_message: `Invalid IPv4 address format: "${ipPart}". Expected 4 decimal octets between 0 and 255.`,
          ip_version: "IPv4",
          input_ip: ipPart,
          cidr_notation: "",
          subnet_mask: "",
          wildcard_mask: null,
          network_address: "",
          broadcast_address: null,
          usable_host_range: { start: "", end: "" },
          total_ips: 0,
          usable_hosts: 0,
          scope: "Reserved",
          rfc_reference: "RFC 791",
          binary_representation: "",
          hex_representation: "",
          ipv6_details: { compressed: null, expanded: null },
        },
        advanced: null,
      };
    }

    let prefix = 32;
    if (prefixPart !== null && prefixPart !== "") {
      if (/^\d+$/.test(prefixPart)) {
        prefix = parseInt(prefixPart, 10);
        if (prefix < 0 || prefix > 32) {
          return {
            result: {
              status: "invalid",
              error_message: `Invalid IPv4 CIDR prefix /${prefixPart}. Prefix length must be an integer between 0 and 32.`,
              ip_version: "IPv4",
              input_ip: ipPart,
              cidr_notation: "",
              subnet_mask: "",
              wildcard_mask: null,
              network_address: "",
              broadcast_address: null,
              usable_host_range: { start: "", end: "" },
              total_ips: 0,
              usable_hosts: 0,
              scope: "Reserved",
              rfc_reference: "RFC 791",
              binary_representation: "",
              hex_representation: "",
              ipv6_details: { compressed: null, expanded: null },
            },
            advanced: null,
          };
        }
      } else {
        // Might be a netmask like 255.255.255.0
        const parsedPrefix = subnetMaskToPrefixIPv4(prefixPart);
        if (parsedPrefix === null) {
          return {
            result: {
              status: "invalid",
              error_message: `Invalid subnet mask "${prefixPart}". Must be valid contiguous dotted-decimal mask.`,
              ip_version: "IPv4",
              input_ip: ipPart,
              cidr_notation: "",
              subnet_mask: "",
              wildcard_mask: null,
              network_address: "",
              broadcast_address: null,
              usable_host_range: { start: "", end: "" },
              total_ips: 0,
              usable_hosts: 0,
              scope: "Reserved",
              rfc_reference: "RFC 791",
              binary_representation: "",
              hex_representation: "",
              ipv6_details: { compressed: null, expanded: null },
            },
            advanced: null,
          };
        }
        prefix = parsedPrefix;
      }
    } else {
      if (options.ipv4DefaultPrefix === "classful") {
        prefix = getClassfulPrefixIPv4(octets[0]);
      } else {
        prefix = 32;
      }
    }

    const ipUint = ipv4ToUint32(octets);
    const maskUint = prefix === 0 ? 0 : ((~0 << (32 - prefix)) >>> 0);
    const wildcardUint = (~maskUint) >>> 0;
    const networkUint = (ipUint & maskUint) >>> 0;
    const broadcastUint = (networkUint | wildcardUint) >>> 0;

    const networkAddress = uint32ToIPv4(networkUint);
    const broadcastAddress = uint32ToIPv4(broadcastUint);
    const subnetMaskStr = uint32ToIPv4(maskUint);
    const wildcardMaskStr = uint32ToIPv4(wildcardUint);

    const totalIps = prefix === 0 ? 4294967296 : Math.pow(2, 32 - prefix);

    let usableHosts: number = 0;
    let usableStart = "";
    let usableEnd = "";

    if (prefix === 32) {
      usableHosts = 1;
      usableStart = uint32ToIPv4(ipUint);
      usableEnd = uint32ToIPv4(ipUint);
    } else if (prefix === 31) {
      // RFC 3021 Point-to-Point Links
      usableHosts = 2;
      usableStart = networkAddress;
      usableEnd = broadcastAddress;
    } else {
      usableHosts = totalIps - 2;
      usableStart = uint32ToIPv4(networkUint + 1);
      usableEnd = uint32ToIPv4(broadcastUint - 1);
    }

    const scopeInfo = getIPv4Scope(ipUint);

    // Binary representation: 4 octets, 8 bits each
    const binaryRep = octets.map((o) => o.toString(2).padStart(8, "0")).join(".");
    // Hex representation: 8 uppercase characters
    const hexRep = octets.map((o) => o.toString(16).padStart(2, "0").toUpperCase()).join("");

    const cidrNotation = `${networkAddress}/${prefix}`;

    // Advanced features
    const reverseDns = generateReverseDnsPtr("IPv4", ipPart, ipUint);
    const ciscoAclStd = `access-list 10 permit ${networkAddress} ${wildcardMaskStr}`;
    const ciscoAclExt = `permit ip ${networkAddress} ${wildcardMaskStr} any`;
    const ciscoOspf = `network ${networkAddress} ${wildcardMaskStr} area 0`;
    const juniperSyntax = `${networkAddress}/${prefix}`;

    // 6to4 and IPv4-mapped
    const ipv4Mapped = `::ffff:${ipPart}`;
    const sixToFour = `2002:${octets[0].toString(16).padStart(2, "0")}${octets[1]
      .toString(16)
      .padStart(2, "0")}:${octets[2].toString(16).padStart(2, "0")}${octets[3]
      .toString(16)
      .padStart(2, "0")}::/48`;

    const result: IPAnalysisResult = {
      status: "valid",
      error_message: null,
      ip_version: "IPv4",
      input_ip: ipPart,
      cidr_notation: cidrNotation,
      subnet_mask: subnetMaskStr,
      wildcard_mask: wildcardMaskStr,
      network_address: networkAddress,
      broadcast_address: broadcastAddress,
      usable_host_range: {
        start: usableStart,
        end: usableEnd,
      },
      total_ips: totalIps,
      usable_hosts: usableHosts,
      scope: scopeInfo.scope,
      rfc_reference: scopeInfo.rfc,
      binary_representation: binaryRep,
      hex_representation: hexRep,
      ipv6_details: {
        compressed: null,
        expanded: null,
      },
    };

    const advanced: AdvancedNetworkDetails = {
      integer_value: ipUint.toString(),
      hex_prefixed: `0x${hexRep}`,
      reverse_dns_ptr: reverseDns,
      cisco_acl_standard: ciscoAclStd,
      cisco_acl_extended: ciscoAclExt,
      cisco_ospf_statement: ciscoOspf,
      juniper_syntax: juniperSyntax,
      ipv4_mapped_ipv6: ipv4Mapped,
      six_to_four_prefix: sixToFour,
      embedded_ipv4: null,
      classification_details: {
        category: scopeInfo.category,
        description: scopeInfo.description,
        rfcs: [scopeInfo.rfc],
        is_special_use: scopeInfo.isSpecial,
      },
      prefix_length: prefix,
      host_bits: 32 - prefix,
    };

    return { result, advanced };
  } else {
    // ---------------- Process IPv6 ----------------
    const ipv6BigInt = parseIPv6(ipPart);
    if (ipv6BigInt === null) {
      return {
        result: {
          status: "invalid",
          error_message: `Invalid IPv6 address format: "${ipPart}". Expected RFC 4291 compliant 128-bit hex representation.`,
          ip_version: "IPv6",
          input_ip: ipPart,
          cidr_notation: "",
          subnet_mask: "",
          wildcard_mask: null,
          network_address: "",
          broadcast_address: null,
          usable_host_range: { start: "", end: "" },
          total_ips: 0,
          usable_hosts: 0,
          scope: "Reserved",
          rfc_reference: "RFC 4291",
          binary_representation: "",
          hex_representation: "",
          ipv6_details: { compressed: null, expanded: null },
        },
        advanced: null,
      };
    }

    let prefix = 128;
    if (prefixPart !== null && prefixPart !== "") {
      if (!/^\d+$/.test(prefixPart)) {
        return {
          result: {
            status: "invalid",
            error_message: `Invalid IPv6 prefix length "/${prefixPart}". Must be an integer between 0 and 128.`,
            ip_version: "IPv6",
            input_ip: ipPart,
            cidr_notation: "",
            subnet_mask: "",
            wildcard_mask: null,
            network_address: "",
            broadcast_address: null,
            usable_host_range: { start: "", end: "" },
            total_ips: 0,
            usable_hosts: 0,
            scope: "Reserved",
            rfc_reference: "RFC 4291",
            binary_representation: "",
            hex_representation: "",
            ipv6_details: { compressed: null, expanded: null },
          },
          advanced: null,
        };
      }
      prefix = parseInt(prefixPart, 10);
      if (prefix < 0 || prefix > 128) {
        return {
          result: {
            status: "invalid",
            error_message: `IPv6 prefix length /${prefix} is out of range. Must be between 0 and 128.`,
            ip_version: "IPv6",
            input_ip: ipPart,
            cidr_notation: "",
            subnet_mask: "",
            wildcard_mask: null,
            network_address: "",
            broadcast_address: null,
            usable_host_range: { start: "", end: "" },
            total_ips: 0,
            usable_hosts: 0,
            scope: "Reserved",
            rfc_reference: "RFC 4291",
            binary_representation: "",
            hex_representation: "",
            ipv6_details: { compressed: null, expanded: null },
          },
          advanced: null,
        };
      }
    } else {
      prefix = options.ipv6DefaultPrefix === "64" ? 64 : 128;
    }

    // Mask calculation
    const hostBits = 128 - prefix;
    let maskBigInt = 0n;
    if (prefix === 128) {
      maskBigInt = (1n << 128n) - 1n;
    } else if (prefix === 0) {
      maskBigInt = 0n;
    } else {
      maskBigInt = ((1n << 128n) - 1n) ^ ((1n << BigInt(hostBits)) - 1n);
    }

    const networkBigInt = ipv6BigInt & maskBigInt;
    const lastBigInt = networkBigInt | ((1n << BigInt(hostBits)) - 1n);

    const compressedIp = formatIPv6Compressed(ipv6BigInt);
    const expandedIp = formatIPv6Expanded(ipv6BigInt);
    const networkCompressed = formatIPv6Compressed(networkBigInt);
    const cidrNotation = `${networkCompressed}/${prefix}`;

    // Subnet mask representation for IPv6: /prefix or expanded mask
    const subnetMaskStr = formatIPv6Compressed(maskBigInt);

    // Total IPs: 2^(128 - prefix)
    const totalIpsBig = 1n << BigInt(hostBits);
    const totalIps = totalIpsBig <= Number.MAX_SAFE_INTEGER ? Number(totalIpsBig) : totalIpsBig.toString();

    let usableHosts: number | string = 0;
    let usableStart = "";
    let usableEnd = "";

    if (prefix === 128) {
      usableHosts = 1;
      usableStart = compressedIp;
      usableEnd = compressedIp;
    } else if (prefix === 127) {
      // RFC 6164 Router point-to-point
      usableHosts = 2;
      usableStart = formatIPv6Compressed(networkBigInt);
      usableEnd = formatIPv6Compressed(lastBigInt);
    } else {
      // Usable hosts: exclude Subnet-Router anycast (::0)
      const usableHostsBig = totalIpsBig - 1n;
      usableHosts = usableHostsBig <= Number.MAX_SAFE_INTEGER ? Number(usableHostsBig) : usableHostsBig.toString();
      usableStart = formatIPv6Compressed(networkBigInt + 1n);
      usableEnd = formatIPv6Compressed(lastBigInt);
    }

    const scopeInfo = getIPv6Scope(ipv6BigInt);

    // Binary representation: 8 groups of 16 bits separated by colon
    const hextets = bigintToIPv6Hextets(ipv6BigInt);
    const binaryRep = hextets.map((h) => h.toString(2).padStart(16, "0")).join(":");

    // Hex representation: 32 hex chars uppercase
    const hexRep = expandedIp.replace(/:/g, "").toUpperCase();

    // Check if embedded IPv4
    let embeddedIpv4: string | null = null;
    if ((ipv6BigInt >> 32n) === 0xffffn) {
      // ::ffff:a.b.c.d
      const last32 = Number(ipv6BigInt & 0xffffffffn);
      embeddedIpv4 = uint32ToIPv4(last32);
    } else if ((Number(ipv6BigInt >> 112n) & 0xffff) === 0x2002) {
      // 6to4
      const o1 = Number((ipv6BigInt >> 96n) & 0xffn);
      const o2 = Number((ipv6BigInt >> 88n) & 0xffn);
      const o3 = Number((ipv6BigInt >> 80n) & 0xffn);
      const o4 = Number((ipv6BigInt >> 72n) & 0xffn);
      embeddedIpv4 = `${o1}.${o2}.${o3}.${o4}`;
    }

    const reverseDns = generateReverseDnsPtr("IPv6", ipPart, ipv6BigInt);
    const juniperSyntax = `${networkCompressed}/${prefix}`;

    const result: IPAnalysisResult = {
      status: "valid",
      error_message: null,
      ip_version: "IPv6",
      input_ip: ipPart,
      cidr_notation: cidrNotation,
      subnet_mask: subnetMaskStr,
      wildcard_mask: null,
      network_address: networkCompressed,
      broadcast_address: null, // IPv6 has no broadcast address
      usable_host_range: {
        start: usableStart,
        end: usableEnd,
      },
      total_ips: totalIps,
      usable_hosts: usableHosts,
      scope: scopeInfo.scope,
      rfc_reference: scopeInfo.rfc,
      binary_representation: binaryRep,
      hex_representation: hexRep,
      ipv6_details: {
        compressed: compressedIp,
        expanded: expandedIp,
      },
    };

    const advanced: AdvancedNetworkDetails = {
      integer_value: ipv6BigInt.toString(),
      hex_prefixed: `0x${hexRep}`,
      reverse_dns_ptr: reverseDns,
      cisco_acl_standard: `ipv6 access-list FILTER permit ipv6 ${networkCompressed}/${prefix} any`,
      cisco_acl_extended: `ipv6 access-list FILTER permit ipv6 ${networkCompressed}/${prefix} any`,
      cisco_ospf_statement: `ipv6 ospf 1 area 0`,
      juniper_syntax: juniperSyntax,
      embedded_ipv4: embeddedIpv4,
      classification_details: {
        category: scopeInfo.category,
        description: scopeInfo.description,
        rfcs: [scopeInfo.rfc],
        is_special_use: scopeInfo.isSpecial,
      },
      prefix_length: prefix,
      host_bits: hostBits,
    };

    return { result, advanced };
  }
}

// ---------------- Subnet Slicing Generator ----------------

export function calculateSubnetSlices(
  baseNetwork: string,
  basePrefix: number,
  targetPrefix: number,
  limit: number = 16
): SubnetSlice[] {
  if (targetPrefix <= basePrefix || targetPrefix > 32) return [];
  const octets = parseIPv4(baseNetwork);
  if (!octets) return [];

  const baseUint = ipv4ToUint32(octets);
  const subnetSize = Math.pow(2, 32 - targetPrefix);
  const totalSubnets = Math.pow(2, targetPrefix - basePrefix);

  const slices: SubnetSlice[] = [];
  const countToReturn = Math.min(totalSubnets, limit);

  for (let i = 0; i < countToReturn; i++) {
    const netUint = (baseUint + i * subnetSize) >>> 0;
    const bcastUint = (netUint + subnetSize - 1) >>> 0;
    const netStr = uint32ToIPv4(netUint);
    const bcastStr = uint32ToIPv4(bcastUint);

    let usableStart = "";
    let usableEnd = "";
    let usableHosts: number = 0;

    if (targetPrefix === 32) {
      usableStart = netStr;
      usableEnd = netStr;
      usableHosts = 1;
    } else if (targetPrefix === 31) {
      usableStart = netStr;
      usableEnd = bcastStr;
      usableHosts = 2;
    } else {
      usableStart = uint32ToIPv4(netUint + 1);
      usableEnd = uint32ToIPv4(bcastUint - 1);
      usableHosts = subnetSize - 2;
    }

    slices.push({
      index: i + 1,
      network_address: netStr,
      cidr: `${netStr}/${targetPrefix}`,
      broadcast_address: bcastStr,
      usable_start: usableStart,
      usable_end: usableEnd,
      usable_hosts: usableHosts,
    });
  }

  return slices;
}

// ---------------- CIDR Table Data ----------------

export interface CIDRTableEntry {
  prefix: number;
  subnetMask: string;
  wildcardMask: string;
  totalIps: number | string;
  usableHosts: number | string;
  classType: string;
  usageNotes: string;
}

export function getIPv4CidrTable(): CIDRTableEntry[] {
  const table: CIDRTableEntry[] = [];
  for (let p = 0; p <= 32; p++) {
    const octets = cidrToSubnetMaskIPv4(p);
    const mask = octets.join(".");
    const wildcard = octets.map((o) => 255 - o).join(".");
    const total = p === 0 ? 4294967296 : Math.pow(2, 32 - p);

    let usable: number | string = 0;
    let notes = "";
    let cls = "CIDR";

    if (p === 32) {
      usable = 1;
      notes = "Single host / loopback / route filter";
    } else if (p === 31) {
      usable = 2;
      notes = "Point-to-point links (RFC 3021)";
    } else if (p === 30) {
      usable = 2;
      notes = "Legacy point-to-point link";
    } else if (p === 29) {
      usable = 6;
      notes = "Small subnet (firewall DMZ, router HA)";
    } else if (p === 28) {
      usable = 14;
      notes = "Small department / server pool";
    } else if (p === 27) {
      usable = 30;
      notes = "Mid-sized branch network";
    } else if (p === 26) {
      usable = 62;
      notes = "Quarter Class C / department";
    } else if (p === 25) {
      usable = 126;
      notes = "Half Class C subnet";
    } else if (p === 24) {
      usable = 254;
      notes = "Standard LAN / Legacy Class C (/24)";
      cls = "Class C";
    } else if (p === 16) {
      usable = total - 2;
      notes = "Campus / Enterprise / Legacy Class B (/16)";
      cls = "Class B";
    } else if (p === 8) {
      usable = total - 2;
      notes = "Large enterprise / Legacy Class A (/8)";
      cls = "Class A";
    } else if (p === 0) {
      usable = 4294967294;
      notes = "Default Route (0.0.0.0/0 - Entire Internet)";
    } else {
      usable = total - 2;
      notes = `Custom CIDR block (2^${32 - p} addresses)`;
    }

    table.push({
      prefix: p,
      subnetMask: mask,
      wildcardMask: wildcard,
      totalIps: total,
      usableHosts: usable,
      classType: cls,
      usageNotes: notes,
    });
  }
  return table;
}
