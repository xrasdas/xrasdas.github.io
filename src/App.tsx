import { useState, useCallback } from "react";

interface XrayConfig {
  remarks?: string;
  outbounds?: Outbound[];
  [key: string]: unknown;
}

interface Outbound {
  protocol: string;
  tag?: string;
  settings?: Record<string, unknown>;
  streamSettings?: StreamSettings;
}

interface StreamSettings {
  network?: string;
  security?: string;
  realitySettings?: Record<string, unknown>;
  tlsSettings?: Record<string, unknown>;
  wsSettings?: Record<string, unknown>;
  grpcSettings?: Record<string, unknown>;
  tcpSettings?: Record<string, unknown>;
  xhttpSettings?: Record<string, unknown>;
  httpSettings?: Record<string, unknown>;
  quicSettings?: Record<string, unknown>;
  kcpSettings?: Record<string, unknown>;
  [key: string]: unknown;
}

function buildQueryParams(params: Record<string, string>): string {
  const parts: string[] = [];
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      parts.push(`${key}=${encodeURIComponent(value)}`);
    }
  }
  return parts.join("&");
}

function extractStreamParams(stream: StreamSettings): Record<string, string> {
  const params: Record<string, string> = {};

  // Network type
  const network = stream.network || "tcp";
  params.type = network;

  // Security
  const security = stream.security || "none";
  params.security = security;

  // Reality settings
  if (security === "reality" && stream.realitySettings) {
    const rs = stream.realitySettings;
    if (rs.serverName) params.sni = String(rs.serverName);
    if (rs.fingerprint) params.fp = String(rs.fingerprint);
    if (rs.publicKey) params.pbk = String(rs.publicKey);
    if (rs.shortId) params.sid = String(rs.shortId);
    if (rs.spiderX) params.spx = String(rs.spiderX);
  }

  // TLS settings
  if (security === "tls" && stream.tlsSettings) {
    const ts = stream.tlsSettings;
    if (ts.serverName) params.sni = String(ts.serverName);
    if (ts.fingerprint) params.fp = String(ts.fingerprint);
    if (ts.alpn) {
      const alpn = ts.alpn;
      if (Array.isArray(alpn)) params.alpn = alpn.join(",");
      else params.alpn = String(alpn);
    }
  }

  // Network-specific settings
  if (network === "ws" && stream.wsSettings) {
    const ws = stream.wsSettings as Record<string, unknown>;
    if (ws.path) params.path = String(ws.path);
    if (ws.headers && typeof ws.headers === "object") {
      const headers = ws.headers as Record<string, unknown>;
      if (headers.Host) params.host = String(headers.Host);
    }
  }

  if (network === "grpc" && stream.grpcSettings) {
    const grpc = stream.grpcSettings as Record<string, unknown>;
    if (grpc.serviceName) params.serviceName = String(grpc.serviceName);
    if (grpc.mode) params.mode = String(grpc.mode);
    if (grpc.authority) params.authority = String(grpc.authority);
  }

  if (network === "tcp" && stream.tcpSettings) {
    const tcp = stream.tcpSettings as Record<string, unknown>;
    if (tcp.header && typeof tcp.header === "object") {
      const header = tcp.header as Record<string, unknown>;
      if (header.type) params.headerType = String(header.type);
      if (header.request && typeof header.request === "object") {
        const req = header.request as Record<string, unknown>;
        if (req.path) {
          const pathArr = req.path;
          if (Array.isArray(pathArr) && pathArr.length > 0)
            params.path = String(pathArr[0]);
        }
        if (req.headers && typeof req.headers === "object") {
          const headers = req.headers as Record<string, unknown>;
          if (headers.Host) {
            const host = headers.Host;
            if (Array.isArray(host) && host.length > 0)
              params.host = String(host[0]);
            else params.host = String(host);
          }
        }
      }
    }
  }

  if (network === "xhttp" && stream.xhttpSettings) {
    const xh = stream.xhttpSettings as Record<string, unknown>;
    if (xh.path) params.path = String(xh.path);
    if (xh.host) params.host = String(xh.host);
    if (xh.mode) params.mode = String(xh.mode);
  }

  if (
    (network === "h2" || network === "http") &&
    (stream.httpSettings || stream.h2Settings)
  ) {
    const h2 = (stream.httpSettings ||
      (stream as Record<string, unknown>).h2Settings) as Record<
      string,
      unknown
    >;
    if (h2) {
      if (h2.path) params.path = String(h2.path);
      if (h2.host) {
        const host = h2.host;
        if (Array.isArray(host) && host.length > 0)
          params.host = String(host[0]);
        else params.host = String(host);
      }
    }
  }

  if (network === "quic" && stream.quicSettings) {
    const quic = stream.quicSettings as Record<string, unknown>;
    if (quic.security) params.quicSecurity = String(quic.security);
    if (quic.key) params.key = String(quic.key);
    if (quic.header && typeof quic.header === "object") {
      const header = quic.header as Record<string, unknown>;
      if (header.type) params.headerType = String(header.type);
    }
  }

  if (network === "kcp" && stream.kcpSettings) {
    const kcp = stream.kcpSettings as Record<string, unknown>;
    if (kcp.seed) params.seed = String(kcp.seed);
    if (kcp.header && typeof kcp.header === "object") {
      const header = kcp.header as Record<string, unknown>;
      if (header.type) params.headerType = String(header.type);
    }
  }

  return params;
}

function convertVless(
  outbound: Outbound,
  remarks: string
): string | null {
  const settings = outbound.settings as Record<string, unknown>;
  if (!settings || !settings.vnext) return null;

  const vnext = settings.vnext as Array<Record<string, unknown>>;
  if (!vnext || vnext.length === 0) return null;

  const server = vnext[0];
  const address = String(server.address);
  const port = String(server.port);
  const users = server.users as Array<Record<string, unknown>>;
  if (!users || users.length === 0) return null;

  const user = users[0];
  const uuid = String(user.id);

  const params: Record<string, string> = {};
  if (user.encryption) params.encryption = String(user.encryption);
  if (user.flow) params.flow = String(user.flow);

  if (outbound.streamSettings) {
    const streamParams = extractStreamParams(outbound.streamSettings);
    Object.assign(params, streamParams);
  }

  const query = buildQueryParams(params);
  const fragment = encodeURIComponent(remarks);

  return `vless://${uuid}@${address}:${port}?${query}#${fragment}`;
}

function convertVmess(
  outbound: Outbound,
  remarks: string
): string | null {
  const settings = outbound.settings as Record<string, unknown>;
  if (!settings || !settings.vnext) return null;

  const vnext = settings.vnext as Array<Record<string, unknown>>;
  if (!vnext || vnext.length === 0) return null;

  const server = vnext[0];
  const users = server.users as Array<Record<string, unknown>>;
  if (!users || users.length === 0) return null;

  const user = users[0];
  const stream = outbound.streamSettings || {};
  const network = stream.network || "tcp";
  const security = stream.security || "none";

  let path = "";
  let host = "";
  let headerType = "none";
  let sni = "";

  const streamParams = extractStreamParams(stream);
  path = streamParams.path || "";
  host = streamParams.host || "";
  headerType = streamParams.headerType || "none";
  sni = streamParams.sni || "";

  // VMess uses base64-encoded JSON (v2rayN format)
  const vmessObj: Record<string, string | number> = {
    v: "2",
    ps: remarks,
    add: String(server.address),
    port: Number(server.port),
    id: String(user.id),
    aid: Number(user.alterId || 0),
    scy: String(user.security || "auto"),
    net: String(network),
    type: headerType,
    host: host,
    path: path,
    tls: security === "tls" ? "tls" : "",
    sni: sni,
    alpn: streamParams.alpn || "",
    fp: streamParams.fp || "",
  };

  const jsonStr = JSON.stringify(vmessObj);
  const b64 = btoa(jsonStr);
  return `vmess://${b64}`;
}

function convertTrojan(
  outbound: Outbound,
  remarks: string
): string | null {
  const settings = outbound.settings as Record<string, unknown>;
  if (!settings || !settings.servers) return null;

  const servers = settings.servers as Array<Record<string, unknown>>;
  if (!servers || servers.length === 0) return null;

  const server = servers[0];
  const password = String(server.password);
  const address = String(server.address);
  const port = String(server.port);

  const params: Record<string, string> = {};

  if (outbound.streamSettings) {
    const streamParams = extractStreamParams(outbound.streamSettings);
    Object.assign(params, streamParams);
  }

  const query = buildQueryParams(params);
  const fragment = encodeURIComponent(remarks);

  return `trojan://${password}@${address}:${port}?${query}#${fragment}`;
}

function convertShadowsocks(
  outbound: Outbound,
  remarks: string
): string | null {
  const settings = outbound.settings as Record<string, unknown>;
  if (!settings || !settings.servers) return null;

  const servers = settings.servers as Array<Record<string, unknown>>;
  if (!servers || servers.length === 0) return null;

  const server = servers[0];
  const method = String(server.method);
  const password = String(server.password);
  const address = String(server.address);
  const port = String(server.port);

  const userInfo = btoa(`${method}:${password}`);
  const fragment = encodeURIComponent(remarks);

  return `ss://${userInfo}@${address}:${port}#${fragment}`;
}

function convertConfig(config: XrayConfig): string | null {
  const remarks = config.remarks || "Unnamed";
  const outbounds = config.outbounds || [];

  // Find proxy outbound (not direct, not block)
  const proxyOutbound = outbounds.find(
    (ob) =>
      ob.tag === "proxy" ||
      (ob.protocol !== "freedom" &&
        ob.protocol !== "blackhole" &&
        ob.protocol !== "dns")
  );

  if (!proxyOutbound) return null;

  switch (proxyOutbound.protocol) {
    case "vless":
      return convertVless(proxyOutbound, remarks);
    case "vmess":
      return convertVmess(proxyOutbound, remarks);
    case "trojan":
      return convertTrojan(proxyOutbound, remarks);
    case "shadowsocks":
    case "ss":
      return convertShadowsocks(proxyOutbound, remarks);
    default:
      return null;
  }
}

function convertConfigs(input: string): { links: string[]; errors: string[] } {
  const links: string[] = [];
  const errors: string[] = [];

  let parsed: unknown;
  try {
    parsed = JSON.parse(input);
  } catch {
    errors.push("Invalid JSON input. Please check your config.");
    return { links, errors };
  }

  const configs: XrayConfig[] = Array.isArray(parsed) ? parsed : [parsed];

  for (let i = 0; i < configs.length; i++) {
    const config = configs[i];
    try {
      const link = convertConfig(config);
      if (link) {
        links.push(link);
      } else {
        errors.push(
          `Config #${i + 1} "${config.remarks || "Unnamed"}": Could not convert — unsupported protocol or missing data.`
        );
      }
    } catch (e) {
      errors.push(
        `Config #${i + 1} "${config.remarks || "Unnamed"}": Error — ${e instanceof Error ? e.message : String(e)}`
      );
    }
  }

  return { links, errors };
}

export function App() {
  const [input, setInput] = useState("");
  const [output, setOutput] = useState<string[]>([]);
  const [errors, setErrors] = useState<string[]>([]);
  const [copied, setCopied] = useState(false);
  const [copyIdx, setCopyIdx] = useState<number | null>(null);

  const handleConvert = useCallback(() => {
    if (!input.trim()) {
      setErrors(["Please paste your Xray JSON config."]);
      setOutput([]);
      return;
    }
    const result = convertConfigs(input.trim());
    setOutput(result.links);
    setErrors(result.errors);
    setCopied(false);
    setCopyIdx(null);
  }, [input]);

  const handleCopyAll = useCallback(async () => {
    const text = output.join("\n");
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [output]);

  const handleCopyOne = useCallback(async (idx: number, link: string) => {
    await navigator.clipboard.writeText(link);
    setCopyIdx(idx);
    setTimeout(() => setCopyIdx(null), 2000);
  }, []);

  const handleClear = useCallback(() => {
    setInput("");
    setOutput([]);
    setErrors([]);
    setCopied(false);
    setCopyIdx(null);
  }, []);

  const loadSample = useCallback(() => {
    const sample = JSON.stringify(
      [
        {
          remarks: "Sample VLESS Config",
          outbounds: [
            {
              protocol: "vless",
              tag: "proxy",
              settings: {
                vnext: [
                  {
                    address: "ip",
                    port: 8443,
                    users: [
                      {
                        id: "uuid",
                        encryption: "none",
                      },
                    ],
                  },
                ],
              },
              streamSettings: {
                network: "xhttp",
                security: "reality",
                realitySettings: {
                  serverName: "mail.ru",
                  publicKey: "pb",
                  shortId: "si",
                  fingerprint: "fn",
                },
                xhttpSettings: {
                  path: "ph",
                  mode: "md",
                  host: "hs",
                },
              },
            },
            { protocol: "freedom", tag: "direct" },
            { protocol: "blackhole", tag: "block" },
          ],
        },
      ],
      null,
      2
    );
    setInput(sample);
  }, []);

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-950 via-gray-900 to-gray-950 text-gray-100">
      {/* Header */}
      <header className="border-b border-gray-800 bg-gray-950/60 backdrop-blur-sm">
        <div className="mx-auto max-w-6xl px-4 py-5">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-blue-500 to-cyan-500 shadow-lg shadow-blue-500/20">
              <svg
                className="h-5 w-5 text-white"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth={2}
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4"
                />
              </svg>
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-white">
                Xray Config Converter
              </h1>
              <p className="text-sm text-gray-400">
                Convert Xray JSON configs to share links (VLESS, VMess, Trojan,
                SS)
              </p>
            </div>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4 py-8">
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Input Panel */}
          <div className="flex flex-col">
            <div className="mb-3 flex items-center justify-between">
              <label className="text-sm font-semibold text-gray-300">
                📋 JSON Config Input
              </label>
              <div className="flex gap-2">
                <button
                  onClick={loadSample}
                  className="rounded-lg bg-gray-800 px-3 py-1.5 text-xs font-medium text-gray-300 transition hover:bg-gray-700 hover:text-white"
                >
                  Load Sample
                </button>
                <button
                  onClick={handleClear}
                  className="rounded-lg bg-gray-800 px-3 py-1.5 text-xs font-medium text-gray-300 transition hover:bg-gray-700 hover:text-white"
                >
                  Clear
                </button>
              </div>
            </div>
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder={`Paste your Xray JSON config here...\n\nAccepts a single config object {} or an array of configs [{}].\n\nSupported protocols:\n• VLESS\n• VMess\n• Trojan\n• Shadowsocks`}
              className="h-[500px] w-full flex-1 resize-none rounded-xl border border-gray-700 bg-gray-900/80 p-4 font-mono text-sm text-gray-200 placeholder-gray-600 outline-none transition focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30"
              spellCheck={false}
            />
          </div>

          {/* Output Panel */}
          <div className="flex flex-col">
            <div className="mb-3 flex items-center justify-between">
              <label className="text-sm font-semibold text-gray-300">
                🔗 Share Links Output
                {output.length > 0 && (
                  <span className="ml-2 inline-flex items-center rounded-full bg-blue-500/20 px-2 py-0.5 text-xs text-blue-400">
                    {output.length} link{output.length !== 1 ? "s" : ""}
                  </span>
                )}
              </label>
              {output.length > 0 && (
                <button
                  onClick={handleCopyAll}
                  className="rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-medium text-white transition hover:bg-blue-500"
                >
                  {copied ? "✓ Copied All!" : "Copy All"}
                </button>
              )}
            </div>
            <div className="flex h-[500px] flex-1 flex-col gap-3 overflow-y-auto rounded-xl border border-gray-700 bg-gray-900/80 p-4">
              {output.length === 0 && errors.length === 0 && (
                <div className="flex flex-1 flex-col items-center justify-center text-gray-500">
                  <svg
                    className="mb-3 h-12 w-12 text-gray-700"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                    strokeWidth={1}
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"
                    />
                  </svg>
                  <p className="text-sm">
                    Converted share links will appear here
                  </p>
                </div>
              )}

              {errors.map((err, i) => (
                <div
                  key={`err-${i}`}
                  className="rounded-lg border border-red-900/50 bg-red-950/50 px-4 py-3 text-sm text-red-300"
                >
                  <span className="mr-1 font-semibold text-red-400">⚠</span>
                  {err}
                </div>
              ))}

              {output.map((link, i) => {
                const protocol = link.split("://")[0].toUpperCase();
                const remark = decodeURIComponent(
                  link.includes("#") ? link.split("#").pop() || "" : ""
                );
                const protocolColors: Record<string, string> = {
                  VLESS:
                    "from-blue-500 to-cyan-500 shadow-blue-500/20",
                  VMESS:
                    "from-purple-500 to-pink-500 shadow-purple-500/20",
                  TROJAN:
                    "from-orange-500 to-red-500 shadow-orange-500/20",
                  SS: "from-green-500 to-emerald-500 shadow-green-500/20",
                };
                const colorClass =
                  protocolColors[protocol] ||
                  "from-gray-500 to-gray-600 shadow-gray-500/20";

                return (
                  <div
                    key={i}
                    className="group rounded-lg border border-gray-700/60 bg-gray-800/50 p-3 transition hover:border-gray-600"
                  >
                    <div className="mb-2 flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span
                          className={`inline-flex rounded-md bg-gradient-to-r px-2 py-0.5 text-[10px] font-bold tracking-wider text-white shadow-sm ${colorClass}`}
                        >
                          {protocol}
                        </span>
                        <span className="text-sm text-gray-300">
                          {remark || `Config #${i + 1}`}
                        </span>
                      </div>
                      <button
                        onClick={() => handleCopyOne(i, link)}
                        className="rounded-md bg-gray-700 px-2.5 py-1 text-xs font-medium text-gray-300 opacity-60 transition hover:bg-gray-600 hover:text-white group-hover:opacity-100"
                      >
                        {copyIdx === i ? "✓ Copied" : "Copy"}
                      </button>
                    </div>
                    <code className="block max-h-20 overflow-auto break-all rounded-md bg-gray-900/70 p-2 font-mono text-xs text-gray-400">
                      {link}
                    </code>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Convert Button */}
        <div className="mt-6 flex justify-center">
          <button
            onClick={handleConvert}
            className="group relative overflow-hidden rounded-xl bg-gradient-to-r from-blue-600 to-cyan-600 px-10 py-3.5 text-sm font-bold tracking-wide text-white shadow-lg shadow-blue-600/25 transition-all hover:shadow-xl hover:shadow-blue-600/30 active:scale-[0.98]"
          >
            <span className="relative z-10 flex items-center gap-2">
              <svg
                className="h-4 w-4 transition-transform group-hover:rotate-180"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth={2}
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
                />
              </svg>
              Convert to Share Links
            </span>
          </button>
        </div>

        {/* Info Section */}
        <div className="mt-10 grid gap-4 sm:grid-cols-3">
          {[
            {
              icon: "🔄",
              title: "Multi-Protocol",
              desc: "Supports VLESS, VMess, Trojan, and Shadowsocks protocols.",
            },
            {
              icon: "📦",
              title: "Batch Convert",
              desc: "Pass an array of configs to convert multiple at once.",
            },
            {
              icon: "🔒",
              title: "Client-Side Only",
              desc: "All processing happens in your browser. Nothing is sent to any server.",
            },
          ].map((item) => (
            <div
              key={item.title}
              className="rounded-xl border border-gray-800 bg-gray-900/50 p-4"
            >
              <div className="mb-2 text-2xl">{item.icon}</div>
              <h3 className="mb-1 text-sm font-semibold text-gray-200">
                {item.title}
              </h3>
              <p className="text-xs text-gray-500">{item.desc}</p>
            </div>
          ))}
        </div>
      </main>

      <footer className="border-t border-gray-800 py-6 text-center text-xs text-gray-600">
        Xray Config Converter — All processing is done locally in your browser.
      </footer>
    </div>
  );
}
