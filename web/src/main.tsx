import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type { Dispatch, FormEvent, ReactNode, SetStateAction } from "react";
import {
  IconAlertTriangle,
  IconArrowsExchange,
  IconCheck,
  IconChevronDown,
  IconCircleCheck,
  IconCloudUpload,
  IconDotsVertical,
  IconLayoutDashboard,
  IconPlus,
  IconRefresh,
  IconSearch,
  IconServer,
  IconSettings,
  IconShieldCheck,
  IconUserCircle,
} from "@tabler/icons-react";
import { createRoot } from "react-dom/client";
import {
  buildRequestHeaders,
  forgetCredential,
  readCredential,
  recoverCredential,
  waitForCredential,
} from "./auth";
import "./styles.css";

type Family = "auto" | "ipv4" | "ipv6";
type Protocol = "tcp" | "udp";
type Snat = { mode: "none" | "masquerade" | "fixed"; address?: string };
type Rule = {
  id: string;
  name: string;
  comment: string;
  enabled: boolean;
  order: number;
  allow_ssh_conflict: boolean;
  family: Family;
  listen_address: "any" | { address: string };
  listen_interface?: string | null;
  source_cidrs: string[];
  protocols: { tcp: boolean; udp: boolean };
  listen_port: { start: number; end: number };
  target_ip: string;
  target_port: { start: number; end: number };
  snat: Snat;
};
type Config = { schema_version: number; rules: Rule[] };
type Status = {
  active_revision?: string;
  draft_revision?: string;
  kernel: {
    table_present: boolean;
    drifted: boolean;
    observed_at?: string;
    counters: {
      rule_id: string;
      protocol: Protocol;
      packets: number;
      bytes: number;
    }[];
  };
  ipv4_forwarding: boolean;
  ipv6_forwarding: boolean;
  warnings: string[];
};
type Backup = { key: string; size_bytes: number; last_modified?: string };
type ApiRequest = <T>(path: string, init?: RequestInit) => Promise<T>;

type ConfirmOptions = {
  title?: string;
  confirmLabel?: string;
  cancelLabel?: string;
  tone?: "default" | "danger";
};
type PromptOptions = {
  submitLabel?: string;
  cancelLabel?: string;
  placeholder?: string;
};
type ConfirmDialog = {
  kind: "confirm";
  title: string;
  message: string;
  confirmLabel: string;
  cancelLabel: string;
  tone: "default" | "danger";
  resolve: (value: boolean) => void;
};
type PasswordDialog = {
  kind: "password";
  title: string;
  message: string;
  submitLabel: string;
  cancelLabel: string;
  placeholder: string;
  resolve: (value: string | null) => void;
};
type DialogRequest = ConfirmDialog | PasswordDialog;
type DialogActions = {
  confirm: (message: string, options?: ConfirmOptions) => Promise<boolean>;
  prompt: (
    title: string,
    message: string,
    options?: PromptOptions,
  ) => Promise<string | null>;
};

const DialogContext = createContext<DialogActions | null>(null);

function DialogProvider({ children }: { children: ReactNode }) {
  const [queue, setQueue] = useState<DialogRequest[]>([]);
  const confirm = useCallback(
    (message: string, options: ConfirmOptions = {}) =>
      new Promise<boolean>((resolve) => {
        setQueue((current) => [
          ...current,
          {
            kind: "confirm",
            title: options.title || "Confirm",
            message,
            confirmLabel: options.confirmLabel || "Confirm",
            cancelLabel: options.cancelLabel || "Cancel",
            tone: options.tone || "default",
            resolve,
          },
        ]);
      }),
    [],
  );
  const prompt = useCallback(
    (title: string, message: string, options: PromptOptions = {}) =>
      new Promise<string | null>((resolve) => {
        setQueue((current) => [
          ...current,
          {
            kind: "password",
            title,
            message,
            submitLabel: options.submitLabel || "Continue",
            cancelLabel: options.cancelLabel || "Cancel",
            placeholder: options.placeholder || "Password",
            resolve,
          },
        ]);
      }),
    [],
  );
  const complete = (value: boolean | string | null) => {
    const current = queue[0];
    if (!current) return;
    if (current.kind === "confirm") current.resolve(Boolean(value));
    else current.resolve(typeof value === "string" ? value : null);
    setQueue((items) => items.slice(1));
  };
  return (
    <DialogContext.Provider value={{ confirm, prompt }}>
      {children}
      <Dialog request={queue[0]} onComplete={complete} />
    </DialogContext.Provider>
  );
}

function useDialog(): DialogActions {
  const dialog = useContext(DialogContext);
  if (!dialog) throw new Error("DialogProvider is required");
  return dialog;
}

function Dialog({
  request,
  onComplete,
}: {
  request?: DialogRequest;
  onComplete: (value: boolean | string | null) => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);
  const [value, setValue] = useState("");
  useEffect(() => {
    setValue("");
    if (request?.kind === "password") inputRef.current?.focus();
    else cancelRef.current?.focus();
  }, [request]);
  useEffect(() => {
    if (!request) return undefined;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape")
        onComplete(request.kind === "confirm" ? false : null);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onComplete, request]);
  if (!request) return null;
  const cancel = () => onComplete(request.kind === "confirm" ? false : null);
  return (
    <div className="modal-backdrop" role="presentation">
      <section
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="portalis-modal-title"
        aria-describedby="portalis-modal-message"
      >
        <div className="modal-eyebrow">PORTALIS</div>
        <h2 id="portalis-modal-title">{request.title}</h2>
        <p id="portalis-modal-message">{request.message}</p>
        {request.kind === "password" ? (
          <form
            onSubmit={(event) => {
              event.preventDefault();
              if (value) onComplete(value);
            }}
          >
            <label className="modal-field">
              <span>{request.placeholder}</span>
              <input
                ref={inputRef}
                type="password"
                value={value}
                placeholder={request.placeholder}
                autoComplete="current-password"
                onChange={(event) => setValue(event.target.value)}
              />
            </label>
            <div className="modal-actions">
              <button
                ref={cancelRef}
                type="button"
                className="secondary"
                onClick={cancel}
              >
                {request.cancelLabel}
              </button>
              <button type="submit" className="primary" disabled={!value}>
                {request.submitLabel}
              </button>
            </div>
          </form>
        ) : (
          <div className="modal-actions">
            <button
              ref={cancelRef}
              type="button"
              className="secondary"
              onClick={cancel}
            >
              {request.cancelLabel}
            </button>
            <button
              type="button"
              className={request.tone === "danger" ? "modal-danger" : "primary"}
              onClick={() => onComplete(true)}
            >
              {request.confirmLabel}
            </button>
          </div>
        )}
      </section>
    </div>
  );
}

const newId = (): string => {
  const webCrypto = globalThis.crypto;
  if (typeof webCrypto?.randomUUID === "function")
    return webCrypto.randomUUID();
  if (typeof webCrypto?.getRandomValues === "function") {
    const bytes = new Uint8Array(16);
    webCrypto.getRandomValues(bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes, (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (value) => {
    const random = Math.floor(Math.random() * 16);
    const nibble = value === "x" ? random : (random & 0x3) | 0x8;
    return nibble.toString(16);
  });
};
const emptyRule = (): Rule => ({
  id: newId(),
  name: "New forward",
  comment: "",
  enabled: true,
  order: 0,
  allow_ssh_conflict: false,
  family: "auto",
  listen_address: "any",
  listen_interface: null,
  source_cidrs: [],
  protocols: { tcp: true, udp: false },
  listen_port: { start: 10000, end: 10000 },
  target_ip: "192.0.2.10",
  target_port: { start: 10000, end: 10000 },
  snat: { mode: "masquerade" },
});
const initial: Config = { schema_version: 1, rules: [] };
const fmtBytes = (value: number) => {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let scaled = value;
  let unit = 0;
  while (scaled >= 1024 && unit < units.length - 1) {
    scaled /= 1024;
    unit += 1;
  }
  return unit === 0
    ? `${scaled} ${units[unit]}`
    : `${scaled.toFixed(1)} ${units[unit]}`;
};
const fmtPackets = (value: number) => {
  const units = ["", "K", "M", "G", "T", "P", "E"];
  let scaled = value;
  let unit = 0;
  while (scaled >= 1000 && unit < units.length - 1) {
    scaled /= 1000;
    unit += 1;
  }
  return unit === 0
    ? scaled.toLocaleString()
    : `${scaled.toFixed(2)} ${units[unit]}`;
};
const fmtDate = (value?: string) =>
  value ? new Date(value).toLocaleString() : "—";
const fmtPortRange = (value: { start: number; end: number }) =>
  value.start === value.end
    ? String(value.start)
    : `${value.start}–${value.end}`;

async function api<T>(
  path: string,
  init?: RequestInit,
  options: {
    onPasswordRequired?: () => Promise<string | null>;
    retrying?: boolean;
  } = {},
): Promise<T> {
  const credential = await waitForCredential(sessionStorage);
  const response = await fetch(path, {
    ...init,
    headers: buildRequestHeaders(credential, init?.headers),
  });
  if (!response.headers.get("content-type")?.includes("application/json"))
    throw new Error(`API endpoint unavailable (${response.status})`);
  const data = await response.json().catch(() => ({}));
  if (response.status === 401 && options.retrying)
    forgetCredential(sessionStorage, credential || undefined);
  if (
    response.status === 401 &&
    !options.retrying &&
    options.onPasswordRequired
  ) {
    const currentCredential = readCredential(sessionStorage);
    if (currentCredential && currentCredential !== credential)
      return api<T>(path, init, { ...options, retrying: true });
    forgetCredential(sessionStorage, credential || undefined);
    const entered = await recoverCredential(
      sessionStorage,
      options.onPasswordRequired,
    );
    if (entered) return api<T>(path, init, { ...options, retrying: true });
  }
  if (!response.ok)
    throw new Error(
      data.error ||
        data.errors?.join("; ") ||
        `Request failed (${response.status})`,
    );
  return data as T;
}

function App() {
  const [language, setLanguage] = useState<"en" | "zh">(
    navigator.language.toLowerCase().startsWith("zh") ? "zh" : "en",
  );
  const [tab, setTab] = useState<"overview" | "rules" | "backups" | "settings">(
    "overview",
  );
  const [config, setConfig] = useState<Config>(initial);
  const draftDirtyRef = useRef(false);
  const [draftDirty, setDraftDirty] = useState(false);
  const [status, setStatus] = useState<Status | null>(null);
  const [backups, setBackups] = useState<{
    local: unknown[];
    remote: Backup[];
    warning?: string;
  }>({ local: [], remote: [] });
  const [selected, setSelected] = useState<string | null>(null);
  const [message, setMessage] = useState<{ good?: string; bad?: string }>({});
  const [busy, setBusy] = useState(false);
  const dialog = useDialog();
  const t = useCallback(
    (en: string, zh: string) => (language === "zh" ? zh : en),
    [language],
  );
  const passwordPrompt = useRef<Promise<string | null> | null>(null);
  const requestPassword = useCallback(() => {
    if (!passwordPrompt.current) {
      const pending = dialog
        .prompt(
          t("Authentication required", "需要认证"),
          t(
            "Enter the Portalis password or setup token to continue.",
            "请输入 Portalis 密码或 setup token 以继续。",
          ),
          {
            submitLabel: t("Continue", "继续"),
            cancelLabel: t("Cancel", "取消"),
            placeholder: t("Password or setup token", "密码或 setup token"),
          },
        )
        .finally(() => {
          passwordPrompt.current = null;
        });
      passwordPrompt.current = pending;
    }
    return passwordPrompt.current;
  }, [dialog, t]);
  const request = useCallback<ApiRequest>(
    (path, init) => api(path, init, { onPasswordRequired: requestPassword }),
    [requestPassword],
  );
  const updateConfig: Dispatch<SetStateAction<Config>> = (value) => {
    draftDirtyRef.current = true;
    setDraftDirty(true);
    setConfig(value);
  };

  const refresh = useCallback(async () => {
    try {
      const [draft, live] = await Promise.all([
        request<Config>("/api/v1/draft"),
        request<Status>("/api/v1/status"),
      ]);
      if (!draftDirtyRef.current) setConfig(draft);
      setStatus(live);
    } catch (error) {
      setMessage({ bad: String(error) });
    }
  }, [request]);
  useEffect(() => {
    void refresh();
  }, [refresh]);
  useEffect(() => {
    const timer = window.setInterval(() => void refresh(), 5000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const counterMap = useMemo(() => {
    const map = new Map<string, { packets: number; bytes: number }>();
    for (const counter of status?.kernel.counters || []) {
      const old = map.get(counter.rule_id) || { packets: 0, bytes: 0 };
      map.set(counter.rule_id, {
        packets: old.packets + counter.packets,
        bytes: old.bytes + counter.bytes,
      });
    }
    return map;
  }, [status]);
  const save = async () => {
    setBusy(true);
    setMessage({});
    try {
      await request("/api/v1/draft", {
        method: "PUT",
        body: JSON.stringify(config),
      });
      draftDirtyRef.current = false;
      setDraftDirty(false);
      setMessage({
        good: t(
          "Draft saved. Review it, then apply.",
          "草稿已保存。确认无误后再应用。",
        ),
      });
    } catch (error) {
      setMessage({ bad: String(error) });
    } finally {
      setBusy(false);
    }
  };
  const apply = async () => {
    if (
      !(await dialog.confirm(
        t(
          "Apply this draft to nftables? SSH is protected by validation.",
          "将草稿应用到 nftables？验证会保护 SSH 连接。",
        ),
        {
          title: t("Apply changes", "应用变更"),
          confirmLabel: t("Apply", "应用"),
          cancelLabel: t("Cancel", "取消"),
          tone: "danger",
        },
      ))
    )
      return;
    setBusy(true);
    setMessage({});
    try {
      await request("/api/v1/apply", { method: "POST" });
      await refresh();
      setMessage({ good: t("Applied successfully.", "已应用成功。") });
    } catch (error) {
      setMessage({ bad: String(error) });
    } finally {
      setBusy(false);
    }
  };
  const loadBackups = async () => {
    try {
      setBackups(await request<typeof backups>("/api/v1/backups"));
    } catch (error) {
      setMessage({ bad: String(error) });
    }
  };
  useEffect(() => {
    if (tab === "backups") void loadBackups();
  }, [tab]);
  const updateRule = (id: string, patch: Partial<Rule>) =>
    updateConfig((value) => ({
      ...value,
      rules: value.rules.map((rule) =>
        rule.id === id ? { ...rule, ...patch } : rule,
      ),
    }));
  const addRule = () => {
    const rule = emptyRule();
    rule.order = config.rules.length;
    updateConfig((value) => ({ ...value, rules: [...value.rules, rule] }));
    setSelected(rule.id);
    setTab("rules");
  };

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          <img className="brand-mark" src="/portalis-icon.svg" alt="" />
          <span>Portalis</span>
          <span className="brand-divider" />{" "}
          <span className="brand-context">Operator Console</span>
        </div>
        <div className="top-actions">
          <span
            className={`connection-state ${status?.kernel.table_present ? "online" : "offline"}`}
          >
            <IconCircleCheck size={15} stroke={2} />
            {status?.kernel.table_present
              ? t("Connected", "已连接")
              : t("Table offline", "规则表离线")}
          </span>
          <button className="top-button" onClick={() => void refresh()}>
            <IconRefresh size={16} stroke={1.8} />
            {t("Reload data", "重新加载")}
          </button>
          <button className="user-chip">
            <IconUserCircle size={17} stroke={1.8} />
            admin <IconChevronDown size={15} stroke={1.8} />
          </button>
          <button
            className="language"
            onClick={() => setLanguage(language === "en" ? "zh" : "en")}
          >
            {language === "en" ? "中文" : "English"}
          </button>
        </div>
      </header>
      <div className="layout">
        <aside>
          <nav className="sidebar-nav">
            <button
              className={`nav-item ${tab === "overview" ? "active" : ""}`}
              onClick={() => setTab("overview")}
            >
              <IconLayoutDashboard size={18} stroke={1.8} />
              {t("Overview", "概览")}
            </button>
            <div className="nav-section">{t("NETWORK", "网络")}</div>
            <button
              className={`nav-item ${tab === "rules" ? "active" : ""}`}
              onClick={() => setTab("rules")}
            >
              <IconArrowsExchange size={18} stroke={1.8} />
              {t("Forwarding rules", "转发规则")}
            </button>
            <button
              className={`nav-item ${tab === "backups" ? "active" : ""}`}
              onClick={() => setTab("backups")}
            >
              <IconCloudUpload size={18} stroke={1.8} />
              {t("Backups", "备份")}
            </button>
            <div className="nav-section">{t("SYSTEM", "系统")}</div>
            <button className="nav-item" onClick={() => setTab("overview")}>
              <IconShieldCheck size={18} stroke={1.8} />
              {t("Nftables status", "Nftables 状态")}
            </button>
            <button
              className={`nav-item ${tab === "settings" ? "active" : ""}`}
              onClick={() => setTab("settings")}
            >
              <IconSettings size={18} stroke={1.8} />
              {t("Settings", "设置")}
            </button>
          </nav>
          <div className="host-info">
            <div>{t("Host", "主机")}</div>
            <strong>
              <IconServer size={16} stroke={1.8} />
              edge-01
            </strong>
            <div>{t("Kernel", "内核")}</div>
            <strong>6.6.18</strong>
          </div>
        </aside>
        <main>
          <div className="page-head">
            <div>
              <div className="eyebrow">
                {tab === "overview"
                  ? t("LIVE OVERVIEW", "实时概览")
                  : tab === "rules"
                    ? t("NETWORK / FORWARDING", "网络 / 转发")
                    : tab === "backups"
                      ? t("SYSTEM / BACKUPS", "系统 / 备份")
                      : t("SYSTEM / SETTINGS", "系统 / 设置")}
              </div>
              <h1>
                {tab === "overview"
                  ? t("Traffic, at a glance.", "流量，一目了然。")
                  : tab === "rules"
                    ? t("Forwarding rules", "转发规则")
                    : tab === "backups"
                      ? t("Safe restore points", "安全备份点")
                      : t("Gateway settings", "网关设置")}
              </h1>
            </div>
            {tab === "rules" && (
              <button className="primary" onClick={addRule}>
                <IconPlus size={17} stroke={2} />
                {t("New rule", "新建规则")}
              </button>
            )}
          </div>
          {message.good && <div className="toast good">✓ {message.good}</div>}
          {message.bad && <div className="toast bad">! {message.bad}</div>}
          {tab === "overview" && (
            <Overview
              status={status}
              config={config}
              counterMap={counterMap}
              t={t}
              onRules={() => setTab("rules")}
            />
          )}
          {tab === "rules" && (
            <RulesTable
              config={config}
              selected={selected}
              setSelected={setSelected}
              updateRule={updateRule}
              setConfig={updateConfig}
              t={t}
              onSave={save}
              onApply={apply}
              busy={busy}
              dirty={draftDirty}
              counterMap={counterMap}
            />
          )}
          {tab === "backups" && (
            <BackupPanel
              backups={backups}
              t={t}
              request={request}
              onReload={loadBackups}
              setMessage={setMessage}
            />
          )}
          {tab === "settings" && (
            <Settings t={t} request={request} setMessage={setMessage} />
          )}
        </main>
      </div>
    </div>
  );
}

function Overview({
  status,
  config,
  counterMap,
  t,
  onRules,
}: {
  status: Status | null;
  config: Config;
  counterMap: Map<string, { packets: number; bytes: number }>;
  t: (en: string, zh: string) => string;
  onRules: () => void;
}) {
  const packets = [...counterMap.values()].reduce(
    (sum, value) => sum + value.packets,
    0,
  );
  const bytes = [...counterMap.values()].reduce(
    (sum, value) => sum + value.bytes,
    0,
  );
  return (
    <>
      <div className="metric-grid">
        <Metric
          label={t("ACTIVE RULES", "生效规则")}
          value={String(config.rules.filter((rule) => rule.enabled).length)}
          note={
            status?.active_revision
              ? `${status.active_revision.slice(0, 8)}…`
              : t("Not applied", "尚未应用")
          }
        />
        <Metric
          label={t("PACKETS", "数据包")}
          value={fmtPackets(packets)}
          unit={t("packets", "包")}
          note={t("live kernel counter", "内核实时计数")}
        />
        <Metric
          label={t("BYTES", "字节数")}
          value={fmtBytes(bytes)}
          note={t("since last apply", "自上次应用")}
        />
        <Metric
          label={t("FORWARDING", "转发开关")}
          value={
            status?.ipv4_forwarding && status?.ipv6_forwarding
              ? "4 + 6"
              : status?.ipv4_forwarding
                ? "IPv4"
                : status?.ipv6_forwarding
                  ? "IPv6"
                  : "off"
          }
          note={t("kernel sysctl", "内核 sysctl")}
        />
      </div>
      {status?.warnings.map((warning, index) => (
        <div className="warning" key={index}>
          <span>△</span>
          <span>{warning}</span>
        </div>
      ))}
      <section className="card">
        <div className="card-head">
          <div>
            <div className="eyebrow">{t("MANAGED TABLE", "受管表")}</div>
            <h2>inet portalis</h2>
          </div>
          <button className="quiet" onClick={onRules}>
            {t("Manage rules →", "管理规则 →")}
          </button>
        </div>
        <div className="table-state">
          <span
            className={`state-pill ${status?.kernel.table_present ? "online" : "offline"}`}
          >
            {status?.kernel.table_present
              ? t("ONLINE", "在线")
              : t("NOT APPLIED", "未应用")}
          </span>
          <span>
            {status?.kernel.drifted
              ? t("Kernel drift detected", "检测到内核漂移")
              : t("Matches active revision", "与生效版本一致")}
          </span>
          <span className="muted">
            {t("Observed", "观测时间")} {status?.kernel.observed_at || "—"}
          </span>
        </div>
      </section>
      <section className="card">
        <div className="card-head">
          <div>
            <div className="eyebrow">
              {t("RECENT RULE ACTIVITY", "最近规则活动")}
            </div>
            <h2>{t("Live counters", "实时计数")}</h2>
          </div>
          <span className="muted">
            {t(
              "TCP and UDP are separate kernel rules",
              "TCP 与 UDP 是独立内核规则",
            )}
          </span>
        </div>
        {config.rules.length === 0 ? (
          <Empty t={t} />
        ) : (
          <div className="activity-list">
            {config.rules.slice(0, 6).map((rule) => {
              const counter = counterMap.get(rule.id) || {
                packets: 0,
                bytes: 0,
              };
              const tcp = status?.kernel.counters.find(
                (item) => item.rule_id === rule.id && item.protocol === "tcp",
              );
              const udp = status?.kernel.counters.find(
                (item) => item.rule_id === rule.id && item.protocol === "udp",
              );
              const packetUnit = t("packets", "包");
              return (
                <div className="activity-row" key={rule.id}>
                  <span
                    className={`rule-dot ${rule.enabled ? "" : "disabled"}`}
                  />
                  <div className="activity-name">
                    <strong>{rule.name}</strong>
                    <span>
                      {rule.family.toUpperCase()} ·{" "}
                      {rule.protocols.tcp && rule.protocols.udp
                        ? "TCP + UDP"
                        : rule.protocols.tcp
                          ? "TCP"
                          : "UDP"}
                    </span>
                  </div>
                  <strong>
                    {fmtPackets(counter.packets)} <small>{packetUnit}</small>
                  </strong>
                  <div className="activity-stats muted">
                    <span>{fmtBytes(counter.bytes)}</span>
                    {tcp && (
                      <span>
                        TCP {fmtPackets(tcp.packets)} {packetUnit}
                      </span>
                    )}
                    {udp && (
                      <span>
                        UDP {fmtPackets(udp.packets)} {packetUnit}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>
    </>
  );
}

function Metric({
  label,
  value,
  unit,
  note,
}: {
  label: string;
  value: string;
  unit?: string;
  note: string;
}) {
  return (
    <div className="metric card">
      <div className="eyebrow">{label}</div>
      <strong>
        {value}
        {unit && <small> {unit}</small>}
      </strong>
      <span>{note}</span>
    </div>
  );
}
function Empty({ t }: { t: (en: string, zh: string) => string }) {
  return (
    <div className="empty">
      {t(
        "No rules yet. Add a forwarding rule to get started.",
        "还没有规则。新增一条转发规则开始使用。",
      )}
    </div>
  );
}

function RulesTable({
  config,
  selected,
  setSelected,
  updateRule,
  setConfig,
  t,
  onSave,
  onApply,
  busy,
  dirty,
  counterMap,
}: {
  config: Config;
  selected: string | null;
  setSelected: (value: string | null) => void;
  updateRule: (id: string, patch: Partial<Rule>) => void;
  setConfig: Dispatch<SetStateAction<Config>>;
  t: (en: string, zh: string) => string;
  onSave: () => void;
  onApply: () => void;
  busy: boolean;
  dirty: boolean;
  counterMap: Map<string, { packets: number; bytes: number }>;
}) {
  const [query, setQuery] = useState("");
  const [family, setFamily] = useState<Family | "all">("all");
  const [state, setState] = useState<"all" | "enabled" | "disabled">("all");
  const visibleRules = config.rules.filter((rule) => {
    const haystack =
      `${rule.name} ${rule.target_ip} ${rule.comment} ${fmtPortRange(rule.listen_port)} ${fmtPortRange(rule.target_port)}`.toLowerCase();
    return (
      (!query || haystack.includes(query.toLowerCase())) &&
      (family === "all" || rule.family === family) &&
      (state === "all" || (state === "enabled" ? rule.enabled : !rule.enabled))
    );
  });
  const current =
    config.rules.find((rule) => rule.id === selected) ||
    visibleRules[0] ||
    config.rules[0];
  return (
    <div className="rules-page">
      <section className="rule-table card">
        <div className="table-heading">
          <div>
            <h2>{t("Rule inventory", "规则清单")}</h2>
            <p>
              {t(
                "Manage the forwarding rules owned by this host.",
                "管理此主机上的转发规则。",
              )}
            </p>
          </div>
          <span className="table-count">
            {visibleRules.length} / {config.rules.length}
          </span>
        </div>
        <div className="table-toolbar">
          <label className="search-field">
            <IconSearch size={17} stroke={1.8} />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder={t("Search rules", "搜索规则")}
            />
          </label>
          <div className="table-filters">
            <select
              aria-label={t("Filter by address family", "按地址族筛选")}
              value={family}
              onChange={(event) =>
                setFamily(event.target.value as Family | "all")
              }
            >
              <option value="all">{t("All families", "全部地址族")}</option>
              <option value="auto">Auto</option>
              <option value="ipv4">IPv4</option>
              <option value="ipv6">IPv6</option>
            </select>
            <select
              aria-label={t("Filter by status", "按状态筛选")}
              value={state}
              onChange={(event) =>
                setState(event.target.value as "all" | "enabled" | "disabled")
              }
            >
              <option value="all">{t("All states", "全部状态")}</option>
              <option value="enabled">{t("Enabled", "已启用")}</option>
              <option value="disabled">{t("Disabled", "已停用")}</option>
            </select>
          </div>
        </div>
        {config.rules.length === 0 ? (
          <Empty t={t} />
        ) : visibleRules.length === 0 ? (
          <div className="empty">
            {t("No rules match this filter.", "没有符合筛选条件的规则。")}
          </div>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>{t("State", "状态")}</th>
                  <th>{t("Listen port", "监听端口")}</th>
                  <th>{t("Protocol", "协议")}</th>
                  <th>{t("Family", "地址族")}</th>
                  <th>{t("Target IP", "目标 IP")}</th>
                  <th>{t("Target port", "目标端口")}</th>
                  <th>{t("Interface", "接口")}</th>
                  <th>{t("Comment", "备注")}</th>
                  <th aria-label="Actions" />
                </tr>
              </thead>
              <tbody>
                {visibleRules.map((rule) => {
                  const counter = counterMap.get(rule.id) || {
                    packets: 0,
                    bytes: 0,
                  };
                  return (
                    <tr
                      className={current?.id === rule.id ? "selected" : ""}
                      key={rule.id}
                      onClick={() => setSelected(rule.id)}
                      onKeyDown={(event) => {
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault();
                          setSelected(rule.id);
                        }
                      }}
                      tabIndex={0}
                    >
                      <td className="table-number">{rule.order + 1}</td>
                      <td>
                        <span
                          className={`status-tag ${rule.enabled ? "active" : "inactive"}`}
                        >
                          {rule.enabled
                            ? t("Enabled", "已启用")
                            : t("Disabled", "已停用")}
                        </span>
                      </td>
                      <td className="mono">{fmtPortRange(rule.listen_port)}</td>
                      <td>
                        {rule.protocols.tcp && rule.protocols.udp
                          ? "TCP + UDP"
                          : rule.protocols.tcp
                            ? "TCP"
                            : rule.protocols.udp
                              ? "UDP"
                              : "—"}
                      </td>
                      <td>{rule.family === "auto" ? "inet" : rule.family}</td>
                      <td className="mono">{rule.target_ip}</td>
                      <td className="mono">{fmtPortRange(rule.target_port)}</td>
                      <td>{rule.listen_interface || "—"}</td>
                      <td className="comment-cell">
                        {rule.comment || "—"}
                        <small>
                          {fmtPackets(counter.packets)} {t("packets", "包")}
                        </small>
                      </td>
                      <td className="row-action">
                        <IconDotsVertical size={17} stroke={1.8} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {current ? (
        <RuleEditor
          rule={current}
          updateRule={updateRule}
          setConfig={setConfig}
          t={t}
        />
      ) : (
        <section className="card editor empty">
          {t("Select a rule to edit.", "选择一条规则进行编辑。")}
        </section>
      )}
      <div className={`action-bar ${dirty ? "dirty" : ""}`}>
        <div className="action-summary">
          <span className="action-icon">
            {dirty ? (
              <IconAlertTriangle size={19} stroke={1.9} />
            ) : (
              <IconCheck size={19} stroke={2} />
            )}
          </span>
          <div>
            <strong>
              {dirty
                ? t("Unsaved draft changes.", "有未保存的草稿变更。")
                : t("Draft is saved.", "草稿已保存。")}
            </strong>
            <span>
              {t(
                "Save stores your edits. Apply changes updates nftables.",
                "保存只存储编辑内容，应用会更新 nftables。",
              )}
            </span>
          </div>
        </div>
        <div className="action-meta">
          {config.rules.length} {t("rules", "条规则")}
        </div>
        <div className="action-buttons">
          <button className="secondary" disabled={busy} onClick={onSave}>
            {t("Save draft", "保存草稿")}
          </button>
          <button className="primary" disabled={busy} onClick={onApply}>
            {busy ? t("Working…", "处理中…") : t("Apply changes", "应用变更")}
          </button>
        </div>
      </div>
    </div>
  );
}

function Rules({
  config,
  selected,
  setSelected,
  updateRule,
  setConfig,
  t,
  onSave,
  onApply,
  busy,
  counterMap,
}: {
  config: Config;
  selected: string | null;
  setSelected: (value: string | null) => void;
  updateRule: (id: string, patch: Partial<Rule>) => void;
  setConfig: Dispatch<SetStateAction<Config>>;
  t: (en: string, zh: string) => string;
  onSave: () => void;
  onApply: () => void;
  busy: boolean;
  counterMap: Map<string, { packets: number; bytes: number }>;
}) {
  const current =
    config.rules.find((rule) => rule.id === selected) || config.rules[0];
  return (
    <div className="rules-layout">
      <section className="card rule-list">
        <div className="card-head">
          <h2>{t("Draft rules", "草稿规则")}</h2>
          <span className="muted">{config.rules.length}</span>
        </div>
        {config.rules.length === 0 ? (
          <Empty t={t} />
        ) : (
          config.rules.map((rule) => {
            const counter = counterMap.get(rule.id) || { packets: 0, bytes: 0 };
            return (
              <button
                className={`rule-card ${current?.id === rule.id ? "selected" : ""}`}
                key={rule.id}
                onClick={() => setSelected(rule.id)}
              >
                <span
                  className={`rule-dot ${rule.enabled ? "" : "disabled"}`}
                />
                <span>
                  <strong>{rule.name}</strong>
                  <small>
                    {rule.family.toUpperCase()} ·{" "}
                    {rule.protocols.tcp && rule.protocols.udp
                      ? "TCP + UDP"
                      : rule.protocols.tcp
                        ? "TCP"
                        : "UDP"}
                  </small>
                </span>
                <em>
                  {fmtPackets(counter.packets)} {t("packets", "包")}
                </em>
              </button>
            );
          })
        )}
      </section>
      {current ? (
        <RuleEditor
          rule={current}
          updateRule={updateRule}
          setConfig={setConfig}
          t={t}
        />
      ) : (
        <section className="card editor empty">
          {t("Select a rule to edit.", "选择一条规则进行编辑。")}
        </section>
      )}
      <div className="action-bar">
        <span className="muted">
          {t(
            "Save is draft-only. Apply changes the kernel atomically.",
            "保存只写入草稿。应用会原子更新内核规则。",
          )}
        </span>
        <div>
          <button className="secondary" disabled={busy} onClick={onSave}>
            {t("Save draft", "保存草稿")}
          </button>
          <button className="primary" disabled={busy} onClick={onApply}>
            {busy ? t("Working…", "处理中…") : t("Apply changes", "应用变更")}
          </button>
        </div>
      </div>
    </div>
  );
}

function RuleEditor({
  rule,
  updateRule,
  setConfig,
  t,
}: {
  rule: Rule;
  updateRule: (id: string, patch: Partial<Rule>) => void;
  setConfig: Dispatch<SetStateAction<Config>>;
  t: (en: string, zh: string) => string;
}) {
  const dialog = useDialog();
  const patch = (value: Partial<Rule>) => updateRule(rule.id, value);
  const port = (
    key: "listen_port" | "target_port",
    field: "start" | "end",
    value: string,
  ) =>
    updateRule(rule.id, {
      [key]: { ...rule[key], [field]: Number(value) || 0 },
    } as Partial<Rule>);
  const remove = async () => {
    if (
      !(await dialog.confirm(
        t("Delete this draft rule?", "删除这条草稿规则？"),
        {
          title: t("Delete rule", "删除规则"),
          confirmLabel: t("Delete", "删除"),
          cancelLabel: t("Cancel", "取消"),
          tone: "danger",
        },
      ))
    )
      return;
    setConfig((value) => ({
      ...value,
      rules: value.rules.filter((item) => item.id !== rule.id),
    }));
  };
  return (
    <section className="card editor">
      <div className="editor-head">
        <div>
          <div className="eyebrow">{t("RULE CONFIGURATION", "规则配置")}</div>
          <h2>{rule.name}</h2>
        </div>
        <label className="switch">
          <input
            type="checkbox"
            checked={rule.enabled}
            onChange={(event) => patch({ enabled: event.target.checked })}
          />
          <span />
          {t("Enabled", "启用")}
        </label>
      </div>
      <div className="form-grid">
        <label className="wide">
          {t("Rule name", "规则名称")}
          <input
            value={rule.name}
            onChange={(event) => patch({ name: event.target.value })}
          />
        </label>
        <label>
          {t("Address family", "地址族")}
          <select
            value={rule.family}
            onChange={(event) =>
              patch({ family: event.target.value as Family })
            }
          >
            <option value="auto">
              {t("Auto (from target IP)", "自动（根据目标 IP）")}
            </option>
            <option value="ipv4">IPv4</option>
            <option value="ipv6">IPv6</option>
          </select>
        </label>
        <label>
          {t("Protocols", "协议")}
          <span className="checks">
            <label>
              <input
                type="checkbox"
                checked={rule.protocols.tcp}
                onChange={(event) =>
                  patch({
                    protocols: { ...rule.protocols, tcp: event.target.checked },
                  })
                }
              />{" "}
              TCP
            </label>
            <label>
              <input
                type="checkbox"
                checked={rule.protocols.udp}
                onChange={(event) =>
                  patch({
                    protocols: { ...rule.protocols, udp: event.target.checked },
                  })
                }
              />{" "}
              UDP
            </label>
          </span>
        </label>
        <label>
          {t("Listen port", "监听端口")}
          <span className="range">
            <input
              type="number"
              min="1"
              max="65535"
              value={rule.listen_port.start}
              onChange={(event) =>
                port("listen_port", "start", event.target.value)
              }
            />
            <i>—</i>
            <input
              type="number"
              min="1"
              max="65535"
              value={rule.listen_port.end}
              onChange={(event) =>
                port("listen_port", "end", event.target.value)
              }
            />
          </span>
        </label>
        <label>
          {t("Target port", "目标端口")}
          <span className="range">
            <input
              type="number"
              min="1"
              max="65535"
              value={rule.target_port.start}
              onChange={(event) =>
                port("target_port", "start", event.target.value)
              }
            />
            <i>—</i>
            <input
              type="number"
              min="1"
              max="65535"
              value={rule.target_port.end}
              onChange={(event) =>
                port("target_port", "end", event.target.value)
              }
            />
          </span>
          <small>{t("Ranges map one-to-one", "范围按一一对应映射")}</small>
        </label>
        <label className="wide">
          {t("Target IP", "目标 IP")}
          <input
            value={rule.target_ip}
            placeholder={rule.family === "ipv6" ? "2001:db8::10" : "192.0.2.10"}
            onChange={(event) => patch({ target_ip: event.target.value })}
          />
        </label>
        <label>
          {t("Listen address", "监听地址")}
          <select
            value={rule.listen_address === "any" ? "any" : "address"}
            onChange={(event) =>
              patch({
                listen_address:
                  event.target.value === "any"
                    ? "any"
                    : { address: rule.family === "ipv6" ? "::" : "0.0.0.0" },
              })
            }
          >
            <option value="any">{t("Any address", "全部地址")}</option>
            <option value="address">{t("Specific IP", "指定 IP")}</option>
          </select>
        </label>
        {rule.listen_address !== "any" && (
          <label>
            {t("Listen IP", "监听 IP")}
            <input
              value={rule.listen_address.address}
              onChange={(event) =>
                patch({ listen_address: { address: event.target.value } })
              }
            />
          </label>
        )}
        <label>
          {t("SNAT mode", "SNAT 模式")}
          <select
            value={rule.snat.mode}
            onChange={(event) =>
              patch({
                snat:
                  event.target.value === "fixed"
                    ? { mode: "fixed", address: rule.target_ip }
                    : { mode: event.target.value as "none" | "masquerade" },
              })
            }
          >
            <option value="masquerade">
              {t("Masquerade (recommended)", "伪装（推荐）")}
            </option>
            <option value="none">{t("None", "不使用")}</option>
            <option value="fixed">{t("Fixed source IP", "固定源 IP")}</option>
          </select>
        </label>
        {rule.snat.mode === "fixed" && (
          <label>
            {t("SNAT source IP", "SNAT 源 IP")}
            <input
              value={rule.snat.address}
              onChange={(event) =>
                patch({ snat: { mode: "fixed", address: rule.snat.address } })
              }
            />
          </label>
        )}
        <label className="wide">
          {t(
            "Source CIDRs (optional, one per line)",
            "来源 CIDR（可选，每行一个）",
          )}
          <textarea
            value={rule.source_cidrs.join("\n")}
            onChange={(event) =>
              patch({
                source_cidrs: event.target.value
                  .split(/[,\n]/)
                  .map((value) => value.trim())
                  .filter(Boolean),
              })
            }
            placeholder={t("Leave empty for all sources", "留空表示所有来源")}
          />
        </label>
        <label className="wide">
          {t("Comment", "备注")}
          <input
            value={rule.comment}
            onChange={(event) => patch({ comment: event.target.value })}
          />
        </label>
        <label className="wide checkline">
          <input
            type="checkbox"
            checked={rule.allow_ssh_conflict}
            onChange={(event) =>
              patch({ allow_ssh_conflict: event.target.checked })
            }
          />
          {t(
            "Advanced: allow overlapping detected SSH port",
            "高级：允许覆盖检测到的 SSH 端口",
          )}
        </label>
      </div>
      <button className="danger-link" onClick={() => void remove()}>
        {t("Delete this draft rule", "删除这条草稿规则")}
      </button>
    </section>
  );
}

function BackupPanel({
  backups,
  t,
  request,
  onReload,
  setMessage,
}: {
  backups: { local: unknown[]; remote: Backup[]; warning?: string };
  t: (en: string, zh: string) => string;
  request: ApiRequest;
  onReload: () => Promise<void>;
  setMessage: (value: { good?: string; bad?: string }) => void;
}) {
  const dialog = useDialog();
  const [busy, setBusy] = useState(false);
  const [profile, setProfile] = useState({
    provider: "aws",
    endpoint: "",
    region: "us-east-1",
    bucket: "",
    prefix: "portalis",
    path_style: false,
    access_key_id: "",
    secret_access_key: "",
  });
  useEffect(() => {
    void request<{
      profile?: Omit<typeof profile, "access_key_id" | "secret_access_key">;
    }>("/api/v1/settings/s3")
      .then((value) => {
        if (value.profile)
          setProfile((current) => ({ ...current, ...value.profile }));
      })
      .catch(() => undefined);
  }, [request]);
  const save = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    try {
      const secrets =
        profile.access_key_id && profile.secret_access_key
          ? {
              access_key_id: profile.access_key_id,
              secret_access_key: profile.secret_access_key,
            }
          : undefined;
      await request("/api/v1/settings/s3", {
        method: "PUT",
        body: JSON.stringify({
          profile: {
            provider: profile.provider,
            endpoint: profile.endpoint,
            region: profile.region,
            bucket: profile.bucket,
            prefix: profile.prefix,
            path_style: profile.path_style,
          },
          secrets,
        }),
      });
      setMessage({ good: t("S3 settings saved.", "S3 设置已保存。") });
    } catch (error) {
      setMessage({ bad: String(error) });
    } finally {
      setBusy(false);
    }
  };
  const backup = async () => {
    setBusy(true);
    try {
      await request("/api/v1/backups", { method: "POST" });
      await onReload();
      setMessage({
        good: t("Active revision backed up.", "当前生效版本已备份。"),
      });
    } catch (error) {
      setMessage({ bad: String(error) });
    } finally {
      setBusy(false);
    }
  };
  const restore = async (key: string) => {
    if (
      !(await dialog.confirm(
        t(
          "Import this backup as a draft? It will not apply until you confirm.",
          "将此备份导入为草稿？确认应用前不会改变系统。",
        ),
        {
          title: t("Import backup", "导入备份"),
          confirmLabel: t("Import", "导入"),
          cancelLabel: t("Cancel", "取消"),
        },
      ))
    )
      return;
    try {
      await request("/api/v1/backups/restore", {
        method: "POST",
        body: JSON.stringify({ key }),
      });
      setMessage({
        good: t("Backup imported as a draft.", "备份已导入为草稿。"),
      });
    } catch (error) {
      setMessage({ bad: String(error) });
    }
  };
  return (
    <>
      <section className="card">
        <div className="card-head">
          <div>
            <div className="eyebrow">
              {t("S3-COMPATIBLE STORAGE", "S3 兼容存储")}
            </div>
            <h2>{t("Remote backups", "远程备份")}</h2>
          </div>
          <button className="primary" disabled={busy} onClick={backup}>
            {t("Backup active now", "立即备份当前版本")}
          </button>
        </div>
        <p className="muted">
          {t(
            "AWS S3, MinIO, Cloudflare R2 and custom endpoints are supported. Scheduled backups run daily at 03:00 and retain the latest 10 revisions.",
            "支持 AWS S3、MinIO、Cloudflare R2 和自定义端点。每日 03:00 自动备份，仅保留最近 10 个版本。",
          )}
        </p>
        {backups.warning && (
          <div className="warning">
            <span>△</span>
            {backups.warning}
          </div>
        )}
        <div className="backup-list">
          {backups.remote.length === 0 ? (
            <Empty t={t} />
          ) : (
            backups.remote.map((item) => (
              <div className="backup-row" key={item.key}>
                <div>
                  <strong>{item.key}</strong>
                  <span>
                    {fmtBytes(item.size_bytes)} · {fmtDate(item.last_modified)}
                  </span>
                </div>
                <button
                  className="quiet"
                  onClick={() => void restore(item.key)}
                >
                  {t("Import draft", "导入草稿")}
                </button>
              </div>
            ))
          )}
        </div>
      </section>
      <section className="card">
        <div className="eyebrow">{t("STORAGE CONNECTION", "存储连接")}</div>
        <h2>{t("Configure S3", "配置 S3")}</h2>
        <form className="form-grid" onSubmit={save}>
          <label>
            {t("Provider", "提供商")}
            <select
              value={profile.provider}
              onChange={(event) =>
                setProfile({ ...profile, provider: event.target.value })
              }
            >
              <option value="aws">AWS S3</option>
              <option value="minio">MinIO</option>
              <option value="r2">Cloudflare R2</option>
              <option value="custom">Custom</option>
            </select>
          </label>
          <label>
            {t("Region", "区域")}
            <input
              value={profile.region}
              onChange={(event) =>
                setProfile({ ...profile, region: event.target.value })
              }
            />
          </label>
          <label className="wide">
            Endpoint{" "}
            <small>
              {profile.provider === "aws"
                ? t("Optional for AWS default endpoint", "AWS 默认端点可留空")
                : t("Required for this provider", "此提供商必填")}
            </small>
            <input
              required={profile.provider !== "aws"}
              value={profile.endpoint}
              placeholder="https://s3.example.com"
              onChange={(event) =>
                setProfile({ ...profile, endpoint: event.target.value })
              }
            />
          </label>
          <label>
            Bucket
            <input
              required
              value={profile.bucket}
              onChange={(event) =>
                setProfile({ ...profile, bucket: event.target.value })
              }
            />
          </label>
          <label>
            Prefix
            <input
              value={profile.prefix}
              onChange={(event) =>
                setProfile({ ...profile, prefix: event.target.value })
              }
            />
          </label>
          <label>
            Access key
            <input
              value={profile.access_key_id}
              autoComplete="off"
              onChange={(event) =>
                setProfile({ ...profile, access_key_id: event.target.value })
              }
            />
          </label>
          <label>
            Secret key
            <input
              type="password"
              value={profile.secret_access_key}
              autoComplete="new-password"
              onChange={(event) =>
                setProfile({
                  ...profile,
                  secret_access_key: event.target.value,
                })
              }
            />
          </label>
          <label className="checkline">
            <input
              type="checkbox"
              checked={profile.path_style}
              onChange={(event) =>
                setProfile({ ...profile, path_style: event.target.checked })
              }
            />
            {t("Use path-style addressing", "使用 path-style 地址")}
          </label>
          <div className="wide">
            <button className="secondary" disabled={busy}>
              {t("Save storage settings", "保存存储设置")}
            </button>
          </div>
        </form>
      </section>
    </>
  );
}

function Settings({
  t,
  request,
  setMessage,
}: {
  t: (en: string, zh: string) => string;
  request: ApiRequest;
  setMessage: (value: { good?: string; bad?: string }) => void;
}) {
  const [password, setPassword] = useState("");
  const save = async (event: FormEvent) => {
    event.preventDefault();
    try {
      await request("/api/v1/auth/password", {
        method: "POST",
        body: JSON.stringify({ password }),
      });
      setPassword("");
      setMessage({
        good: t("Password enabled for web access.", "已为 Web 访问启用密码。"),
      });
    } catch (error) {
      setMessage({ bad: String(error) });
    }
  };
  return (
    <section className="card narrow">
      <div className="eyebrow">{t("ACCESS CONTROL", "访问控制")}</div>
      <h2>{t("Web authentication", "Web 认证")}</h2>
      <p className="muted">
        {t(
          "Portalis permits passwordless access only when no Web password is configured and both the TCP peer and HTTP Host are loopback. Configure a strong password before exposing the web listener or using a reverse proxy. Cross-origin writes are rejected.",
          "Portalis 仅在未配置 Web 密码且 TCP 对端与 HTTP Host 都是本机地址时允许免密码访问。暴露 Web 监听或使用反向代理前，请先配置强密码。跨域写操作会被拒绝。",
        )}
      </p>
      <form onSubmit={save}>
        <label>
          {t("New password (12+ characters)", "新密码（至少 12 个字符）")}
          <input
            type="password"
            minLength={12}
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </label>
        <button className="primary" type="submit">
          {t("Set password", "设置密码")}
        </button>
      </form>
      <div className="info-block">
        <strong>{t("SSH protection", "SSH 保护")}</strong>
        <span>
          {t(
            "TCP/UDP forwarding rules that overlap detected SSH ports are rejected by default. Portalis never changes SSH or global firewall policies.",
            "默认拒绝覆盖检测到的 SSH 端口的 TCP/UDP 转发规则。Portalis 不会修改 SSH 或全局防火墙策略。",
          )}
        </span>
      </div>
    </section>
  );
}

createRoot(document.getElementById("root")!).render(
  <DialogProvider>
    <App />
  </DialogProvider>,
);
