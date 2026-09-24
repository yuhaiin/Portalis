import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type {
  Dispatch,
  FormEvent,
  KeyboardEvent as ReactKeyboardEvent,
  ReactNode,
  SetStateAction,
} from "react";
import {
  IconAlertTriangle,
  IconArrowsExchange,
  IconCheck,
  IconChevronDown,
  IconCircleCheck,
  IconCloudUpload,
  IconDotsVertical,
  IconInfoCircle,
  IconLayoutDashboard,
  IconPlus,
  IconRefresh,
  IconSearch,
  IconServer,
  IconSettings,
  IconUserCircle,
} from "@tabler/icons-react";
import { createPortal } from "react-dom";
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
type Translator = (text: string) => string;
type SelectOption = { value: string; label: string };
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
type AboutInfo = {
  name: string;
  version: string;
  hostname: string | null;
  operating_system: string;
  kernel_release: string | null;
  architecture: string;
  api_version: string;
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

type SelectPosition = {
  left: number;
  top?: number;
  bottom?: number;
  width: number;
  maxHeight: number;
};

function SelectControl({
  value,
  options,
  ariaLabel,
  onValueChange,
}: {
  value: string;
  options: SelectOption[];
  ariaLabel: string;
  onValueChange: (value: string) => void;
}) {
  const id = useId();
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const [position, setPosition] = useState<SelectPosition | null>(null);
  const selectedIndex = Math.max(
    0,
    options.findIndex((option) => option.value === value),
  );
  const selectedOption = options[selectedIndex];
  const popupId = `${id}-options`;

  const openSelect = () => {
    setActiveIndex(selectedIndex);
    setOpen(true);
  };

  const chooseOption = (index: number) => {
    const option = options[index];
    if (!option) return;
    onValueChange(option.value);
    setOpen(false);
    triggerRef.current?.focus();
  };

  useEffect(() => {
    if (!open) return undefined;
    const closeOnOutsidePointer = (event: PointerEvent) => {
      const target = event.target;
      if (
        target instanceof Node &&
        !rootRef.current?.contains(target) &&
        !menuRef.current?.contains(target)
      ) {
        setOpen(false);
      }
    };
    document.addEventListener("pointerdown", closeOnOutsidePointer);
    return () =>
      document.removeEventListener("pointerdown", closeOnOutsidePointer);
  }, [open]);

  useLayoutEffect(() => {
    if (!open) return undefined;
    const updatePosition = () => {
      const trigger = triggerRef.current;
      if (!trigger) return;
      const rect = trigger.getBoundingClientRect();
      const maxMenuHeight = Math.min(280, window.innerHeight - 20);
      const estimatedHeight = Math.min(options.length * 42 + 12, maxMenuHeight);
      const spaceBelow = window.innerHeight - rect.bottom - 10;
      const spaceAbove = rect.top - 10;
      const opensAbove = spaceBelow < estimatedHeight && spaceAbove > spaceBelow;
      const availableHeight = opensAbove ? spaceAbove : spaceBelow;
      const width = Math.min(rect.width, window.innerWidth - 16);
      setPosition({
        left: Math.max(8, Math.min(rect.left, window.innerWidth - width - 8)),
        top: opensAbove ? undefined : rect.bottom + 6,
        bottom: opensAbove ? window.innerHeight - rect.top + 6 : undefined,
        width,
        maxHeight: Math.max(90, Math.min(maxMenuHeight, availableHeight)),
      });
    };
    const repositionOnScroll = (event: Event) => {
      if (
        event.target instanceof Node &&
        menuRef.current?.contains(event.target)
      ) {
        return;
      }
      updatePosition();
    };
    updatePosition();
    window.addEventListener("resize", updatePosition);
    window.addEventListener("scroll", repositionOnScroll, true);
    return () => {
      window.removeEventListener("resize", updatePosition);
      window.removeEventListener("scroll", repositionOnScroll, true);
    };
  }, [open, options.length]);

  useEffect(() => {
    if (open) {
      document
        .getElementById(`${popupId}-option-${activeIndex}`)
        ?.scrollIntoView({ block: "nearest" });
    }
  }, [activeIndex, open, popupId]);

  const onKeyDown = (event: ReactKeyboardEvent<HTMLButtonElement>) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      if (!open) {
        openSelect();
        return;
      }
      const step = event.key === "ArrowDown" ? 1 : -1;
      setActiveIndex((index) =>
        Math.max(0, Math.min(options.length - 1, index + step)),
      );
      return;
    }
    if (event.key === "Home" && open) {
      event.preventDefault();
      setActiveIndex(0);
      return;
    }
    if (event.key === "End" && open) {
      event.preventDefault();
      setActiveIndex(options.length - 1);
      return;
    }
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      if (open) chooseOption(activeIndex);
      else openSelect();
      return;
    }
    if (event.key === "Escape" && open) {
      event.preventDefault();
      setOpen(false);
      return;
    }
    if (event.key === "Tab" && open) setOpen(false);
  };

  return (
    <div className={`select-control ${open ? "open" : ""}`} ref={rootRef}>
      <button
        ref={triggerRef}
        type="button"
        className="select-trigger"
        role="combobox"
        aria-label={ariaLabel}
        aria-expanded={open}
        aria-controls={open ? popupId : undefined}
        aria-haspopup="listbox"
        aria-activedescendant={
          open ? `${popupId}-option-${activeIndex}` : undefined
        }
        onClick={() => (open ? setOpen(false) : openSelect())}
        onKeyDown={onKeyDown}
      >
        <span>{selectedOption?.label ?? value}</span>
        <IconChevronDown size={18} stroke={1.8} aria-hidden="true" />
      </button>
      {open &&
        position &&
        createPortal(
          <div
            ref={menuRef}
            id={popupId}
            className="select-menu"
            role="listbox"
            aria-label={ariaLabel}
            style={position}
          >
            {options.map((option, index) => (
              <div
                id={`${popupId}-option-${index}`}
                key={option.value}
                className="select-option"
                role="option"
                aria-selected={index === selectedIndex}
                data-active={index === activeIndex}
                onPointerEnter={() => setActiveIndex(index)}
                onClick={() => chooseOption(index)}
              >
                <span>{option.label}</span>
                {index === selectedIndex && (
                  <IconCheck size={16} stroke={2} aria-hidden="true" />
                )}
              </div>
            ))}
          </div>,
          document.body,
        )}
    </div>
  );
}

function App() {
  const [tab, setTab] = useState<
    "overview" | "rules" | "backups" | "settings" | "about"
  >("overview");
  const [accountMenuOpen, setAccountMenuOpen] = useState(false);
  const [hasSavedCredential, setHasSavedCredential] = useState(() =>
    Boolean(readCredential(sessionStorage)),
  );
  const accountMenuRef = useRef<HTMLDivElement>(null);
  const [config, setConfig] = useState<Config>(initial);
  const draftDirtyRef = useRef(false);
  const [draftDirty, setDraftDirty] = useState(false);
  const [status, setStatus] = useState<Status | null>(null);
  const [aboutInfo, setAboutInfo] = useState<AboutInfo | null>(null);
  const [aboutLoading, setAboutLoading] = useState(false);
  const [backups, setBackups] = useState<{
    local: unknown[];
    remote: Backup[];
    warning?: string;
  }>({ local: [], remote: [] });
  const [selected, setSelected] = useState<string | null>(null);
  const [message, setMessage] = useState<{ good?: string; bad?: string }>({});
  const [busy, setBusy] = useState(false);
  const dialog = useDialog();
  const t = useCallback((text: string) => text, []);
  const passwordPrompt = useRef<Promise<string | null> | null>(null);
  useEffect(() => {
    if (!accountMenuOpen) return undefined;
    const closeOnOutsidePointer = (event: PointerEvent) => {
      const target = event.target;
      if (
        target instanceof Node &&
        !accountMenuRef.current?.contains(target)
      ) {
        setAccountMenuOpen(false);
      }
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setAccountMenuOpen(false);
    };
    document.addEventListener("pointerdown", closeOnOutsidePointer);
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("pointerdown", closeOnOutsidePointer);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, [accountMenuOpen]);
  const requestPassword = useCallback(() => {
    if (!passwordPrompt.current) {
      const pending = dialog
        .prompt(
          t("Authentication required"),
          t(
            "Enter the Portalis password or setup token to continue."),
          {
            submitLabel: t("Continue"),
            cancelLabel: t("Cancel"),
            placeholder: t("Password or setup token"),
          },
        )
        .then((credential) => {
          if (credential) setHasSavedCredential(true);
          return credential;
        })
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
          "Draft saved. Review it, then apply."),
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
          "Apply this draft to nftables? SSH is protected by validation."),
        {
          title: t("Apply changes"),
          confirmLabel: t("Apply"),
          cancelLabel: t("Cancel"),
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
      setMessage({ good: t("Applied successfully.") });
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
  const loadAbout = useCallback(async () => {
    setAboutLoading(true);
    try {
      setAboutInfo(await request<AboutInfo>("/api/v1/about"));
    } catch (error) {
      setMessage({ bad: String(error) });
    } finally {
      setAboutLoading(false);
    }
  }, [request]);
  useEffect(() => {
    if (tab === "about") void loadAbout();
  }, [tab, loadAbout]);
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
        </div>
        <div className="top-actions">
          <span
            className={`connection-state ${status?.kernel.table_present ? "online" : "offline"}`}
          >
            <IconCircleCheck size={15} stroke={2} />
            {status?.kernel.table_present
              ? t("Connected")
              : t("Table offline")}
          </span>
          <button className="top-button" onClick={() => void refresh()}>
            <IconRefresh size={16} stroke={1.8} />
            {t("Reload data")}
          </button>
          <div className="account-menu" ref={accountMenuRef}>
            <button
              className="user-chip"
              aria-expanded={accountMenuOpen}
              aria-controls={accountMenuOpen ? "account-actions" : undefined}
              onClick={() => setAccountMenuOpen((open) => !open)}
            >
              <IconUserCircle size={17} stroke={1.8} aria-hidden="true" />
              <span>{t("Web access")}</span>
              <IconChevronDown size={15} stroke={1.8} aria-hidden="true" />
            </button>
            {accountMenuOpen && (
              <div
                className="account-menu-panel"
                id="account-actions"
                role="group"
                aria-label={t("Account actions")}
              >
                <div className="account-menu-heading">
                  <strong>{t("Web access")}</strong>
                  <small>{t("Credentials are stored for this tab.")}</small>
                </div>
                <button
                  className="account-menu-item"
                  onClick={() => {
                    setTab("settings");
                    setAccountMenuOpen(false);
                  }}
                >
                  {t("Authentication settings")}
                </button>
                {hasSavedCredential && (
                  <button
                    className="account-menu-item"
                    onClick={() => {
                      forgetCredential(sessionStorage);
                      setHasSavedCredential(false);
                      setAccountMenuOpen(false);
                      window.location.reload();
                    }}
                  >
                    {t("Forget saved credential")}
                  </button>
                )}
              </div>
            )}
          </div>
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
              {t("Overview")}
            </button>
            <button
              className={`nav-item ${tab === "rules" ? "active" : ""}`}
              onClick={() => setTab("rules")}
            >
              <IconArrowsExchange size={18} stroke={1.8} />
              {t("Forwarding rules")}
            </button>
            <button
              className={`nav-item ${tab === "backups" ? "active" : ""}`}
              onClick={() => setTab("backups")}
            >
              <IconCloudUpload size={18} stroke={1.8} />
              {t("Backups")}
            </button>
            <button
              className={`nav-item ${tab === "settings" ? "active" : ""}`}
              onClick={() => setTab("settings")}
            >
              <IconSettings size={18} stroke={1.8} />
              {t("Settings")}
            </button>
            <button
              className={`nav-item ${tab === "about" ? "active" : ""}`}
              onClick={() => setTab("about")}
            >
              <IconInfoCircle size={18} stroke={1.8} />
              {t("About")}
            </button>
          </nav>
        </aside>
        <main>
          <div className="page-head">
            <div>
              <div className="eyebrow">
                {tab === "overview"
                  ? t("LIVE OVERVIEW")
                  : tab === "rules"
                    ? t("NETWORK / FORWARDING")
                    : tab === "backups"
                      ? t("SYSTEM / BACKUPS")
                      : tab === "settings"
                        ? t("SYSTEM / SETTINGS")
                        : t("SYSTEM / ABOUT")}
              </div>
              <h1>
                {tab === "overview"
                  ? t("Traffic, at a glance.")
                  : tab === "rules"
                    ? t("Forwarding rules")
                    : tab === "backups"
                      ? t("Safe restore points")
                      : tab === "settings"
                        ? t("Gateway settings")
                        : t("About Portalis")}
              </h1>
            </div>
            {tab === "rules" && (
              <button className="primary" onClick={addRule}>
                <IconPlus size={17} stroke={2} />
                {t("New rule")}
              </button>
            )}
            {tab === "about" && (
              <button
                className="secondary"
                onClick={() => void loadAbout()}
                disabled={aboutLoading}
              >
                <IconRefresh size={16} stroke={1.8} />
                {t("Refresh information")}
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
          {tab === "about" && (
            <AboutPage info={aboutInfo} loading={aboutLoading} t={t} />
          )}
        </main>
      </div>
    </div>
  );
}

function AboutPage({
  info,
  loading,
  t,
}: {
  info: AboutInfo | null;
  loading: boolean;
  t: Translator;
}) {
  const placeholder = loading ? t("Loading…") : "—";
  const fields = [
    { label: t("Hostname"), value: info?.hostname },
    { label: t("Operating system"), value: info?.operating_system },
    { label: t("Kernel version"), value: info?.kernel_release },
    { label: t("Architecture"), value: info?.architecture },
  ];

  return (
    <div className="about-page">
      <section className="card about-summary">
        <div className="about-summary-main">
          <img className="about-mark" src="/portalis-icon.svg" alt="" />
          <div>
            <div className="eyebrow">{t("PORTALIS SERVICE")}</div>
            <h2>{info?.name ?? "Portalis"}</h2>
            <p>{t("Network forwarding managed with nftables.")}</p>
          </div>
        </div>
        <div className="about-meta">
          <span>
            <small>{t("Version")}</small>
            {info ? `v${info.version}` : placeholder}
          </span>
          <span>
            <small>{t("API")}</small>
            {info?.api_version ?? placeholder}
          </span>
        </div>
      </section>
      <section className="card about-system">
        <div className="about-system-head">
          <IconServer size={19} stroke={1.8} aria-hidden="true" />
          <div>
            <div className="eyebrow">{t("HOST")}</div>
            <h2>{t("System information")}</h2>
          </div>
        </div>
        <dl className="about-fields">
          {fields.map(({ label, value }) => (
            <div className="about-field" key={label}>
              <dt>{label}</dt>
              <dd>{value || placeholder}</dd>
            </div>
          ))}
        </dl>
      </section>
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
  t: Translator;
  onRules: () => void;
}) {
  const packets = [...counterMap.values()].reduce(
    (sum, value) => sum + value.packets,
    0,
  );
  const bytesByProtocol = (protocol: Protocol) =>
    (status?.kernel.counters || []).reduce(
      (sum, counter) =>
        counter.protocol === protocol ? sum + counter.bytes : sum,
      0,
    );
  return (
    <>
      <div className="metric-grid">
        <Metric
          label={t("ACTIVE RULES")}
          value={String(config.rules.filter((rule) => rule.enabled).length)}
          note={
            status?.active_revision
              ? `${status.active_revision.slice(0, 8)}…`
              : t("Not applied")
          }
        />
        <Metric
          label={t("PACKETS")}
          value={fmtPackets(packets)}
          unit={t("packets")}
          note={t("live kernel counter")}
        />
        <div className="metric metric-bytes card">
          <div className="eyebrow">{t("BYTES")}</div>
          <div className="metric-protocol-values">
            <div>
              <span>TCP</span>
              <strong>{fmtBytes(bytesByProtocol("tcp"))}</strong>
            </div>
            <div>
              <span>UDP</span>
              <strong>{fmtBytes(bytesByProtocol("udp"))}</strong>
            </div>
          </div>
          <span>{t("since last apply")}</span>
        </div>
        <Metric
          label={t("FORWARDING")}
          value={
            status?.ipv4_forwarding && status?.ipv6_forwarding
              ? "4 + 6"
              : status?.ipv4_forwarding
                ? "IPv4"
                : status?.ipv6_forwarding
                  ? "IPv6"
                  : "off"
          }
          note={t("kernel sysctl")}
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
            <div className="eyebrow">{t("MANAGED TABLE")}</div>
            <h2>inet portalis</h2>
          </div>
          <button className="quiet" onClick={onRules}>
            {t("Manage rules →")}
          </button>
        </div>
        <div className="table-state">
          <span
            className={`state-pill ${status?.kernel.table_present ? "online" : "offline"}`}
          >
            {status?.kernel.table_present
              ? t("ONLINE")
              : t("NOT APPLIED")}
          </span>
          <span>
            {status?.kernel.drifted
              ? t("Kernel drift detected")
              : t("Matches active revision")}
          </span>
          <span className="muted">
            {t("Observed")} {status?.kernel.observed_at || "—"}
          </span>
        </div>
      </section>
      <section className="card">
        <div className="card-head">
          <div>
            <div className="eyebrow">
              {t("RECENT RULE ACTIVITY")}
            </div>
            <h2>{t("Live counters")}</h2>
          </div>
          <span className="muted">
            {t(
              "TCP and UDP are separate kernel rules")}
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
              const packetUnit = t("packets");
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
function Empty({ t }: { t: Translator }) {
  return (
    <div className="empty">
      {t(
        "No rules yet. Add a forwarding rule to get started.")}
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
  t: Translator;
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
            <h2>{t("Rule inventory")}</h2>
            <p>
              {t(
                "Manage the forwarding rules owned by this host.")}
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
              placeholder={t("Search rules")}
            />
          </label>
          <div className="table-filters">
            <SelectControl
              ariaLabel={t("Filter by address family")}
              value={family}
              onValueChange={(value) => setFamily(value as Family | "all")}
              options={[
                { value: "all", label: t("All families") },
                { value: "auto", label: "Auto" },
                { value: "ipv4", label: "IPv4" },
                { value: "ipv6", label: "IPv6" },
              ]}
            />
            <SelectControl
              ariaLabel={t("Filter by status")}
              value={state}
              onValueChange={(value) =>
                setState(value as "all" | "enabled" | "disabled")
              }
              options={[
                { value: "all", label: t("All states") },
                { value: "enabled", label: t("Enabled") },
                { value: "disabled", label: t("Disabled") },
              ]}
            />
          </div>
        </div>
        {config.rules.length === 0 ? (
          <Empty t={t} />
        ) : visibleRules.length === 0 ? (
          <div className="empty">
            {t("No rules match this filter.")}
          </div>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>{t("State")}</th>
                  <th>{t("Listen port")}</th>
                  <th>{t("Protocol")}</th>
                  <th>{t("Family")}</th>
                  <th>{t("Target IP")}</th>
                  <th>{t("Target port")}</th>
                  <th>{t("Interface")}</th>
                  <th>{t("Comment")}</th>
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
                            ? t("Enabled")
                            : t("Disabled")}
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
                          {fmtPackets(counter.packets)} {t("packets")}
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
      {current && (
        <RuleEditor
          rule={current}
          updateRule={updateRule}
          setConfig={setConfig}
          t={t}
        />
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
                ? t("Unsaved draft changes.")
                : t("Draft is saved.")}
            </strong>
            <span>
              {t(
                "Save stores your edits. Apply changes updates nftables.")}
            </span>
          </div>
        </div>
        <div className="action-meta">
          {config.rules.length} {t("rules")}
        </div>
        <div className="action-buttons">
          <button className="secondary" disabled={busy} onClick={onSave}>
            {t("Save draft")}
          </button>
          <button className="primary" disabled={busy} onClick={onApply}>
            {busy ? t("Working…") : t("Apply changes")}
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
  t: Translator;
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
          <h2>{t("Draft rules")}</h2>
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
                  {fmtPackets(counter.packets)} {t("packets")}
                </em>
              </button>
            );
          })
        )}
      </section>
      {current && (
        <RuleEditor
          rule={current}
          updateRule={updateRule}
          setConfig={setConfig}
          t={t}
        />
      )}
      <div className="action-bar">
        <span className="muted">
          {t(
            "Save is draft-only. Apply changes the kernel atomically.")}
        </span>
        <div>
          <button className="secondary" disabled={busy} onClick={onSave}>
            {t("Save draft")}
          </button>
          <button className="primary" disabled={busy} onClick={onApply}>
            {busy ? t("Working…") : t("Apply changes")}
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
  t: Translator;
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
        t("Delete this draft rule?"),
        {
          title: t("Delete rule"),
          confirmLabel: t("Delete"),
          cancelLabel: t("Cancel"),
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
          <div className="eyebrow">{t("RULE CONFIGURATION")}</div>
          <h2>{rule.name}</h2>
        </div>
        <label className="switch">
          <input
            type="checkbox"
            checked={rule.enabled}
            onChange={(event) => patch({ enabled: event.target.checked })}
          />
          <span />
          {t("Enabled")}
        </label>
      </div>
      <div className="form-grid">
        <label className="wide">
          {t("Rule name")}
          <input
            value={rule.name}
            onChange={(event) => patch({ name: event.target.value })}
          />
        </label>
        <label>
          {t("Address family")}
          <SelectControl
            ariaLabel={t("Address family")}
            value={rule.family}
            onValueChange={(value) => patch({ family: value as Family })}
            options={[
              { value: "auto", label: t("Auto (from target IP)") },
              { value: "ipv4", label: "IPv4" },
              { value: "ipv6", label: "IPv6" },
            ]}
          />
        </label>
        <label>
          {t("Protocols")}
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
          {t("Listen port")}
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
          {t("Target port")}
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
          <small>{t("Ranges map one-to-one")}</small>
        </label>
        <label className="wide">
          {t("Target IP")}
          <input
            value={rule.target_ip}
            placeholder={rule.family === "ipv6" ? "2001:db8::10" : "192.0.2.10"}
            onChange={(event) => patch({ target_ip: event.target.value })}
          />
        </label>
        <label>
          {t("Listen address")}
          <SelectControl
            ariaLabel={t("Listen address")}
            value={rule.listen_address === "any" ? "any" : "address"}
            onValueChange={(value) =>
              patch({
                listen_address:
                  value === "any"
                    ? "any"
                    : { address: rule.family === "ipv6" ? "::" : "0.0.0.0" },
              })
            }
            options={[
              { value: "any", label: t("Any address") },
              { value: "address", label: t("Specific IP") },
            ]}
          />
        </label>
        {rule.listen_address !== "any" && (
          <label>
            {t("Listen IP")}
            <input
              value={rule.listen_address.address}
              onChange={(event) =>
                patch({ listen_address: { address: event.target.value } })
              }
            />
          </label>
        )}
        <label>
          {t("SNAT mode")}
          <SelectControl
            ariaLabel={t("SNAT mode")}
            value={rule.snat.mode}
            onValueChange={(value) =>
              patch({
                snat:
                  value === "fixed"
                    ? { mode: "fixed", address: rule.target_ip }
                    : { mode: value as "none" | "masquerade" },
              })
            }
            options={[
              { value: "masquerade", label: t("Masquerade (recommended)") },
              { value: "none", label: t("None") },
              { value: "fixed", label: t("Fixed source IP") },
            ]}
          />
        </label>
        {rule.snat.mode === "fixed" && (
          <label>
            {t("SNAT source IP")}
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
            "Source CIDRs (optional, one per line)")}
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
            placeholder={t("Leave empty for all sources")}
          />
        </label>
        <label className="wide">
          {t("Comment")}
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
            "Advanced: allow overlapping detected SSH port")}
        </label>
      </div>
      <button className="danger-link" onClick={() => void remove()}>
        {t("Delete this draft rule")}
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
  t: Translator;
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
      setMessage({ good: t("S3 settings saved.") });
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
        good: t("Active revision backed up."),
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
          "Import this backup as a draft? It will not apply until you confirm."),
        {
          title: t("Import backup"),
          confirmLabel: t("Import"),
          cancelLabel: t("Cancel"),
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
        good: t("Backup imported as a draft."),
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
              {t("S3-COMPATIBLE STORAGE")}
            </div>
            <h2>{t("Remote backups")}</h2>
          </div>
          <button className="primary" disabled={busy} onClick={backup}>
            {t("Backup active now")}
          </button>
        </div>
        <p className="muted">
          {t(
            "AWS S3, MinIO, Cloudflare R2 and custom endpoints are supported. Scheduled backups run daily at 03:00 and retain the latest 10 revisions.")}
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
                  {t("Import draft")}
                </button>
              </div>
            ))
          )}
        </div>
      </section>
      <section className="card">
        <div className="eyebrow">{t("STORAGE CONNECTION")}</div>
        <h2>{t("Configure S3")}</h2>
        <form className="storage-form" onSubmit={save}>
          <div className="form-grid">
            <label>
              {t("Provider")}
              <SelectControl
                ariaLabel={t("Provider")}
                value={profile.provider}
                onValueChange={(value) =>
                  setProfile({ ...profile, provider: value })
                }
                options={[
                  { value: "aws", label: "AWS S3" },
                  { value: "minio", label: "MinIO" },
                  { value: "r2", label: "Cloudflare R2" },
                  { value: "custom", label: "Custom" },
                ]}
              />
            </label>
            <label>
              {t("Region")}
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
                  ? t("Optional for AWS default endpoint")
                  : t("Required for this provider")}
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
            <label className="wide checkline">
              <input
                type="checkbox"
                checked={profile.path_style}
                onChange={(event) =>
                  setProfile({ ...profile, path_style: event.target.checked })
                }
              />
              {t("Use path-style addressing")}
            </label>
          </div>
          <div className="form-actions">
            <button className="secondary" disabled={busy}>
              {t("Save storage settings")}
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
  t: Translator;
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
        good: t("Password enabled for web access."),
      });
    } catch (error) {
      setMessage({ bad: String(error) });
    }
  };
  return (
    <section className="card narrow">
      <div className="eyebrow">{t("ACCESS CONTROL")}</div>
      <h2>{t("Web authentication")}</h2>
      <p className="muted">
        {t(
          "Portalis permits passwordless access only when no Web password is configured and both the TCP peer and HTTP Host are loopback. Configure a strong password before exposing the web listener or using a reverse proxy. Cross-origin writes are rejected.")}
      </p>
      <form onSubmit={save}>
        <label>
          {t("New password (12+ characters)")}
          <input
            type="password"
            minLength={12}
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </label>
        <button className="primary" type="submit">
          {t("Set password")}
        </button>
      </form>
      <div className="info-block">
        <strong>{t("SSH protection")}</strong>
        <span>
          {t(
            "TCP/UDP forwarding rules that overlap detected SSH ports are rejected by default. Portalis never changes SSH or global firewall policies.")}
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
