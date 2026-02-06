import React, { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { HashRouter, Link, Navigate, Route, Routes, useLocation, useNavigate, useParams } from "react-router-dom";
import { Marked, marked } from "marked";
import DOMPurify from "dompurify";
import { APP_INFO } from "./config";
import { apiFetch, clearToken, setToken } from "./auth";
import { IANA_TIMEZONES } from "./timezones";

const LICENSE_URL = `${APP_INFO.repoUrl}/blob/master/LICENSE`;
const THEME_KEY = "form_app_theme";
let appDefaultTimezone = "Asia/Ho_Chi_Minh";
const getAppDefaultTimezone = () => appDefaultTimezone;
const setAppDefaultTimezone = (tz: string) => {
  appDefaultTimezone = tz;
};
const getUserTimeZone = () =>
  Intl.DateTimeFormat().resolvedOptions().timeZone || getAppDefaultTimezone();
const TIMEZONE_OPTIONS = [
  "Asia/Ho_Chi_Minh",
  "Asia/Bangkok",
  "UTC",
  "Asia/Singapore",
  "Asia/Shanghai",
  "Asia/Tokyo",
  "Asia/Seoul",
  "Europe/London",
  "Europe/Berlin",
  "America/New_York",
  "America/Los_Angeles",
  "Australia/Sydney"
];
const ALL_TIMEZONES = Array.from(new Set([...IANA_TIMEZONES, ...TIMEZONE_OPTIONS]));

function escapeHtml(input: string) {
  return input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const RICH_ALLOWED_TAGS = [
  "a",
  "b",
  "blockquote",
  "br",
  "code",
  "del",
  "div",
  "em",
  "h1",
  "h2",
  "h3",
  "h4",
  "h5",
  "h6",
  "hr",
  "i",
  "img",
  "input",
  "li",
  "ol",
  "p",
  "pre",
  "span",
  "strong",
  "sub",
  "sup",
  "table",
  "tbody",
  "td",
  "th",
  "thead",
  "tr",
  "u",
  "ul"
];
const RICH_ALLOWED_ATTR = [
  "href",
  "title",
  "target",
  "rel",
  "class",
  "id",
  "aria-label",
  "aria-hidden",
  "src",
  "alt",
  "width",
  "height",
  "type",
  "checked",
  "disabled",
  "colspan",
  "rowspan",
  "align"
];
const RICH_FORBID_TAGS = ["style", "script", "iframe", "object", "embed", "svg", "math"];
const RICH_URI_ALLOWLIST = /^(?:(?:https?|mailto):|\/|#)/i;
let markedConfigured = false;
let markedHtmlConfigured = false;
const markedHtmlInstance = new Marked();

function ensureMarkedConfigured() {
  if (markedConfigured) return;
  marked.setOptions({ gfm: true, breaks: true });
  marked.use({
    renderer: {
      html: () => ""
    }
  });
  markedConfigured = true;
}

function ensureMarkedHtmlConfigured() {
  if (markedHtmlConfigured) return;
  markedHtmlInstance.setOptions({ gfm: true, breaks: true });
  markedHtmlConfigured = true;
}

function sanitizeRichHtml(input: string) {
  return DOMPurify.sanitize(input, {
    ALLOWED_TAGS: RICH_ALLOWED_TAGS,
    ALLOWED_ATTR: RICH_ALLOWED_ATTR,
    FORBID_TAGS: RICH_FORBID_TAGS,
    ALLOW_DATA_ATTR: false,
    ALLOWED_URI_REGEXP: RICH_URI_ALLOWLIST
  });
}

function renderRichTextHtml(
  text: string,
  markdownEnabled: boolean,
  inline: boolean,
  allowHtml = false
) {
  if (!text) return "";
  if (!markdownEnabled) {
    if (allowHtml) {
      const withBreaks = text.replace(/\n/g, "<br />");
      return sanitizeRichHtml(withBreaks);
    }
    const escaped = escapeHtml(text);
    return inline ? escaped.replace(/\n/g, "<br />") : escaped.replace(/\n/g, "<br />");
  }
  if (allowHtml) {
    ensureMarkedHtmlConfigured();
    const html = inline ? markedHtmlInstance.parseInline(text) : markedHtmlInstance.parse(text);
    return sanitizeRichHtml(String(html));
  }
  ensureMarkedConfigured();
  const html = inline ? marked.parseInline(text) : marked.parse(text);
  return sanitizeRichHtml(String(html));
}

type SubmissionExportFormat = "markdown" | "txt" | "csv";
type FieldMetaMap = Record<string, { label: string; type: string; rules?: Record<string, unknown> }>;

function buildFieldMetaFromSchema(fields: any[]) {
  const meta: FieldMetaMap = {};
  const order: string[] = [];
  fields.forEach((field) => {
    if (!field?.id) return;
    const id = String(field.id);
    order.push(id);
    meta[id] = {
      label: field.label || id,
      type: field.type || "text",
      rules: field.rules && typeof field.rules === "object" ? field.rules : undefined
    };
  });
  return { meta, order };
}

function formatFilenameTimestamp(date: Date) {
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}-${pad(
    date.getHours()
  )}${pad(date.getMinutes())}${pad(date.getSeconds())}`;
}

function csvEscapeValue(value: string) {
  if (value.includes('"') || value.includes("\n") || value.includes("\r") || value.includes(",")) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

function escapeMarkdownCell(value: string) {
  return value.replace(/\|/g, "\\|").replace(/\r?\n/g, "<br>");
}

function normalizeExportValue(value: unknown) {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value);
  } catch (error) {
    return String(value);
  }
}

function downloadTextFile(filename: string, content: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  link.click();
  URL.revokeObjectURL(link.href);
}

function useMathJax(enabled: boolean) {
  useEffect(() => {
    if (!enabled) return;
    if ((window as any).MathJax) return;
    const script = document.createElement("script");
    script.src = "https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-mml-chtml.js";
    script.async = true;
    document.head.appendChild(script);
  }, [enabled]);
}

function RichText({
  text,
  markdownEnabled,
  mathjaxEnabled,
  className,
  allowHtml = false,
  inline = false
}: {
  text?: string | null;
  markdownEnabled: boolean;
  mathjaxEnabled: boolean;
  className?: string;
  allowHtml?: boolean;
  inline?: boolean;
}) {
  const ref = useRef<HTMLDivElement | HTMLSpanElement | null>(null);
  const html = useMemo(
    () => renderRichTextHtml(text ? String(text) : "", markdownEnabled, inline, allowHtml),
    [text, markdownEnabled, inline, allowHtml]
  );

  useEffect(() => {
    if (!mathjaxEnabled || !ref.current) return;
    const mathjax = (window as any).MathJax;
    if (mathjax?.typesetPromise) {
      mathjax.typesetPromise([ref.current]).catch(() => null);
    }
  }, [html, mathjaxEnabled]);

  if (inline) {
    return (
      <span
        ref={ref as React.RefObject<HTMLSpanElement>}
        className={className}
        dangerouslySetInnerHTML={{ __html: html }}
      />
    );
  }
  return (
    <div
      ref={ref as React.RefObject<HTMLDivElement>}
      className={className}
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}

function TimezoneSelect({
  value,
  onChange,
  disabled,
  idPrefix
}: {
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
  idPrefix: string;
}) {
  const defaultTz = getAppDefaultTimezone();
  const safeValue = value || defaultTz;
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [query, setQuery] = useState(safeValue);
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const [dropUp, setDropUp] = useState(false);
  const options = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    const queryWithSpaces = normalized.replace(/_/g, " ");
    const queryWithUnderscores = normalized.replace(/\s+/g, "_");
    const filtered = normalized
      ? ALL_TIMEZONES.filter((tz) => {
        const tzLower = tz.toLowerCase();
        const tzSpaces = tzLower.replace(/_/g, " ");
        return (
          tzLower.includes(normalized) ||
          tzLower.includes(queryWithUnderscores) ||
          tzSpaces.includes(normalized) ||
          tzSpaces.includes(queryWithSpaces)
        );
      })
      : ALL_TIMEZONES.slice();
    return filtered;
  }, [query]);

  useEffect(() => {
    if (!open) {
      setQuery(safeValue);
    }
  }, [safeValue, open]);

  useEffect(() => {
    function handleOutside(event: MouseEvent) {
      if (!containerRef.current) return;
      if (!containerRef.current.contains(event.target as Node)) {
        setOpen(false);
        setQuery(safeValue);
      }
    }
    if (open) {
      document.addEventListener("mousedown", handleOutside);
    }
    return () => document.removeEventListener("mousedown", handleOutside);
  }, [open, safeValue]);

  function resolveTimezone(inputValue: string) {
    const trimmed = inputValue.trim();
    if (!trimmed) return defaultTz;
    if (ALL_TIMEZONES.includes(trimmed)) return trimmed;
    const lower = trimmed.toLowerCase();
    const exact = ALL_TIMEZONES.find((tz) => tz.toLowerCase() === lower);
    if (exact) return exact;
    const normalized = trimmed.replace(/\s+/g, "_");
    if (ALL_TIMEZONES.includes(normalized)) return normalized;
    const normalizedLower = normalized.toLowerCase();
    const match = ALL_TIMEZONES.find((tz) => tz.toLowerCase() === normalizedLower);
    return match || defaultTz;
  }

  function commitSelection(next: string) {
    const resolved = resolveTimezone(next);
    onChange(resolved);
    setQuery(resolved);
    setOpen(false);
  }

  function handleKeyDown(event: React.KeyboardEvent<HTMLInputElement>) {
    if (!open && (event.key === "ArrowDown" || event.key === "ArrowUp")) {
      setOpen(true);
      return;
    }
    if (!open) return;
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActiveIndex((prev) => Math.min(prev + 1, options.length - 1));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActiveIndex((prev) => Math.max(prev - 1, 0));
    } else if (event.key === "Enter") {
      event.preventDefault();
      const selected = options[activeIndex];
      if (selected) {
        commitSelection(selected);
      } else {
        commitSelection(query);
      }
    } else if (event.key === "Escape") {
      event.preventDefault();
      setOpen(false);
      setQuery(safeValue);
    }
  }

  return (
    <div className="timezone-select" ref={containerRef}>
      <input
        id={`${idPrefix}-tz-input`}
        type="text"
        className="form-control"
        value={query}
        placeholder="Search timezones"
        onChange={(event) => {
          setQuery(event.target.value);
          setOpen(true);
          setActiveIndex(0);
        }}
        onFocus={() => {
          setOpen(true);
          setActiveIndex(0);
          const rect = containerRef.current?.getBoundingClientRect();
          if (rect) {
            const menuHeight = 260;
            const shouldDropUp = rect.bottom + menuHeight > window.innerHeight;
            setDropUp(shouldDropUp);
          }
        }}
        onBlur={() => {
          commitSelection(query);
        }}
        onKeyDown={handleKeyDown}
        disabled={disabled}
        autoComplete="off"
        spellCheck={false}
        aria-expanded={open}
        aria-controls={`${idPrefix}-tz-menu`}
      />
      {open ? (
        <div
          className={`timezone-menu${dropUp ? " timezone-menu--up" : ""}`}
          id={`${idPrefix}-tz-menu`}
          role="listbox"
        >
          {options.length === 0 ? (
            <div className="timezone-option timezone-option--empty">No matches</div>
          ) : (
            options.map((tz, index) => (
              <div
                key={tz}
                role="option"
                aria-selected={index === activeIndex}
                className={`timezone-option${index === activeIndex ? " timezone-option--active" : ""}`}
                onMouseDown={(event) => {
                  event.preventDefault();
                  commitSelection(tz);
                }}
                onMouseEnter={() => setActiveIndex(index)}
              >
                {tz}
              </div>
            ))
          )}
        </div>
      ) : null}
    </div>
  );
}

function VersionSelector({
  submissionId,
  saveAllVersions,
  onVersionChange,
}: {
  submissionId: string | null;
  saveAllVersions: boolean;
  onVersionChange: (version: string) => void;
}) {
  const [versions, setVersions] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedVersion, setSelectedVersion] = useState<string>("none");

  useEffect(() => {
    if (!saveAllVersions || !submissionId) {
      setVersions([]);
      return;
    }

    let active = true;
    async function loadVersions() {
      setLoading(true);
      try {
        const response = await apiFetch(
          `${API_BASE}/api/me/submissions/${encodeURIComponent(submissionId!)}/versions`
        );
        const payload = await response.json().catch(() => null);
        if (!active) return;

        if (response.ok && Array.isArray(payload?.versions)) {
          setVersions(payload.versions);
        }
      } catch (error) {
        console.error("Failed to load versions:", error);
      } finally {
        if (active) setLoading(false);
      }
    }

    loadVersions();
    return () => {
      active = false;
    };
  }, [submissionId, saveAllVersions]);

  if (!saveAllVersions || versions.length === 0) {
    return null;
  }

  function handleChange(value: string) {
    setSelectedVersion(value);
    onVersionChange(value);
  }

  return (
    <div className="form-group">
      <label htmlFor="version-selector">
        Load previous version (or start with blank form):
      </label>
      <select
        id="version-selector"
        className="form-control"
        value={selectedVersion}
        onChange={(e) => handleChange(e.target.value)}
        disabled={loading}
      >
        <option value="none">Start with blank form</option>
        <option value="latest">Use latest submission</option>
        {versions.map((v) => (
            <option key={v.version_number} value={String(v.version_number)}>
              Version {v.version_number} (submitted {v.created_at ? formatTimeICT(v.created_at) : "n/a"})
            </option>
        ))}
      </select>
      {loading && <small className="text-muted">Loading versions...</small>}
    </div>
  );
}

function VersionHistorySection({ submissionId }: { submissionId: string }) {
  const [versions, setVersions] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    async function loadVersions() {
      setLoading(true);
      try {
        const response = await apiFetch(
          `${API_BASE}/api/me/submissions/${encodeURIComponent(submissionId)}/versions`
        );
        const payload = await response.json().catch(() => null);
        if (!active) return;

        if (response.ok && Array.isArray(payload?.versions)) {
          setVersions(payload.versions);
        }
      } catch (error) {
        console.error("Failed to load versions:", error);
      } finally {
        if (active) setLoading(false);
      }
    }

    loadVersions();
    return () => {
      active = false;
    };
  }, [submissionId]);

  return (
    <div className="panel panel--compact mt-3">
      <div className="panel-header">
        <h3 className="mb-0">
          <i className="bi bi-clock-history" aria-hidden="true" /> Version History
        </h3>
      </div>
      {loading ? (
        <p className="muted">Loading version history...</p>
      ) : versions.length === 0 ? (
        <p className="muted">No version history available.</p>
      ) : (
        <div className="table-responsive">
          <table className="table table-sm">
            <thead>
              <tr>
                <th>Version</th>
                <th>Created</th>
                <th>Created By</th>
              </tr>
            </thead>
            <tbody>
              {versions.map((v) => (
                <tr key={v.version_number}>
                  <td>
                    <span className="badge text-bg-secondary">
                      Version {v.version_number}
                    </span>
                  </td>
                  <td>{new Date(v.created_at).toLocaleString()}</td>
                  <td className="text-muted">{v.created_by || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

type FormSummary = {
  slug: string;
  title: string;
  description?: string | null;
  is_public: boolean;
  is_locked: boolean;
  auth_policy?: string;
  available_from?: string | null;
  available_until?: string | null;
  password_required?: boolean;
  password_require_access?: boolean;
  password_require_submit?: boolean;
  is_open?: boolean;
  discussion_enabled?: boolean;
  discussion_markdown_enabled?: boolean;
  discussion_html_enabled?: boolean;
  discussion_mathjax_enabled?: boolean;
  comment_notify_enabled?: boolean;
};

type VisibilityMatchMode = "any" | "all";

type VisibilityCondition = {
  dependsOn: string;
  values: string[];
  mode?: VisibilityMatchMode;
};

type FieldVisibilityRule = {
  dependsOn?: string;
  values?: string[];
  mode?: VisibilityMatchMode;
  conditions?: VisibilityCondition[];
};

type FormField = {
  id: string;
  label: string;
  type: string;
  required: boolean;
  placeholder?: string;
  description?: string;
  options?: string[];
  multiple?: boolean;
  rules?: Record<string, unknown>;
  visibility?: FieldVisibilityRule;
};

type FormDetail = {
  slug: string;
  title: string;
  description?: string | null;
  is_locked: boolean;
  is_public: boolean;
  auth_policy: string;
  template_schema_json?: string | null;
  file_rules_json?: string | null;
  fields: FormField[];
  available_from?: string | null;
  available_until?: string | null;
  password_required?: boolean;
  password_require_access?: boolean;
  password_require_submit?: boolean;
  reminder_enabled?: boolean;
  reminder_frequency?: string | null;
  is_open?: boolean;
  discussion_enabled?: boolean;
  discussion_markdown_enabled?: boolean;
  discussion_html_enabled?: boolean;
  discussion_mathjax_enabled?: boolean;
  comment_notify_enabled?: boolean;
  canvas_enabled?: boolean;
  canvas_course_id?: string | null;
  canvas_course_name?: string | null;
  canvas_allowed_sections?: Array<{ id: string; name: string }>;
  canvas_fields_position?: string | null;
  file_rules?: {
    enabled: boolean;
    maxFiles: number;
    maxSizeBytes: number;
    maxFileSizeBytes?: number;
    allowedExtensions: string[];
    required: boolean;
  };
};

type UserInfo = {
  userId: string;
  provider: string;
  email?: string | null;
  username?: string | null;
  isAdmin: boolean;
};

type ApiError = {
  status: number;
  requestId?: string;
  message?: string;
  detail?: unknown;
};

type FieldErrors = Record<string, string>;

type FileStatus = "pending" | "uploading" | "uploaded" | "error";
type FileMeta = { status: FileStatus; progress: number };
type UploadedFile = {
  fieldKey: string;
  name: string;
  size: number;
  contentType?: string;
  r2Key: string;
  sha256: string;
};

type SubmissionComment = {
  id: string;
  submission_id: string;
  author_user_id: string;
  author_role: string;
  author_email?: string | null;
  author_login?: string | null;
  body: string;
  created_at: string;
  updated_at: string;
  deleted_at: string | null;
  deleted_by: string | null;
  deleted_reason: string | null;
  parent_comment_id?: string | null;
  quote_comment_id?: string | null;
  replies?: SubmissionComment[];
  can_edit?: boolean;
  can_delete?: boolean;
  can_restore?: boolean;
  can_purge?: boolean;
};

type FieldRule = {
  extensions: string[];
  maxBytes: number;
  maxFiles: number;
};

type FieldRuleset = {
  fields: Record<string, FieldRule>;
  defaultRule: FieldRule;
};

type FileItem = {
  id: string;
  field_id: string;
  original_name: string;
  size_bytes: number;
  vt_status?: string | null;
  vt_verdict?: string | null;
  finalized_at?: string | null;
  final_drive_file_id?: string | null;
};

type NoticeType = "success" | "info" | "warning" | "error";
type ToastNotice = {
  id: string;
  message: string;
  type: NoticeType;
};

const DEFAULT_LOCAL_API = "http://127.0.0.1:8787";
const DEFAULT_PROD_API = "https://form-app-api.hoanganhduc.workers.dev";
const API_BASE =
  import.meta.env.VITE_API_BASE ||
  (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1"
    ? DEFAULT_LOCAL_API
    : DEFAULT_PROD_API);
const PUBLIC_BASE = import.meta.env.VITE_WEB_BASE || "/forms/";
const RETURN_TO_KEY = "form_app_return_to";

function formatSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function toTitleCase(value: string) {
  const lowerWords = new Set([
    "van",
    "der",
    "den",
    "de",
    "da",
    "dos",
    "das",
    "di",
    "du",
    "la",
    "le",
    "von",
    "bin",
    "binti",
    "ibn",
    "al",
    "el"
  ]);
  return value
    .toLowerCase()
    .split(/\s+/)
    .filter((part) => part.length > 0)
    .map((part, index) => {
      const pieces = part.split("-").map((segment) => {
        if (!segment) return segment;
        if (index > 0 && lowerWords.has(segment)) return segment;
        return segment.charAt(0).toUpperCase() + segment.slice(1);
      });
      return pieces.join("-");
    })
    .join(" ");
}

function isValidDateString(value: string) {
  if (value.includes("T")) {
    const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(value);
    if (!match) return false;
    const year = Number(match[1]);
    const month = Number(match[2]);
    const day = Number(match[3]);
    const hour = Number(match[4]);
    const minute = Number(match[5]);
    if (!year || month < 1 || month > 12 || day < 1 || day > 31) return false;
    if (hour < 0 || hour > 23 || minute < 0 || minute > 59) return false;
    const date = new Date(Date.UTC(year, month - 1, day, hour, minute));
    return (
      date.getUTCFullYear() === year &&
      date.getUTCMonth() === month - 1 &&
      date.getUTCDate() === day &&
      date.getUTCHours() === hour &&
      date.getUTCMinutes() === minute
    );
  }
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (!year || month < 1 || month > 12 || day < 1 || day > 31) return false;
  const date = new Date(Date.UTC(year, month - 1, day));
  return (
    date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day
  );
}

function isValidTimeString(value: string) {
  return /^([01]\d|2[0-3]):([0-5]\d)$/.test(value);
}

function formatReminderFrequency(value: string | null | undefined) {
  if (!value) return "";
  const normalized = value.trim().toLowerCase();
  if (!normalized) return "";
  if (normalized === "daily") return "every day";
  if (normalized === "weekly") return "every week";
  if (normalized === "monthly") return "every month";
  const match = /^(\d+):(days|weeks|months)$/.exec(normalized);
  if (!match) return "";
  const count = Number(match[1]);
  if (!Number.isFinite(count) || count <= 0) return "";
  const unit = match[2];
  const label = count === 1 ? unit.replace(/s$/, "") : unit;
  return `every ${count} ${label}`;
}

function parseSelectionValues(field: FormField, rawValue: string) {
  const trimmed = rawValue.trim();
  if (!trimmed) return [];
  if (field.type === "checkbox" && field.multiple) {
    return trimmed
      .split(",")
      .map((item) => item.trim())
      .filter((item) => item.length > 0);
  }
  return [trimmed];
}

function buildVisibilityMap(fields: FormField[], values: Record<string, string>) {
  const fieldById = new Map(fields.map((field) => [field.id, field]));
  const memo = new Map<string, boolean>();
  const compute = (field: FormField, stack: Set<string>): boolean => {
    if (memo.has(field.id)) {
      return memo.get(field.id)!;
    }
    if (stack.has(field.id)) {
      memo.set(field.id, true);
      return true;
    }
    const rule = field.visibility;
    const normalized = normalizeVisibilityRule(rule);
    if (!normalized) {
      memo.set(field.id, true);
      return true;
    }
    const nextStack = new Set(stack);
    nextStack.add(field.id);
    const evaluateCondition = (condition: VisibilityCondition) => {
      const dependsOn = condition.dependsOn.trim();
      if (!dependsOn) return true;
      const controller = fieldById.get(dependsOn);
      if (!controller || !VISIBILITY_CONTROLLER_TYPES.has(controller.type)) {
        return true;
      }
      if (!compute(controller, nextStack)) {
        return false;
      }
      const selected = parseSelectionValues(controller, values[controller.id] || "");
      const ruleValues = Array.isArray(condition.values)
        ? condition.values.map((value) => String(value)).filter((value) => value.length > 0)
        : [];
      if (ruleValues.length === 0) return true;
      const mode = condition.mode === "all" ? "all" : "any";
      return mode === "all"
        ? ruleValues.every((value) => selected.includes(value))
        : ruleValues.some((value) => selected.includes(value));
    };
    const matches =
      normalized.operator === "any"
        ? normalized.conditions.some((condition) => evaluateCondition(condition))
        : normalized.conditions.every((condition) => evaluateCondition(condition));
    memo.set(field.id, matches);
    return matches;
  };
  const map: Record<string, boolean> = {};
  fields.forEach((field) => {
    map[field.id] = compute(field, new Set());
  });
  return map;
}

function zonedTimeToUtcIso(localValue: string, timeZone: string) {
  if (!localValue) return "";
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(localValue);
  if (!match) return "";
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const utcGuess = Date.UTC(year, month - 1, day, hour, minute);
  const dtf = new Intl.DateTimeFormat("en-US", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false
  });
  const parts = Object.fromEntries(dtf.formatToParts(new Date(utcGuess)).map((part) => [part.type, part.value]));
  const tzYear = Number(parts.year);
  const tzMonth = Number(parts.month);
  const tzDay = Number(parts.day);
  const tzHour = Number(parts.hour);
  const tzMinute = Number(parts.minute);
  const tzAsUtc = Date.UTC(tzYear, tzMonth - 1, tzDay, tzHour, tzMinute);
  const diff = tzAsUtc - utcGuess;
  const corrected = utcGuess - diff;
  return new Date(corrected).toISOString();
}

function dateOnlyToUtcIso(localDate: string, timeZone: string) {
  if (!localDate) return "";
  return zonedTimeToUtcIso(`${localDate}T00:00`, timeZone);
}

function timeOnlyToUtcIso(localTime: string, timeZone: string) {
  if (!localTime) return "";
  return zonedTimeToUtcIso(`1970-01-01T${localTime}`, timeZone);
}

function utcToLocalDateTime(isoValue: string, timeZone: string) {
  if (!isoValue) return "";
  const date = new Date(isoValue);
  if (Number.isNaN(date.getTime())) return "";
  if (!timeZone) return date.toISOString().slice(0, 16);
  const dtf = new Intl.DateTimeFormat("en-US", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false
  });
  const parts = Object.fromEntries(dtf.formatToParts(date).map((part) => [part.type, part.value]));
  if (!parts.year || !parts.month || !parts.day || !parts.hour || !parts.minute) return "";
  return `${parts.year}-${parts.month}-${parts.day}T${parts.hour}:${parts.minute}`;
}

function utcToLocalDateOnly(isoValue: string, timeZone: string) {
  if (!isoValue) return "";
  const date = new Date(isoValue);
  if (Number.isNaN(date.getTime())) return "";
  if (!timeZone) return date.toISOString().slice(0, 10);
  const dtf = new Intl.DateTimeFormat("en-US", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  });
  const parts = Object.fromEntries(dtf.formatToParts(date).map((part) => [part.type, part.value]));
  if (!parts.year || !parts.month || !parts.day) return "";
  return `${parts.year}-${parts.month}-${parts.day}`;
}

function utcToLocalTimeOnly(isoValue: string, timeZone: string) {
  if (!isoValue) return "";
  const date = new Date(isoValue);
  if (Number.isNaN(date.getTime())) return "";
  if (!timeZone) return date.toISOString().slice(11, 16);
  const dtf = new Intl.DateTimeFormat("en-US", {
    timeZone,
    hour: "2-digit",
    minute: "2-digit",
    hour12: false
  });
  const parts = Object.fromEntries(dtf.formatToParts(date).map((part) => [part.type, part.value]));
  if (!parts.hour || !parts.minute) return "";
  return `${parts.hour}:${parts.minute}`;
}

function normalizeNameValue(value: string) {
  return value.normalize("NFKC").trim().replace(/\s+/g, " ");
}

function pickNameFromData(data: Record<string, unknown> | null) {
  if (!data) return "";
  const preferredKeys = ["full_name", "fullName", "fullname", "full-name", "name"];
  for (const key of preferredKeys) {
    const value = data[key];
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }
  const nameKey = Object.keys(data).find((key) => key.toLowerCase().includes("name"));
  if (nameKey) {
    const value = data[nameKey];
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }
  return "";
}

function getAuthPolicyLabel(policy?: string) {
  const value = policy || "optional";
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function getUserDisplayName(user: UserInfo | null): string {
  if (!user) return "n/a";
  if (user.provider === "github" && user.username) return user.username;
  return user.email || user.userId;
}

function getAuthPolicyIcon(policy?: string) {
  switch (policy) {
    case "google":
      return "bi-google";
    case "github":
      return "bi-github";
    case "required":
      return "bi-shield-lock";
    case "either":
      return "bi-shield-check";
    case "optional":
    default:
      return "bi-shield";
  }
}

function getLockIcon(isLocked: boolean) {
  return isLocked ? "bi-lock-fill" : "bi-unlock";
}

function getVisibilityIcon(isPublic: boolean) {
  return isPublic ? "bi-globe2" : "bi-eye-slash";
}

function getUploadStatusIcon(status: string) {
  switch (status) {
    case "uploading":
      return "bi-cloud-arrow-up";
    case "uploaded":
      return "bi-check-circle";
    case "error":
      return "bi-exclamation-octagon";
    case "pending":
    default:
      return "bi-clock-history";
  }
}

function getVtStatusIcon(value: string) {
  switch (value) {
    case "clean":
      return "bi-shield-check";
    case "suspicious":
      return "bi-exclamation-triangle";
    case "malicious":
      return "bi-bug-fill";
    case "running":
    case "queued":
    case "pending":
    case "unknown":
      return "bi-hourglass-split";
    case "error":
    default:
      return "bi-exclamation-octagon";
  }
}

function getVtBadgeClass(value: string) {
  switch (value) {
    case "clean":
      return "text-bg-success";
    case "suspicious":
      return "text-bg-warning";
    case "malicious":
      return "text-bg-danger";
    case "running":
    case "queued":
    case "unknown":
    case "pending":
      return "text-bg-secondary";
    case "error":
    default:
      return "text-bg-danger";
  }
}

class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean; message: string; stack: string }
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false, message: "", stack: "" };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, message: error.message || "Unknown error", stack: error.stack || "" };
  }

  componentDidCatch() {
    // Errors are shown in UI; avoid noisy logs.
  }

  render() {
    if (!this.state.hasError) {
      return this.props.children;
    }
    return (
      <section className="panel panel--error">
        <h2>App error</h2>
        <p className="muted">{this.state.message}</p>
        {this.state.stack ? <pre className="mb-0">{this.state.stack}</pre> : null}
      </section>
    );
  }
}

function parseSchemaText(text: string) {
  if (!text.trim()) return { schema: { fields: [] as Array<Record<string, unknown>> }, fields: [] as Array<Record<string, unknown>> };
  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === "object") {
      const fields = Array.isArray((parsed as any).fields) ? (parsed as any).fields : [];
      return { schema: { ...(parsed as any), fields }, fields };
    }
  } catch (error) {
    return { schema: { fields: [] as Array<Record<string, unknown>> }, fields: [], error: "Schema JSON is invalid." };
  }
  return { schema: { fields: [] as Array<Record<string, unknown>> }, fields: [] as Array<Record<string, unknown>> };
}

function normalizeVisibilityRule(input: unknown): { operator: VisibilityMatchMode; conditions: VisibilityCondition[] } | null {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  const record = input as Record<string, unknown>;
  const operator = record.mode === "any" ? "any" : "all";
  const rawConditions = Array.isArray(record.conditions) ? record.conditions : null;
  if (rawConditions) {
    const conditions: VisibilityCondition[] = [];
    for (const raw of rawConditions) {
      if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
      const cond = raw as Record<string, unknown>;
      const dependsOn = typeof cond.dependsOn === "string" ? cond.dependsOn.trim() : "";
      const values = Array.isArray(cond.values)
        ? cond.values.map((value) => String(value).trim()).filter((value) => value.length > 0)
        : [];
      if (!dependsOn || values.length === 0) return null;
      const mode = cond.mode === "all" ? "all" : "any";
      conditions.push({ dependsOn, values, mode });
    }
    return conditions.length > 0 ? { operator, conditions } : null;
  }
  const dependsOn = typeof record.dependsOn === "string" ? record.dependsOn.trim() : "";
  const values = Array.isArray(record.values)
    ? record.values.map((value) => String(value).trim()).filter((value) => value.length > 0)
    : [];
  if (!dependsOn || values.length === 0) return null;
  const mode = record.mode === "all" ? "all" : "any";
  return { operator: "all", conditions: [{ dependsOn, values, mode }] };
}

function parseVisibilityRule(input: unknown) {
  return normalizeVisibilityRule(input);
}

function validateFileRulesInSchema(schema: unknown): string | null {
  if (!schema || typeof schema !== "object") return null;
  const fields = Array.isArray((schema as any).fields) ? (schema as any).fields : [];
  for (const field of fields) {
    if (!field || typeof field !== "object") continue;
    if ((field as any).type !== "file") continue;
    const fieldId = String((field as any).id || "");
    const rules =
      ((field as any).rules && typeof (field as any).rules === "object" ? (field as any).rules : null) ||
      ((field as any).fileRules && typeof (field as any).fileRules === "object" ? (field as any).fileRules : null);
    if (!rules) continue;
    if (typeof rules !== "object" || Array.isArray(rules)) {
      return `File field "${fieldId || "unknown"}" has invalid rules object.`;
    }
    const allowedExtensions = (rules as any).allowedExtensions ?? (rules as any).extensions;
    if (allowedExtensions !== undefined && !Array.isArray(allowedExtensions)) {
      return `File field "${fieldId || "unknown"}" extensions must be an array.`;
    }
    if (Array.isArray(allowedExtensions)) {
      const invalid = allowedExtensions.some(
        (ext) => typeof ext !== "string" || ext.trim().length === 0
      );
      if (invalid) {
        return `File field "${fieldId || "unknown"}" has invalid extensions.`;
      }
    }
    const maxBytes =
      (rules as any).maxFileSizeBytes ?? (rules as any).maxBytes ?? (rules as any).maxSizeBytes;
    if (maxBytes !== undefined && (typeof maxBytes !== "number" || maxBytes <= 0)) {
      return `File field "${fieldId || "unknown"}" max size must be a positive number.`;
    }
    const maxFiles = (rules as any).maxFiles ?? (rules as any).maxCount;
    if (maxFiles !== undefined && (typeof maxFiles !== "number" || maxFiles <= 0)) {
      return `File field "${fieldId || "unknown"}" max files must be a positive number.`;
    }
  }
  return null;
}

function validateVisibilityRulesInSchema(schema: unknown): string | null {
  if (!schema || typeof schema !== "object") return null;
  const fields = Array.isArray((schema as any).fields) ? (schema as any).fields : [];
  if (fields.length === 0) return null;
  const fieldIds = new Set<string>();
  const controllers = new Set<string>();
  fields.forEach((field: any) => {
    const id = typeof field?.id === "string" ? field.id : "";
    if (id) {
      fieldIds.add(id);
    }
    if (VISIBILITY_CONTROLLER_TYPES.has(String(field?.type || "")) && id) {
      controllers.add(id);
    }
  });
  for (const field of fields) {
    if (!field || typeof field !== "object") continue;
    const id = typeof (field as any).id === "string" ? (field as any).id : "";
    const visibility = (field as any).visibility;
    if (!visibility) continue;
    const parsed = parseVisibilityRule(visibility);
    if (!parsed) {
      return `Field "${id || "unknown"}" visibility is invalid.`;
    }
    for (const condition of parsed.conditions) {
      if (!fieldIds.has(condition.dependsOn)) {
        return `Field "${id || "unknown"}" depends on missing field "${condition.dependsOn}".`;
      }
      if (!controllers.has(condition.dependsOn)) {
        return `Field "${id || "unknown"}" depends on non-choice field "${condition.dependsOn}".`;
      }
      if (condition.dependsOn === id) {
        return `Field "${id || "unknown"}" cannot depend on itself.`;
      }
    }
  }
  return null;
}

function addFieldToSchemaText(
  text: string,
  field: Record<string, unknown>
) {
  const parsed = parseSchemaText(text);
  if ((parsed as any).error) return { error: (parsed as any).error };
  const fields = Array.isArray(parsed.fields) ? parsed.fields : [];
  if (fields.some((item: any) => item?.id === field.id)) {
    return { error: "Field id already exists in schema." };
  }
  const next = { ...(parsed.schema as any), fields: [...fields, field] };
  return { text: JSON.stringify(next, null, 2) };
}

function removeFieldFromSchemaText(text: string, fieldId: string) {
  const parsed = parseSchemaText(text);
  if ((parsed as any).error) return { error: (parsed as any).error };
  const fields = Array.isArray(parsed.fields) ? parsed.fields : [];
  const next = { ...(parsed.schema as any), fields: fields.filter((item: any) => item?.id !== fieldId) };
  return { text: JSON.stringify(next, null, 2) };
}

function moveFieldInSchemaText(text: string, fieldId: string, direction: "up" | "down") {
  const parsed = parseSchemaText(text);
  if ((parsed as any).error) return { error: (parsed as any).error };
  const fields = Array.isArray(parsed.fields) ? parsed.fields : [];
  const index = fields.findIndex((item: any) => item?.id === fieldId);
  if (index < 0) return { error: "Field not found." };
  const nextIndex = direction === "up" ? index - 1 : index + 1;
  if (nextIndex < 0 || nextIndex >= fields.length) {
    return { text: JSON.stringify(parsed.schema as any, null, 2) };
  }
  const nextFields = [...fields];
  const [item] = nextFields.splice(index, 1);
  nextFields.splice(nextIndex, 0, item);
  const next = { ...(parsed.schema as any), fields: nextFields };
  return { text: JSON.stringify(next, null, 2) };
}

function moveFieldToIndexInSchemaText(text: string, fieldId: string, targetIndex: number) {
  const parsed = parseSchemaText(text);
  if ((parsed as any).error) return { error: (parsed as any).error };
  const fields = Array.isArray(parsed.fields) ? parsed.fields : [];
  const index = fields.findIndex((item: any) => item?.id === fieldId);
  if (index < 0) return { error: "Field not found." };
  if (targetIndex < 0 || targetIndex >= fields.length || targetIndex === index) {
    return { text: JSON.stringify(parsed.schema as any, null, 2) };
  }
  const nextFields = [...fields];
  const [item] = nextFields.splice(index, 1);
  nextFields.splice(targetIndex, 0, item);
  const next = { ...(parsed.schema as any), fields: nextFields };
  return { text: JSON.stringify(next, null, 2) };
}

type FieldBuilderConfig = {
  type: string;
  customType: string;
  id: string;
  label: string;
  required: boolean;
  description: string;
  placeholder: string;
  options: string;
  multiple: boolean;
  textareaMarkdownEnabled: boolean;
  textareaMathjaxEnabled: boolean;
  textareaRows: number;
  emailDomain: string;
  autofillFromLogin: boolean;
  dateTimezone: string;
  dateMode: string;
  dateShowTimezone: boolean;
  visibilityEnabled: boolean;
  visibilityOperator: VisibilityMatchMode;
  visibilityConditions: Array<{ dependsOn: string; values: string; mode: VisibilityMatchMode }>;
};

type FileFieldBuilderConfig = {
  id: string;
  label: string;
  required: boolean;
  extensions: string;
  maxSizeMb: number;
  maxFiles: number;
};

const VISIBILITY_CONTROLLER_TYPES = new Set(["select", "checkbox", "radio"]);

function buildFieldPayload(config: FieldBuilderConfig) {
  if (!config.id.trim()) {
    return { error: "Field id is required." };
  }
  const type = config.type === "custom" ? config.customType.trim() : config.type;
  if (!type) {
    return { error: "Field type is required." };
  }
  const options = config.options
    .split(",")
    .map((opt) => opt.trim())
    .filter((opt) => opt.length > 0);
  const field: Record<string, unknown> = {
    id: config.id.trim(),
    type,
    label: config.label.trim() || config.id.trim(),
    required: Boolean(config.required)
  };
  if (config.description.trim()) {
    field.description = config.description.trim();
  }
  if (config.placeholder.trim()) {
    field.placeholder = config.placeholder.trim();
  }
  if (["select", "checkbox"].includes(type) && options.length > 0) {
    field.options = options;
    if (type === "checkbox") {
      field.multiple = Boolean(config.multiple);
    }
  }
  if (type === "email") {
    const domain = config.emailDomain.trim().toLowerCase().replace(/^@/, "");
    const rules: Record<string, unknown> = {};
    if (domain) {
      rules.domain = domain;
    }
    if (config.autofillFromLogin) {
      rules.autofill = true;
    }
    field.rules = rules;
  }
  if (type === "github_username") {
    const rules: Record<string, unknown> = {};
    if (config.autofillFromLogin) {
      rules.autofill = true;
    }
    field.rules = rules;
  }
  if (type === "date") {
    const rules: Record<string, unknown> = {};
    const timezone = config.dateTimezone.trim() || getAppDefaultTimezone();
    rules.timezoneDefault = timezone;
    const mode = config.dateMode && config.dateMode.trim() ? config.dateMode.trim() : "datetime";
    rules.mode = mode;
    if (!config.dateShowTimezone) {
      rules.timezoneOptional = true;
    }
    field.rules = rules;
  }
  if (type === "textarea") {
    const rules: Record<string, unknown> = {};
    if (config.textareaMarkdownEnabled) {
      rules.markdownEnabled = true;
    }
    if (config.textareaMathjaxEnabled) {
      rules.mathjaxEnabled = true;
    }
    if (Number.isFinite(config.textareaRows) && config.textareaRows > 0) {
      rules.rows = Math.max(1, Math.round(config.textareaRows));
    }
    if (Object.keys(rules).length > 0) {
      field.rules = rules;
    }
  }
  if (config.visibilityEnabled) {
    const normalizedConditions: VisibilityCondition[] = [];
    for (const condition of config.visibilityConditions) {
      const dependsOn = condition.dependsOn.trim();
      const values = condition.values
        .split(",")
        .map((value) => value.trim())
        .filter((value) => value.length > 0);
      if (!dependsOn && values.length === 0) {
        continue;
      }
      if (!dependsOn) {
        return { error: "Visibility depends-on field is required." };
      }
      if (dependsOn === config.id.trim()) {
        return { error: "Visibility depends-on field cannot be the same as the field id." };
      }
      if (values.length === 0) {
        return { error: "Visibility requires at least one match value." };
      }
      normalizedConditions.push({
        dependsOn,
        values,
        mode: condition.mode === "all" ? "all" : "any"
      });
    }
    if (normalizedConditions.length === 0) {
      return { error: "Visibility requires at least one condition." };
    }
    const operator = config.visibilityOperator === "any" ? "any" : "all";
    field.visibility = {
      mode: operator,
      conditions: normalizedConditions
    };
  }
  return { field };
}

function applyAddFieldToSchema(schemaText: string, config: FieldBuilderConfig) {
  const payload = buildFieldPayload(config);
  if (payload.error) return { error: payload.error };
  return addFieldToSchemaText(schemaText, payload.field!);
}

function applyAddFileFieldToSchema(schemaText: string, config: FileFieldBuilderConfig) {
  if (!config.id.trim()) {
    return { error: "File field id is required." };
  }
  if (!schemaText.trim()) {
    return { error: "Schema JSON is required." };
  }
  let parsed: any = null;
  try {
    parsed = JSON.parse(schemaText);
  } catch (error) {
    return { error: "Schema JSON is invalid." };
  }
  if (!parsed || typeof parsed !== "object") {
    return { error: "Schema JSON must be an object." };
  }
  if (!Array.isArray(parsed.fields)) {
    parsed.fields = [];
  }
  const exists = parsed.fields.some((field: any) => field?.id === config.id.trim());
  if (exists) {
    return { error: "Field id already exists in schema." };
  }
  const extensions = config.extensions
    .split(",")
    .map((ext) => ext.trim().toLowerCase().replace(/^\./, ""))
    .filter((ext) => ext.length > 0);
  const maxBytes = Math.max(1, Number(config.maxSizeMb || 0)) * 1024 * 1024;
  const maxFiles = Math.max(1, Number(config.maxFiles || 1));
  parsed.fields.push({
    id: config.id.trim(),
    type: "file",
    label: config.label.trim() || config.id.trim(),
    required: Boolean(config.required),
    rules: {
      allowedExtensions: extensions,
      maxFileSizeBytes: maxBytes,
      maxFiles
    }
  });
  return { text: JSON.stringify(parsed, null, 2) };
}

function updateFieldInSchemaText(
  schemaText: string,
  currentId: string,
  config: FieldBuilderConfig
) {
  if (!currentId.trim()) {
    return { error: "Select a field to edit." };
  }
  if (!schemaText.trim()) {
    return { error: "Schema JSON is required." };
  }
  let parsed: any = null;
  try {
    parsed = JSON.parse(schemaText);
  } catch (error) {
    return { error: "Schema JSON is invalid." };
  }
  if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.fields)) {
    return { error: "Schema JSON must include fields." };
  }
  const targetIndex = parsed.fields.findIndex((field: any) => field?.id === currentId);
  if (targetIndex === -1) {
    return { error: "Field not found in schema." };
  }
  const payload = buildFieldPayload(config);
  if (payload.error) {
    return { error: payload.error };
  }
  const nextId = String(payload.field!.id);
  if (
    nextId !== currentId &&
    parsed.fields.some((field: any) => field?.id === nextId)
  ) {
    return { error: "Field id already exists in schema." };
  }
    const currentField = parsed.fields[targetIndex] || {};
    const nextField = { ...currentField, ...payload.field };
  if (
    payload.field?.type !== "email" &&
    payload.field?.type !== "github_username" &&
    payload.field?.type !== "date" &&
    payload.field?.type !== "textarea"
  ) {
    delete (nextField as any).rules;
  }
    if (payload.field?.type === "textarea" && !(payload.field as any).rules) {
      delete (nextField as any).rules;
    }
    if (payload.field && !("visibility" in payload.field) && "visibility" in nextField) {
      delete (nextField as any).visibility;
    }
  if (!payload.field?.description && "description" in nextField) {
    delete (nextField as any).description;
  }
  parsed.fields[targetIndex] = nextField;
  return { text: JSON.stringify(parsed, null, 2) };
}

function updateFileFieldInSchemaText(
  schemaText: string,
  currentId: string,
  config: FileFieldBuilderConfig
) {
  if (!currentId.trim()) {
    return { error: "Select a file field to edit." };
  }
  if (!schemaText.trim()) {
    return { error: "Schema JSON is required." };
  }
  let parsed: any = null;
  try {
    parsed = JSON.parse(schemaText);
  } catch (error) {
    return { error: "Schema JSON is invalid." };
  }
  if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.fields)) {
    return { error: "Schema JSON must include fields." };
  }
  const targetIndex = parsed.fields.findIndex((field: any) => field?.id === currentId);
  if (targetIndex === -1) {
    return { error: "File field not found in schema." };
  }
  const nextId = config.id.trim();
  if (!nextId) {
    return { error: "Field id is required." };
  }
  if (
    nextId !== currentId &&
    parsed.fields.some((field: any) => field?.id === nextId)
  ) {
    return { error: "Field id already exists in schema." };
  }
  const extensions = config.extensions
    .split(",")
    .map((ext) => ext.trim().toLowerCase().replace(/^\./, ""))
    .filter((ext) => ext.length > 0);
  const maxBytes = Math.max(1, Number(config.maxSizeMb || 0)) * 1024 * 1024;
  const maxFiles = Math.max(1, Number(config.maxFiles || 1));
  const currentField = parsed.fields[targetIndex] || {};
  parsed.fields[targetIndex] = {
    ...currentField,
    id: nextId,
    type: "file",
    label: config.label.trim() || nextId,
    required: Boolean(config.required),
    rules: {
      allowedExtensions: extensions,
      maxFileSizeBytes: maxBytes,
      maxFiles
    }
  };
  return { text: JSON.stringify(parsed, null, 2) };
}

function FieldBuilderPanel({
  idPrefix,
  title,
  builderType,
  builderCustomType,
  builderId,
  builderLabel,
  builderRequired,
  builderDescription,
  builderPlaceholder,
  builderOptions,
  builderMultiple,
  builderTextareaMarkdownEnabled,
  builderTextareaMathjaxEnabled,
  builderTextareaRows,
  builderEmailDomain,
  builderAutofillFromLogin,
  builderDateTimezone,
  builderDateMode,
  builderDateShowTimezone,
  builderVisibilityEnabled,
  builderVisibilityOperator,
  builderVisibilityConditions,
  visibilityControllers,
  markdownEnabled,
  mathjaxEnabled,
  onTypeChange,
  onCustomTypeChange,
  onIdChange,
  onLabelChange,
  onRequiredChange,
  onDescriptionChange,
  onPlaceholderChange,
  onOptionsChange,
  onMultipleChange,
  onTextareaMarkdownEnabledChange,
  onTextareaMathjaxEnabledChange,
  onTextareaRowsChange,
  onEmailDomainChange,
  onAutofillFromLoginChange,
  onDateTimezoneChange,
  onDateModeChange,
  onDateShowTimezoneChange,
  onVisibilityEnabledChange,
  onVisibilityOperatorChange,
  onVisibilityConditionsChange,
  onAddField,
  fields,
  onRemoveField,
  onEditField,
  onMoveField,
  onReorderField
}: {
  idPrefix: string;
  title: string;
  builderType: string;
  builderCustomType: string;
  builderId: string;
  builderLabel: string;
  builderRequired: boolean;
  builderDescription: string;
  builderPlaceholder: string;
  builderOptions: string;
  builderMultiple: boolean;
  builderTextareaMarkdownEnabled: boolean;
  builderTextareaMathjaxEnabled: boolean;
  builderTextareaRows: number;
  builderEmailDomain: string;
  builderAutofillFromLogin: boolean;
  builderDateTimezone: string;
  builderDateMode: string;
  builderDateShowTimezone: boolean;
  builderVisibilityEnabled: boolean;
  builderVisibilityOperator: VisibilityMatchMode;
  builderVisibilityConditions: Array<{ dependsOn: string; values: string; mode: VisibilityMatchMode }>;
  visibilityControllers: Array<{ id: string; label: string; options: string[] }>;
  markdownEnabled: boolean;
  mathjaxEnabled: boolean;
  onTypeChange: (value: string) => void;
  onCustomTypeChange: (value: string) => void;
  onIdChange: (value: string) => void;
  onLabelChange: (value: string) => void;
  onRequiredChange: (value: boolean) => void;
  onDescriptionChange: (value: string) => void;
  onPlaceholderChange: (value: string) => void;
  onOptionsChange: (value: string) => void;
  onMultipleChange: (value: boolean) => void;
  onTextareaMarkdownEnabledChange: (value: boolean) => void;
  onTextareaMathjaxEnabledChange: (value: boolean) => void;
  onTextareaRowsChange: (value: number) => void;
  onEmailDomainChange: (value: string) => void;
  onAutofillFromLoginChange: (value: boolean) => void;
  onDateTimezoneChange: (value: string) => void;
  onDateModeChange: (value: string) => void;
  onDateShowTimezoneChange: (value: boolean) => void;
  onVisibilityEnabledChange: (value: boolean) => void;
  onVisibilityOperatorChange: (value: VisibilityMatchMode) => void;
  onVisibilityConditionsChange: (
    value: Array<{ dependsOn: string; values: string; mode: VisibilityMatchMode }>
  ) => void;
  onAddField: () => void;
  fields: Array<Record<string, unknown>>;
  onRemoveField: (id: string) => void;
  onEditField?: (id: string, field: Record<string, unknown>) => void;
  onMoveField?: (id: string, direction: "up" | "down") => void;
  onReorderField?: (id: string, targetIndex: number) => void;
}) {
  const [dragOverId, setDragOverId] = useState<string | null>(null);
  const requiredId = `${idPrefix}-required`;
  const multipleId = `${idPrefix}-multiple`;
  const visibilityId = `${idPrefix}-visibility`;
  const availableVisibilityControllers = visibilityControllers.filter(
    (controller) => controller.id !== builderId
  );
  const visibilityConditions =
    builderVisibilityConditions.length > 0
      ? builderVisibilityConditions
      : [{ dependsOn: "", values: "", mode: "any" as VisibilityMatchMode }];
  const updateVisibilityCondition = (index: number, patch: Partial<{ dependsOn: string; values: string; mode: VisibilityMatchMode }>) => {
    const next = visibilityConditions.map((condition, idx) =>
      idx === index ? { ...condition, ...patch } : condition
    );
    onVisibilityConditionsChange(next);
  };
  const addVisibilityCondition = () => {
    onVisibilityConditionsChange([
      ...visibilityConditions,
      { dependsOn: "", values: "", mode: "any" }
    ]);
  };
  const removeVisibilityCondition = (index: number) => {
    const next = visibilityConditions.filter((_, idx) => idx !== index);
    onVisibilityConditionsChange(next.length > 0 ? next : [{ dependsOn: "", values: "", mode: "any" }]);
  };
  return (
    <div className="panel panel--compact">
      <div className="panel-header">
        <h4 className="mb-0">{title}</h4>
      </div>
      <div className="row g-3">
        <div className="col-md-3">
          <label className="form-label">Type</label>
          <select className="form-select" value={builderType} onChange={(event) => onTypeChange(event.target.value)}>
            <option value="text">Text</option>
            <option value="full_name">Full Name</option>
            <option value="email">Email</option>
            <option value="github_username">GitHub Username</option>
            <option value="url">URL</option>
            <option value="date">Date/Time</option>
            <option value="number">Number</option>
            <option value="textarea">Textarea</option>
            <option value="select">Dropdown</option>
            <option value="checkbox">Checkboxes</option>
            <option value="custom">Custom</option>
          </select>
        </div>
        <div className="col-md-3">
          <label className="form-label">Field id</label>
          <input className="form-control" value={builderId} onChange={(event) => onIdChange(event.target.value)} />
        </div>
        <div className="col-md-3">
          <label className="form-label">Label</label>
          <input className="form-control" value={builderLabel} onChange={(event) => onLabelChange(event.target.value)} />
          {builderLabel ? (
            <div className="mt-2">
              <div className="muted">Preview</div>
              <RichText
                text={builderLabel}
                markdownEnabled={markdownEnabled}
                mathjaxEnabled={mathjaxEnabled}
                inline
              />
            </div>
          ) : null}
        </div>
        <div className="col-md-6">
          <label className="form-label">Description (optional)</label>
          <textarea
            className="form-control"
            value={builderDescription}
            onChange={(event) => onDescriptionChange(event.target.value)}
            rows={2}
          />
          {builderDescription ? (
            <div className="mt-2">
              <div className="muted">Preview</div>
              <RichText text={builderDescription} markdownEnabled={markdownEnabled} mathjaxEnabled={mathjaxEnabled} />
            </div>
          ) : null}
        </div>
        <div className="col-md-3">
          <label className="form-label">Required</label>
          <div className="form-check mt-2">
            <input
              className="form-check-input"
              type="checkbox"
              checked={builderRequired}
              onChange={(event) => onRequiredChange(event.target.checked)}
              id={requiredId}
            />
            <label className="form-check-label" htmlFor={requiredId}>
              Yes
            </label>
          </div>
        </div>
        {builderType === "custom" ? (
          <div className="col-md-3">
            <label className="form-label">Custom type</label>
            <input
              className="form-control"
              value={builderCustomType}
              onChange={(event) => onCustomTypeChange(event.target.value)}
            />
          </div>
        ) : null}
        {["text", "full_name", "email", "github_username", "url", "number", "textarea", "custom"].includes(builderType) ? (
          <div className="col-md-6">
            <label className="form-label">Placeholder</label>
            <textarea
              className="form-control"
              rows={2}
              value={builderPlaceholder}
              onChange={(event) => onPlaceholderChange(event.target.value)}
            />
            {builderPlaceholder ? (
              <div className="mt-2">
                <div className="muted">Preview</div>
                <RichText
                  text={builderPlaceholder}
                  markdownEnabled={markdownEnabled}
                  mathjaxEnabled={mathjaxEnabled}
                />
              </div>
            ) : null}
          </div>
        ) : null}
        {builderType === "email" ? (
          <div className="col-md-6">
            <label className="form-label">Allowed domain (optional)</label>
            <input
              className="form-control"
              value={builderEmailDomain}
              onChange={(event) => onEmailDomainChange(event.target.value)}
              placeholder="example.com"
            />
            <div className="form-check mt-2">
              <input
                className="form-check-input"
                type="checkbox"
                checked={builderAutofillFromLogin}
                onChange={(event) => onAutofillFromLoginChange(event.target.checked)}
                id={`${idPrefix}-email-autofill`}
              />
              <label className="form-check-label" htmlFor={`${idPrefix}-email-autofill`}>
                Auto-fill from login email
              </label>
            </div>
          </div>
        ) : null}
        {builderType === "textarea" ? (
          <div className="col-md-6">
            <label className="form-label">Textarea input support</label>
            <div className="form-check mt-2">
              <input
                className="form-check-input"
                type="checkbox"
                checked={builderTextareaMarkdownEnabled}
                onChange={(event) => onTextareaMarkdownEnabledChange(event.target.checked)}
                id={`${idPrefix}-textarea-markdown`}
              />
              <label className="form-check-label" htmlFor={`${idPrefix}-textarea-markdown`}>
                Allow Markdown + HTML input
              </label>
            </div>
            <div className="form-check mt-2">
              <input
                className="form-check-input"
                type="checkbox"
                checked={builderTextareaMathjaxEnabled}
                onChange={(event) => onTextareaMathjaxEnabledChange(event.target.checked)}
                id={`${idPrefix}-textarea-mathjax`}
              />
              <label className="form-check-label" htmlFor={`${idPrefix}-textarea-mathjax`}>
                Allow MathJax input
              </label>
            </div>
            <div className="mt-2">
              <label className="form-label">Textarea rows</label>
              <input
                type="number"
                className="form-control"
                min={1}
                value={builderTextareaRows}
                onChange={(event) => onTextareaRowsChange(Math.max(1, parseInt(event.target.value, 10) || 1))}
              />
              <div className="muted mt-1">Fixed number of visible lines for this textarea.</div>
            </div>
            <div className="muted mt-2">
              Preview is shown to the user when enabled and the app settings allow it.
            </div>
          </div>
        ) : null}
        {builderType === "github_username" ? (
          <div className="col-md-6">
            <label className="form-label">Login integration</label>
            <div className="form-check mt-2">
              <input
                className="form-check-input"
                type="checkbox"
                checked={builderAutofillFromLogin}
                onChange={(event) => onAutofillFromLoginChange(event.target.checked)}
                id={`${idPrefix}-github-autofill`}
              />
              <label className="form-check-label" htmlFor={`${idPrefix}-github-autofill`}>
                Auto-fill from GitHub login
              </label>
            </div>
          </div>
        ) : null}
        {builderType === "date" ? (
          <div className="col-md-6">
            <label className="form-label">Date/Time mode</label>
            <select
              className="form-select"
              value={builderDateMode}
              onChange={(event) => onDateModeChange(event.target.value)}
            >
              <option value="datetime">Date & time</option>
              <option value="date">Date only</option>
              <option value="time">Time only</option>
            </select>
            <div className="mt-3">
              <label className="form-label">Default timezone</label>
              <TimezoneSelect
                idPrefix={`${idPrefix}-date-tz`}
                value={builderDateTimezone}
                onChange={onDateTimezoneChange}
              />
            </div>
            <div className="form-check mt-3">
              <input
                className="form-check-input"
                type="checkbox"
                checked={builderDateShowTimezone}
                onChange={(event) => onDateShowTimezoneChange(event.target.checked)}
                id={`${idPrefix}-date-show-tz`}
              />
              <label className="form-check-label" htmlFor={`${idPrefix}-date-show-tz`}>
                Show timezone selector
              </label>
            </div>
          </div>
        ) : null}
        {["select", "checkbox"].includes(builderType) ? (
          <div className="col-md-6">
            <label className="form-label">Options (comma separated)</label>
            <input
              className="form-control"
              value={builderOptions}
              onChange={(event) => onOptionsChange(event.target.value)}
              placeholder="Option A, Option B"
            />
          </div>
        ) : null}
        {builderType === "checkbox" ? (
          <div className="col-md-3">
            <label className="form-label">Multiple allowed</label>
            <div className="form-check mt-2">
              <input
                className="form-check-input"
                type="checkbox"
                checked={builderMultiple}
                onChange={(event) => onMultipleChange(event.target.checked)}
                id={multipleId}
              />
              <label className="form-check-label" htmlFor={multipleId}>
                Yes
              </label>
            </div>
          </div>
        ) : null}
        <div className="col-12">
          <label className="form-label">Conditional visibility</label>
          <div className="form-check mt-2">
            <input
              className="form-check-input"
              type="checkbox"
              checked={builderVisibilityEnabled}
              onChange={(event) => onVisibilityEnabledChange(event.target.checked)}
              id={visibilityId}
              disabled={availableVisibilityControllers.length === 0}
            />
            <label className="form-check-label" htmlFor={visibilityId}>
              Show only when conditions match
            </label>
          </div>
          {availableVisibilityControllers.length === 0 ? (
            <div className="muted mt-1">Add a dropdown/checkbox field first to enable conditions.</div>
          ) : builderVisibilityEnabled ? (
            <div className="mt-1">
              <div className="row g-3">
                <div className="col-md-4">
                  <label className="form-label">Match</label>
                  <select
                    className="form-select"
                    value={builderVisibilityOperator}
                    onChange={(event) =>
                      onVisibilityOperatorChange(event.target.value === "any" ? "any" : "all")
                    }
                  >
                    <option value="all">All conditions</option>
                    <option value="any">Any condition</option>
                  </select>
                </div>
              </div>
              {visibilityConditions.map((condition, index) => {
                const visibilityOptions = (
                  availableVisibilityControllers.find(
                    (controller) => controller.id === condition.dependsOn
                  )?.options ?? []
                ).join(", ");
                return (
                  <div className="row g-3 mt-1" key={`visibility-${index}`}>
                    <div className="col-md-4">
                      <label className="form-label">Depends on</label>
                      <select
                        className="form-select"
                        value={condition.dependsOn}
                        onChange={(event) =>
                          updateVisibilityCondition(index, { dependsOn: event.target.value })
                        }
                      >
                        <option value="">Select field</option>
                        {availableVisibilityControllers.map((controller) => (
                          <option key={controller.id} value={controller.id}>
                            {controller.label || controller.id}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div className="col-md-3">
                      <label className="form-label">Match mode</label>
                      <select
                        className="form-select"
                        value={condition.mode}
                        onChange={(event) =>
                          updateVisibilityCondition(index, {
                            mode: event.target.value === "all" ? "all" : "any"
                          })
                        }
                      >
                        <option value="any">Any selected</option>
                        <option value="all">All selected</option>
                      </select>
                    </div>
                    <div className="col-md-4">
                      <label className="form-label">Values (comma separated)</label>
                      <input
                        className="form-control"
                        value={condition.values}
                        onChange={(event) =>
                          updateVisibilityCondition(index, { values: event.target.value })
                        }
                        placeholder="Option A, Option B"
                      />
                      {visibilityOptions ? (
                        <div className="muted mt-1">Available: {visibilityOptions}</div>
                      ) : (
                        <div className="muted mt-1">Select a controller field to see options.</div>
                      )}
                    </div>
                    <div className="col-md-1 d-flex align-items-end">
                      <button
                        type="button"
                        className="btn btn-outline-danger btn-sm"
                        onClick={() => removeVisibilityCondition(index)}
                        aria-label="Remove condition"
                        title="Remove condition"
                      >
                        <i className="bi bi-x-lg" aria-hidden="true" />
                      </button>
                    </div>
                  </div>
                );
              })}
              <div className="mt-2">
                <button
                  type="button"
                  className="btn btn-outline-secondary btn-sm"
                  onClick={addVisibilityCondition}
                >
                  <i className="bi bi-plus-circle" aria-hidden="true" /> Add condition
                </button>
              </div>
            </div>
          ) : null}
        </div>
      </div>
      <div className="d-flex gap-2 mt-3">
        <button type="button" className="btn btn-outline-primary" onClick={onAddField}>
          <i className="bi bi-plus-circle" aria-hidden="true" /> Add field
        </button>
      </div>
      {fields.length > 0 ? (
        <div className="table-responsive mt-3">
          <table className="table table-sm">
            <thead>
              <tr>
                <th style={{ width: "2.5rem" }}></th>
                <th>Id</th>
                <th>Type</th>
                <th>Label</th>
                <th>Required</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {fields.map((field, index) => (
                <tr
                  key={String(field.id || field.label)}
                  className={dragOverId === String(field.id || "") ? "table-active" : undefined}
                  onDragOver={(event) => {
                    if (!onReorderField) return;
                    event.preventDefault();
                    event.dataTransfer.dropEffect = "move";
                  }}
                  onDragEnter={() => {
                    if (!onReorderField || !field.id) return;
                    setDragOverId(String(field.id));
                  }}
                  onDragLeave={() => {
                    if (!onReorderField) return;
                    setDragOverId((prev) => (prev === String(field.id || "") ? null : prev));
                  }}
                  onDrop={(event) => {
                    if (!onReorderField) return;
                    event.preventDefault();
                    const draggedId = event.dataTransfer.getData("text/plain");
                    if (!draggedId) return;
                    onReorderField(draggedId, index);
                    setDragOverId(null);
                  }}
                >
                  <td>
                    {onReorderField && field.id ? (
                      <span
                        role="button"
                        title="Drag to reorder"
                        draggable
                        onDragStart={(event) => {
                          if (!onReorderField || !field.id) return;
                          event.dataTransfer.setData("text/plain", String(field.id));
                          event.dataTransfer.effectAllowed = "move";
                        }}
                        style={{ cursor: "grab" }}
                      >
                        <i className="bi bi-grip-vertical" aria-hidden="true" />
                      </span>
                    ) : null}
                  </td>
                  <td>{String(field.id || "")}</td>
                  <td>{String(field.type || "")}</td>
                  <td>{String(field.label || "")}</td>
                  <td>{field.required ? "Yes" : "No"}</td>
                  <td>
                    {onMoveField ? (
                      <div className="btn-group btn-group-sm me-2" role="group">
                        <button
                          type="button"
                          className="btn btn-outline-secondary"
                          onClick={() => onMoveField(String(field.id || ""), "up")}
                          disabled={!field.id || index === 0}
                        >
                          <i className="bi bi-arrow-up" aria-hidden="true" />
                        </button>
                        <button
                          type="button"
                          className="btn btn-outline-secondary"
                          onClick={() => onMoveField(String(field.id || ""), "down")}
                          disabled={!field.id || index === fields.length - 1}
                        >
                          <i className="bi bi-arrow-down" aria-hidden="true" />
                        </button>
                      </div>
                    ) : null}
                    {onEditField ? (
                      <button
                        type="button"
                        className="btn btn-outline-secondary btn-sm me-2"
                        onClick={() => onEditField(String(field.id || ""), field)}
                        disabled={!field.id}
                      >
                        <i className="bi bi-pencil" aria-hidden="true" /> Edit
                      </button>
                    ) : null}
                    <button
                      type="button"
                      className="btn btn-outline-danger btn-sm"
                      onClick={() => onRemoveField(String(field.id || ""))}
                      disabled={!field.id}
                    >
                      <i className="bi bi-trash" aria-hidden="true" /> Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}

function FileFieldBuilderPanel({
  idPrefix,
  title,
  fieldId,
  fieldLabel,
  fieldRequired,
  fieldExtensions,
  fieldMaxSizeMb,
  fieldMaxFiles,
  onIdChange,
  onLabelChange,
  onRequiredChange,
  onExtensionsChange,
  onMaxSizeChange,
  onMaxFilesChange,
  onAdd
}: {
  idPrefix: string;
  title: string;
  fieldId: string;
  fieldLabel: string;
  fieldRequired: boolean;
  fieldExtensions: string;
  fieldMaxSizeMb: number;
  fieldMaxFiles: number;
  onIdChange: (value: string) => void;
  onLabelChange: (value: string) => void;
  onRequiredChange: (value: boolean) => void;
  onExtensionsChange: (value: string) => void;
  onMaxSizeChange: (value: number) => void;
  onMaxFilesChange: (value: number) => void;
  onAdd: () => void;
}) {
  const requiredId = `${idPrefix}-required`;
  return (
    <div className="panel panel--compact">
      <div className="panel-header">
        <h4 className="mb-0">{title}</h4>
      </div>
      <div className="row g-3">
        <div className="col-md-3">
          <label className="form-label">Field id</label>
          <input className="form-control" value={fieldId} onChange={(event) => onIdChange(event.target.value)} />
        </div>
        <div className="col-md-3">
          <label className="form-label">Label</label>
          <input className="form-control" value={fieldLabel} onChange={(event) => onLabelChange(event.target.value)} />
        </div>
        <div className="col-md-2">
          <label className="form-label">Required</label>
          <div className="form-check mt-2">
            <input
              className="form-check-input"
              type="checkbox"
              checked={fieldRequired}
              onChange={(event) => onRequiredChange(event.target.checked)}
              id={requiredId}
            />
            <label className="form-check-label" htmlFor={requiredId}>
              Yes
            </label>
          </div>
        </div>
        <div className="col-md-2">
          <label className="form-label">Max size (MB)</label>
          <input
            className="form-control"
            type="number"
            min={1}
            value={fieldMaxSizeMb}
            onChange={(event) => onMaxSizeChange(Number(event.target.value))}
          />
        </div>
        <div className="col-md-2">
          <label className="form-label">Max files</label>
          <input
            className="form-control"
            type="number"
            min={1}
            value={fieldMaxFiles}
            onChange={(event) => onMaxFilesChange(Number(event.target.value))}
          />
        </div>
        <div className="col-12">
          <label className="form-label">Allowed extensions (csv)</label>
          <input
            className="form-control"
            value={fieldExtensions}
            onChange={(event) => onExtensionsChange(event.target.value)}
            placeholder="pdf,png,jpg"
          />
        </div>
      </div>
      <div className="d-flex gap-2 mt-3">
        <button type="button" className="btn btn-outline-primary" onClick={onAdd}>
          <i className="bi bi-file-earmark-plus" aria-hidden="true" /> Add file field
        </button>
      </div>
    </div>
  );
}

function buildAdminExportUrl(
  formSlug: string,
  options: {
    format: "csv" | "txt";
    mode: "flat" | "json";
    includeMeta: boolean;
    maxRows: number;
    fields?: string;
  }
) {
  const params = new URLSearchParams();
  params.set("formSlug", formSlug);
  params.set("format", options.format);
  params.set("mode", options.mode);
  params.set("includeMeta", options.includeMeta ? "1" : "0");
  params.set("maxRows", String(options.maxRows));
  if (options.fields && options.fields.trim()) {
    params.set("fields", options.fields.trim());
  }
  return `${API_BASE}/api/admin/submissions/export?${params.toString()}`;
}

function buildFormSubmissionsExportUrl(
  formSlug: string,
  format: "csv" | "txt",
  fields?: string
) {
  const params = new URLSearchParams();
  params.set("format", format);
  if (fields && fields.trim()) {
    params.set("fields", fields.trim());
  }
  return `${API_BASE}/api/admin/forms/${encodeURIComponent(formSlug)}/submissions/export?${params.toString()}`;
}

function parseFileRules(raw: string | null | undefined): FieldRuleset {
  const defaultRule: FieldRule = {
    extensions: [],
    maxBytes: 10 * 1024 * 1024,
    maxFiles: 3
  };
  if (!raw) {
    return { fields: {}, defaultRule };
  }
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    if (parsed && typeof parsed === "object" && "fields" in parsed) {
      const fields: Record<string, FieldRule> = {};
      const fieldRules = (parsed as { fields?: Record<string, unknown> }).fields || {};
      Object.entries(fieldRules).forEach(([fieldId, value]) => {
        if (!value || typeof value !== "object") return;
        const record = value as Record<string, unknown>;
        const extensions = Array.isArray(record.extensions)
          ? record.extensions
            .map((ext) => (typeof ext === "string" ? ext.toLowerCase().replace(/^\./, "") : ""))
            .filter((ext) => ext.length > 0)
          : [];
        const maxBytes = typeof record.maxBytes === "number" ? record.maxBytes : defaultRule.maxBytes;
        const maxFiles = typeof record.maxFiles === "number" ? record.maxFiles : defaultRule.maxFiles;
        fields[fieldId] = { extensions, maxBytes, maxFiles };
      });
      return { fields, defaultRule };
    }
    const record = parsed as Record<string, unknown>;
    const extensions = Array.isArray(record.allowedExtensions)
      ? record.allowedExtensions
        .map((ext) => (typeof ext === "string" ? ext.toLowerCase().replace(/^\./, "") : ""))
        .filter((ext) => ext.length > 0)
      : [];
    const maxBytes =
      typeof record.maxFileSizeBytes === "number"
        ? record.maxFileSizeBytes
        : typeof record.maxSizeBytes === "number"
          ? record.maxSizeBytes
          : defaultRule.maxBytes;
    const maxFiles = typeof record.maxFiles === "number" ? record.maxFiles : defaultRule.maxFiles;
    return { fields: {}, defaultRule: { extensions, maxBytes, maxFiles } };
  } catch (error) {
    return { fields: {}, defaultRule };
  }
}

function getFieldRule(rules: FieldRuleset, fieldId: string): FieldRule {
  return rules.fields[fieldId] || rules.defaultRule;
}

function formatTimeICT(value: string | null) {
  if (!value) return "";
  let normalized = value;
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(value)) {
    normalized = value.replace(" ", "T") + "Z";
  }
  const date = new Date(normalized);
  if (Number.isNaN(date.getTime())) return value;
  const timeZone = getAppDefaultTimezone() || "UTC";
  try {
    return new Intl.DateTimeFormat("en-GB", {
      timeZone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
      timeZoneName: "short"
    }).format(date);
  } catch (error) {
    try {
      return new Intl.DateTimeFormat("en-GB", {
        timeZone: "UTC",
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
        timeZoneName: "short"
      }).format(date);
    } catch (err) {
      return date.toLocaleString("en-GB");
    }
  }
}

function buildSubmissionExportContent({
  submission,
  dataValues,
  fieldMeta,
  fieldOrder,
  format,
  versionLabel
}: {
  submission: any;
  dataValues: Record<string, unknown> | null;
  fieldMeta: FieldMetaMap;
  fieldOrder: string[];
  format: SubmissionExportFormat;
  versionLabel?: string | null;
}) {
  const submissionId = submission?.submissionId ? String(submission.submissionId) : "submission";
  const formSlug = submission?.form?.slug ? String(submission.form.slug) : "submission";
  const formTitle = submission?.form?.title ? String(submission.form.title) : formSlug;
  const timestamp = formatFilenameTimestamp(new Date());
  const slugPart = formSlug.replace(/[^a-zA-Z0-9_-]+/g, "-").replace(/^-+|-+$/g, "") || "submission";
  const idPart = submissionId.replace(/[^a-zA-Z0-9_-]+/g, "-").replace(/^-+|-+$/g, "") || "submission";
  const extension = format === "markdown" ? "md" : format;
  const filename = `${slugPart}-${idPart}-${timestamp}.${extension}`;
  const createdAt = formatTimeICT(submission?.created_at ?? null);
  const updatedAt = formatTimeICT(submission?.updated_at ?? null);
  const reminderText = submission?.form?.reminder_enabled
    ? formatReminderFrequency(submission.form.reminder_frequency)
    : "";

  const metaEntries = [
    { key: "exported_at", label: "Exported", value: formatTimeICT(new Date().toISOString()) },
    { key: "submission_id", label: "Submission ID", value: submissionId },
    { key: "form_title", label: "Form", value: formTitle },
    { key: "form_slug", label: "Form slug", value: formSlug },
    { key: "submitted_at", label: "Submitted", value: createdAt },
    { key: "updated_at", label: "Updated", value: updatedAt }
  ];
  if (versionLabel) {
    metaEntries.push({ key: "data_version", label: "Data version", value: versionLabel });
  }
  if (submission?.form?.auth_policy) {
    metaEntries.push({
      key: "auth_policy",
      label: "Auth policy",
      value: String(submission.form.auth_policy)
    });
  }
  if (submission?.user_id) {
    metaEntries.push({
      key: "user_id",
      label: "User ID",
      value: submission.user_id
    });
  }
  if (submission?.submitter?.provider) {
    metaEntries.push({
      key: "submitter_provider",
      label: "Submitter provider",
      value: submission.submitter.provider
    });
  }
  if (submission?.submitter?.email) {
    metaEntries.push({
      key: "submitter_email",
      label: "Submitter email",
      value: submission.submitter.email
    });
  }
  if (submission?.submitter?.github_username) {
    metaEntries.push({
      key: "submitter_github_username",
      label: "Submitter GitHub username",
      value: submission.submitter.github_username
    });
  }
  if (submission?.created_ip) {
    metaEntries.push({
      key: "created_ip",
      label: "Created IP",
      value: submission.created_ip
    });
  }
  if (submission?.created_user_agent) {
    metaEntries.push({
      key: "created_user_agent",
      label: "Created user agent",
      value: submission.created_user_agent
    });
  }
  if (typeof submission?.form?.is_locked === "boolean") {
    metaEntries.push({
      key: "form_locked",
      label: "Form locked",
      value: submission.form.is_locked ? "yes" : "no"
    });
  }
  if (typeof submission?.form?.is_public === "boolean") {
    metaEntries.push({
      key: "form_public",
      label: "Form public",
      value: submission.form.is_public ? "yes" : "no"
    });
  }
  if (submission?.form?.reminder_enabled) {
    metaEntries.push({
      key: "reminder_frequency",
      label: "Reminder frequency",
      value: reminderText || "enabled"
    });
  }
  if (submission?.form?.reminder_until) {
    metaEntries.push({
      key: "reminder_until",
      label: "Reminder until",
      value: formatTimeICT(submission.form.reminder_until)
    });
  }
  if (submission?.canvas?.status) {
    metaEntries.push({ key: "canvas_status", label: "Canvas status", value: submission.canvas.status });
  }
  if (submission?.canvas?.error) {
    metaEntries.push({ key: "canvas_error", label: "Canvas error", value: submission.canvas.error });
  }
  if (submission?.canvas?.course_id) {
    metaEntries.push({
      key: "canvas_course_id",
      label: "Canvas course ID",
      value: submission.canvas.course_id
    });
  }
  if (submission?.canvas?.section_id) {
    metaEntries.push({
      key: "canvas_section_id",
      label: "Canvas section ID",
      value: submission.canvas.section_id
    });
  }
  if (submission?.canvas?.user_id) {
    metaEntries.push({ key: "canvas_user_id", label: "Canvas user ID", value: submission.canvas.user_id });
  }
  if (submission?.canvas?.user_name) {
    metaEntries.push({
      key: "canvas_user_name",
      label: "Canvas user name",
      value: submission.canvas.user_name
    });
  }
  if (submission?.canvas?.display_name) {
    metaEntries.push({
      key: "canvas_display_name",
      label: "Canvas display name",
      value: submission.canvas.display_name
    });
  }
  if (submission?.canvas?.full_name) {
    metaEntries.push({
      key: "canvas_full_name",
      label: "Canvas full name",
      value: submission.canvas.full_name
    });
  }

  const dataObject =
    dataValues && typeof dataValues === "object" && !Array.isArray(dataValues) ? dataValues : {};
  const orderedKeys = fieldOrder.filter((key) => key in dataObject);
  const remainingKeys = Object.keys(dataObject).filter((key) => !orderedKeys.includes(key));
  const dataKeys = [...orderedKeys, ...remainingKeys];
  const dataEntries = dataKeys.map((key) => {
    const metaLabel = fieldMeta[key]?.label || key;
    const label = metaLabel !== key ? `${metaLabel} (${key})` : metaLabel;
    return {
      key,
      label,
      value: normalizeExportValue(dataObject[key])
    };
  });

  const files = Array.isArray(submission?.files) ? submission.files : [];

  if (format === "markdown") {
    const lines = ["# Submission export", "", "## Metadata"];
    metaEntries.forEach((entry) => {
      lines.push(`- **${entry.label}:** ${escapeMarkdownCell(entry.value || "n/a")}`);
    });
    lines.push("", "## Data");
    if (dataEntries.length === 0) {
      lines.push("_No data_");
    } else {
      lines.push("| Field | Value |", "| --- | --- |");
      dataEntries.forEach((entry) => {
        lines.push(`| ${escapeMarkdownCell(entry.label)} | ${escapeMarkdownCell(entry.value || "")} |`);
      });
    }
    lines.push("", "## Files");
    if (files.length === 0) {
      lines.push("_No files_");
    } else {
      lines.push("| Field | File | Size | VirusTotal |", "| --- | --- | --- | --- |");
      files.forEach((file: any) => {
        const fileLabel = fieldMeta[file.field_id]?.label || file.field_id || "file";
        const sizeValue =
          typeof file.size_bytes === "number"
            ? `${formatSize(file.size_bytes)} (${file.size_bytes} bytes)`
            : "n/a";
        const vtLabel = file.vt_verdict
          ? `${file.vt_status || "pending"} (${file.vt_verdict})`
          : file.vt_status || "pending";
        lines.push(
          `| ${escapeMarkdownCell(fileLabel)} | ${escapeMarkdownCell(
            String(file.original_name || "")
          )} | ${escapeMarkdownCell(sizeValue)} | ${escapeMarkdownCell(vtLabel)} |`
        );
      });
    }
    return { filename, content: lines.join("\n"), mimeType: "text/markdown; charset=utf-8" };
  }

  if (format === "txt") {
    const lines = ["Submission export", ""];
    metaEntries.forEach((entry) => {
      lines.push(`${entry.label}: ${entry.value || "n/a"}`);
    });
    lines.push("", "Data:");
    if (dataEntries.length === 0) {
      lines.push("  (no data)");
    } else {
      dataEntries.forEach((entry) => {
        lines.push(`- ${entry.label}: ${entry.value || ""}`);
      });
    }
    lines.push("", "Files:");
    if (files.length === 0) {
      lines.push("  (no files)");
    } else {
      files.forEach((file: any, index: number) => {
        const fileLabel = fieldMeta[file.field_id]?.label || file.field_id || "file";
        lines.push(`- File ${index + 1}`);
        lines.push(`  Field: ${fileLabel}`);
        lines.push(`  Name: ${file.original_name || "n/a"}`);
        if (typeof file.size_bytes === "number") {
          lines.push(`  Size: ${formatSize(file.size_bytes)} (${file.size_bytes} bytes)`);
        }
        if (file.vt_status) {
          lines.push(`  VirusTotal: ${file.vt_status}${file.vt_verdict ? ` (${file.vt_verdict})` : ""}`);
        }
        if (file.final_drive_file_id) {
          lines.push(`  Drive file ID: ${file.final_drive_file_id}`);
        }
        if (file.drive_web_view_link) {
          lines.push(`  Drive link: ${file.drive_web_view_link}`);
        }
        if (file.finalized_at) {
          lines.push(`  Finalized: ${formatTimeICT(file.finalized_at)}`);
        }
      });
    }
    return { filename, content: lines.join("\n"), mimeType: "text/plain; charset=utf-8" };
  }

  const rows: string[][] = [["section", "key", "value"]];
  metaEntries.forEach((entry) => {
    rows.push(["meta", entry.key, entry.value || ""]);
  });
  dataEntries.forEach((entry) => {
    rows.push(["data", entry.key, entry.value || ""]);
  });
  files.forEach((file: any, index: number) => {
    const prefix = `file.${index + 1}`;
    rows.push(["file", `${prefix}.field`, fieldMeta[file.field_id]?.label || file.field_id || "file"]);
    rows.push(["file", `${prefix}.name`, String(file.original_name || "")]);
    if (typeof file.size_bytes === "number") {
      rows.push(["file", `${prefix}.size_bytes`, String(file.size_bytes)]);
    }
    if (file.vt_status) {
      rows.push(["file", `${prefix}.vt_status`, String(file.vt_status)]);
    }
    if (file.vt_verdict) {
      rows.push(["file", `${prefix}.vt_verdict`, String(file.vt_verdict)]);
    }
    if (file.final_drive_file_id) {
      rows.push(["file", `${prefix}.drive_file_id`, String(file.final_drive_file_id)]);
    }
    if (file.drive_web_view_link) {
      rows.push(["file", `${prefix}.drive_link`, String(file.drive_web_view_link)]);
    }
    if (file.finalized_at) {
      rows.push(["file", `${prefix}.finalized_at`, formatTimeICT(file.finalized_at)]);
    }
  });
  const content = rows.map((row) => row.map((cell) => csvEscapeValue(String(cell))).join(",")).join("\n");
  return { filename, content, mimeType: "text/csv; charset=utf-8" };
}

function isoToLocalInput(value?: string | null) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60000);
  return local.toISOString().slice(0, 16);
}

function localInputToIso(value: string) {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
}

function localInputToUtcWithZone(value: string, timeZone: string) {
  if (!value) return null;
  const utcIso = zonedTimeToUtcIso(value, timeZone);
  return utcIso || null;
}

function utcToLocalInputWithZone(value: string | null | undefined, timeZone: string) {
  if (!value) return "";
  const local = utcToLocalDateTime(value, timeZone);
  if (local) return local;
  return isoToLocalInput(value);
}

function buildReturnTo() {
  return `${window.location.origin}${PUBLIC_BASE}#/auth/callback?return_to=${encodeURIComponent(
    window.location.href
  )}`;
}

function buildFileIdentity(fieldKey: string, file: File) {
  return `${fieldKey}:${file.name}:${file.size}`;
}

function AuthBar({
  user,
  onLogin,
  onLogout
}: {
  user: UserInfo | null;
  onLogin: (provider: "google" | "github") => void;
  onLogout: (silent?: boolean) => void;
}) {
  const providerLabel = user?.provider
    ? user.provider.charAt(0).toUpperCase() + user.provider.slice(1)
    : "";
  const providerIcon = user?.provider === "google" ? "bi-google" : user?.provider === "github" ? "bi-github" : "";
  return (
    <div className="auth-bar">
      {user ? (
        <>
          <div className="auth-user">
            <div className="auth-user-title">Signed in</div>
            <div className="auth-user-meta">
              {getUserDisplayName(user)} -{" "}
              {providerIcon ? <i className={`bi ${providerIcon}`} aria-hidden="true" /> : null}{" "}
              {providerLabel}
            </div>
          </div>
          <button type="button" className="btn btn-outline-secondary btn-sm" onClick={() => onLogout()}>
            <i className="bi bi-box-arrow-right" aria-hidden="true" /> Logout
          </button>
        </>
      ) : (
        <>
          <button type="button" className="btn btn-primary btn-sm btn-auth" onClick={() => onLogin("google")}>
            <i className="bi bi-google" aria-hidden="true" /> Login with Google
          </button>
          <button
            type="button"
            className="btn btn-dark btn-auth"
            onClick={() => onLogin("github")}
          >
            <i className="bi bi-github" aria-hidden="true" /> Login with GitHub
          </button>
        </>
      )}
    </div>
  );
}

function ApiStatus({ loading, error }: { loading: boolean; error: ApiError | null }) {
  return (
    <div className={`status ${error ? "status--error" : "status--ok"}`}>
      <span className="status-dot" />
      <div>
        <div className="status-title">
          API status: {loading ? "checking..." : error ? "error" : "online"}
        </div>
        <div className="status-meta">{API_BASE}</div>
      </div>
    </div>
  );
}

function AuthStatus({ user }: { user: UserInfo | null }) {
  const providerLabel = user?.provider
    ? user.provider.charAt(0).toUpperCase() + user.provider.slice(1)
    : "";
  const providerIcon = user?.provider === "google" ? "bi-google" : user?.provider === "github" ? "bi-github" : "";
  return (
    <div className="panel panel--compact">
      <div className="panel-header">
        <h2>Auth status</h2>
        <span className={`badge ${user ? "text-bg-success" : "text-bg-secondary"}`}>
          <i
            className={`bi ${user ? "bi-shield-check" : "bi-shield-x"}`}
            aria-hidden="true"
          />{" "}
          {user ? "Authenticated" : "Signed out"}
        </span>
      </div>
      {user ? (
        <div>
          <div className="muted">{getUserDisplayName(user)}</div>
          <div className="muted">
            Provider:{" "}
            {providerIcon ? <i className={`bi ${providerIcon}`} aria-hidden="true" /> : null}{" "}
            {providerLabel}
          </div>
        </div>
      ) : (
        <div className="muted">Not signed in.</div>
      )}
    </div>
  );
}

function HomePage({
  forms,
  loading,
  error,
  user,
  markdownEnabled,
  mathjaxEnabled
}: {
  forms: FormSummary[];
  loading: boolean;
  error: ApiError | null;
  user: UserInfo | null;
  markdownEnabled: boolean;
  mathjaxEnabled: boolean;
}) {
  const formsBase = useMemo(() => {
    const base = PUBLIC_BASE.endsWith("/") ? PUBLIC_BASE : `${PUBLIC_BASE}/`;
    return `${base}#/f/`;
  }, []);
  const docsUrl = `${PUBLIC_BASE}#/docs`;

  return (
    <>
      <header className="hero">
        <div>
          <p className="eyebrow">Public forms</p>
          <h1>Form App</h1>
          <p className="subhead">Browse available forms and submit securely.</p>
        </div>
        <ApiStatus loading={loading} error={error} />
      </header>

      {error ? (
        <section className="panel panel--error">
          <h2>Unable to load forms</h2>
          <p>
            Status: {error.status || "network"} {error.message ? `- ${error.message}` : ""}
          </p>
          {error.requestId ? <p className="muted">Request ID: {error.requestId}</p> : null}
        </section>
      ) : null}

      <section className="panel">
        <div className="panel-header">
          <h2>Available forms</h2>
          <span className="badge">{loading ? "Loading..." : `${forms.length} total`}</span>
        </div>
        {forms.length === 0 && !loading ? (
          <p className="muted">No public forms yet.</p>
        ) : (
          <ul className="forms">
            {forms.map((form) => (
              <li key={form.slug} className="form-card">
                <div>
                  <h3 className="mb-1">
                    <RichText
                      text={form.title}
                      markdownEnabled={markdownEnabled}
                      mathjaxEnabled={mathjaxEnabled}
                      inline
                    />
                  </h3>
                  {form.description ? (
                    <p className="muted mb-2">
                      <RichText
                        text={form.description}
                        markdownEnabled={markdownEnabled}
                        mathjaxEnabled={mathjaxEnabled}
                        inline
                      />
                    </p>
                  ) : null}
                  <p className="muted mb-2">Slug: {form.slug}</p>
                  <div className="d-flex gap-2 flex-wrap">
                    <span
                      className={`badge ${form.is_locked ? "text-bg-danger" : "text-bg-success"}`}
                      title={form.is_locked ? "Form is locked for submissions" : "Form is open for submissions"}
                    >
                      <i className={`bi ${getLockIcon(form.is_locked)}`} aria-hidden="true" />{" "}
                      {form.is_locked ? "Locked" : "Unlocked"}
                    </span>
                    <span
                      className={`badge ${form.is_public ? "text-bg-primary" : "text-bg-secondary"}`}
                      title={form.is_public ? "Visible in public list" : "Hidden from public list"}
                    >
                      <i className={`bi ${getVisibilityIcon(form.is_public)}`} aria-hidden="true" />{" "}
                      {form.is_public ? "Public" : "Private"}
                    </span>
                    <span className="badge text-bg-secondary" title="Authentication policy for submissions">
                      <i
                        className={`bi ${getAuthPolicyIcon(form.auth_policy)}`}
                        aria-hidden="true"
                      />{" "}
                      {getAuthPolicyLabel(form.auth_policy)}
                    </span>
                  </div>
                </div>
                <a className="form-link btn btn-outline-primary btn-sm" href={`${formsBase}${form.slug}`}>
                  Fill form
                </a>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="panel panel--split">
        <div>
          <div className="panel-header">
            <h2>About</h2>
          </div>
          <ul className="list-unstyled mb-0">
            <li>
              <i className="bi bi-window me-2" aria-hidden="true" />
              <strong>App:</strong> {APP_INFO.title}
            </li>
            <li>
              <i className="bi bi-person-badge me-2" aria-hidden="true" />
              <strong>Author:</strong> {APP_INFO.author}
            </li>
            <li>
              <i className="bi bi-file-earmark-text me-2" aria-hidden="true" />
              <strong>License:</strong>{" "}
              <a href={LICENSE_URL} target="_blank" rel="noreferrer">
                {APP_INFO.license}
              </a>
            </li>
            <li>
              <i className="bi bi-github me-2" aria-hidden="true" />
              <strong>Source:</strong>{" "}
              <a href={APP_INFO.repoUrl} target="_blank" rel="noreferrer">
                {APP_INFO.repoUrl}
              </a>
            </li>
            <li>
              <i className="bi bi-book me-2" aria-hidden="true" />
              <strong>Docs:</strong> <a href={docsUrl}>/forms/docs</a>
            </li>
            <li>
              <i className="bi bi-stars me-2" aria-hidden="true" />
              <strong>Assistants:</strong> GitHub Copilot, ChatGPT Codex, Google Antigravity
            </li>
          </ul>
        </div>
        <AuthStatus user={user} />
      </section>
    </>
  );
}

function AuthCallback({
  onComplete,
  onNotice
}: {
  onComplete: () => void;
  onNotice: (message: string, type?: NoticeType) => void;
}) {
  const navigate = useNavigate();
  useEffect(() => {
    const url = new URL(window.location.href);
    const hashParams = new URLSearchParams(url.hash.replace(/^#/, ""));
    const queryParams = url.searchParams;
    const token = hashParams.get("token") || queryParams.get("token");
    if (token) {
      setToken(token);
      onNotice("Logged in successfully.", "success");
    }
    const returnTo = queryParams.get("return_to") || localStorage.getItem(RETURN_TO_KEY);
    localStorage.removeItem(RETURN_TO_KEY);
    const destination = returnTo || `${PUBLIC_BASE}#/`;
    window.location.replace(destination);
    onComplete();
    navigate("/", { replace: true });
  }, [navigate, onComplete, onNotice]);

  return (
    <section className="panel">
      <h2>Signing you in...</h2>
      <p className="muted">Please wait.</p>
    </section>
  );
}

function FormPage({
  slug,
  user,
  onLogin,
  onNotice,
  markdownEnabled,
  mathjaxEnabled
}: {
  slug: string;
  user: UserInfo | null;
  onLogin: (provider: "google" | "github") => void;
  onNotice: (message: string, type?: NoticeType) => void;
  markdownEnabled: boolean;
  mathjaxEnabled: boolean;
}) {
  const [form, setForm] = useState<FormDetail | null>(null);
  const [values, setValues] = useState<Record<string, string>>({});
  const [formPassword, setFormPassword] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [loadError, setLoadError] = useState<ApiError | null>(null);
  const [submitError, setSubmitError] = useState<ApiError | null>(null);
  const [submitDebug, setSubmitDebug] = useState<string | null>(null);
  const [savedAt, setSavedAt] = useState<string | null>(null);
  const [locked, setLocked] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [selectedFiles, setSelectedFiles] = useState<Record<string, File[]>>({});
  const [fileUrls, setFileUrls] = useState<Record<string, string[]>>({});
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
  const [fileMeta, setFileMeta] = useState<Record<string, FileMeta>>({});
  const [uploadedFiles, setUploadedFiles] = useState<Record<string, UploadedFile>>({});
  const [fieldUploading, setFieldUploading] = useState<Record<string, boolean>>({});
  const [submissionId, setSubmissionId] = useState<string | null>(null);
  const [hasExistingSubmission, setHasExistingSubmission] = useState(false);
  const [fileItems, setFileItems] = useState<FileItem[]>([]);
  const [accessRequired, setAccessRequired] = useState(false);
  const [accessError, setAccessError] = useState<string | null>(null);
  const [accessing, setAccessing] = useState(false);
  const navigate = useNavigate();
  const draftKey = useMemo(() => `form-draft:${slug}`, [slug]);
  const accessCacheKey = useMemo(() => `form-access:${slug}`, [slug]);
  const ACCESS_CACHE_TTL_MS = 30 * 60 * 1000;
  const [draftPreview, setDraftPreview] = useState<{ values: Record<string, string>; updatedAt: string } | null>(
    null
  );
  const [draftVisible, setDraftVisible] = useState(false);
  const [previousSubmission, setPreviousSubmission] = useState<{ values: Record<string, string>; updatedAt: string | null } | null>(
    null
  );
  const [previousSubmissionVisible, setPreviousSubmissionVisible] = useState(false);
  const [importStatus, setImportStatus] = useState<string | null>(null);

  function getEmailDomain(field: FormField) {
    const rules = (field as any).rules || {};
    if (typeof rules.domain !== "string") return "";
    return rules.domain.trim().toLowerCase().replace(/^@/, "");
  }

  function getAutofillValue(field: FormField) {
    const rules = (field as any).rules || {};
    if (!rules.autofill || !user) return "";
    if (field.type === "email" && user.email) {
      const domain = getEmailDomain(field);
      if (!domain || user.email.toLowerCase().endsWith(`@${domain}`)) {
        return user.email;
      }
    }
    if (field.type === "github_username" && user.provider === "github" && user.username) {
      return user.username;
    }
    return "";
  }

  function ensureUrlWithScheme(rawValue: string) {
    const trimmed = rawValue.trim();
    if (!trimmed) {
      return { value: trimmed, changed: false };
    }
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed)) {
      return { value: trimmed, changed: false };
    }
    return { value: `https://${trimmed}`, changed: true };
  }

  function validateFieldValue(field: FormField, rawValue: string): string | null {
    const value = rawValue.trim();
    if (!value) return null;
    if (field.type === "email") {
      const domain = getEmailDomain(field);
      const normalized = domain && !value.includes("@") ? `${value}@${domain}` : value;
      const emailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized);
      if (!emailValid) return "Invalid email";
      if (domain && !normalized.toLowerCase().endsWith(`@${domain}`)) {
        return `Email must use @${domain}`;
      }
      return null;
    }
    if (field.type === "number") {
      const numberValid = /^-?\d+(\.\d+)?$/.test(value);
      return numberValid ? null : "Invalid number";
    }
    if (field.type === "date") {
      const rules = (field as any).rules || {};
      const mode = typeof rules.mode === "string" ? rules.mode : "datetime";
      if (mode === "time") {
        return isValidTimeString(value) ? null : "Invalid time";
      }
      if (mode === "date") {
        return isValidDateString(value) ? null : "Invalid date";
      }
      return isValidDateString(value) ? null : "Invalid date/time";
    }
    if (field.type === "full_name") {
      const hasDigits = /\d/.test(value);
      return hasDigits ? "Name cannot include digits" : null;
    }
    if (field.type === "github_username") {
      const valid = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$/.test(value);
      return valid ? null : "Invalid GitHub username";
    }
    if (field.type === "url") {
      const normalized = ensureUrlWithScheme(value).value;
      try {
        const url = new URL(normalized);
        if (url.protocol !== "http:" && url.protocol !== "https:") {
          return "URL must start with http or https";
        }
      } catch {
        return "Invalid URL";
      }
    }
    if (field.type === "select") {
      const options = Array.isArray((field as any).options) ? (field as any).options : [];
      if (options.length > 0 && !options.includes(value)) {
        return "Invalid selection";
      }
    }
    if (field.type === "checkbox") {
      const options = Array.isArray((field as any).options) ? (field as any).options : [];
      const selected = value
        .split(",")
        .map((item) => item.trim())
        .filter((item) => item.length > 0);
      if (options.length > 0 && selected.some((item) => !options.includes(item))) {
        return "Invalid selection";
      }
    }
    if (field.type === "text" || field.type === "textarea" || field.type === "url") {
      const minLength = Number((field as any).minLength || 0);
      const maxLength = Number((field as any).maxLength || 0);
      if (minLength && value.length < minLength) {
        return `Minimum ${minLength} characters`;
      }
      if (maxLength && value.length > maxLength) {
        return `Maximum ${maxLength} characters`;
      }
    }
    return null;
  }

  function buildMarkdownTemplate() {
    if (!form) return "";
    const lines: string[] = [];
    lines.push(`# ${form.title || form.slug}`);
    lines.push("");
    lines.push(`<!-- formSlug: ${form.slug} -->`);
    lines.push(`<!-- generatedAt: ${new Date().toISOString()} -->`);
    lines.push("");
    lines.push(
      "Fill values under each Value: section. Example values are placeholders and can be modified or removed."
    );
    lines.push("");
    (form.fields || [])
      .filter((field) => field.type !== "file")
      .forEach((field) => {
        lines.push(`## ${field.id}`);
        lines.push(`Label: ${field.label}`);
        lines.push(`Type: ${field.type}`);
        if (field.description) {
          lines.push(`Description: ${field.description}`);
        }
        if (Array.isArray(field.options) && field.options.length > 0) {
          lines.push(`Options: ${field.options.join(" | ")}`);
        }
        if (field.type === "checkbox" && field.multiple) {
          lines.push("Multiple: true");
        }
        lines.push("Value:");
        if (Array.isArray(field.options) && field.options.length > 0) {
          lines.push(`Example: ${field.options[0]} (edit as needed)`);
        } else {
          const example =
            typeof (field as any).placeholder === "string" && (field as any).placeholder.trim()
              ? (field as any).placeholder.trim()
              : field.type === "email"
                ? "name@example.com"
                : field.type === "url"
                  ? "https://example.com"
                  : field.type === "number"
                    ? "123"
                    : field.type === "date"
                      ? "2024-01-01"
                      : field.type === "full_name"
                        ? "Jane Doe"
                        : "Example text";
          lines.push(`Example: ${example} (edit as needed)`);
        }
        lines.push("");
      });
    return lines.join("\n");
  }

  function parseMarkdownTemplate(text: string) {
    const values: Record<string, string> = {};
    const slugMatch = text.match(/formSlug:\s*([a-zA-Z0-9_-]+)/);
    const parsedSlug = slugMatch ? slugMatch[1] : null;
    const lines = text.split(/\r?\n/);
    let currentId: string | null = null;
    let collecting = false;
    let skipExample = false;
    let buffer: string[] = [];
    const commit = () => {
      if (currentId) {
        const value = buffer.join("\n").replace(/\s+$/, "");
        values[currentId] = value;
      }
      buffer = [];
      collecting = false;
      skipExample = false;
    };
    for (const line of lines) {
      const headingMatch = line.match(/^##\s+(.+)$/);
      if (headingMatch) {
        commit();
        currentId = headingMatch[1].trim();
        continue;
      }
      if (!currentId) {
        continue;
      }
      if (line.startsWith("Value:")) {
        collecting = true;
        const remainder = line.slice("Value:".length).trim();
        if (remainder) {
          buffer.push(remainder);
        }
        continue;
      }
      if (collecting && line.startsWith("Example:")) {
        skipExample = true;
        continue;
      }
      if (collecting) {
        if (skipExample && !line.trim()) {
          skipExample = false;
          continue;
        }
        buffer.push(line);
      }
    }
    commit();
    return { slug: parsedSlug, values };
  }

  function normalizeImportedValue(field: FormField, rawValue: string) {
    const trimmed = rawValue.trim();
    if (!trimmed) return "";
    if (field.type === "checkbox" && field.multiple) {
      const parts = trimmed
        .split(/[\n,]+/)
        .map((part) => part.trim())
        .filter(Boolean);
      return parts.join(", ");
    }
    const firstLine = trimmed.split(/\r?\n/).find((line) => line.trim());
    return firstLine ? firstLine.trim() : trimmed;
  }

  function normalizeJsonValue(field: FormField, rawValue: unknown) {
    if (rawValue == null) return "";
    if (Array.isArray(rawValue)) {
      if (field.type === "checkbox") {
        return rawValue.map((item) => String(item).trim()).filter(Boolean).join(", ");
      }
      return rawValue.map((item) => String(item).trim()).filter(Boolean).join("\n");
    }
    if (typeof rawValue === "object") {
      return JSON.stringify(rawValue);
    }
    return String(rawValue);
  }

  function applyImportedValues(
    nextValues: Record<string, string>,
    unknownFields: string[],
    sourceLabel: string
  ) {
    setValues((prev) => ({ ...prev, ...nextValues }));
    Object.entries(nextValues).forEach(([fieldId, value]) => {
      const field = form?.fields.find((item) => item.id === fieldId);
      if (!field) return;
      updateFieldError(field, value);
    });
    setImportStatus(
      unknownFields.length > 0
        ? `Imported values from ${sourceLabel}. Unknown fields ignored: ${unknownFields.join(", ")}.`
        : `Imported values from ${sourceLabel}.`
    );
  }

  function buildJsonPayload() {
    if (!form) return null;
    const fields = (form.fields || [])
      .filter((field) => field.type !== "file")
      .map((field) => ({
        id: field.id,
        label: field.label,
        type: field.type
      }));
    const valuesPayload: Record<string, string> = {};
    fields.forEach((field) => {
      const raw = values[field.id];
      if (raw !== undefined && String(raw).trim()) {
        valuesPayload[field.id] = raw;
        return;
      }
      const example =
        typeof (field as any).placeholder === "string" && (field as any).placeholder.trim()
          ? (field as any).placeholder.trim()
          : field.type === "email"
            ? "name@example.com"
            : field.type === "url"
              ? "https://example.com"
              : field.type === "number"
                ? "123"
                : field.type === "date"
                  ? "2024-01-01"
                  : field.type === "full_name"
                    ? "Jane Doe"
                    : Array.isArray((field as any).options) && (field as any).options.length > 0
                      ? String((field as any).options[0])
                      : "Example text";
      valuesPayload[field.id] = example;
    });
    return {
      formSlug: form.slug,
      generatedAt: new Date().toISOString(),
      note: "Example values below are placeholders and can be modified or removed.",
      fields,
      values: valuesPayload
    };
  }

  async function handleImportFile(event: React.ChangeEvent<HTMLInputElement>) {
    setImportStatus(null);
    const file = event.target.files?.[0];
    if (!file || !form) return;
    try {
      const text = await file.text();
      const trimmed = text.trim();
      let parsedJson: any = null;
      if (trimmed) {
        try {
          parsedJson = JSON.parse(trimmed);
        } catch {
          parsedJson = null;
        }
      }
      if (parsedJson) {
        const valuesPayload =
          parsedJson && typeof parsedJson === "object" && !Array.isArray(parsedJson) && parsedJson.values
            ? parsedJson.values
            : parsedJson;
        if (!valuesPayload || typeof valuesPayload !== "object" || Array.isArray(valuesPayload)) {
          setImportStatus("JSON must be an object of field values.");
          return;
        }
        if (
          parsedJson &&
          typeof parsedJson === "object" &&
          parsedJson.formSlug &&
          parsedJson.formSlug !== form.slug
        ) {
          onNotice("JSON payload is for a different form.", "warning");
        }
        const nextValues: Record<string, string> = {};
        const unknownFields: string[] = [];
        for (const [fieldId, value] of Object.entries(valuesPayload)) {
          const field = form.fields.find((item) => item.id === fieldId);
          if (!field) {
            unknownFields.push(fieldId);
            continue;
          }
          const normalized = normalizeJsonValue(field, value);
          nextValues[fieldId] = normalizeImportedValue(field, normalized);
        }
        applyImportedValues(nextValues, unknownFields, "JSON");
        return;
      }
      const parsed = parseMarkdownTemplate(text);
      if (parsed.slug && parsed.slug !== form.slug) {
        onNotice("Markdown template is for a different form.", "warning");
      }
      const nextValues: Record<string, string> = {};
      const unknownFields: string[] = [];
      for (const [fieldId, value] of Object.entries(parsed.values)) {
        const field = form.fields.find((item) => item.id === fieldId);
        if (!field) {
          unknownFields.push(fieldId);
          continue;
        }
        nextValues[fieldId] = normalizeImportedValue(field, value);
      }
      applyImportedValues(nextValues, unknownFields, "markdown");
    } catch (error) {
      setImportStatus("Failed to import file.");
    } finally {
      event.target.value = "";
    }
  }

  function handleDownloadMarkdown() {
    const template = buildMarkdownTemplate();
    if (!template || !form) return;
    const blob = new Blob([template], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${form.slug}-template.md`;
    link.click();
    URL.revokeObjectURL(url);
  }

  function handleDownloadJson() {
    const payload = buildJsonPayload();
    if (!payload || !form) return;
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${form.slug}-values.json`;
    link.click();
    URL.revokeObjectURL(url);
  }

  function updateFieldError(field: FormField, rawValue: string) {
    const trimmed = rawValue.trim();
    const message = field.required && !trimmed ? "Required" : validateFieldValue(field, rawValue);
    setFieldErrors((prev) => {
      const next = { ...prev };
      if (message) {
        next[field.id] = message;
      } else {
        delete next[field.id];
      }
      return next;
    });
  }

  async function checkGithubUsername(field: FormField, rawValue: string) {
    const rules = (field as any).rules || {};
    const allowAutofill = Boolean(rules.autofill);
    if (allowAutofill) return;
    const value = rawValue.trim();
    if (!value) return;
    if (!/^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$/.test(value)) {
      return;
    }
    try {
      const response = await fetch(`https://api.github.com/users/${encodeURIComponent(value)}`, {
        headers: { "user-agent": "form-app" }
      });
      setFieldErrors((prev) => {
        const next = { ...prev };
        if (response.status === 404) {
          next[field.id] = "GitHub username not found.";
        } else if (!response.ok) {
          next[field.id] = "Unable to verify GitHub username right now.";
        } else {
          delete next[field.id];
        }
        return next;
      });
    } catch (error) {
      setFieldErrors((prev) => ({ ...prev, [field.id]: "Unable to verify GitHub username right now." }));
    }
  }

  useEffect(() => {
    let active = true;

    async function loadForm() {
      setLoading(true);
      setLoadError(null);
      setSubmitError(null);
      setSubmitDebug(null);
      setSelectedFiles({});
      setFormPassword("");
      Object.values(fileUrls)
        .flat()
        .forEach((url) => URL.revokeObjectURL(url));
      setFileUrls({});
      setUploadError(null);
      setFieldErrors({});
      setFileMeta({});
      setUploadedFiles({});
      setFieldUploading({});
      setSubmissionId(null);
      setHasExistingSubmission(false);
      setFileItems([]);
      try {
        const response = await apiFetch(`${API_BASE}/api/forms/${slug}`);
        const text = await response.text();
        let payload: any = null;
        try {
          payload = JSON.parse(text);
        } catch {
          payload = null;
        }

        if (!response.ok) {
          if (
            response.status === 403 &&
            payload?.error === "invalid_payload" &&
            payload?.detail?.field === "formPassword"
          ) {
            let cachedPassword = "";
            try {
              const cachedRaw = localStorage.getItem(accessCacheKey);
              if (cachedRaw) {
                const cached = JSON.parse(cachedRaw) as { password?: string; expiresAt?: number };
                if (cached?.password && cached?.expiresAt && cached.expiresAt > Date.now()) {
                  cachedPassword = String(cached.password);
                } else {
                  localStorage.removeItem(accessCacheKey);
                }
              }
            } catch {
              // ignore cache read failures
            }
            if (cachedPassword) {
              const accessResponse = await apiFetch(
                `${API_BASE}/api/forms/${encodeURIComponent(slug)}/access`,
                {
                  method: "POST",
                  headers: { "content-type": "application/json" },
                  body: JSON.stringify({ formPassword: cachedPassword })
                }
              );
              const accessPayload = await accessResponse.json().catch(() => null);
              if (!active) return;
              if (accessResponse.ok) {
                setForm(accessPayload?.data || null);
                setAccessRequired(false);
                setAccessError(null);
                setFormPassword(cachedPassword);
                setLocked(
                  Boolean(accessPayload?.data?.is_locked) || accessPayload?.data?.is_open === false
                );
                setLoading(false);
                return;
              }
              try {
                localStorage.removeItem(accessCacheKey);
              } catch {
                // ignore cache removal failures
              }
            }
            if (!active) return;
            setAccessRequired(true);
            setAccessError("Form password is required to access this form.");
            setLoading(false);
            return;
          }
          if (!active) return;
          setLoadError({
            status: response.status,
            requestId: payload?.requestId ?? undefined,
            message: payload?.error ?? "Request failed"
          });
          setLoading(false);
          return;
        }

        const data = payload?.data;
        if (!active) return;
        setForm(data);
        setAccessRequired(false);
        setAccessError(null);
        setLocked(Boolean(data?.is_locked) || data?.is_open === false);
        setLoading(false);
      } catch (err) {
        if (!active) return;
        setLoadError({
          status: 0,
          message: err instanceof Error ? err.message : "Network error"
        });
        setLoading(false);
      }
    }

    loadForm();
    return () => {
      active = false;
    };
  }, [slug]);

  useEffect(() => {
    if (!form) return;

    let active = true;
    async function loadFilesForSubmission(id: string) {
      const response = await apiFetch(
        `${API_BASE}/api/forms/${form?.slug || ""}/files?submissionId=${encodeURIComponent(id)}`
      );
      const payload = await response.json().catch(() => null);
      if (!active) return;
      if (response.ok && Array.isArray(payload?.data)) {
        setFileItems(payload.data);
      }
    }

    async function loadSubmission() {
      if (!user) {
        return;
      }
      const response = await apiFetch(
        `${API_BASE}/api/forms/${encodeURIComponent(form?.slug || "")}/my-submission`
      );
      const text = await response.text();
      let payload: any = null;
      try {
        payload = JSON.parse(text);
      } catch {
        payload = null;
      }
      if (!active) return;
      if (response.ok && payload?.data) {
        const resolvedId = payload.data.submissionId || payload.data.id || null;
        const submissionData = payload.data.data_json ?? payload.data.data ?? null;
        if (submissionData && typeof submissionData === "object") {
          const nextValues: Record<string, string> = { ...(submissionData as Record<string, string>) };
          (form?.fields || [])
            .filter((field) => field.type === "date")
            .forEach((field) => {
              const raw = (submissionData as Record<string, unknown>)[field.id];
              if (typeof raw !== "string") return;
              const tzKey = `${field.id}__tz`;
              const rules = (field as any).rules || {};
              const mode = typeof rules.mode === "string" ? rules.mode : "datetime";
              const tzRaw = (submissionData as Record<string, unknown>)[tzKey];
              const tz =
                (typeof tzRaw === "string" && tzRaw.trim()) ||
                (typeof rules.timezoneDefault === "string" ? String(rules.timezoneDefault) : "") ||
                getAppDefaultTimezone();
              nextValues[tzKey] = tz;
              if (raw.endsWith("Z")) {
                const local =
                  mode === "time"
                    ? utcToLocalTimeOnly(raw, tz)
                    : mode === "date"
                      ? utcToLocalDateOnly(raw, tz)
                      : utcToLocalDateTime(raw, tz);
                if (local) {
                  nextValues[field.id] = local;
                }
              }
            });
          setPreviousSubmission({
            values: nextValues,
            updatedAt: payload.data.updated_at || payload.data.created_at || null
          });
          setPreviousSubmissionVisible(true);
        }
        setSavedAt(payload.data.updated_at || payload.data.created_at || null);
        if (resolvedId) {
          setSubmissionId(resolvedId);
          setHasExistingSubmission(true);
          loadFilesForSubmission(resolvedId);
        }
      }
    }

    loadSubmission();
    return () => {
      active = false;
    };
  }, [form, user]);

  async function handleVersionChange(version: string) {
    if (!submissionId || !form) return;
    if (version === "none") {
      setValues({});
      setPreviousSubmissionVisible(false);
      return;
    }
    if (version === "latest") {
      // Reload current
      const response = await apiFetch(`${API_BASE}/api/forms/${encodeURIComponent(form.slug)}/my-submission`);
      const payload = await response.json().catch(() => null);
      if (response.ok && payload?.data?.data) {
        setValues(payload.data.data);
        setPreviousSubmissionVisible(false);
      }
      return;
    }
    // Load specific version
    const response = await apiFetch(`${API_BASE}/api/me/submissions/${encodeURIComponent(submissionId)}/versions/${encodeURIComponent(version)}`);
    const payload = await response.json().catch(() => null);
    const versionData = payload?.data ?? payload?.version?.data ?? null;
    if (response.ok) {
      if (versionData && typeof versionData === "object") {
        setValues(versionData);
      } else {
        setValues({});
      }
      setPreviousSubmissionVisible(false); // Hide the "previous submission available" banner since we explicitly loaded one
    } else {
      onNotice("Failed to load version.", "error");
    }
  }

  useEffect(() => {
    if (!form) return;
    if (hasExistingSubmission) return;
    const raw = localStorage.getItem(draftKey);
    if (!raw) {
      setDraftPreview(null);
      setDraftVisible(false);
      return;
    }
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === "object" && parsed.values && typeof parsed.values === "object") {
        setDraftPreview({
          values: parsed.values as Record<string, string>,
          updatedAt: typeof parsed.updatedAt === "string" ? parsed.updatedAt : ""
        });
        setDraftVisible(true);
      }
    } catch {
      setDraftPreview(null);
      setDraftVisible(false);
    }
  }, [form, hasExistingSubmission, draftKey]);

  useEffect(() => {
    if (!form) return;
    if (hasExistingSubmission) return;
    const timer = window.setTimeout(() => {
      const nonEmpty = Object.entries(values).some(([, val]) => String(val || "").trim().length > 0);
      if (!nonEmpty) {
        localStorage.removeItem(draftKey);
        return;
      }
      const payload = {
        values,
        updatedAt: new Date().toISOString()
      };
      localStorage.setItem(draftKey, JSON.stringify(payload));
    }, 400);
    return () => window.clearTimeout(timer);
  }, [values, form, draftKey, hasExistingSubmission]);

  useEffect(() => {
    if (!form || !user) return;
    const nextValues: Record<string, string> = {};
    let changed = false;
    form.fields.forEach((field) => {
      const autofillValue = getAutofillValue(field);
      if (!autofillValue) return;
      if ((values[field.id] || "").trim()) return;
      nextValues[field.id] = autofillValue;
      changed = true;
    });
    if (changed) {
      setValues((prev) => ({ ...prev, ...nextValues }));
    }
  }, [form, user, values]);

  useEffect(() => {
    if (!form) return;
    const nextValues: Record<string, string> = {};
    let changed = false;
    form.fields
      .filter((field) => field.type === "date")
      .forEach((field) => {
        const tzKey = `${field.id}__tz`;
        if ((values[tzKey] || "").trim()) return;
        const rules = (field as any).rules || {};
        const tz =
          (typeof rules.timezoneDefault === "string" ? String(rules.timezoneDefault) : "") ||
          getAppDefaultTimezone();
        nextValues[tzKey] = tz;
        changed = true;
      });
    if (changed) {
      setValues((prev) => ({ ...prev, ...nextValues }));
    }
  }, [form, values]);

  const canvasSections = Array.isArray(form?.canvas_allowed_sections) ? form?.canvas_allowed_sections : [];
  const singleCanvasSection = canvasSections.length === 1 ? canvasSections[0] : null;

  useEffect(() => {
    if (!form?.canvas_enabled) return;
    if (!singleCanvasSection) return;
    if ((values._canvas_section_id || "").trim()) return;
    setValues((prev) => ({ ...prev, _canvas_section_id: String(singleCanvasSection.id) }));
  }, [form?.canvas_enabled, singleCanvasSection, values._canvas_section_id]);

  useEffect(() => {
    if (!form || !submissionId) return;
    const pending = fileItems.filter((item) => item.vt_status === "pending");
    if (pending.length === 0) return;
    const timer = window.setInterval(() => {
      pending.forEach((item) => {
        handleCheckFile(item.id);
      });
    }, 4000);
    return () => window.clearInterval(timer);
  }, [fileItems, form, submissionId]);

  const requiresAuth = form && form.auth_policy !== "optional";
  const canSubmit = form && (!requiresAuth || Boolean(user));
  const authPolicy = form?.auth_policy || "optional";
  const allowGoogleAuth =
    authPolicy === "required" || authPolicy === "either" || authPolicy === "google";
  const allowGithubAuth =
    authPolicy === "required" || authPolicy === "either" || authPolicy === "github";
  const isAuthorized =
    authPolicy === "optional" ||
    (authPolicy === "required" && Boolean(user)) ||
    (authPolicy === "either" && Boolean(user)) ||
    (authPolicy === "google" && user?.provider === "google") ||
    (authPolicy === "github" && user?.provider === "github");
  const fileRules = useMemo(
    () => parseFileRules(form?.file_rules_json ?? null),
    [form?.file_rules_json]
  );
  const visibilityMap = useMemo(
    () => buildVisibilityMap(form?.fields || [], values),
    [form?.fields, values]
  );
  const requiresAccessPassword = Boolean(form?.password_require_access);
  const requiresSubmitPassword =
    Boolean(form?.password_require_submit) ||
    (!form?.password_require_access &&
      !form?.password_require_submit &&
      Boolean(form?.password_required));
  const hasPassword = !requiresSubmitPassword || formPassword.trim().length > 0;
  const isOpen = form?.is_open !== false;
  const existingFilesByField = useMemo(() => {
    const map: Record<string, FileItem[]> = {};
    fileItems.forEach((item) => {
      if (!map[item.field_id]) {
        map[item.field_id] = [];
      }
      map[item.field_id].push(item);
    });
    return map;
  }, [fileItems]);
  const isAnyUploading = Object.values(fieldUploading).some(Boolean);
  const submitLabel = "Submit";
  const completionCheck = useMemo(() => {
    if (!form) {
      return { complete: false, reason: "" };
    }
    for (const field of form.fields) {
      if (visibilityMap[field.id] === false) {
        continue;
      }
      if (field.type === "file") {
        const files = selectedFiles[field.id] || [];
        const existing = existingFilesByField[field.id] || [];
        if (field.required && files.length === 0 && existing.length === 0) {
          return { complete: false, reason: `Missing required file: ${field.label || field.id}` };
        }
        continue;
      }
      const raw = values[field.id] || "";
      const autofillValue = getAutofillValue(field);
      const value = (raw.trim() || autofillValue).trim();
      if (field.required && !value) {
        return { complete: false, reason: `Missing required field: ${field.label || field.id}` };
      }
      if (value) {
        const message = validateFieldValue(field, value);
        if (message) {
          return {
            complete: false,
            reason: `Invalid ${field.label || field.id}: ${message}`
          };
        }
      }
    }
    if (!hasPassword) {
      return { complete: false, reason: "Enter the form password." };
    }
    return { complete: true, reason: "" };
  }, [form, values, selectedFiles, existingFilesByField, hasPassword, user, visibilityMap]);
  const isFormComplete = completionCheck.complete;
  const submitDisabledReason = !canSubmit
    ? "Please sign in to submit."
    : !isOpen
      ? "Form is closed."
      : locked
        ? "Form is locked."
        : isAnyUploading
          ? "Files are uploading."
          : !isFormComplete
            ? completionCheck.reason || "Complete required fields and select required files."
            : "";
  const canvasFieldsPosition = form?.canvas_fields_position || "bottom";
  const canvasCourseTitle =
    form?.canvas_enabled && form?.canvas_course_name ? form.canvas_course_name : null;
  const canvasCourseField = canvasCourseTitle ? (
    <div key="canvas-course" className="field">
      <span>Canvas Course</span>
      <div className="field-value">{canvasCourseTitle}</div>
    </div>
  ) : null;
  const passwordField = requiresSubmitPassword ? (
    <label key="form-password" className="field">
      <span>Form password *</span>
      <input
        type="password"
        value={formPassword}
        disabled={locked || !canSubmit}
        onChange={(event) => setFormPassword(event.target.value)}
        placeholder="Enter form password"
      />
      <span className="field-help">Required to submit this form.</span>
      {fieldErrors.formPassword ? (
        <span className="field-error">{fieldErrors.formPassword}</span>
      ) : null}
    </label>
  ) : null;
  const canvasSectionField =
    form?.canvas_enabled && canvasSections.length > 0 ? (
      singleCanvasSection ? (
        <div key="canvas-section" className="field">
          <span>Canvas Section</span>
          <div className="field-value">{singleCanvasSection.name}</div>
          <span className="field-help">Assigned automatically.</span>
        </div>
      ) : (
        <label key="canvas-section" className="field">
          <span>Canvas Section *</span>
          <select
            value={values._canvas_section_id || ""}
            disabled={locked || !canSubmit}
            onChange={(event) =>
              setValues((prev) => ({ ...prev, _canvas_section_id: event.target.value }))
            }
          >
            <option value="">Select a section</option>
            {canvasSections.map((section) => (
              <option key={section.id} value={section.id}>
                {section.name}
              </option>
            ))}
          </select>
          <span className="field-help">Select one section to enroll.</span>
        </label>
      )
    ) : null;
  const canvasNodes = [canvasCourseField, canvasSectionField, passwordField].filter(
    Boolean
  ) as React.ReactNode[];
  const renderFieldLabel = (field: FormField) => {
    const labelText = String(field.label || field.id || "");
    return (
      <>
        <span className="field-label">
          <RichText
            text={labelText}
            markdownEnabled={markdownEnabled}
            mathjaxEnabled={mathjaxEnabled}
            inline
          />
          {field.required ? " *" : ""}
        </span>
        {field.description ? (
          <span className="field-help">
            <RichText
              text={String(field.description)}
              markdownEnabled={markdownEnabled}
              mathjaxEnabled={mathjaxEnabled}
            />
          </span>
        ) : null}
      </>
    );
  };
  const fieldNodes = (form?.fields || []).map((field) => {
    if (visibilityMap[field.id] === false) {
      return null;
    }
    if (field.type === "file") {
      const rules = getFieldRule(fileRules, field.id);
      const files = selectedFiles[field.id] || [];
      const isFieldUploading = Boolean(fieldUploading[field.id]);
      const existing = existingFilesByField[field.id] || [];
      const reachedMax = rules.maxFiles > 0 && existing.length >= rules.maxFiles;
      const hasPendingSelected = files.some((file) => {
        const meta = fileMeta[buildFileIdentity(field.id, file)];
        return !meta || meta.status !== "uploaded";
      });
      return (
        <label key={field.id} className="field">
          {renderFieldLabel(field)}
          <input
            type="file"
            multiple={Boolean(rules.maxFiles ? rules.maxFiles > 1 : true)}
            required={Boolean(field.required && existing.length === 0)}
            disabled={locked || !canSubmit || uploading || reachedMax}
            onChange={(event) => handleFileChange(field.id, event.target.files)}
            accept={
              rules.extensions.length ? rules.extensions.map((ext) => `.${ext}`).join(",") : undefined
            }
          />
          <span className="field-help">
            {rules.extensions.length > 0 ? `Allowed: ${rules.extensions.join(", ")}` : "All file types"}
            {" - "}Max size {formatSize(rules.maxBytes)}
            {" - "}Max files {rules.maxFiles} (existing files {existing.length})
            {field.required ? " - Required" : ""}
          </span>
          <div className="upload-actions">
            <button
              type="button"
              className="btn btn-outline-success btn-sm"
              disabled={
                locked ||
                !canSubmit ||
                isFieldUploading ||
                files.length === 0 ||
                (requiresSubmitPassword && !formPassword.trim())
              }
              onClick={() => handleUploadField(field.id)}
            >
              <i className="bi bi-cloud-upload" aria-hidden="true" />{" "}
              {isFieldUploading ? "Uploading..." : "Upload selected files"}
            </button>
            <span className="badge text-bg-light">
              <i className="bi bi-paperclip" aria-hidden="true" />{" "}
              {files.length === 0 ? "No files selected" : `Selected ${files.length}`}
            </span>
            {existing.length > 0 ? (
              <span className="badge text-bg-secondary">
                <i className="bi bi-inbox" aria-hidden="true" /> Existing {existing.length}
              </span>
            ) : null}
          </div>
          {uploadError ? (
            <div className="alert alert-warning mt-2" role="alert">
              {uploadError}
            </div>
          ) : null}
          {files.length > 0 && hasPendingSelected ? (
            <div className="upload-list mt-2">
              <div className="upload-title">Files selected</div>
              <ul>
                {files.map((file, index) => {
                  const url = fileUrls[field.id]?.[index] || "";
                  const key = buildFileIdentity(field.id, file);
                  const meta = fileMeta[key] || { status: "pending", progress: 0 };
                  const statusText = meta.status;
                  return (
                    <li key={`${field.id}-${file.name}-${index}`}>
                      <div className="upload-item">
                        <div className="upload-name">{file.name}</div>
                        <div className="upload-meta">
                          {formatSize(file.size)} - {file.type || "unknown type"}
                        </div>
                        <div className={`upload-status upload-status--${statusText}`}>
                          <i
                            className={`bi ${getUploadStatusIcon(statusText)}`}
                            aria-hidden="true"
                          />{" "}
                          Status: {statusText} - {meta.progress}%
                        </div>
                        {url && meta.status === "uploaded" ? (
                          <div className="upload-link">
                            <span className="upload-url">{url}</span>
                          </div>
                        ) : null}
                      </div>
                    </li>
                  );
                })}
              </ul>
            </div>
          ) : null}
          {existing.length > 0 ? (
            <div className="upload-list mt-2">
              <div className="upload-title d-flex align-items-center justify-content-between">
                <span>Uploaded files</span>
                {!locked ? (
                  <button
                    type="button"
                    className="btn btn-outline-danger btn-sm"
                    onClick={() => handleRemoveAllFiles(field.id, existing)}
                  >
                    <i className="bi bi-trash" aria-hidden="true" /> Remove all
                  </button>
                ) : null}
              </div>
              <ul>
                {existing.map((item) => (
                  <li key={item.id}>
                    <div className="upload-item">
                      <div className="upload-name">{item.original_name}</div>
                      <div className="upload-meta">{formatSize(item.size_bytes)}</div>
                      <div className="upload-meta">
                        <i
                          className={`bi ${getVtStatusIcon(item.vt_status || "pending")}`}
                          aria-hidden="true"
                        />{" "}
                        VirusTotal: {item.vt_status || "pending"}{" "}
                        {item.vt_verdict ? `(${item.vt_verdict})` : ""}
                      </div>
                      <div className="upload-actions">
                        <button
                          type="button"
                          className="btn btn-outline-secondary btn-sm"
                          onClick={() => handleCheckFile(item.id)}
                        >
                          <i className="bi bi-arrow-repeat" aria-hidden="true" /> Check status
                        </button>
                        {!locked ? (
                          <button
                            type="button"
                            className="btn btn-outline-danger btn-sm"
                            onClick={() => handleRemoveFile(item.id)}
                          >
                            <i className="bi bi-trash" aria-hidden="true" /> Remove
                          </button>
                        ) : null}
                        {!locked ? (
                          <label className="btn btn-outline-primary btn-sm mb-0">
                            <i className="bi bi-arrow-left-right" aria-hidden="true" /> Replace
                            <input
                              type="file"
                              hidden
                              accept={
                                rules.extensions.length
                                  ? rules.extensions.map((ext) => `.${ext}`).join(",")
                                  : undefined
                              }
                              onChange={(event) =>
                                (() => {
                                  const file = event.target.files?.[0] || null;
                                  event.currentTarget.value = "";
                                  handleReplaceFile(field.id, item.id, file);
                                })()
                              }
                            />
                          </label>
                        ) : null}
                        {item.finalized_at ? (
                          <span className="badge text-bg-success">
                            <i className="bi bi-cloud-check" aria-hidden="true" /> Finalized
                          </span>
                        ) : null}
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </label>
      );
    }

    if (field.type === "email" || field.type === "github_username") {
      const autofillValue = getAutofillValue(field);
      const isAutofilled = Boolean(autofillValue);
      const inputValue = values[field.id] || autofillValue || "";
      const placeholder =
        typeof (field as any).placeholder === "string" && (field as any).placeholder.trim()
          ? String((field as any).placeholder)
          : field.label;
      const activePlaceholder = inputValue ? "" : placeholder;
      const domain = field.type === "email" ? getEmailDomain(field) : "";
      return (
        <label key={field.id} className="field">
          {renderFieldLabel(field)}
          <input
            type="text"
            className="form-control"
            value={inputValue}
            disabled={locked || !canSubmit || isAutofilled}
            placeholder={activePlaceholder}
            onChange={(event) => setValues((prev) => ({ ...prev, [field.id]: event.target.value }))}
            onBlur={(event) => {
              updateFieldError(field, event.target.value);
              if (field.type === "github_username") {
                void checkGithubUsername(field, event.target.value);
              }
            }}
          />
          {field.type === "email" && domain ? (
            <span className="field-help">Email must end with @{domain}.</span>
          ) : null}
          {fieldErrors[field.id] ? (
            <span className="field-error">{fieldErrors[field.id]}</span>
          ) : null}
        </label>
      );
    }

    if (field.type === "full_name") {
      const autofillValue = getAutofillValue(field);
      const isAutofilled = Boolean(autofillValue);
      const inputValue = values[field.id] || autofillValue || "";
      const placeholder =
        typeof (field as any).placeholder === "string" && (field as any).placeholder.trim()
          ? String((field as any).placeholder)
          : field.label;
      const activePlaceholder = inputValue ? "" : placeholder;
      return (
        <label key={field.id} className="field">
          {renderFieldLabel(field)}
          <input
            type="text"
            className="form-control"
            value={inputValue}
            disabled={locked || !canSubmit || isAutofilled}
            placeholder={activePlaceholder}
            onChange={(event) => setValues((prev) => ({ ...prev, [field.id]: event.target.value }))}
          />
        </label>
      );
    }

    if (field.type === "textarea") {
      const rules = (field as any).rules || {};
      const markdownActive = markdownEnabled && Boolean(rules.markdownEnabled);
      const mathjaxActive = mathjaxEnabled && Boolean(rules.mathjaxEnabled);
      const showRichNotice = markdownActive || mathjaxActive;
      const placeholder =
        typeof (field as any).placeholder === "string" && (field as any).placeholder.trim()
          ? String((field as any).placeholder)
          : field.label;
      const value = values[field.id] || "";
      const activePlaceholder = value ? "" : placeholder;
      const placeholderLines = placeholder ? placeholder.split(/\r?\n/).length : 0;
      const fixedRows =
        typeof (rules as any).rows === "number" && Number.isFinite((rules as any).rows)
          ? Math.max(1, Math.round((rules as any).rows))
          : null;
      const textareaRows = fixedRows ?? Math.max(3, placeholderLines || 3);
      return (
        <label key={field.id} className="field">
          {renderFieldLabel(field)}
          <textarea
            className="form-control"
            value={value}
            disabled={locked || !canSubmit}
            placeholder={activePlaceholder}
            rows={textareaRows}
            onChange={(event) => setValues((prev) => ({ ...prev, [field.id]: event.target.value }))}
          />
          {showRichNotice ? (
            <span className="field-help">
              {markdownActive
                ? `Markdown + HTML${mathjaxActive ? " + MathJax" : ""} input is supported.`
                : "MathJax input is supported."}
            </span>
          ) : null}
          {showRichNotice && value.trim() ? (
            <div className="field-preview">
              <RichText
                text={value}
                markdownEnabled={markdownActive}
                mathjaxEnabled={mathjaxActive}
              />
            </div>
          ) : null}
        </label>
      );
    }

    if (field.type === "url") {
      const placeholder =
        typeof (field as any).placeholder === "string" && (field as any).placeholder.trim()
          ? String((field as any).placeholder)
          : field.label;
      const activePlaceholder = values[field.id] ? "" : placeholder;
      return (
        <label key={field.id} className="field">
          {renderFieldLabel(field)}
          <input
            type="url"
            className="form-control"
            value={values[field.id] || ""}
            disabled={locked || !canSubmit}
            placeholder={activePlaceholder}
            onChange={(event) => setValues((prev) => ({ ...prev, [field.id]: event.target.value }))}
            onBlur={(event) => {
              const next = ensureUrlWithScheme(event.target.value);
              if (next.changed) {
                setValues((prev) => ({ ...prev, [field.id]: next.value }));
              }
              updateFieldError(field, next.value);
            }}
          />
          {fieldErrors[field.id] ? (
            <span className="field-error">{fieldErrors[field.id]}</span>
          ) : null}
        </label>
      );
    }

    if (field.type === "date") {
      const rules = (field as any).rules || {};
      const mode = typeof rules.mode === "string" ? rules.mode : "datetime";
      const inputType = mode === "date" ? "date" : mode === "time" ? "time" : "datetime-local";
      const showTimezone = !(rules.timezoneOptional === true);
      const tzKey = `${field.id}__tz`;
      const selectedTz =
        (values[tzKey] || "").trim() ||
        (typeof rules.timezoneDefault === "string" ? String(rules.timezoneDefault) : "") ||
        getAppDefaultTimezone();
      const placeholder =
        typeof (field as any).placeholder === "string" && (field as any).placeholder.trim()
          ? String((field as any).placeholder)
          : field.label;
      const activePlaceholder = values[field.id] ? "" : placeholder;
      return (
        <label key={field.id} className="field">
          {renderFieldLabel(field)}
          <input
            type={inputType}
            className="form-control"
            value={values[field.id] || ""}
            disabled={locked || !canSubmit}
            placeholder={activePlaceholder}
            onChange={(event) => setValues((prev) => ({ ...prev, [field.id]: event.target.value }))}
            onBlur={(event) => updateFieldError(field, event.target.value)}
          />
          {showTimezone ? (
            <TimezoneSelect
              idPrefix={`${field.id}-tz`}
              value={selectedTz}
              onChange={(next) => setValues((prev) => ({ ...prev, [tzKey]: next }))}
              disabled={locked || !canSubmit}
            />
          ) : null}
          {fieldErrors[field.id] ? (
            <span className="field-error">{fieldErrors[field.id]}</span>
          ) : null}
        </label>
      );
    }

    if (field.type === "number") {
      const placeholder =
        typeof (field as any).placeholder === "string" && (field as any).placeholder.trim()
          ? String((field as any).placeholder)
          : field.label;
      const activePlaceholder = values[field.id] ? "" : placeholder;
      return (
        <label key={field.id} className="field">
          {renderFieldLabel(field)}
          <input
            type="number"
            className="form-control"
            value={values[field.id] || ""}
            disabled={locked || !canSubmit}
            placeholder={activePlaceholder}
            onChange={(event) => setValues((prev) => ({ ...prev, [field.id]: event.target.value }))}
          />
        </label>
      );
    }

    if (field.type === "select") {
      const options = Array.isArray((field as any).options) ? (field as any).options : [];
      return (
        <label key={field.id} className="field">
          {renderFieldLabel(field)}
          <select
            className="form-select"
            value={values[field.id] || ""}
            disabled={locked || !canSubmit}
            onChange={(event) => setValues((prev) => ({ ...prev, [field.id]: event.target.value }))}
          >
            <option value="" disabled>
              Select an option
            </option>
            {options.map((option: string) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </label>
      );
    }

    if (field.type === "checkbox") {
      const options = Array.isArray((field as any).options) ? (field as any).options : [];
      const isMultiple = Boolean((field as any).multiple);
      return (
        <label key={field.id} className="field">
          {renderFieldLabel(field)}
          <div className="checkbox-group">
            {options.map((option: string) => {
              const value = values[field.id] || "";
              const selected = isMultiple
                ? value.split(",").map((item) => item.trim()).includes(option)
                : value === option;
              return (
                <label key={`${field.id}-${option}`} className="checkbox-option">
                  <input
                    type="checkbox"
                    disabled={locked || !canSubmit}
                    checked={selected}
                    onChange={(event) => {
                      if (!isMultiple) {
                        setValues((prev) => ({ ...prev, [field.id]: event.target.checked ? option : "" }));
                        return;
                      }
                      const parts = value ? value.split(",").map((item) => item.trim()) : [];
                      const next = new Set(parts);
                      if (event.target.checked) {
                        next.add(option);
                      } else {
                        next.delete(option);
                      }
                      setValues((prev) => ({ ...prev, [field.id]: Array.from(next).join(", ") }));
                    }}
                  />
                  <span className="ms-2">{option}</span>
                </label>
              );
            })}
          </div>
        </label>
      );
    }

    const placeholder =
      typeof (field as any).placeholder === "string" && (field as any).placeholder.trim()
        ? String((field as any).placeholder)
        : field.label;
    const activePlaceholder = values[field.id] ? "" : placeholder;
    return (
      <label key={field.id} className="field">
        {renderFieldLabel(field)}
        <input
          type="text"
          className="form-control"
          value={values[field.id] || ""}
          disabled={locked || !canSubmit}
          placeholder={activePlaceholder}
          onChange={(event) => setValues((prev) => ({ ...prev, [field.id]: event.target.value }))}
        />
      </label>
    );
  });
  const visibleFieldNodes = fieldNodes.filter(Boolean) as React.ReactNode[];
  if (canvasNodes.length > 0) {
    if (canvasFieldsPosition === "top") {
      visibleFieldNodes.unshift(...(canvasNodes as any[]));
    } else if (canvasFieldsPosition === "after_identity") {
      let insertAfter = -1;
      let visibleIndex = -1;
      form?.fields?.forEach((field) => {
        if (visibilityMap[field.id] === false) {
          return;
        }
        visibleIndex += 1;
        if (field.type === "email" || field.type === "full_name") {
          insertAfter = visibleIndex;
        }
      });
      if (insertAfter < 0 && visibleFieldNodes.length > 0) {
        insertAfter = 0;
      }
      if (insertAfter < 0) {
        visibleFieldNodes.unshift(...(canvasNodes as any[]));
      } else {
        visibleFieldNodes.splice(insertAfter + 1, 0, ...(canvasNodes as any[]));
      }
    } else {
      visibleFieldNodes.push(...(canvasNodes as any[]));
    }
  }

  function buildFileSelectionMessage(
    fieldKey: string,
    files: File[],
    existingCountOverride?: number
  ) {
    const rules = getFieldRule(fileRules, fieldKey);
    const existingCount =
      typeof existingCountOverride === "number"
        ? existingCountOverride
        : existingFilesByField[fieldKey]?.length || 0;
    const errors: string[] = [];
    if (rules.maxFiles > 0 && existingCount + files.length > rules.maxFiles) {
      errors.push(
        `File limit is ${rules.maxFiles}. Delete or replace an existing file, or reselect fewer files.`
      );
    }
    if (rules.maxBytes) {
      const tooLarge = files.find((file) => file.size > rules.maxBytes);
      if (tooLarge) {
        errors.push(`File too large: ${tooLarge.name} (${formatSize(tooLarge.size)}).`);
      }
    }
    if (rules.extensions.length) {
      const allowed = rules.extensions.map((ext) => ext.toLowerCase());
      const invalid = files.find((file) => {
        const parts = file.name.toLowerCase().split(".");
        const ext = parts.length > 1 ? parts[parts.length - 1] : "";
        return !ext || !allowed.includes(ext);
      });
      if (invalid) {
        errors.push(`Invalid file type: ${invalid.name}.`);
      }
    }
    if (errors.length === 0) {
      return { ok: true, rules, existingCount, message: null };
    }
    const info = rules.maxFiles
      ? ` Max files ${rules.maxFiles} (existing files ${existingCount}).`
      : ` Existing files ${existingCount}.`;
    const details = files.length
      ? ` Selected: ${files.map((file) => `${file.name} (${formatSize(file.size)})`).join(", ")}.`
      : "";
    return { ok: false, rules, existingCount, message: `${errors.join(" ")}${info}${details}`.trim() };
  }

  function applySelectedFiles(fieldKey: string, files: File[]) {
    setSelectedFiles((prev) => ({ ...prev, [fieldKey]: files }));
    setFileMeta((prev) => {
      const next: Record<string, FileMeta> = { ...prev };
      Object.keys(next).forEach((key) => {
        if (key.startsWith(`${fieldKey}:`)) {
          delete next[key];
        }
      });
      files.forEach((file) => {
        const key = buildFileIdentity(fieldKey, file);
        next[key] = { status: "pending", progress: 0 };
      });
      return next;
    });
    setFileUrls((prev) => {
      const previousUrls = prev[fieldKey] || [];
      previousUrls.forEach((url) => URL.revokeObjectURL(url));
      return {
        ...prev,
        [fieldKey]: files.map((file) => URL.createObjectURL(file))
      };
    });
    setUploadedFiles((prev) => {
      const next: Record<string, UploadedFile> = { ...prev };
      Object.keys(next).forEach((key) => {
        if (key.startsWith(`${fieldKey}:`)) {
          delete next[key];
        }
      });
      return next;
    });
  }

  function handleFileChange(fieldKey: string, fileList: FileList | null) {
    if (!fileList) return;
    const files = Array.from(fileList);
    const validation = buildFileSelectionMessage(fieldKey, files);
    if (!validation.ok) {
      setUploadError(validation.message);
      applySelectedFiles(fieldKey, []);
      return;
    }
    setUploadError(null);
    applySelectedFiles(fieldKey, files);
  }

  async function handleUploadField(
    fieldKey: string,
    overrideFiles?: File[],
    existingCountOverride?: number
  ) {
    if (!form) return;
    if (requiresSubmitPassword && !formPassword.trim()) {
      setUploadError("Enter the form password before uploading files.");
      return false;
    }
    const files = (overrideFiles ?? selectedFiles[fieldKey]) || [];
    if (files.length === 0) return false;
    const validation = buildFileSelectionMessage(fieldKey, files, existingCountOverride);
    if (!validation.ok) {
      setUploadError(validation.message);
      return false;
    }
    const rules = validation.rules;
    const existingCount = validation.existingCount;
    setFieldUploading((prev) => ({ ...prev, [fieldKey]: true }));
    setUploadError(null);
    try {
      const formData = new FormData();
      formData.append("fieldId", fieldKey);
      if (submissionId) {
        formData.append("submissionId", submissionId);
      }
      if (formPassword.trim()) {
        formData.append("formPassword", formPassword.trim());
      }
      files.forEach((file) => formData.append("files", file, file.name));
      files.forEach((file) => {
        const identity = buildFileIdentity(fieldKey, file);
        setFileMeta((prev) => ({ ...prev, [identity]: { status: "uploading", progress: 0 } }));
      });

      const response = await apiFetch(`${API_BASE}/api/forms/${form.slug}/upload`, {
        method: "POST",
        body: formData
      });
      const payload = await response.json().catch(() => null);
      if (!response.ok) {
        const info = rules.maxFiles
          ? ` Max files ${rules.maxFiles} (existing files ${existingCount}).`
          : ` Existing files ${existingCount}.`;
        const details = files.length
          ? ` Selected: ${files.map((file) => `${file.name} (${formatSize(file.size)})`).join(", ")}.`
          : "";
        const serverMessage =
          payload?.detail?.message ||
          payload?.detail?.field ||
          (typeof payload?.detail === "string" ? payload.detail : null);
        const needsReselect =
          payload?.detail?.message === "max_files_exceeded" ||
          serverMessage === "max_files_exceeded";
        const guidance = needsReselect
          ? " Reselect fewer files or delete/replace an existing file."
          : "";
        const serverInfo =
          payload?.detail?.maxFiles || payload?.detail?.maxBytes
            ? ` Server limits: maxFiles=${payload?.detail?.maxFiles ?? "n/a"}, maxBytes=${payload?.detail?.maxBytes ?? "n/a"
            }.`
            : "";
        throw new Error(
          `${payload?.error || "Upload failed"}${serverMessage ? `: ${serverMessage}` : ""}.${info}${details}${guidance}${serverInfo}`.trim()
        );
      }
      if (payload?.submissionId && !submissionId) {
        setSubmissionId(payload.submissionId);
      }
      files.forEach((file) => {
        const identity = buildFileIdentity(fieldKey, file);
        setFileMeta((prev) => ({ ...prev, [identity]: { status: "uploaded", progress: 100 } }));
        setUploadedFiles((prev) => ({
          ...prev,
          [identity]: {
            fieldKey,
            name: file.name,
            size: file.size
          } as UploadedFile
        }));
      });

      const nextSubmissionId = payload?.submissionId || submissionId;
      if (nextSubmissionId) {
        const filesResponse = await apiFetch(
          `${API_BASE}/api/forms/${form.slug}/files?submissionId=${encodeURIComponent(
            nextSubmissionId
          )}`
        );
        const filesPayload = await filesResponse.json().catch(() => null);
        if (filesResponse.ok && Array.isArray(filesPayload?.data)) {
          setFileItems(filesPayload.data);
        }
      }
      return true;
    } catch (error) {
      setUploadError(error instanceof Error ? error.message : "Upload failed");
      files.forEach((file) => {
        const identity = buildFileIdentity(fieldKey, file);
        setFileMeta((prev) => ({ ...prev, [identity]: { status: "error", progress: 0 } }));
      });
      return false;
    } finally {
      setFieldUploading((prev) => ({ ...prev, [fieldKey]: false }));
    }
  }

  async function refreshFileItems() {
    if (!form || !submissionId) return;
    const response = await apiFetch(
      `${API_BASE}/api/forms/${form.slug}/files?submissionId=${encodeURIComponent(submissionId)}`
    );
    const payload = await response.json().catch(() => null);
    if (response.ok && Array.isArray(payload?.data)) {
      setFileItems(payload.data);
    }
  }

  async function handleCheckFile(fileItemId: string) {
    if (!form) return;
    const response = await apiFetch(`${API_BASE}/api/forms/${form.slug}/files/${fileItemId}/check`, {
      method: "POST"
    });
    const payload = await response.json().catch(() => null);
    if (response.ok && payload?.data) {
      setFileItems((prev) => prev.map((item) => (item.id === fileItemId ? payload.data : item)));
    }
  }

  async function handleRemoveFile(fileItemId: string) {
    if (!form) return;
    const response = await apiFetch(`${API_BASE}/api/forms/${form.slug}/files/${fileItemId}`, {
      method: "DELETE"
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setUploadError(payload?.error || "Failed to remove file");
      return false;
    }
    setFileItems((prev) => prev.filter((item) => item.id !== fileItemId));
    return true;
  }

  async function restoreRemovedFile(fileItemId: string) {
    const response = await apiFetch(`${API_BASE}/api/me/trash/restore`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ type: "file", id: fileItemId })
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setUploadError(payload?.error || "Failed to restore previous file.");
      return false;
    }
    await refreshFileItems();
    return true;
  }

  async function handleRemoveAllFiles(fieldKey: string, items: FileItem[]) {
    if (!form || locked) return;
    if (items.length === 0) return;
    if (!window.confirm(`Move all ${items.length} uploaded file(s) to trash?`)) {
      return;
    }
    for (const item of items) {
      // Best-effort: stop on error to surface it.
      const ok = await handleRemoveFile(item.id);
      if (!ok) {
        return;
      }
    }
  }

  async function handleReplaceFile(fieldKey: string, fileItemId: string, file: File | null) {
    if (!file || locked || !canSubmit) return;
    setUploadError(null);
    applySelectedFiles(fieldKey, []);
    const existingCountBefore = existingFilesByField[fieldKey]?.length || 0;
    const removed = await handleRemoveFile(fileItemId);
    if (!removed) return;
    const rules = getFieldRule(fileRules, fieldKey);
    const replaceErrors: string[] = [];
    if (rules.maxBytes && file.size > rules.maxBytes) {
      replaceErrors.push(`File too large: ${file.name} (${formatSize(file.size)}).`);
    }
    if (rules.extensions.length) {
      const allowed = rules.extensions.map((ext) => ext.toLowerCase());
      const parts = file.name.toLowerCase().split(".");
      const ext = parts.length > 1 ? parts[parts.length - 1] : "";
      if (!ext || !allowed.includes(ext)) {
        replaceErrors.push(`Invalid file type: ${file.name}.`);
      }
    }
    if (replaceErrors.length > 0) {
      const restored = await restoreRemovedFile(fileItemId);
      setUploadError(
        `${replaceErrors.join(" ")}${restored ? " Previous file restored." : " Unable to restore previous file."}`
      );
      return;
    }
    const uploaded = await handleUploadField(
      fieldKey,
      [file],
      Math.max(existingCountBefore - 1, 0)
    );
    if (!uploaded) {
      const restored = await restoreRemovedFile(fileItemId);
      setUploadError((prev) =>
        prev
          ? `${prev}${restored ? " Previous file restored." : " Unable to restore previous file."}`
          : `Replacement failed.${restored ? " Previous file restored." : ""}`
      );
    }
  }

  async function handleAccess(event: React.FormEvent) {
    event.preventDefault();
    if (!formPassword.trim()) {
      setAccessError("Enter the form password to continue.");
      return;
    }
    setAccessing(true);
    setAccessError(null);
    const response = await apiFetch(`${API_BASE}/api/forms/${encodeURIComponent(slug)}/access`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ formPassword: formPassword.trim() })
    });
    const payload = await response.json().catch(() => null);
    setAccessing(false);
    if (!response.ok) {
      setAccessError(payload?.error || "Invalid form password.");
      return;
    }
    try {
      localStorage.setItem(
        accessCacheKey,
        JSON.stringify({
          password: formPassword.trim(),
          expiresAt: Date.now() + ACCESS_CACHE_TTL_MS
        })
      );
    } catch {
      // ignore cache write failures
    }
    setForm(payload?.data || null);
    setAccessRequired(false);
    setAccessError(null);
    setLocked(Boolean(payload?.data?.is_locked) || payload?.data?.is_open === false);
  }


  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    if (!form) return;
    setFieldErrors({});
    setSaving(true);
    setSubmitError(null);
    if (!isAuthorized) {
      setSubmitError({
        status: 403,
        message: "Login required to submit this form."
      });
      setSaving(false);
      return;
    }

    const errors: FieldErrors = {};
    const normalizedValues: Record<string, string> = {};
    const githubChecks: Array<Promise<void>> = [];
    form.fields.forEach((field) => {
      if (visibilityMap[field.id] === false) {
        return;
      }
      const raw = values[field.id] || "";
      const autofillValue = getAutofillValue(field);
      const value = (raw.trim() || autofillValue).trim();
      if (field.required && !value) {
        errors[field.id] = "Required";
        return;
      }
      const message = validateFieldValue(field, value);
      if (message) {
        errors[field.id] = message;
        return;
      }
      let normalized = value;
      if (field.type === "email") {
        const domain = getEmailDomain(field);
        if (domain && normalized && !normalized.includes("@")) {
          normalized = `${normalized}@${domain}`;
        }
      }
      if (field.type === "full_name" && normalized) {
        normalized = toTitleCase(normalized);
      }
      if (field.type === "url" && normalized) {
        normalized = ensureUrlWithScheme(normalized).value;
      }
      if (field.type === "date" && normalized) {
        const rules = (field as any).rules || {};
        const mode = typeof rules.mode === "string" ? rules.mode : "datetime";
        const tzKey = `${field.id}__tz`;
        const tz =
          (values[tzKey] || "").trim() ||
          (typeof rules.timezoneDefault === "string" ? String(rules.timezoneDefault) : "") ||
          getAppDefaultTimezone();
        const utcIso =
          mode === "time"
            ? timeOnlyToUtcIso(normalized, tz)
            : mode === "date"
              ? dateOnlyToUtcIso(normalized, tz)
              : zonedTimeToUtcIso(normalized, tz);
        if (!utcIso) {
          errors[field.id] = mode === "time" ? "Invalid time" : mode === "date" ? "Invalid date" : "Invalid date/time";
          return;
        }
        normalizedValues[tzKey] = tz;
        normalizedValues[field.id] = utcIso;
        return;
      }
      if (field.type === "github_username") {
        const rules = (field as any).rules || {};
        const allowAutofill = Boolean(rules.autofill);
        if (!allowAutofill && normalized) {
          githubChecks.push(
            (async () => {
              try {
                const response = await fetch(
                  `https://api.github.com/users/${encodeURIComponent(normalized)}`,
                  { headers: { "user-agent": "form-app" } }
                );
                if (response.status === 404) {
                  errors[field.id] = "GitHub username not found.";
                } else if (!response.ok) {
                  errors[field.id] = "Unable to verify GitHub username right now.";
                }
              } catch (error) {
                errors[field.id] = "Unable to verify GitHub username right now.";
              }
            })()
          );
        }
      }
      normalizedValues[field.id] = normalized;
    });
    const fileFields = form.fields.filter((field) => field.type === "file");
    fileFields.forEach((field) => {
      if (visibilityMap[field.id] === false) {
        return;
      }
      const files = selectedFiles[field.id] || [];
      const uploaded = files.filter((file) => uploadedFiles[buildFileIdentity(field.id, file)]);
      if (field.required && uploaded.length === 0) {
        errors[field.id] = "Upload required";
      }
      if (files.length > 0 && uploaded.length !== files.length) {
        errors[field.id] = "Please upload selected files";
      }
    });

    if (form.canvas_enabled && canvasSections.length > 0) {
      const selectedSection = typeof values._canvas_section_id === "string" ? values._canvas_section_id.trim() : "";
      if (selectedSection) {
        normalizedValues._canvas_section_id = selectedSection;
      } else if (singleCanvasSection) {
        normalizedValues._canvas_section_id = String(singleCanvasSection.id);
      } else {
        errors._canvas_section_id = "Please select a section";
      }
    }
    if (requiresSubmitPassword && !formPassword.trim()) {
      errors.formPassword = "Required";
    }

    Object.entries(values).forEach(([fieldId, rawValue]) => {
      if (fieldId.endsWith("__tz")) {
        return;
      }
      const field = form.fields.find((item) => item.id === fieldId);
      if (!field) {
        return;
      }
      if (visibilityMap[field.id] === false) {
        return;
      }
      if (field.type === "date") {
        return;
      }
      if (!(fieldId in normalizedValues)) {
        normalizedValues[fieldId] = String(rawValue || "").trim();
      }
    });

    if (githubChecks.length > 0) {
      await Promise.all(githubChecks);
    }

    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      setSaving(false);
      return;
    }

    try {
      setUploading(true);
      const response = await apiFetch(`${API_BASE}/api/submissions`, {
        method: "POST",
        headers: {
          "content-type": "application/json"
        },
        body: JSON.stringify({
          formSlug: form.slug,
          data: normalizedValues,
          formPassword: formPassword.trim() || null
        })
      });
      const text = await response.text();
      const status = response.status;
      let payload: any = null;
      try {
        payload = JSON.parse(text);
      } catch {
        payload = null;
      }
      setUploading(false);
      if (status < 200 || status >= 300) {
        const detailMessage =
          payload?.detail?.message ||
          payload?.detail?.field ||
          (typeof payload?.detail === "string" ? payload.detail : null);
        setSubmitError({
          status,
          requestId: payload?.requestId ?? undefined,
          message: detailMessage
            ? `${payload?.error || "Request failed"}: ${detailMessage}`
            : payload?.error || "Request failed",
          detail: payload?.detail
        });
        setSubmitDebug(text);
        if (status === 409 || status === 423) {
          setLocked(true);
        }
        setSaving(false);
        return;
      }
      const returnedId = payload?.data?.id || payload?.submissionId;
      if (returnedId) {
        setSubmissionId(returnedId);
        setHasExistingSubmission(true);
        const filesResponse = await apiFetch(
          `${API_BASE}/api/forms/${form.slug}/files?submissionId=${encodeURIComponent(
            returnedId
          )}`
        );
        const filesPayload = await filesResponse.json().catch(() => null);
        if (filesResponse.ok && Array.isArray(filesPayload?.data)) {
          setFileItems(filesPayload.data);
        }
      }
      setSavedAt(new Date().toISOString());
      setSaving(false);
      if (returnedId) {
        navigate(`/me/submissions/${returnedId}?submitted=1`);
      }
    } catch (err) {
      setUploading(false);
      setSubmitError({
        status: 0,
        message: err instanceof Error ? err.message : "Network error"
      });
      setSubmitDebug(err instanceof Error ? err.message : "Network error");
      setFileMeta((prev) => {
        const next: Record<string, FileMeta> = { ...prev };
        Object.keys(next).forEach((key) => {
          next[key] = { status: "error", progress: next[key].progress };
        });
        return next;
      });
      setSaving(false);
    }
  }

  if (loading) {
    return (
      <section className="panel">
        <h2>Loading form...</h2>
      </section>
    );
  }

  if (loadError) {
    return (
      <section className="panel panel--error">
        <h2>Unable to load form</h2>
        <p>
          Status: {loadError.status || "network"}{" "}
          {loadError.message ? `- ${loadError.message}` : ""}
        </p>
        {loadError.requestId ? <p className="muted">Request ID: {loadError.requestId}</p> : null}
      </section>
    );
  }

  if (accessRequired && !form) {
    return (
      <section className="panel">
        <h2>Form password required</h2>
        <form className="form-grid" onSubmit={handleAccess}>
          <label className="field">
            <span>Form password *</span>
            <input
              type="password"
              value={formPassword}
              disabled={accessing}
              onChange={(event) => setFormPassword(event.target.value)}
              placeholder="Enter form password to continue"
            />
            {accessError ? <span className="field-error">{accessError}</span> : null}
          </label>
          <button type="submit" className="btn btn-primary" disabled={accessing}>
            <i className="bi bi-unlock" aria-hidden="true" /> {accessing ? "Checking..." : "Unlock form"}
          </button>
        </form>
      </section>
    );
  }

  if (!form) {
    return (
      <section className="panel">
        <h2>Form not found</h2>
      </section>
    );
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <h2 className="mb-1">
            <RichText
              text={form.title}
              markdownEnabled={markdownEnabled}
              mathjaxEnabled={mathjaxEnabled}
              inline
            />
          </h2>
          {form.description ? (
            <p className="muted mb-1">
              <RichText
                text={form.description}
                markdownEnabled={markdownEnabled}
                mathjaxEnabled={mathjaxEnabled}
                inline
              />
            </p>
          ) : null}
          {(markdownEnabled || mathjaxEnabled) ? (
            <div className="field-help mt-2">
              <i className="bi bi-markdown" aria-hidden="true" /> Markdown
              {mathjaxEnabled ? " + MathJax" : ""} and HTML input are supported.
            </div>
          ) : null}
        </div>
        <div className="status-tags">
          <span className={`badge ${form.is_locked ? "text-bg-danger" : "text-bg-success"}`}>
            <i className={`bi ${getLockIcon(form.is_locked)}`} aria-hidden="true" />{" "}
            {form.is_locked ? "Locked" : "Unlocked"}
          </span>
          <span className={`badge ${form.is_public ? "text-bg-primary" : "text-bg-secondary"}`}>
            <i className={`bi ${getVisibilityIcon(form.is_public)}`} aria-hidden="true" />{" "}
            {form.is_public ? "Public" : "Private"}
          </span>
        </div>
      </div>

      {form.is_locked ? (
        <div className="alert alert-warning" role="alert">
          Form is locked.
        </div>
      ) : null}
      {form.available_from || form.available_until ? (
        <div className={`alert ${isOpen ? "alert-info" : "alert-warning"}`} role="alert">
          <i className="bi bi-clock" aria-hidden="true" />{" "}
          {form.available_from ? (
            <span>Opens: {formatTimeICT(form.available_from)}</span>
          ) : (
            <span>Opens: now</span>
          )}
          {form.available_until ? (
            <span className="ms-2">Closes: {formatTimeICT(form.available_until)}</span>
          ) : (
            <span className="ms-2">Closes: not set</span>
          )}
        </div>
      ) : null}

      {submitError ? (
        <div className="alert alert-danger" role="alert">
          <div className="alert-heading">We could not submit your form.</div>
          <div>{submitError.message || "Please check your inputs and try again."}</div>
          {submitError.requestId ? (
            <div className="muted">Request ID: {submitError.requestId}</div>
          ) : null}
        </div>
      ) : null}
      {submitError && import.meta.env.DEV && submitDebug ? (
        <div className="panel panel--inline">
          <div className="muted">Debug response</div>
          <pre className="mb-0">{submitDebug}</pre>
        </div>
      ) : null}

      {accessRequired ? (
        <div className="panel panel--inline panel--warning">
          <form className="form-grid" onSubmit={handleAccess}>
            <label className="field">
              <span>Form password *</span>
              <input
                type="password"
                value={formPassword}
                disabled={accessing}
                onChange={(event) => setFormPassword(event.target.value)}
                placeholder="Enter form password to continue"
              />
              {accessError ? <span className="field-error">{accessError}</span> : null}
            </label>
            <button type="submit" className="btn btn-primary" disabled={accessing}>
              <i className="bi bi-unlock" aria-hidden="true" />{" "}
              {accessing ? "Checking..." : "Unlock form"}
            </button>
          </form>
        </div>
      ) : null}

      {requiresAuth && !isAuthorized ? (
        <div className="panel panel--error panel--inline">
          <p>
            <i className="bi bi-shield-lock" aria-hidden="true" /> This form requires authentication.
            Please sign in to continue.
          </p>
          <div className="auth-bar">
            {allowGoogleAuth ? (
              <button type="button" className="btn btn-primary btn-auth" onClick={() => onLogin("google")}>
                <i className="bi bi-google" aria-hidden="true" /> Login with Google
              </button>
            ) : null}
            {allowGithubAuth ? (
              <button type="button" className="btn btn-dark btn-auth" onClick={() => onLogin("github")}>
                <i className="bi bi-github" aria-hidden="true" /> Login with GitHub
              </button>
            ) : null}
          </div>
        </div>
      ) : null}

      {previousSubmissionVisible && previousSubmission ? (
        <div className="panel panel--inline">
          <div className="d-flex flex-wrap align-items-center justify-content-between gap-2">
            <div>
              <div className="fw-semibold">Previous submission available</div>
              {previousSubmission.updatedAt ? (
                <div className="muted">Last submitted: {formatTimeICT(previousSubmission.updatedAt)}</div>
              ) : null}
            </div>
            <div className="d-flex flex-wrap gap-2">
              {!Boolean((form as any)?.save_all_versions) ? (
                <button
                  type="button"
                  className="btn btn-outline-secondary btn-sm"
                  onClick={() => {
                    setValues(previousSubmission.values);
                    Object.entries(previousSubmission.values).forEach(([fieldId, value]) => {
                      const field = form?.fields.find((item) => item.id === fieldId);
                      if (field) updateFieldError(field, value);
                    });
                    setPreviousSubmissionVisible(false);
                  }}
                >
                  <i className="bi bi-arrow-counterclockwise" aria-hidden="true" /> Use previous submission
                </button>
              ) : null}
              <button
                type="button"
                className="btn btn-outline-danger btn-sm"
                onClick={() => setPreviousSubmissionVisible(false)}
              >
                <i className="bi bi-x-circle" aria-hidden="true" /> Dismiss
              </button>
            </div>
          </div>
          {Boolean((form as any)?.save_all_versions) ? (
            <div className="mt-3">
              <VersionSelector
                submissionId={submissionId}
                saveAllVersions={Boolean((form as any)?.save_all_versions)}
                onVersionChange={handleVersionChange}
              />
            </div>
          ) : null}
        </div>
      ) : null}

      {draftVisible && draftPreview ? (
        <div className="panel panel--inline">
          <div className="d-flex flex-wrap align-items-center justify-content-between gap-2">
            <div>
              <div className="fw-semibold">Draft available</div>
              {draftPreview.updatedAt ? (
                <div className="muted">Last updated: {formatTimeICT(draftPreview.updatedAt)}</div>
              ) : null}
            </div>
            <div className="d-flex flex-wrap gap-2">
              <button
                type="button"
                className="btn btn-outline-secondary btn-sm"
                onClick={() => {
                  setValues((prev) => ({ ...prev, ...draftPreview.values }));
                  setDraftVisible(false);
                }}
              >
                <i className="bi bi-arrow-counterclockwise" aria-hidden="true" /> Restore draft
              </button>
              <button
                type="button"
                className="btn btn-outline-danger btn-sm"
                onClick={() => {
                  localStorage.removeItem(draftKey);
                  setDraftVisible(false);
                  setDraftPreview(null);
                }}
              >
                <i className="bi bi-trash" aria-hidden="true" /> Dismiss
              </button>
            </div>
          </div>
        </div>
      ) : null}
      {form ? (
        <div className="panel panel--inline">
          <div className="d-flex flex-wrap align-items-center justify-content-between gap-2">
            <div>
              <div className="fw-semibold">Import/export</div>
              <div className="muted">Import a markdown or JSON file to populate the form.</div>
            </div>
            <div className="d-flex flex-wrap gap-2 align-items-center">
              {isAuthorized && hasPassword ? (
                <>
                  <div className="btn-group btn-group-sm" role="group">
                    <button type="button" className="btn btn-outline-secondary" onClick={handleDownloadMarkdown}>
                      <i className="bi bi-download" aria-hidden="true" /> Export markdown
                    </button>
                    <button type="button" className="btn btn-outline-secondary" onClick={handleDownloadJson}>
                      <i className="bi bi-download" aria-hidden="true" /> Export JSON
                    </button>
                  </div>
                  <label className="btn btn-outline-secondary btn-sm mb-0">
                    <i className="bi bi-upload" aria-hidden="true" /> Import file
                    <input
                      type="file"
                      accept=".md,.json,text/markdown,application/json,text/plain"
                      onChange={handleImportFile}
                      style={{ display: "none" }}
                    />
                  </label>
                </>
              ) : (
                <span className="muted">Sign in and unlock the form to use import/export.</span>
              )}
            </div>
          </div>
          {importStatus ? <div className="muted mt-2">{importStatus}</div> : null}
        </div>
      ) : null}

      <form className="form-grid" onSubmit={handleSubmit}>
        {visibleFieldNodes.length === 0 ? <p className="muted">No fields configured yet.</p> : visibleFieldNodes}
        {uploading ? <p className="muted">Uploading files...</p> : null}
        <div className="form-actions form-actions--sticky">
          {!locked ? (
            <button
              className="btn btn-primary"
              type="submit"
              disabled={!canSubmit || saving || locked || uploading || isAnyUploading || !isFormComplete}
              title={submitDisabledReason}
            >
              <i className="bi bi-send" aria-hidden="true" />{" "}
              {saving ? "Saving..." : isAnyUploading ? "Uploading..." : submitLabel}
            </button>
          ) : null}
          {savedAt ? <span className="muted">Last saved: {formatTimeICT(savedAt)}</span> : null}
          {submitDisabledReason ? <span className="muted">{submitDisabledReason}</span> : null}
        </div>
      </form>
    </section>
  );
}

function FormRoute({
  user,
  onLogin,
  onNotice,
  markdownEnabled,
  mathjaxEnabled
}: {
  user: UserInfo | null;
  onLogin: (provider: "google" | "github") => void;
  onNotice: (message: string, type?: NoticeType) => void;
  markdownEnabled: boolean;
  mathjaxEnabled: boolean;
}) {
  const params = useParams();
  const slug = params.slug || "";
  return (
    <FormPage
      slug={slug}
      user={user}
      onLogin={onLogin}
      onNotice={onNotice}
      markdownEnabled={markdownEnabled}
      mathjaxEnabled={mathjaxEnabled}
    />
  );
}

function DocsPage() {
  return (
    <section className="panel">
      <h2>Docs</h2>
      <p className="muted">
        This guide explains how Form App is structured and how to use the main features.
      </p>
      <p className="muted">
        Note: This codebase was built with the assistance of GitHub Copilot, ChatGPT Codex, and Google Antigravity.
      </p>

      <div className="panel panel--compact">
        <h3>Architecture overview</h3>
        <ul className="list-unstyled">
          <li>
            <strong>API:</strong> Cloudflare Worker in <code>apps/api</code> with D1 for data,
            R2 for uploads, VirusTotal for scanning, and Drive for finalization.
          </li>
          <li>
            <strong>Web:</strong> Vite + React in <code>apps/web</code>, routed with HashRouter.
          </li>
          <li>
            <strong>Auth:</strong> Google/GitHub OAuth; JWT stored in cookie.
          </li>
        </ul>
      </div>

      <div className="panel panel--compact">
        <h3>Core routes</h3>
        <ul className="list-unstyled">
          <li>
            <strong>Public:</strong> <code>/#/</code>, <code>/#/f/&lt;slug&gt;</code>,{" "}
            <code>/#/docs</code>
          </li>
          <li>
            <strong>User:</strong> <code>/#/me</code>, <code>/#/me/submissions/&lt;id&gt;</code>
          </li>
          <li>
            <strong>Account:</strong> <code>/#/account</code>, <code>/#/canvas</code>
          </li>
          <li>
            <strong>Admin:</strong> <code>/#/admin</code>
          </li>
          <li>
            <strong>Builder:</strong> <code>/#/admin/builder</code> (admin-only)
          </li>
        </ul>
        <p className="muted mb-0">
          Admin pages are grouped under the Admin menu in the top navigation.
        </p>
      </div>

      <div className="panel panel--compact">
        <h3>Main features</h3>
        <ul className="list-unstyled">
          <li>
            <strong>Public forms:</strong> list and fill public forms from <code>/api/forms</code>.
          </li>
          <li>
            <strong>Submission:</strong> submit and resubmit while unlocked; locked forms block edits.
          </li>
          <li>
            <strong>Drafts:</strong> unsent inputs auto-save locally and can be restored on return.
          </li>
          <li>
            <strong>Uploads:</strong> staged to R2, scanned by VirusTotal, finalized to Drive if clean.
          </li>
          <li>
            <strong>Admin:</strong> manage forms/templates, review submissions, export CSV/TXT.
          </li>
          <li>
            <strong>Emails:</strong> admin email log, trash, and test send with preset templates.
          </li>
          <li>
            <strong>Rich text:</strong> Markdown + MathJax + HTML supported in titles,
            descriptions, labels, and text values when enabled in Admin App settings.
          </li>
          <li>
            <strong>Admin dashboard:</strong> list forms/templates/submissions/users with bulk
            move-to-trash actions.
          </li>
          <li>
            <strong>Exports:</strong> export submissions and optionally filter to specific data keys
            with the fields input.
          </li>
          <li>
            <strong>Builder:</strong> duplicate forms/templates for faster reuse.
          </li>
          <li>
            <strong>Account:</strong> linked identities, deletion flow, and user-level canvas info.
          </li>
        </ul>
      </div>

      <div className="panel panel--compact">
        <h3>Mobile QA checklist</h3>
        <ul className="list-unstyled">
          <li>Test at 375px and 768px widths (no horizontal scrolling).</li>
          <li>Mobile menu drawer opens and closes on tap.</li>
          <li>Login buttons are full-width and easy to tap.</li>
          <li>Form fields stack vertically with readable errors.</li>
          <li>Sticky submit bar appears and does not cover inputs.</li>
        </ul>
      </div>

      <div className="panel panel--compact">
        <h3>Field rules</h3>
        <ul className="list-unstyled">
          <li>
            <strong>Email domain:</strong> email fields can require a specific domain (e.g.
            <code>example.com</code>). Both UI and API validate it.
          </li>
          <li>
            <strong>Login auto-fill:</strong> email and GitHub username fields can auto-fill from
            the signed-in user when enabled in the builder. If the login email domain does not
            match the required domain, users can still manually enter a valid address for that
            domain.
          </li>
          <li>
            <strong>Full name:</strong> full name fields normalize to title-case on submit.
          </li>
          <li>
            <strong>URL:</strong> URL fields accept only valid <code>http</code>/<code>https</code>
            links and auto-prefix missing schemes on blur/submit.
          </li>
          <li>
            <strong>Date/time:</strong> date fields include time + timezone. Submissions store UTC
            timestamps plus the chosen timezone. Modes: date only, time only, or date & time.
          </li>
          <li>
            <strong>Availability:</strong> forms can be opened/closed by time with a timezone
            selector. Availability times are stored in UTC.
          </li>
          <li>
            <strong>Timezone picker:</strong> searchable dropdown backed by the full IANA list,
            with a curated fallback so Asia/Ho_Chi_Minh always appears.
          </li>
          <li>
            <strong>Default timezone:</strong> admins can set a global default timezone (Admin App settings). Times are displayed in the viewer's local timezone.
          </li>
          <li>
            <strong>Markdown + MathJax:</strong> enabled/disabled globally in Admin App settings.
            When enabled, form titles, descriptions, labels, and text values render rich content.
          </li>
          <li>
            <strong>Canvas sync scope:</strong> admins can choose to sync active, concluded, or all Canvas courses (Admin Canvas page). This controls which courses appear in builders and Canvas tools.
          </li>
        </ul>
      </div>

      <div className="panel panel--compact">
        <h3>Builder workflow (admin)</h3>
        <ul className="list-unstyled">
          <li>Use Admin &gt; Builder to create or edit forms/templates.</li>
          <li>
            Toggle <strong>New</strong> vs <strong>Edit</strong> to switch between create/update.
          </li>
          <li>
            Field builder supports: text, textarea, number, date/time, email, URL, GitHub
            username, full name, select, checkbox, and file fields.
          </li>
          <li>
            File fields store rules per field: extensions, max size, max files.
          </li>
          <li>Use drag handles (or mobile up/down buttons) to reorder fields.</li>
        </ul>
      </div>

      <div className="panel panel--compact">
        <h3>Canvas enrollment forms</h3>
        <ul className="list-unstyled">
          <li>Enable Canvas enrollment in the Builder and select a Canvas course.</li>
          <li>
            Course availability depends on the Canvas sync scope set in Admin Canvas page (active, concluded, or all).
          </li>
          <li>Optionally limit the dropdown to specific course sections.</li>
          <li>
            The form must include a <strong>Full Name</strong> field and an <strong>Email</strong>{" "}
            field; these are required for Canvas enrollment.
          </li>
          <li>
            If more than one section is available, users must select a section. If there is only
            one section, it is auto-assigned.
          </li>
          <li>
            After submit: the API enrolls the user and records a status on the submission.
          </li>
          <li>
            Admin App settings control whether delete/restore actions deactivate or reactivate
            Canvas enrollments and whether hard delete actions unenroll Canvas users.
          </li>
          <li>
            Admin Canvas page exposes the retry queue and dead letters with Retry/Drop actions.
          </li>
        </ul>
      </div>

      <div className="panel panel--compact">
        <h3>Routine tasks + health</h3>
        <ul className="list-unstyled">
          <li>
            Admin dashboard includes routine tasks (cron-based) and health history for key
            services.
          </li>
          <li>
            Routine tasks include Canvas sync, name mismatch checks, Canvas retry queue, backup,
            and empty trash.
          </li>
          <li>
            Tasks support bulk Run/Save and bulk Enable/Disable actions from the dashboard.
            Latest run time appears in the status column.
          </li>
          <li>
            Admin Emails page loads test presets from <code>/api/admin/emails/presets</code> so new
            predefined messages appear automatically in the dropdown.
          </li>
          <li>
            Routine run logs are retained (last 100 per task, last 30 days).
          </li>
          <li>
            Health data is stored in D1 and summarized in the admin health panel.
          </li>
        </ul>
      </div>

      <div className="panel panel--compact">
        <h3>Backups + restore</h3>
        <ul className="list-unstyled">
          <li>
            Admin can export selected forms/templates to JSON backups.
          </li>
          <li>
            Restore supports slug conflict handling (restore trash version or cancel).
          </li>
          <li>
            Routine backup writes JSON to R2 and Drive under <code>/backups</code>.
          </li>
        </ul>
      </div>

      <div className="panel panel--compact">
        <h3>Admin submissions access</h3>
        <ul className="list-unstyled">
          <li>Admin can open any submission at <code>/#/me/submissions/&lt;id&gt;</code>.</li>
          <li>Recent submissions list links each submission ID to that detail view.</li>
          <li>Admin lists support bulk select + move-to-trash for forms/templates/users/submissions.</li>
        </ul>
      </div>

      <div className="panel panel--compact">
        <h3>How to use the app</h3>
        <ol className="mb-0">
          <li>Open the home page and choose a public form.</li>
          <li>Sign in if the form requires Google or GitHub authentication.</li>
          <li>Fill fields and submit. If unlocked, you can edit and resubmit later.</li>
          <li>
            For file fields: select files, upload them, then submit the form to finalize.
          </li>
          <li>Review your submissions in <code>/#/me</code>.</li>
        </ol>
      </div>

      <div className="panel panel--compact">
        <h3>OAuth + linking</h3>
        <ul className="list-unstyled">
          <li>
            Login: <code>/auth/login/google</code>, <code>/auth/login/github</code>
          </li>
          <li>
            Link providers (signed in): <code>/auth/link/google</code>,{" "}
            <code>/auth/link/github</code>
          </li>
          <li>
            Deleted accounts cannot log in; they are redirected to{" "}
            <code>/#/account?error=user_deleted</code>.
          </li>
        </ul>
      </div>

      <div className="panel panel--compact">
        <h3>Upload flow (API)</h3>
        <ol className="mb-0">
          <li>
            Init: <code>POST /api/uploads/init</code> (creates a draft upload session)
          </li>
          <li>
            Put bytes: <code>PUT /api/uploads/put</code> (stores in R2)
          </li>
          <li>
            Complete: <code>POST /api/uploads/complete</code> (creates DB row + VT scan)
          </li>
          <li>
            Check: <code>GET /api/submissions/upload/status</code> (poll VT status)
          </li>
          <li>Finalize: uploads to Drive when scans are clean and Drive is configured.</li>
        </ol>
      </div>

      <div className="panel panel--compact">
        <h3>Account deletion</h3>
        <ul className="list-unstyled mb-0">
          <li>User deletion is soft-delete plus immediate logout.</li>
          <li>Only admin can restore or permanently delete users.</li>
        </ul>
      </div>

      <div className="panel panel--compact">
        <h3>Theme</h3>
        <ul className="list-unstyled mb-0">
          <li>Dark theme is the default.</li>
          <li>The theme toggle persists in localStorage.</li>
        </ul>
      </div>

      <div className="panel panel--compact">
        <h3>Local deployment</h3>
        <ol className="mb-0">
          <li>Install deps: <code>npm install</code></li>
          <li>Start API: <code>npm run dev:api</code></li>
          <li>Start Web: <code>npm run dev:web</code></li>
          <li>Open <code>http://localhost:5173/forms/</code></li>
          <li>Canvas sync requires <code>CANVAS_API_TOKEN</code> in <code>apps/api/.dev.vars</code>.</li>
        </ol>
      </div>

      <div className="panel panel--compact">
        <h3>Production deployment</h3>
        <ul className="list-unstyled">
          <li>
            <strong>Web (GitHub Pages):</strong> build with{" "}
            <code>VITE_API_BASE=https://form-app-api.hoanganhduc.workers.dev</code>{" "}
            and <code>VITE_WEB_BASE=/forms/</code>, then upload <code>apps/web/dist</code>.
          </li>
          <li>
            <strong>API (Cloudflare Workers):</strong> configure{" "}
            <code>wrangler.toml</code> bindings, run migrations, then deploy with{" "}
            <code>npx wrangler deploy -c wrangler.toml</code>.
          </li>
          <li>
            <strong>Canvas:</strong> set <code>CANVAS_API_TOKEN</code> and optional{" "}
            <code>CANVAS_ACCOUNT_ID</code> in Cloudflare secrets/vars, then sync courses.
          </li>
        </ul>
      </div>

      <div className="panel panel--compact">
        <h3>Quick API reference</h3>
        <ul className="list-unstyled mb-0">
          <li><code>GET /api/forms</code> public form list</li>
          <li><code>GET /api/forms/:slug</code> form detail</li>
          <li><code>POST /api/submissions</code> create/update submission</li>
          <li><code>GET /api/me/submissions</code> user dashboard</li>
          <li><code>GET /api/me/submissions/:id</code> submission detail (admin can open any)</li>
          <li><code>POST /api/uploads/init</code> upload init</li>
          <li><code>PUT /api/uploads/put</code> upload bytes</li>
          <li><code>POST /api/uploads/complete</code> finalize upload + VT</li>
          <li><code>GET /api/submissions/upload/status</code> VT status</li>
        </ul>
      </div>
    </section>
  );
}

function NotFoundPage() {
  return (
    <section className="panel panel--error">
      <h2>Page not found</h2>
      <p className="muted">
        If you are using a hash route, try <code>/forms/#/admin</code> or <code>/forms/#/</code>.
      </p>
      <div className="d-flex gap-2">
        <Link className="btn btn-outline-primary btn-sm" to="/">
          Home
        </Link>
        <Link className="btn btn-outline-secondary btn-sm" to="/admin">
          Admin
        </Link>
      </div>
    </section>
  );
}

function DashboardPage({
  user,
  onLogin,
  onNotice,
  markdownEnabled,
  mathjaxEnabled
}: {
  user: UserInfo | null;
  onLogin: (provider: "google" | "github") => void;
  onNotice: (message: string, type?: NoticeType) => void;
  markdownEnabled: boolean;
  mathjaxEnabled: boolean;
}) {
  const [loading, setLoading] = useState(true);
  const [items, setItems] = useState<any[]>([]);
  const [error, setError] = useState<ApiError | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [emailsLoading, setEmailsLoading] = useState(true);
  const [emailsError, setEmailsError] = useState<ApiError | null>(null);
  const [emails, setEmails] = useState<any[]>([]);

  useEffect(() => {
    if (!user) {
      setLoading(false);
      setItems([]);
      return;
    }
    let active = true;
    async function loadDashboard() {
      setLoading(true);
      const response = await apiFetch(`${API_BASE}/api/me/submissions`);
      const payload = await response.json().catch(() => null);
      if (!active) return;
      if (!response.ok) {
        setError({
          status: response.status,
          requestId: payload?.requestId,
          message: payload?.error || "Request failed"
        });
        setLoading(false);
        return;
      }
      const data = Array.isArray(payload?.data) ? payload.data : [];
      setItems(
        data.map((entry: any) => ({
          form: entry.form,
          latestSubmission: entry.latestSubmission,
          canEdit: Boolean(entry.canEdit),
          countSubmissions: Number(entry.count_submissions ?? 0),
          latestSubmissionId: entry.latest_submission_id ?? entry.latestSubmission?.id ?? null
        }))
      );
      setError(null);
      setLoading(false);
    }
    loadDashboard();
    return () => {
      active = false;
    };
  }, [user]);

  useEffect(() => {
    if (!user) {
      setEmails([]);
      setEmailsLoading(false);
      return;
    }
    let active = true;
    async function loadEmails() {
      setEmailsLoading(true);
      const response = await apiFetch(`${API_BASE}/api/me/emails?page=1&pageSize=100`);
      const payload = await response.json().catch(() => null);
      if (!active) return;
      if (!response.ok) {
        setEmailsError({
          status: response.status,
          requestId: payload?.requestId,
          message: payload?.error || "Request failed"
        });
        setEmailsLoading(false);
        return;
      }
      setEmails(Array.isArray(payload?.data) ? payload.data : []);
      setEmailsError(null);
      setEmailsLoading(false);
    }
    loadEmails();
    return () => {
      active = false;
    };
  }, [user]);

  async function handleDeleteSubmission(formSlug: string, canvasEnabled: boolean) {
    setActionError(null);
    const confirmMessage = canvasEnabled
      ? "Move this submission to trash? This will deactivate your Canvas enrollment for this course."
      : "Move this submission to trash?";
    if (!window.confirm(confirmMessage)) {
      return;
    }
    const response = await apiFetch(
      `${API_BASE}/api/me/submission?formSlug=${encodeURIComponent(formSlug)}`,
      { method: "DELETE" }
    );
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setActionError(payload?.error || "Failed to delete submission.");
      return;
    }
    if (canvasEnabled && payload?.canvasAction) {
      const canvasLabel =
        payload.canvasAction === "deactivated"
          ? "deactivated"
          : payload.canvasAction === "failed"
            ? "failed"
            : "skipped";
      onNotice(
        `Submission deleted. Canvas deactivation: ${canvasLabel}.`,
        payload.canvasAction === "failed" ? "warning" : "success"
      );
    } else {
      onNotice("Submission deleted.", "success");
    }
    setItems((prev) => prev.filter((entry) => entry.form?.slug !== formSlug));
  }

  if (!user) {
    return (
      <section className="panel panel--error">
        <h2>Sign in required</h2>
        <p>Please sign in to view your dashboard.</p>
        <div className="auth-bar">
          <button type="button" className="btn btn-primary btn-auth" onClick={() => onLogin("google")}>
            <i className="bi bi-google" aria-hidden="true" /> Login with Google
          </button>
          <button type="button" className="btn btn-dark btn-auth" onClick={() => onLogin("github")}>
            <i className="bi bi-github" aria-hidden="true" /> Login with GitHub
          </button>
        </div>
      </section>
    );
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <h2>My Dashboard</h2>
      </div>
      {loading ? <p className="muted">Loading...</p> : null}
      {error ? (
        <div className="alert alert-danger" role="alert">
          {error.message || "Failed to load dashboard."}
        </div>
      ) : null}
      {actionError ? <div className="alert alert-danger">{actionError}</div> : null}
      {items.length === 0 && !loading ? <p className="muted">No submissions yet.</p> : null}
      {items.length > 0 ? (
        <div className="table-responsive">
          <table className="table table-sm">
            <thead>
              <tr>
                <th>Form</th>
                <th>Access</th>
                <th>Auth</th>
                <th>Status</th>
                <th>Last submitted</th>
                <th>Submissions</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((entry) => {
                const form = entry.form || {};
                const latest = entry.latestSubmission || {};
                const slug = form.slug || "unknown";
                const lastTime = latest.updated_at || latest.created_at;
                return (
                  <tr key={latest.id || slug}>
                    <td>
                      <a className="text-decoration-none" href={`${PUBLIC_BASE}#/f/${slug}`}>
                        <i className="bi bi-ui-checks" aria-hidden="true" />{" "}
                        <RichText
                          text={form.title || slug}
                          markdownEnabled={markdownEnabled}
                          mathjaxEnabled={mathjaxEnabled}
                          inline
                        />
                      </a>
                      <div className="muted">{slug}</div>
                      {form.deleted_at ? <div className="muted">Deleted</div> : null}
                    </td>
                    <td>
                      <span
                        className={`badge ${form.is_public ? "text-bg-info" : "text-bg-secondary"}`}
                        title={form.is_public ? "Public form" : "Private form"}
                      >
                        <i className={`bi ${getVisibilityIcon(Boolean(form.is_public))}`} aria-hidden="true" />{" "}
                        {form.is_public ? "Public" : "Private"}
                      </span>
                    </td>
                    <td>
                      <span className="badge text-bg-light" title={`Auth policy: ${getAuthPolicyLabel(form.auth_policy)}`}>
                        <i className={`bi ${getAuthPolicyIcon(form.auth_policy)}`} aria-hidden="true" />{" "}
                        {getAuthPolicyLabel(form.auth_policy)}
                      </span>
                    </td>
                    <td>
                      <span
                        className={`badge ${form.is_locked ? "text-bg-danger" : "text-bg-success"}`}
                      >
                        <i className={`bi ${getLockIcon(form.is_locked)}`} aria-hidden="true" />{" "}
                        {form.is_locked ? "Locked" : "Unlocked"}
                      </span>
                    </td>
                    <td>{lastTime ? formatTimeICT(lastTime) : "n/a"}</td>
                    <td>
                      {Number(entry.countSubmissions) || 0}
                    </td>
                    <td>
                      <div className="d-flex gap-2 flex-wrap">
                        <a className="btn btn-outline-primary btn-sm" href={`${PUBLIC_BASE}#/f/${slug}`}>
                          <i className="bi bi-pencil-square" aria-hidden="true" />{" "}
                          {entry.canEdit ? "Edit" : "Open"}
                        </a>
                        {entry.latestSubmissionId ? (
                          <Link
                            className="btn btn-outline-secondary btn-sm"
                            to={`/me/submissions/${entry.latestSubmissionId}`}
                          >
                            <i className="bi bi-eye" aria-hidden="true" /> View
                          </Link>
                        ) : null}
                        <button
                          type="button"
                          className="btn btn-outline-danger btn-sm"
                          onClick={() => handleDeleteSubmission(slug, Boolean(form.canvas_enabled))}
                        >
                          <i className="bi bi-trash" aria-hidden="true" /> Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : null}
      <div className="panel panel--compact mt-3">
        <div className="panel-header">
          <h3 className="mb-0">Email log</h3>
        </div>
        {emailsLoading ? <p className="muted">Loading emails...</p> : null}
        {emailsError ? (
          <div className="alert alert-danger" role="alert">
            {emailsError.message || "Failed to load emails."}
          </div>
        ) : null}
        {!emailsLoading && emails.length === 0 ? (
          <div className="muted">No emails sent to your linked identities yet.</div>
        ) : null}
        {emails.length > 0 ? (
          <div className="table-responsive">
            <table className="table table-sm">
              <thead>
                <tr>
                  <th>Sent</th>
                  <th>To</th>
                  <th>Subject</th>
                  <th>Status</th>
                  <th>Form</th>
                  <th>Submission</th>
                  <th>Trigger</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {emails.map((item) => (
                  <tr key={item.id}>
                    <td className="text-nowrap">
                      {item.created_at ? formatTimeICT(item.created_at) : "n/a"}
                    </td>
                    <td className="text-break">{item.to_email || "n/a"}</td>
                    <td className="text-break">{item.subject || "n/a"}</td>
                    <td className="text-nowrap">
                      {item.status || "n/a"}
                      {item.error ? <div className="muted">{item.error}</div> : null}
                    </td>
                    <td className="text-break">
                      {item.form_title || item.form_slug || "n/a"}
                      {item.form_slug ? <div className="muted">{item.form_slug}</div> : null}
                    </td>
                    <td className="text-break">{item.submission_id || "n/a"}</td>
                    <td className="text-break">
                      {item.trigger_source || "n/a"}
                      {item.triggered_by ? <div className="muted">{item.triggered_by}</div> : null}
                    </td>
                    <td className="text-break">
                      <details>
                        <summary>View</summary>
                        <div className="mt-2">
                          <div className="muted">Body</div>
                          <pre className="mb-2">{item.body || ""}</pre>
                          <div className="muted">All fields</div>
                          <pre className="mb-0">{JSON.stringify(item, null, 2)}</pre>
                        </div>
                      </details>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </div>
    </section>
  );
}

function AccountPage({
  user,
  onLogin,
  onLogout,
  onNotice
}: {
  user: UserInfo | null;
  onLogin: (provider: "google" | "github") => void;
  onLogout: (silent?: boolean) => void;
  onNotice: (message: string, type?: NoticeType) => void;
}) {
  const location = useLocation();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [identities, setIdentities] = useState<any[]>([]);
  const [hasCanvasInfo, setHasCanvasInfo] = useState(false);

  useEffect(() => {
    if (!user) {
      setLoading(false);
      return;
    }
    let active = true;
    async function loadAccount() {
      setLoading(true);
      const response = await apiFetch(`${API_BASE}/api/me`);
      const payload = await response.json().catch(() => null);
      if (!active) return;
      if (!response.ok) {
        setError({
          status: response.status,
          requestId: payload?.requestId,
          message: payload?.error || "Request failed"
        });
        setLoading(false);
        return;
      }
      let nextIdentities: any[] = [];
      if (Array.isArray(payload?.identities)) {
        nextIdentities = payload.identities;
      } else if (Array.isArray(payload?.data)) {
        nextIdentities = payload.data;
      }
      if (nextIdentities.length === 0) {
        const identitiesRes = await apiFetch(`${API_BASE}/api/me/identities`);
        const identitiesPayload = await identitiesRes.json().catch(() => null);
        if (identitiesRes.ok && Array.isArray(identitiesPayload?.data)) {
          nextIdentities = identitiesPayload.data;
        }
      }
      setIdentities(nextIdentities);
      setHasCanvasInfo(Boolean(payload?.canvas?.course_id || payload?.canvas?.user_id));
      setError(null);
      setLoading(false);
    }
    loadAccount();
    return () => {
      active = false;
    };
  }, [user]);

  const params = new URLSearchParams(location.search);
  const linked = params.get("linked");
  const linkError = params.get("error");
  const errorProvider = params.get("provider");

  if (!user) {
    return (
      <section className="panel panel--error">
        <h2>Sign in required</h2>
        <p>Please sign in to manage your account.</p>
        {linkError === "user_deleted" ? (
          <div className="alert alert-danger" role="alert">
            Your account has been deleted. Please contact an admin to restore access.
          </div>
        ) : null}
        <div className="auth-bar">
          <button type="button" className="btn btn-primary btn-auth" onClick={() => onLogin("google")}>
            <i className="bi bi-google" aria-hidden="true" /> Login with Google
          </button>
          <button type="button" className="btn btn-dark btn-auth" onClick={() => onLogin("github")}>
            <i className="bi bi-github" aria-hidden="true" /> Login with GitHub
          </button>
        </div>
      </section>
    );
  }

  const providers = new Set(identities.map((identity) => identity.provider));

  function handleLink(provider: "google" | "github") {
    window.location.assign(`${API_BASE}/auth/link/${provider}`);
  }

  async function handleDeleteAccount() {
    setActionError(null);
    const confirmMessage = hasCanvasInfo
      ? "Move your account to trash? This will move your submissions to trash and deactivate your Canvas enrollments. If you want to restore your account later, contact an admin."
      : "Move your account to trash? This will move your submissions to trash. If you want to restore your account later, contact an admin.";
    if (!window.confirm(confirmMessage)) {
      return;
    }
    // Soft-delete the account server-side; API clears the auth cookie.
    const response = await apiFetch(`${API_BASE}/api/me`, { method: "DELETE" });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setActionError(payload?.error || "Failed to delete account.");
      return;
    }
    onNotice("Account moved to trash.", "success");
    onLogout(true);
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Account</h2>
        {user ? (
          <span className="badge">
            {user.provider === "github"
              ? getUserDisplayName(user)
              : getUserDisplayName(user)}
          </span>
        ) : null}
      </div>
      {linked ? (
        <div className="alert alert-success" role="alert">
          Linked {linked} successfully.
        </div>
      ) : null}
      {linkError ? (
        <div className="alert alert-danger" role="alert">
          {linkError === "identity_already_linked"
            ? `That ${errorProvider || "identity"} account is already linked to another user.`
            : linkError === "user_deleted"
              ? "Your account has been deleted. Please contact an admin to restore access."
              : "Unable to link identity."}
        </div>
      ) : null}
      {loading ? <p className="muted">Loading...</p> : null}
      {error ? (
        <div className="alert alert-danger" role="alert">
          {error.message || "Failed to load account."}
        </div>
      ) : null}
      {actionError ? <div className="alert alert-danger">{actionError}</div> : null}
      <div className="panel panel--compact">
        <div className="panel-header">
          <h3 className="mb-0">Role</h3>
        </div>
        <span
          className={`badge fs-6 ${user?.isAdmin ? "text-bg-warning" : "text-bg-secondary"}`}
        >
          {user?.isAdmin ? "Admin" : "User"}
        </span>
      </div>
      <div className="panel panel--compact mt-3">
        <div className="panel-header">
          <h3 className="mb-0">Linked identities</h3>
        </div>
        <div className="row g-3">
          <div className="col-md-6">
            {identities.length === 0 ? (
              <div className="muted">No linked identities yet.</div>
            ) : (
              <ul className="list-unstyled mb-0">
                {identities.map((identity) => (
                  <li key={`${identity.provider}-${identity.providerSub || identity.providerLogin || identity.email}`}>
                    <span className="badge text-bg-light me-2">
                      <i className={`bi ${getAuthPolicyIcon(identity.provider)}`} aria-hidden="true" />{" "}
                      {identity.provider}
                    </span>
                    {identity.provider === "github"
                      ? identity.providerLogin || identity.email || identity.providerSub || "n/a"
                      : identity.email || identity.providerLogin || identity.providerSub || "n/a"}
                  </li>
                ))}
              </ul>
            )}
          </div>
          <div className="col-md-6">
            <div className="muted">Link another provider</div>
            <div className="d-flex flex-wrap gap-2 mt-2">
              <button
                type="button"
                className="btn btn-outline-primary"
                disabled={providers.has("google")}
                onClick={() => handleLink("google")}
              >
                <i className="bi bi-google" aria-hidden="true" />{" "}
                {providers.has("google") ? "Google linked" : "Link Google"}
              </button>
              <button
                type="button"
                className="btn btn-outline-dark"
                disabled={providers.has("github")}
                onClick={() => handleLink("github")}
              >
                <i className="bi bi-github" aria-hidden="true" />{" "}
                {providers.has("github") ? "GitHub linked" : "Link GitHub"}
              </button>
            </div>
          </div>
        </div>
      </div>
      <div className="mt-3">
        <button type="button" className="btn btn-outline-danger" onClick={handleDeleteAccount}>
          <i className="bi bi-person-x" aria-hidden="true" /> Delete my account
        </button>
      </div>
    </section>
  );
}

function CanvasPage({
  user,
  onLogin,
  markdownEnabled,
  mathjaxEnabled
}: {
  user: UserInfo | null;
  onLogin: (provider: "google" | "github") => void;
  markdownEnabled: boolean;
  mathjaxEnabled: boolean;
}) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const [canvasInfo, setCanvasInfo] = useState<{
    user_id: string | null;
    name: string | null;
    course_id: string | null;
    course_name: string | null;
    course_code: string | null;
    section_id: string | null;
    section_name: string | null;
    status: string | null;
    enrolled_at: string | null;
    form_title: string | null;
    submission_id: string | null;
    submission_deleted: boolean;
  } | null>(null);

  useEffect(() => {
    if (!user) {
      setLoading(false);
      return;
    }
    let active = true;
    async function loadCanvas() {
      setLoading(true);
      const response = await apiFetch(`${API_BASE}/api/me`);
      const payload = await response.json().catch(() => null);
      if (!active) return;
      if (!response.ok) {
        setError({
          status: response.status,
          requestId: payload?.requestId,
          message: payload?.error || "Request failed"
        });
        setLoading(false);
        return;
      }
      setCanvasInfo(payload?.canvas ?? null);
      setError(null);
      setLoading(false);
    }
    loadCanvas();
    return () => {
      active = false;
    };
  }, [user]);

  if (!user) {
    return (
      <section className="panel panel--error">
        <h2>Sign in required</h2>
        <p>Please sign in to view Canvas details.</p>
        <div className="auth-bar">
          <button type="button" className="btn btn-primary btn-auth" onClick={() => onLogin("google")}>
            <i className="bi bi-google" aria-hidden="true" /> Login with Google
          </button>
          <button type="button" className="btn btn-dark btn-auth" onClick={() => onLogin("github")}>
            <i className="bi bi-github" aria-hidden="true" /> Login with GitHub
          </button>
        </div>
      </section>
    );
  }

  const hasCanvasInfo = Boolean(
    canvasInfo &&
    (canvasInfo.user_id ||
      canvasInfo.course_id ||
      canvasInfo.course_name ||
      canvasInfo.course_code ||
      canvasInfo.section_id ||
      canvasInfo.section_name ||
      canvasInfo.status ||
      canvasInfo.name ||
      canvasInfo.enrolled_at ||
      canvasInfo.form_title)
  );

  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Canvas</h2>
      </div>
      {loading ? <p className="muted">Loading...</p> : null}
      {error ? (
        <div className="alert alert-danger" role="alert">
          {error.message || "Failed to load Canvas."}
        </div>
      ) : null}
      {user.isAdmin ? (
        <div className="alert alert-info">
          Admin view is available in <Link to="/admin/canvas">Admin Canvas</Link>.
        </div>
      ) : null}
      {hasCanvasInfo ? (
        <div className="panel panel--compact">
          <div className="panel-header">
            <h3 className="mb-0">Your Canvas enrollment</h3>
          </div>
          <div className="row g-3">
            {(canvasInfo as any)?.full_name ? (
              <div className="col-md-6">
                <div className="muted">Canvas full name</div>
                <div>{(canvasInfo as any).full_name}</div>
              </div>
            ) : null}
            {(canvasInfo as any)?.display_name ? (
              <div className="col-md-6">
                <div className="muted">Canvas display name</div>
                <div>{(canvasInfo as any).display_name}</div>
              </div>
            ) : null}
            {canvasInfo?.user_id ? (
              <div className="col-md-6">
                <div className="muted">Canvas ID</div>
                <div>{canvasInfo.user_id}</div>
              </div>
            ) : null}
            {canvasInfo?.course_name || canvasInfo?.course_code || canvasInfo?.course_id ? (
              <div className="col-md-6">
                <div className="muted">Registered course</div>
                {canvasInfo?.course_id ? (
                  <a
                    href={`https://canvas.instructure.com/courses/${canvasInfo.course_id}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    {canvasInfo.course_name || canvasInfo.course_code || canvasInfo.course_id}
                  </a>
                ) : (
                  <div>{canvasInfo.course_name || canvasInfo.course_code || canvasInfo.course_id}</div>
                )}
              </div>
            ) : null}
            {canvasInfo?.section_name || canvasInfo?.section_id ? (
              <div className="col-md-6">
                <div className="muted">Section</div>
                <div>{canvasInfo.section_name || canvasInfo.section_id}</div>
              </div>
            ) : null}
            {canvasInfo?.status ? (
              <div className="col-md-6">
                <div className="muted">Enrollment status</div>
                <div>{canvasInfo.status === "deleted" ? "unenrolled" : canvasInfo.status}</div>
              </div>
            ) : null}
            {canvasInfo?.enrolled_at ? (
              <div className="col-md-6">
                <div className="muted">
                  Registered via form{" "}
                  <RichText
                    text={canvasInfo.form_title || "submission"}
                    markdownEnabled={markdownEnabled}
                    mathjaxEnabled={mathjaxEnabled}
                    inline
                  />{" "}
                  at
                </div>
                <div className="d-flex flex-wrap gap-2 align-items-center">
                  <span>{formatTimeICT(canvasInfo.enrolled_at)}</span>
                  {canvasInfo?.submission_id && !canvasInfo.submission_deleted ? (
                    <Link to={`/me/submissions/${canvasInfo.submission_id}`}>
                      View submission
                    </Link>
                  ) : null}
                </div>
              </div>
            ) : null}
          </div>
        </div>
      ) : (
        <div className="muted">No Canvas enrollment found yet.</div>
      )}
    </section>
  );
}

function SubmissionDetailPage({
  user,
  onLogin,
  onNotice,
  markdownEnabled,
  mathjaxEnabled
}: {
  user: UserInfo | null;
  onLogin: (provider: "google" | "github") => void;
  onNotice: (message: string, type?: NoticeType) => void;
  markdownEnabled: boolean;
  mathjaxEnabled: boolean;
}) {
  const { id } = useParams();
  const location = useLocation();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const [data, setData] = useState<any | null>(null);
  const [fieldMeta, setFieldMeta] = useState<
    Record<string, { label: string; type: string; rules?: Record<string, unknown> }>
  >({});
  const [fieldOrder, setFieldOrder] = useState<string[]>([]);
  const [showSubmitNotice, setShowSubmitNotice] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [versionList, setVersionList] = useState<any[]>([]);
  const [versionListLoading, setVersionListLoading] = useState(false);
  const [versionView, setVersionView] = useState<{
    selected: string;
    data: Record<string, unknown> | null;
    createdAt: string | null;
  }>({ selected: "latest", data: null, createdAt: null });
  const [versionError, setVersionError] = useState<string | null>(null);
  const [commentList, setCommentList] = useState<SubmissionComment[]>([]);
  const [commentLoading, setCommentLoading] = useState(false);
  const [commentError, setCommentError] = useState<string | null>(null);
  const [commentDraft, setCommentDraft] = useState("");
  const [commentSaving, setCommentSaving] = useState(false);
  const [commentEditId, setCommentEditId] = useState<string | null>(null);
  const [commentEditDraft, setCommentEditDraft] = useState("");
  const [commentActionError, setCommentActionError] = useState<string | null>(null);
  const [commentReplyToId, setCommentReplyToId] = useState<string | null>(null);
  const [commentQuoteId, setCommentQuoteId] = useState<string | null>(null);
  const [commentPage, setCommentPage] = useState(1);
  const [commentHasMore, setCommentHasMore] = useState(false);
  const renderLabel = (label: string) => (
    <RichText
      text={label}
      markdownEnabled={markdownEnabled}
      mathjaxEnabled={mathjaxEnabled}
      inline
    />
  );
  const renderValue = (value: string) => (
    <RichText text={value} markdownEnabled={markdownEnabled} mathjaxEnabled={mathjaxEnabled} />
  );
  const reminderText = useMemo(() => {
    if (!data?.form?.reminder_enabled) return "";
    const freqText = formatReminderFrequency(data.form.reminder_frequency);
    if (!freqText) return "";
    const untilText = data.form.reminder_until ? formatTimeICT(data.form.reminder_until) : "";
    return untilText
      ? `Reminder: resubmit ${freqText} until ${untilText}.`
      : `Reminder: resubmit ${freqText}.`;
  }, [data]);

  const discussionEnabled = data?.form?.discussion_enabled === true;
  const discussionMarkdownEnabled =
    data?.form?.discussion_markdown_enabled === true || data?.form?.discussion_markdown_enabled == null;
  const discussionHtmlEnabled = data?.form?.discussion_html_enabled === true;
  const discussionMathjaxEnabled = data?.form?.discussion_mathjax_enabled === true;

  const renderCommentBody = (body: string) => (
    <RichText
      text={body}
      markdownEnabled={discussionMarkdownEnabled}
      mathjaxEnabled={discussionMathjaxEnabled}
      allowHtml={discussionHtmlEnabled}
    />
  );

  const discussionSupportLabel =
    discussionMarkdownEnabled || discussionHtmlEnabled || discussionMathjaxEnabled
      ? `Supports${discussionMarkdownEnabled ? " Markdown" : ""}${discussionHtmlEnabled ? " + HTML" : ""}${
          discussionMathjaxEnabled ? " + MathJax" : ""
        }.`
      : "Plain text only.";

  const commentLookup = useMemo(() => {
    const map = new Map<string, SubmissionComment>();
    commentList.forEach((comment) => map.set(comment.id, comment));
    return map;
  }, [commentList]);

  const threadedComments = useMemo(() => {
    const sorted = [...commentList].sort(
      (a, b) => Date.parse(a.created_at) - Date.parse(b.created_at)
    );
    const map = new Map<string, SubmissionComment>();
    sorted.forEach((comment) => map.set(comment.id, { ...comment, replies: [] }));
    const roots: SubmissionComment[] = [];
    map.forEach((comment) => {
      if (comment.parent_comment_id && map.has(comment.parent_comment_id)) {
        map.get(comment.parent_comment_id)!.replies!.push(comment);
      } else {
        roots.push(comment);
      }
    });
    return roots;
  }, [commentList]);

  const renderSubmissionDataTable = (dataObject: Record<string, unknown>) => {
    const orderedKeys = fieldOrder.filter(
      (key) => key in dataObject && fieldMeta[key]?.type !== "file"
    );
    const remainingKeys = Object.keys(dataObject).filter(
      (key) =>
        !orderedKeys.includes(key) &&
        !key.endsWith("__tz") &&
        fieldMeta[key]?.type !== "file"
    );
    const allKeys = [...orderedKeys, ...remainingKeys];
    if (allKeys.length === 0) {
      return (
        <tr>
          <td className="muted">No data</td>
        </tr>
      );
    }
    return allKeys.map((key) => {
      const meta = fieldMeta[key];
      const raw = dataObject[key];
      if (meta?.type === "date" && typeof raw === "string") {
        const rules = meta.rules || {};
        const mode =
          typeof rules.mode === "string" && rules.mode.trim()
            ? rules.mode.trim()
            : "datetime";
        const showTimezone = rules.timezoneOptional !== true;
        const tzKey = `${key}__tz`;
        const tzValue =
          typeof dataObject[tzKey] === "string" && String(dataObject[tzKey]).trim()
            ? String(dataObject[tzKey])
            : typeof rules.timezoneDefault === "string"
              ? String(rules.timezoneDefault)
              : getAppDefaultTimezone();
        const displayValue = raw.endsWith("Z")
          ? mode === "time"
            ? utcToLocalTimeOnly(raw, tzValue)
            : mode === "date"
              ? utcToLocalDateOnly(raw, tzValue)
              : utcToLocalDateTime(raw, tzValue)
          : raw;
        return (
          <tr key={key}>
            <th className="text-nowrap">{renderLabel(meta?.label || key)}</th>
            <td className="text-break">
              <div>{renderValue(displayValue || "n/a")}</div>
              {showTimezone && tzValue ? (
                <div className="muted">Timezone: {tzValue}</div>
              ) : null}
            </td>
          </tr>
        );
      }
      return (
        <tr key={key}>
          <th className="text-nowrap">{renderLabel(meta?.label || key)}</th>
          <td className="text-break">
            {typeof raw === "string"
              ? renderValue(raw)
              : typeof raw === "number" || typeof raw === "boolean"
                ? String(raw)
                : JSON.stringify(raw)}
          </td>
        </tr>
      );
    });
  };

  useEffect(() => {
    if (!user || !id) {
      setLoading(false);
      return;
    }
    let active = true;
    async function loadSubmission() {
      setLoading(true);
      const response = await apiFetch(`${API_BASE}/api/me/submissions/${encodeURIComponent(String(id))}`);
      const payload = await response.json().catch(() => null);
      if (!active) return;
      if (!response.ok) {
        setError({
          status: response.status,
          requestId: payload?.requestId,
          message: payload?.error || "Request failed"
        });
        setLoading(false);
        return;
      }
      setData(payload?.data ?? null);
      setError(null);
      setLoading(false);
    }
    loadSubmission();
    return () => {
      active = false;
    };
  }, [user, id]);

  useEffect(() => {
    if (!data?.submissionId || !data?.form?.save_all_versions) {
      setVersionList([]);
      setVersionListLoading(false);
      setVersionView({ selected: "latest", data: null, createdAt: null });
      setVersionError(null);
      return;
    }
    let active = true;
    async function loadVersions() {
      setVersionListLoading(true);
      setVersionError(null);
      try {
        const response = await apiFetch(
          `${API_BASE}/api/me/submissions/${encodeURIComponent(data.submissionId)}/versions`
        );
        const payload = await response.json().catch(() => null);
        if (!active) return;
        if (!response.ok) {
          setVersionError(payload?.error || "Failed to load versions.");
          setVersionList([]);
          return;
        }
        setVersionList(Array.isArray(payload?.versions) ? payload.versions : []);
      } catch (error) {
        if (!active) return;
        setVersionError(error instanceof Error ? error.message : "Failed to load versions.");
        setVersionList([]);
      } finally {
        if (active) setVersionListLoading(false);
      }
    }
    loadVersions();
    return () => {
      active = false;
    };
  }, [data?.submissionId, data?.form?.save_all_versions]);

  useEffect(() => {
    if (!data?.submissionId || !discussionEnabled) {
      setCommentList([]);
      setCommentLoading(false);
      setCommentError(null);
      setCommentHasMore(false);
      setCommentPage(1);
      return;
    }
    let active = true;
    async function loadComments() {
      setCommentLoading(true);
      setCommentError(null);
      const response = await apiFetch(
        `${API_BASE}/api/me/submissions/${encodeURIComponent(data.submissionId)}/comments?page=${commentPage}&pageSize=20`
      );
      const payload = await response.json().catch(() => null);
      if (!active) return;
      if (!response.ok) {
        setCommentError(payload?.error || "Failed to load comments.");
        setCommentList([]);
        setCommentLoading(false);
        return;
      }
      const incoming = Array.isArray(payload?.comments) ? payload.comments : [];
      setCommentList((prev) => {
        const base = commentPage === 1 ? [] : prev;
        const seen = new Set(base.map((item) => item.id));
        const next = [...base];
        for (const item of incoming) {
          if (!item?.id || seen.has(item.id)) continue;
          seen.add(item.id);
          next.push(item);
        }
        return next;
      });
      setCommentHasMore(Boolean(payload?.hasMore));
      setCommentLoading(false);
    }
    loadComments();
    return () => {
      active = false;
    };
  }, [data?.submissionId, discussionEnabled, commentPage]);

  async function handleVersionViewChange(value: string) {
    setVersionView({ selected: value, data: null, createdAt: null });
    setVersionError(null);
    if (value === "latest") {
      return;
    }
    if (!data?.submissionId) {
      return;
    }
    const response = await apiFetch(
      `${API_BASE}/api/me/submissions/${encodeURIComponent(data.submissionId)}/versions/${encodeURIComponent(value)}`
    );
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setVersionError(payload?.error || "Failed to load version.");
      return;
    }
    const versionData = payload?.data ?? payload?.version?.data ?? null;
    setVersionView({
      selected: value,
      data: versionData && typeof versionData === "object" ? versionData : null,
      createdAt: payload?.version?.created_at || payload?.createdAt || null
    });
  }

  async function handleCommentSubmit() {
    if (!data?.submissionId) return;
    const body = commentDraft.trim();
    if (!body) {
      setCommentActionError("Comment cannot be empty.");
      return;
    }
    setCommentActionError(null);
    setCommentSaving(true);
    const response = await apiFetch(
      `${API_BASE}/api/me/submissions/${encodeURIComponent(data.submissionId)}/comments`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          body,
          parentCommentId: commentReplyToId,
          quoteCommentId: commentQuoteId
        })
      }
    );
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setCommentActionError(payload?.error || "Failed to post comment.");
      setCommentSaving(false);
      return;
    }
    setCommentDraft("");
    setCommentReplyToId(null);
    setCommentQuoteId(null);
    if (commentPage !== 1) {
      setCommentPage(1);
    }
    setCommentList(Array.isArray(payload?.comments) ? payload.comments : commentList);
    setCommentSaving(false);
  }

  async function handleCommentEditSave(commentId: string) {
    if (!data?.submissionId) return;
    const body = commentEditDraft.trim();
    if (!body) {
      setCommentActionError("Comment cannot be empty.");
      return;
    }
    setCommentActionError(null);
    setCommentSaving(true);
    const response = await apiFetch(
      `${API_BASE}/api/me/submissions/${encodeURIComponent(data.submissionId)}/comments/${encodeURIComponent(
        commentId
      )}`,
      {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ body })
      }
    );
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setCommentActionError(payload?.error || "Failed to update comment.");
      setCommentSaving(false);
      return;
    }
    setCommentEditId(null);
    setCommentEditDraft("");
    if (commentPage !== 1) {
      setCommentPage(1);
    }
    setCommentList(Array.isArray(payload?.comments) ? payload.comments : commentList);
    setCommentSaving(false);
  }

  async function handleCommentDelete(commentId: string) {
    if (!data?.submissionId) return;
    if (!window.confirm("Delete this comment?")) return;
    setCommentActionError(null);
    const response = await apiFetch(
      `${API_BASE}/api/me/submissions/${encodeURIComponent(data.submissionId)}/comments/${encodeURIComponent(
        commentId
      )}`,
      { method: "DELETE" }
    );
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setCommentActionError(payload?.error || "Failed to delete comment.");
      return;
    }
    if (commentPage !== 1) {
      setCommentPage(1);
    }
    setCommentList(Array.isArray(payload?.comments) ? payload.comments : commentList);
  }

  async function handleCommentRestore(commentId: string) {
    if (!data?.submissionId) return;
    setCommentActionError(null);
    const response = await apiFetch(
      `${API_BASE}/api/me/submissions/${encodeURIComponent(data.submissionId)}/comments/${encodeURIComponent(
        commentId
      )}/restore`,
      { method: "POST" }
    );
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setCommentActionError(payload?.error || "Failed to restore comment.");
      return;
    }
    if (commentPage !== 1) {
      setCommentPage(1);
    }
    setCommentList(Array.isArray(payload?.comments) ? payload.comments : commentList);
  }

  async function handleCommentPurge(commentId: string) {
    if (!data?.submissionId) return;
    if (!window.confirm("Permanently delete this comment? This cannot be undone.")) return;
    setCommentActionError(null);
    const response = await apiFetch(
      `${API_BASE}/api/me/submissions/${encodeURIComponent(data.submissionId)}/comments/${encodeURIComponent(
        commentId
      )}/purge`,
      { method: "POST" }
    );
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setCommentActionError(payload?.error || "Failed to purge comment.");
      return;
    }
    if (commentPage !== 1) {
      setCommentPage(1);
    }
    setCommentList(Array.isArray(payload?.comments) ? payload.comments : commentList);
  }

  async function handleDeleteSubmission() {
    if (!data?.form?.slug) return;
    setDeleteError(null);
    const confirmMessage = data.form?.canvas_enabled
      ? "Move this submission to trash? This will deactivate your Canvas enrollment for this course."
      : "Move this submission to trash?";
    if (!window.confirm(confirmMessage)) {
      return;
    }
    const response = await apiFetch(
      `${API_BASE}/api/me/submission?formSlug=${encodeURIComponent(data.form.slug)}`,
      { method: "DELETE" }
    );
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setDeleteError(payload?.error || "Failed to delete submission.");
      return;
    }
    if (data.form?.canvas_enabled && payload?.canvasAction) {
      const canvasLabel =
        payload.canvasAction === "deactivated"
          ? "deactivated"
          : payload.canvasAction === "failed"
            ? "failed"
            : "skipped";
      onNotice(
        `Submission deleted. Canvas deactivation: ${canvasLabel}.`,
        payload.canvasAction === "failed" ? "warning" : "success"
      );
    } else {
      onNotice("Submission deleted.", "success");
    }
    navigate("/me");
  }

  function resolveSelectedSubmissionData() {
    const selectedIsLatest = versionView.selected === "latest" || !data?.form?.save_all_versions;
    const selectedData = selectedIsLatest ? data?.data_json : versionView.data;
    return {
      selectedIsLatest,
      selectedData:
        selectedData && typeof selectedData === "object" && !Array.isArray(selectedData)
          ? (selectedData as Record<string, unknown>)
          : null
    };
  }

  function handleExportSubmission(format: SubmissionExportFormat) {
    if (!data) return;
    const selection = resolveSelectedSubmissionData();
    const versionLabel = selection.selectedIsLatest
      ? "latest"
      : versionView.selected
        ? `version ${versionView.selected}`
        : "version";
    const exportPayload = buildSubmissionExportContent({
      submission: data,
      dataValues: selection.selectedData,
      fieldMeta,
      fieldOrder,
      format,
      versionLabel
    });
    downloadTextFile(exportPayload.filename, exportPayload.content, exportPayload.mimeType);
  }

  useEffect(() => {
    if (!data?.form?.slug) {
      setFieldMeta({});
      setFieldOrder([]);
      return;
    }
    let active = true;
    async function loadFormLabels() {
      const response = await apiFetch(`${API_BASE}/api/forms/${encodeURIComponent(data.form.slug)}`);
      const payload = await response.json().catch(() => null);
      if (!active) return;
      if (!response.ok) {
        setFieldMeta({});
        setFieldOrder([]);
        return;
      }
      const fields = Array.isArray(payload?.data?.fields) ? payload.data.fields : [];
      const { meta, order } = buildFieldMetaFromSchema(fields);
      setFieldMeta(meta);
      setFieldOrder(order);
    }
    loadFormLabels();
    return () => {
      active = false;
    };
  }, [data?.form?.slug]);

  const submittedName =
    data?.data_json && typeof data.data_json === "object"
      ? pickNameFromData(data.data_json as Record<string, unknown>)
      : "";
  const canvasFullName =
    data?.canvas && typeof data.canvas.full_name === "string" ? data.canvas.full_name.trim() : "";
  const canvasDisplayName =
    data?.canvas && typeof data.canvas.display_name === "string"
      ? data.canvas.display_name.trim()
      : "";
  const isCanvasInvited = data?.canvas?.status === "invited";
  const isCanvasDeleted = data?.canvas?.status === "deleted";
  const isCanvasNameMissing =
    isCanvasInvited && !isCanvasDeleted && submittedName && (!canvasFullName || !canvasDisplayName);
  const hasNameMismatch =
    isCanvasInvited &&
    !isCanvasDeleted &&
    submittedName &&
    canvasFullName &&
    canvasDisplayName &&
    (normalizeNameValue(submittedName) !== normalizeNameValue(canvasFullName) ||
      normalizeNameValue(submittedName) !== normalizeNameValue(canvasDisplayName));

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const submitted = params.get("submitted") === "1";
    if (!submitted) {
      setShowSubmitNotice(false);
      return;
    }
    setShowSubmitNotice(true);
    const timer = window.setTimeout(() => {
      setShowSubmitNotice(false);
      navigate(location.pathname, { replace: true });
    }, 10000);
    return () => {
      window.clearTimeout(timer);
    };
  }, [location.pathname, location.search, navigate]);

  if (!user) {
    return (
      <section className="panel panel--error">
        <h2>Sign in required</h2>
        <p>Please sign in to view your submission.</p>
        <div className="auth-bar">
          <button type="button" className="btn btn-primary btn-auth" onClick={() => onLogin("google")}>
            <i className="bi bi-google" aria-hidden="true" /> Login with Google
          </button>
          <button type="button" className="btn btn-dark btn-auth" onClick={() => onLogin("github")}>
            <i className="bi bi-github" aria-hidden="true" /> Login with GitHub
          </button>
        </div>
      </section>
    );
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <h2>My Submission</h2>
      </div>
      {loading ? <p className="muted">Loading...</p> : null}
      {error ? (
        <div className="alert alert-danger" role="alert">
          {error.message || "Failed to load submission."}
        </div>
      ) : null}
      {showSubmitNotice ? (
        <div className="alert alert-success" role="alert">
          <div className="fw-semibold">Your submission was saved.</div>
          {data?.canvas?.status === "invited" ? (
            <div className="mt-1">
              Your Canvas enrollment is invited. Please check your email to accept the invitation.
            </div>
          ) : null}
          {data?.canvas?.status === "deactivated" ? (
            <div className="mt-1">
              Your Canvas enrollment is deactivated. Contact the administrator if you need access
              restored.
            </div>
          ) : null}
        </div>
      ) : null}
      {deleteError ? <div className="alert alert-danger">{deleteError}</div> : null}
      {data ? (
        <div className="panel panel--compact">
          <div className="d-flex justify-content-between align-items-center mb-2">
            <div>
              <div className="muted">Form</div>
              <div className="fw-semibold">{data.form?.title || data.form?.slug || "Form"}</div>
              {data.form?.slug ? <div className="muted">{data.form.slug}</div> : null}
            </div>
            <div className="d-flex flex-wrap gap-2">
              <div className="btn-group">
                <button
                  type="button"
                  className="btn btn-outline-secondary btn-sm"
                  onClick={() => handleExportSubmission("markdown")}
                >
                  <i className="bi bi-download" aria-hidden="true" /> Export Markdown
                </button>
                <button
                  type="button"
                  className="btn btn-outline-secondary btn-sm"
                  onClick={() => handleExportSubmission("txt")}
                >
                  <i className="bi bi-download" aria-hidden="true" /> Export TXT
                </button>
                <button
                  type="button"
                  className="btn btn-outline-secondary btn-sm"
                  onClick={() => handleExportSubmission("csv")}
                >
                  <i className="bi bi-download" aria-hidden="true" /> Export CSV
                </button>
              </div>
              <Link className="btn btn-outline-primary btn-sm" to={`/f/${data.form?.slug || ""}`}>
                <i className="bi bi-box-arrow-up-right" aria-hidden="true" /> Open form
              </Link>
              <button type="button" className="btn btn-outline-danger btn-sm" onClick={handleDeleteSubmission}>
                <i className="bi bi-trash" aria-hidden="true" /> Delete
              </button>
            </div>
          </div>
          <div className="muted">
            Submitted: {data.created_at ? formatTimeICT(data.created_at) : "n/a"}
          </div>
          <div className="muted">
            Updated: {data.updated_at ? formatTimeICT(data.updated_at) : "n/a"}
          </div>
          {reminderText ? (
            <div className="alert alert-info mt-2 mb-0">
              <i className="bi bi-info-circle" aria-hidden="true" /> {reminderText}
            </div>
          ) : null}
          {data.canvas?.status ? (
            <div className="muted">
              Canvas enrollment: {data.canvas.status === "deleted" ? "unenrolled" : data.canvas.status}
              {data.canvas.error &&
                data.canvas.status !== "deactivated" &&
                data.canvas.status !== "deleted" &&
                data.canvas.status !== "invited"
                ? ` (${data.canvas.error})`
                : ""}
            </div>
          ) : null}
          {data.canvas?.status ? (
            <div className="muted">
              Canvas full name: {canvasFullName || "n/a"} · Canvas display name:{" "}
              {canvasDisplayName || "n/a"}
            </div>
          ) : null}
          {hasNameMismatch || isCanvasNameMissing ? (
            <div className="alert alert-warning mt-2">
              <i className="bi bi-exclamation-triangle" aria-hidden="true" /> Your Canvas display
              name{" "}
              {canvasFullName || canvasDisplayName ? (
                <>
                  differs from the submitted full name <strong>{submittedName}</strong>. Canvas
                  full name: <strong>{canvasFullName || "n/a"}</strong>. Canvas display name:{" "}
                  <strong>{canvasDisplayName || "n/a"}</strong>.
                </>
              ) : (
                <>is missing.</>
              )}{" "}
              Please update your Canvas display name to match your submitted full name.
            </div>
          ) : null}
          {data.form?.save_all_versions ? (
            <div className="mt-3">
              <div className="muted mb-2">Version viewer</div>
              <div className="form-group">
                <label htmlFor="submission-version-viewer">Select version to view:</label>
                <select
                  id="submission-version-viewer"
                  className="form-control"
                  value={versionView.selected}
                  onChange={(event) => handleVersionViewChange(event.target.value)}
                  disabled={versionListLoading || versionList.length === 0}
                >
                  <option value="latest">Latest submission</option>
                  {versionList.map((v) => (
                    <option key={v.version_number} value={String(v.version_number)}>
                      Version {v.version_number} (submitted {v.created_at ? formatTimeICT(v.created_at) : "n/a"})
                    </option>
                  ))}
                </select>
                {versionListLoading ? <small className="text-muted">Loading versions...</small> : null}
                {!versionListLoading && versionList.length === 0 ? (
                  <small className="text-muted">No previous versions yet.</small>
                ) : null}
                {versionError ? <div className="alert alert-warning mt-2">{versionError}</div> : null}
              </div>
            </div>
          ) : null}
          <div className="mt-3">
            <div className="muted mb-2">Data</div>
            {(() => {
              const selection = resolveSelectedSubmissionData();
              return selection.selectedData ? (
                <div className="table-responsive">
                  <table className="table table-sm">
                    <tbody>
                      {renderSubmissionDataTable(selection.selectedData)}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="muted">No data</div>
              );
            })()}
            {data.form?.save_all_versions && versionView.selected !== "latest" && versionView.createdAt ? (
              <div className="muted mt-1">Version submitted: {formatTimeICT(versionView.createdAt)}</div>
            ) : null}
          </div>
          <div className="mt-3">
            <div className="muted mb-2">Files</div>
            {Array.isArray(data.files) && data.files.length > 0 ? (
              <div className="table-responsive">
                <table className="table table-sm">
                  <thead>
                    <tr>
                      <th>Field</th>
                      <th>File</th>
                      <th>Size</th>
                      <th>VirusTotal</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.files.map((file: any) => (
                      <tr key={file.id}>
                        <td>{renderLabel(fieldMeta[file.field_id]?.label || file.field_id)}</td>
                        <td className="text-break">{file.original_name}</td>
                        <td>{typeof file.size_bytes === "number" ? formatSize(file.size_bytes) : "n/a"}</td>
                        <td>
                          {(() => {
                            const statusLabel = file.vt_status || "pending";
                            const verdictLabel = file.vt_verdict || null;
                            const reportUrl = file.sha256
                              ? `https://www.virustotal.com/gui/file/${file.sha256}`
                              : null;
                            return (
                              <>
                                {reportUrl ? (
                                  <a href={reportUrl} target="_blank" rel="noreferrer">
                                    <span className={`badge ${getVtBadgeClass(statusLabel)}`}>
                                      <i className={`bi ${getVtStatusIcon(statusLabel)}`} aria-hidden="true" />{" "}
                                      {statusLabel}
                                    </span>
                                  </a>
                                ) : (
                                  <span className={`badge ${getVtBadgeClass(statusLabel)}`}>
                                    <i className={`bi ${getVtStatusIcon(statusLabel)}`} aria-hidden="true" />{" "}
                                    {statusLabel}
                                  </span>
                                )}
                                {verdictLabel && verdictLabel !== statusLabel ? (
                                  <span className="ms-2 text-muted">({verdictLabel})</span>
                                ) : null}
                              </>
                            );
                          })()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="muted">No files uploaded</div>
            )}
            <div className="alert alert-info mt-2 mb-0">
              <i className="bi bi-info-circle" aria-hidden="true" /> To change any details or
              manage uploaded files, open the form and update your submission.
            </div>
          </div>
          {discussionEnabled ? (
            <div className="mt-3">
              <div className="muted mb-2">Discussion</div>
              {commentError ? <div className="alert alert-danger">{commentError}</div> : null}
              {commentActionError ? <div className="alert alert-danger">{commentActionError}</div> : null}
              {commentLoading ? (
                <div className="muted">Loading discussion...</div>
              ) : threadedComments.length === 0 ? (
                <div className="muted">No comments yet.</div>
              ) : (
                <div className="d-flex flex-column gap-3">
                  {threadedComments.map((comment) => {
                    const renderComment = (item: SubmissionComment, depth: number) => {
                      const isDeleted = !!item.deleted_at;
                      const isEditing = commentEditId === item.id;
                      const authorLabel =
                        item.author_role === "admin"
                          ? "Admin"
                          : item.author_user_id === user?.userId
                            ? "You"
                            : "User";
                      const authorMeta =
                        item.author_role === "admin" && (item.author_email || item.author_login)
                          ? ` · ${item.author_email || item.author_login}`
                          : "";
                      const edited = item.updated_at && item.updated_at !== item.created_at;
                      const editedLabel = edited ? " · edited" : "";
                          const editedTitle = edited ? `Edited at ${formatTimeICT(item.updated_at)}` : "";
                      const quote =
                        item.quote_comment_id && commentLookup.has(item.quote_comment_id)
                          ? commentLookup.get(item.quote_comment_id)!
                          : null;
                      const quoteLabel = quote
                        ? quote.author_role === "admin"
                          ? "Admin"
                          : quote.author_user_id === user?.userId
                            ? "You"
                            : "User"
                        : "";
                      return (
                        <div
                          key={item.id}
                          className={`card ${isDeleted ? "border-warning" : ""}`}
                          style={depth > 0 ? { marginLeft: `${depth * 1.5}rem` } : undefined}
                        >
                          <div className="card-body">
                            <div className="d-flex justify-content-between flex-wrap gap-2">
                              <div>
                                <div className="fw-semibold">
                                  {authorLabel}
                                  {authorMeta}
                                </div>
                                <div className="muted" title={editedTitle}>
                                  {formatTimeICT(item.created_at)}
                                  {editedLabel}
                                  {isDeleted ? " · deleted" : ""}
                                </div>
                              </div>
                              <div className="d-flex gap-2 flex-wrap">
                                {!isDeleted ? (
                                  <button
                                    type="button"
                                    className="btn btn-outline-secondary btn-sm"
                                    onClick={() => {
                                      setCommentReplyToId(item.id);
                                      setCommentQuoteId(null);
                                      setCommentDraft("");
                                    }}
                                  >
                                    <i className="bi bi-reply" aria-hidden="true" /> Reply
                                  </button>
                                ) : null}
                                {!isDeleted ? (
                                  <button
                                    type="button"
                                    className="btn btn-outline-secondary btn-sm"
                                    onClick={() => {
                                      setCommentReplyToId(item.id);
                                      setCommentQuoteId(item.id);
                                      setCommentDraft("");
                                    }}
                                  >
                                    <i className="bi bi-quote" aria-hidden="true" /> Quote
                                  </button>
                                ) : null}
                                {item.can_edit && !isDeleted ? (
                                  <button
                                    type="button"
                                    className="btn btn-outline-secondary btn-sm"
                                    disabled={commentSaving}
                                    onClick={() => {
                                      setCommentEditId(item.id);
                                      setCommentEditDraft(item.body);
                                    }}
                                  >
                                    <i className="bi bi-pencil" aria-hidden="true" /> Edit
                                  </button>
                                ) : null}
                                {item.can_delete && !isDeleted ? (
                                  <button
                                    type="button"
                                    className="btn btn-outline-danger btn-sm"
                                    onClick={() => handleCommentDelete(item.id)}
                                  >
                                    <i className="bi bi-trash" aria-hidden="true" /> Delete
                                  </button>
                                ) : null}
                                {item.can_restore && isDeleted ? (
                                  <button
                                    type="button"
                                    className="btn btn-outline-primary btn-sm"
                                    onClick={() => handleCommentRestore(item.id)}
                                  >
                                    <i className="bi bi-arrow-counterclockwise" aria-hidden="true" /> Restore
                                  </button>
                                ) : null}
                                {item.can_purge && isDeleted ? (
                                  <button
                                    type="button"
                                    className="btn btn-outline-danger btn-sm"
                                    onClick={() => handleCommentPurge(item.id)}
                                  >
                                    <i className="bi bi-x-circle" aria-hidden="true" /> Purge
                                  </button>
                                ) : null}
                              </div>
                            </div>
                            {quote ? (
                              <div className="alert alert-light mt-2 mb-2">
                                <div className="muted mb-1">Quoted from {quoteLabel}</div>
                                {renderCommentBody(quote.body)}
                              </div>
                            ) : null}
                            {isEditing ? (
                              <div className="mt-3">
                                <textarea
                                  className="form-control"
                                  rows={4}
                                  value={commentEditDraft}
                                  onChange={(event) => setCommentEditDraft(event.target.value)}
                                  disabled={commentSaving}
                                />
                                <div className="d-flex gap-2 mt-2">
                                  <button
                                    type="button"
                                    className="btn btn-primary btn-sm"
                                    disabled={commentSaving}
                                    onClick={() => handleCommentEditSave(item.id)}
                                  >
                                    <i className="bi bi-check-lg" aria-hidden="true" /> Save
                                  </button>
                                  <button
                                    type="button"
                                    className="btn btn-outline-secondary btn-sm"
                                    disabled={commentSaving}
                                    onClick={() => {
                                      setCommentEditId(null);
                                      setCommentEditDraft("");
                                    }}
                                  >
                                    Cancel
                                  </button>
                                </div>
                              </div>
                            ) : (
                              <div className="mt-2">{renderCommentBody(item.body)}</div>
                            )}
                            {isDeleted ? (
                              <div className="muted mt-2">
                                Deleted{" "}
                                {item.deleted_by ? `by ${item.deleted_by} ` : ""}at{" "}
                                {item.deleted_at ? formatTimeICT(item.deleted_at) : "n/a"}.
                                {item.deleted_reason ? ` ${item.deleted_reason}` : ""}
                              </div>
                            ) : null}
                          </div>
                          {item.replies && item.replies.length > 0 ? (
                            <div className="mt-2">
                              {item.replies.map((child) => renderComment(child, depth + 1))}
                            </div>
                          ) : null}
                        </div>
                      );
                    };
                    return renderComment(comment, 0);
                  })}
                </div>
              )}
              {commentHasMore ? (
                <button
                  type="button"
                  className="btn btn-outline-secondary btn-sm mt-2"
                  disabled={commentLoading}
                  onClick={() => setCommentPage((prev) => prev + 1)}
                >
                  Load more
                </button>
              ) : null}
              <div className="mt-3">
                <label htmlFor="comment-editor" className="form-label">
                  Add a comment
                </label>
                <div className="muted mb-2">{discussionSupportLabel}</div>
                {commentReplyToId ? (
                  <div className="alert alert-light py-2">
                    Replying to{" "}
                    {commentLookup.get(commentReplyToId)?.author_role === "admin"
                      ? "Admin"
                      : commentLookup.get(commentReplyToId)?.author_user_id === user?.userId
                        ? "You"
                        : "User"}
                    {commentQuoteId ? " (quoted)" : ""}
                    <button
                      type="button"
                      className="btn btn-link btn-sm ms-2"
                      onClick={() => {
                        setCommentReplyToId(null);
                        setCommentQuoteId(null);
                      }}
                    >
                      Clear
                    </button>
                  </div>
                ) : null}
                <textarea
                  id="comment-editor"
                  className="form-control"
                  rows={4}
                  value={commentDraft}
                  onChange={(event) => setCommentDraft(event.target.value)}
                  disabled={commentSaving}
                />
                {commentDraft.trim() ? (
                  <div className="mt-2">
                    <div className="muted">Preview</div>
                    {renderCommentBody(commentDraft)}
                  </div>
                ) : null}
                <div className="d-flex gap-2 mt-2">
                  <button
                    type="button"
                    className="btn btn-primary btn-sm"
                    disabled={commentSaving || !commentDraft.trim()}
                    onClick={handleCommentSubmit}
                  >
                    <i className="bi bi-chat-dots" aria-hidden="true" /> Post
                  </button>
                  <button
                    type="button"
                    className="btn btn-outline-secondary btn-sm"
                    disabled={commentSaving || !commentDraft.trim()}
                    onClick={() => setCommentDraft("")}
                  >
                    Clear
                  </button>
                </div>
              </div>
            </div>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}

function AdminCanvasPage({
  user,
  onLogin,
  onNotice,
  appDefaultTimezone,
  onUpdateDefaultTimezone,
  markdownEnabled,
  mathjaxEnabled
}: {
  user: UserInfo | null;
  onLogin: (p: "google" | "github") => void;
  onNotice: (message: string, type?: NoticeType) => void;
  appDefaultTimezone: string;
  onUpdateDefaultTimezone: (tz: string) => Promise<boolean>;
  markdownEnabled: boolean;
  mathjaxEnabled: boolean;
}) {
  const [status, setStatus] = useState<"loading" | "ok" | "forbidden">("loading");
  const [courses, setCourses] = useState<any[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [testStatus, setTestStatus] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<string | null>(null);
  const [lookupQuery, setLookupQuery] = useState("");
  const [forms, setForms] = useState<any[]>([]);
  const [templates, setTemplates] = useState<any[]>([]);
  const [users, setUsers] = useState<any[]>([]);
  const [uploads, setUploads] = useState<any[]>([]);
  const [routines, setRoutines] = useState<any[]>([]);
  const [healthSummary, setHealthSummary] = useState<any[]>([]);
  const [healthHistory, setHealthHistory] = useState<any[]>([]);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [routineEdits, setRoutineEdits] = useState<Record<string, { cron: string; enabled: boolean }>>(
    {}
  );
  const [routineStatus, setRoutineStatus] = useState<string | null>(null);
  const [routineLogs, setRoutineLogs] = useState<any[]>([]);
  const [activeRoutineLogId, setActiveRoutineLogId] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<string | null>(null);
  const [selectedSlug, setSelectedSlug] = useState<string>("");
  const [format, setFormat] = useState<"csv" | "txt">("csv");
  const [mode, setMode] = useState<"flat" | "json">("flat");
  const [includeMeta, setIncludeMeta] = useState(true);
  const [maxRows, setMaxRows] = useState(5000);
  const [exportFieldOptions, setExportFieldOptions] = useState<string[]>([]);
  const [selectedExportFields, setSelectedExportFields] = useState<Set<string>>(new Set());
  const [exportFieldFilter, setExportFieldFilter] = useState("");
  const [exportFieldLabels, setExportFieldLabels] = useState<Record<string, string>>({});
  const [copyStatus, setCopyStatus] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [uploadActionError, setUploadActionError] = useState<string | null>(null);
  const [settingsTimezone, setSettingsTimezone] = useState(appDefaultTimezone);
  const [lookupCourseId, setLookupCourseId] = useState("");
  const [lookupResult, setLookupResult] = useState<any[]>([]);
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [lookupLoading, setLookupLoading] = useState(false);
  const [retryQueue, setRetryQueue] = useState<any[]>([]);
  const [deadletters, setDeadletters] = useState<any[]>([]);
  const [retryError, setRetryError] = useState<string | null>(null);
  const [retryLoading, setRetryLoading] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [enrollName, setEnrollName] = useState("");
  const [enrollEmail, setEnrollEmail] = useState("");
  const [enrollRole, setEnrollRole] = useState("student");
  const [enrollCourseId, setEnrollCourseId] = useState("");
  const [enrollSectionId, setEnrollSectionId] = useState("");
  const [enrollSections, setEnrollSections] = useState<any[]>([]);
  const [enrollLoading, setEnrollLoading] = useState(false);
  const [canvasSyncMode, setCanvasSyncMode] = useState<"active" | "concluded" | "all">("active");
  const [canvasSyncSaving, setCanvasSyncSaving] = useState(false);
  const isMountedRef = useRef(true);

  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  async function refreshCanvasOverview(showLoading: boolean) {
    if (showLoading) {
      setStatus("loading");
    }
    const [overviewRes, retryRes] = await Promise.all([
      apiFetch(`${API_BASE}/api/admin/canvas/overview`),
      apiFetch(`${API_BASE}/api/admin/canvas/retry-queue?limit=100`)
    ]);
    const payload = await overviewRes.json().catch(() => null);
    const retryPayload = await retryRes.json().catch(() => null);
    if (!isMountedRef.current) return;
    if (overviewRes.status === 401 || overviewRes.status === 403) {
      setStatus("forbidden");
      return;
    }
    if (!overviewRes.ok) {
      setError(payload?.error || "Failed to load Canvas overview.");
      setStatus("ok");
      return;
    }
    setCourses(Array.isArray(payload?.data) ? payload.data : []);
    if (retryRes.ok) {
      setRetryQueue(Array.isArray(retryPayload?.queue) ? retryPayload.queue : []);
      setDeadletters(Array.isArray(retryPayload?.deadletters) ? retryPayload.deadletters : []);
      setRetryError(null);
    } else {
      setRetryError(retryPayload?.error || "Failed to load retry queue.");
    }
    setError(null);
    setActionError(null);
    setStatus("ok");
  }

  useEffect(() => {
    refreshCanvasOverview(true);
  }, []);

  useEffect(() => {
    let active = true;
    (async () => {
      const response = await apiFetch(`${API_BASE}/api/settings`);
      const payload = await response.json().catch(() => null);
      if (!active) return;
      if (response.ok) {
        const mode = payload?.canvasCourseSyncMode;
        if (mode === "active" || mode === "concluded" || mode === "all") {
          setCanvasSyncMode(mode);
        }
      }
    })();
    return () => {
      active = false;
    };
  }, []);

  async function handleCanvasSync() {
    setSyncing(true);
    setActionError(null);
    const response = await apiFetch(`${API_BASE}/api/admin/canvas/sync`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ mode: "all" })
    });
    const payload = await response.json().catch(() => null);
    setSyncing(false);
    if (!response.ok) {
      setActionError(payload?.error || "Canvas sync failed.");
      onNotice("Canvas sync failed.", "error");
      return;
    }
    onNotice("Canvas sync complete.", "success");
    await refreshCanvasOverview(false);
  }

  useEffect(() => {
    if (courses.length === 0) {
      setLookupCourseId("");
    }
  }, [courses.length]);

  useEffect(() => {
    if (!enrollCourseId) {
      setEnrollSections([]);
      setEnrollSectionId("");
      return;
    }
    let active = true;
    (async () => {
      const response = await apiFetch(
        `${API_BASE}/api/admin/canvas/courses/${encodeURIComponent(enrollCourseId)}/sections?page=1&pageSize=200`
      );
      const payload = await response.json().catch(() => null);
      if (!active) return;
      if (!response.ok) {
        setEnrollSections([]);
        return;
      }
      let items = Array.isArray(payload?.data) ? payload.data : [];
      if (items.length === 0) {
        await apiFetch(`${API_BASE}/api/admin/canvas/sync`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ mode: "course_sections", courseId: enrollCourseId })
        });
        const refresh = await apiFetch(
          `${API_BASE}/api/admin/canvas/courses/${encodeURIComponent(
            enrollCourseId
          )}/sections?page=1&pageSize=200`
        );
        const refreshPayload = await refresh.json().catch(() => null);
        if (!active) return;
        if (refresh.ok) {
          items = Array.isArray(refreshPayload?.data) ? refreshPayload.data : [];
        }
      }
      setEnrollSections(items);
      if (!items.find((item: any) => String(item.id) === enrollSectionId)) {
        setEnrollSectionId("");
      }
    })();
    return () => {
      active = false;
    };
  }, [enrollCourseId, enrollSectionId]);



  async function handleRegistrationAction(
    submissionId: string,
    task: "deactivate" | "delete" | "reactivate"
  ) {
    setActionError(null);
    if (
      task === "delete" &&
      !window.confirm("Remove this user from the course? This action cannot be undone.")
    ) {
      return;
    }
    const response = await apiFetch(
      `${API_BASE}/api/admin/canvas/registrations/${encodeURIComponent(submissionId)}/${task}`,
      { method: "POST" }
    );
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      const detailMessage =
        payload?.detail?.message ||
        payload?.detail?.field ||
        (typeof payload?.detail === "string" ? payload.detail : null);
      setActionError(
        detailMessage
          ? `${payload?.error || "Failed to update enrollment"}: ${detailMessage}`
          : payload?.error || "Failed to update enrollment."
      );
      return;
    }
    onNotice(
      task === "delete"
        ? "Enrollment deleted."
        : task === "reactivate"
          ? "Enrollment reactivated."
          : "Enrollment deactivated.",
      "success"
    );
    setCourses((prev) =>
      prev.map((course) => ({
        ...course,
        registrations: Array.isArray(course.registrations)
          ? course.registrations.map((reg: any) =>
            reg.submission_id === submissionId
              ? {
                ...reg,
                status:
                  task === "delete"
                    ? "deleted"
                    : task === "reactivate"
                      ? "invited"
                      : "deactivated"
              }
              : reg
          )
          : course.registrations
      }))
    );
  }

  async function handleRegistrationReinvite(submissionId: string) {
    setActionError(null);
    const response = await apiFetch(
      `${API_BASE}/api/admin/canvas/registrations/${encodeURIComponent(submissionId)}/reinvite`,
      { method: "POST" }
    );
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      const detailMessage =
        payload?.detail?.message ||
        payload?.detail?.field ||
        (typeof payload?.detail === "string" ? payload.detail : null);
      setActionError(
        detailMessage
          ? `${payload?.error || "Failed to reinvite user"}: ${detailMessage}`
          : payload?.error || "Failed to reinvite user."
      );
      return;
    }
    onNotice("Reinvite message is sent.", "success");
    setCourses((prev) =>
      prev.map((course) => ({
        ...course,
        registrations: Array.isArray(course.registrations)
          ? course.registrations.map((reg: any) =>
            reg.submission_id === submissionId
              ? { ...reg, status: payload?.status || "invited", error: payload?.error || null }
              : reg
          )
          : course.registrations
      }))
    );
  }

  async function handleRegistrationNotify(submissionId: string) {
    setActionError(null);
    const response = await apiFetch(
      `${API_BASE}/api/admin/canvas/registrations/${encodeURIComponent(submissionId)}/notify`,
      { method: "POST" }
    );
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      const detailMessage =
        payload?.detail?.message ||
        payload?.detail?.field ||
        (typeof payload?.detail === "string" ? payload.detail : null);
      setActionError(
        detailMessage
          ? `${payload?.error || "Failed to notify user"}: ${detailMessage}`
          : payload?.error || "Failed to notify user."
      );
      return;
    }
    onNotice("Alert message is sent.", "success");
  }

  async function handleRetryAction(
    entryId: string,
    action: "retry" | "drop",
    source: "queue" | "deadletter"
  ) {
    setRetryError(null);
    setRetryLoading(true);
    const response = await apiFetch(
      `${API_BASE}/api/admin/canvas/retry-queue/${encodeURIComponent(entryId)}/${action}?source=${source}`,
      { method: "POST" }
    );
    const payload = await response.json().catch(() => null);
    setRetryLoading(false);
    if (!response.ok) {
      setRetryError(payload?.error || "Action failed.");
      return;
    }
    onNotice(action === "retry" ? "Retry queued." : "Entry removed.", "success");
    if (action === "drop") {
      if (source === "queue") {
        setRetryQueue((prev) => prev.filter((item) => item.id !== entryId));
      } else {
        setDeadletters((prev) => prev.filter((item) => item.id !== entryId));
      }
    } else if (source === "deadletter") {
      setDeadletters((prev) => prev.filter((item) => item.id !== entryId));
    }
  }

  if (status === "loading") {
    return (
      <section className="panel">
        <h2>Loading Canvas...</h2>
      </section>
    );
  }

  if (status === "forbidden") {
    return (
      <section className="panel panel--error">
        <h2>Not authorized</h2>
        <p>Please sign in with an admin account.</p>
        <div className="auth-bar">
          <button type="button" className="btn btn-primary btn-auth" onClick={() => onLogin("google")}>
            <i className="bi bi-google" aria-hidden="true" /> Login with Google
          </button>
          <button type="button" className="btn btn-dark btn-auth" onClick={() => onLogin("github")}>
            <i className="bi bi-github" aria-hidden="true" /> Login with GitHub
          </button>
        </div>
      </section>
    );
  }

  return (
    <section className="panel admin-scope">
      <div className="panel-header">
        <div>
          <h2>Canvas</h2>
          {user ? <span className="badge">{getUserDisplayName(user)}</span> : null}
        </div>
        <button
          type="button"
          className="btn btn-outline-primary btn-sm"
          onClick={handleCanvasSync}
          disabled={syncing}
        >
          <i className="bi bi-arrow-repeat" aria-hidden="true" />{" "}
          {syncing ? "Syncing..." : "Sync Canvas"}
        </button>
      </div>
      {error ? <div className="alert alert-warning">{error}</div> : null}
      {actionError ? <div className="alert alert-warning">{actionError}</div> : null}
      <div className="panel panel--compact mb-3">
        <div className="panel-header">
          <h3 className="mb-0">Canvas settings</h3>
        </div>
        <div className="row g-3 align-items-end">
          <div className="col-md-6">
            <label className="form-label">Course sync scope</label>
            <select
              className="form-select"
              value={canvasSyncMode}
              disabled={canvasSyncSaving}
              onChange={async (event) => {
                const next = event.target.value as "active" | "concluded" | "all";
                setCanvasSyncMode(next);
                setCanvasSyncSaving(true);
                const response = await apiFetch(`${API_BASE}/api/admin/settings`, {
                  method: "PATCH",
                  headers: { "content-type": "application/json" },
                  body: JSON.stringify({ canvasCourseSyncMode: next })
                });
                const payload = await response.json().catch(() => null);
                setCanvasSyncSaving(false);
                if (!response.ok) {
                  onNotice(payload?.error || "Failed to update Canvas sync scope.", "error");
                  return;
                }
                if (payload?.canvasCourseSyncMode) {
                  setCanvasSyncMode(payload.canvasCourseSyncMode);
                }
                onNotice("Canvas sync scope updated.", "success");
              }}
            >
              <option value="active">Active courses only</option>
              <option value="concluded">Concluded courses only</option>
              <option value="all">Active + concluded</option>
            </select>
            <div className="muted mt-1">
              Controls which Canvas courses are synced, searchable, and available in builders.
            </div>
          </div>
        </div>
      </div>
      <div className="panel panel--compact mb-3">
        <div className="panel-header">
          <h3 className="mb-0">Canvas access test</h3>
        </div>
        <div className="d-flex flex-wrap gap-2 align-items-center mb-2">
          <button
            type="button"
            className="btn btn-outline-secondary btn-sm"
            onClick={async () => {
              setTestStatus(null);
              setTestResult(null);
              const response = await apiFetch(`${API_BASE}/api/admin/canvas/test`);
              const payload = await response.json().catch(() => null);
              if (!response.ok) {
                setTestStatus(payload?.error || "Canvas test failed.");
                return;
              }
              setTestStatus("Canvas API reachable.");
              setTestResult(
                payload?.canvas_name
                  ? `Authenticated as ${payload.canvas_name} (ID ${payload.canvas_user_id || "n/a"})`
                  : "Canvas user retrieved."
              );
            }}
          >
            <i className="bi bi-plug" aria-hidden="true" /> Test Canvas access
          </button>
          {testStatus ? <span className="muted">{testStatus}</span> : null}
        </div>
        {testResult ? <div className="alert alert-info mt-2 mb-0">{testResult}</div> : null}
      </div>
      <div className="panel panel--compact mb-3">
        <div className="panel-header">
          <h3 className="mb-0">Canvas retry queue</h3>
        </div>
        {retryError ? <div className="alert alert-warning">{retryError}</div> : null}
        <div className="row g-3">
          <div className="col-lg-6">
            <div className="muted mb-2">Queued retries</div>
            <div className="table-responsive">
              <table className="table table-sm">
                <thead>
                  <tr>
                    <th>Submission</th>
                    <th>Email</th>
                    <th>Attempts</th>
                    <th>Next run</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {retryQueue.length === 0 ? (
                    <tr>
                      <td colSpan={5}>No queued retries.</td>
                    </tr>
                  ) : (
                    retryQueue.map((item: any) => (
                      <tr key={item.id}>
                        <td className="text-break">
                          <div>
                            <RichText
                              text={item.form_title || item.form_slug || "Submission"}
                              markdownEnabled={markdownEnabled}
                              mathjaxEnabled={mathjaxEnabled}
                              inline
                            />
                          </div>
                          <div className="muted">{item.submission_id}</div>
                        </td>
                        <td>{item.submitter_email || "n/a"}</td>
                        <td>{item.attempts ?? 0}</td>
                        <td>{item.next_run_at ? formatTimeICT(item.next_run_at) : "n/a"}</td>
                        <td>
                          <div className="d-flex gap-2 flex-wrap">
                            <button
                              type="button"
                              className="btn btn-outline-primary btn-sm"
                              disabled={retryLoading}
                              onClick={() => handleRetryAction(item.id, "retry", "queue")}
                            >
                              <i className="bi bi-arrow-clockwise" aria-hidden="true" /> Retry now
                            </button>
                            <button
                              type="button"
                              className="btn btn-outline-danger btn-sm"
                              disabled={retryLoading}
                              onClick={() => handleRetryAction(item.id, "drop", "queue")}
                            >
                              <i className="bi bi-trash" aria-hidden="true" /> Drop
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
          <div className="col-lg-6">
            <div className="muted mb-2">Dead letters</div>
            <div className="table-responsive">
              <table className="table table-sm">
                <thead>
                  <tr>
                    <th>Submission</th>
                    <th>Email</th>
                    <th>Attempts</th>
                    <th>Created</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {deadletters.length === 0 ? (
                    <tr>
                      <td colSpan={5}>No dead letters.</td>
                    </tr>
                  ) : (
                    deadletters.map((item: any) => (
                      <tr key={item.id}>
                        <td className="text-break">
                          <div>
                            <RichText
                              text={item.form_title || item.form_slug || "Submission"}
                              markdownEnabled={markdownEnabled}
                              mathjaxEnabled={mathjaxEnabled}
                              inline
                            />
                          </div>
                          <div className="muted">{item.submission_id}</div>
                        </td>
                        <td>{item.submitter_email || "n/a"}</td>
                        <td>{item.attempts ?? 0}</td>
                        <td>{item.created_at ? formatTimeICT(item.created_at) : "n/a"}</td>
                        <td>
                          <div className="d-flex gap-2 flex-wrap">
                            <button
                              type="button"
                              className="btn btn-outline-primary btn-sm"
                              disabled={retryLoading}
                              onClick={() => handleRetryAction(item.id, "retry", "deadletter")}
                            >
                              <i className="bi bi-arrow-clockwise" aria-hidden="true" /> Retry now
                            </button>
                            <button
                              type="button"
                              className="btn btn-outline-danger btn-sm"
                              disabled={retryLoading}
                              onClick={() => handleRetryAction(item.id, "drop", "deadletter")}
                            >
                              <i className="bi bi-trash" aria-hidden="true" /> Drop
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
      <div className="panel panel--compact mb-3">
        <div className="panel-header">
          <h3 className="mb-0">Canvas user lookup</h3>
        </div>
        <div className="row g-3 align-items-end">
          <div className="col-md-4">
            <label className="form-label">Keyword</label>
            <input
              className="form-control"
              value={lookupQuery}
              onChange={(event) => setLookupQuery(event.target.value)}
              placeholder="Email, name, or username"
            />
          </div>
          <div className="col-md-4">
            <label className="form-label">Course</label>
            <select
              className="form-select"
              value={lookupCourseId}
              onChange={(event) => setLookupCourseId(event.target.value)}
              disabled={courses.length === 0}
            >
              <option value="">All courses</option>
              {courses.map((course) => (
                <option key={course.id} value={course.id}>
                  {course.name}
                </option>
              ))}
            </select>
          </div>
          <div className="col-md-4">
            <button
              type="button"
              className="btn btn-outline-primary w-100"
              disabled={!lookupQuery.trim() || lookupLoading}
              onClick={async () => {
                setLookupError(null);
                setLookupResult([]);
                if (!lookupQuery.trim()) return;
                setLookupLoading(true);
                const params = new URLSearchParams({
                  q: lookupQuery.trim(),
                  ...(lookupCourseId ? { courseId: lookupCourseId } : {})
                });
                const response = await apiFetch(
                  `${API_BASE}/api/admin/canvas/user-lookup?${params.toString()}`
                );
                const payload = await response.json().catch(() => null);
                setLookupLoading(false);
                if (!response.ok) {
                  setLookupError(payload?.error || "Lookup failed.");
                  return;
                }
                setLookupResult(Array.isArray(payload?.data) ? payload.data : []);
              }}
            >
              <i className="bi bi-search" aria-hidden="true" />{" "}
              {lookupLoading ? "Looking up..." : "Lookup"}
            </button>
          </div>
        </div>
        {lookupError ? <div className="alert alert-warning mt-2 mb-0">{lookupError}</div> : null}
        {lookupResult.length > 0 ? (
          <div className="alert alert-info mt-2 mb-0">
            {lookupResult.map((user) => (
              <div key={user.id} className="mb-2">
                <div>
                  <strong>Full name: {user.full_name || "n/a"}</strong>
                </div>
                <div className="muted">
                  Display name: {user.display_name || "n/a"} | Sortable:{" "}
                  {user.sortable_name || "n/a"} | Pronouns: {user.pronouns || "n/a"}
                </div>
                <div className="muted">Email: {user.email || user.login_id || "n/a"}</div>
                <div className="muted">
                  {lookupCourseId ? (
                    <>
                      Course:{" "}
                      {courses.find((course) => course.id === lookupCourseId)?.name ||
                        lookupCourseId ||
                        "n/a"}
                      {Array.isArray(user.roles) && user.roles.length > 0
                        ? ` | Roles: ${user.roles.join(", ")}`
                        : ""}
                    </>
                  ) : Array.isArray(user.courses) && user.courses.length > 0 ? (
                    <>
                      Courses:{" "}
                      {user.courses
                        .map(
                          (course: any) =>
                            `${course.name || course.id}${Array.isArray(course.roles) && course.roles.length > 0
                              ? ` (${course.roles.join(", ")})`
                              : ""
                            }`
                        )
                        .join("; ")}
                    </>
                  ) : (
                    <>Courses: n/a</>
                  )}
                </div>
              </div>
            ))}
          </div>
        ) : null}
      </div>
      <div className="panel panel--compact mb-3">
        <div className="panel-header">
          <h3 className="mb-0">Enroll user</h3>
        </div>
        <div className="row g-3 align-items-end">
          <div className="col-md-3">
            <label className="form-label">Full name</label>
            <input
              className="form-control"
              value={enrollName}
              onChange={(event) => setEnrollName(event.target.value)}
              placeholder="Nguyen Van A"
            />
          </div>
          <div className="col-md-3">
            <label className="form-label">Email</label>
            <input
              className="form-control"
              value={enrollEmail}
              onChange={(event) => setEnrollEmail(event.target.value)}
              placeholder="name@example.com"
            />
          </div>
          <div className="col-md-2">
            <label className="form-label">Role</label>
            <select
              className="form-select"
              value={enrollRole}
              onChange={(event) => setEnrollRole(event.target.value)}
            >
              <option value="student">Student</option>
              <option value="teacher">Teacher</option>
              <option value="ta">TA</option>
              <option value="observer">Observer</option>
              <option value="designer">Designer</option>
            </select>
          </div>
          <div className="col-md-2">
            <label className="form-label">Course</label>
            <select
              className="form-select"
              value={enrollCourseId}
              onChange={(event) => setEnrollCourseId(event.target.value)}
              disabled={courses.length === 0}
            >
              <option value="">Select course</option>
              {courses.map((course) => (
                <option key={course.id} value={course.id}>
                  {course.name}
                </option>
              ))}
            </select>
          </div>
          <div className="col-md-2">
            <label className="form-label">Section</label>
            <select
              className="form-select"
              value={enrollSectionId}
              onChange={(event) => setEnrollSectionId(event.target.value)}
              disabled={!enrollCourseId}
            >
              <option value="">No section</option>
              {enrollSections.map((section: any) => (
                <option key={section.id} value={section.id}>
                  {section.name}
                </option>
              ))}
            </select>
          </div>
          <div className="col-md-12">
            <button
              type="button"
              className="btn btn-outline-primary"
              disabled={
                enrollLoading ||
                !enrollCourseId ||
                !enrollName.trim() ||
                !enrollEmail.trim()
              }
              onClick={async () => {
                setActionError(null);
                if (!enrollName.trim() || !enrollEmail.trim() || !enrollCourseId) {
                  setActionError("Please provide name, email, and course.");
                  return;
                }
                setEnrollLoading(true);
                const response = await apiFetch(`${API_BASE}/api/admin/canvas/enroll`, {
                  method: "POST",
                  headers: { "content-type": "application/json" },
                  body: JSON.stringify({
                    name: enrollName.trim(),
                    email: enrollEmail.trim(),
                    role: enrollRole,
                    courseId: enrollCourseId,
                    sectionId: enrollSectionId || null
                  })
                });
                const payload = await response.json().catch(() => null);
                setEnrollLoading(false);
                if (!response.ok) {
                  setActionError(payload?.error || "Enrollment failed.");
                  return;
                }
                onNotice("Enrollment invite sent.", "success");
                setEnrollName("");
                setEnrollEmail("");
                setEnrollRole("student");
                setEnrollSectionId("");
                await refreshCanvasOverview(false);
              }}
            >
              <i className="bi bi-person-plus" aria-hidden="true" />{" "}
              {enrollLoading ? "Sending..." : "Enroll user"}
            </button>
          </div>
        </div>
      </div>
      {courses.length === 0 ? (
        <p className="muted">No Canvas courses cached yet. Run a sync first.</p>
      ) : (
        courses.map((course) => (
          <div key={course.id} className="panel panel--compact mb-3">
            <div className="panel-header">
              <div>
                <h3 className="mb-1">{course.name}</h3>
                <div className="muted">
                  {course.code ? `${course.code} • ` : ""}ID {course.id}
                </div>
              </div>
              <span className="badge text-bg-light">{course.workflow_state || "active"}</span>
            </div>
            <div className="table-responsive">
              <table className="table table-sm">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Email / GitHub</th>
                    <th>Status</th>
                    <th>Section</th>
                    <th>Form</th>
                    <th>Submission</th>
                    <th>Enrolled at</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {Array.isArray(course.registrations) && course.registrations.length > 0 ? (
                    course.registrations.map((reg: any) => (
                      <tr key={reg.submission_id}>
                        <td>
                          {reg.name || "n/a"}
                          {reg.name &&
                            (!reg.canvas_full_name || !reg.canvas_display_name) &&
                            reg.status !== "deleted" ? (
                            <span className="badge text-bg-warning ms-2">
                              <i className="bi bi-person-x" aria-hidden="true" /> Missing in Canvas
                            </span>
                          ) : reg.name &&
                            reg.canvas_full_name &&
                            reg.canvas_display_name &&
                            reg.status !== "deleted" &&
                            (normalizeNameValue(reg.name) !==
                              normalizeNameValue(reg.canvas_full_name) ||
                              normalizeNameValue(reg.name) !==
                              normalizeNameValue(reg.canvas_display_name)) ? (
                            <span className="badge text-bg-warning ms-2">
                              <i className="bi bi-exclamation-triangle" aria-hidden="true" /> Mismatch
                            </span>
                          ) : null}
                          {reg.canvas_full_name || reg.canvas_display_name ? (
                            <div className="muted mt-1">
                              Canvas full: {reg.canvas_full_name || "n/a"} · display:{" "}
                              {reg.canvas_display_name || "n/a"}
                            </div>
                          ) : null}
                        </td>
                        <td>{reg.email || reg.github_username || reg.user_id || "n/a"}</td>
                        <td>
                          <span
                            className={`badge ${reg.status === "invited"
                              ? "text-bg-success"
                              : reg.status === "failed"
                                ? "text-bg-danger"
                                : reg.status === "deactivated"
                                  ? "text-bg-warning"
                                  : reg.status === "deleted"
                                    ? "text-bg-dark"
                                    : "text-bg-secondary"
                              }`}
                            title={reg.error || ""}
                          >
                            <i
                              className={`bi ${reg.status === "invited"
                                ? "bi-check-circle"
                                : reg.status === "failed"
                                  ? "bi-exclamation-triangle"
                                  : reg.status === "deactivated"
                                    ? "bi-person-dash"
                                    : reg.status === "deleted"
                                      ? "bi-person-x"
                                      : "bi-clock"
                                }`}
                              aria-hidden="true"
                            />{" "}
                            {reg.status === "deleted" ? "unenrolled" : reg.status}
                          </span>
                        </td>
                        <td>{reg.section_name || reg.section_id || "n/a"}</td>
                        <td>
                          {reg.form_title ? (
                            <RichText
                              text={reg.form_title}
                              markdownEnabled={markdownEnabled}
                              mathjaxEnabled={mathjaxEnabled}
                              inline
                            />
                          ) : (
                            "n/a"
                          )}
                        </td>
                        <td>
                          {reg.submission_deleted ? (
                            <span title={reg.submission_id}>
                              <RichText
                                text={reg.form_title || reg.form_slug || "Submission"}
                                markdownEnabled={markdownEnabled}
                                mathjaxEnabled={mathjaxEnabled}
                                inline
                              />
                            </span>
                          ) : (
                            <Link to={`/me/submissions/${reg.submission_id}`} title={reg.submission_id}>
                              <RichText
                                text={reg.form_title || reg.form_slug || "Submission"}
                                markdownEnabled={markdownEnabled}
                                mathjaxEnabled={mathjaxEnabled}
                                inline
                              />
                            </Link>
                          )}
                          {reg.form_title ? (
                            <div className="muted">{reg.submission_id}</div>
                          ) : null}
                        </td>
                        <td>{reg.enrolled_at ? formatTimeICT(reg.enrolled_at) : "n/a"}</td>
                        <td>
                          <div className="d-flex flex-wrap gap-2">
                            {reg.name &&
                              (!reg.canvas_full_name || !reg.canvas_display_name) &&
                              reg.status !== "deleted" ? (
                              <button
                                type="button"
                                className="btn btn-outline-warning"
                                onClick={() => handleRegistrationNotify(reg.submission_id)}
                              >
                                <i className="bi bi-person-x" aria-hidden="true" /> Alert
                              </button>
                            ) : reg.name &&
                              reg.canvas_full_name &&
                              reg.canvas_display_name &&
                              reg.status !== "deleted" &&
                              (normalizeNameValue(reg.name) !==
                                normalizeNameValue(reg.canvas_full_name) ||
                                normalizeNameValue(reg.name) !==
                                normalizeNameValue(reg.canvas_display_name)) ? (
                              <button
                                type="button"
                                className="btn btn-outline-warning"
                                onClick={() => handleRegistrationNotify(reg.submission_id)}
                              >
                                <i className="bi bi-exclamation-triangle" aria-hidden="true" /> Alert
                              </button>
                            ) : null}
                            <button
                              type="button"
                              className="btn btn-outline-primary"
                              onClick={() => handleRegistrationReinvite(reg.submission_id)}
                            >
                              <i className="bi bi-send" aria-hidden="true" /> Reinvite
                            </button>
                            {reg.status === "deactivated" ? (
                              <button
                                type="button"
                                className="btn btn-outline-success"
                                onClick={() => handleRegistrationAction(reg.submission_id, "reactivate")}
                              >
                                <i className="bi bi-person-check" aria-hidden="true" /> Reactivate
                              </button>
                            ) : reg.status !== "deleted" ? (
                              <button
                                type="button"
                                className="btn btn-outline-warning"
                                onClick={() => handleRegistrationAction(reg.submission_id, "deactivate")}
                              >
                                <i className="bi bi-person-dash" aria-hidden="true" /> Deactivate
                              </button>
                            ) : null}
                            {reg.status !== "deleted" ? (
                              <button
                                type="button"
                                className="btn btn-outline-danger"
                                onClick={() => handleRegistrationAction(reg.submission_id, "delete")}
                              >
                                <i className="bi bi-person-x" aria-hidden="true" /> Unenroll
                              </button>
                            ) : null}
                            <button
                              type="button"
                              className="btn btn-outline-danger"
                              onClick={async () => {
                                setActionError(null);
                                if (!window.confirm("Move this form submission to trash?")) return;
                                const response = await apiFetch(
                                  `${API_BASE}/api/admin/canvas/registrations/${encodeURIComponent(
                                    reg.submission_id
                                  )}/submission-delete`,
                                  { method: "POST" }
                                );
                                const payload = await response.json().catch(() => null);
                                if (!response.ok) {
                                  setActionError(payload?.error || "Failed to delete submission.");
                                  return;
                                }
                                if (payload?.canvasAction) {
                                  const canvasLabel =
                                    payload.canvasAction === "deactivated"
                                      ? "deactivated"
                                      : payload.canvasAction === "failed"
                                        ? "failed"
                                        : "skipped";
                                  onNotice(
                                    `Form submission deleted. Canvas deactivation: ${canvasLabel}.`,
                                    payload.canvasAction === "failed" ? "warning" : "success"
                                  );
                                } else {
                                  onNotice("Form submission deleted.", "success");
                                }
                                setCourses((prev) =>
                                  prev.map((course) => ({
                                    ...course,
                                    registrations: Array.isArray(course.registrations)
                                      ? course.registrations.filter(
                                        (item: any) => item.submission_id !== reg.submission_id
                                      )
                                      : course.registrations
                                  }))
                                );
                              }}
                            >
                              <i className="bi bi-trash" aria-hidden="true" /> Delete
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={8}>No registrations recorded.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        ))
      )}
    </section>
  );
}


function AdminPage({
  user,
  onLogin,
  onNotice,
  appDefaultTimezone,
  onUpdateDefaultTimezone,
  appCanvasDeleteSyncEnabled,
  onUpdateCanvasDeleteSyncEnabled,
  appMarkdownEnabled,
  appMathjaxEnabled,
  onUpdateMarkdownEnabled,
  onUpdateMathjaxEnabled
}: {
  user: UserInfo | null;
  onLogin: (p: "google" | "github") => void;
  onNotice: (message: string, type?: NoticeType) => void;
  appDefaultTimezone: string;
  onUpdateDefaultTimezone: (tz: string) => Promise<boolean>;
  appCanvasDeleteSyncEnabled: boolean;
  onUpdateCanvasDeleteSyncEnabled: (enabled: boolean) => Promise<boolean>;
  appMarkdownEnabled: boolean;
  appMathjaxEnabled: boolean;
  onUpdateMarkdownEnabled: (enabled: boolean) => Promise<boolean>;
  onUpdateMathjaxEnabled: (enabled: boolean) => Promise<boolean>;
}) {
  const [status, setStatus] = useState<"loading" | "ok" | "forbidden">("loading");
  const [error, setError] = useState<string | null>(null);
  const [forms, setForms] = useState<any[]>([]);
  const [templates, setTemplates] = useState<any[]>([]);
  const [users, setUsers] = useState<any[]>([]);
  const [uploads, setUploads] = useState<any[]>([]);
  const [submissions, setSubmissions] = useState<any[]>([]);
  const [submissionsError, setSubmissionsError] = useState<string | null>(null);
  const [submissionExportingId, setSubmissionExportingId] = useState<string | null>(null);
  const [routines, setRoutines] = useState<any[]>([]);
  const [healthSummary, setHealthSummary] = useState<any[]>([]);
  const [lastRefresh, setLastRefresh] = useState<string | null>(null);
  const [formStatusFilter, setFormStatusFilter] = useState("all");
  const [userRoleFilter, setUserRoleFilter] = useState("all");
  const [submissionFormFilter, setSubmissionFormFilter] = useState("");
  const [submissionUserFilter, setSubmissionUserFilter] = useState("");
  const [settingsTimezone, setSettingsTimezone] = useState(appDefaultTimezone);
  const [settingsCanvasDeleteSync, setSettingsCanvasDeleteSync] = useState(
    appCanvasDeleteSyncEnabled
  );
  const [settingsMarkdownEnabled, setSettingsMarkdownEnabled] = useState(appMarkdownEnabled);
  const [settingsMathjaxEnabled, setSettingsMathjaxEnabled] = useState(appMathjaxEnabled);
  const [routineEdits, setRoutineEdits] = useState<Record<string, { cron: string; enabled: boolean }>>(
    {}
  );
  const [routineLogs, setRoutineLogs] = useState<Record<string, any[]>>({});
  const [activeRoutineLogId, setActiveRoutineLogId] = useState<string | null>(null);
  const [adminSelected, setAdminSelected] = useState<{
    forms: Set<string>;
    templates: Set<string>;
    users: Set<string>;
    submissions: Set<string>;
  }>({
    forms: new Set(),
    templates: new Set(),
    users: new Set(),
    submissions: new Set()
  });
  const [adminBulkStatus, setAdminBulkStatus] = useState<{
    label: string;
    done: number;
    total: number;
    type: "forms" | "templates" | "users" | "submissions";
  } | null>(null);
  const formTitleBySlug = useMemo(() => {
    const next: Record<string, string> = {};
    forms.forEach((form) => {
      if (form?.slug && form?.title) {
        next[String(form.slug)] = String(form.title);
      }
    });
    return next;
  }, [forms]);
  const filteredForms = useMemo(() => {
    if (formStatusFilter === "all") return forms;
    return forms.filter((form) => {
      if (formStatusFilter === "locked") return Boolean(form.is_locked);
      if (formStatusFilter === "unlocked") return !Boolean(form.is_locked);
      if (formStatusFilter === "public") return Boolean(form.is_public);
      if (formStatusFilter === "private") return !Boolean(form.is_public);
      if (formStatusFilter.startsWith("auth:")) {
        const policy = formStatusFilter.replace("auth:", "");
        return String(form.auth_policy || "optional") === policy;
      }
      return true;
    });
  }, [forms, formStatusFilter]);
  const filteredUsers = useMemo(() => {
    if (userRoleFilter === "all") return users;
    return users.filter((entry) =>
      userRoleFilter === "admin" ? Boolean(entry.is_admin) : !Boolean(entry.is_admin)
    );
  }, [users, userRoleFilter]);
  const userOptions = useMemo(
    () =>
      users
        .filter((entry) => entry?.id)
        .map((entry) => ({
          id: String(entry.id),
          label:
            entry.email ||
            entry.provider_login ||
            entry.github_username ||
            entry.google_email ||
            String(entry.id)
        })),
    [users]
  );
  const filteredSubmissions = useMemo(() => {
    return submissions.filter((entry) => {
      if (submissionFormFilter && String(entry.form_slug || "") !== submissionFormFilter) {
        return false;
      }
      if (submissionUserFilter && String(entry.user_id || "") !== submissionUserFilter) {
        return false;
      }
      return true;
    });
  }, [submissions, submissionFormFilter, submissionUserFilter]);
  const [routineStatus, setRoutineStatus] = useState<string | null>(null);
  const [routineSelected, setRoutineSelected] = useState<Set<string>>(new Set());
  const [routineBulkStatus, setRoutineBulkStatus] = useState<{
    label: string;
    done: number;
    total: number;
  } | null>(null);
  const [statusActionId, setStatusActionId] = useState<string | null>(null);

  useEffect(() => {
    setSettingsTimezone(appDefaultTimezone || getAppDefaultTimezone());
  }, [appDefaultTimezone]);

  useEffect(() => {
    setSettingsCanvasDeleteSync(appCanvasDeleteSyncEnabled);
  }, [appCanvasDeleteSyncEnabled]);

  useEffect(() => {
    setSettingsMarkdownEnabled(appMarkdownEnabled);
  }, [appMarkdownEnabled]);

  useEffect(() => {
    setSettingsMathjaxEnabled(appMathjaxEnabled);
  }, [appMathjaxEnabled]);

  async function handleTimezoneChange(next: string) {
    setSettingsTimezone(next);
    const ok = await onUpdateDefaultTimezone(next);
    const message = ok ? "Default timezone updated." : "Failed to update timezone.";
    onNotice(message, ok ? "success" : "error");
  }

  async function handleCanvasDeleteSyncChange(next: boolean) {
    setSettingsCanvasDeleteSync(next);
    const ok = await onUpdateCanvasDeleteSyncEnabled(next);
    const message = ok
      ? "Canvas delete/restore sync updated."
      : "Failed to update Canvas delete/restore sync.";
    onNotice(message, ok ? "success" : "error");
  }

  async function handleMarkdownToggle(next: boolean) {
    setSettingsMarkdownEnabled(next);
    const ok = await onUpdateMarkdownEnabled(next);
    const message = ok ? "Markdown rendering updated." : "Failed to update Markdown setting.";
    onNotice(message, ok ? "success" : "error");
  }

  async function handleMathjaxToggle(next: boolean) {
    setSettingsMathjaxEnabled(next);
    const ok = await onUpdateMathjaxEnabled(next);
    const message = ok ? "MathJax rendering updated." : "Failed to update MathJax setting.";
    onNotice(message, ok ? "success" : "error");
  }

  async function updateFormStatus(
    slug: string,
    patch: Record<string, unknown>,
    successMessage: string
  ) {
    if (!slug) return;
    setStatusActionId(slug);
    const response = await apiFetch(`${API_BASE}/api/admin/forms/${encodeURIComponent(slug)}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(patch)
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      onNotice(payload?.error || "Failed to update form status.", "warning");
      setStatusActionId(null);
      return;
    }
    onNotice(successMessage, "success");
    await loadAdmin();
    setStatusActionId(null);
  }

  function getNextAuthPolicy(current?: string | null) {
    const order = ["optional", "required", "google", "github", "either"];
    const normalized = order.includes(String(current)) ? String(current) : "optional";
    const index = order.indexOf(normalized);
    return order[(index + 1) % order.length];
  }

  function toggleRoutineSelected(id: string) {
    setRoutineSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }

  function toggleRoutineAll(ids: string[]) {
    setRoutineSelected((prev) => {
      const next = new Set(prev);
      const allSelected = ids.every((id) => next.has(id));
      if (allSelected) {
        ids.forEach((id) => next.delete(id));
      } else {
        ids.forEach((id) => next.add(id));
      }
      return next;
    });
  }

  async function bulkRunRoutines() {
    const ids = Array.from(routineSelected);
    if (ids.length === 0) return;
    setRoutineStatus(null);
    setRoutineBulkStatus({ label: "Running", done: 0, total: ids.length });
    for (let i = 0; i < ids.length; i += 1) {
      const response = await apiFetch(`${API_BASE}/api/admin/routines/run`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ id: ids[i] })
      });
      const payload = await response.json().catch(() => null);
      if (!response.ok) {
        setRoutineStatus(payload?.error || `Failed to run ${ids[i]}.`);
      }
      setRoutineBulkStatus((prev) =>
        prev ? { ...prev, done: Math.min(prev.total, prev.done + 1) } : prev
      );
    }
    setRoutineBulkStatus(null);
    setRoutineSelected(new Set());
    onNotice("Bulk run triggered.", "success");
    loadAdmin();
  }

  async function bulkSaveRoutines() {
    const ids = Array.from(routineSelected);
    if (ids.length === 0) return;
    setRoutineStatus(null);
    setRoutineBulkStatus({ label: "Saving", done: 0, total: ids.length });
    for (let i = 0; i < ids.length; i += 1) {
      const task = routines.find((entry) => entry.id === ids[i]);
      if (!task) {
        setRoutineBulkStatus((prev) =>
          prev ? { ...prev, done: Math.min(prev.total, prev.done + 1) } : prev
        );
        continue;
      }
      const edit = routineEdits[task.id] || {
        cron: task.cron,
        enabled: Boolean(task.enabled)
      };
      const response = await apiFetch(`${API_BASE}/api/admin/routines`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          id: task.id,
          cron: edit.cron,
          enabled: edit.enabled
        })
      });
      const payload = await response.json().catch(() => null);
      if (!response.ok) {
        setRoutineStatus(payload?.error || `Failed to update ${task.id}.`);
      }
      setRoutineBulkStatus((prev) =>
        prev ? { ...prev, done: Math.min(prev.total, prev.done + 1) } : prev
      );
    }
    setRoutineBulkStatus(null);
    setRoutineSelected(new Set());
    onNotice("Bulk save completed.", "success");
    loadAdmin();
  }

  async function bulkEnableRoutines(nextEnabled: boolean) {
    const ids = Array.from(routineSelected);
    if (ids.length === 0) return;
    setRoutineStatus(null);
    setRoutineBulkStatus({
      label: nextEnabled ? "Enabling" : "Disabling",
      done: 0,
      total: ids.length
    });
    for (let i = 0; i < ids.length; i += 1) {
      const task = routines.find((entry) => entry.id === ids[i]);
      if (!task) {
        setRoutineBulkStatus((prev) =>
          prev ? { ...prev, done: Math.min(prev.total, prev.done + 1) } : prev
        );
        continue;
      }
      const response = await apiFetch(`${API_BASE}/api/admin/routines`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          id: task.id,
          cron: routineEdits[task.id]?.cron ?? task.cron ?? "",
          enabled: nextEnabled
        })
      });
      const payload = await response.json().catch(() => null);
      if (!response.ok) {
        setRoutineStatus(payload?.error || `Failed to update ${task.id}.`);
      }
      setRoutineEdits((prev) => ({
        ...prev,
        [task.id]: {
          cron: prev[task.id]?.cron ?? task.cron ?? "",
          enabled: nextEnabled
        }
      }));
      setRoutineBulkStatus((prev) =>
        prev ? { ...prev, done: Math.min(prev.total, prev.done + 1) } : prev
      );
    }
    setRoutineBulkStatus(null);
    setRoutineSelected(new Set());
    onNotice(nextEnabled ? "Selected routines enabled." : "Selected routines disabled.", "success");
    loadAdmin();
  }

  function toggleAdminSelected(
    type: "forms" | "templates" | "users" | "submissions",
    id: string
  ) {
    setAdminSelected((prev) => {
      const next = {
        forms: new Set(prev.forms),
        templates: new Set(prev.templates),
        users: new Set(prev.users),
        submissions: new Set(prev.submissions)
      };
      const bucket = next[type];
      if (bucket.has(id)) {
        bucket.delete(id);
      } else {
        bucket.add(id);
      }
      return next;
    });
  }

  function toggleAdminAll(
    type: "forms" | "templates" | "users" | "submissions",
    ids: string[]
  ) {
    setAdminSelected((prev) => {
      const next = {
        forms: new Set(prev.forms),
        templates: new Set(prev.templates),
        users: new Set(prev.users),
        submissions: new Set(prev.submissions)
      };
      const bucket = next[type];
      const allSelected = ids.every((id) => bucket.has(id));
      if (allSelected) {
        ids.forEach((id) => bucket.delete(id));
      } else {
        ids.forEach((id) => bucket.add(id));
      }
      return next;
    });
  }

  async function bulkDeleteAdmin(type: "forms" | "templates" | "users" | "submissions") {
    const ids = Array.from(adminSelected[type]);
    if (ids.length === 0) {
      return;
    }
    if (!window.confirm(`Move ${ids.length} ${type} to trash?`)) {
      return;
    }
    setAdminBulkStatus({ label: "Deleting", done: 0, total: ids.length, type });
    const canvasSummary = { deactivated: 0, failed: 0, skipped: 0 };
    for (let i = 0; i < ids.length; i += 1) {
      const id = ids[i];
      let endpoint = "";
      if (type === "forms") {
        endpoint = `/api/admin/forms/${encodeURIComponent(id)}`;
      } else if (type === "templates") {
        endpoint = `/api/admin/templates/${encodeURIComponent(id)}`;
      } else if (type === "users") {
        endpoint = `/api/admin/users/${encodeURIComponent(id)}`;
      } else {
        endpoint = `/api/admin/submissions/${encodeURIComponent(id)}`;
      }
      const response = await apiFetch(`${API_BASE}${endpoint}`, { method: "DELETE" });
      const payload = await response.json().catch(() => null);
      if (!response.ok) {
        onNotice(payload?.error || `Failed to delete ${id}.`, "warning");
      } else if ((type === "users" || type === "submissions") && payload?.canvasAction) {
        if (payload.canvasAction === "deactivated") {
          canvasSummary.deactivated += 1;
        } else if (payload.canvasAction === "failed") {
          canvasSummary.failed += 1;
        } else {
          canvasSummary.skipped += 1;
        }
      }
      setAdminBulkStatus((prev) =>
        prev ? { ...prev, done: Math.min(prev.total, prev.done + 1) } : prev
      );
    }
    setAdminSelected((prev) => ({ ...prev, [type]: new Set() }));
    setAdminBulkStatus(null);
    if ((type === "users" || type === "submissions") && (canvasSummary.deactivated || canvasSummary.failed || canvasSummary.skipped)) {
      onNotice(
        `Selected items moved to trash. Canvas deactivation: ${canvasSummary.deactivated} deactivated, ${canvasSummary.failed} failed, ${canvasSummary.skipped} skipped.`,
        canvasSummary.failed > 0 ? "warning" : "success"
      );
    } else {
      onNotice("Selected items moved to trash.", "success");
    }
    loadAdmin();
  }

  function clearAdminSelection(type: "forms" | "templates" | "users" | "submissions") {
    setAdminSelected((prev) => ({ ...prev, [type]: new Set() }));
  }

  async function handleAdminSubmissionExport(submissionId: string, format: SubmissionExportFormat) {
    setSubmissionExportingId(submissionId);
    try {
      const response = await apiFetch(
        `${API_BASE}/api/me/submissions/${encodeURIComponent(submissionId)}`
      );
      const payload = await response.json().catch(() => null);
      if (!response.ok) {
        onNotice(payload?.error || "Failed to load submission.", "warning");
        return;
      }
      const submission = payload?.data;
      if (!submission) {
        onNotice("Submission data is unavailable.", "warning");
        return;
      }

      let meta: FieldMetaMap = {};
      let order: string[] = [];
      const slug = submission?.form?.slug;
      if (slug) {
        const formRes = await apiFetch(`${API_BASE}/api/forms/${encodeURIComponent(slug)}`);
        const formPayload = await formRes.json().catch(() => null);
        if (formRes.ok) {
          const fields = Array.isArray(formPayload?.data?.fields) ? formPayload.data.fields : [];
          const built = buildFieldMetaFromSchema(fields);
          meta = built.meta;
          order = built.order;
        }
      }

      const exportPayload = buildSubmissionExportContent({
        submission,
        dataValues:
          submission?.data_json && typeof submission.data_json === "object"
            ? (submission.data_json as Record<string, unknown>)
            : null,
        fieldMeta: meta,
        fieldOrder: order,
        format,
        versionLabel: "latest"
      });
      downloadTextFile(exportPayload.filename, exportPayload.content, exportPayload.mimeType);
    } catch (error) {
      onNotice("Failed to export submission.", "warning");
    } finally {
      setSubmissionExportingId(null);
    }
  }

  async function loadAdmin() {
    try {
      const healthRes = await apiFetch(`${API_BASE}/api/admin/health`);
      if (healthRes.status === 401 || healthRes.status === 403) {
        setStatus("forbidden");
        return;
      }
      if (!healthRes.ok) {
        const payload = await healthRes.json().catch(() => null);
        setError(payload?.error || "Failed to load admin data.");
        setStatus("ok");
        return;
      }

      const [
        formsRes,
        templatesRes,
        usersRes,
        uploadsRes,
        routinesRes,
        healthSummaryRes,
        submissionsRes
      ] = await Promise.all([
        apiFetch(`${API_BASE}/api/admin/forms`),
        apiFetch(`${API_BASE}/api/admin/templates`),
        apiFetch(`${API_BASE}/api/admin/users`),
        apiFetch(`${API_BASE}/api/admin/uploads?limit=50`),
        apiFetch(`${API_BASE}/api/admin/routines`),
        apiFetch(`${API_BASE}/api/admin/health/summary`),
        apiFetch(`${API_BASE}/api/admin/submissions?page=1&pageSize=10`)
      ]);

      const formsPayload = formsRes.ok ? await formsRes.json().catch(() => null) : null;
      const templatesPayload = templatesRes.ok ? await templatesRes.json().catch(() => null) : null;
      const usersPayload = usersRes.ok ? await usersRes.json().catch(() => null) : null;
      const uploadsPayload = uploadsRes.ok ? await uploadsRes.json().catch(() => null) : null;
      const routinesPayload = routinesRes.ok ? await routinesRes.json().catch(() => null) : null;
      const healthPayload = healthSummaryRes.ok ? await healthSummaryRes.json().catch(() => null) : null;
      const submissionsPayload = submissionsRes.ok
        ? await submissionsRes.json().catch(() => null)
        : null;

      setForms(Array.isArray(formsPayload?.data) ? formsPayload.data : []);
      setTemplates(Array.isArray(templatesPayload?.data) ? templatesPayload.data : []);
      setUsers(Array.isArray(usersPayload?.data) ? usersPayload.data : []);
      setUploads(Array.isArray(uploadsPayload?.data) ? uploadsPayload.data : []);
      setRoutines(Array.isArray(routinesPayload?.data) ? routinesPayload.data : []);
      setHealthSummary(Array.isArray(healthPayload?.data) ? healthPayload.data : []);
      if (!submissionsRes.ok) {
        setSubmissionsError(submissionsPayload?.error || "Failed to load submissions.");
        setSubmissions([]);
      } else {
        setSubmissionsError(null);
        setSubmissions(Array.isArray(submissionsPayload?.data) ? submissionsPayload.data : []);
      }
      setRoutineEdits((prev) => {
        const next: Record<string, { cron: string; enabled: boolean }> = { ...prev };
        (Array.isArray(routinesPayload?.data) ? routinesPayload.data : []).forEach((task: any) => {
          if (!task?.id) return;
          next[task.id] = {
            cron: typeof task.cron === "string" ? task.cron : "",
            enabled: Boolean(task.enabled)
          };
        });
        return next;
      });
      setError(null);
      setStatus("ok");
      setLastRefresh(new Date().toISOString());
    } catch (err) {
      setError("Failed to load admin data.");
      setStatus("ok");
    }
  }

  useEffect(() => {
    loadAdmin();
  }, []);

  if (status === "loading") {
    return (
      <section className="panel">
        <h2>Loading admin dashboard...</h2>
      </section>
    );
  }

  if (status === "forbidden") {
    return (
      <section className="panel panel--error">
        <h2>Not authorized</h2>
        <p>Please sign in with an admin account.</p>
        <div className="auth-bar">
          <button type="button" className="btn btn-primary btn-auth" onClick={() => onLogin("google")}>            <i className="bi bi-google" aria-hidden="true" /> Login with Google
          </button>
          <button type="button" className="btn btn-dark btn-auth" onClick={() => onLogin("github")}>            <i className="bi bi-github" aria-hidden="true" /> Login with GitHub
          </button>
        </div>
      </section>
    );
  }

  return (
    <section className="panel admin-scope">
      <div className="panel-header">
        <h2>Admin Dashboard</h2>
        {user ? <span className="badge">{getUserDisplayName(user)}</span> : null}
      </div>
      {error ? <div className="alert alert-warning">{error}</div> : null}
      {adminBulkStatus ? (
        <div className="alert alert-info">
          {adminBulkStatus.label} {adminBulkStatus.type}: {adminBulkStatus.done}/{adminBulkStatus.total}
        </div>
      ) : null}
      <div className="d-flex align-items-center gap-2 mb-3">
        <button type="button" className="btn btn-outline-primary btn-sm" onClick={loadAdmin}>
          <i className="bi bi-arrow-clockwise" aria-hidden="true" /> Refresh
        </button>
        {lastRefresh ? <span className="muted">Last refresh: {formatTimeICT(lastRefresh)}</span> : null}
      </div>

      <section className="panel panel--compact mb-3">
        <div className="panel-header">
          <h3 className="mb-0">App settings</h3>
        </div>
        <div className="row g-3 align-items-end">
          <div className="col-md-6">
            <label className="form-label">Default timezone</label>
            <TimezoneSelect idPrefix="admin-default-tz" value={settingsTimezone} onChange={handleTimezoneChange} />
          </div>
          <div className="col-md-8">
            <label className="form-label">Canvas sync on delete/restore</label>
            <div className="form-check form-switch">
              <input
                className="form-check-input"
                type="checkbox"
                id="admin-canvas-delete-sync"
                checked={settingsCanvasDeleteSync}
                onChange={(event) => handleCanvasDeleteSyncChange(event.target.checked)}
              />
              <label className="form-check-label" htmlFor="admin-canvas-delete-sync">
                Deactivate/reactivate Canvas enrollments when moving submissions or users to trash
                and restoring them.
              </label>
            </div>
            <div className="muted mt-1">
              If disabled, delete/restore actions will not change Canvas enrollments.
            </div>
          </div>
          <div className="col-md-6">
            <label className="form-label">Markdown rendering</label>
            <div className="form-check form-switch">
              <input
                className="form-check-input"
                type="checkbox"
                id="admin-markdown-enabled"
                checked={settingsMarkdownEnabled}
                onChange={(event) => handleMarkdownToggle(event.target.checked)}
              />
              <label className="form-check-label" htmlFor="admin-markdown-enabled">
                Enable Markdown + HTML rendering in form content.
              </label>
            </div>
          </div>
          <div className="col-md-6">
            <label className="form-label">MathJax rendering</label>
            <div className="form-check form-switch">
              <input
                className="form-check-input"
                type="checkbox"
                id="admin-mathjax-enabled"
                checked={settingsMathjaxEnabled}
                onChange={(event) => handleMathjaxToggle(event.target.checked)}
              />
              <label className="form-check-label" htmlFor="admin-mathjax-enabled">
                Enable MathJax rendering for formulas.
              </label>
            </div>
          </div>
        </div>
      </section>

      <section className="panel panel--compact mb-3">
        <div className="panel-header">
          <h3 className="mb-0">Overview</h3>
        </div>
        <div className="row g-3">
          <div className="col-md-3">
            <div className="stat-card">
              <div className="stat-card__label">Forms</div>
              <div className="stat-card__value">{forms.length}</div>
            </div>
          </div>
          <div className="col-md-3">
            <div className="stat-card">
              <div className="stat-card__label">Templates</div>
              <div className="stat-card__value">{templates.length}</div>
            </div>
          </div>
          <div className="col-md-3">
            <div className="stat-card">
              <div className="stat-card__label">Users</div>
              <div className="stat-card__value">{users.length}</div>
            </div>
          </div>
          <div className="col-md-3">
            <div className="stat-card">
              <div className="stat-card__label">Uploads</div>
              <div className="stat-card__value">{uploads.length}</div>
            </div>
          </div>
          <div className="col-md-3">
            <div className="stat-card">
              <div className="stat-card__label">Submissions</div>
              <div className="stat-card__value">{submissions.length}</div>
            </div>
          </div>
          <div className="col-md-3">
            <div className="stat-card">
              <div className="stat-card__label">Tasks</div>
              <div className="stat-card__value">{routines.length}</div>
            </div>
          </div>
          <div className="col-md-3">
            <div className="stat-card">
              <div className="stat-card__label">Health entries</div>
              <div className="stat-card__value">{healthSummary.length}</div>
            </div>
          </div>
        </div>
      </section>

      <section className="panel panel--compact mb-3">
        <div className="panel-header">
          <h3 className="mb-0">Forms</h3>
          <Link to="/admin/builder" className="btn btn-outline-secondary btn-sm">
            <i className="bi bi-pencil-square" aria-hidden="true" /> Builder
          </Link>
        </div>
        <div className="d-flex flex-wrap gap-2 align-items-end mb-2">
          <div>
            <label className="form-label">Status</label>
            <select
              className="form-select form-select-sm"
              value={formStatusFilter}
              onChange={(event) => setFormStatusFilter(event.target.value)}
            >
              <option value="all">All</option>
              <option value="locked">Locked</option>
              <option value="unlocked">Unlocked</option>
              <option value="public">Public</option>
              <option value="private">Private</option>
              <option value="auth:optional">Auth: Optional</option>
              <option value="auth:required">Auth: Required</option>
              <option value="auth:google">Auth: Google</option>
              <option value="auth:github">Auth: GitHub</option>
              <option value="auth:either">Auth: Either</option>
            </select>
          </div>
          <div className="ms-auto muted">Showing: {filteredForms.length}</div>
        </div>
        {forms.length === 0 ? (
          <div className="muted">No forms yet.</div>
        ) : filteredForms.length === 0 ? (
          <div className="muted">No forms match the selected filters.</div>
        ) : (
          <div className="table-responsive">
            <table className="table table-sm">
              <thead>
                <tr>
                  <th>
                    <input
                      type="checkbox"
                      className="form-check-input"
                      checked={
                        filteredForms.length > 0 &&
                        filteredForms
                          .slice(0, 10)
                          .every((item: any) => adminSelected.forms.has(item.slug))
                      }
                      onChange={() =>
                        toggleAdminAll(
                          "forms",
                          filteredForms
                            .slice(0, 10)
                            .map((item: any) => item.slug)
                            .filter(Boolean)
                        )
                      }
                    />
                  </th>
                  <th>Form</th>
                  <th>Status</th>
                  <th>Submissions</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredForms.slice(0, 10).map((form) => (
                  <tr key={form.slug}>
                    <td>
                      <input
                        type="checkbox"
                        className="form-check-input"
                        checked={adminSelected.forms.has(form.slug)}
                        onChange={() => toggleAdminSelected("forms", form.slug)}
                      />
                    </td>
                    <td>
                      <div>
                        <a className="text-decoration-none" href={`${PUBLIC_BASE}#/f/${form.slug}`}>
                          <RichText
                            text={form.title || form.slug}
                            markdownEnabled={appMarkdownEnabled}
                            mathjaxEnabled={appMathjaxEnabled}
                            inline
                          />
                        </a>
                      </div>
                      {form.description ? (
                        <div className="muted">
                          <RichText
                            text={form.description}
                            markdownEnabled={appMarkdownEnabled}
                            mathjaxEnabled={appMathjaxEnabled}
                            inline
                          />
                        </div>
                      ) : null}
                    </td>
                    <td>
                      <div className="status-badges status-badges--forms">
                        <button
                          type="button"
                          className={`badge status-pill status-pill--lock ${form.is_locked ? "text-bg-danger" : "text-bg-success"
                            }`}
                          title={form.is_locked ? "Form is locked" : "Form is open"}
                          disabled={statusActionId === form.slug}
                          onClick={() =>
                            updateFormStatus(
                              form.slug,
                              { is_locked: !form.is_locked },
                              `Form ${form.is_locked ? "unlocked" : "locked"}.`
                            )
                          }
                        >
                          <i className={`bi ${getLockIcon(form.is_locked)}`} aria-hidden="true" />{" "}
                          {form.is_locked ? "Locked" : "Unlocked"}
                        </button>
                        <button
                          type="button"
                          className={`badge status-pill status-pill--visibility ${form.is_public ? "text-bg-info" : "text-bg-secondary"
                            }`}
                          title={form.is_public ? "Public form" : "Private form"}
                          disabled={statusActionId === form.slug}
                          onClick={() =>
                            updateFormStatus(
                              form.slug,
                              { is_public: !form.is_public },
                              `Form set to ${form.is_public ? "private" : "public"}.`
                            )
                          }
                        >
                          <i className={`bi ${getVisibilityIcon(Boolean(form.is_public))}`} aria-hidden="true" />{" "}
                          {form.is_public ? "Public" : "Private"}
                        </button>
                        <button
                          type="button"
                          className="badge status-pill status-pill--auth text-bg-light"
                          title={`Auth policy: ${getAuthPolicyLabel(form.auth_policy)}`}
                          disabled={statusActionId === form.slug}
                          onClick={() =>
                            updateFormStatus(
                              form.slug,
                              { auth_policy: getNextAuthPolicy(form.auth_policy) },
                              "Auth policy updated."
                            )
                          }
                        >
                          <i className={`bi ${getAuthPolicyIcon(form.auth_policy)}`} aria-hidden="true" />{" "}
                          {getAuthPolicyLabel(form.auth_policy)}
                        </button>
                        {form.canvas_enabled ? (
                          <span className="badge text-bg-warning" title="Canvas enrollment enabled">
                            <i className="bi bi-mortarboard" aria-hidden="true" /> Canvas
                          </span>
                        ) : null}
                        {form.password_required ? (
                          <button
                            type="button"
                            className="badge text-bg-dark"
                            title="Password required"
                            disabled={statusActionId === form.slug}
                            onClick={() =>
                              updateFormStatus(
                                form.slug,
                                {
                                  passwordRequired: false,
                                  passwordRequireAccess: false,
                                  passwordRequireSubmit: false
                                },
                                "Password requirement removed."
                              )
                            }
                          >
                            <i className="bi bi-key" aria-hidden="true" /> Password
                          </button>
                        ) : null}
                      </div>
                      <div className="muted mt-1">
                        Updated:{" "}
                        {form.updated_at
                          ? formatTimeICT(form.updated_at)
                          : form.created_at
                            ? formatTimeICT(form.created_at)
                            : "n/a"}
                      </div>
                    </td>
                    <td>{Number(form.submission_count) || 0}</td>
                    <td>
                      <div className="d-flex flex-wrap gap-2">
                        <a className="btn btn-outline-primary btn-sm" href={`${PUBLIC_BASE}#/f/${form.slug}`}>
                          <i className="bi bi-box-arrow-up-right" aria-hidden="true" /> Open
                        </a>
                        <Link className="btn btn-outline-secondary btn-sm" to="/admin/builder">
                          <i className="bi bi-pencil-square" aria-hidden="true" /> Edit
                        </Link>
                        <button
                          type="button"
                          className="btn btn-outline-danger btn-sm"
                          onClick={async () => {
                            if (!window.confirm("Move this form to trash?")) return;
                            const response = await apiFetch(
                              `${API_BASE}/api/admin/forms/${encodeURIComponent(form.slug)}`,
                              { method: "DELETE" }
                            );
                            const payload = await response.json().catch(() => null);
                            if (!response.ok) {
                              onNotice(payload?.error || "Failed to move form to trash.", "warning");
                              return;
                            }
                            onNotice("Form moved to trash.", "success");
                            loadAdmin();
                          }}
                        >
                          <i className="bi bi-trash" aria-hidden="true" /> Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {adminSelected.forms.size > 0 ? (
          <div className="d-flex justify-content-end gap-2 mt-2">
            <button
              type="button"
              className="btn btn-outline-secondary btn-sm"
              onClick={() => clearAdminSelection("forms")}
            >
              <i className="bi bi-x-circle" aria-hidden="true" /> Clear selection
            </button>
            <button
              type="button"
              className="btn btn-outline-danger btn-sm"
              onClick={() => bulkDeleteAdmin("forms")}
            >
              <i className="bi bi-trash" aria-hidden="true" /> Delete selected
            </button>
          </div>
        ) : null}
      </section>

      <section className="panel panel--compact mb-3">
        <div className="panel-header">
          <h3 className="mb-0">Templates</h3>
          <Link to="/admin/builder" className="btn btn-outline-secondary btn-sm">
            <i className="bi bi-pencil-square" aria-hidden="true" /> Builder
          </Link>
        </div>
        <div className="d-flex flex-wrap gap-2 align-items-end mb-2">
          <div className="ms-auto muted">Showing: {templates.length}</div>
        </div>
        {templates.length === 0 ? (
          <div className="muted">No templates yet.</div>
        ) : (
          <div className="table-responsive">
            <table className="table table-sm">
              <thead>
                <tr>
                  <th>
                    <input
                      type="checkbox"
                      className="form-check-input"
                      checked={
                        templates.length > 0 &&
                        templates.slice(0, 10).every((item: any) => adminSelected.templates.has(item.key))
                      }
                      onChange={() =>
                        toggleAdminAll(
                          "templates",
                          templates.slice(0, 10).map((item: any) => item.key).filter(Boolean)
                        )
                      }
                    />
                  </th>
                  <th>Template</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {templates.slice(0, 10).map((template) => (
                  <tr key={template.key}>
                    <td>
                      <input
                        type="checkbox"
                        className="form-check-input"
                        checked={adminSelected.templates.has(template.key)}
                        onChange={() => toggleAdminSelected("templates", template.key)}
                      />
                    </td>
                    <td>
                      <div>
                        <Link className="text-decoration-none" to="/admin/builder">
                          <RichText
                            text={template.name || template.key}
                            markdownEnabled={appMarkdownEnabled}
                            mathjaxEnabled={appMathjaxEnabled}
                            inline
                          />
                        </Link>
                      </div>
                    </td>
                    <td>
                      <div className="muted">
                        Updated:{" "}
                        {template.updated_at
                          ? formatTimeICT(template.updated_at)
                          : template.created_at
                            ? formatTimeICT(template.created_at)
                            : "n/a"}
                      </div>
                    </td>
                    <td>
                      <div className="d-flex flex-wrap gap-2">
                        <Link className="btn btn-outline-secondary btn-sm" to="/admin/builder">
                          <i className="bi bi-pencil-square" aria-hidden="true" /> Edit
                        </Link>
                        <button
                          type="button"
                          className="btn btn-outline-danger btn-sm"
                          onClick={async () => {
                            if (!window.confirm("Move this template to trash?")) return;
                            const response = await apiFetch(
                              `${API_BASE}/api/admin/templates/${encodeURIComponent(template.key)}`,
                              { method: "DELETE" }
                            );
                            const payload = await response.json().catch(() => null);
                            if (!response.ok) {
                              onNotice(payload?.error || "Failed to move template to trash.", "warning");
                              return;
                            }
                            onNotice("Template moved to trash.", "success");
                            loadAdmin();
                          }}
                        >
                          <i className="bi bi-trash" aria-hidden="true" /> Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {adminSelected.templates.size > 0 ? (
          <div className="d-flex justify-content-end gap-2 mt-2">
            <button
              type="button"
              className="btn btn-outline-secondary btn-sm"
              onClick={() => clearAdminSelection("templates")}
            >
              <i className="bi bi-x-circle" aria-hidden="true" /> Clear selection
            </button>
            <button
              type="button"
              className="btn btn-outline-danger btn-sm"
              onClick={() => bulkDeleteAdmin("templates")}
            >
              <i className="bi bi-trash" aria-hidden="true" /> Delete selected
            </button>
          </div>
        ) : null}
      </section>

      <section className="panel panel--compact mb-3">
        <div className="panel-header">
          <h3 className="mb-0">Users</h3>
        </div>
        <div className="d-flex flex-wrap gap-2 align-items-end mb-2">
          <div>
            <label className="form-label">Role</label>
            <select
              className="form-select form-select-sm"
              value={userRoleFilter}
              onChange={(event) => setUserRoleFilter(event.target.value)}
            >
              <option value="all">All</option>
              <option value="admin">Admin</option>
              <option value="user">User</option>
            </select>
          </div>
          <div className="ms-auto muted">Showing: {filteredUsers.length}</div>
        </div>
        {users.length === 0 ? (
          <div className="muted">No users yet.</div>
        ) : filteredUsers.length === 0 ? (
          <div className="muted">No users match the selected filters.</div>
        ) : (
          <div className="table-responsive">
            <table className="table table-sm">
              <thead>
                <tr>
                  <th>
                    <input
                      type="checkbox"
                      className="form-check-input"
                      checked={
                        filteredUsers.length > 0 &&
                        filteredUsers
                          .slice(0, 10)
                          .every((item: any) => adminSelected.users.has(item.id))
                      }
                      onChange={() =>
                        toggleAdminAll(
                          "users",
                          filteredUsers
                            .slice(0, 10)
                            .map((item: any) => item.id)
                            .filter(Boolean)
                        )
                      }
                    />
                  </th>
                  <th>User</th>
                  <th>Role</th>
                  <th>Canvas</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredUsers.slice(0, 10).map((item) => {
                  const isAdmin = Boolean(item.is_admin ?? item.isAdmin);
                  const googleEmail = item.google_email || item.email || "";
                  const githubLogin = item.github_login || item.provider_login || "";
                  const canvasStatus = item.canvas_status || "";
                  const canvasBadge =
                    canvasStatus === "invited"
                      ? "text-bg-info"
                      : canvasStatus === "failed"
                        ? "text-bg-danger"
                        : canvasStatus === "pending"
                          ? "text-bg-warning"
                          : canvasStatus
                            ? "text-bg-success"
                            : "text-bg-secondary";
                  return (
                    <tr key={item.id}>
                      <td>
                        <input
                          type="checkbox"
                          className="form-check-input"
                          checked={adminSelected.users.has(item.id)}
                          onChange={() => toggleAdminSelected("users", item.id)}
                        />
                      </td>
                      <td>
                        {googleEmail ? (
                          <div>
                            <i className="bi bi-google" aria-hidden="true" /> {googleEmail}
                          </div>
                        ) : null}
                        {githubLogin ? (
                          <div>
                            <i className="bi bi-github" aria-hidden="true" /> {githubLogin}
                          </div>
                        ) : null}
                        {!googleEmail && !githubLogin ? <div>{item.id}</div> : null}
                        {(googleEmail || githubLogin) && item.id ? (
                          <div className="muted">{item.id}</div>
                        ) : null}
                      </td>
                      <td>
                        <span className={`badge ${isAdmin ? "text-bg-warning" : "text-bg-secondary"}`}>
                          {isAdmin ? "Admin" : "User"}
                        </span>
                      </td>
                      <td>
                        {canvasStatus ? (
                          <span className={`badge ${canvasBadge}`} title="Latest Canvas enrollment status">
                            {canvasStatus}
                          </span>
                        ) : (
                          <span className="muted">n/a</span>
                        )}
                      </td>
                      <td>
                        <div className="d-flex flex-wrap gap-2">
                          {!isAdmin ? (
                            <button
                              type="button"
                              className="btn btn-outline-primary btn-sm"
                              onClick={async () => {
                                const response = await apiFetch(
                                  `${API_BASE}/api/admin/users/${encodeURIComponent(item.id)}/promote`,
                                  { method: "POST" }
                                );
                                const payload = await response.json().catch(() => null);
                                if (!response.ok) {
                                  onNotice(payload?.error || "Failed to promote user.", "warning");
                                  return;
                                }
                                onNotice("User promoted to admin.", "success");
                                loadAdmin();
                              }}
                            >
                              <i className="bi bi-shield-plus" aria-hidden="true" /> Promote
                            </button>
                          ) : null}
                          <button
                            type="button"
                            className="btn btn-outline-danger btn-sm"
                            onClick={async () => {
                              if (!window.confirm("Move this user to trash?")) return;
                              const response = await apiFetch(
                                `${API_BASE}/api/admin/users/${encodeURIComponent(item.id)}`,
                                { method: "DELETE" }
                              );
                              const payload = await response.json().catch(() => null);
                              if (!response.ok) {
                                onNotice(payload?.error || "Failed to move user to trash.", "warning");
                                return;
                              }
                              if (payload?.canvasAction) {
                                const canvasLabel =
                                  payload.canvasAction === "deactivated"
                                    ? "deactivated"
                                    : payload.canvasAction === "failed"
                                      ? "failed"
                                      : "skipped";
                                onNotice(
                                  `User moved to trash. Canvas deactivation: ${canvasLabel}.`,
                                  payload.canvasAction === "failed" ? "warning" : "success"
                                );
                              } else {
                                onNotice("User moved to trash.", "success");
                              }
                              loadAdmin();
                            }}
                          >
                            <i className="bi bi-trash" aria-hidden="true" /> Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {adminSelected.users.size > 0 ? (
          <div className="d-flex justify-content-end gap-2 mt-2">
            <button
              type="button"
              className="btn btn-outline-secondary btn-sm"
              onClick={() => clearAdminSelection("users")}
            >
              <i className="bi bi-x-circle" aria-hidden="true" /> Clear selection
            </button>
            <button
              type="button"
              className="btn btn-outline-danger btn-sm"
              onClick={() => bulkDeleteAdmin("users")}
            >
              <i className="bi bi-trash" aria-hidden="true" /> Delete selected
            </button>
          </div>
        ) : null}
      </section>

      <section className="panel panel--compact mb-3">
        <div className="panel-header">
          <h3 className="mb-0">Submissions</h3>
        </div>
        <div className="d-flex flex-wrap gap-2 align-items-end mb-2">
          <div>
            <label className="form-label">Form</label>
            <select
              className="form-select form-select-sm"
              value={submissionFormFilter}
              onChange={(event) => setSubmissionFormFilter(event.target.value)}
            >
              <option value="">All</option>
              {forms.map((form) => (
                <option key={form.slug} value={form.slug}>
                  {form.title || form.slug}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="form-label">User</label>
            <select
              className="form-select form-select-sm"
              value={submissionUserFilter}
              onChange={(event) => setSubmissionUserFilter(event.target.value)}
            >
              <option value="">All</option>
              {userOptions.map((option) => (
                <option key={option.id} value={option.id}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
          <div className="ms-auto muted">Showing: {filteredSubmissions.length}</div>
        </div>
        {submissionsError ? <div className="alert alert-warning">{submissionsError}</div> : null}
        {submissions.length === 0 ? (
          <div className="muted">No submissions yet.</div>
        ) : filteredSubmissions.length === 0 ? (
          <div className="muted">No submissions match the selected filters.</div>
        ) : (
          <div className="table-responsive">
            <table className="table table-sm">
              <thead>
                <tr>
                  <th>
                    <input
                      type="checkbox"
                      className="form-check-input"
                      checked={
                        filteredSubmissions.length > 0 &&
                        filteredSubmissions
                          .slice(0, 10)
                          .every((item: any) => adminSelected.submissions.has(item.id))
                      }
                      onChange={() =>
                        toggleAdminAll(
                          "submissions",
                          filteredSubmissions
                            .slice(0, 10)
                            .map((item: any) => item.id)
                            .filter(Boolean)
                        )
                      }
                    />
                  </th>
                  <th>Submission</th>
                  <th>User</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredSubmissions.slice(0, 10).map((item) => {
                  const title = item.form_title || formTitleBySlug[item.form_slug] || item.id;
                  return (
                    <tr key={item.id}>
                      <td>
                        <input
                          type="checkbox"
                          className="form-check-input"
                          checked={adminSelected.submissions.has(item.id)}
                          onChange={() => toggleAdminSelected("submissions", item.id)}
                        />
                      </td>
                      <td>
                        <div>
                          <RichText
                            text={title}
                            markdownEnabled={appMarkdownEnabled}
                            mathjaxEnabled={appMathjaxEnabled}
                            inline
                          />
                        </div>
                        {title !== item.id ? (
                          <div className="muted">
                            <a
                              className="text-decoration-none"
                              href={`${PUBLIC_BASE}#/me/submissions/${item.id}`}
                            >
                              {item.id}
                            </a>
                          </div>
                        ) : null}
                      </td>
                      <td>
                        {item.submitter_email ||
                          item.submitter_github_username ||
                          userOptions.find((option) => option.id === item.user_id)?.label ||
                          item.user_id ||
                          "n/a"}
                      </td>
                      <td>{item.created_at ? formatTimeICT(item.created_at) : "n/a"}</td>
                      <td>
                        <div className="d-flex flex-wrap gap-2">
                          <select
                            className="form-select form-select-sm"
                            defaultValue=""
                            disabled={submissionExportingId === item.id}
                            onChange={(event) => {
                              const value = event.currentTarget.value as SubmissionExportFormat | "";
                              if (!value) return;
                              event.currentTarget.value = "";
                              handleAdminSubmissionExport(item.id, value);
                            }}
                          >
                            <option value="">Export...</option>
                            <option value="markdown">Markdown</option>
                            <option value="txt">TXT</option>
                            <option value="csv">CSV</option>
                          </select>
                          <button
                            type="button"
                            className="btn btn-outline-danger btn-sm"
                            onClick={async () => {
                              if (!window.confirm("Move this submission to trash?")) return;
                              const response = await apiFetch(
                                `${API_BASE}/api/admin/submissions/${encodeURIComponent(item.id)}`,
                                { method: "DELETE" }
                              );
                              const payload = await response.json().catch(() => null);
                              if (!response.ok) {
                                onNotice(payload?.error || "Failed to move submission to trash.", "warning");
                                return;
                              }
                              if (payload?.canvasAction) {
                                const canvasLabel =
                                  payload.canvasAction === "deactivated"
                                    ? "deactivated"
                                    : payload.canvasAction === "failed"
                                      ? "failed"
                                      : "skipped";
                                onNotice(
                                  `Submission moved to trash. Canvas deactivation: ${canvasLabel}.`,
                                  payload.canvasAction === "failed" ? "warning" : "success"
                                );
                              } else {
                                onNotice("Submission moved to trash.", "success");
                              }
                              loadAdmin();
                            }}
                          >
                            <i className="bi bi-trash" aria-hidden="true" /> Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {adminSelected.submissions.size > 0 ? (
          <div className="d-flex justify-content-end gap-2 mt-2">
            <button
              type="button"
              className="btn btn-outline-secondary btn-sm"
              onClick={() => clearAdminSelection("submissions")}
            >
              <i className="bi bi-x-circle" aria-hidden="true" /> Clear selection
            </button>
            <button
              type="button"
              className="btn btn-outline-danger btn-sm"
              onClick={() => bulkDeleteAdmin("submissions")}
            >
              <i className="bi bi-trash" aria-hidden="true" /> Delete selected
            </button>
          </div>
        ) : null}
      </section>

      <section className="panel panel--compact mb-3">
        <div className="panel-header">
          <h3 className="mb-0">Routine tasks</h3>
        </div>
        {routineBulkStatus ? (
          <div className="alert alert-info">
            {routineBulkStatus.label}: {routineBulkStatus.done}/{routineBulkStatus.total}
          </div>
        ) : null}
        {routineStatus ? <div className="alert alert-info">{routineStatus}</div> : null}
        {routines.length === 0 ? (
          <div className="muted">No routines configured.</div>
        ) : (
          <div className="table-responsive">
            <div className="d-flex justify-content-end gap-2 mb-2">
              <button
                type="button"
                className="btn btn-outline-secondary btn-sm"
                disabled={routineSelected.size === 0}
                onClick={() => setRoutineSelected(new Set())}
              >
                <i className="bi bi-x-circle" aria-hidden="true" /> Clear selection
              </button>
              <button
                type="button"
                className="btn btn-outline-success btn-sm"
                disabled={routineSelected.size === 0}
                onClick={() => bulkEnableRoutines(true)}
              >
                <i className="bi bi-toggle-on" aria-hidden="true" /> Enable selected
              </button>
              <button
                type="button"
                className="btn btn-outline-warning btn-sm"
                disabled={routineSelected.size === 0}
                onClick={() => bulkEnableRoutines(false)}
              >
                <i className="bi bi-toggle-off" aria-hidden="true" /> Disable selected
              </button>
              <button
                type="button"
                className="btn btn-outline-primary btn-sm"
                disabled={routineSelected.size === 0}
                onClick={bulkSaveRoutines}
              >
                <i className="bi bi-save" aria-hidden="true" /> Save selected
              </button>
              <button
                type="button"
                className="btn btn-outline-secondary btn-sm"
                disabled={routineSelected.size === 0}
                onClick={bulkRunRoutines}
              >
                <i className="bi bi-play" aria-hidden="true" /> Run selected
              </button>
            </div>
            <table className="table table-sm">
              <thead>
                <tr>
                  <th>
                    <input
                      type="checkbox"
                      className="form-check-input"
                      checked={routines.length > 0 && routines.every((task) => routineSelected.has(task.id))}
                      onChange={() =>
                        toggleRoutineAll(routines.map((task: any) => task.id).filter(Boolean))
                      }
                    />
                  </th>
                  <th>Task</th>
                  <th>Cron</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {routines.map((task) => (
                  <tr key={task.id}>
                    <td>
                      <input
                        type="checkbox"
                        className="form-check-input"
                        checked={routineSelected.has(task.id)}
                        onChange={() => toggleRoutineSelected(task.id)}
                      />
                    </td>
                    <td>{task.title || task.id}</td>
                    <td style={{ minWidth: 160 }}>
                      <input
                        className="form-control form-control-sm"
                        value={routineEdits[task.id]?.cron ?? task.cron ?? ""}
                        onChange={(event) =>
                          setRoutineEdits((prev) => ({
                            ...prev,
                            [task.id]: {
                              cron: event.target.value,
                              enabled: prev[task.id]?.enabled ?? Boolean(task.enabled)
                            }
                          }))
                        }
                      />
                    </td>
                    <td>
                      <button
                        type="button"
                        className={`badge border-0 ${task.last_status === "ok"
                          ? "text-bg-success"
                          : task.last_status
                            ? "text-bg-warning"
                            : "text-bg-secondary"
                          }`}
                        onClick={async () => {
                          const nextId = activeRoutineLogId === task.id ? null : task.id;
                          setActiveRoutineLogId(nextId);
                          if (!nextId) return;
                          const response = await apiFetch(
                            `${API_BASE}/api/admin/routines/logs?taskId=${encodeURIComponent(
                              task.id
                            )}&limit=20`
                          );
                          const payload = await response.json().catch(() => null);
                          if (!response.ok) {
                            setRoutineStatus(payload?.error || "Failed to load logs.");
                            return;
                          }
                          setRoutineLogs((prev) => ({
                            ...prev,
                            [task.id]: Array.isArray(payload?.data) ? payload.data : []
                          }));
                        }}
                        title="View logs"
                      >
                        {task.last_status || "n/a"}
                      </button>
                      <div className="muted">
                        {task.last_run_at ? formatTimeICT(task.last_run_at) : "Never run"}
                      </div>
                    </td>
                    <td>
                      <div className="d-flex flex-wrap gap-2">
                        <button
                          type="button"
                          className="btn btn-outline-primary btn-sm"
                          onClick={async () => {
                            setRoutineStatus(null);
                            const edit = routineEdits[task.id] || {
                              cron: task.cron,
                              enabled: Boolean(task.enabled)
                            };
                            const response = await apiFetch(`${API_BASE}/api/admin/routines`, {
                              method: "POST",
                              headers: { "content-type": "application/json" },
                              body: JSON.stringify({
                                id: task.id,
                                cron: edit.cron,
                                enabled: edit.enabled
                              })
                            });
                            const payload = await response.json().catch(() => null);
                            if (!response.ok) {
                              setRoutineStatus(payload?.error || "Failed to update routine.");
                              return;
                            }
                            setRoutineStatus("Routine updated.");
                            loadAdmin();
                          }}
                        >
                          <i className="bi bi-save" aria-hidden="true" /> Save
                        </button>
                        {routineEdits[task.id]?.enabled ?? Boolean(task.enabled) ? (
                          <button
                            type="button"
                            className="btn btn-outline-warning btn-sm"
                            onClick={async () => {
                              setRoutineStatus(null);
                              const response = await apiFetch(`${API_BASE}/api/admin/routines`, {
                                method: "POST",
                                headers: { "content-type": "application/json" },
                                body: JSON.stringify({
                                  id: task.id,
                                  cron: routineEdits[task.id]?.cron ?? task.cron ?? "",
                                  enabled: false
                                })
                              });
                              const payload = await response.json().catch(() => null);
                              if (!response.ok) {
                                setRoutineStatus(payload?.error || "Failed to disable routine.");
                                return;
                              }
                              setRoutineEdits((prev) => ({
                                ...prev,
                                [task.id]: {
                                  cron: prev[task.id]?.cron ?? task.cron ?? "",
                                  enabled: false
                                }
                              }));
                              setRoutineStatus("Routine disabled.");
                              loadAdmin();
                            }}
                          >
                            <i className="bi bi-toggle-off" aria-hidden="true" /> Disable
                          </button>
                        ) : (
                          <button
                            type="button"
                            className="btn btn-outline-success btn-sm"
                            onClick={async () => {
                              setRoutineStatus(null);
                              const response = await apiFetch(`${API_BASE}/api/admin/routines`, {
                                method: "POST",
                                headers: { "content-type": "application/json" },
                                body: JSON.stringify({
                                  id: task.id,
                                  cron: routineEdits[task.id]?.cron ?? task.cron ?? "",
                                  enabled: true
                                })
                              });
                              const payload = await response.json().catch(() => null);
                              if (!response.ok) {
                                setRoutineStatus(payload?.error || "Failed to enable routine.");
                                return;
                              }
                              setRoutineEdits((prev) => ({
                                ...prev,
                                [task.id]: {
                                  cron: prev[task.id]?.cron ?? task.cron ?? "",
                                  enabled: true
                                }
                              }));
                              setRoutineStatus("Routine enabled.");
                              loadAdmin();
                            }}
                          >
                            <i className="bi bi-toggle-on" aria-hidden="true" /> Enable
                          </button>
                        )}
                        <button
                          type="button"
                          className="btn btn-outline-secondary btn-sm"
                          onClick={async () => {
                            setRoutineStatus(null);
                            const response = await apiFetch(`${API_BASE}/api/admin/routines/run`, {
                              method: "POST",
                              headers: { "content-type": "application/json" },
                              body: JSON.stringify({ id: task.id })
                            });
                            const payload = await response.json().catch(() => null);
                            if (!response.ok) {
                              setRoutineStatus(payload?.error || "Failed to run routine.");
                              return;
                            }
                            setRoutineStatus("Routine run triggered.");
                            loadAdmin();
                          }}
                        >
                          <i className="bi bi-play" aria-hidden="true" /> Run
                        </button>
                        {/* Logs are accessible via status badge */}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {activeRoutineLogId ? (
              <div className="mt-3">
                <div className="d-flex flex-wrap justify-content-between align-items-center mb-2">
                  <div className="muted">
                    Logs for{" "}
                    <strong>
                      {routines.find((task) => task.id === activeRoutineLogId)?.title ||
                        activeRoutineLogId}
                    </strong>
                  </div>
                  <button
                    type="button"
                    className="btn btn-outline-danger btn-sm"
                    onClick={async () => {
                      if (!window.confirm("Clear logs for this routine?")) return;
                      const response = await apiFetch(
                        `${API_BASE}/api/admin/routines/logs/clear`,
                        {
                          method: "POST",
                          headers: { "content-type": "application/json" },
                          body: JSON.stringify({ taskId: activeRoutineLogId })
                        }
                      );
                      const payload = await response.json().catch(() => null);
                      if (!response.ok) {
                        setRoutineStatus(payload?.error || "Failed to clear logs.");
                        return;
                      }
                      setRoutineStatus("Logs cleared.");
                      setRoutineLogs((prev) => ({ ...prev, [activeRoutineLogId]: [] }));
                      loadAdmin();
                    }}
                  >
                    <i className="bi bi-trash" aria-hidden="true" /> Clear logs
                  </button>
                </div>
                <div className="table-responsive">
                  <table className="table table-sm">
                    <thead>
                      <tr>
                        <th>Run at</th>
                        <th>Status</th>
                        <th>Message</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(routineLogs[activeRoutineLogId] || []).map((entry) => (
                        <tr key={entry.id}>
                          <td>{entry.run_at ? formatTimeICT(entry.run_at) : "n/a"}</td>
                          <td>{entry.status || "n/a"}</td>
                          <td>{entry.message || "n/a"}</td>
                        </tr>
                      ))}
                      {!routineLogs[activeRoutineLogId]?.length ? (
                        <tr>
                          <td colSpan={3}>No logs yet.</td>
                        </tr>
                      ) : null}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : null}
          </div>
        )}
      </section>

      <section className="panel panel--compact mb-3">
        <div className="panel-header">
          <h3 className="mb-0">Health summary</h3>
          <button
            type="button"
            className="btn btn-outline-danger btn-sm"
            onClick={async () => {
              if (!window.confirm("Clear health history logs?")) return;
              const response = await apiFetch(`${API_BASE}/api/admin/health/clear`, {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({})
              });
              const payload = await response.json().catch(() => null);
              if (!response.ok) {
                setRoutineStatus(payload?.error || "Failed to clear health logs.");
                return;
              }
              setRoutineStatus("Health history cleared.");
              loadAdmin();
            }}
          >
            <i className="bi bi-trash" aria-hidden="true" /> Clear logs
          </button>
        </div>
        {healthSummary.length === 0 ? (
          <div className="muted">No health data yet.</div>
        ) : (
          <div className="table-responsive">
            <table className="table table-sm">
              <thead>
                <tr>
                  <th>Service</th>
                  <th>Status</th>
                  <th>Checked</th>
                </tr>
              </thead>
              <tbody>
                {healthSummary.map((entry) => (
                  <tr key={`${entry.service}-${entry.checked_at}`}>
                    <td>{entry.service_title || entry.service}</td>
                    <td>
                      <span className={`badge ${entry.status === "ok" ? "text-bg-success" : entry.status === "error" ? "text-bg-danger" : "text-bg-secondary"}`}>
                        {entry.status || "n/a"}
                      </span>
                    </td>
                    <td>{entry.checked_at ? formatTimeICT(entry.checked_at) : "n/a"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </section>
  );
}

function AdminEmailsPage({
  user,
  onLogin,
  markdownEnabled,
  mathjaxEnabled
}: {
  user: UserInfo | null;
  onLogin: (p: "google" | "github") => void;
  markdownEnabled: boolean;
  mathjaxEnabled: boolean;
}) {
  const [status, setStatus] = useState<"loading" | "ok" | "forbidden">("loading");
  const [emails, setEmails] = useState<any[]>([]);
  const [selectedEmailIds, setSelectedEmailIds] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(50);
  const [total, setTotal] = useState(0);
  const [filterStatus, setFilterStatus] = useState("");
  const [filterEmail, setFilterEmail] = useState("");
  const [filterUserId, setFilterUserId] = useState("");
  const [filterForm, setFilterForm] = useState("");
  const [forms, setForms] = useState<Array<{ slug: string; title: string }>>([]);
  const [users, setUsers] = useState<Array<{ id: string; email?: string | null; google_email?: string | null }>>([]);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [testRecipient, setTestRecipient] = useState("");
  const [testUserId, setTestUserId] = useState("");
  const [testSubject, setTestSubject] = useState("Test email from Form App");
  const [testBody, setTestBody] = useState("This is a test email from Form App.");
  const [testPresetKey, setTestPresetKey] = useState("custom");
  const [testPresetList, setTestPresetList] = useState<
    Array<{ key: string; label: string; subject?: string; body?: string }>
  >([]);
  const [testStatus, setTestStatus] = useState<string | null>(null);
  const [actionStatus, setActionStatus] = useState<{ message: string; type: NoticeType } | null>(
    null
  );
  const testPresets = useMemo(() => {
    const custom = [{ key: "custom", label: "Custom" }];
    return [...custom, ...(Array.isArray(testPresetList) ? testPresetList : [])];
  }, [testPresetList]);
  const usersById = useMemo(() => {
    const map = new Map<string, { id: string; email?: string | null; google_email?: string | null }>();
    users.forEach((item) => {
      map.set(item.id, item);
    });
    return map;
  }, [users]);
  const testUserEmails = useMemo(() => {
    if (!testUserId) return [];
    const userInfo = usersById.get(testUserId);
    if (!userInfo) return [];
    const emails = new Set<string>();
    if (userInfo.email) emails.add(userInfo.email.trim());
    if (userInfo.google_email) emails.add(userInfo.google_email.trim());
    return Array.from(emails).filter(Boolean);
  }, [testUserId, usersById]);

  useEffect(() => {
    let active = true;
    async function loadForms() {
      const response = await apiFetch(`${API_BASE}/api/admin/forms`);
      const payload = await response.json().catch(() => null);
      if (!active) return;
      if (!response.ok || !Array.isArray(payload?.data)) {
        setForms([]);
        return;
      }
      setForms(
        payload.data
          .filter((item: any) => item?.slug)
          .map((item: any) => ({ slug: String(item.slug), title: String(item.title || item.slug) }))
      );
    }
    loadForms();
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    async function loadUsers() {
      const response = await apiFetch(`${API_BASE}/api/admin/users`);
      const payload = await response.json().catch(() => null);
      if (!active) return;
      if (!response.ok || !Array.isArray(payload?.data)) {
        setUsers([]);
        return;
      }
      setUsers(
        payload.data
          .filter((item: any) => item?.id)
          .map((item: any) => ({
            id: String(item.id),
            email: typeof item.email === "string" ? item.email : null,
            google_email: typeof item.google_email === "string" ? item.google_email : null
          }))
      );
    }
    loadUsers();
    const handleFocus = () => {
      loadUsers();
    };
    const refreshId = window.setInterval(loadUsers, 60000);
    window.addEventListener("focus", handleFocus);
    return () => {
      active = false;
      window.removeEventListener("focus", handleFocus);
      window.clearInterval(refreshId);
    };
  }, []);

  useEffect(() => {
    let active = true;
    async function loadPresets() {
      const response = await apiFetch(`${API_BASE}/api/admin/emails/presets`);
      const payload = await response.json().catch(() => null);
      if (!active) return;
      if (!response.ok || !Array.isArray(payload?.data)) {
        setTestPresetList([]);
        return;
      }
      setTestPresetList(
        Array.isArray(payload?.data)
          ? payload.data.map((p: any) => ({
            key: String(p.key),
            label: String(p.label),
            subject: p.subject ? String(p.subject) : undefined,
            body: p.body ? String(p.body) : undefined
          }))
          : []
      );
    }
    loadPresets();
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    async function loadEmails() {
      setStatus("loading");
      const params = new URLSearchParams();
      params.set("page", String(page));
      params.set("pageSize", String(pageSize));
      params.set("includeBody", "1");
      if (filterStatus) params.set("status", filterStatus);
      if (filterEmail) params.set("email", filterEmail);
      if (filterUserId) params.set("userId", filterUserId);
      if (filterForm) params.set("formSlug", filterForm);
      const response = await apiFetch(`${API_BASE}/api/admin/emails?${params.toString()}`);
      const payload = await response.json().catch(() => null);
      if (!active) return;
      if (response.status === 401 || response.status === 403) {
        setStatus("forbidden");
        return;
      }
      if (!response.ok) {
        setError(payload?.error || "Failed to load emails.");
        setStatus("ok");
        return;
      }
      setEmails(Array.isArray(payload?.data) ? payload.data : []);
      setSelectedEmailIds(new Set());
      setTotal(payload?.total || 0);
      setError(null);
      setStatus("ok");
    }
    loadEmails();
    return () => {
      active = false;
    };
  }, [page, pageSize, filterStatus, filterEmail, filterUserId, filterForm]);

  if (status === "loading") {
    return (
      <section className="panel">
        <h2>Loading emails...</h2>
      </section>
    );
  }

  if (status === "forbidden") {
    return (
      <section className="panel panel--error">
        <h2>Not authorized</h2>
        <p>Please sign in with an admin account.</p>
        <div className="auth-bar">
          <button type="button" className="btn btn-primary btn-auth" onClick={() => onLogin("google")}>
            <i className="bi bi-google" aria-hidden="true" /> Login with Google
          </button>
          <button type="button" className="btn btn-dark btn-auth" onClick={() => onLogin("github")}>
            <i className="bi bi-github" aria-hidden="true" /> Login with GitHub
          </button>
        </div>
      </section>
    );
  }

  return (
    <section className="panel admin-scope">
      <div className="panel-header">
        <h2>Emails</h2>
        {user ? <span className="badge">{getUserDisplayName(user)}</span> : null}
      </div>
      {actionStatus ? (
        <div className={`alert alert-${actionStatus.type === "success" ? "success" : "warning"}`}>
          {actionStatus.message}
        </div>
      ) : null}
      {error ? <div className="alert alert-warning">{error}</div> : null}
      <div className="panel panel--compact mb-3">
        <div className="panel-header">
          <h3 className="mb-0">Test email</h3>
        </div>
        <div className="row g-3">
          <div className="col-md-4">
            <label className="form-label">Preset</label>
            <select
              className="form-select"
              value={testPresetKey}
              onChange={(event) => {
                const nextKey = event.target.value;
                setTestPresetKey(nextKey);
                const preset = testPresets.find((item) => item.key === nextKey);
                if ((preset as any)?.subject) {
                  setTestSubject((preset as any).subject);
                }
                if ((preset as any)?.body) {
                  setTestBody((preset as any).body);
                }
              }}
            >
              {testPresets.map((preset) => (
                <option key={preset.key} value={preset.key}>
                  {preset.label}
                </option>
              ))}
            </select>
            <div className="muted mt-1">Selecting a preset will overwrite the subject/body.</div>
          </div>
          <div className="col-md-4">
            <label className="form-label">Recipient user</label>
            <select
              className="form-select"
              value={testUserId}
              onChange={(event) => {
                const nextUserId = event.target.value;
                setTestUserId(nextUserId);
                const userInfo = usersById.get(nextUserId);
                const nextEmail =
                  (userInfo?.email && userInfo.email.trim()) ||
                  (userInfo?.google_email && userInfo.google_email.trim()) ||
                  "";
                setTestRecipient(nextEmail);
              }}
            >
              <option value="">Select user</option>
              {users.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.email || item.google_email || item.id}
                </option>
              ))}
            </select>
            {testUserId && testUserEmails.length === 0 ? (
              <div className="muted mt-1">No emails found for this user.</div>
            ) : null}
            {testUserEmails.length > 1 ? (
              <div className="muted mt-1">Will send to {testUserEmails.length} linked emails.</div>
            ) : null}
          </div>
          <div className="col-md-4">
            <label className="form-label">Recipient</label>
            <input
              className="form-control"
              value={testRecipient}
              onChange={(event) => setTestRecipient(event.target.value)}
              placeholder="example@domain.com"
            />
          </div>
          <div className="col-md-8">
            <label className="form-label">Subject</label>
            <input
              className="form-control"
              value={testSubject}
              onChange={(event) => setTestSubject(event.target.value)}
            />
          </div>
          <div className="col-12">
            <label className="form-label">Body</label>
            <textarea
              className="form-control"
              rows={4}
              value={testBody}
              onChange={(event) => setTestBody(event.target.value)}
            />
          </div>
          <div className="col-12 d-flex flex-wrap gap-2 align-items-center">
            <button
              type="button"
              className="btn btn-outline-primary"
              onClick={async () => {
                setTestStatus(null);
                if (!testRecipient.trim()) {
                  setTestStatus("Recipient is required.");
                  return;
                }
                const response = await apiFetch(`${API_BASE}/api/admin/emails/test`, {
                  method: "POST",
                  headers: { "content-type": "application/json" },
                  body: JSON.stringify({
                    to: testRecipient.trim(),
                    subject: testSubject.trim() || "Test email from Form App",
                    body: testBody.trim() || "This is a test email from Form App."
                  })
                });
                const payload = await response.json().catch(() => null);
                if (!response.ok) {
                  const detailMessage =
                    payload?.detail?.message ||
                    payload?.detail?.field ||
                    (typeof payload?.detail === "string" ? payload.detail : null);
                  setTestStatus(
                    detailMessage
                      ? `${payload?.error || "Failed to send test email"}: ${detailMessage}`
                      : payload?.error || "Failed to send test email."
                  );
                  return;
                }
                setTestStatus("Test email is sent.");
              }}
            >
              <i className="bi bi-send" aria-hidden="true" /> Send test email
            </button>
            <button
              type="button"
              className="btn btn-outline-secondary"
              disabled={!testUserId || testUserEmails.length === 0}
              onClick={async () => {
                setTestStatus(null);
                if (!testUserId || testUserEmails.length === 0) {
                  setTestStatus("Select a user with a linked email.");
                  return;
                }
                const failures: string[] = [];
                for (const email of testUserEmails) {
                  const response = await apiFetch(`${API_BASE}/api/admin/emails/test`, {
                    method: "POST",
                    headers: { "content-type": "application/json" },
                    body: JSON.stringify({
                      to: email,
                      subject: testSubject.trim() || "Test email from Form App",
                      body: testBody.trim() || "This is a test email from Form App."
                    })
                  });
                  if (!response.ok) {
                    const payload = await response.json().catch(() => null);
                    failures.push(payload?.error || "send_failed");
                  }
                }
                if (failures.length > 0) {
                  setTestStatus(`Failed to send to ${failures.length} email(s).`);
                  return;
                }
                setTestStatus(`Test email sent to ${testUserEmails.length} linked email(s).`);
              }}
            >
              <i className="bi bi-person" aria-hidden="true" /> Send to user
            </button>
            {testStatus ? <span className="muted">{testStatus}</span> : null}
          </div>
        </div>
      </div>
      <div className="d-flex flex-wrap gap-2 align-items-end mb-3">
        <div>
          <label className="form-label">Status</label>
          <select
            className="form-select form-select-sm"
            value={filterStatus}
            onChange={(event) => {
              setPage(1);
              setFilterStatus(event.target.value);
            }}
          >
            <option value="">All</option>
            <option value="sent">Sent</option>
            <option value="failed">Failed</option>
          </select>
        </div>
        <div>
          <label className="form-label">Recipient</label>
          <input
            className="form-control form-control-sm"
            value={filterEmail}
            onChange={(event) => {
              setPage(1);
              setFilterEmail(event.target.value);
            }}
            placeholder="Search email"
          />
        </div>
        <div>
          <label className="form-label">User</label>
          <select
            className="form-select form-select-sm"
            value={filterUserId}
            onChange={(event) => {
              setPage(1);
              setFilterUserId(event.target.value);
            }}
          >
            <option value="">All</option>
            {users.map((item) => (
              <option key={item.id} value={item.id}>
                {item.email || item.google_email || item.id}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="form-label">Form</label>
          <select
            className="form-select form-select-sm"
            value={filterForm}
            onChange={(event) => {
              setPage(1);
              setFilterForm(event.target.value);
            }}
          >
            <option value="">All</option>
            {forms.map((form) => (
              <option key={form.slug} value={form.slug}>
                {form.title}
              </option>
            ))}
          </select>
        </div>
        <div className="ms-auto muted">Total: {total}</div>
        {selectedEmailIds.size > 0 ? (
          <>
            <button
              type="button"
              className="btn btn-outline-danger btn-sm"
              onClick={async () => {
                setActionStatus(null);
                if (!window.confirm("Move selected emails to trash?")) {
                  return;
                }
                const ids = Array.from(selectedEmailIds);
                let failed = 0;
                for (const id of ids) {
                  const response = await apiFetch(
                    `${API_BASE}/api/admin/emails/${encodeURIComponent(id)}`,
                    { method: "DELETE" }
                  );
                  if (!response.ok) {
                    failed += 1;
                  }
                }
                setEmails((prev) => prev.filter((entry) => !selectedEmailIds.has(entry.id)));
                setTotal((prev) => Math.max(0, prev - (ids.length - failed)));
                setSelectedEmailIds(new Set());
                setActionStatus({
                  message:
                    failed > 0
                      ? `Moved ${ids.length - failed} email(s) to trash. ${failed} failed.`
                      : `Moved ${ids.length} email(s) to trash.`,
                  type: failed > 0 ? "warning" : "success"
                });
              }}
            >
              <i className="bi bi-trash" aria-hidden="true" /> Delete selected
            </button>
            <button
              type="button"
              className="btn btn-outline-secondary btn-sm"
              onClick={() => setSelectedEmailIds(new Set())}
            >
              <i className="bi bi-x-circle" aria-hidden="true" /> Clear selection
            </button>
          </>
        ) : null}
      </div>
      <div className="table-responsive">
        <table className="table table-sm">
          <thead>
            <tr>
              <th>
                <input
                  type="checkbox"
                  aria-label="Select all emails"
                  checked={emails.length > 0 && selectedEmailIds.size === emails.length}
                  onChange={(event) => {
                    if (event.target.checked) {
                      setSelectedEmailIds(new Set(emails.map((item) => item.id)));
                    } else {
                      setSelectedEmailIds(new Set());
                    }
                  }}
                />
              </th>
              <th>Sent at</th>
              <th>To</th>
              <th>Subject</th>
              <th>Status</th>
              <th>Submission</th>
              <th>Source</th>
              <th>Error</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {emails.length === 0 ? (
              <tr>
                <td colSpan={9}>No emails found.</td>
              </tr>
            ) : (
              emails.map((item) => {
                const isExpanded = expanded.has(item.id);
                return (
                  <Fragment key={item.id}>
                    <tr>
                      <td>
                        <input
                          type="checkbox"
                          aria-label={`Select email ${item.id}`}
                          checked={selectedEmailIds.has(item.id)}
                          onChange={(event) => {
                            const next = new Set(selectedEmailIds);
                            if (event.target.checked) {
                              next.add(item.id);
                            } else {
                              next.delete(item.id);
                            }
                            setSelectedEmailIds(next);
                          }}
                        />
                      </td>
                      <td>{item.created_at ? formatTimeICT(item.created_at) : "n/a"}</td>
                      <td>{item.to_email}</td>
                      <td>{item.subject}</td>
                      <td>
                        <span
                          className={`badge ${item.status === "sent"
                            ? "text-bg-success"
                            : item.status === "failed"
                              ? "text-bg-danger"
                              : "text-bg-secondary"
                            }`}
                        >
                          {item.status}
                        </span>
                      </td>
                      <td>
                        {item.submission_id ? (
                          <Link to={`/me/submissions/${item.submission_id}`} title={item.submission_id}>
                            <RichText
                              text={item.form_title || item.form_slug || "Submission"}
                              markdownEnabled={markdownEnabled}
                              mathjaxEnabled={mathjaxEnabled}
                              inline
                            />
                          </Link>
                        ) : (
                          <span className="muted">n/a</span>
                        )}
                        {item.submission_id && item.form_title ? (
                          <div className="muted">{item.submission_id}</div>
                        ) : null}
                      </td>
                      <td>{item.trigger_source || "n/a"}</td>
                      <td className="text-break">{item.error || "—"}</td>
                      <td>
                        <div className="d-flex gap-2">
                          <button
                            type="button"
                            className="btn btn-outline-secondary btn-sm"
                            onClick={() => {
                              const next = new Set(expanded);
                              if (isExpanded) {
                                next.delete(item.id);
                              } else {
                                next.add(item.id);
                              }
                              setExpanded(next);
                            }}
                          >
                            <i className="bi bi-eye" aria-hidden="true" />{" "}
                            {isExpanded ? "Hide" : "View"}
                          </button>
                          <button
                            type="button"
                            className="btn btn-outline-danger btn-sm"
                            onClick={async () => {
                              setActionStatus(null);
                              if (!window.confirm("Move this email to trash?")) {
                                return;
                              }
                              const response = await apiFetch(
                                `${API_BASE}/api/admin/emails/${encodeURIComponent(item.id)}`,
                                { method: "DELETE" }
                              );
                              const payload = await response.json().catch(() => null);
                              if (!response.ok) {
                                setActionStatus({
                                  message: payload?.error || "Delete failed.",
                                  type: "warning"
                                });
                                return;
                              }
                              setEmails((prev) => prev.filter((entry) => entry.id !== item.id));
                              setTotal((prev) => Math.max(0, prev - 1));
                              setActionStatus({ message: "Email moved to trash.", type: "success" });
                            }}
                          >
                            <i className="bi bi-trash" aria-hidden="true" /> Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                    {isExpanded ? (
                      <tr>
                        <td colSpan={9}>
                          <div className="panel panel--compact">
                            <div className="panel-header">
                              <strong>Body</strong>
                            </div>
                            <pre className="m-0">{item.body}</pre>
                          </div>
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>
      <div className="d-flex gap-2 justify-content-end">
        <button
          type="button"
          className="btn btn-outline-secondary btn-sm"
          disabled={page <= 1}
          onClick={() => setPage((prev) => Math.max(1, prev - 1))}
        >
          <i className="bi bi-arrow-left" aria-hidden="true" /> Prev
        </button>
        <button
          type="button"
          className="btn btn-outline-secondary btn-sm"
          disabled={page * pageSize >= total}
          onClick={() => setPage((prev) => prev + 1)}
        >
          Next <i className="bi bi-arrow-right" aria-hidden="true" />
        </button>
      </div>
    </section>
  );
}

function TrashPage({
  user,
  onLogin,
  onNotice,
  markdownEnabled,
  mathjaxEnabled
}: {
  user: UserInfo | null;
  onLogin: (provider: "google" | "github") => void;
  onNotice: (message: string, type?: NoticeType) => void;
  markdownEnabled: boolean;
  mathjaxEnabled: boolean;
}) {
  const isAdmin = Boolean(user?.isAdmin);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [trashType, setTrashType] = useState("all");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [data, setData] = useState<Record<string, any[]>>({});
  const [totals, setTotals] = useState<Record<string, number>>({});
  const [selected, setSelected] = useState<Record<string, Set<string>>>({});
  const [bulkStatus, setBulkStatus] = useState<{ label: string; done: number; total: number } | null>(
    null
  );

  const typeOptions = isAdmin
    ? [
      { value: "all", label: "All" },
      { value: "forms", label: "Forms" },
      { value: "templates", label: "Templates" },
      { value: "users", label: "Users" },
      { value: "submissions", label: "Submissions" },
      { value: "files", label: "Files" },
      { value: "emails", label: "Emails" }
    ]
    : [
      { value: "all", label: "All" },
      { value: "submissions", label: "Submissions" },
      { value: "files", label: "Files" }
    ];

  function startBulk(label: string, total: number) {
    setBulkStatus({ label, done: 0, total });
  }

  function advanceBulk() {
    setBulkStatus((prev) =>
      prev ? { ...prev, done: Math.min(prev.done + 1, prev.total) } : prev
    );
  }

  function finishBulk(message?: string) {
    if (message) {
      onNotice(message, "success");
    }
    setBulkStatus(null);
  }

  function toggleSelected(type: string, id: string) {
    setSelected((prev) => {
      const next = new Set(prev[type] ?? []);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return { ...prev, [type]: next };
    });
  }

  function toggleAllSelected(type: string, ids: string[]) {
    setSelected((prev) => {
      const current = prev[type] ?? new Set<string>();
      const next = new Set<string>();
      if (ids.some((id) => !current.has(id))) {
        ids.forEach((id) => next.add(id));
      }
      return { ...prev, [type]: next };
    });
  }

  function toSingular(type: string) {
    return type.endsWith("s") ? type.slice(0, -1) : type;
  }

  async function loadTrash() {
    setLoading(true);
    setError(null);
    const endpoint = isAdmin ? "/api/admin/trash" : "/api/me/trash";
    const params = new URLSearchParams();
    params.set("type", trashType);
    params.set("page", String(page));
    params.set("pageSize", String(pageSize));
    const response = await apiFetch(`${API_BASE}${endpoint}?${params.toString()}`);
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setError(payload?.error || "Failed to load trash.");
      setLoading(false);
      return;
    }
    setData(payload?.data || {});
    setTotals(payload?.totals || {});
    setLoading(false);
  }

  useEffect(() => {
    if (!user) {
      setLoading(false);
      return;
    }
    let active = true;
    loadTrash().catch(() => {
      if (active) setError("Failed to load trash.");
    });
    return () => {
      active = false;
    };
  }, [user, isAdmin, trashType, page, pageSize]);

  if (!user) {
    return (
      <section className="panel panel--error">
        <h2>Sign in required</h2>
        <p>Please sign in to view trash.</p>
        <div className="auth-bar">
          <button type="button" className="btn btn-primary btn-auth" onClick={() => onLogin("google")}>
            <i className="bi bi-google" aria-hidden="true" /> Login with Google
          </button>
          <button type="button" className="btn btn-dark btn-auth" onClick={() => onLogin("github")}>
            <i className="bi bi-github" aria-hidden="true" /> Login with GitHub
          </button>
        </div>
      </section>
    );
  }

  async function restoreItem(type: string, id: string) {
    const endpoint = isAdmin ? "/api/admin/trash/restore" : "/api/me/trash/restore";
    const response = await apiFetch(`${API_BASE}${endpoint}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ type, id })
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setError(payload?.error || "Restore failed.");
      return;
    }
    await loadTrash();
    if (type === "submission") {
      if (payload?.canvasAction) {
        const canvasLabel = String(payload.canvasAction);
        onNotice(
          `Item restored. Canvas status: ${canvasLabel}.`,
          payload?.canvasWarning ? "warning" : "success"
        );
      } else {
        onNotice("Item restored.", "success");
      }
    } else {
      onNotice("Item restored.", "success");
    }
  }

  async function purgeItem(type: string, id: string) {
    if (!window.confirm("Permanently delete this item? This cannot be undone.")) {
      return;
    }
    const endpoint = isAdmin ? "/api/admin/trash/purge" : "/api/me/trash/purge";
    const response = await apiFetch(`${API_BASE}${endpoint}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ type, id })
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setError(payload?.error || "Permanent delete failed.");
      return;
    }
    if ((type === "user" || type === "submission") && payload?.canvasAction) {
      const canvasLabel =
        payload.canvasAction === "unenrolled" ? "unenrolled" : "skipped";
      onNotice(
        `Item deleted. Canvas unenroll: ${canvasLabel}.`,
        payload.canvasAction === "skipped" ? "warning" : "success"
      );
    } else {
      onNotice("Item deleted.", "success");
    }
    await loadTrash();
  }

  async function emptyTrash() {
    if (!window.confirm("Permanently delete all items in trash? This cannot be undone.")) {
      return;
    }
    const endpoint = isAdmin ? "/api/admin/trash/empty" : "/api/me/trash/empty";
    startBulk("Emptying trash", 1);
    const response = await apiFetch(`${API_BASE}${endpoint}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ type: trashType })
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setError(payload?.error || "Empty trash failed.");
      setBulkStatus(null);
      return;
    }
    advanceBulk();
    const summary = payload?.canvasSummary;
    if (summary && (summary.users || summary.submissions)) {
      const usersSummary = summary.users
        ? `${summary.users.unenrolled || 0} users unenrolled, ${summary.users.skipped || 0} skipped`
        : null;
      const submissionsSummary = summary.submissions
        ? `${summary.submissions.unenrolled || 0} submissions unenrolled, ${summary.submissions.skipped || 0} skipped`
        : null;
      const parts = [usersSummary, submissionsSummary].filter(Boolean);
      finishBulk(parts.length > 0 ? `Trash emptied. Canvas unenroll: ${parts.join(" | ")}.` : "Trash emptied.");
    } else {
      finishBulk("Trash emptied.");
    }
    await loadTrash();
  }

  async function bulkRestore(type: string) {
    const ids = Array.from(selected[type] ?? []);
    if (ids.length === 0) return;
    startBulk("Restoring items", ids.length);
    for (const id of ids) {
      await restoreItem(toSingular(type), id);
      advanceBulk();
    }
    setSelected((prev) => ({ ...prev, [type]: new Set() }));
    finishBulk("Items restored.");
  }

  async function bulkPurge(type: string) {
    const ids = Array.from(selected[type] ?? []);
    if (ids.length === 0) return;
    if (!window.confirm("Permanently delete selected items? This cannot be undone.")) {
      return;
    }
    startBulk("Permanently deleting items", ids.length);
    const singular = toSingular(type);
    const canvasSummary = { unenrolled: 0, skipped: 0 };
    for (const id of ids) {
      const response = await apiFetch(`${API_BASE}${isAdmin ? "/api/admin/trash/purge" : "/api/me/trash/purge"}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ type: singular, id })
      });
      const payload = await response.json().catch(() => null);
      if (!response.ok) {
        setError(payload?.error || "Permanent delete failed.");
      } else if ((singular === "user" || singular === "submission") && payload?.canvasAction) {
        if (payload.canvasAction === "unenrolled") {
          canvasSummary.unenrolled += 1;
        } else {
          canvasSummary.skipped += 1;
        }
      }
      advanceBulk();
    }
    setSelected((prev) => ({ ...prev, [type]: new Set() }));
    if ((singular === "user" || singular === "submission") && (canvasSummary.unenrolled || canvasSummary.skipped)) {
      finishBulk(
        `Items deleted. Canvas unenroll: ${canvasSummary.unenrolled} unenrolled, ${canvasSummary.skipped} skipped.`
      );
    } else {
      finishBulk("Items deleted.");
    }
    await loadTrash();
  }

  const forms = Array.isArray(data.forms) ? data.forms : [];
  const templates = Array.isArray(data.templates) ? data.templates : [];
  const users = Array.isArray(data.users) ? data.users : [];
  const submissions = Array.isArray(data.submissions) ? data.submissions : [];
  const files = Array.isArray(data.files) ? data.files : [];
  const emails = Array.isArray(data.emails) ? data.emails : [];

  function renderBulkControls(type: string, rowIds: string[]) {
    return (
      <div className="d-flex gap-2 mt-2">
        <button
          type="button"
          className="btn btn-outline-secondary btn-sm"
          disabled={(selected[type] ?? new Set()).size === 0}
          onClick={() => bulkRestore(type)}
        >
          <i className="bi bi-arrow-counterclockwise" aria-hidden="true" /> Restore selected
        </button>
        {isAdmin ? (
          <button
            type="button"
            className="btn btn-outline-danger btn-sm"
            disabled={(selected[type] ?? new Set()).size === 0}
            onClick={() => bulkPurge(type)}
          >
            <i className="bi bi-trash" aria-hidden="true" /> Delete selected
          </button>
        ) : null}
      </div>
    );
  }

  return (
    <section className={`panel ${isAdmin ? "admin-scope" : ""}`}>
      <div className="panel-header">
        <h2>Trash</h2>
        {user ? <span className="badge">{getUserDisplayName(user)}</span> : null}
      </div>
      {bulkStatus ? (
        <div className="alert alert-info">
          {bulkStatus.label}: {bulkStatus.done}/{bulkStatus.total}
        </div>
      ) : null}
      {error ? <div className="alert alert-warning">{error}</div> : null}
      <div className="d-flex align-items-center gap-2 mb-3">
        <select
          className="form-select w-auto"
          value={trashType}
          onChange={(event) => {
            setTrashType(event.target.value);
            setPage(1);
          }}
        >
          {typeOptions.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
        {loading ? <span className="muted">Loading...</span> : null}
        {isAdmin ? (
          <button
            type="button"
            className="btn btn-outline-danger btn-sm ms-auto"
            onClick={emptyTrash}
          >
            <i className="bi bi-trash3" aria-hidden="true" /> Empty trash
          </button>
        ) : null}
      </div>

      {(trashType === "all" || trashType === "forms") && isAdmin ? (
        <div className="table-responsive mb-4">
          <table className="table table-sm">
            <thead>
              <tr>
                <th>
                  <input
                    type="checkbox"
                    className="form-check-input"
                    checked={
                      forms.length > 0 &&
                      forms.every((item: any) => (selected.forms ?? new Set()).has(item.slug))
                    }
                    onChange={() =>
                      toggleAllSelected(
                        "forms",
                        forms.map((item: any) => item.slug).filter(Boolean)
                      )
                    }
                  />
                </th>
                <th>Form</th>
                <th>Deleted</th>
                <th>Reason</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {forms.length === 0 ? (
                <tr>
                  <td colSpan={5}>No deleted forms.</td>
                </tr>
              ) : (
                forms.map((item: any) => (
                  <tr key={item.slug}>
                    <td>
                      <input
                        type="checkbox"
                        className="form-check-input"
                        checked={(selected.forms ?? new Set()).has(item.slug)}
                        onChange={() => toggleSelected("forms", item.slug)}
                      />
                    </td>
                    <td>
                      <div>
                        <RichText
                          text={item.title || item.slug}
                          markdownEnabled={markdownEnabled}
                          mathjaxEnabled={mathjaxEnabled}
                          inline
                        />
                      </div>
                      {item.title && item.slug ? <div className="muted">{item.slug}</div> : null}
                    </td>
                    <td>{item.deleted_at ? formatTimeICT(item.deleted_at) : "n/a"}</td>
                    <td>{item.deleted_reason || "n/a"}</td>
                    <td className="table-actions">
                      <div className="d-flex gap-2">
                        <button
                          type="button"
                          className="btn btn-outline-secondary btn-sm"
                          onClick={() => restoreItem("form", item.slug)}
                        >
                          <i className="bi bi-arrow-counterclockwise" aria-hidden="true" /> Restore
                        </button>
                        {isAdmin ? (
                          <button
                            type="button"
                            className="btn btn-outline-danger btn-sm"
                            onClick={() => purgeItem("form", item.slug)}
                          >
                            <i className="bi bi-trash" aria-hidden="true" /> Delete
                          </button>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
          {renderBulkControls("forms", forms.map((item: any) => item.slug).filter(Boolean))}
        </div>
      ) : null}

      {(trashType === "all" || trashType === "templates") && isAdmin ? (
        <div className="table-responsive mb-4">
          <table className="table table-sm">
            <thead>
              <tr>
                <th>
                  <input
                    type="checkbox"
                    className="form-check-input"
                    checked={
                      templates.length > 0 &&
                      templates.every((item: any) => (selected.templates ?? new Set()).has(item.key))
                    }
                    onChange={() =>
                      toggleAllSelected(
                        "templates",
                        templates.map((item: any) => item.key).filter(Boolean)
                      )
                    }
                  />
                </th>
                <th>Template</th>
                <th>Deleted</th>
                <th>Reason</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {templates.length === 0 ? (
                <tr>
                  <td colSpan={5}>No deleted templates.</td>
                </tr>
              ) : (
                templates.map((item: any) => (
                  <tr key={item.key}>
                    <td>
                      <input
                        type="checkbox"
                        className="form-check-input"
                        checked={(selected.templates ?? new Set()).has(item.key)}
                        onChange={() => toggleSelected("templates", item.key)}
                      />
                    </td>
                    <td>
                      <div>
                        <RichText
                          text={item.name || item.key}
                          markdownEnabled={markdownEnabled}
                          mathjaxEnabled={mathjaxEnabled}
                          inline
                        />
                      </div>
                      {item.name && item.key ? <div className="muted">{item.key}</div> : null}
                    </td>
                    <td>{item.deleted_at ? formatTimeICT(item.deleted_at) : "n/a"}</td>
                    <td>{item.deleted_reason || "n/a"}</td>
                    <td className="table-actions">
                      <div className="d-flex gap-2">
                        <button
                          type="button"
                          className="btn btn-outline-secondary btn-sm"
                          onClick={() => restoreItem("template", item.key)}
                        >
                          <i className="bi bi-arrow-counterclockwise" aria-hidden="true" /> Restore
                        </button>
                        {isAdmin ? (
                          <button
                            type="button"
                            className="btn btn-outline-danger btn-sm"
                            onClick={() => purgeItem("template", item.key)}
                          >
                            <i className="bi bi-trash" aria-hidden="true" /> Delete
                          </button>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
          {renderBulkControls("templates", templates.map((item: any) => item.key).filter(Boolean))}
        </div>
      ) : null}

      {(trashType === "all" || trashType === "users") && isAdmin ? (
        <div className="table-responsive mb-4">
          <table className="table table-sm">
            <thead>
              <tr>
                <th>
                  <input
                    type="checkbox"
                    className="form-check-input"
                    checked={
                      users.length > 0 &&
                      users.every((item: any) => (selected.users ?? new Set()).has(item.id))
                    }
                    onChange={() =>
                      toggleAllSelected(
                        "users",
                        users.map((item: any) => item.id).filter(Boolean)
                      )
                    }
                  />
                </th>
                <th>User</th>
                <th>Deleted</th>
                <th>Reason</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.length === 0 ? (
                <tr>
                  <td colSpan={5}>No deleted users.</td>
                </tr>
              ) : (
                users.map((item: any) => (
                  <tr key={item.id}>
                    <td>
                      <input
                        type="checkbox"
                        className="form-check-input"
                        checked={(selected.users ?? new Set()).has(item.id)}
                        onChange={() => toggleSelected("users", item.id)}
                      />
                    </td>
                    <td>{item.email || item.provider_login || item.id}</td>
                    <td>{item.deleted_at ? formatTimeICT(item.deleted_at) : "n/a"}</td>
                    <td>{item.deleted_reason || "n/a"}</td>
                    <td className="table-actions">
                      <div className="d-flex gap-2">
                        <button
                          type="button"
                          className="btn btn-outline-secondary btn-sm"
                          onClick={() => restoreItem("user", item.id)}
                        >
                          <i className="bi bi-arrow-counterclockwise" aria-hidden="true" /> Restore
                        </button>
                        {isAdmin ? (
                          <button
                            type="button"
                            className="btn btn-outline-danger btn-sm"
                            onClick={() => purgeItem("user", item.id)}
                          >
                            <i className="bi bi-trash" aria-hidden="true" /> Delete
                          </button>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
          {renderBulkControls("users", users.map((item: any) => item.id).filter(Boolean))}
        </div>
      ) : null}

      {(trashType === "all" || trashType === "submissions") ? (
        <div className="table-responsive mb-4">
          <table className="table table-sm">
            <thead>
              <tr>
                <th>
                  <input
                    type="checkbox"
                    className="form-check-input"
                    checked={
                      submissions.length > 0 &&
                      submissions.every((item: any) => (selected.submissions ?? new Set()).has(item.id))
                    }
                    onChange={() =>
                      toggleAllSelected(
                        "submissions",
                        submissions.map((item: any) => item.id).filter(Boolean)
                      )
                    }
                  />
                </th>
                <th>Submission</th>
                <th>Form</th>
                <th>Deleted</th>
                <th>Reason</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {submissions.length === 0 ? (
                <tr>
                  <td colSpan={6}>No deleted submissions.</td>
                </tr>
              ) : (
                submissions.map((item: any) => (
                  <tr key={item.id}>
                    <td>
                      <input
                        type="checkbox"
                        className="form-check-input"
                        checked={(selected.submissions ?? new Set()).has(item.id)}
                        onChange={() => toggleSelected("submissions", item.id)}
                      />
                    </td>
                    <td>
                      <div>
                        <RichText
                          text={item.form_title || item.form_slug || "Submission"}
                          markdownEnabled={markdownEnabled}
                          mathjaxEnabled={mathjaxEnabled}
                          inline
                        />
                      </div>
                      <div className="muted">{item.id}</div>
                    </td>
                    <td>
                      {item.form_title ? (
                        <RichText
                          text={item.form_title}
                          markdownEnabled={markdownEnabled}
                          mathjaxEnabled={mathjaxEnabled}
                          inline
                        />
                      ) : (
                        "n/a"
                      )}
                    </td>
                    <td>{item.deleted_at ? formatTimeICT(item.deleted_at) : "n/a"}</td>
                    <td>{item.deleted_reason || "n/a"}</td>
                    <td className="table-actions">
                      <div className="d-flex gap-2">
                        <button
                          type="button"
                          className="btn btn-outline-secondary btn-sm"
                          onClick={() => restoreItem("submission", item.id)}
                        >
                          <i className="bi bi-arrow-counterclockwise" aria-hidden="true" /> Restore
                        </button>
                        {isAdmin ? (
                          <button
                            type="button"
                            className="btn btn-outline-danger btn-sm"
                            onClick={() => purgeItem("submission", item.id)}
                          >
                            <i className="bi bi-trash" aria-hidden="true" /> Delete
                          </button>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
          {renderBulkControls("submissions", submissions.map((item: any) => item.id).filter(Boolean))}
        </div>
      ) : null}

      {(trashType === "all" || trashType === "files") ? (
        <div className="table-responsive mb-4">
          <table className="table table-sm">
            <thead>
              <tr>
                <th>
                  <input
                    type="checkbox"
                    className="form-check-input"
                    checked={
                      files.length > 0 &&
                      files.every((item: any) => (selected.files ?? new Set()).has(item.id))
                    }
                    onChange={() =>
                      toggleAllSelected(
                        "files",
                        files.map((item: any) => item.id).filter(Boolean)
                      )
                    }
                  />
                </th>
                <th>File</th>
                <th>Form</th>
                <th>Submission</th>
                <th>Deleted</th>
                <th>Reason</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {files.length === 0 ? (
                <tr>
                  <td colSpan={7}>No deleted files.</td>
                </tr>
              ) : (
                files.map((item: any) => (
                  <tr key={item.id}>
                    <td>
                      <input
                        type="checkbox"
                        className="form-check-input"
                        checked={(selected.files ?? new Set()).has(item.id)}
                        onChange={() => toggleSelected("files", item.id)}
                      />
                    </td>
                    <td>{item.original_name || item.id}</td>
                    <td>
                      {item.form_title ? (
                        <RichText
                          text={item.form_title}
                          markdownEnabled={markdownEnabled}
                          mathjaxEnabled={mathjaxEnabled}
                          inline
                        />
                      ) : (
                        "n/a"
                      )}
                    </td>
                    <td>
                      {item.submission_id ? (
                        <>
                          <div>
                            <RichText
                              text={item.form_title || item.form_slug || "Submission"}
                              markdownEnabled={markdownEnabled}
                              mathjaxEnabled={mathjaxEnabled}
                              inline
                            />
                          </div>
                          {item.form_title ? (
                            <div className="muted">{item.submission_id}</div>
                          ) : null}
                        </>
                      ) : (
                        "n/a"
                      )}
                    </td>
                    <td>{item.deleted_at ? formatTimeICT(item.deleted_at) : "n/a"}</td>
                    <td>{item.deleted_reason || "n/a"}</td>
                    <td className="table-actions">
                      <div className="d-flex gap-2">
                        <button
                          type="button"
                          className="btn btn-outline-secondary btn-sm"
                          onClick={() => restoreItem("file", item.id)}
                        >
                          <i className="bi bi-arrow-counterclockwise" aria-hidden="true" /> Restore
                        </button>
                        {isAdmin ? (
                          <button
                            type="button"
                            className="btn btn-outline-danger btn-sm"
                            onClick={() => purgeItem("file", item.id)}
                          >
                            <i className="bi bi-trash" aria-hidden="true" /> Delete
                          </button>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
          {renderBulkControls("files", files.map((item: any) => item.id).filter(Boolean))}
        </div>
      ) : null}

      {(trashType === "all" || trashType === "emails") && isAdmin ? (
        <div className="table-responsive mb-4">
          <table className="table table-sm">
            <thead>
              <tr>
                <th>
                  <input
                    type="checkbox"
                    className="form-check-input"
                    checked={
                      emails.length > 0 &&
                      emails.every((item: any) => (selected.emails ?? new Set()).has(item.id))
                    }
                    onChange={() =>
                      toggleAllSelected(
                        "emails",
                        emails.map((item: any) => item.id).filter(Boolean)
                      )
                    }
                  />
                </th>
                <th>To</th>
                <th>Subject</th>
                <th>Status</th>
                <th>Submission</th>
                <th>Deleted</th>
                <th>Reason</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {emails.length === 0 ? (
                <tr>
                  <td colSpan={8}>No deleted emails.</td>
                </tr>
              ) : (
                emails.map((item: any) => (
                  <tr key={item.id}>
                    <td>
                      <input
                        type="checkbox"
                        className="form-check-input"
                        checked={(selected.emails ?? new Set()).has(item.id)}
                        onChange={() => toggleSelected("emails", item.id)}
                      />
                    </td>
                    <td>{item.to_email || "n/a"}</td>
                    <td>{item.subject || "n/a"}</td>
                    <td>
                      <span
                        className={`badge ${item.status === "sent"
                          ? "text-bg-success"
                          : item.status === "failed"
                            ? "text-bg-danger"
                            : "text-bg-secondary"
                          }`}
                      >
                        {item.status || "n/a"}
                      </span>
                    </td>
                    <td>{item.submission_id || "n/a"}</td>
                    <td>{item.deleted_at ? formatTimeICT(item.deleted_at) : "n/a"}</td>
                    <td>{item.deleted_reason || "n/a"}</td>
                    <td className="table-actions">
                      <div className="d-flex gap-2">
                        <button
                          type="button"
                          className="btn btn-outline-secondary btn-sm"
                          onClick={() => restoreItem("email", item.id)}
                        >
                          <i className="bi bi-arrow-counterclockwise" aria-hidden="true" /> Restore
                        </button>
                        <button
                          type="button"
                          className="btn btn-outline-danger btn-sm"
                          onClick={() => purgeItem("email", item.id)}
                        >
                          <i className="bi bi-trash" aria-hidden="true" /> Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
          {renderBulkControls("emails", emails.map((item: any) => item.id).filter(Boolean))}
        </div>
      ) : null}
    </section>
  );
}

function BuilderPage({
  user,
  onLogin,
  onNotice,
  appDefaultTimezone,
  markdownEnabled,
  mathjaxEnabled
}: {
  user: UserInfo | null;
  onLogin: (p: "google" | "github") => void;
  onNotice: (message: string, type?: NoticeType) => void;
  appDefaultTimezone: string;
  markdownEnabled: boolean;
  mathjaxEnabled: boolean;
}) {
  const [status, setStatus] = useState<"loading" | "ok" | "forbidden">("loading");
  const [forms, setForms] = useState<any[]>([]);
  const [templates, setTemplates] = useState<any[]>([]);
  const [lastRefresh, setLastRefresh] = useState<string | null>(null);
  const [templateEditorKey, setTemplateEditorKey] = useState("");
  const [templateEditorOriginalKey, setTemplateEditorOriginalKey] = useState("");
  const [templateEditorName, setTemplateEditorName] = useState("");
  const [templateEditorSchema, setTemplateEditorSchema] = useState("");
  const [templateEditorStatus, setTemplateEditorStatus] = useState<string | null>(null);
  const [templateBuilderMode, setTemplateBuilderMode] = useState<"create" | "edit">("edit");
  const [builderType, setBuilderType] = useState("text");
  const [builderCustomType, setBuilderCustomType] = useState("");
  const [builderId, setBuilderId] = useState("");
  const [builderLabel, setBuilderLabel] = useState("");
  const [builderRequired, setBuilderRequired] = useState(false);
  const [builderDescription, setBuilderDescription] = useState("");
  const [builderPlaceholder, setBuilderPlaceholder] = useState("");
  const [builderOptions, setBuilderOptions] = useState("");
  const [builderMultiple, setBuilderMultiple] = useState(false);
  const [builderTextareaMarkdownEnabled, setBuilderTextareaMarkdownEnabled] = useState(false);
  const [builderTextareaMathjaxEnabled, setBuilderTextareaMathjaxEnabled] = useState(false);
  const [builderTextareaRows, setBuilderTextareaRows] = useState(4);
  const [builderEmailDomain, setBuilderEmailDomain] = useState("");
  const [builderDateTimezone, setBuilderDateTimezone] = useState(getAppDefaultTimezone());
  const [builderDateMode, setBuilderDateMode] = useState("datetime");
  const [builderDateShowTimezone, setBuilderDateShowTimezone] = useState(true);
  const [builderAutofillFromLogin, setBuilderAutofillFromLogin] = useState(false);
  const [builderVisibilityEnabled, setBuilderVisibilityEnabled] = useState(false);
  const [builderVisibilityOperator, setBuilderVisibilityOperator] =
    useState<VisibilityMatchMode>("all");
  const [builderVisibilityConditions, setBuilderVisibilityConditions] = useState<
    Array<{ dependsOn: string; values: string; mode: VisibilityMatchMode }>
  >([{ dependsOn: "", values: "", mode: "any" }]);
  const [templateFromFormSlug, setTemplateFromFormSlug] = useState("");
  const [templateFromFormStatus, setTemplateFromFormStatus] = useState<string | null>(null);
  const [templateFieldEditId, setTemplateFieldEditId] = useState("");
  const [fileFieldId, setFileFieldId] = useState("");
  const [fileFieldLabel, setFileFieldLabel] = useState("");
  const [fileFieldRequired, setFileFieldRequired] = useState(false);
  const [fileFieldExtensions, setFileFieldExtensions] = useState("");
  const [fileFieldMaxSizeMb, setFileFieldMaxSizeMb] = useState(10);
  const [fileFieldMaxFiles, setFileFieldMaxFiles] = useState(2);
  const [templateFileEditId, setTemplateFileEditId] = useState("");
  const [templateFileDragOverId, setTemplateFileDragOverId] = useState<string | null>(null);
  const [formBuilderSlug, setFormBuilderSlug] = useState("");
  const [formBuilderSlugEdit, setFormBuilderSlugEdit] = useState("");
  const [formBuilderSchema, setFormBuilderSchema] = useState("");
  const [formBuilderStatus, setFormBuilderStatus] = useState<string | null>(null);
  const [formBuilderDescription, setFormBuilderDescription] = useState("");
  const [formBuilderTemplateKey, setFormBuilderTemplateKey] = useState("");
  const [formBuilderPublic, setFormBuilderPublic] = useState(true);
  const [formBuilderLocked, setFormBuilderLocked] = useState(false);
  const [formBuilderAuthPolicy, setFormBuilderAuthPolicy] = useState("optional");
  const [formBuilderAvailableFrom, setFormBuilderAvailableFrom] = useState("");
  const [formBuilderAvailableUntil, setFormBuilderAvailableUntil] = useState("");
  const [formBuilderAvailabilityTimezone, setFormBuilderAvailabilityTimezone] = useState(
    getAppDefaultTimezone()
  );
  const [formBuilderPasswordRequireAccess, setFormBuilderPasswordRequireAccess] = useState(false);
  const [formBuilderPasswordRequireSubmit, setFormBuilderPasswordRequireSubmit] = useState(false);
  const [formBuilderPassword, setFormBuilderPassword] = useState("");
  const [formBuilderPasswordVisible, setFormBuilderPasswordVisible] = useState(false);
  const [formBuilderCanvasEnabled, setFormBuilderCanvasEnabled] = useState(false);
  const [formBuilderCanvasCourseId, setFormBuilderCanvasCourseId] = useState("");
  const [formBuilderCanvasAllowedSections, setFormBuilderCanvasAllowedSections] = useState<
    string[] | null
  >(null);
  const [formBuilderCanvasPosition, setFormBuilderCanvasPosition] = useState("bottom");
  const [formBuilderMode, setFormBuilderMode] = useState<"create" | "edit">("edit");
  const [formBuilderDiscussionEnabled, setFormBuilderDiscussionEnabled] = useState(false);
  const [formBuilderDiscussionMarkdownEnabled, setFormBuilderDiscussionMarkdownEnabled] =
    useState(true);
  const [formBuilderDiscussionHtmlEnabled, setFormBuilderDiscussionHtmlEnabled] = useState(false);
  const [formBuilderDiscussionMathjaxEnabled, setFormBuilderDiscussionMathjaxEnabled] =
    useState(false);
  const [formBuilderCommentNotifyEnabled, setFormBuilderCommentNotifyEnabled] =
    useState(true);
  const [formFieldType, setFormFieldType] = useState("text");
  const [formFieldCustomType, setFormFieldCustomType] = useState("");
  const [formFieldId, setFormFieldId] = useState("");
  const [formFieldLabel, setFormFieldLabel] = useState("");
  const [formFieldRequired, setFormFieldRequired] = useState(false);
  const [formFieldDescription, setFormFieldDescription] = useState("");
  const [formFieldPlaceholder, setFormFieldPlaceholder] = useState("");
  const [formFieldOptions, setFormFieldOptions] = useState("");
  const [formFieldMultiple, setFormFieldMultiple] = useState(false);
  const [formFieldTextareaMarkdownEnabled, setFormFieldTextareaMarkdownEnabled] = useState(false);
  const [formFieldTextareaMathjaxEnabled, setFormFieldTextareaMathjaxEnabled] = useState(false);
  const [formFieldTextareaRows, setFormFieldTextareaRows] = useState(4);
  const [formEmailDomain, setFormEmailDomain] = useState("");
  const [formDateTimezone, setFormDateTimezone] = useState(getAppDefaultTimezone());
  const [formDateMode, setFormDateMode] = useState("datetime");
  const [formDateShowTimezone, setFormDateShowTimezone] = useState(true);
  const [formAutofillFromLogin, setFormAutofillFromLogin] = useState(false);
  const [formFieldVisibilityEnabled, setFormFieldVisibilityEnabled] = useState(false);
  const [formFieldVisibilityOperator, setFormFieldVisibilityOperator] =
    useState<VisibilityMatchMode>("all");
  const [formFieldVisibilityConditions, setFormFieldVisibilityConditions] = useState<
    Array<{ dependsOn: string; values: string; mode: VisibilityMatchMode }>
  >([{ dependsOn: "", values: "", mode: "any" }]);
  const [formFieldEditId, setFormFieldEditId] = useState("");
  const [formFileFieldId, setFormFileFieldId] = useState("");
  const [formFileFieldLabel, setFormFileFieldLabel] = useState("");
  const [formFileFieldRequired, setFormFileFieldRequired] = useState(false);
  const [formFileFieldExtensions, setFormFileFieldExtensions] = useState("");
  const [formFileFieldMaxSizeMb, setFormFileFieldMaxSizeMb] = useState(10);
  const [formFileFieldMaxFiles, setFormFileFieldMaxFiles] = useState(2);
  const [formFileEditId, setFormFileEditId] = useState("");
  const [formFileDragOverId, setFormFileDragOverId] = useState<string | null>(null);
  const [formCreateSlug, setFormCreateSlug] = useState("");
  const [formCreateTitle, setFormCreateTitle] = useState("");
  const [formCreateDescription, setFormCreateDescription] = useState("");
  const [formCreateTemplateKey, setFormCreateTemplateKey] = useState("");
  const [formCreateSchema, setFormCreateSchema] = useState('{"fields": []}');
  const [formCreateAuthPolicy, setFormCreateAuthPolicy] = useState("optional");
  const [formCreatePublic, setFormCreatePublic] = useState(true);
  const [formCreateLocked, setFormCreateLocked] = useState(false);
  const [formCreateAvailableFrom, setFormCreateAvailableFrom] = useState("");
  const [formCreateAvailableUntil, setFormCreateAvailableUntil] = useState("");
  const [formCreateAvailabilityTimezone, setFormCreateAvailabilityTimezone] = useState(
    getAppDefaultTimezone()
  );
  const [formCreatePasswordRequireAccess, setFormCreatePasswordRequireAccess] = useState(false);
  const [formCreatePasswordRequireSubmit, setFormCreatePasswordRequireSubmit] = useState(false);
  const [formCreatePassword, setFormCreatePassword] = useState("");
  const [formCreatePasswordVisible, setFormCreatePasswordVisible] = useState(false);
  const formCreatePasswordRequired = formCreatePasswordRequireAccess || formCreatePasswordRequireSubmit;
  const formBuilderPasswordRequired =
    formBuilderPasswordRequireAccess || formBuilderPasswordRequireSubmit;
  const [formCreateCanvasEnabled, setFormCreateCanvasEnabled] = useState(false);
  const [formCreateCanvasCourseId, setFormCreateCanvasCourseId] = useState("");
  const [formCreateCanvasAllowedSections, setFormCreateCanvasAllowedSections] = useState<
    string[] | null
  >(null);
  const [formCreateCanvasPosition, setFormCreateCanvasPosition] = useState("bottom");
  const [formCreateStatus, setFormCreateStatus] = useState<string | null>(null);
  const [formCreateDiscussionEnabled, setFormCreateDiscussionEnabled] = useState(false);
  const [formCreateDiscussionMarkdownEnabled, setFormCreateDiscussionMarkdownEnabled] =
    useState(true);
  const [formCreateDiscussionHtmlEnabled, setFormCreateDiscussionHtmlEnabled] = useState(false);
  const [formCreateDiscussionMathjaxEnabled, setFormCreateDiscussionMathjaxEnabled] =
    useState(false);
  const [formCreateCommentNotifyEnabled, setFormCreateCommentNotifyEnabled] =
    useState(true);
  const [canvasCourses, setCanvasCourses] = useState<any[]>([]);
  const [canvasCourseQuery, setCanvasCourseQuery] = useState("");
  const [canvasCoursesLoading, setCanvasCoursesLoading] = useState(false);
  const [canvasCoursesNeedsSync, setCanvasCoursesNeedsSync] = useState(false);
  const [canvasSections, setCanvasSections] = useState<any[]>([]);
  const [canvasSectionsCourseId, setCanvasSectionsCourseId] = useState<string | null>(null);
  const [canvasSectionsNeedsSync, setCanvasSectionsNeedsSync] = useState(false);
  const [canvasSyncing, setCanvasSyncing] = useState(false);
  const [canvasError, setCanvasError] = useState<string | null>(null);
  const [formBuilderReminderEnabled, setFormBuilderReminderEnabled] = useState(false);
  const [formBuilderReminderValue, setFormBuilderReminderValue] = useState(1);
  const [formBuilderReminderUnit, setFormBuilderReminderUnit] = useState("weeks");
  const [formBuilderReminderUntil, setFormBuilderReminderUntil] = useState("");
  const [formBuilderSaveAllVersions, setFormBuilderSaveAllVersions] = useState(false);
  const [formBuilderSubmissionBackupEnabled, setFormBuilderSubmissionBackupEnabled] =
    useState(false);
  const [formBuilderSubmissionBackupFormats, setFormBuilderSubmissionBackupFormats] = useState<string[]>(
    ["json"]
  );
  const [formCreateReminderEnabled, setFormCreateReminderEnabled] = useState(false);
  const [formCreateReminderValue, setFormCreateReminderValue] = useState(1);
  const [formCreateReminderUnit, setFormCreateReminderUnit] = useState("weeks");
  const [formCreateReminderUntil, setFormCreateReminderUntil] = useState("");
  const [formCreateSaveAllVersions, setFormCreateSaveAllVersions] = useState(false);
  const [formCreateSubmissionBackupEnabled, setFormCreateSubmissionBackupEnabled] =
    useState(false);
  const [formCreateSubmissionBackupFormats, setFormCreateSubmissionBackupFormats] = useState<string[]>(
    ["json"]
  );

  const prevDefaultTimezoneRef = useRef(appDefaultTimezone);
  useEffect(() => {
    const prev = prevDefaultTimezoneRef.current;
    if (!appDefaultTimezone || appDefaultTimezone === prev) return;
    const applyDefault = (
      current: string,
      setter: React.Dispatch<React.SetStateAction<string>>
    ) => {
      if (!current || current === prev) {
        setter(appDefaultTimezone);
      }
    };
    applyDefault(builderDateTimezone, setBuilderDateTimezone);
    applyDefault(formDateTimezone, setFormDateTimezone);
    applyDefault(formBuilderAvailabilityTimezone, setFormBuilderAvailabilityTimezone);
    applyDefault(formCreateAvailabilityTimezone, setFormCreateAvailabilityTimezone);
    prevDefaultTimezoneRef.current = appDefaultTimezone;
  }, [
    appDefaultTimezone,
    builderDateTimezone,
    formDateTimezone,
    formBuilderAvailabilityTimezone,
    formCreateAvailabilityTimezone
  ]);

  async function loadBuilder() {
    const healthRes = await apiFetch(`${API_BASE}/api/admin/health`);
    if (healthRes.status === 401 || healthRes.status === 403 || !healthRes.ok) {
      setStatus("forbidden");
      return;
    }
    setStatus("ok");

    const [formsRes, templatesRes] = await Promise.all([
      apiFetch(`${API_BASE}/api/admin/forms`),
      apiFetch(`${API_BASE}/api/admin/templates`)
    ]);

    const formsPayload = formsRes.ok ? await formsRes.json().catch(() => null) : null;
    setForms(Array.isArray(formsPayload?.data) ? formsPayload.data : []);

    const templatesPayload = templatesRes.ok ? await templatesRes.json().catch(() => null) : null;
    setTemplates(Array.isArray(templatesPayload?.data) ? templatesPayload.data : []);

    setLastRefresh(new Date().toISOString());
  }

  function shiftAvailabilityValues(
    currentTz: string,
    nextTz: string,
    fromValue: string,
    untilValue: string
  ) {
    if (!fromValue && !untilValue) {
      return { from: fromValue, until: untilValue };
    }
    const convert = (value: string) => {
      if (!value) return value;
      const utc = zonedTimeToUtcIso(value, currentTz);
      if (!utc) return value;
      const local = utcToLocalDateTime(utc, nextTz);
      return local || value;
    };
    return { from: convert(fromValue), until: convert(untilValue) };
  }

  async function loadCanvasCourses(query: string) {
    setCanvasError(null);
    setCanvasCoursesLoading(true);
    const response = await apiFetch(
      `${API_BASE}/api/admin/canvas/courses?q=${encodeURIComponent(query)}&page=1&pageSize=50`
    );
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setCanvasError(payload?.error || "Failed to load Canvas courses.");
      setCanvasCourses([]);
      setCanvasCoursesNeedsSync(false);
      setCanvasCoursesLoading(false);
      return;
    }
    setCanvasCourses(Array.isArray(payload?.data) ? payload.data : []);
    setCanvasCoursesNeedsSync(Boolean(payload?.needsSync));
    setCanvasCoursesLoading(false);
  }

  async function loadCanvasSections(courseId: string) {
    if (!courseId) {
      setCanvasSections([]);
      setCanvasSectionsCourseId(null);
      setCanvasSectionsNeedsSync(false);
      return;
    }
    setCanvasError(null);
    const response = await apiFetch(
      `${API_BASE}/api/admin/canvas/courses/${encodeURIComponent(
        courseId
      )}/sections?page=1&pageSize=200`
    );
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setCanvasError(payload?.error || "Failed to load Canvas sections.");
      setCanvasSections([]);
      setCanvasSectionsCourseId(courseId);
      setCanvasSectionsNeedsSync(false);
      return;
    }
    setCanvasSections(Array.isArray(payload?.data) ? payload.data : []);
    setCanvasSectionsCourseId(courseId);
    setCanvasSectionsNeedsSync(Boolean(payload?.needsSync));
  }

  async function syncCanvas(mode: "courses" | "course_sections", courseId?: string) {
    setCanvasSyncing(true);
    setCanvasError(null);
    const response = await apiFetch(`${API_BASE}/api/admin/canvas/sync`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ mode, courseId })
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setCanvasError(payload?.error || "Canvas sync failed.");
      setCanvasSyncing(false);
      return;
    }
    if (mode === "courses") {
      await loadCanvasCourses(canvasCourseQuery);
    } else if (mode === "course_sections" && courseId) {
      await loadCanvasSections(courseId);
    }
    setCanvasSyncing(false);
  }

  async function handleCreateTemplateFromForm(slug: string) {
    if (!slug) {
      setTemplateEditorStatus("Select exactly one form to create a template.");
      return false;
    }
    setTemplateEditorStatus(null);
    const backupRes = await apiFetch(
      `${API_BASE}/api/admin/forms/${encodeURIComponent(slug)}/backup`
    );
    const backupPayload = await backupRes.json().catch(() => null);
    if (!backupRes.ok) {
      setTemplateEditorStatus(backupPayload?.error || "Failed to load form backup.");
      return false;
    }
    const schema = backupPayload?.data?.form?.schema_json;
    if (!schema) {
      setTemplateEditorStatus("Form backup does not include schema.");
      return false;
    }
    const key = window.prompt("Template key for this form?");
    if (!key || !key.trim()) {
      setTemplateEditorStatus("Template key is required.");
      return false;
    }
    const name = window.prompt("Template name?") || key.trim();
    const response = await apiFetch(`${API_BASE}/api/admin/templates/restore`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        type: "template",
        template: {
          key: key.trim(),
          name: name.trim(),
          schema_json: schema,
          file_rules_json: backupPayload?.data?.form?.file_rules_json ?? null
        }
      })
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setTemplateEditorStatus(payload?.error || "Template create failed.");
      return false;
    }
    setTemplateEditorStatus("Template created from form.");
    return true;
  }


  useEffect(() => {
    let active = true;
    loadBuilder().catch(() => {
      if (active) setStatus("forbidden");
    });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (!formBuilderCanvasEnabled && !formCreateCanvasEnabled) return;
    if (canvasCourses.length > 0 || canvasCoursesLoading) return;
    loadCanvasCourses(canvasCourseQuery).catch(() => null);
  }, [formBuilderCanvasEnabled, formCreateCanvasEnabled, canvasCourses.length, canvasCoursesLoading, canvasCourseQuery]);

  if (status === "loading") {
    return (
      <section className="panel">
        <h2>Loading builder...</h2>
      </section>
    );
  }

  if (status === "forbidden") {
    return (
      <section className="panel panel--error">
        <h2>Not authorized</h2>
        <p>Please sign in with an admin account.</p>
        <div className="auth-bar">
          <button type="button" className="btn btn-primary btn-auth" onClick={() => onLogin("google")}>
            <i className="bi bi-google" aria-hidden="true" /> Login with Google
          </button>
          <button type="button" className="btn btn-dark btn-auth" onClick={() => onLogin("github")}>
            <i className="bi bi-github" aria-hidden="true" /> Login with GitHub
          </button>
        </div>
      </section>
    );
  }

  async function handleLoadTemplate(key: string) {
    if (!key) return;
    setTemplateEditorStatus(null);
    const response = await apiFetch(`${API_BASE}/api/admin/templates/${encodeURIComponent(key)}`);
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setTemplateEditorStatus(payload?.error || "Failed to load template.");
      return;
    }
    const template = payload?.data;
    setTemplateEditorKey(template?.key || key);
    setTemplateEditorOriginalKey(template?.key || key);
    setTemplateEditorName(template?.name || "");
    setTemplateEditorSchema(
      template?.schema_json ? JSON.stringify(JSON.parse(template.schema_json), null, 2) : ""
    );
  }

  async function handleCreateTemplate() {
    setTemplateEditorStatus(null);
    if (!templateEditorKey || !templateEditorName || !templateEditorSchema) {
      setTemplateEditorStatus("Key, name, and schema are required.");
      return;
    }
    const parsed = parseSchemaText(templateEditorSchema);
    if ((parsed as any).error) {
      setTemplateEditorStatus((parsed as any).error);
      return;
    }
    const rulesError = validateFileRulesInSchema(parsed.schema);
    if (rulesError) {
      setTemplateEditorStatus(rulesError);
      return;
    }
    const visibilityError = validateVisibilityRulesInSchema(parsed.schema);
    if (visibilityError) {
      setTemplateEditorStatus(visibilityError);
      return;
    }
    const response = await apiFetch(`${API_BASE}/api/admin/templates`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        key: templateEditorKey,
        name: templateEditorName,
        schema_json: templateEditorSchema
      })
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setTemplateEditorStatus(payload?.error || "Failed to create template.");
      return;
    }
    setTemplateEditorStatus("Template created.");
    await loadBuilder();
  }

  async function handleUpdateTemplate() {
    setTemplateEditorStatus(null);
    if (!templateEditorKey || !templateEditorSchema) {
      setTemplateEditorStatus("Select a template and provide schema.");
      return;
    }
    if (!templateEditorOriginalKey) {
      setTemplateEditorStatus("Select a template to update.");
      return;
    }
    const parsed = parseSchemaText(templateEditorSchema);
    if ((parsed as any).error) {
      setTemplateEditorStatus((parsed as any).error);
      return;
    }
    const rulesError = validateFileRulesInSchema(parsed.schema);
    if (rulesError) {
      setTemplateEditorStatus(rulesError);
      return;
    }
    const visibilityError = validateVisibilityRulesInSchema(parsed.schema);
    if (visibilityError) {
      setTemplateEditorStatus(visibilityError);
      return;
    }
    const response = await apiFetch(
      `${API_BASE}/api/admin/templates/${encodeURIComponent(templateEditorOriginalKey)}`,
      {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          newKey:
            templateEditorKey !== templateEditorOriginalKey
              ? templateEditorKey
              : undefined,
          name: templateEditorName || undefined,
          schema_json: templateEditorSchema
        })
      }
    );
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setTemplateEditorStatus(payload?.error || "Failed to update template.");
      return;
    }
    setTemplateEditorStatus("Template updated.");
    if (templateEditorKey !== templateEditorOriginalKey) {
      setTemplateEditorOriginalKey(templateEditorKey);
    }
    await loadBuilder();
  }

  async function handleDuplicateTemplate() {
    if (!templateEditorKey) {
      setTemplateEditorStatus("Select a template to duplicate.");
      return;
    }
    const proposedKey = `${templateEditorKey}-copy`;
    const newKey = window.prompt("New key for duplicated template:", proposedKey);
    if (!newKey || !newKey.trim()) return;
    const newName = window.prompt(
      "Name for duplicated template:",
      `${templateEditorName || templateEditorKey} copy`
    );
    if (!newName || !newName.trim()) {
      setTemplateEditorStatus("Name is required for duplicate template.");
      return;
    }
    const parsed = parseSchemaText(templateEditorSchema);
    if ((parsed as any).error) {
      setTemplateEditorStatus((parsed as any).error);
      return;
    }
    const rulesError = validateFileRulesInSchema(parsed.schema);
    if (rulesError) {
      setTemplateEditorStatus(rulesError);
      return;
    }
    const visibilityError = validateVisibilityRulesInSchema(parsed.schema);
    if (visibilityError) {
      setTemplateEditorStatus(visibilityError);
      return;
    }
    const response = await apiFetch(`${API_BASE}/api/admin/templates`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        key: newKey.trim(),
        name: newName.trim(),
        schema_json: templateEditorSchema
      })
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setTemplateEditorStatus(payload?.error || "Failed to create duplicate template.");
      return;
    }
    setTemplateEditorStatus("Duplicate template created.");
    await loadBuilder();
  }

  function handleAddField() {
    const nextSchema = applyAddFieldToSchema(templateEditorSchema, {
      type: builderType,
      customType: builderCustomType,
      id: builderId,
      label: builderLabel,
      required: builderRequired,
      description: builderDescription,
      placeholder: builderPlaceholder,
      options: builderOptions,
      multiple: builderMultiple,
      textareaMarkdownEnabled: builderTextareaMarkdownEnabled,
      textareaMathjaxEnabled: builderTextareaMathjaxEnabled,
      textareaRows: builderTextareaRows,
      emailDomain: builderEmailDomain,
      autofillFromLogin: builderAutofillFromLogin,
      dateTimezone: builderDateTimezone,
      dateMode: builderDateMode,
      dateShowTimezone: builderDateShowTimezone,
      visibilityEnabled: builderVisibilityEnabled,
      visibilityOperator: builderVisibilityOperator,
      visibilityConditions: builderVisibilityConditions
    });
    if (nextSchema.error) {
      setTemplateEditorStatus(nextSchema.error);
      return;
    }
    if (nextSchema.text) {
      setTemplateEditorSchema(nextSchema.text);
    }
    setTemplateEditorStatus("Field added to schema.");
    setBuilderId("");
    setBuilderLabel("");
    setBuilderRequired(false);
    setBuilderDescription("");
    setBuilderPlaceholder("");
    setBuilderOptions("");
    setBuilderMultiple(false);
    setBuilderTextareaMarkdownEnabled(false);
    setBuilderTextareaMathjaxEnabled(false);
    setBuilderTextareaRows(4);
    setBuilderEmailDomain("");
    setBuilderAutofillFromLogin(false);
    setBuilderDateTimezone(getAppDefaultTimezone());
    setBuilderDateMode("datetime");
    setBuilderDateShowTimezone(true);
    setBuilderVisibilityEnabled(false);
    setBuilderVisibilityOperator("all");
    setBuilderVisibilityConditions([{ dependsOn: "", values: "", mode: "any" }]);
  }

  function handleRemoveField(fieldId: string) {
    const nextSchema = removeFieldFromSchemaText(templateEditorSchema, fieldId);
    if (nextSchema.error) {
      setTemplateEditorStatus(nextSchema.error);
      return;
    }
    if (nextSchema.text) {
      setTemplateEditorSchema(nextSchema.text);
    }
    setTemplateEditorStatus("Field removed.");
  }

  function handleMoveTemplateField(fieldId: string, direction: "up" | "down") {
    const nextSchema = moveFieldInSchemaText(templateEditorSchema, fieldId, direction);
    if (nextSchema.error) {
      setTemplateEditorStatus(nextSchema.error);
      return;
    }
    if (nextSchema.text) {
      setTemplateEditorSchema(nextSchema.text);
    }
    setTemplateEditorStatus("Field moved.");
  }

  function handleReorderTemplateField(fieldId: string, targetIndex: number) {
    const nextSchema = moveFieldToIndexInSchemaText(templateEditorSchema, fieldId, targetIndex);
    if (nextSchema.error) {
      setTemplateEditorStatus(nextSchema.error);
      return;
    }
    if (nextSchema.text) {
      setTemplateEditorSchema(nextSchema.text);
    }
    setTemplateEditorStatus("Field reordered.");
  }

  function handleSelectTemplateField(fieldId: string, field: Record<string, unknown> | null) {
    setTemplateFieldEditId(fieldId);
    if (!field) return;
    const type = String(field.type || "text");
    const rules = (field as any).rules || {};
    const domain = typeof rules.domain === "string" ? rules.domain : "";
    setBuilderType(
      ["text", "full_name", "email", "github_username", "url", "date", "number", "textarea", "select", "checkbox"].includes(type)
        ? type
        : "custom"
    );
    setBuilderCustomType(
      ["text", "full_name", "email", "github_username", "url", "date", "number", "textarea", "select", "checkbox"].includes(type)
        ? ""
        : type
    );
    setBuilderId(String(field.id || ""));
    setBuilderLabel(String(field.label || ""));
    setBuilderRequired(Boolean(field.required));
    setBuilderDescription(String((field as any).description || ""));
    setBuilderPlaceholder(String(field.placeholder || ""));
    const options = Array.isArray((field as any).options) ? (field as any).options : [];
    setBuilderOptions(options.join(","));
    setBuilderMultiple(Boolean((field as any).multiple));
    setBuilderTextareaMarkdownEnabled(type === "textarea" ? Boolean(rules.markdownEnabled) : false);
    setBuilderTextareaMathjaxEnabled(type === "textarea" ? Boolean(rules.mathjaxEnabled) : false);
    setBuilderTextareaRows(
      type === "textarea" && typeof rules.rows === "number" ? Math.max(1, Math.round(rules.rows)) : 4
    );
    setBuilderEmailDomain(type === "email" ? String(domain) : "");
    setBuilderAutofillFromLogin(
      type === "email" || type === "github_username" ? Boolean(rules.autofill) : false
    );
    setBuilderDateTimezone(
      type === "date" && typeof rules.timezoneDefault === "string"
        ? String(rules.timezoneDefault)
        : getAppDefaultTimezone()
    );
    setBuilderDateMode(
      type === "date" && typeof rules.mode === "string" ? String(rules.mode) : "datetime"
    );
    setBuilderDateShowTimezone(!(type === "date" && rules.timezoneOptional === true));
    const visibility = (field as any).visibility || {};
    const normalizedVisibility = normalizeVisibilityRule(visibility);
    if (normalizedVisibility) {
      setBuilderVisibilityEnabled(true);
      setBuilderVisibilityOperator(normalizedVisibility.operator);
      setBuilderVisibilityConditions(
        normalizedVisibility.conditions.map((condition) => ({
          dependsOn: condition.dependsOn,
          values: condition.values.join(", "),
          mode: condition.mode === "all" ? "all" : "any"
        }))
      );
    } else {
      setBuilderVisibilityEnabled(false);
      setBuilderVisibilityOperator("all");
      setBuilderVisibilityConditions([{ dependsOn: "", values: "", mode: "any" }]);
    }
  }

  function handleUpdateTemplateField() {
    const nextSchema = updateFieldInSchemaText(templateEditorSchema, templateFieldEditId, {
      type: builderType,
      customType: builderCustomType,
      id: builderId,
      label: builderLabel,
      required: builderRequired,
      description: builderDescription,
      placeholder: builderPlaceholder,
      options: builderOptions,
      multiple: builderMultiple,
      textareaMarkdownEnabled: builderTextareaMarkdownEnabled,
      textareaMathjaxEnabled: builderTextareaMathjaxEnabled,
      textareaRows: builderTextareaRows,
      emailDomain: builderEmailDomain,
      autofillFromLogin: builderAutofillFromLogin,
      dateTimezone: builderDateTimezone,
      dateMode: builderDateMode,
      dateShowTimezone: builderDateShowTimezone,
      visibilityEnabled: builderVisibilityEnabled,
      visibilityOperator: builderVisibilityOperator,
      visibilityConditions: builderVisibilityConditions
    });
    if (nextSchema.error) {
      setTemplateEditorStatus(nextSchema.error);
      return;
    }
    if (nextSchema.text) {
      setTemplateEditorSchema(nextSchema.text);
    }
    setTemplateEditorStatus("Field updated.");
    if (templateFieldEditId === builderId) {
      setTemplateFieldEditId(builderId);
    }
  }

  function handleAddFileField() {
    const nextSchema = applyAddFileFieldToSchema(templateEditorSchema, {
      id: fileFieldId,
      label: fileFieldLabel,
      required: fileFieldRequired,
      extensions: fileFieldExtensions,
      maxSizeMb: fileFieldMaxSizeMb,
      maxFiles: fileFieldMaxFiles
    });
    if (nextSchema.error) {
      setTemplateEditorStatus(nextSchema.error);
      return;
    }
    if (nextSchema.text) {
      setTemplateEditorSchema(nextSchema.text);
    }
    setTemplateEditorStatus("File field added to schema.");
    setFileFieldId("");
    setFileFieldLabel("");
    setFileFieldRequired(false);
    setFileFieldExtensions("");
  }

  function handleSelectTemplateFileField(fieldId: string, field: Record<string, unknown> | null) {
    setTemplateFileEditId(fieldId);
    if (!field) return;
    const rules = (field as any).rules || {};
    const extensions = Array.isArray(rules.allowedExtensions)
      ? rules.allowedExtensions
      : Array.isArray(rules.extensions)
        ? rules.extensions
        : [];
    const maxBytes =
      typeof rules.maxFileSizeBytes === "number"
        ? rules.maxFileSizeBytes
        : typeof rules.maxSizeBytes === "number"
          ? rules.maxSizeBytes
          : 10 * 1024 * 1024;
    const maxFiles = typeof rules.maxFiles === "number" ? rules.maxFiles : 1;
    setFileFieldId(String((field as any).id || ""));
    setFileFieldLabel(String((field as any).label || ""));
    setFileFieldRequired(Boolean((field as any).required));
    setFileFieldExtensions(extensions.join(","));
    setFileFieldMaxSizeMb(Math.max(1, Math.round(maxBytes / (1024 * 1024))));
    setFileFieldMaxFiles(Math.max(1, maxFiles));
  }

  function handleUpdateTemplateFileField() {
    const nextSchema = updateFileFieldInSchemaText(templateEditorSchema, templateFileEditId, {
      id: fileFieldId,
      label: fileFieldLabel,
      required: fileFieldRequired,
      extensions: fileFieldExtensions,
      maxSizeMb: fileFieldMaxSizeMb,
      maxFiles: fileFieldMaxFiles
    });
    if (nextSchema.error) {
      setTemplateEditorStatus(nextSchema.error);
      return;
    }
    if (nextSchema.text) {
      setTemplateEditorSchema(nextSchema.text);
    }
    setTemplateEditorStatus("File field updated.");
  }

  async function handleLoadFormSchema(slug: string) {
    setFormBuilderStatus(null);
    if (!slug) {
      setFormBuilderSchema("");
      setFormBuilderDescription("");
      setFormBuilderPublic(true);
      setFormBuilderLocked(false);
      setFormBuilderAuthPolicy("optional");
      setFormBuilderAvailableFrom("");
      setFormBuilderAvailableUntil("");
      setFormBuilderAvailabilityTimezone(getAppDefaultTimezone());
      setFormBuilderPasswordRequireAccess(false);
      setFormBuilderPasswordRequireSubmit(false);
      setFormBuilderPassword("");
      setFormBuilderCanvasEnabled(false);
      setFormBuilderCanvasCourseId("");
      setFormBuilderCanvasAllowedSections(null);
      setFormBuilderCanvasAllowedSections(null);
      setFormBuilderCanvasPosition("bottom");
      setFormBuilderReminderEnabled(false);
      setFormBuilderReminderValue(1);
      setFormBuilderReminderUnit("weeks");
      setFormBuilderReminderUntil("");
      setFormBuilderSubmissionBackupEnabled(false);
      setFormBuilderSubmissionBackupFormats(["json"]);
      setFormCreateReminderEnabled(false);
      setFormCreateReminderValue(1);
      setFormCreateReminderUnit("weeks");
      setFormCreateReminderUntil("");
      setFormBuilderDiscussionEnabled(false);
      setFormBuilderDiscussionMarkdownEnabled(true);
      setFormBuilderDiscussionHtmlEnabled(false);
      setFormBuilderDiscussionMathjaxEnabled(false);
      setFormBuilderCommentNotifyEnabled(true);
      setFormBuilderTemplateKey("");
      setFormBuilderSlugEdit("");
      return;
    }
    setFormBuilderSlugEdit(slug);
    const response = await apiFetch(`${API_BASE}/api/forms/${encodeURIComponent(slug)}`);
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setFormBuilderStatus(payload?.error || "Failed to load form schema.");
      return;
    }
    const rawSchema = payload?.data?.template_schema_json || "";
    if (!rawSchema) {
      setFormBuilderSchema("");
      setFormBuilderStatus("Schema not found.");
      return;
    }
    try {
      const parsed = JSON.parse(rawSchema);
      setFormBuilderSchema(JSON.stringify(parsed, null, 2));
      setFormBuilderStatus("Schema loaded.");
    } catch (error) {
      setFormBuilderSchema(rawSchema);
      setFormBuilderStatus("Schema loaded (raw).");
    }

    const selected = safeForms.find((form) => form.slug === slug);
    if (selected) {
      setFormBuilderDescription(String(selected.description || ""));
      setFormBuilderTemplateKey(selected.templateKey ? String(selected.templateKey) : "");
      setFormBuilderPublic(Boolean(selected.is_public));
      setFormBuilderLocked(Boolean(selected.is_locked));
      setFormBuilderAuthPolicy(String(selected.auth_policy || "optional"));
      setFormBuilderAvailableFrom(
        utcToLocalInputWithZone(selected.available_from ?? null, formBuilderAvailabilityTimezone)
      );
      setFormBuilderAvailableUntil(
        utcToLocalInputWithZone(selected.available_until ?? null, formBuilderAvailabilityTimezone)
      );
      const accessFlag = Boolean(selected.password_require_access);
      const submitFlag =
        Boolean(selected.password_require_submit) ||
        (!accessFlag && !selected.password_require_submit && Boolean(selected.password_required));
      setFormBuilderPasswordRequireAccess(accessFlag);
      setFormBuilderPasswordRequireSubmit(submitFlag);
      setFormBuilderPassword("");
      setFormBuilderCanvasEnabled(Boolean(selected.canvas_enabled));
      setFormBuilderCanvasCourseId(String(selected.canvas_course_id || ""));
      setFormBuilderCanvasCourseId(String(selected.canvas_course_id || ""));
      setFormBuilderCanvasPosition(String(selected.canvas_fields_position || "bottom"));
      setFormBuilderReminderEnabled(Boolean(selected.reminder_enabled));
      const freq = String(selected.reminder_frequency || "1:weeks");
      if (freq.includes(":")) {
        const [val, unit] = freq.split(":");
        setFormBuilderReminderValue(parseInt(val) || 1);
        setFormBuilderReminderUnit(unit || "weeks");
      } else {
        // Backward compatibility
        if (freq === "daily") { setFormBuilderReminderValue(1); setFormBuilderReminderUnit("days"); }
        else if (freq === "monthly") { setFormBuilderReminderValue(1); setFormBuilderReminderUnit("months"); }
        else { setFormBuilderReminderValue(1); setFormBuilderReminderUnit("weeks"); }
      }
      setFormBuilderReminderUntil(
        utcToLocalInputWithZone(selected.reminder_until ?? null, formBuilderAvailabilityTimezone)
      );
      setFormBuilderSaveAllVersions(Boolean(selected.save_all_versions));
      setFormBuilderSubmissionBackupEnabled(Boolean(selected.submission_backup_enabled));
      setFormBuilderSubmissionBackupFormats(
        Array.isArray(selected.submission_backup_formats) && selected.submission_backup_formats.length > 0
          ? selected.submission_backup_formats
          : ["json"]
      );
      setFormBuilderDiscussionEnabled(Boolean(selected.discussion_enabled));
      setFormBuilderDiscussionMarkdownEnabled(
        selected.discussion_markdown_enabled == null ? true : Boolean(selected.discussion_markdown_enabled)
      );
      setFormBuilderDiscussionHtmlEnabled(Boolean(selected.discussion_html_enabled));
      setFormBuilderDiscussionMathjaxEnabled(Boolean(selected.discussion_mathjax_enabled));
      setFormBuilderCommentNotifyEnabled(
        selected.comment_notify_enabled == null ? true : Boolean(selected.comment_notify_enabled)
      );
      if (selected.canvas_allowed_section_ids_json) {
        try {
          const parsed = JSON.parse(String(selected.canvas_allowed_section_ids_json));
          if (Array.isArray(parsed)) {
            setFormBuilderCanvasAllowedSections(parsed.map((id: any) => String(id)));
          } else {
            setFormBuilderCanvasAllowedSections(null);
          }
        } catch (error) {
          setFormBuilderCanvasAllowedSections(null);
        }
      } else {
        setFormBuilderCanvasAllowedSections(null);
      }
      if (selected.canvas_course_id) {
        loadCanvasSections(String(selected.canvas_course_id));
      }
    }
  }

  async function handleUpdateFormSchema() {
    setFormBuilderStatus(null);
    if (!formBuilderSlug) {
      setFormBuilderStatus("Select a form to update.");
      return;
    }
    const normalizedSlugEdit = formBuilderSlugEdit.trim();
    const nextSlug =
      normalizedSlugEdit && normalizedSlugEdit !== formBuilderSlug
        ? normalizedSlugEdit
        : null;
    if (!formBuilderSchema.trim()) {
      setFormBuilderStatus("Schema JSON is required.");
      return;
    }
    const parsed = parseSchemaText(formBuilderSchema);
    if ((parsed as any).error) {
      setFormBuilderStatus((parsed as any).error);
      return;
    }
    const rulesError = validateFileRulesInSchema(parsed.schema);
    if (rulesError) {
      setFormBuilderStatus(rulesError);
      return;
    }
    const visibilityError = validateVisibilityRulesInSchema(parsed.schema);
    if (visibilityError) {
      setFormBuilderStatus(visibilityError);
      return;
    }
    const response = await apiFetch(`${API_BASE}/api/admin/forms/${encodeURIComponent(formBuilderSlug)}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        schema_json: formBuilderSchema,
        newSlug: nextSlug || undefined
      })
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      const detailMessage =
        payload?.detail?.message ||
        payload?.detail?.field ||
        (typeof payload?.detail === "string" ? payload.detail : null);
      setFormBuilderStatus(
        detailMessage
          ? `${payload?.error || "Failed to update form"}: ${detailMessage}`
          : payload?.error || "Failed to update form."
      );
      onNotice("Failed to update form schema.", "error");
      return;
    }
    if (nextSlug) {
      setFormBuilderSlug(nextSlug);
      setFormBuilderSlugEdit(nextSlug);
    }
    setFormBuilderStatus("Form schema updated.");
    onNotice("Form schema updated.", "success");
    await loadBuilder();
  }

  async function handleRefreshFormFromTemplate() {
    setFormBuilderStatus(null);
    if (!formBuilderSlug) {
      setFormBuilderStatus("Select a form to update.");
      return;
    }
    const templateKey = formBuilderTemplateKey.trim();
    if (!templateKey) {
      setFormBuilderStatus("This form has no template to refresh from.");
      return;
    }
    if (!window.confirm("Refresh form schema from the latest template? This will overwrite form schema.")) {
      return;
    }
    const response = await apiFetch(`${API_BASE}/api/admin/forms/${encodeURIComponent(formBuilderSlug)}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ templateKey, refreshTemplate: true })
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setFormBuilderStatus(payload?.error || "Failed to refresh form from template.");
      return;
    }
    await loadBuilder();
    await handleLoadFormSchema(formBuilderSlug);
    setFormBuilderStatus("Form refreshed from template.");
  }

  function generatePassword(length: number = 12) {
    const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%";
    const array = new Uint32Array(length);
    crypto.getRandomValues(array);
    let result = "";
    for (let i = 0; i < length; i += 1) {
      result += alphabet[array[i] % alphabet.length];
    }
    return result;
  }

  async function handleDuplicateForm() {
    if (!formBuilderSlug) {
      setFormBuilderStatus("Select a form to duplicate.");
      return;
    }
    const baseSlug = formBuilderSlug.replace(/-copy\\d*$/, "");
    const proposedSlug = `${baseSlug}-copy`;
    const newSlug = window.prompt("New slug for duplicated form:", proposedSlug);
    if (!newSlug || !newSlug.trim()) return;
    const newTitle = window.prompt("Title for duplicated form:", `${formBuilderSlug} copy`) || "";
    if (!newTitle.trim()) {
      setFormBuilderStatus("Title is required for duplicate form.");
      return;
    }
    setFormBuilderStatus(null);
    const backupRes = await apiFetch(
      `${API_BASE}/api/admin/forms/${encodeURIComponent(formBuilderSlug)}/backup`
    );
    const backupPayload = await backupRes.json().catch(() => null);
    if (!backupRes.ok) {
      setFormBuilderStatus(backupPayload?.error || "Failed to load form backup.");
      return;
    }
    const formData = backupPayload?.data?.form || null;
    if (!formData || !formData.templateKey) {
      setFormBuilderStatus("Backup data is missing template info.");
      return;
    }
    let canvasAllowedSectionIds: string[] | null = null;
    if (formData.canvas_allowed_section_ids_json) {
      try {
        const parsedAllowed = JSON.parse(formData.canvas_allowed_section_ids_json);
        if (Array.isArray(parsedAllowed)) {
          canvasAllowedSectionIds = parsedAllowed.map((id: any) => String(id));
        }
      } catch {
        canvasAllowedSectionIds = null;
      }
    }
    const createRes = await apiFetch(`${API_BASE}/api/admin/forms`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        slug: newSlug.trim(),
        title: newTitle.trim(),
        templateKey: formData.templateKey,
        description: formData.description ?? null,
        is_public: Boolean(formData.is_public),
        is_locked: Boolean(formData.is_locked),
        auth_policy: formData.auth_policy || "optional",
        availableFrom: formData.available_from ?? null,
        availableUntil: formData.available_until ?? null,
        passwordRequired: false,
        canvasEnabled: Boolean(formData.canvas_enabled),
        canvasCourseId: formData.canvas_course_id ?? null,
        canvasAllowedSectionIds,
        canvasFieldsPosition: formData.canvas_fields_position || "bottom",
        submissionBackupEnabled: Boolean(formData.submission_backup_enabled),
        submissionBackupFormats:
          Array.isArray(formData.submission_backup_formats) && formData.submission_backup_formats.length > 0
            ? formData.submission_backup_formats
            : ["json"],
        discussionEnabled: Boolean(formData.discussion_enabled),
        discussionMarkdownEnabled:
          formData.discussion_markdown_enabled == null
            ? true
            : Boolean(formData.discussion_markdown_enabled),
        discussionHtmlEnabled: Boolean(formData.discussion_html_enabled),
        discussionMathjaxEnabled: Boolean(formData.discussion_mathjax_enabled),
        commentNotifyEnabled:
          formData.comment_notify_enabled == null ? true : Boolean(formData.comment_notify_enabled)
      })
    });
    const createPayload = await createRes.json().catch(() => null);
    if (!createRes.ok) {
      setFormBuilderStatus(createPayload?.error || "Failed to create duplicate form.");
      return;
    }
    if (formData.schema_json) {
      await apiFetch(`${API_BASE}/api/admin/forms/${encodeURIComponent(newSlug.trim())}`, {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ schema_json: formData.schema_json })
      });
    }
    if (formData.password_required) {
      setFormBuilderStatus("Duplicate created. Password is not copied; set a new one.");
    } else {
      setFormBuilderStatus("Duplicate form created.");
    }
    await loadBuilder();
  }

  async function handleUpdateFormSettings() {
    setFormBuilderStatus(null);
    if (!formBuilderSlug) {
      setFormBuilderStatus("Select a form to update.");
      return;
    }
    const normalizedSlugEdit = formBuilderSlugEdit.trim();
    const nextSlug =
      normalizedSlugEdit && normalizedSlugEdit !== formBuilderSlug
        ? normalizedSlugEdit
        : null;
    if (formBuilderCanvasEnabled && !formBuilderCanvasCourseId) {
      setFormBuilderStatus("Select a Canvas course or disable Canvas enrollment.");
      return;
    }
    if (
      formBuilderCanvasEnabled &&
      formBuilderCanvasAllowedSections !== null &&
      formBuilderCanvasAllowedSections.length === 0
    ) {
      setFormBuilderStatus("Select at least one section or allow all sections.");
      return;
    }
    const canvasAllowedSectionIds = Array.isArray(formBuilderCanvasAllowedSections)
      ? formBuilderCanvasAllowedSections
      : undefined;
    const availableFrom =
      localInputToUtcWithZone(formBuilderAvailableFrom, formBuilderAvailabilityTimezone) || null;
    const availableUntil =
      localInputToUtcWithZone(formBuilderAvailableUntil, formBuilderAvailabilityTimezone) || null;
    if (availableFrom && availableUntil && availableFrom >= availableUntil) {
      setFormBuilderStatus("Available until must be after available from.");
      return;
    }
    let response: Response | null = null;
    let payload: any = null;
    try {
      response = await apiFetch(`${API_BASE}/api/admin/forms/${encodeURIComponent(formBuilderSlug)}`, {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          newSlug: nextSlug || undefined,
          description: formBuilderDescription || null,
          templateKey: formBuilderTemplateKey.trim() || null,
          refreshTemplate: false,
          is_public: formBuilderPublic,
          is_locked: formBuilderLocked,
          auth_policy: formBuilderAuthPolicy,
          availableFrom,
          availableUntil,
          passwordRequired: formBuilderPasswordRequired,
          passwordRequireAccess: formBuilderPasswordRequireAccess,
          passwordRequireSubmit: formBuilderPasswordRequireSubmit,
          formPassword: formBuilderPassword.trim() || null,
          canvasEnabled: formBuilderCanvasEnabled,
          canvasCourseId: formBuilderCanvasEnabled ? formBuilderCanvasCourseId || null : null,
          ...(formBuilderCanvasEnabled && canvasAllowedSectionIds
            ? { canvasAllowedSectionIds }
            : {}),
          canvasFieldsPosition: formBuilderCanvasPosition,
          reminderEnabled: formBuilderReminderEnabled,
          reminderFrequency: `${formBuilderReminderValue}:${formBuilderReminderUnit}`,
          reminderUntil: localInputToUtcWithZone(formBuilderReminderUntil, formBuilderAvailabilityTimezone) || null,
          saveAllVersions: formBuilderSaveAllVersions,
          submissionBackupEnabled: formBuilderSubmissionBackupEnabled,
          submissionBackupFormats: formBuilderSubmissionBackupFormats,
          discussionEnabled: formBuilderDiscussionEnabled,
          discussionMarkdownEnabled: formBuilderDiscussionMarkdownEnabled,
          discussionHtmlEnabled: formBuilderDiscussionHtmlEnabled,
          discussionMathjaxEnabled: formBuilderDiscussionMathjaxEnabled,
          commentNotifyEnabled: formBuilderCommentNotifyEnabled
        })
      });
      payload = await response.json().catch(() => null);
    } catch (error) {
      setFormBuilderStatus("Failed to update form settings.");
      onNotice("Failed to update form settings.", "error");
      return;
    }
    if (!response || !response.ok) {
      const detailMessage =
        payload?.detail?.message ||
        payload?.detail?.field ||
        (typeof payload?.detail === "string" ? payload.detail : null);
      setFormBuilderStatus(
        detailMessage
          ? `${payload?.error || "Failed to update form settings"}: ${detailMessage}`
          : payload?.error || "Failed to update form settings."
      );
      onNotice("Failed to update form settings.", "error");
      return;
    }
    if (nextSlug) {
      setFormBuilderSlug(nextSlug);
      setFormBuilderSlugEdit(nextSlug);
    }
    const warnings = Array.isArray(payload?.warning) ? payload.warning : payload?.warning ? [payload.warning] : [];
    const missingColumns = warnings
      .filter((warning: any) => warning?.code === "missing_columns" && Array.isArray(warning.columns))
      .flatMap((warning: any) => warning.columns);
    if (missingColumns.length > 0) {
      const uniqueColumns = Array.from(new Set(missingColumns.map(String)));
      const warningMessage = `Form settings updated, but some fields could not be saved: ${uniqueColumns.join(", ")}.`;
      setFormBuilderStatus(warningMessage);
      onNotice(warningMessage, "warning");
    } else {
      setFormBuilderStatus("Form settings updated.");
      onNotice("Form settings updated.", "success");
    }
    await loadBuilder();
  }

  function handleCopyFormLink() {
    if (!formBuilderSlug) {
      setFormBuilderStatus("Select a form to copy the link.");
      return;
    }
    const base = `${window.location.origin}${PUBLIC_BASE}`.replace(/\/+$/, "/");
    const link = `${base}#/f/${encodeURIComponent(formBuilderSlug)}`;
    navigator.clipboard
      .writeText(link)
      .then(() => setFormBuilderStatus("Form link copied."))
      .catch(() => setFormBuilderStatus("Unable to copy form link."));
  }

  function handleAddFormField() {
    const nextSchema = applyAddFieldToSchema(formBuilderSchema, {
      type: formFieldType,
      customType: formFieldCustomType,
      id: formFieldId,
      label: formFieldLabel,
      required: formFieldRequired,
      description: formFieldDescription,
      placeholder: formFieldPlaceholder,
      options: formFieldOptions,
      multiple: formFieldMultiple,
      textareaMarkdownEnabled: formFieldTextareaMarkdownEnabled,
      textareaMathjaxEnabled: formFieldTextareaMathjaxEnabled,
      textareaRows: formFieldTextareaRows,
      emailDomain: formEmailDomain,
      autofillFromLogin: formAutofillFromLogin,
      dateTimezone: formDateTimezone,
      dateMode: formDateMode,
      dateShowTimezone: formDateShowTimezone,
      visibilityEnabled: formFieldVisibilityEnabled,
      visibilityOperator: formFieldVisibilityOperator,
      visibilityConditions: formFieldVisibilityConditions
    });
    if (nextSchema.error) {
      setFormBuilderStatus(nextSchema.error);
      return;
    }
    if (nextSchema.text) {
      setFormBuilderSchema(nextSchema.text);
    }
    setFormBuilderStatus("Field added to form schema.");
    setFormFieldId("");
    setFormFieldLabel("");
    setFormFieldRequired(false);
    setFormFieldDescription("");
    setFormFieldPlaceholder("");
    setFormFieldOptions("");
    setFormFieldMultiple(false);
    setFormFieldTextareaMarkdownEnabled(false);
    setFormFieldTextareaMathjaxEnabled(false);
    setFormFieldTextareaRows(4);
    setFormEmailDomain("");
    setFormAutofillFromLogin(false);
    setFormDateTimezone(getAppDefaultTimezone());
    setFormDateMode("datetime");
    setFormDateShowTimezone(true);
    setFormFieldVisibilityEnabled(false);
    setFormFieldVisibilityOperator("all");
    setFormFieldVisibilityConditions([{ dependsOn: "", values: "", mode: "any" }]);
  }

  function handleRemoveFormField(fieldId: string) {
    const nextSchema = removeFieldFromSchemaText(formBuilderSchema, fieldId);
    if (nextSchema.error) {
      setFormBuilderStatus(nextSchema.error);
      return;
    }
    if (nextSchema.text) {
      setFormBuilderSchema(nextSchema.text);
    }
    setFormBuilderStatus("Field removed.");
  }

  function handleMoveFormField(fieldId: string, direction: "up" | "down") {
    const nextSchema = moveFieldInSchemaText(formBuilderSchema, fieldId, direction);
    if (nextSchema.error) {
      setFormBuilderStatus(nextSchema.error);
      return;
    }
    if (nextSchema.text) {
      setFormBuilderSchema(nextSchema.text);
    }
    setFormBuilderStatus("Field moved.");
  }

  function handleReorderFormField(fieldId: string, targetIndex: number) {
    const nextSchema = moveFieldToIndexInSchemaText(formBuilderSchema, fieldId, targetIndex);
    if (nextSchema.error) {
      setFormBuilderStatus(nextSchema.error);
      return;
    }
    if (nextSchema.text) {
      setFormBuilderSchema(nextSchema.text);
    }
    setFormBuilderStatus("Field reordered.");
  }

  function handleSelectFormField(fieldId: string, field: Record<string, unknown> | null) {
    setFormFieldEditId(fieldId);
    if (!field) return;
    const type = String(field.type || "text");
    const rules = (field as any).rules || {};
    const domain = typeof rules.domain === "string" ? rules.domain : "";
    setFormFieldType(
      ["text", "full_name", "email", "github_username", "url", "date", "number", "textarea", "select", "checkbox"].includes(type)
        ? type
        : "custom"
    );
    setFormFieldCustomType(
      ["text", "full_name", "email", "github_username", "url", "date", "number", "textarea", "select", "checkbox"].includes(type)
        ? ""
        : type
    );
    setFormFieldId(String(field.id || ""));
    setFormFieldLabel(String(field.label || ""));
    setFormFieldRequired(Boolean(field.required));
    setFormFieldDescription(String((field as any).description || ""));
    setFormFieldPlaceholder(String(field.placeholder || ""));
    const options = Array.isArray((field as any).options) ? (field as any).options : [];
    setFormFieldOptions(options.join(","));
    setFormFieldMultiple(Boolean((field as any).multiple));
    setFormFieldTextareaMarkdownEnabled(type === "textarea" ? Boolean(rules.markdownEnabled) : false);
    setFormFieldTextareaMathjaxEnabled(type === "textarea" ? Boolean(rules.mathjaxEnabled) : false);
    setFormFieldTextareaRows(
      type === "textarea" && typeof rules.rows === "number" ? Math.max(1, Math.round(rules.rows)) : 4
    );
    setFormEmailDomain(type === "email" ? String(domain) : "");
    setFormAutofillFromLogin(
      type === "email" || type === "github_username" ? Boolean(rules.autofill) : false
    );
    setFormDateTimezone(
      type === "date" && typeof rules.timezoneDefault === "string"
        ? String(rules.timezoneDefault)
        : getAppDefaultTimezone()
    );
    setFormDateMode(
      type === "date" && typeof rules.mode === "string" ? String(rules.mode) : "datetime"
    );
    setFormDateShowTimezone(!(type === "date" && rules.timezoneOptional === true));
    const visibility = (field as any).visibility || {};
    const normalizedVisibility = normalizeVisibilityRule(visibility);
    if (normalizedVisibility) {
      setFormFieldVisibilityEnabled(true);
      setFormFieldVisibilityOperator(normalizedVisibility.operator);
      setFormFieldVisibilityConditions(
        normalizedVisibility.conditions.map((condition) => ({
          dependsOn: condition.dependsOn,
          values: condition.values.join(", "),
          mode: condition.mode === "all" ? "all" : "any"
        }))
      );
    } else {
      setFormFieldVisibilityEnabled(false);
      setFormFieldVisibilityOperator("all");
      setFormFieldVisibilityConditions([{ dependsOn: "", values: "", mode: "any" }]);
    }
  }

  function handleUpdateFormField() {
    const nextSchema = updateFieldInSchemaText(formBuilderSchema, formFieldEditId, {
      type: formFieldType,
      customType: formFieldCustomType,
      id: formFieldId,
      label: formFieldLabel,
      required: formFieldRequired,
      description: formFieldDescription,
      placeholder: formFieldPlaceholder,
      options: formFieldOptions,
      multiple: formFieldMultiple,
      textareaMarkdownEnabled: formFieldTextareaMarkdownEnabled,
      textareaMathjaxEnabled: formFieldTextareaMathjaxEnabled,
      textareaRows: formFieldTextareaRows,
      emailDomain: formEmailDomain,
      autofillFromLogin: formAutofillFromLogin,
      dateTimezone: formDateTimezone,
      dateMode: formDateMode,
      dateShowTimezone: formDateShowTimezone,
      visibilityEnabled: formFieldVisibilityEnabled,
      visibilityOperator: formFieldVisibilityOperator,
      visibilityConditions: formFieldVisibilityConditions
    });
    if (nextSchema.error) {
      setFormBuilderStatus(nextSchema.error);
      return;
    }
    if (nextSchema.text) {
      setFormBuilderSchema(nextSchema.text);
    }
    setFormBuilderStatus("Field updated.");
  }

  function handleAddFormFileField() {
    const nextSchema = applyAddFileFieldToSchema(formBuilderSchema, {
      id: formFileFieldId,
      label: formFileFieldLabel,
      required: formFileFieldRequired,
      extensions: formFileFieldExtensions,
      maxSizeMb: formFileFieldMaxSizeMb,
      maxFiles: formFileFieldMaxFiles
    });
    if (nextSchema.error) {
      setFormBuilderStatus(nextSchema.error);
      return;
    }
    if (nextSchema.text) {
      setFormBuilderSchema(nextSchema.text);
    }
    setFormBuilderStatus("File field added to form schema.");
    setFormFileFieldId("");
    setFormFileFieldLabel("");
    setFormFileFieldRequired(false);
    setFormFileFieldExtensions("");
  }

  function handleSelectFormFileField(fieldId: string, field: Record<string, unknown> | null) {
    setFormFileEditId(fieldId);
    if (!field) return;
    const rules = (field as any).rules || {};
    const extensions = Array.isArray(rules.allowedExtensions)
      ? rules.allowedExtensions
      : Array.isArray(rules.extensions)
        ? rules.extensions
        : [];
    const maxBytes =
      typeof rules.maxFileSizeBytes === "number"
        ? rules.maxFileSizeBytes
        : typeof rules.maxSizeBytes === "number"
          ? rules.maxSizeBytes
          : 10 * 1024 * 1024;
    const maxFiles = typeof rules.maxFiles === "number" ? rules.maxFiles : 1;
    setFormFileFieldId(String((field as any).id || ""));
    setFormFileFieldLabel(String((field as any).label || ""));
    setFormFileFieldRequired(Boolean((field as any).required));
    setFormFileFieldExtensions(extensions.join(","));
    setFormFileFieldMaxSizeMb(Math.max(1, Math.round(maxBytes / (1024 * 1024))));
    setFormFileFieldMaxFiles(Math.max(1, maxFiles));
  }

  function handleUpdateFormFileField() {
    const nextSchema = updateFileFieldInSchemaText(formBuilderSchema, formFileEditId, {
      id: formFileFieldId,
      label: formFileFieldLabel,
      required: formFileFieldRequired,
      extensions: formFileFieldExtensions,
      maxSizeMb: formFileFieldMaxSizeMb,
      maxFiles: formFileFieldMaxFiles
    });
    if (nextSchema.error) {
      setFormBuilderStatus(nextSchema.error);
      return;
    }
    if (nextSchema.text) {
      setFormBuilderSchema(nextSchema.text);
    }
    setFormBuilderStatus("File field updated.");
  }

  async function handleCreateForm() {
    setFormCreateStatus(null);
    if (!formCreateSlug || !formCreateTitle) {
      setFormCreateStatus("Slug and title are required.");
      return;
    }
    const hasTemplate = Boolean(formCreateTemplateKey);
    const schemaSource = formCreateSchema.trim() ? formCreateSchema : '{"fields": []}';
    if (!hasTemplate) {
      const parsed = parseSchemaText(schemaSource);
      if ((parsed as any).error) {
        setFormCreateStatus((parsed as any).error);
        return;
      }
      const rulesError = validateFileRulesInSchema(parsed.schema);
      if (rulesError) {
        setFormCreateStatus(rulesError);
        return;
      }
      const visibilityError = validateVisibilityRulesInSchema(parsed.schema);
      if (visibilityError) {
        setFormCreateStatus(visibilityError);
        return;
      }
    }
    if (formCreateCanvasEnabled && !formCreateCanvasCourseId) {
      setFormCreateStatus("Select a Canvas course or disable Canvas enrollment.");
      return;
    }
    if (
      formCreateCanvasEnabled &&
      formCreateCanvasAllowedSections !== null &&
      formCreateCanvasAllowedSections.length === 0
    ) {
      setFormCreateStatus("Select at least one section or allow all sections.");
      return;
    }
    const createCanvasAllowedSectionIds = Array.isArray(formCreateCanvasAllowedSections)
      ? formCreateCanvasAllowedSections
      : undefined;
    const availableFrom =
      localInputToUtcWithZone(formCreateAvailableFrom, formCreateAvailabilityTimezone) || null;
    const availableUntil =
      localInputToUtcWithZone(formCreateAvailableUntil, formCreateAvailabilityTimezone) || null;
    if (availableFrom && availableUntil && availableFrom >= availableUntil) {
      setFormCreateStatus("Available until must be after available from.");
      return;
    }
    if (formCreatePasswordRequired && !formCreatePassword.trim()) {
      setFormCreateStatus("Form password is required when password protection is enabled.");
      return;
    }
    const response = await apiFetch(`${API_BASE}/api/admin/forms`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        slug: formCreateSlug,
        title: formCreateTitle,
        templateKey: hasTemplate ? formCreateTemplateKey : undefined,
        schema_json: !hasTemplate ? schemaSource : undefined,
        description: formCreateDescription || null,
        is_public: formCreatePublic,
        is_locked: formCreateLocked,
        auth_policy: formCreateAuthPolicy,
        availableFrom,
        availableUntil,
        passwordRequired: formCreatePasswordRequired,
        passwordRequireAccess: formCreatePasswordRequireAccess,
        passwordRequireSubmit: formCreatePasswordRequireSubmit,
        formPassword: formCreatePassword.trim() || null,
        canvasEnabled: formCreateCanvasEnabled,
        canvasCourseId: formCreateCanvasEnabled ? formCreateCanvasCourseId || null : null,
        ...(formCreateCanvasEnabled && createCanvasAllowedSectionIds
          ? { canvasAllowedSectionIds: createCanvasAllowedSectionIds }
          : {}),
        canvasFieldsPosition: formCreateCanvasPosition,
        saveAllVersions: formCreateSaveAllVersions,
        submissionBackupEnabled: formCreateSubmissionBackupEnabled,
        submissionBackupFormats: formCreateSubmissionBackupFormats,
        reminderEnabled: formCreateReminderEnabled,
        reminderFrequency: `${formCreateReminderValue}:${formCreateReminderUnit}`,
        reminderUntil: localInputToUtcWithZone(formCreateReminderUntil, formCreateAvailabilityTimezone) || null,
        discussionEnabled: formCreateDiscussionEnabled,
        discussionMarkdownEnabled: formCreateDiscussionMarkdownEnabled,
        discussionHtmlEnabled: formCreateDiscussionHtmlEnabled,
        discussionMathjaxEnabled: formCreateDiscussionMathjaxEnabled,
        commentNotifyEnabled: formCreateCommentNotifyEnabled
      })
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      const detailMessage =
        typeof payload?.detail?.message === "string"
          ? payload.detail.message
          : typeof payload?.detail === "string"
            ? payload.detail
            : "";
      const statusMessage = [payload?.error, detailMessage].filter(Boolean).join(": ");
      setFormCreateStatus(statusMessage || "Failed to create form.");
      return;
    }
    setFormCreateStatus("Form created.");
    setFormCreateSlug("");
    setFormCreateTitle("");
    setFormCreateDescription("");
    setFormCreateLocked(false);
    setFormCreateSchema('{"fields": []}');
    setFormCreateAvailableFrom("");
    setFormCreateAvailableUntil("");
    setFormCreateAvailabilityTimezone(getAppDefaultTimezone());
    setFormCreatePasswordRequireAccess(false);
    setFormCreatePasswordRequireSubmit(false);
    setFormCreatePassword("");
    setFormCreateCanvasEnabled(false);
    setFormCreateCanvasCourseId("");
    setFormCreateCanvasAllowedSections(null);
    setFormCreateCanvasPosition("bottom");
    setFormCreateReminderEnabled(false);
    setFormCreateReminderValue(1);
    setFormCreateReminderUnit("weeks");
    setFormCreateReminderUntil("");
    setFormCreateSubmissionBackupEnabled(false);
    setFormCreateSubmissionBackupFormats(["json"]);
    setFormCreateDiscussionEnabled(false);
    setFormCreateDiscussionMarkdownEnabled(true);
    setFormCreateDiscussionHtmlEnabled(false);
    setFormCreateDiscussionMathjaxEnabled(false);
    setFormCreateCommentNotifyEnabled(true);
    await loadBuilder();
  }

  function renderCanvasConfig(options: {
    enabled: boolean;
    onEnabledChange: (value: boolean) => void;
    courseId: string;
    onCourseIdChange: (value: string) => void;
    allowedSectionIds: string[] | null;
    onAllowedSectionIdsChange: (value: string[] | null) => void;
    fieldsPosition: string;
    onFieldsPositionChange: (value: string) => void;
    idPrefix: string;
  }) {
    const sections =
      options.courseId && canvasSectionsCourseId === options.courseId ? canvasSections : [];
    const allowAll = options.allowedSectionIds === null;
    const selectedSet = new Set(
      allowAll ? sections.map((section) => String(section.id)) : options.allowedSectionIds || []
    );
    return (
      <div className="panel panel--compact mt-3">
        <div className="panel-header">
          <h4 className="mb-0">Canvas enrollment</h4>
        </div>
        <div className="form-check mt-2">
          <input
            className="form-check-input"
            type="checkbox"
            checked={options.enabled}
            onChange={(event) => options.onEnabledChange(event.target.checked)}
            id={`${options.idPrefix}-canvas-enabled`}
          />
          <label className="form-check-label" htmlFor={`${options.idPrefix}-canvas-enabled`}>
            Enable Canvas enrollment
          </label>
        </div>
        {options.enabled ? (
          <>
            <div className="row g-3 mt-1">
              <div className="col-md-6">
                <label className="form-label">Course</label>
                <div className="input-group mb-2">
                  <input
                    className="form-control"
                    placeholder="Search courses"
                    value={canvasCourseQuery}
                    onChange={(event) => setCanvasCourseQuery(event.target.value)}
                  />
                  <button
                    type="button"
                    className="btn btn-outline-secondary"
                    onClick={() => loadCanvasCourses(canvasCourseQuery)}
                    disabled={canvasCoursesLoading}
                  >
                    <i className="bi bi-search" aria-hidden="true" />{" "}
                    {canvasCoursesLoading ? "Searching..." : "Search"}
                  </button>
                  <button
                    type="button"
                    className="btn btn-outline-primary"
                    onClick={() => syncCanvas("courses")}
                    disabled={canvasSyncing}
                  >
                    <i className="bi bi-arrow-repeat" aria-hidden="true" /> Sync
                  </button>
                </div>
                {canvasCoursesNeedsSync ? (
                  <div className="alert alert-warning py-2">No cached courses. Sync first.</div>
                ) : null}
                <select
                  className="form-select"
                  value={options.courseId}
                  onChange={(event) => {
                    const next = event.target.value;
                    options.onCourseIdChange(next);
                    options.onAllowedSectionIdsChange(null);
                    loadCanvasSections(next);
                  }}
                >
                  <option value="">Select course</option>
                  {canvasCourses.map((course) => (
                    <option key={course.id} value={String(course.id)}>
                      {course.name} {course.code ? `(${course.code})` : ""}
                    </option>
                  ))}
                </select>
              </div>
              <div className="col-md-6">
                <label className="form-label">Sections</label>
                <div className="d-flex flex-wrap gap-2 mb-2">
                  <button
                    type="button"
                    className="btn btn-outline-primary btn-sm"
                    onClick={() => syncCanvas("course_sections", options.courseId)}
                    disabled={canvasSyncing || !options.courseId}
                  >
                    <i className="bi bi-arrow-repeat" aria-hidden="true" /> Sync sections
                  </button>
                  <button
                    type="button"
                    className="btn btn-outline-secondary btn-sm"
                    onClick={() => options.onAllowedSectionIdsChange(null)}
                    disabled={!options.courseId}
                  >
                    <i className="bi bi-check2-all" aria-hidden="true" /> Select all
                  </button>
                  <button
                    type="button"
                    className="btn btn-outline-secondary btn-sm"
                    onClick={() => options.onAllowedSectionIdsChange([])}
                    disabled={!options.courseId}
                  >
                    <i className="bi bi-x-circle" aria-hidden="true" /> Clear
                  </button>
                </div>
                {canvasSectionsNeedsSync && options.courseId ? (
                  <div className="alert alert-warning py-2">No cached sections. Sync first.</div>
                ) : null}
                {sections.length > 0 ? (
                  <div className="section-picker">
                    {sections.map((section) => {
                      const id = String(section.id);
                      const checked = selectedSet.has(id);
                      return (
                        <label key={id} className="d-flex align-items-center gap-2 mb-1">
                          <input
                            type="checkbox"
                            checked={checked}
                            onChange={(event) => {
                              const next = new Set(selectedSet);
                              if (event.target.checked) {
                                next.add(id);
                              } else {
                                next.delete(id);
                              }
                              const nextList = Array.from(next);
                              if (nextList.length === sections.length) {
                                options.onAllowedSectionIdsChange(null);
                              } else {
                                options.onAllowedSectionIdsChange(nextList);
                              }
                            }}
                          />
                          <span>{section.name}</span>
                        </label>
                      );
                    })}
                  </div>
                ) : (
                  <div className="muted">Select a course to view sections.</div>
                )}
                {options.allowedSectionIds !== null && options.allowedSectionIds.length === 0 ? (
                  <div className="alert alert-warning py-2 mt-2">
                    Select at least one section or allow all sections.
                  </div>
                ) : null}
              </div>
            </div>
            <div className="mt-3">
              <label className="form-label">Canvas fields position</label>
              <select
                className="form-select"
                value={options.fieldsPosition}
                onChange={(event) => options.onFieldsPositionChange(event.target.value)}
              >
                <option value="top">Top of form</option>
                <option value="after_identity">After name/email</option>
                <option value="bottom">Bottom of form</option>
              </select>
              <div className="muted mt-1">
                Controls where the Canvas course info and section selector appear.
              </div>
            </div>
            {canvasError ? <div className="alert alert-danger mt-2">{canvasError}</div> : null}
          </>
        ) : null}
      </div>
    );
  }

  const safeForms = Array.isArray(forms) ? forms.filter((form) => form && typeof form === "object") : [];
  const safeTemplates = Array.isArray(templates)
    ? templates.filter((tpl) => tpl && typeof tpl === "object")
    : [];
  const selectedBuilderForm = safeForms.find((form) => form.slug === formBuilderSlug);
  const parsedTemplateSchema = parseSchemaText(templateEditorSchema);
  const schemaFields = Array.isArray(parsedTemplateSchema.fields)
    ? (parsedTemplateSchema.fields as Array<Record<string, unknown>>)
    : [];
  const templateTextFields = schemaFields.filter((field) => field.type !== "file");
  const templateFileFields = schemaFields.filter((field) => field.type === "file");
  const templateRulesError = validateFileRulesInSchema(parsedTemplateSchema.schema);
  const templateVisibilityError = validateVisibilityRulesInSchema(parsedTemplateSchema.schema);
  const parsedFormSchema = parseSchemaText(formBuilderSchema);
  const formSchemaFields = Array.isArray(parsedFormSchema.fields)
    ? (parsedFormSchema.fields as Array<Record<string, unknown>>)
    : [];
  const formTextFields = formSchemaFields.filter((field) => field.type !== "file");
  const formFileFields = formSchemaFields.filter((field) => field.type === "file");
  const formRulesError = validateFileRulesInSchema(parsedFormSchema.schema);
  const formVisibilityError = validateVisibilityRulesInSchema(parsedFormSchema.schema);
  const templateVisibilityControllers = schemaFields
    .filter((field) => VISIBILITY_CONTROLLER_TYPES.has(String(field.type)))
    .map((field) => {
      const options = Array.isArray((field as any).options) ? (field as any).options : [];
      return { id: String(field.id || ""), label: String(field.label || field.id || ""), options };
    })
    .filter((controller) => controller.id);
  const formVisibilityControllers = formSchemaFields
    .filter((field) => VISIBILITY_CONTROLLER_TYPES.has(String(field.type)))
    .map((field) => {
      const options = Array.isArray((field as any).options) ? (field as any).options : [];
      return { id: String(field.id || ""), label: String(field.label || field.id || ""), options };
    })
    .filter((controller) => controller.id);

  return (
    <section className="panel admin-scope">
      <div className="panel-header">
        <h2>Builder</h2>
        {user ? <span className="badge">{getUserDisplayName(user)}</span> : null}
      </div>
      {(markdownEnabled || mathjaxEnabled) ? (
        <div className="alert alert-info">
          <i className="bi bi-markdown" aria-hidden="true" /> Markdown
          {mathjaxEnabled ? " + MathJax" : ""} and HTML input are supported in titles,
          descriptions, labels, and placeholders.
        </div>
      ) : null}
      <div className="d-flex align-items-center gap-2 mb-3">
        <button type="button" className="btn btn-outline-primary btn-sm" onClick={() => loadBuilder()}>
          <i className="bi bi-arrow-clockwise" aria-hidden="true" /> Refresh
        </button>
        {lastRefresh ? <span className="muted">Last refresh: {formatTimeICT(lastRefresh)}</span> : null}
      </div>
      <div className="admin-grid">
        <div>
          <h3>Form builder</h3>
          <div className="panel panel--compact">
            <div className="d-flex flex-wrap gap-2 mb-3">
              <div className="btn-group" role="group">
                <button
                  type="button"
                  className={`btn ${formBuilderMode === "create" ? "btn-primary" : "btn-outline-primary"}`}
                  onClick={() => {
                    setFormBuilderMode("create");
                    setFormBuilderSlug("");
                    setFormBuilderSlugEdit("");
                    setFormBuilderSchema("");
                    setFormBuilderStatus(null);
                    setFormCreateCanvasEnabled(false);
                    setFormCreateCanvasCourseId("");
                    setFormCreateCanvasAllowedSections(null);
                    setFormCreateCanvasPosition("bottom");
                    setFormCreateAvailabilityTimezone(getAppDefaultTimezone());
                    setFormCreateSaveAllVersions(false);
                    setFormCreateSubmissionBackupEnabled(false);
                    setFormCreateSubmissionBackupFormats(["json"]);
                    setFormDateShowTimezone(true);
                  }}
                >
                  <i className="bi bi-plus-circle" aria-hidden="true" /> New form
                </button>
                <button
                  type="button"
                  className={`btn ${formBuilderMode === "edit" ? "btn-primary" : "btn-outline-primary"}`}
                  onClick={() => {
                    setFormBuilderMode("edit");
                    setFormCreateStatus(null);
                  }}
                >
                  <i className="bi bi-pencil-square" aria-hidden="true" /> Edit form
                </button>
              </div>
            </div>
            {formBuilderMode === "create" ? (
              <div className="row g-3">
                <div className="col-md-4">
                  <label className="form-label">Slug</label>
                  <input
                    className="form-control"
                    value={formCreateSlug}
                    onChange={(event) => setFormCreateSlug(event.target.value)}
                  />
                </div>
                <div className="col-md-4">
                  <label className="form-label">Title</label>
                  <input
                    className="form-control"
                    value={formCreateTitle}
                    onChange={(event) => setFormCreateTitle(event.target.value)}
                  />
                  {formCreateTitle ? (
                    <div className="mt-2">
                      <div className="muted">Preview</div>
                      <RichText
                        text={formCreateTitle}
                        markdownEnabled={markdownEnabled}
                        mathjaxEnabled={mathjaxEnabled}
                        inline
                      />
                    </div>
                  ) : null}
                </div>
                <div className="col-md-4">
                  <label className="form-label">Template (optional)</label>
                  <select
                    className="form-select"
                    value={formCreateTemplateKey}
                    onChange={(event) => setFormCreateTemplateKey(event.target.value)}
                  >
                    <option value="">Select template</option>
                    {safeTemplates
                      .filter((tpl) => typeof tpl.key === "string")
                      .map((tpl) => (
                        <option key={tpl.key} value={tpl.key}>
                          {tpl.name} ({tpl.key})
                        </option>
                      ))}
                  </select>
                  {!formCreateTemplateKey ? (
                    <div className="muted mt-2">
                      No template selected. Provide schema JSON to create from scratch.
                    </div>
                  ) : null}
                </div>
                {!formCreateTemplateKey ? (
                  <div className="col-md-8">
                    <label className="form-label">Schema JSON</label>
                    <textarea
                      className="form-control"
                      rows={4}
                      value={formCreateSchema}
                      onChange={(event) => setFormCreateSchema(event.target.value)}
                    />
                    <div className="muted mt-1">
                      Leave empty fields array to start with a blank form.
                    </div>
                  </div>
                ) : null}
                <div className="col-md-6">
                  <label className="form-label">Description</label>
                  <input
                    className="form-control"
                    value={formCreateDescription}
                    onChange={(event) => setFormCreateDescription(event.target.value)}
                  />
                  {formCreateDescription ? (
                    <div className="mt-2">
                      <div className="muted">Preview</div>
                      <RichText
                        text={formCreateDescription}
                        markdownEnabled={markdownEnabled}
                        mathjaxEnabled={mathjaxEnabled}
                      />
                    </div>
                  ) : null}
                </div>
                <div className="col-md-3">
                  <label className="form-label">Auth policy</label>
                  <select
                    className="form-select"
                    value={formCreateAuthPolicy}
                    onChange={(event) => setFormCreateAuthPolicy(event.target.value)}
                  >
                    <option value="optional">Optional</option>
                    <option value="required">Required</option>
                    <option value="google">Google</option>
                    <option value="github">GitHub</option>
                    <option value="either">Either</option>
                  </select>
                </div>
                <div className="col-md-3">
                  <label className="form-label">Public</label>
                  <div className="form-check mt-2">
                    <input
                      className="form-check-input"
                      type="checkbox"
                      checked={formCreatePublic}
                      onChange={(event) => setFormCreatePublic(event.target.checked)}
                      id="formCreatePublic"
                    />
                    <label className="form-check-label" htmlFor="formCreatePublic">
                      Yes
                    </label>
                  </div>
                </div>
                <div className="col-md-3">
                  <label className="form-label">Locked</label>
                  <div className="form-check mt-2">
                    <input
                      className="form-check-input"
                      type="checkbox"
                      checked={formCreateLocked}
                      onChange={(event) => setFormCreateLocked(event.target.checked)}
                      id="formCreateLocked"
                    />
                    <label className="form-check-label" htmlFor="formCreateLocked">
                      Yes
                    </label>
                  </div>
                </div>
                <div className="col-md-3">
                  <label className="form-label">Save Versions</label>
                  <div className="form-check mt-2">
                    <input
                      className="form-check-input"
                      type="checkbox"
                      checked={formCreateSaveAllVersions}
                      onChange={(event) => setFormCreateSaveAllVersions(event.target.checked)}
                      id="formCreateSaveAllVersions"
                    />
                    <label className="form-check-label" htmlFor="formCreateSaveAllVersions">
                      Yes
                    </label>
                  </div>
                </div>
                <div className="col-md-3">
                  <label className="form-label">Submission backup</label>
                  <div className="form-check mt-2">
                    <input
                      className="form-check-input"
                      type="checkbox"
                      checked={formCreateSubmissionBackupEnabled}
                      onChange={(event) => setFormCreateSubmissionBackupEnabled(event.target.checked)}
                      id="formCreateSubmissionBackupEnabled"
                    />
                    <label className="form-check-label" htmlFor="formCreateSubmissionBackupEnabled">
                      Enable routine backups
                    </label>
                  </div>
                  <div className="muted mt-1">Saves submissions to Google Drive.</div>
                  <div className="mt-2">
                    {["json", "markdown", "csv"].map((format) => {
                      const id = `formCreateSubmissionBackupFormat-${format}`;
                      return (
                        <div key={format} className="form-check form-check-inline">
                          <input
                            className="form-check-input"
                            type="checkbox"
                            id={id}
                            disabled={!formCreateSubmissionBackupEnabled}
                            checked={formCreateSubmissionBackupFormats.includes(format)}
                            onChange={(event) => {
                              const checked = event.target.checked;
                              setFormCreateSubmissionBackupFormats((prev) => {
                                const next = new Set(prev);
                                if (checked) next.add(format);
                                else next.delete(format);
                                return next.size > 0 ? Array.from(next) : ["json"];
                              });
                            }}
                          />
                          <label className="form-check-label" htmlFor={id}>
                            {format.toUpperCase()}
                          </label>
                        </div>
                      );
                    })}
                  </div>
                </div>
                <div className="col-md-4">
                  <label className="form-label">Available from</label>
                  <input
                    className="form-control"
                    type="datetime-local"
                    value={formCreateAvailableFrom}
                    onChange={(event) => setFormCreateAvailableFrom(event.target.value)}
                    disabled={formCreateLocked}
                  />
                </div>
                <div className="col-md-4">
                  <label className="form-label">Available until</label>
                  <input
                    className="form-control"
                    type="datetime-local"
                    value={formCreateAvailableUntil}
                    onChange={(event) => setFormCreateAvailableUntil(event.target.value)}
                    disabled={formCreateLocked}
                  />
                </div>
                <div className="col-md-4">
                  <label className="form-label">Availability timezone</label>
                  <TimezoneSelect
                    idPrefix="form-create-availability"
                    value={formCreateAvailabilityTimezone}
                    onChange={(nextTz) => {
                      const shifted = shiftAvailabilityValues(
                        formCreateAvailabilityTimezone,
                        nextTz,
                        formCreateAvailableFrom,
                        formCreateAvailableUntil
                      );
                      setFormCreateAvailabilityTimezone(nextTz);
                      setFormCreateAvailableFrom(shifted.from);
                      setFormCreateAvailableUntil(shifted.until);
                    }}
                    disabled={formCreateLocked}
                  />
                </div>
                <div className="col-md-4">
                  <label className="form-label">Password requirements</label>
                  <div className="form-check mt-2">
                    <input
                      className="form-check-input"
                      type="checkbox"
                      checked={formCreatePasswordRequireAccess}
                      onChange={(event) => setFormCreatePasswordRequireAccess(event.target.checked)}
                      id="formCreatePasswordRequireAccess"
                    />
                    <label className="form-check-label" htmlFor="formCreatePasswordRequireAccess">
                      Require password to access
                    </label>
                  </div>
                  <div className="form-check mt-1">
                    <input
                      className="form-check-input"
                      type="checkbox"
                      checked={formCreatePasswordRequireSubmit}
                      onChange={(event) => setFormCreatePasswordRequireSubmit(event.target.checked)}
                      id="formCreatePasswordRequireSubmit"
                    />
                    <label className="form-check-label" htmlFor="formCreatePasswordRequireSubmit">
                      Require password to submit
                    </label>
                  </div>
                  <div className="muted mt-2">
                    Password protection is independent of auth policy.
                  </div>
                  {(formCreatePasswordRequireAccess || formCreatePasswordRequireSubmit) ? (
                    <>
                      <div className="input-group mt-2">
                        <input
                          className="form-control"
                          type={formCreatePasswordVisible ? "text" : "password"}
                          placeholder="Set form password"
                          value={formCreatePassword}
                          onChange={(event) => setFormCreatePassword(event.target.value)}
                        />
                        <button
                          type="button"
                          className="btn btn-outline-secondary"
                          onClick={() => setFormCreatePasswordVisible((prev) => !prev)}
                          aria-label={formCreatePasswordVisible ? "Hide password" : "Show password"}
                        >
                          <i
                            className={`bi ${formCreatePasswordVisible ? "bi-eye-slash" : "bi-eye"}`}
                            aria-hidden="true"
                          />
                        </button>
                      </div>
                      <button
                        type="button"
                        className="btn btn-outline-secondary btn-sm mt-2"
                        onClick={() => setFormCreatePassword(generatePassword())}
                      >
                        <i className="bi bi-shuffle" aria-hidden="true" /> Generate password
                      </button>
                      <button
                        type="button"
                        className="btn btn-outline-secondary btn-sm mt-2"
                        onClick={() => {
                          if (!formCreatePassword.trim()) {
                            setFormCreateStatus("Generate a password first.");
                            return;
                          }
                          navigator.clipboard
                            .writeText(formCreatePassword.trim())
                            .then(() => {
                              setFormCreateStatus("Password copied.");
                              onNotice("Password copied.", "success");
                            })
                            .catch(() => setFormCreateStatus("Unable to copy password."));
                        }}
                      >
                        <i className="bi bi-clipboard" aria-hidden="true" /> Copy password
                      </button>
                    </>
                  ) : null}
                </div>
                <div className="col-md-3">
                  <label className="form-label">Reminders</label>
                  <div className="form-check mt-2">
                    <input
                      className="form-check-input"
                      type="checkbox"
                      checked={formCreateReminderEnabled}
                      onChange={(event) => setFormCreateReminderEnabled(event.target.checked)}
                      id="formCreateReminderEnabled"
                    />
                    <label className="form-check-label" htmlFor="formCreateReminderEnabled">
                      Enabled
                    </label>
                  </div>
                </div>
                {formCreateReminderEnabled && (
                  <div className="col-md-4">
                    <label className="form-label">Reminder Frequency</label>
                    <div className="input-group">
                      <input
                        type="number"
                        className="form-control"
                        min="1"
                        value={formCreateReminderValue}
                        onChange={(e) =>
                          setFormCreateReminderValue(Math.max(1, parseInt(e.target.value) || 1))
                        }
                      />
                      <select
                        className="form-select"
                        value={formCreateReminderUnit}
                        onChange={(event) => setFormCreateReminderUnit(event.target.value)}
                      >
                        <option value="days">Day(s)</option>
                        <option value="weeks">Week(s)</option>
                        <option value="months">Month(s)</option>
                      </select>
                    </div>
                  </div>
                )}
                {formCreateReminderEnabled && (
                  <div className="col-md-3">
                    <label className="form-label">Reminder until</label>
                    <input
                      className="form-control"
                      type="datetime-local"
                      value={formCreateReminderUntil}
                      onChange={(event) => setFormCreateReminderUntil(event.target.value)}
                    />
                  </div>
                )}
                <div className="col-md-4">
                    <label className="form-label">Discussion</label>
                    <div className="form-check mt-2">
                      <input
                        className="form-check-input"
                        type="checkbox"
                      checked={formCreateDiscussionEnabled}
                      onChange={(event) => {
                        const next = event.target.checked;
                        setFormCreateDiscussionEnabled(next);
                        if (!next) {
                          setFormCreateCommentNotifyEnabled(false);
                        }
                      }}
                        id="formCreateDiscussionEnabled"
                      />
                      <label className="form-check-label" htmlFor="formCreateDiscussionEnabled">
                        Enable discussion
                      </label>
                    </div>
                    <div className="d-flex flex-column gap-1 mt-2">
                      <div className="form-check">
                        <input
                          className="form-check-input"
                          type="checkbox"
                          checked={formCreateCommentNotifyEnabled}
                          onChange={(event) => setFormCreateCommentNotifyEnabled(event.target.checked)}
                          id="formCreateCommentNotifyEnabled"
                          disabled={!formCreateDiscussionEnabled}
                        />
                        <label className="form-check-label" htmlFor="formCreateCommentNotifyEnabled">
                          Enable comment notifications
                        </label>
                      </div>
                      <div className="form-check">
                        <input
                          className="form-check-input"
                          type="checkbox"
                          checked={formCreateDiscussionMarkdownEnabled}
                          onChange={(event) => setFormCreateDiscussionMarkdownEnabled(event.target.checked)}
                        id="formCreateDiscussionMarkdownEnabled"
                        disabled={!formCreateDiscussionEnabled}
                      />
                      <label className="form-check-label" htmlFor="formCreateDiscussionMarkdownEnabled">
                        Allow Markdown
                      </label>
                    </div>
                    <div className="form-check">
                      <input
                        className="form-check-input"
                        type="checkbox"
                        checked={formCreateDiscussionMathjaxEnabled}
                        onChange={(event) => setFormCreateDiscussionMathjaxEnabled(event.target.checked)}
                        id="formCreateDiscussionMathjaxEnabled"
                        disabled={!formCreateDiscussionEnabled}
                      />
                      <label className="form-check-label" htmlFor="formCreateDiscussionMathjaxEnabled">
                        Allow MathJax
                      </label>
                    </div>
                    <div className="form-check">
                      <input
                        className="form-check-input"
                        type="checkbox"
                        checked={formCreateDiscussionHtmlEnabled}
                        onChange={(event) => setFormCreateDiscussionHtmlEnabled(event.target.checked)}
                        id="formCreateDiscussionHtmlEnabled"
                        disabled={!formCreateDiscussionEnabled}
                      />
                      <label className="form-check-label" htmlFor="formCreateDiscussionHtmlEnabled">
                        Allow HTML
                      </label>
                    </div>
                  </div>
                </div>
                <div className="col-12">
                  {renderCanvasConfig({
                    enabled: formCreateCanvasEnabled,
                    onEnabledChange: setFormCreateCanvasEnabled,
                    courseId: formCreateCanvasCourseId,
                    onCourseIdChange: setFormCreateCanvasCourseId,
                    allowedSectionIds: formCreateCanvasAllowedSections,
                    onAllowedSectionIdsChange: setFormCreateCanvasAllowedSections,
                    fieldsPosition: formCreateCanvasPosition,
                    onFieldsPositionChange: setFormCreateCanvasPosition,
                    idPrefix: "form-create"
                  })}
                </div>
                <div className="col-12 d-flex flex-wrap gap-2 mt-2">
                  <button type="button" className="btn btn-primary" onClick={handleCreateForm}>
                    <i className="bi bi-plus-square" aria-hidden="true" /> Create form
                  </button>
                  {formCreateStatus ? <span className="muted">{formCreateStatus}</span> : null}
                </div>
              </div>
            ) : null}
            {formBuilderMode === "edit" ? (
              <div>
                <div className="row g-3">
                  <div className="col-md-4">
                    <label className="form-label">Form</label>
                    <select
                      className="form-select"
                      value={formBuilderSlug}
                      onChange={(event) => {
                        const value = event.target.value;
                        setFormBuilderSlug(value);
                        handleLoadFormSchema(value);
                      }}
                    >
                      <option value="">Select form</option>
                      {safeForms
                        .filter((form) => typeof form.slug === "string")
                        .map((form) => (
                          <option key={form.slug} value={form.slug}>
                            {form.title} ({form.slug})
                          </option>
                        ))}
                    </select>
                  </div>
                  <div className="col-md-4">
                    <label className="form-label">Slug</label>
                    <input
                      className="form-control"
                      value={formBuilderSlugEdit}
                      onChange={(event) => setFormBuilderSlugEdit(event.target.value)}
                      disabled={!formBuilderSlug}
                    />
                  </div>
                  <div className="col-md-4">
                    <label className="form-label">Description</label>
                    <input
                      className="form-control"
                      value={formBuilderDescription}
                      onChange={(event) => setFormBuilderDescription(event.target.value)}
                      disabled={!formBuilderSlug}
                    />
                    {formBuilderDescription ? (
                      <div className="mt-2">
                        <div className="muted">Preview</div>
                        <RichText
                          text={formBuilderDescription}
                          markdownEnabled={markdownEnabled}
                          mathjaxEnabled={mathjaxEnabled}
                        />
                      </div>
                    ) : null}
                  </div>
                  <div className="col-md-4">
                    <label className="form-label">Template (optional)</label>
                    <select
                      className="form-select"
                      value={formBuilderTemplateKey}
                      onChange={(event) => setFormBuilderTemplateKey(event.target.value)}
                      disabled={!formBuilderSlug}
                    >
                      <option value="">Select template</option>
                      {safeTemplates
                        .filter((tpl) => typeof tpl.key === "string")
                        .map((tpl) => (
                          <option key={tpl.key} value={tpl.key}>
                            {tpl.name} ({tpl.key})
                          </option>
                        ))}
                    </select>
                  </div>
                  <div className="col-md-4">
                    <label className="form-label">Auth policy</label>
                    <select
                      className="form-select"
                      value={formBuilderAuthPolicy}
                      onChange={(event) => setFormBuilderAuthPolicy(event.target.value)}
                      disabled={!formBuilderSlug}
                    >
                      <option value="optional">Optional</option>
                      <option value="required">Required</option>
                      <option value="google">Google</option>
                      <option value="github">GitHub</option>
                      <option value="either">Either</option>
                    </select>
                  </div>
                  <div className="col-md-2">
                    <label className="form-label">Public</label>
                    <div className="form-check mt-2">
                      <input
                        className="form-check-input"
                        type="checkbox"
                        checked={formBuilderPublic}
                        onChange={(event) => setFormBuilderPublic(event.target.checked)}
                        disabled={!formBuilderSlug}
                        id="formBuilderPublic"
                      />
                      <label className="form-check-label" htmlFor="formBuilderPublic">
                        Yes
                      </label>
                    </div>
                  </div>
                  <div className="col-md-2">
                    <label className="form-label">Locked</label>
                    <div className="form-check mt-2">
                      <input
                        className="form-check-input"
                        type="checkbox"
                        checked={formBuilderLocked}
                        onChange={(event) => setFormBuilderLocked(event.target.checked)}
                        disabled={!formBuilderSlug}
                        id="formBuilderLocked"
                      />
                      <label className="form-check-label" htmlFor="formBuilderLocked">
                        Yes
                      </label>
                    </div>
                  </div>
                  <div className="col-md-2">
                    <label className="form-label">Save Versions</label>
                    <div className="form-check mt-2">
                      <input
                        className="form-check-input"
                        type="checkbox"
                        checked={formBuilderSaveAllVersions}
                        onChange={(event) => setFormBuilderSaveAllVersions(event.target.checked)}
                        disabled={!formBuilderSlug}
                        id="formBuilderSaveAllVersions"
                      />
                      <label className="form-check-label" htmlFor="formBuilderSaveAllVersions">
                        Yes
                      </label>
                    </div>
                  </div>
                  <div className="col-md-3">
                    <label className="form-label">Submission backup</label>
                    <div className="form-check mt-2">
                      <input
                        className="form-check-input"
                        type="checkbox"
                        checked={formBuilderSubmissionBackupEnabled}
                        onChange={(event) => setFormBuilderSubmissionBackupEnabled(event.target.checked)}
                        disabled={!formBuilderSlug}
                        id="formBuilderSubmissionBackupEnabled"
                      />
                      <label className="form-check-label" htmlFor="formBuilderSubmissionBackupEnabled">
                        Enable routine backups
                      </label>
                    </div>
                    <div className="muted mt-1">Saves submissions to Google Drive.</div>
                    <div className="mt-2">
                      {["json", "markdown", "csv"].map((format) => {
                        const id = `formBuilderSubmissionBackupFormat-${format}`;
                        return (
                          <div key={format} className="form-check form-check-inline">
                            <input
                              className="form-check-input"
                              type="checkbox"
                              id={id}
                              disabled={!formBuilderSlug || !formBuilderSubmissionBackupEnabled}
                              checked={formBuilderSubmissionBackupFormats.includes(format)}
                              onChange={(event) => {
                                const checked = event.target.checked;
                                setFormBuilderSubmissionBackupFormats((prev) => {
                                  const next = new Set(prev);
                                  if (checked) next.add(format);
                                  else next.delete(format);
                                  return next.size > 0 ? Array.from(next) : ["json"];
                                });
                              }}
                            />
                            <label className="form-check-label" htmlFor={id}>
                              {format.toUpperCase()}
                            </label>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                  <div className="col-md-4">
                    <label className="form-label">Available from</label>
                    <input
                      className="form-control"
                      type="datetime-local"
                      value={formBuilderAvailableFrom}
                      onChange={(event) => setFormBuilderAvailableFrom(event.target.value)}
                      disabled={!formBuilderSlug || formBuilderLocked}
                    />
                  </div>
                  <div className="col-md-4">
                    <label className="form-label">Available until</label>
                    <input
                      className="form-control"
                      type="datetime-local"
                      value={formBuilderAvailableUntil}
                      onChange={(event) => setFormBuilderAvailableUntil(event.target.value)}
                      disabled={!formBuilderSlug || formBuilderLocked}
                    />
                  </div>
                  <div className="col-md-4">
                    <label className="form-label">Availability timezone</label>
                    <TimezoneSelect
                      idPrefix="form-availability"
                      value={formBuilderAvailabilityTimezone}
                      onChange={(nextTz) => {
                        const shifted = shiftAvailabilityValues(
                          formBuilderAvailabilityTimezone,
                          nextTz,
                          formBuilderAvailableFrom,
                          formBuilderAvailableUntil
                        );
                        setFormBuilderAvailabilityTimezone(nextTz);
                        setFormBuilderAvailableFrom(shifted.from);
                        setFormBuilderAvailableUntil(shifted.until);
                      }}
                      disabled={!formBuilderSlug || formBuilderLocked}
                    />
                  </div>
                  <div className="col-md-2">
                    <label className="form-label">Reminders</label>
                    <div className="form-check mt-2">
                      <input
                        className="form-check-input"
                        type="checkbox"
                        checked={formBuilderReminderEnabled}
                        onChange={(event) => setFormBuilderReminderEnabled(event.target.checked)}
                        disabled={!formBuilderSlug}
                        id="formBuilderReminderEnabled"
                      />
                      <label className="form-check-label" htmlFor="formBuilderReminderEnabled">
                        Enabled
                      </label>
                    </div>
                  </div>
                  {formBuilderReminderEnabled && (
                    <div className="col-md-4">
                      <label className="form-label">Reminder Frequency</label>
                      <div className="input-group">
                        <input
                          type="number"
                          className="form-control"
                          min="1"
                          value={formBuilderReminderValue}
                          onChange={(e) => setFormBuilderReminderValue(Math.max(1, parseInt(e.target.value) || 1))}
                          disabled={!formBuilderSlug}
                        />
                        <select
                          className="form-select"
                          value={formBuilderReminderUnit}
                          onChange={(event) => setFormBuilderReminderUnit(event.target.value)}
                          disabled={!formBuilderSlug}
                        >
                          <option value="days">Day(s)</option>
                          <option value="weeks">Week(s)</option>
                          <option value="months">Month(s)</option>
                        </select>
                      </div>
                    </div>
                  )}
                  {formBuilderReminderEnabled && (
                    <div className="col-md-3">
                      <label className="form-label">Reminder until</label>
                      <input
                        className="form-control"
                        type="datetime-local"
                        value={formBuilderReminderUntil}
                        onChange={(event) => setFormBuilderReminderUntil(event.target.value)}
                        disabled={!formBuilderSlug}
                      />
                      <div className="muted mt-1" style={{ fontSize: "0.8rem" }}>
                        No reminders sent after this date.
                      </div>
                    </div>
                  )}
                  <div className="col-md-4">
                    <label className="form-label">Discussion</label>
                    <div className="form-check mt-2">
                      <input
                        className="form-check-input"
                        type="checkbox"
                      checked={formBuilderDiscussionEnabled}
                      onChange={(event) => {
                        const next = event.target.checked;
                        setFormBuilderDiscussionEnabled(next);
                        if (!next) {
                          setFormBuilderCommentNotifyEnabled(false);
                        }
                      }}
                        disabled={!formBuilderSlug}
                        id="formBuilderDiscussionEnabled"
                      />
                      <label className="form-check-label" htmlFor="formBuilderDiscussionEnabled">
                        Enable discussion
                      </label>
                    </div>
                    <div className="d-flex flex-column gap-1 mt-2">
                      <div className="form-check">
                        <input
                          className="form-check-input"
                          type="checkbox"
                          checked={formBuilderCommentNotifyEnabled}
                          onChange={(event) => setFormBuilderCommentNotifyEnabled(event.target.checked)}
                          id="formBuilderCommentNotifyEnabled"
                          disabled={!formBuilderSlug || !formBuilderDiscussionEnabled}
                        />
                        <label className="form-check-label" htmlFor="formBuilderCommentNotifyEnabled">
                          Enable comment notifications
                        </label>
                      </div>
                      <div className="form-check">
                        <input
                          className="form-check-input"
                          type="checkbox"
                          checked={formBuilderDiscussionMarkdownEnabled}
                          onChange={(event) => setFormBuilderDiscussionMarkdownEnabled(event.target.checked)}
                          id="formBuilderDiscussionMarkdownEnabled"
                          disabled={!formBuilderSlug || !formBuilderDiscussionEnabled}
                        />
                        <label className="form-check-label" htmlFor="formBuilderDiscussionMarkdownEnabled">
                          Allow Markdown
                        </label>
                      </div>
                      <div className="form-check">
                        <input
                          className="form-check-input"
                          type="checkbox"
                          checked={formBuilderDiscussionMathjaxEnabled}
                          onChange={(event) => setFormBuilderDiscussionMathjaxEnabled(event.target.checked)}
                          id="formBuilderDiscussionMathjaxEnabled"
                          disabled={!formBuilderSlug || !formBuilderDiscussionEnabled}
                        />
                        <label className="form-check-label" htmlFor="formBuilderDiscussionMathjaxEnabled">
                          Allow MathJax
                        </label>
                      </div>
                      <div className="form-check">
                        <input
                          className="form-check-input"
                          type="checkbox"
                          checked={formBuilderDiscussionHtmlEnabled}
                          onChange={(event) => setFormBuilderDiscussionHtmlEnabled(event.target.checked)}
                          id="formBuilderDiscussionHtmlEnabled"
                          disabled={!formBuilderSlug || !formBuilderDiscussionEnabled}
                        />
                        <label className="form-check-label" htmlFor="formBuilderDiscussionHtmlEnabled">
                          Allow HTML
                        </label>
                      </div>
                    </div>
                  </div>
                  <div className="col-md-4">
                    <label className="form-label">Password requirements</label>
                    <div className="form-check mt-2">
                      <input
                        className="form-check-input"
                        type="checkbox"
                        checked={formBuilderPasswordRequireAccess}
                        onChange={(event) => setFormBuilderPasswordRequireAccess(event.target.checked)}
                        disabled={!formBuilderSlug}
                        id="formBuilderPasswordRequireAccess"
                      />
                      <label className="form-check-label" htmlFor="formBuilderPasswordRequireAccess">
                        Require password to access
                      </label>
                    </div>
                    <div className="form-check mt-1">
                      <input
                        className="form-check-input"
                        type="checkbox"
                        checked={formBuilderPasswordRequireSubmit}
                        onChange={(event) => setFormBuilderPasswordRequireSubmit(event.target.checked)}
                        disabled={!formBuilderSlug}
                        id="formBuilderPasswordRequireSubmit"
                      />
                      <label className="form-check-label" htmlFor="formBuilderPasswordRequireSubmit">
                        Require password to submit
                      </label>
                    </div>
                    <div className="muted mt-2">
                      Password protection is independent of auth policy.
                    </div>
                    {formBuilderPasswordRequired ? (
                      <>
                        <div className="input-group mt-2">
                          <input
                            className="form-control"
                            type={formBuilderPasswordVisible ? "text" : "password"}
                            placeholder="Set new password"
                            value={formBuilderPassword}
                            onChange={(event) => setFormBuilderPassword(event.target.value)}
                            disabled={!formBuilderSlug}
                          />
                          <button
                            type="button"
                            className="btn btn-outline-secondary"
                            onClick={() => setFormBuilderPasswordVisible((prev) => !prev)}
                            aria-label={formBuilderPasswordVisible ? "Hide password" : "Show password"}
                            disabled={!formBuilderSlug}
                          >
                            <i
                              className={`bi ${formBuilderPasswordVisible ? "bi-eye-slash" : "bi-eye"}`}
                              aria-hidden="true"
                            />
                          </button>
                        </div>
                        <button
                          type="button"
                          className="btn btn-outline-secondary btn-sm mt-2"
                          onClick={() => setFormBuilderPassword(generatePassword())}
                          disabled={!formBuilderSlug}
                        >
                          <i className="bi bi-shuffle" aria-hidden="true" /> Generate password
                        </button>
                        <button
                          type="button"
                          className="btn btn-outline-secondary btn-sm mt-2"
                          onClick={() => {
                            if (!formBuilderPassword.trim()) {
                              setFormBuilderStatus("Generate a password first.");
                              return;
                            }
                            navigator.clipboard
                              .writeText(formBuilderPassword.trim())
                              .then(() => {
                                setFormBuilderStatus("Password copied.");
                                onNotice("Password copied.", "success");
                              })
                              .catch(() => setFormBuilderStatus("Unable to copy password."));
                          }}
                          disabled={!formBuilderSlug}
                        >
                          <i className="bi bi-clipboard" aria-hidden="true" /> Copy password
                        </button>
                      </>
                    ) : null}
                  </div>
                  <div className="col-12">
                    {renderCanvasConfig({
                      enabled: formBuilderCanvasEnabled,
                      onEnabledChange: setFormBuilderCanvasEnabled,
                      courseId: formBuilderCanvasCourseId,
                      onCourseIdChange: setFormBuilderCanvasCourseId,
                      allowedSectionIds: formBuilderCanvasAllowedSections,
                      onAllowedSectionIdsChange: setFormBuilderCanvasAllowedSections,
                      fieldsPosition: formBuilderCanvasPosition,
                      onFieldsPositionChange: setFormBuilderCanvasPosition,
                      idPrefix: "form-edit"
                    })}
                  </div>
                  <div className="col-12">
                    <label className="form-label">Schema JSON</label>
                    <textarea
                      className="form-control"
                      rows={6}
                      value={formBuilderSchema}
                      onChange={(event) => setFormBuilderSchema(event.target.value)}
                    />
                    <div className="muted mt-1">
                      Changes here override the form schema. File rules are mirrored automatically.
                    </div>
                    {formRulesError ? (
                      <div className="alert alert-warning mt-2 py-2">{formRulesError}</div>
                    ) : null}
                    {formVisibilityError ? (
                      <div className="alert alert-warning mt-2 py-2">{formVisibilityError}</div>
                    ) : null}
                  </div>
                  <div className="col-12">
                    <FieldBuilderPanel
                      idPrefix="form"
                      title="Form fields"
                      builderType={formFieldType}
                      builderCustomType={formFieldCustomType}
                      builderId={formFieldId}
                      builderLabel={formFieldLabel}
                      builderRequired={formFieldRequired}
                      builderDescription={formFieldDescription}
                      builderPlaceholder={formFieldPlaceholder}
                      builderOptions={formFieldOptions}
                      builderMultiple={formFieldMultiple}
                      builderTextareaMarkdownEnabled={formFieldTextareaMarkdownEnabled}
                      builderTextareaMathjaxEnabled={formFieldTextareaMathjaxEnabled}
                      builderTextareaRows={formFieldTextareaRows}
                      builderEmailDomain={formEmailDomain}
                      builderAutofillFromLogin={formAutofillFromLogin}
                      builderDateTimezone={formDateTimezone}
                      builderDateMode={formDateMode}
                      builderDateShowTimezone={formDateShowTimezone}
                      builderVisibilityEnabled={formFieldVisibilityEnabled}
                      builderVisibilityOperator={formFieldVisibilityOperator}
                      builderVisibilityConditions={formFieldVisibilityConditions}
                      visibilityControllers={formVisibilityControllers}
                      markdownEnabled={markdownEnabled}
                      mathjaxEnabled={mathjaxEnabled}
                      onTypeChange={setFormFieldType}
                      onCustomTypeChange={setFormFieldCustomType}
                      onIdChange={setFormFieldId}
                      onLabelChange={setFormFieldLabel}
                      onRequiredChange={setFormFieldRequired}
                      onDescriptionChange={setFormFieldDescription}
                      onPlaceholderChange={setFormFieldPlaceholder}
                      onOptionsChange={setFormFieldOptions}
                      onMultipleChange={setFormFieldMultiple}
                      onTextareaMarkdownEnabledChange={setFormFieldTextareaMarkdownEnabled}
                      onTextareaMathjaxEnabledChange={setFormFieldTextareaMathjaxEnabled}
                      onTextareaRowsChange={setFormFieldTextareaRows}
                      onEmailDomainChange={setFormEmailDomain}
                      onAutofillFromLoginChange={setFormAutofillFromLogin}
                      onDateTimezoneChange={setFormDateTimezone}
                      onDateModeChange={setFormDateMode}
                      onDateShowTimezoneChange={setFormDateShowTimezone}
                      onVisibilityEnabledChange={setFormFieldVisibilityEnabled}
                      onVisibilityOperatorChange={setFormFieldVisibilityOperator}
                      onVisibilityConditionsChange={setFormFieldVisibilityConditions}
                      onAddField={handleAddFormField}
                      fields={formTextFields}
                      onRemoveField={handleRemoveFormField}
                      onEditField={handleSelectFormField}
                      onMoveField={handleMoveFormField}
                      onReorderField={handleReorderFormField}
                    />
                    {formTextFields.length > 0 ? (
                      <div className="panel panel--compact mt-3">
                        <div className="panel-header">
                          <h4 className="mb-0">Edit existing field</h4>
                        </div>
                        <div className="row g-3">
                          <div className="col-md-4">
                            <label className="form-label">Select field</label>
                            <select
                              className="form-select"
                              value={formFieldEditId}
                              onChange={(event) => {
                                const value = event.target.value;
                                const target = formSchemaFields.find(
                                  (field) => field.type !== "file" && field.id === value
                                ) as Record<string, unknown> | undefined;
                                handleSelectFormField(value, target || null);
                              }}
                            >
                              <option value="">Choose field</option>
                              {formTextFields.map((field) => (
                                <option key={String(field.id)} value={String(field.id)}>
                                  {String(field.label || field.id)}
                                </option>
                              ))}
                            </select>
                          </div>
                          <div className="col-md-8 d-flex align-items-end">
                            <button
                              type="button"
                              className="btn btn-outline-secondary"
                              disabled={!formFieldEditId}
                              onClick={handleUpdateFormField}
                            >
                              <i className="bi bi-pencil-square" aria-hidden="true" /> Update field
                            </button>
                          </div>
                        </div>
                      </div>
                    ) : null}
                  </div>
                  <div className="col-12">
                    <FileFieldBuilderPanel
                      idPrefix="form-file"
                      title="Form file fields"
                      fieldId={formFileFieldId}
                      fieldLabel={formFileFieldLabel}
                      fieldRequired={formFileFieldRequired}
                      fieldExtensions={formFileFieldExtensions}
                      fieldMaxSizeMb={formFileFieldMaxSizeMb}
                      fieldMaxFiles={formFileFieldMaxFiles}
                      onIdChange={setFormFileFieldId}
                      onLabelChange={setFormFileFieldLabel}
                      onRequiredChange={setFormFileFieldRequired}
                      onExtensionsChange={setFormFileFieldExtensions}
                      onMaxSizeChange={setFormFileFieldMaxSizeMb}
                      onMaxFilesChange={setFormFileFieldMaxFiles}
                      onAdd={handleAddFormFileField}
                    />
                    {formFileFields.length > 0 ? (
                      <div className="panel panel--compact mt-3">
                        <div className="panel-header">
                          <h4 className="mb-0">Edit existing file field</h4>
                        </div>
                        <div className="row g-3">
                          <div className="col-md-4">
                            <label className="form-label">Select file field</label>
                            <select
                              className="form-select"
                              value={formFileEditId}
                              onChange={(event) => {
                                const value = event.target.value;
                                const target = formFileFields.find(
                                  (field) => field.type === "file" && field.id === value
                                ) as Record<string, unknown> | undefined;
                                handleSelectFormFileField(value, target || null);
                              }}
                            >
                              <option value="">Choose field</option>
                              {formFileFields.map((field) => (
                                <option key={String(field.id)} value={String(field.id)}>
                                  {String(field.label || field.id)}
                                </option>
                              ))}
                            </select>
                          </div>
                          <div className="col-md-8 d-flex align-items-end">
                            <button
                              type="button"
                              className="btn btn-outline-secondary"
                              disabled={!formFileEditId}
                              onClick={handleUpdateFormFileField}
                            >
                              <i className="bi bi-sliders" aria-hidden="true" /> Update file field rules
                            </button>
                          </div>
                        </div>
                        <div className="table-responsive mt-3">
                          <table className="table table-sm">
                            <thead>
                              <tr>
                                <th style={{ width: "2.5rem" }}></th>
                                <th>Id</th>
                                <th>Label</th>
                                <th>Extensions</th>
                                <th>Max size</th>
                                <th>Max files</th>
                                <th></th>
                              </tr>
                            </thead>
                            <tbody>
                              {formFileFields.map((field, index) => {
                                const rules = (field as any).rules || {};
                                const extensions = Array.isArray(rules.allowedExtensions)
                                  ? rules.allowedExtensions
                                  : Array.isArray(rules.extensions)
                                    ? rules.extensions
                                    : [];
                                const maxBytes =
                                  typeof rules.maxFileSizeBytes === "number"
                                    ? rules.maxFileSizeBytes
                                    : typeof rules.maxSizeBytes === "number"
                                      ? rules.maxSizeBytes
                                      : 0;
                                const maxFiles =
                                  typeof rules.maxFiles === "number" ? rules.maxFiles : 0;
                                return (
                                  <tr
                                    key={String(field.id)}
                                    className={
                                      formFileDragOverId === String(field.id) ? "table-active" : undefined
                                    }
                                    onDragOver={(event) => {
                                      event.preventDefault();
                                      event.dataTransfer.dropEffect = "move";
                                    }}
                                    onDragEnter={() => {
                                      setFormFileDragOverId(String(field.id));
                                    }}
                                    onDragLeave={() => {
                                      setFormFileDragOverId((prev) =>
                                        prev === String(field.id) ? null : prev
                                      );
                                    }}
                                    onDrop={(event) => {
                                      event.preventDefault();
                                      const draggedId = event.dataTransfer.getData("text/plain");
                                      if (!draggedId) return;
                                      handleReorderFormField(draggedId, index);
                                      setFormFileDragOverId(null);
                                    }}
                                  >
                                    <td>
                                      <span
                                        role="button"
                                        title="Drag to reorder"
                                        draggable
                                        onDragStart={(event) => {
                                          event.dataTransfer.setData("text/plain", String(field.id));
                                          event.dataTransfer.effectAllowed = "move";
                                        }}
                                        style={{ cursor: "grab" }}
                                      >
                                        <i className="bi bi-grip-vertical" aria-hidden="true" />
                                      </span>
                                    </td>
                                    <td>{String(field.id)}</td>
                                    <td>{String(field.label || "")}</td>
                                    <td>{extensions.length > 0 ? extensions.join(", ") : "any"}</td>
                                    <td>{maxBytes ? formatSize(maxBytes) : "default"}</td>
                                    <td>{maxFiles || "default"}</td>
                                    <td>
                                      <div className="btn-group btn-group-sm me-2" role="group">
                                        <button
                                          type="button"
                                          className="btn btn-outline-secondary"
                                          onClick={() => handleMoveFormField(String(field.id), "up")}
                                          disabled={!field.id || index === 0}
                                        >
                                          <i className="bi bi-arrow-up" aria-hidden="true" />
                                        </button>
                                        <button
                                          type="button"
                                          className="btn btn-outline-secondary"
                                          onClick={() => handleMoveFormField(String(field.id), "down")}
                                          disabled={!field.id || index === formFileFields.length - 1}
                                        >
                                          <i className="bi bi-arrow-down" aria-hidden="true" />
                                        </button>
                                      </div>
                                      <button
                                        type="button"
                                        className="btn btn-outline-secondary btn-sm"
                                        onClick={() =>
                                          handleSelectFormFileField(String(field.id), field as Record<string, unknown>)
                                        }
                                      >
                                        <i className="bi bi-pencil" aria-hidden="true" /> Edit
                                      </button>
                                      <button
                                        type="button"
                                        className="btn btn-outline-danger btn-sm ms-2"
                                        onClick={() => handleRemoveFormField(String(field.id))}
                                      >
                                        <i className="bi bi-trash" aria-hidden="true" /> Remove
                                      </button>
                                    </td>
                                  </tr>
                                );
                              })}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    ) : null}
                  </div>
                </div>
                <div className="d-flex flex-wrap gap-2 mt-3">
                  <button
                    type="button"
                    className="btn btn-outline-secondary"
                    onClick={handleUpdateFormSettings}
                    disabled={!formBuilderSlug}
                  >
                    <i className="bi bi-sliders" aria-hidden="true" /> Update form settings
                  </button>
                  <button
                    type="button"
                    className="btn btn-outline-secondary"
                    onClick={handleDuplicateForm}
                    disabled={!formBuilderSlug}
                  >
                    <i className="bi bi-files" aria-hidden="true" /> Duplicate form
                  </button>
                  <button
                    type="button"
                    className="btn btn-outline-primary"
                    onClick={handleCopyFormLink}
                    disabled={!formBuilderSlug}
                  >
                    <i className="bi bi-link-45deg" aria-hidden="true" /> Copy form link
                  </button>
                  {formBuilderTemplateKey.trim() ? (
                    <button
                      type="button"
                      className="btn btn-outline-primary"
                      onClick={handleRefreshFormFromTemplate}
                      disabled={!formBuilderSlug}
                    >
                      <i className="bi bi-arrow-repeat" aria-hidden="true" /> Refresh from template
                    </button>
                  ) : null}
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={handleUpdateFormSchema}
                    disabled={!formBuilderSlug}
                  >
                    <i className="bi bi-save" aria-hidden="true" /> Save form schema
                  </button>
                  {formBuilderStatus ? <span className="muted">{formBuilderStatus}</span> : null}
                </div>
              </div>
            ) : null}
          </div>
        </div>
        <div>
          <h3>Template editor</h3>
          <div className="panel panel--compact mb-3">
            <div className="panel-header">
              <h4 className="mb-0">Create template from form</h4>
            </div>
            <div className="d-flex flex-wrap gap-2 align-items-center">
              <select
                className="form-select form-select-sm w-auto"
                value={templateFromFormSlug}
                onChange={(event) => setTemplateFromFormSlug(event.target.value)}
              >
                <option value="">Select a form</option>
                {safeForms
                  .filter((form) => form && typeof form.slug === "string")
                  .map((form) => (
                    <option key={form.slug} value={form.slug}>
                      {form.title || form.slug}
                    </option>
                  ))}
              </select>
              <button
                type="button"
                className="btn btn-outline-secondary btn-sm"
                disabled={!templateFromFormSlug}
                onClick={async () => {
                  if (!templateFromFormSlug) {
                    setTemplateFromFormStatus("Select a form to create a template.");
                    return;
                  }
                  setTemplateFromFormStatus(null);
                  const ok = await handleCreateTemplateFromForm(templateFromFormSlug);
                  if (ok) {
                    await loadBuilder();
                    setTemplateFromFormStatus("Template created from form.");
                  } else {
                    setTemplateFromFormStatus("Unable to create template from form.");
                  }
                }}
              >
                <i className="bi bi-box-arrow-right" aria-hidden="true" /> Create template
              </button>
              {templateFromFormStatus ? (
                <span className="muted">{templateFromFormStatus}</span>
              ) : null}
            </div>
          </div>
          <div className="panel panel--compact">
            <div className="d-flex flex-wrap gap-2 mb-3">
              <div className="btn-group" role="group">
                <button
                  type="button"
                  className={`btn ${templateBuilderMode === "create" ? "btn-primary" : "btn-outline-primary"}`}
                  onClick={() => {
                    setTemplateBuilderMode("create");
                    setTemplateEditorKey("");
                    setTemplateEditorOriginalKey("");
                    setTemplateEditorName("");
                    setTemplateEditorSchema("");
                    setTemplateEditorStatus(null);
                  }}
                >
                  <i className="bi bi-plus-circle" aria-hidden="true" /> New template
                </button>
                <button
                  type="button"
                  className={`btn ${templateBuilderMode === "edit" ? "btn-primary" : "btn-outline-primary"}`}
                  onClick={() => {
                    setTemplateBuilderMode("edit");
                  }}
                >
                  <i className="bi bi-pencil-square" aria-hidden="true" /> Edit template
                </button>
              </div>
            </div>
            <div className="row g-3">
              {templateBuilderMode === "edit" ? (
                <div className="col-md-4">
                  <label className="form-label">Template</label>
                  <select
                    className="form-select"
                    value={templateEditorKey}
                    onChange={(event) => {
                      setTemplateEditorKey(event.target.value);
                      handleLoadTemplate(event.target.value);
                    }}
                  >
                    <option value="">Select template</option>
                    {safeTemplates
                      .filter((tpl) => typeof tpl.key === "string")
                      .map((tpl) => (
                        <option key={tpl.key} value={tpl.key}>
                          {tpl.name} ({tpl.key})
                        </option>
                      ))}
                  </select>
                </div>
              ) : null}
              <div className="col-md-4">
                <label className="form-label">Key</label>
                <input
                  className="form-control"
                  value={templateEditorKey}
                  onChange={(event) => setTemplateEditorKey(event.target.value)}
                />
              </div>
              <div className="col-md-4">
                <label className="form-label">Name</label>
                <input
                  className="form-control"
                  value={templateEditorName}
                  onChange={(event) => setTemplateEditorName(event.target.value)}
                />
                {templateEditorName ? (
                  <div className="mt-2">
                    <div className="muted">Preview</div>
                    <RichText
                      text={templateEditorName}
                      markdownEnabled={markdownEnabled}
                      mathjaxEnabled={mathjaxEnabled}
                      inline
                    />
                  </div>
                ) : null}
              </div>
              <div className="col-12">
                <label className="form-label">Schema JSON</label>
                <textarea
                  className="form-control"
                  rows={6}
                  value={templateEditorSchema}
                  onChange={(event) => setTemplateEditorSchema(event.target.value)}
                />
                <div className="muted mt-1">
                  File field rules example:
                  <code className="d-block mt-1">
                    {`{"id":"resume","type":"file","label":"Resume","rules":{"allowedExtensions":["pdf","png"],"maxFileSizeBytes":10485760,"maxFiles":2}}`}
                  </code>
                </div>
                {templateRulesError ? (
                  <div className="alert alert-warning mt-2 py-2">{templateRulesError}</div>
                ) : null}
                {templateVisibilityError ? (
                  <div className="alert alert-warning mt-2 py-2">{templateVisibilityError}</div>
                ) : null}
              </div>
              <div className="col-12">
                <FieldBuilderPanel
                  idPrefix="template"
                  title="Field builder"
                  builderType={builderType}
                  builderCustomType={builderCustomType}
                  builderId={builderId}
                  builderLabel={builderLabel}
                  builderRequired={builderRequired}
                  builderDescription={builderDescription}
                  builderPlaceholder={builderPlaceholder}
                  builderOptions={builderOptions}
                  builderMultiple={builderMultiple}
                  builderTextareaMarkdownEnabled={builderTextareaMarkdownEnabled}
                  builderTextareaMathjaxEnabled={builderTextareaMathjaxEnabled}
                  builderTextareaRows={builderTextareaRows}
                  builderEmailDomain={builderEmailDomain}
                  builderAutofillFromLogin={builderAutofillFromLogin}
                  builderDateTimezone={builderDateTimezone}
                  builderDateMode={builderDateMode}
                  builderDateShowTimezone={builderDateShowTimezone}
                  builderVisibilityEnabled={builderVisibilityEnabled}
                  builderVisibilityOperator={builderVisibilityOperator}
                  builderVisibilityConditions={builderVisibilityConditions}
                  visibilityControllers={templateVisibilityControllers}
                  markdownEnabled={markdownEnabled}
                  mathjaxEnabled={mathjaxEnabled}
                  onTypeChange={setBuilderType}
                  onCustomTypeChange={setBuilderCustomType}
                  onIdChange={setBuilderId}
                  onLabelChange={setBuilderLabel}
                  onRequiredChange={setBuilderRequired}
                  onDescriptionChange={setBuilderDescription}
                  onPlaceholderChange={setBuilderPlaceholder}
                  onOptionsChange={setBuilderOptions}
                  onMultipleChange={setBuilderMultiple}
                  onTextareaMarkdownEnabledChange={setBuilderTextareaMarkdownEnabled}
                  onTextareaMathjaxEnabledChange={setBuilderTextareaMathjaxEnabled}
                  onTextareaRowsChange={setBuilderTextareaRows}
                  onEmailDomainChange={setBuilderEmailDomain}
                  onAutofillFromLoginChange={setBuilderAutofillFromLogin}
                  onDateTimezoneChange={setBuilderDateTimezone}
                  onDateModeChange={setBuilderDateMode}
                  onDateShowTimezoneChange={setBuilderDateShowTimezone}
                  onVisibilityEnabledChange={setBuilderVisibilityEnabled}
                  onVisibilityOperatorChange={setBuilderVisibilityOperator}
                  onVisibilityConditionsChange={setBuilderVisibilityConditions}
                  onAddField={handleAddField}
                  fields={templateTextFields}
                  onRemoveField={handleRemoveField}
                  onEditField={handleSelectTemplateField}
                  onMoveField={handleMoveTemplateField}
                  onReorderField={handleReorderTemplateField}
                />
                {templateTextFields.length > 0 ? (
                  <div className="panel panel--compact mt-3">
                    <div className="panel-header">
                      <h4 className="mb-0">Edit existing field</h4>
                    </div>
                    <div className="row g-3">
                      <div className="col-md-4">
                        <label className="form-label">Select field</label>
                        <select
                          className="form-select"
                          value={templateFieldEditId}
                          onChange={(event) => {
                            const value = event.target.value;
                            const target = schemaFields.find(
                              (field) => field.type !== "file" && field.id === value
                            ) as Record<string, unknown> | undefined;
                            handleSelectTemplateField(value, target || null);
                          }}
                        >
                          <option value="">Choose field</option>
                          {templateTextFields.map((field) => (
                            <option key={String(field.id)} value={String(field.id)}>
                              {String(field.label || field.id)}
                            </option>
                          ))}
                        </select>
                      </div>
                      <div className="col-md-8 d-flex align-items-end">
                        <button
                          type="button"
                          className="btn btn-outline-secondary"
                          disabled={!templateFieldEditId}
                          onClick={handleUpdateTemplateField}
                        >
                          <i className="bi bi-pencil-square" aria-hidden="true" /> Update field
                        </button>
                      </div>
                    </div>
                  </div>
                ) : null}
              </div>
              <div className="col-12">
                <FileFieldBuilderPanel
                  idPrefix="template-file"
                  title="Add file field"
                  fieldId={fileFieldId}
                  fieldLabel={fileFieldLabel}
                  fieldRequired={fileFieldRequired}
                  fieldExtensions={fileFieldExtensions}
                  fieldMaxSizeMb={fileFieldMaxSizeMb}
                  fieldMaxFiles={fileFieldMaxFiles}
                  onIdChange={setFileFieldId}
                  onLabelChange={setFileFieldLabel}
                  onRequiredChange={setFileFieldRequired}
                  onExtensionsChange={setFileFieldExtensions}
                  onMaxSizeChange={setFileFieldMaxSizeMb}
                  onMaxFilesChange={setFileFieldMaxFiles}
                  onAdd={handleAddFileField}
                />
                {templateFileFields.length > 0 ? (
                  <div className="panel panel--compact mt-3">
                    <div className="panel-header">
                      <h4 className="mb-0">Edit existing file field</h4>
                    </div>
                    <div className="row g-3">
                      <div className="col-md-4">
                        <label className="form-label">Select file field</label>
                        <select
                          className="form-select"
                          value={templateFileEditId}
                          onChange={(event) => {
                            const value = event.target.value;
                            const target = templateFileFields.find(
                              (field) => field.type === "file" && field.id === value
                            ) as Record<string, unknown> | undefined;
                            handleSelectTemplateFileField(value, target || null);
                          }}
                        >
                          <option value="">Choose field</option>
                          {templateFileFields.map((field) => (
                            <option key={String(field.id)} value={String(field.id)}>
                              {String(field.label || field.id)}
                            </option>
                          ))}
                        </select>
                      </div>
                      <div className="col-md-8 d-flex align-items-end">
                        <button
                          type="button"
                          className="btn btn-outline-secondary"
                          disabled={!templateFileEditId}
                          onClick={handleUpdateTemplateFileField}
                        >
                          <i className="bi bi-sliders" aria-hidden="true" /> Update file field rules
                        </button>
                      </div>
                    </div>
                    <div className="table-responsive mt-3">
                      <table className="table table-sm">
                        <thead>
                          <tr>
                            <th style={{ width: "2.5rem" }}></th>
                            <th>Id</th>
                            <th>Label</th>
                            <th>Extensions</th>
                            <th>Max size</th>
                            <th>Max files</th>
                            <th></th>
                          </tr>
                        </thead>
                        <tbody>
                          {templateFileFields.map((field, index) => {
                            const rules = (field as any).rules || {};
                            const extensions = Array.isArray(rules.allowedExtensions)
                              ? rules.allowedExtensions
                              : Array.isArray(rules.extensions)
                                ? rules.extensions
                                : [];
                            const maxBytes =
                              typeof rules.maxFileSizeBytes === "number"
                                ? rules.maxFileSizeBytes
                                : typeof rules.maxSizeBytes === "number"
                                  ? rules.maxSizeBytes
                                  : 0;
                            const maxFiles =
                              typeof rules.maxFiles === "number" ? rules.maxFiles : 0;
                            return (
                              <tr
                                key={String(field.id)}
                                className={
                                  templateFileDragOverId === String(field.id) ? "table-active" : undefined
                                }
                                onDragOver={(event) => {
                                  event.preventDefault();
                                  event.dataTransfer.dropEffect = "move";
                                }}
                                onDragEnter={() => {
                                  setTemplateFileDragOverId(String(field.id));
                                }}
                                onDragLeave={() => {
                                  setTemplateFileDragOverId((prev) =>
                                    prev === String(field.id) ? null : prev
                                  );
                                }}
                                onDrop={(event) => {
                                  event.preventDefault();
                                  const draggedId = event.dataTransfer.getData("text/plain");
                                  if (!draggedId) return;
                                  handleReorderTemplateField(draggedId, index);
                                  setTemplateFileDragOverId(null);
                                }}
                              >
                                <td>
                                  <span
                                    role="button"
                                    title="Drag to reorder"
                                    draggable
                                    onDragStart={(event) => {
                                      event.dataTransfer.setData("text/plain", String(field.id));
                                      event.dataTransfer.effectAllowed = "move";
                                    }}
                                    style={{ cursor: "grab" }}
                                  >
                                    <i className="bi bi-grip-vertical" aria-hidden="true" />
                                  </span>
                                </td>
                                <td>{String(field.id)}</td>
                                <td>{String(field.label || "")}</td>
                                <td>{extensions.length > 0 ? extensions.join(", ") : "any"}</td>
                                <td>{maxBytes ? formatSize(maxBytes) : "default"}</td>
                                <td>{maxFiles || "default"}</td>
                                <td>
                                  <div className="btn-group btn-group-sm me-2" role="group">
                                    <button
                                      type="button"
                                      className="btn btn-outline-secondary"
                                      onClick={() => handleMoveTemplateField(String(field.id), "up")}
                                      disabled={!field.id || index === 0}
                                    >
                                      <i className="bi bi-arrow-up" aria-hidden="true" />
                                    </button>
                                    <button
                                      type="button"
                                      className="btn btn-outline-secondary"
                                      onClick={() => handleMoveTemplateField(String(field.id), "down")}
                                      disabled={!field.id || index === templateFileFields.length - 1}
                                    >
                                      <i className="bi bi-arrow-down" aria-hidden="true" />
                                    </button>
                                  </div>
                                  <button
                                    type="button"
                                    className="btn btn-outline-secondary btn-sm"
                                    onClick={() =>
                                      handleSelectTemplateFileField(
                                        String(field.id),
                                        field as Record<string, unknown>
                                      )
                                    }
                                  >
                                    <i className="bi bi-pencil" aria-hidden="true" /> Edit
                                  </button>
                                  <button
                                    type="button"
                                    className="btn btn-outline-danger btn-sm ms-2"
                                    onClick={() => handleRemoveField(String(field.id))}
                                  >
                                    <i className="bi bi-trash" aria-hidden="true" /> Remove
                                  </button>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
            <div className="d-flex flex-wrap gap-2 mt-3">
              {templateBuilderMode === "edit" ? (
                <>
                  <button
                    type="button"
                    className="btn btn-outline-secondary"
                    onClick={handleUpdateTemplate}
                    disabled={!templateEditorKey}
                  >
                    <i className="bi bi-save" aria-hidden="true" /> Update template
                  </button>
                  <button
                    type="button"
                    className="btn btn-outline-secondary"
                    onClick={handleDuplicateTemplate}
                    disabled={!templateEditorKey}
                  >
                    <i className="bi bi-files" aria-hidden="true" /> Duplicate template
                  </button>
                </>
              ) : (
                <button type="button" className="btn btn-primary" onClick={handleCreateTemplate}>
                  <i className="bi bi-plus-square" aria-hidden="true" /> Create template
                </button>
              )}
              {templateEditorStatus ? <span className="muted">{templateEditorStatus}</span> : null}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function AppShell() {
  const [forms, setForms] = useState<FormSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const [user, setUser] = useState<UserInfo | null>(null);
  const [hasCanvasSubmission, setHasCanvasSubmission] = useState(false);
  const [routeKey, setRouteKey] = useState(0);
  const [toasts, setToasts] = useState<ToastNotice[]>([]);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [theme, setTheme] = useState<"dark" | "light">(() => {
    const saved = localStorage.getItem(THEME_KEY);
    return saved === "light" || saved === "dark" ? saved : "dark";
  });
  const [appMarkdownEnabled, setAppMarkdownEnabled] = useState(true);
  const [appMathjaxEnabled, setAppMathjaxEnabled] = useState(true);
  const [appTimezone, setAppTimezoneState] = useState(getAppDefaultTimezone());
  const [appCanvasDeleteSyncEnabled, setAppCanvasDeleteSyncEnabled] = useState(true);
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    async function loadUser() {
      const response = await apiFetch(`${API_BASE}/auth/me`);
      const payload = await response.json().catch(() => null);
      if (payload?.authenticated) {
        setUser(payload.user);
      } else {
        setUser(null);
      }
    }

    loadUser();
  }, [routeKey]);

  useEffect(() => {
    if (!user) {
      setHasCanvasSubmission(false);
      return;
    }
    let active = true;
    async function loadCanvasFlag() {
      const response = await apiFetch(`${API_BASE}/api/me`);
      const payload = await response.json().catch(() => null);
      if (!active) return;
      if (!response.ok) {
        setHasCanvasSubmission(false);
        return;
      }
      const canvas = payload?.canvas;
      setHasCanvasSubmission(Boolean(canvas?.course_id || canvas?.submission_id || canvas?.form_title));
    }
    loadCanvasFlag().catch(() => {
      if (active) setHasCanvasSubmission(false);
    });
    return () => {
      active = false;
    };
  }, [user?.userId]);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem(THEME_KEY, theme);
  }, [theme]);

  useMathJax(appMathjaxEnabled);

  useEffect(() => {
    let active = true;
    async function loadSettings() {
      const response = await apiFetch(`${API_BASE}/api/settings`);
      const payload = await response.json().catch(() => null);
      if (!active) return;
      if (response.ok) {
        if (typeof payload?.timezoneDefault === "string" && payload.timezoneDefault.trim()) {
          const nextTz = payload.timezoneDefault.trim();
          setAppDefaultTimezone(nextTz);
          setAppTimezoneState(nextTz);
        }
        if (typeof payload?.canvasDeleteSyncEnabled === "boolean") {
          setAppCanvasDeleteSyncEnabled(payload.canvasDeleteSyncEnabled);
        }
        if (typeof payload?.markdownEnabled === "boolean") {
          setAppMarkdownEnabled(payload.markdownEnabled);
        }
        if (typeof payload?.mathjaxEnabled === "boolean") {
          setAppMathjaxEnabled(payload.mathjaxEnabled);
        }
      }
    }
    loadSettings().catch(() => null);
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    setMobileMenuOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    document.body.style.overflow = mobileMenuOpen ? "hidden" : "";
    return () => {
      document.body.style.overflow = "";
    };
  }, [mobileMenuOpen]);

  function pushNotice(message: string, type: NoticeType = "info") {
    const id = crypto.randomUUID();
    setToasts((prev) => [...prev, { id, message, type }]);
    window.setTimeout(() => {
      setToasts((prev) => prev.filter((toast) => toast.id !== id));
    }, 3000);
  }

  useEffect(() => {
    let active = true;

    async function loadForms() {
      try {
        const response = await apiFetch(`${API_BASE}/api/forms`);
        const text = await response.text();
        let payload: any = null;
        try {
          payload = JSON.parse(text);
        } catch {
          payload = null;
        }

        if (!response.ok) {
          const requestId = payload?.requestId ?? null;
          if (!active) return;
          setError({
            status: response.status,
            requestId: requestId ?? undefined,
            message: payload?.error ?? "Request failed"
          });
          setLoading(false);
          return;
        }

        const data = Array.isArray(payload?.data) ? payload.data : [];
        if (!active) return;
        setForms(data);
        setError(null);
        setLoading(false);
      } catch (err) {
        if (!active) return;
        setError({
          status: 0,
          message: err instanceof Error ? err.message : "Network error"
        });
        setLoading(false);
      }
    }

    loadForms();
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    const path = location.pathname || "/";
    let pageTitle = "Home";
    if (path.startsWith("/admin/builder")) {
      pageTitle = "Builder";
    } else if (path.startsWith("/admin/canvas")) {
      pageTitle = "Canvas";
    } else if (path.startsWith("/canvas")) {
      pageTitle = "Canvas";
    } else if (path.startsWith("/trash")) {
      pageTitle = "Trash";
    } else if (path.startsWith("/account")) {
      pageTitle = "Account";
    } else if (path.startsWith("/admin")) {
      pageTitle = "Admin Dashboard";
    } else if (path.startsWith("/me")) {
      pageTitle = "My Dashboard";
    } else if (path.startsWith("/docs")) {
      pageTitle = "Docs";
    } else if (path.startsWith("/f/")) {
      pageTitle = "Form";
    } else if (path.startsWith("/auth/callback")) {
      pageTitle = "Auth";
    } else if (path !== "/") {
      pageTitle = "Page";
    }
    document.title = `Form App - ${pageTitle}`;
  }, [location.pathname]);

  function handleLogin(provider: "google" | "github") {
    const returnTo = window.location.href;
    localStorage.setItem(RETURN_TO_KEY, returnTo);
    const callbackUrl = buildReturnTo();
    const loginUrl = `${API_BASE}/auth/login/${provider}?return_to=${encodeURIComponent(callbackUrl)}`;
    window.location.assign(loginUrl);
  }

  function handleLogout(silent: boolean = false) {
    apiFetch(`${API_BASE}/auth/logout`).finally(() => {
      clearToken();
      setUser(null);
      setRouteKey((prev) => prev + 1);
      if (!silent) {
        pushNotice("Logged out successfully.", "success");
      }
      navigate("/", { replace: true });
    });
  }

  function toggleTheme() {
    setTheme((prev) => (prev === "dark" ? "light" : "dark"));
  }

  async function updateDefaultTimezone(nextTz: string) {
    const response = await apiFetch(`${API_BASE}/api/admin/settings`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ timezoneDefault: nextTz })
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      return false;
    }
    setAppDefaultTimezone(nextTz);
    setAppTimezoneState(nextTz);
    return true;
  }

  async function updateCanvasDeleteSyncEnabled(nextValue: boolean) {
    const response = await apiFetch(`${API_BASE}/api/admin/settings`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ canvasDeleteSyncEnabled: nextValue })
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      return false;
    }
    if (typeof payload?.canvasDeleteSyncEnabled === "boolean") {
      setAppCanvasDeleteSyncEnabled(payload.canvasDeleteSyncEnabled);
    } else {
      setAppCanvasDeleteSyncEnabled(nextValue);
    }
    return true;
  }

  async function updateMarkdownEnabled(nextValue: boolean) {
    const response = await apiFetch(`${API_BASE}/api/admin/settings`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ markdownEnabled: nextValue })
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      return false;
    }
    if (typeof payload?.markdownEnabled === "boolean") {
      setAppMarkdownEnabled(payload.markdownEnabled);
    } else {
      setAppMarkdownEnabled(nextValue);
    }
    return true;
  }

  async function updateMathjaxEnabled(nextValue: boolean) {
    const response = await apiFetch(`${API_BASE}/api/admin/settings`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ mathjaxEnabled: nextValue })
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      return false;
    }
    if (typeof payload?.mathjaxEnabled === "boolean") {
      setAppMathjaxEnabled(payload.mathjaxEnabled);
    } else {
      setAppMathjaxEnabled(nextValue);
    }
    return true;
  }
  const navLinks: Array<{ to: string; label: string; icon: string; show: boolean }> = [
    { to: "/", label: "Home", icon: "bi-house", show: true },
    { to: "/dashboard", label: "My Dashboard", icon: "bi-speedometer2", show: Boolean(user) },
    {
      to: "/canvas",
      label: "Canvas",
      icon: "bi-mortarboard",
      show: Boolean(user && !user.isAdmin && hasCanvasSubmission)
    },
    { to: "/trash", label: "Trash", icon: "bi-trash", show: Boolean(user && !user.isAdmin) },
    { to: "/account", label: "Account", icon: "bi-person", show: Boolean(user) }
  ];
  const adminLinks: Array<{ to: string; label: string; icon: string }> = [
    { to: "/admin", label: "Admin Dashboard", icon: "bi-gear" },
    { to: "/admin/builder", label: "Builder", icon: "bi-pencil-square" },
    { to: "/admin/canvas", label: "Canvas", icon: "bi-mortarboard" },
    { to: "/admin/emails", label: "Emails", icon: "bi-envelope" },
    { to: "/trash", label: "Trash", icon: "bi-trash" }
  ];
  const adminMenuRef = useRef<HTMLDetailsElement | null>(null);

  return (
    <div className="app">
      {toasts.length > 0 ? (
        <div
          style={{
            position: "fixed",
            right: 20,
            bottom: 20,
            zIndex: 1050,
            minWidth: 260
          }}
        >
          {toasts.map((toast) => (
            <div
              key={toast.id}
              className={`alert shadow ${toast.type === "success"
                ? "alert-success"
                : toast.type === "error"
                  ? "alert-danger"
                  : toast.type === "warning"
                    ? "alert-warning"
                    : "alert-info"
                }`}
              role="status"
            >
              {toast.message}
            </div>
          ))}
        </div>
      ) : null}
      <header className="app-header">
        <div className="app-header__mobile">
          <button
            type="button"
            className="btn btn-outline-secondary btn-sm"
            onClick={() => setMobileMenuOpen(true)}
            aria-label="Open menu"
          >
            <i className="bi bi-list" aria-hidden="true" />
          </button>
          <div className="app-header__title">Form App</div>
          <button
            type="button"
            className="btn btn-outline-secondary btn-sm"
            onClick={toggleTheme}
            title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
          >
            <i className={`bi ${theme === "dark" ? "bi-sun" : "bi-moon"}`} aria-hidden="true" />
          </button>
        </div>
        <nav className="navbar navbar-expand navbar-light bg-light rounded px-3 mb-3 app-header__desktop">
          <div className="navbar-nav me-auto align-items-center">
            {navLinks
              .filter((link) => link.show)
              .map((link) => (
                <Link key={link.to} className="nav-link d-flex align-items-center gap-2" to={link.to}>
                  <i className={`bi ${link.icon}`} aria-hidden="true" /> {link.label}
                </Link>
              ))}
            {user?.isAdmin ? (
              <details className="nav-dropdown" ref={adminMenuRef}>
                <summary className="nav-link d-flex align-items-center gap-2">
                  <i className="bi bi-shield-lock" aria-hidden="true" /> Admin
                </summary>
                <div className="nav-dropdown__menu">
                  {adminLinks.map((link) => (
                    <Link
                      key={link.to}
                      className="nav-dropdown__item"
                      to={link.to}
                      onClick={() => adminMenuRef.current?.removeAttribute("open")}
                    >
                      <i className={`bi ${link.icon}`} aria-hidden="true" /> {link.label}
                    </Link>
                  ))}
                </div>
              </details>
            ) : null}
          </div>
          <AuthBar user={user} onLogin={handleLogin} onLogout={handleLogout} />
        </nav>
      </header>
      <button
        type="button"
        className="btn btn-outline-secondary btn-sm theme-fab"
        onClick={toggleTheme}
        title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
      >
        <i className={`bi ${theme === "dark" ? "bi-sun" : "bi-moon"}`} aria-hidden="true" />{" "}
        {theme === "dark" ? "Light" : "Dark"}
      </button>
      {mobileMenuOpen ? (
        <div className="mobile-drawer">
          <button
            type="button"
            className="mobile-drawer__backdrop"
            aria-label="Close menu"
            onClick={() => setMobileMenuOpen(false)}
          />
          <div className="mobile-drawer__panel">
            <div className="mobile-drawer__header">
              <div>
                <div className="mobile-drawer__title">Form App</div>
                {user ? (
                  <div className="muted">{getUserDisplayName(user)}</div>
                ) : (
                  <div className="muted">Guest</div>
                )}
              </div>
              <button
                type="button"
                className="btn btn-outline-secondary btn-sm"
                onClick={() => setMobileMenuOpen(false)}
                aria-label="Close menu"
              >
                <i className="bi bi-x-lg" aria-hidden="true" />
              </button>
            </div>
            <div className="mobile-drawer__links">
              {[...navLinks.filter((link) => link.show), ...(user?.isAdmin ? adminLinks : [])].map(
                (link) => (
                  <Link key={link.to} className="mobile-drawer__link" to={link.to}>
                    <i className={`bi ${link.icon}`} aria-hidden="true" /> {link.label}
                  </Link>
                )
              )}
            </div>
            <div className="mobile-drawer__actions">
              {user ? (
                <button type="button" className="btn btn-outline-danger w-100" onClick={() => handleLogout()}>
                  <i className="bi bi-box-arrow-right" aria-hidden="true" /> Logout
                </button>
              ) : (
                <>
                  <button type="button" className="btn btn-primary w-100" onClick={() => handleLogin("google")}>
                    <i className="bi bi-google" aria-hidden="true" /> Login with Google
                  </button>
                  <button type="button" className="btn btn-outline-dark w-100" onClick={() => handleLogin("github")}>
                    <i className="bi bi-github" aria-hidden="true" /> Login with GitHub
                  </button>
                </>
              )}
            </div>
          </div>
        </div>
      ) : null}

      <Routes>
        <Route
          path="/"
          element={
            <HomePage
              forms={forms}
              loading={loading}
              error={error}
              user={user}
              markdownEnabled={appMarkdownEnabled}
              mathjaxEnabled={appMathjaxEnabled}
            />
          }
        />
        <Route
          path="/auth/callback"
          element={
            <AuthCallback
              onComplete={() => setRouteKey((prev) => prev + 1)}
              onNotice={pushNotice}
            />
          }
        />
        <Route
          path="/f/:slug"
          element={
            <FormRoute
              user={user}
              onLogin={handleLogin}
              onNotice={pushNotice}
              markdownEnabled={appMarkdownEnabled}
              mathjaxEnabled={appMathjaxEnabled}
            />
          }
        />
        <Route
          path="/me"
          element={
            <DashboardPage
              user={user}
              onLogin={handleLogin}
              onNotice={pushNotice}
              markdownEnabled={appMarkdownEnabled}
              mathjaxEnabled={appMathjaxEnabled}
            />
          }
        />
        <Route
          path="/dashboard"
          element={
            <DashboardPage
              user={user}
              onLogin={handleLogin}
              onNotice={pushNotice}
              markdownEnabled={appMarkdownEnabled}
              mathjaxEnabled={appMathjaxEnabled}
            />
          }
        />
        <Route
          path="/account"
          element={
            <AccountPage
              user={user}
              onLogin={handleLogin}
              onLogout={handleLogout}
              onNotice={pushNotice}
            />
          }
        />
        <Route
          path="/canvas"
          element={
            user && !user.isAdmin && hasCanvasSubmission ? (
              <CanvasPage
                user={user}
                onLogin={handleLogin}
                markdownEnabled={appMarkdownEnabled}
                mathjaxEnabled={appMathjaxEnabled}
              />
            ) : (
              <Navigate to="/dashboard" replace />
            )
          }
        />
        <Route
          path="/me/submissions/:id"
          element={
            <SubmissionDetailPage
              user={user}
              onLogin={handleLogin}
              onNotice={pushNotice}
              markdownEnabled={appMarkdownEnabled}
              mathjaxEnabled={appMathjaxEnabled}
            />
          }
        />
        <Route path="/docs" element={<DocsPage />} />
        <Route
          path="/admin"
          element={
            <AdminPage
              user={user}
              onLogin={handleLogin}
              onNotice={pushNotice}
              appDefaultTimezone={appTimezone}
              onUpdateDefaultTimezone={updateDefaultTimezone}
              appCanvasDeleteSyncEnabled={appCanvasDeleteSyncEnabled}
              onUpdateCanvasDeleteSyncEnabled={updateCanvasDeleteSyncEnabled}
              appMarkdownEnabled={appMarkdownEnabled}
              appMathjaxEnabled={appMathjaxEnabled}
              onUpdateMarkdownEnabled={updateMarkdownEnabled}
              onUpdateMathjaxEnabled={updateMathjaxEnabled}
            />
          }
        />
        <Route
          path="/admin/canvas"
          element={
            <AdminCanvasPage
              user={user}
              onLogin={handleLogin}
              onNotice={pushNotice}
              appDefaultTimezone={appTimezone}
              onUpdateDefaultTimezone={updateDefaultTimezone}
              markdownEnabled={appMarkdownEnabled}
              mathjaxEnabled={appMathjaxEnabled}
            />
          }
        />
        <Route
          path="/admin/emails"
          element={
            <AdminEmailsPage
              user={user}
              onLogin={handleLogin}
              markdownEnabled={appMarkdownEnabled}
              mathjaxEnabled={appMathjaxEnabled}
            />
          }
        />
        <Route
          path="/trash"
          element={
            <TrashPage
              user={user}
              onLogin={handleLogin}
              onNotice={pushNotice}
              markdownEnabled={appMarkdownEnabled}
              mathjaxEnabled={appMathjaxEnabled}
            />
          }
        />
        <Route
          path="/admin/builder"
          element={
            user?.isAdmin ? (
              <BuilderPage
                user={user}
                onLogin={handleLogin}
                onNotice={pushNotice}
                appDefaultTimezone={appTimezone}
                markdownEnabled={appMarkdownEnabled}
                mathjaxEnabled={appMathjaxEnabled}
              />
            ) : (
              <NotFoundPage />
            )
          }
        />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
      <footer className="site-footer">
        <div>{APP_INFO.title}</div>
        <div>{APP_INFO.description}</div>
        <div>Built with assistance from GitHub Copilot, ChatGPT Codex, and Google Antigravity.</div>
        <div>
          (c) {new Date().getFullYear()} {APP_INFO.author}.{" "}
          License:{" "}
          <a href={LICENSE_URL} target="_blank" rel="noreferrer">
            {APP_INFO.license}
          </a>
          .{" "}
          <a href={APP_INFO.repoUrl} target="_blank" rel="noreferrer">
            Source
          </a>
          .
        </div>
      </footer>
    </div>
  );
}

export default function App() {
  return (
    <HashRouter>
      <ErrorBoundary>
        <AppShell />
      </ErrorBoundary>
    </HashRouter>
  );
}
