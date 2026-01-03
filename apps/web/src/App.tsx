import React, { useEffect, useMemo, useState } from "react";
import { HashRouter, Link, Route, Routes, useLocation, useNavigate, useParams } from "react-router-dom";
import { APP_INFO } from "./config";
import { apiFetch, clearToken, setToken } from "./auth";

type FormSummary = {
  slug: string;
  title: string;
  is_public: boolean;
  is_locked: boolean;
  auth_policy?: string;
};

type FormField = {
  id: string;
  label: string;
  type: string;
  required: boolean;
  placeholder?: string;
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

function getAuthPolicyLabel(policy?: string) {
  const value = policy || "optional";
  return value.charAt(0).toUpperCase() + value.slice(1);
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
  placeholder: string;
  options: string;
  multiple: boolean;
  emailDomain: string;
  autofillFromLogin: boolean;
};

type FileFieldBuilderConfig = {
  id: string;
  label: string;
  required: boolean;
  extensions: string;
  maxSizeMb: number;
  maxFiles: number;
};

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
  if (payload.field?.type !== "email" && payload.field?.type !== "github_username") {
    delete (nextField as any).rules;
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
  builderPlaceholder,
  builderOptions,
  builderMultiple,
  builderEmailDomain,
  builderAutofillFromLogin,
  onTypeChange,
  onCustomTypeChange,
  onIdChange,
  onLabelChange,
  onRequiredChange,
  onPlaceholderChange,
  onOptionsChange,
  onMultipleChange,
  onEmailDomainChange,
  onAutofillFromLoginChange,
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
  builderPlaceholder: string;
  builderOptions: string;
  builderMultiple: boolean;
  builderEmailDomain: string;
  builderAutofillFromLogin: boolean;
  onTypeChange: (value: string) => void;
  onCustomTypeChange: (value: string) => void;
  onIdChange: (value: string) => void;
  onLabelChange: (value: string) => void;
  onRequiredChange: (value: boolean) => void;
  onPlaceholderChange: (value: string) => void;
  onOptionsChange: (value: string) => void;
  onMultipleChange: (value: boolean) => void;
  onEmailDomainChange: (value: string) => void;
  onAutofillFromLoginChange: (value: boolean) => void;
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
            <option value="date">Date</option>
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
        {["text", "full_name", "email", "github_username", "number", "textarea", "custom"].includes(builderType) ? (
          <div className="col-md-6">
            <label className="form-label">Placeholder</label>
            <input
              className="form-control"
              value={builderPlaceholder}
              onChange={(event) => onPlaceholderChange(event.target.value)}
            />
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
  options: { format: "csv" | "txt"; mode: "flat" | "json"; includeMeta: boolean; maxRows: number }
) {
  const params = new URLSearchParams();
  params.set("formSlug", formSlug);
  params.set("format", options.format);
  params.set("mode", options.mode);
  params.set("includeMeta", options.includeMeta ? "1" : "0");
  params.set("maxRows", String(options.maxRows));
  return `${API_BASE}/api/admin/submissions/export?${params.toString()}`;
}

function buildFormSubmissionsExportUrl(formSlug: string, format: "csv" | "txt") {
  const params = new URLSearchParams();
  params.set("format", format);
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
  try {
    return new Intl.DateTimeFormat("en-GB", {
      timeZone: "Asia/Ho_Chi_Minh",
      dateStyle: "medium",
      timeStyle: "short",
      timeZoneName: "short"
    }).format(date);
  } catch (error) {
    const offsetMs = 7 * 60 * 60 * 1000;
    const ictDate = new Date(date.getTime() + offsetMs);
    const pad = (num: number) => String(num).padStart(2, "0");
    const day = pad(ictDate.getUTCDate());
    const month = pad(ictDate.getUTCMonth() + 1);
    const year = ictDate.getUTCFullYear();
    const hours = pad(ictDate.getUTCHours());
    const minutes = pad(ictDate.getUTCMinutes());
    return `${day}/${month}/${year}, ${hours}:${minutes} ICT`;
  }
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
  onLogout: () => void;
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
            {user.email || user.userId} -{" "}
            {providerIcon ? <i className={`bi ${providerIcon}`} aria-hidden="true" /> : null}{" "}
            {providerLabel}
          </div>
          </div>
          <button type="button" className="btn btn-outline-secondary btn-sm" onClick={onLogout}>
            <i className="bi bi-box-arrow-right" aria-hidden="true" /> Logout
          </button>
        </>
      ) : (
        <>
          <button type="button" className="btn btn-primary btn-sm" onClick={() => onLogin("google")}>
            <i className="bi bi-google" aria-hidden="true" /> Login with Google
          </button>
          <button
            type="button"
            className="btn btn-outline-dark btn-sm"
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
      </div>
      {user ? (
        <div>
          <div>Authenticated</div>
          <div className="muted">{user.email || user.userId}</div>
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
  user
}: {
  forms: FormSummary[];
  loading: boolean;
  error: ApiError | null;
  user: UserInfo | null;
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
                  <h3>{form.title}</h3>
                  <p className="muted mb-2">Slug: {form.slug}</p>
                  <div className="d-flex gap-2 flex-wrap">
                    <span className={`badge ${form.is_locked ? "text-bg-danger" : "text-bg-success"}`}>
                      <i className={`bi ${getLockIcon(form.is_locked)}`} aria-hidden="true" />{" "}
                      {form.is_locked ? "Locked" : "Unlocked"}
                    </span>
                    <span className={`badge ${form.is_public ? "text-bg-primary" : "text-bg-secondary"}`}>
                      <i className={`bi ${getVisibilityIcon(form.is_public)}`} aria-hidden="true" />{" "}
                      {form.is_public ? "Public" : "Private"}
                    </span>
                    <span className="badge text-bg-secondary">
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
              <strong>License:</strong> {APP_INFO.license}
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
  onNotice
}: {
  slug: string;
  user: UserInfo | null;
  onLogin: (provider: "google" | "github") => void;
  onNotice: (message: string, type?: NoticeType) => void;
}) {
  const [form, setForm] = useState<FormDetail | null>(null);
  const [values, setValues] = useState<Record<string, string>>({});
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
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const navigate = useNavigate();

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
      return isValidDateString(value) ? null : "Invalid date";
    }
    if (field.type === "full_name") {
      const hasDigits = /\d/.test(value);
      return hasDigits ? "Name cannot include digits" : null;
    }
    if (field.type === "github_username") {
      const valid = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$/.test(value);
      return valid ? null : "Invalid GitHub username";
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
    if (field.type === "text" || field.type === "textarea") {
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

  useEffect(() => {
    let active = true;

    async function loadForm() {
      setLoading(true);
      setLoadError(null);
      setSubmitError(null);
      setSubmitDebug(null);
      setSelectedFiles({});
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
      const response = await apiFetch(`${API_BASE}/api/forms/${slug}`);
      const text = await response.text();
      let payload: any = null;
      try {
        payload = JSON.parse(text);
      } catch {
        payload = null;
      }

      if (!response.ok) {
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
      setLocked(Boolean(data?.is_locked));
      setLoading(false);
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
        `${API_BASE}/api/forms/${form.slug}/files?submissionId=${encodeURIComponent(id)}`
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
        `${API_BASE}/api/forms/${encodeURIComponent(form.slug)}/my-submission`
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
          setValues(submissionData as Record<string, string>);
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
  const isFormComplete = Boolean(
    form &&
      form.fields.every((field) => {
        if (field.type === "file") {
          const files = selectedFiles[field.id] || [];
          const existing = existingFilesByField[field.id] || [];
          if (field.required && files.length === 0 && existing.length === 0) return false;
          return true;
        }
        const raw = values[field.id] || "";
        const autofillValue = getAutofillValue(field);
        const value = (raw.trim() || autofillValue).trim();
        if (field.required && !value) return false;
        if (value && validateFieldValue(field, value)) return false;
        return true;
      })
  );
  const submitDisabledReason = !canSubmit
    ? "Please sign in to submit."
    : locked
    ? "Form is locked."
    : isAnyUploading
    ? "Files are uploading."
    : !isFormComplete
    ? "Complete required fields and select required files."
    : "";

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
            ? ` Server limits: maxFiles=${payload?.detail?.maxFiles ?? "n/a"}, maxBytes=${
                payload?.detail?.maxBytes ?? "n/a"
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
    if (!window.confirm(`Remove all ${items.length} uploaded file(s)?`)) {
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

  async function handleDeleteSubmission() {
    if (!form) return;
    setDeleteError(null);
    if (!window.confirm("Delete your submission? This cannot be undone.")) {
      return;
    }
    const response = await apiFetch(
      `${API_BASE}/api/me/submission?formSlug=${encodeURIComponent(form.slug)}`,
      { method: "DELETE" }
    );
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setDeleteError(payload?.error || "Failed to delete submission.");
      return;
    }
    setSubmissionId(null);
    setSavedAt(null);
    setValues({});
    setSelectedFiles({});
    setFileItems([]);
    setUploadedFiles({});
    onNotice("Submission deleted.", "success");
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
    form.fields.forEach((field) => {
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
      normalizedValues[field.id] = normalized;
    });
    const fileFields = form.fields.filter((field) => field.type === "file");
    fileFields.forEach((field) => {
      const files = selectedFiles[field.id] || [];
      const uploaded = files.filter((file) => uploadedFiles[buildFileIdentity(field.id, file)]);
      if (field.required && uploaded.length === 0) {
        errors[field.id] = "Upload required";
      }
      if (files.length > 0 && uploaded.length !== files.length) {
        errors[field.id] = "Please upload selected files";
      }
    });

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
          data: normalizedValues
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
        navigate(`/me/submissions/${returnedId}`);
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
          <h2>{form.title}</h2>
          {form.description ? <p className="muted">{form.description}</p> : null}
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

      {requiresAuth && !isAuthorized ? (
        <div className="panel panel--error panel--inline">
          <p>
            <i className="bi bi-shield-lock" aria-hidden="true" /> This form requires authentication.
            Please sign in to continue.
          </p>
          <div className="auth-bar">
            <button type="button" className="btn btn-primary" onClick={() => onLogin("google")}>
              <i className="bi bi-google" aria-hidden="true" /> Login with Google
            </button>
            <button type="button" className="btn btn-outline-dark" onClick={() => onLogin("github")}>
              <i className="bi bi-github" aria-hidden="true" /> Login with GitHub
            </button>
          </div>
        </div>
      ) : null}

      <form className="form-grid" onSubmit={handleSubmit}>
        {form.fields.length === 0 ? (
          <p className="muted">No fields configured yet.</p>
        ) : (
          form.fields.map((field) => {
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
                  <span>
                    {field.label}
                    {field.required ? " *" : ""}
                  </span>
                  <input
                    type="file"
                    multiple={Boolean(rules.maxFiles ? rules.maxFiles > 1 : true)}
                    required={Boolean(field.required && existing.length === 0)}
                    disabled={locked || !canSubmit || uploading || reachedMax}
                    onChange={(event) => handleFileChange(field.id, event.target.files)}
                    accept={
                      rules.extensions.length
                        ? rules.extensions.map((ext) => `.${ext}`).join(",")
                        : undefined
                    }
                  />
                  <span className="field-help">
                    {rules.extensions.length > 0
                      ? `Allowed: ${rules.extensions.join(", ")}`
                      : "All file types"}
                    {" - "}Max size {formatSize(rules.maxBytes)}
                    {" - "}Max files {rules.maxFiles} (existing files {existing.length})
                    {field.required ? " - Required" : ""}
                  </span>
                  <div className="upload-actions">
                    <button
                      type="button"
                      className="btn btn-outline-success btn-sm"
                      disabled={locked || !canSubmit || isFieldUploading || files.length === 0}
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
              const domain = field.type === "email" ? getEmailDomain(field) : "";
              return (
                <label key={field.id} className="field">
                  <span>
                    {field.label}
                    {field.required ? " *" : ""}
                  </span>
                  <input
                    type={field.type === "email" ? "email" : "text"}
                    value={inputValue}
                    placeholder={placeholder}
                    disabled={locked || !canSubmit || isAutofilled}
                    onChange={(event) => {
                      const nextValue = event.target.value;
                      setValues((prev) => ({ ...prev, [field.id]: nextValue }));
                      if (fieldErrors[field.id]) {
                        updateFieldError(field, nextValue);
                      }
                    }}
                    onBlur={(event) => updateFieldError(field, event.target.value)}
                  />
                  {domain ? (
                    <span className="field-help">Required domain: @{domain}</span>
                  ) : null}
                  {isAutofilled ? (
                    <span className="field-help">Auto-filled from login</span>
                  ) : null}
                  {fieldErrors[field.id] ? (
                    <span className="error-text">{fieldErrors[field.id]}</span>
                  ) : null}
                </label>
              );
            }

            if (field.type === "textarea") {
              const placeholder =
                typeof (field as any).placeholder === "string" && (field as any).placeholder.trim()
                  ? String((field as any).placeholder)
                  : field.label;
              return (
                <label key={field.id} className="field">
                  <span>
                    {field.label}
                    {field.required ? " *" : ""}
                  </span>
                  <textarea
                    rows={4}
                    value={values[field.id] || ""}
                    placeholder={placeholder}
                    disabled={locked || !canSubmit}
                    onChange={(event) =>
                      setValues((prev) => ({ ...prev, [field.id]: event.target.value }))
                    }
                    onBlur={(event) => updateFieldError(field, event.target.value)}
                  />
                  {fieldErrors[field.id] ? (
                    <span className="error-text">{fieldErrors[field.id]}</span>
                  ) : null}
                </label>
              );
            }

            if (field.type === "select") {
              const options = Array.isArray((field as any).options) ? (field as any).options : [];
              return (
                <label key={field.id} className="field">
                  <span>
                    {field.label}
                    {field.required ? " *" : ""}
                  </span>
                  <select
                    value={values[field.id] || ""}
                    disabled={locked || !canSubmit || options.length === 0}
                    onChange={(event) => {
                      const nextValue = event.target.value;
                      setValues((prev) => ({ ...prev, [field.id]: nextValue }));
                      if (fieldErrors[field.id]) {
                        updateFieldError(field, nextValue);
                      }
                    }}
                    onBlur={(event) => updateFieldError(field, event.target.value)}
                  >
                    <option value="">Select an option</option>
                    {options.map((option: string) => (
                      <option key={option} value={option}>
                        {option}
                      </option>
                    ))}
                  </select>
                  {options.length === 0 ? <span className="error-text">No options configured</span> : null}
                  {fieldErrors[field.id] ? (
                    <span className="error-text">{fieldErrors[field.id]}</span>
                  ) : null}
                </label>
              );
            }

            if (field.type === "checkbox") {
              const options = Array.isArray((field as any).options) ? (field as any).options : [];
              const selectedValues = (values[field.id] || "")
                .split(",")
                .map((item) => item.trim())
                .filter((item) => item.length > 0);
              const multiple = Boolean((field as any).multiple);
              return (
                <fieldset key={field.id} className="field field--group" disabled={locked || !canSubmit}>
                  <legend>
                    {field.label}
                    {field.required ? " *" : ""}
                  </legend>
                  {options.length === 0 ? <span className="error-text">No options configured</span> : null}
                  <div className="checkbox-grid">
                    {options.map((option: string) => {
                      const checked = selectedValues.includes(option);
                      return (
                        <label key={option} className="checkbox-item">
                          <input
                            type="checkbox"
                            checked={checked}
                            onChange={(event) => {
                              let nextValues = [...selectedValues];
                              if (event.target.checked) {
                                if (!multiple) {
                                  nextValues = [option];
                                } else if (!nextValues.includes(option)) {
                                  nextValues.push(option);
                                }
                              } else {
                                nextValues = nextValues.filter((item) => item !== option);
                              }
                              const nextValue = nextValues.join(", ");
                              setValues((prev) => ({ ...prev, [field.id]: nextValue }));
                              if (fieldErrors[field.id]) {
                                updateFieldError(field, nextValue);
                              }
                            }}
                            onBlur={() => updateFieldError(field, selectedValues.join(", "))}
                          />
                          <span>{option}</span>
                        </label>
                      );
                    })}
                  </div>
                  {fieldErrors[field.id] ? (
                    <span className="error-text">{fieldErrors[field.id]}</span>
                  ) : null}
                </fieldset>
              );
            }

            if (field.type === "full_name") {
              const placeholder =
                typeof (field as any).placeholder === "string" && (field as any).placeholder.trim()
                  ? String((field as any).placeholder)
                  : field.label;
              return (
                <label key={field.id} className="field">
                  <span>
                    {field.label}
                    {field.required ? " *" : ""}
                  </span>
                <input
                  type="text"
                  value={values[field.id] || ""}
                  placeholder={placeholder}
                  disabled={locked || !canSubmit}
                  onChange={(event) =>
                    setValues((prev) => ({ ...prev, [field.id]: event.target.value }))
                  }
                  onBlur={(event) => {
                    const formatted = toTitleCase(event.target.value);
                    if (formatted !== event.target.value) {
                      setValues((prev) => ({ ...prev, [field.id]: formatted }));
                    }
                    updateFieldError(field, formatted);
                  }}
                />
                {fieldErrors[field.id] ? (
                  <span className="error-text">{fieldErrors[field.id]}</span>
                ) : null}
                </label>
              );
            }

            return (
              <label key={field.id} className="field">
                <span>
                  {field.label}
                  {field.required ? " *" : ""}
                </span>
                <input
                  type={
                    field.type === "date"
                      ? "date"
                      : field.type === "email"
                      ? "email"
                      : field.type === "number"
                      ? "number"
                      : "text"
                  }
                  value={values[field.id] || ""}
                  placeholder={
                    typeof (field as any).placeholder === "string" && (field as any).placeholder.trim()
                      ? String((field as any).placeholder)
                      : field.label
                  }
                  disabled={locked || !canSubmit}
                  onChange={(event) => {
                    const nextValue = event.target.value;
                    setValues((prev) => ({ ...prev, [field.id]: nextValue }));
                    if (fieldErrors[field.id]) {
                      updateFieldError(field, nextValue);
                    }
                  }}
                  onBlur={(event) => updateFieldError(field, event.target.value)}
                />
                {fieldErrors[field.id] ? (
                  <span className="error-text">{fieldErrors[field.id]}</span>
                ) : null}
              </label>
            );
          })
        )}
        {uploading ? <p className="muted">Uploading files...</p> : null}
        {deleteError ? <div className="alert alert-danger">{deleteError}</div> : null}
        <div className="form-actions">
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
          {hasExistingSubmission ? (
            <button
              type="button"
              className="btn btn-outline-danger"
              disabled={saving || uploading || isAnyUploading}
              onClick={handleDeleteSubmission}
            >
              <i className="bi bi-trash" aria-hidden="true" /> Delete
            </button>
          ) : null}
          {savedAt ? <span className="muted">Last saved: {formatTimeICT(savedAt)}</span> : null}
        </div>
      </form>
    </section>
  );
}

function FormRoute({
  user,
  onLogin,
  onNotice
}: {
  user: UserInfo | null;
  onLogin: (provider: "google" | "github") => void;
  onNotice: (message: string, type?: NoticeType) => void;
}) {
  const params = useParams();
  const slug = params.slug || "";
  return <FormPage slug={slug} user={user} onLogin={onLogin} onNotice={onNotice} />;
}

function DocsPage() {
  return (
    <section className="panel">
      <h2>Docs</h2>
      <p className="muted">
        This guide explains how Form App is structured and how to use the main features.
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
            <strong>Account:</strong> <code>/#/account</code>
          </li>
          <li>
            <strong>Admin:</strong> <code>/#/admin</code>
          </li>
          <li>
            <strong>Builder:</strong> <code>/#/admin/builder</code> (admin-only)
          </li>
        </ul>
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
            <strong>Uploads:</strong> staged to R2, scanned by VirusTotal, finalized to Drive if clean.
          </li>
          <li>
            <strong>Admin:</strong> manage forms/templates, review submissions, export CSV/TXT.
          </li>
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
        </ul>
      </div>

      <div className="panel panel--compact">
        <h3>Builder workflow (admin)</h3>
        <ul className="list-unstyled">
          <li>Use the Builder tab to create or edit forms/templates.</li>
          <li>
            Toggle <strong>New</strong> vs <strong>Edit</strong> to switch between create/update.
          </li>
          <li>
            Field builder supports: text, textarea, number, date, email, GitHub username, full
            name, select, checkbox, and file fields.
          </li>
          <li>
            File fields store rules per field: extensions, max size, max files.
          </li>
          <li>Use drag handles to reorder fields.</li>
        </ul>
      </div>

      <div className="panel panel--compact">
        <h3>Admin submissions access</h3>
        <ul className="list-unstyled">
          <li>Admin can open any submission at <code>/#/me/submissions/&lt;id&gt;</code>.</li>
          <li>Recent submissions list links each submission ID to that detail view.</li>
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
        <h3>Local deployment</h3>
        <ol className="mb-0">
          <li>Install deps: <code>npm install</code></li>
          <li>Start API: <code>npm run dev:api</code></li>
          <li>Start Web: <code>npm run dev:web</code></li>
          <li>Open <code>http://localhost:5173/forms/</code></li>
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
  onLogin
}: {
  user: UserInfo | null;
  onLogin: (provider: "google" | "github") => void;
}) {
  const [loading, setLoading] = useState(true);
  const [items, setItems] = useState<any[]>([]);
  const [error, setError] = useState<ApiError | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

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

  if (!user) {
    return (
      <section className="panel panel--error">
        <h2>Sign in required</h2>
        <p>Please sign in to view your dashboard.</p>
        <div className="auth-bar">
          <button type="button" className="btn btn-primary" onClick={() => onLogin("google")}>
            <i className="bi bi-google" aria-hidden="true" /> Login with Google
          </button>
          <button type="button" className="btn btn-outline-dark" onClick={() => onLogin("github")}>
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
                        <i className="bi bi-ui-checks" aria-hidden="true" /> {form.title || slug}
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
                        {entry.canEdit ? "Edit submission" : "Open form"}
                      </a>
                      {entry.latestSubmissionId ? (
                        <Link
                          className="btn btn-outline-secondary btn-sm"
                          to={`/me/submissions/${entry.latestSubmissionId}`}
                        >
                          <i className="bi bi-eye" aria-hidden="true" /> View submission
                        </Link>
                      ) : null}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}

function AccountPage({
  user,
  onLogin,
  onLogout
}: {
  user: UserInfo | null;
  onLogin: (provider: "google" | "github") => void;
  onLogout: () => void;
}) {
  const location = useLocation();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [identities, setIdentities] = useState<any[]>([]);

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
      setIdentities(Array.isArray(payload?.identities) ? payload.identities : []);
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
          <button type="button" className="btn btn-primary" onClick={() => onLogin("google")}>
            <i className="bi bi-google" aria-hidden="true" /> Login with Google
          </button>
          <button type="button" className="btn btn-outline-dark" onClick={() => onLogin("github")}>
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
    if (!window.confirm("Delete your account? This will remove your submissions.")) {
      return;
    }
    // Soft-delete the account server-side; API clears the auth cookie.
    const response = await apiFetch(`${API_BASE}/api/me`, { method: "DELETE" });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setActionError(payload?.error || "Failed to delete account.");
      return;
    }
    onLogout();
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Account</h2>
        {user ? <span className="badge">{user.email || user.userId}</span> : null}
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
        <div className="row g-3">
          <div className="col-md-6">
            <div className="muted">Linked identities</div>
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
                    {identity.email || identity.providerLogin || identity.providerSub || "n/a"}
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

function SubmissionDetailPage({
  user,
  onLogin
}: {
  user: UserInfo | null;
  onLogin: (provider: "google" | "github") => void;
}) {
  const { id } = useParams();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const [data, setData] = useState<any | null>(null);
  const [fieldMeta, setFieldMeta] = useState<Record<string, { label: string; type: string }>>({});
  const [fieldOrder, setFieldOrder] = useState<string[]>([]);

  useEffect(() => {
    if (!user || !id) {
      setLoading(false);
      return;
    }
    let active = true;
    async function loadSubmission() {
      setLoading(true);
      const response = await apiFetch(`${API_BASE}/api/me/submissions/${encodeURIComponent(id)}`);
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
      const nextMeta: Record<string, { label: string; type: string }> = {};
      const order: string[] = [];
      fields.forEach((field: any) => {
        if (field?.id) {
          const id = String(field.id);
          order.push(id);
          nextMeta[id] = {
            label: field.label || id,
            type: field.type || "text"
          };
        }
      });
      setFieldMeta(nextMeta);
      setFieldOrder(order);
    }
    loadFormLabels();
    return () => {
      active = false;
    };
  }, [data?.form?.slug]);

  if (!user) {
    return (
      <section className="panel panel--error">
        <h2>Sign in required</h2>
        <p>Please sign in to view your submission.</p>
        <div className="auth-bar">
          <button type="button" className="btn btn-primary" onClick={() => onLogin("google")}>
            <i className="bi bi-google" aria-hidden="true" /> Login with Google
          </button>
          <button type="button" className="btn btn-outline-dark" onClick={() => onLogin("github")}>
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
      {data ? (
        <div className="panel panel--compact">
          <div className="d-flex justify-content-between align-items-center mb-2">
            <div>
              <div className="muted">Form</div>
              <div className="fw-semibold">{data.form?.title || data.form?.slug || "Form"}</div>
              {data.form?.slug ? <div className="muted">{data.form.slug}</div> : null}
            </div>
            <Link className="btn btn-outline-primary btn-sm" to={`/f/${data.form?.slug || ""}`}>
              Open form
            </Link>
          </div>
          <div className="muted">
            Submitted: {data.created_at ? formatTimeICT(data.created_at) : "n/a"}
          </div>
          <div className="muted">
            Updated: {data.updated_at ? formatTimeICT(data.updated_at) : "n/a"}
          </div>
          <div className="mt-3">
            <div className="muted mb-2">Data</div>
            {data.data_json && typeof data.data_json === "object" ? (
              <div className="table-responsive">
                <table className="table table-sm">
                  <tbody>
                  {Object.entries(data.data_json)
                    .filter(([key]) => fieldMeta[key]?.type !== "file")
                    .map(([key, value]) => (
                      <tr key={key}>
                        <th className="text-nowrap">{fieldMeta[key]?.label || key}</th>
                        <td className="text-break">
                          {typeof value === "string" || typeof value === "number" || typeof value === "boolean"
                            ? String(value)
                            : JSON.stringify(value)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="muted">No data</div>
            )}
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
                        <td>{fieldMeta[file.field_id]?.label || file.field_id}</td>
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
        </div>
      ) : null}
    </section>
  );
}

function AdminPage({
  user,
  onLogin,
  onNotice
}: {
  user: UserInfo | null;
  onLogin: (p: "google" | "github") => void;
  onNotice: (message: string, type?: NoticeType) => void;
}) {
  const [status, setStatus] = useState<"loading" | "ok" | "forbidden">("loading");
  const [forms, setForms] = useState<any[]>([]);
  const [templates, setTemplates] = useState<any[]>([]);
  const [users, setUsers] = useState<any[]>([]);
  const [uploads, setUploads] = useState<any[]>([]);
  const [exportError, setExportError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<string | null>(null);
  const [selectedSlug, setSelectedSlug] = useState<string>("");
  const [submissions, setSubmissions] = useState<any[]>([]);
  const [loadingSubmissions, setLoadingSubmissions] = useState(false);
  const [submissionsError, setSubmissionsError] = useState<string | null>(null);
  const [submissionActionError, setSubmissionActionError] = useState<string | null>(null);
  const [format, setFormat] = useState<"csv" | "txt">("csv");
  const [mode, setMode] = useState<"flat" | "json">("flat");
  const [includeMeta, setIncludeMeta] = useState(true);
  const [maxRows, setMaxRows] = useState(5000);
  const [copyStatus, setCopyStatus] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [uploadActionError, setUploadActionError] = useState<string | null>(null);
  const [bulkStatus, setBulkStatus] = useState<{ label: string; total: number; done: number } | null>(
    null
  );
  const [selectedForms, setSelectedForms] = useState<Set<string>>(new Set());
  const [selectedTemplates, setSelectedTemplates] = useState<Set<string>>(new Set());
  const [selectedUsers, setSelectedUsers] = useState<Set<string>>(new Set());
  const [selectedSubmissions, setSelectedSubmissions] = useState<Set<string>>(new Set());

  function startBulk(label: string, total: number) {
    setBulkStatus({ label, total, done: 0 });
  }

  function advanceBulk() {
    setBulkStatus((prev) => (prev ? { ...prev, done: Math.min(prev.done + 1, prev.total) } : prev));
  }

  function finishBulk(message?: string) {
    setBulkStatus(null);
    if (message) {
      onNotice(message);
    }
  }

  async function loadAdmin() {
    const healthRes = await apiFetch(`${API_BASE}/api/admin/health`);
    if (healthRes.status === 401 || healthRes.status === 403 || !healthRes.ok) {
      setStatus("forbidden");
      return;
    }
    setStatus("ok");

    const [formsRes, templatesRes, usersRes, uploadsRes] = await Promise.all([
      apiFetch(`${API_BASE}/api/admin/forms`),
      apiFetch(`${API_BASE}/api/admin/templates`),
      apiFetch(`${API_BASE}/api/admin/users`),
      apiFetch(`${API_BASE}/api/admin/uploads?limit=100`)
    ]);

    const formsPayload = formsRes.ok ? await formsRes.json().catch(() => null) : null;
    const formsList = Array.isArray(formsPayload?.data) ? formsPayload.data : [];
    setForms(formsList);
    if (!selectedSlug && formsList.length > 0) {
      const firstSlug = typeof formsList[0]?.slug === "string" ? formsList[0].slug : "";
      if (firstSlug) {
        setSelectedSlug(firstSlug);
      }
    }

    const templatesPayload = templatesRes.ok ? await templatesRes.json().catch(() => null) : null;
    setTemplates(Array.isArray(templatesPayload?.data) ? templatesPayload.data : []);

    const usersPayload = usersRes.ok ? await usersRes.json().catch(() => null) : null;
    setUsers(Array.isArray(usersPayload?.data) ? usersPayload.data : []);

    const uploadsPayload = uploadsRes.ok ? await uploadsRes.json().catch(() => null) : null;
    setUploads(Array.isArray(uploadsPayload?.data) ? uploadsPayload.data : []);

    setLastRefresh(new Date().toISOString());
  }

  async function loadSubmissionsForSlug(targetSlug: string) {
    if (!targetSlug || status !== "ok") return;
    setLoadingSubmissions(true);
    setSubmissionsError(null);
    const response = await apiFetch(
      `${API_BASE}/api/admin/submissions?formSlug=${encodeURIComponent(targetSlug)}&page=1&pageSize=10`
    );
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setSubmissionsError(payload?.error || "Failed to load submissions.");
      setLoadingSubmissions(false);
      return;
    }
    setSubmissions(Array.isArray(payload?.data) ? payload.data : []);
    setLoadingSubmissions(false);
  }

  useEffect(() => {
    let active = true;
    loadAdmin().catch(() => {
      if (active) setStatus("forbidden");
    });
    const timer = window.setInterval(() => {
      if (active && status === "ok") {
        loadAdmin().catch(() => null);
      }
    }, 15000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [status]);

  useEffect(() => {
    let active = true;
    loadSubmissionsForSlug(selectedSlug).catch(() => {
      if (active) {
        setSubmissionsError("Failed to load submissions.");
        setLoadingSubmissions(false);
      }
    });
    return () => {
      active = false;
    };
  }, [selectedSlug, status]);

  if (status === "loading") {
    return (
      <section className="panel">
        <h2>Loading admin...</h2>
      </section>
    );
  }

  if (status === "forbidden") {
    return (
      <section className="panel panel--error">
        <h2>Not authorized</h2>
        <p>Please sign in with an admin account.</p>
        <div className="auth-bar">
          <button type="button" className="btn btn-primary" onClick={() => onLogin("google")}>
            <i className="bi bi-google" aria-hidden="true" /> Login with Google
          </button>
          <button type="button" className="btn btn-outline-primary" onClick={() => onLogin("github")}>
            <i className="bi bi-github" aria-hidden="true" /> Login with GitHub
          </button>
        </div>
      </section>
    );
  }

  async function handleExport(slug: string, format: "csv" | "txt") {
    setExportError(null);
    try {
      const response = await apiFetch(buildFormSubmissionsExportUrl(slug, format));
      if (!response.ok) {
        const payload = await response.json().catch(() => null);
        setExportError(payload?.error || "Export failed");
        return;
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${slug}.${format}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (error) {
      setExportError(error instanceof Error ? error.message : "Export failed");
    }
  }

  function handleDownload(selectedFormat: "csv" | "txt") {
    if (!selectedSlug) return;
    const url = buildAdminExportUrl(selectedSlug, {
      format: selectedFormat,
      mode,
      includeMeta,
      maxRows: Math.min(Math.max(maxRows, 1), 50000)
    });
    window.open(url, "_blank");
  }

  async function handleCopyUrl() {
    if (!selectedSlug) return;
    const url = buildAdminExportUrl(selectedSlug, {
      format,
      mode,
      includeMeta,
      maxRows: Math.min(Math.max(maxRows, 1), 50000)
    });
    try {
      await navigator.clipboard.writeText(url);
      setCopyStatus("Copied.");
    } catch (error) {
      setCopyStatus("Copy failed.");
    }
    window.setTimeout(() => setCopyStatus(null), 2000);
  }

  function nextAuthPolicy(value: string | null | undefined) {
    const order = ["optional", "required", "google", "github", "either"];
    const current = value || "optional";
    const idx = order.indexOf(current);
    return order[(idx + 1) % order.length];
  }

  async function updateFormStatus(slug: string, patch: Record<string, unknown>) {
    setActionError(null);
    const response = await apiFetch(`${API_BASE}/api/admin/forms/${encodeURIComponent(slug)}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(patch)
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setActionError(payload?.error || "Failed to update form.");
      return false;
    }
    setForms((prev) =>
      prev.map((form) => (form.slug === slug ? { ...form, ...patch } : form))
    );
    return true;
  }

  async function updateTemplateStatus(key: string, patch: Record<string, unknown>) {
    setActionError(null);
    const response = await apiFetch(
      `${API_BASE}/api/admin/templates/${encodeURIComponent(key)}`,
      {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(patch)
      }
    );
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setActionError(payload?.error || "Failed to update template.");
      return false;
    }
    setTemplates((prev) =>
      prev.map((tpl) => (tpl.key === key ? { ...tpl, ...patch } : tpl))
    );
    return true;
  }

  async function handleDeleteForm(slug: string) {
    setActionError(null);
    if (!window.confirm(`Delete form "${slug}"? This cannot be undone.`)) {
      return;
    }
    const response = await apiFetch(`${API_BASE}/api/admin/forms/${encodeURIComponent(slug)}`, {
      method: "DELETE"
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setActionError(payload?.error || "Failed to delete form.");
      return;
    }
    setForms((prev) => prev.filter((form) => form.slug !== slug));
    if (selectedSlug === slug) {
      setSelectedSlug("");
    }
  }

  async function handleDeleteTemplate(key: string) {
    setActionError(null);
    if (!window.confirm(`Delete template "${key}"? This cannot be undone.`)) {
      return;
    }
    const response = await apiFetch(
      `${API_BASE}/api/admin/templates/${encodeURIComponent(key)}`,
      { method: "DELETE" }
    );
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setActionError(payload?.error || "Failed to delete template.");
      return;
    }
    setTemplates((prev) => prev.filter((tpl) => tpl.key !== key));
  }

  async function handleDeleteUser(userId: string) {
    setActionError(null);
    if (!window.confirm("Delete this user? This will soft-delete the account.")) {
      return;
    }
    const response = await apiFetch(`${API_BASE}/api/admin/users/${encodeURIComponent(userId)}`, {
      method: "DELETE"
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setActionError(payload?.error || "Failed to delete user.");
      return;
    }
    setUsers((prev) => prev.filter((user) => user.id !== userId));
  }

  async function handleDeleteUpload(uploadId: string) {
    setUploadActionError(null);
    if (!window.confirm("Delete this upload?")) {
      return;
    }
    const response = await apiFetch(`${API_BASE}/api/admin/uploads/${encodeURIComponent(uploadId)}`, {
      method: "DELETE"
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setUploadActionError(payload?.error || "Failed to delete upload.");
      return;
    }
    setUploads((prev) => prev.filter((item) => item.id !== uploadId));
  }

  function toggleSelected(setter: React.Dispatch<React.SetStateAction<Set<string>>>, id: string) {
    setter((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }

  function toggleAllSelected(
    setter: React.Dispatch<React.SetStateAction<Set<string>>>,
    ids: string[]
  ) {
    setter((prev) => {
      const next = new Set<string>();
      if (ids.some((id) => !prev.has(id))) {
        ids.forEach((id) => next.add(id));
      }
      return next;
    });
  }

  async function bulkDeleteForms() {
    const ids = Array.from(selectedForms);
    if (ids.length === 0) return;
    if (!window.confirm("Delete selected forms?")) return;
    setActionError(null);
    startBulk("Deleting forms", ids.length);
    for (const slug of ids) {
      const response = await apiFetch(`${API_BASE}/api/admin/forms/${encodeURIComponent(slug)}`, {
        method: "DELETE"
      });
      if (!response.ok) {
        setActionError(`Failed to delete form ${slug}.`);
        finishBulk();
        return;
      }
      advanceBulk();
    }
    setSelectedForms(new Set());
    await loadAdmin();
    finishBulk("Deleted selected forms.");
  }

  async function bulkDeleteTemplates() {
    const ids = Array.from(selectedTemplates);
    if (ids.length === 0) return;
    if (!window.confirm("Delete selected templates?")) return;
    setActionError(null);
    startBulk("Deleting templates", ids.length);
    for (const key of ids) {
      const response = await apiFetch(`${API_BASE}/api/admin/templates/${encodeURIComponent(key)}`, {
        method: "DELETE"
      });
      if (!response.ok) {
        setActionError(`Failed to delete template ${key}.`);
        finishBulk();
        return;
      }
      advanceBulk();
    }
    setSelectedTemplates(new Set());
    await loadAdmin();
    finishBulk("Deleted selected templates.");
  }

  async function bulkDeleteUsers() {
    const ids = Array.from(selectedUsers);
    if (ids.length === 0) return;
    if (!window.confirm("Delete selected users?")) return;
    setActionError(null);
    startBulk("Deleting users", ids.length);
    for (const id of ids) {
      const response = await apiFetch(`${API_BASE}/api/admin/users/${encodeURIComponent(id)}`, {
        method: "DELETE"
      });
      if (!response.ok) {
        setActionError(`Failed to delete user ${id}.`);
        finishBulk();
        return;
      }
      advanceBulk();
    }
    setSelectedUsers(new Set());
    await loadAdmin();
    finishBulk("Deleted selected users.");
  }

  async function bulkDeleteSubmissions() {
    const ids = Array.from(selectedSubmissions);
    if (ids.length === 0) return;
    if (!window.confirm("Delete selected submissions?")) return;
    setSubmissionActionError(null);
    startBulk("Deleting submissions", ids.length);
    for (const id of ids) {
      const response = await apiFetch(`${API_BASE}/api/admin/submissions/${encodeURIComponent(id)}`, {
        method: "DELETE"
      });
      if (!response.ok) {
        setSubmissionActionError(`Failed to delete submission ${id}.`);
        finishBulk();
        return;
      }
      advanceBulk();
    }
    setSelectedSubmissions(new Set());
    await loadSubmissionsForSlug(selectedSlug);
    finishBulk("Deleted selected submissions.");
  }


  async function handleDeleteSubmissionAdmin(submissionId: string) {
    setSubmissionActionError(null);
    if (!window.confirm("Delete this submission?")) {
      return;
    }
    const response = await apiFetch(
      `${API_BASE}/api/admin/submissions/${encodeURIComponent(submissionId)}`,
      { method: "DELETE" }
    );
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setSubmissionActionError(payload?.error || "Failed to delete submission.");
      return;
    }
    setSubmissions((prev) => prev.filter((row) => row.id !== submissionId));
  }


  const safeForms = Array.isArray(forms) ? forms.filter((form) => form && typeof form === "object") : [];
  const safeTemplates = Array.isArray(templates)
    ? templates.filter((tpl) => tpl && typeof tpl === "object")
    : [];
  const safeUsers = Array.isArray(users) ? users.filter((item) => item && typeof item === "object") : [];
  const safeUploads = Array.isArray(uploads)
    ? uploads.filter((item) => item && typeof item === "object")
    : [];
  const safeSubmissions = Array.isArray(submissions)
    ? submissions.filter((item) => item && typeof item === "object")
    : [];
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Admin</h2>
        {user ? <span className="badge">{user.email || user.userId}</span> : null}
      </div>
      {bulkStatus ? (
        <div className="alert alert-info">
          {bulkStatus.label}: {bulkStatus.done}/{bulkStatus.total}
        </div>
      ) : null}
      {actionError ? <div className="alert alert-warning">{actionError}</div> : null}
      {exportError ? <div className="alert alert-warning">{exportError}</div> : null}
      <div className="d-flex align-items-center gap-2 mb-3">
        <button type="button" className="btn btn-outline-primary btn-sm" onClick={() => loadAdmin()}>
          <i className="bi bi-arrow-clockwise" aria-hidden="true" /> Refresh
        </button>
        {lastRefresh ? <span className="muted">Last refresh: {formatTimeICT(lastRefresh)}</span> : null}
      </div>
      <div className="admin-grid">
        <div>
          <h3>Submissions</h3>
          <div className="panel panel--compact">
            <div className="row g-3">
              <div className="col-md-4">
                <label className="form-label">Form</label>
                <select
                  className="form-select"
                  value={selectedSlug}
                  onChange={(event) => setSelectedSlug(event.target.value)}
                >
                  <option value="">Select a form</option>
                  {safeForms
                    .filter((form) => form && typeof form.slug === "string")
                    .map((form) => (
                      <option key={form.slug} value={form.slug}>
                        {form.title} ({form.slug})
                      </option>
                    ))}
                </select>
              </div>
              <div className="col-md-2">
                <label className="form-label">Format</label>
                <select
                  className="form-select"
                  value={format}
                  onChange={(event) => setFormat(event.target.value as "csv" | "txt")}
                >
                  <option value="csv">CSV</option>
                  <option value="txt">TXT</option>
                </select>
              </div>
              <div className="col-md-2">
                <label className="form-label">Mode</label>
                <select
                  className="form-select"
                  value={mode}
                  onChange={(event) => setMode(event.target.value as "flat" | "json")}
                >
                  <option value="flat">Flat</option>
                  <option value="json">JSON</option>
                </select>
              </div>
              <div className="col-md-2">
                <label className="form-label">Include meta</label>
                <div className="form-check mt-2">
                  <input
                    className="form-check-input"
                    type="checkbox"
                    checked={includeMeta}
                    onChange={(event) => setIncludeMeta(event.target.checked)}
                    id="includeMetaToggle"
                  />
                  <label className="form-check-label" htmlFor="includeMetaToggle">
                    Yes
                  </label>
                </div>
              </div>
              <div className="col-md-2">
                <label className="form-label">Max rows</label>
                <input
                  className="form-control"
                  type="number"
                  min={1}
                  max={50000}
                  value={maxRows}
                  onChange={(event) => setMaxRows(Number(event.target.value))}
                />
              </div>
            </div>
            <div className="d-flex flex-wrap gap-2 mt-3">
              <button
                type="button"
                className="btn btn-primary"
                disabled={!selectedSlug}
                onClick={() => handleDownload(format)}
              >
                <i className="bi bi-download" aria-hidden="true" /> Download {format.toUpperCase()}
              </button>
              <button
                type="button"
                className="btn btn-outline-secondary"
                disabled={!selectedSlug}
                onClick={handleCopyUrl}
              >
                <i className="bi bi-link-45deg" aria-hidden="true" /> Copy export URL
              </button>
              {copyStatus ? <span className="muted align-self-center">{copyStatus}</span> : null}
            </div>
          </div>
          <div className="panel panel--compact">
            <div className="panel-header">
              <h3 className="mb-0">Recent submissions</h3>
              {loadingSubmissions ? <span className="badge">Loading...</span> : null}
            </div>
            {submissionsError ? <div className="alert alert-warning">{submissionsError}</div> : null}
            {submissionActionError ? (
              <div className="alert alert-warning">{submissionActionError}</div>
            ) : null}
            <div className="table-responsive">
              <table className="table table-sm">
                <thead>
                  <tr>
                    <th>
                      <input
                        type="checkbox"
                        className="form-check-input"
                        checked={
                          safeSubmissions.length > 0 &&
                          safeSubmissions.every((row) => row?.id && selectedSubmissions.has(row.id))
                        }
                        onChange={() =>
                          toggleAllSelected(
                            setSelectedSubmissions,
                            safeSubmissions.map((row) => row.id).filter(Boolean)
                          )
                        }
                      />
                    </th>
                    <th>ID</th>
                    <th>User</th>
                    <th>Provider</th>
                    <th>Created</th>
                    <th>Updated</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {safeSubmissions.length === 0 ? (
                    <tr>
                      <td colSpan={7}>No submissions found.</td>
                    </tr>
                  ) : (
                    safeSubmissions.map((row) => (
                      <tr key={row.id}>
                        <td>
                          <input
                            type="checkbox"
                            className="form-check-input"
                            checked={selectedSubmissions.has(row.id)}
                            onChange={() => toggleSelected(setSelectedSubmissions, row.id)}
                          />
                        </td>
                        <td className="text-break">
                          <Link to={`/me/submissions/${row.id}`} title="Open submission">
                            {row.id}
                          </Link>
                        </td>
                        <td>
                          {row.submitter_email || row.submitter_github_username || row.user_id || "n/a"}
                        </td>
                        <td>{row.submitter_provider || "n/a"}</td>
                        <td>{row.created_at ? formatTimeICT(row.created_at) : "n/a"}</td>
                        <td>{row.updated_at ? formatTimeICT(row.updated_at) : "n/a"}</td>
                        <td>
                          <button
                            type="button"
                            className="btn btn-outline-danger btn-sm"
                            onClick={() => handleDeleteSubmissionAdmin(row.id)}
                          >
                            <i className="bi bi-trash" aria-hidden="true" /> Delete
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
            <button
              type="button"
              className="btn btn-outline-danger btn-sm mt-2"
              disabled={selectedSubmissions.size === 0}
              onClick={bulkDeleteSubmissions}
            >
              <i className="bi bi-trash" aria-hidden="true" /> Delete selected
            </button>
          </div>
        </div>
        <div>
          <h3>Forms</h3>
          <div className="table-responsive">
            <table className="table table-sm">
              <thead>
                <tr>
                  <th>
                    <input
                      type="checkbox"
                      className="form-check-input"
                      checked={
                        safeForms.length > 0 &&
                        safeForms.every((item) => item?.slug && selectedForms.has(item.slug))
                      }
                      onChange={() =>
                        toggleAllSelected(
                          setSelectedForms,
                          safeForms.map((item) => item.slug).filter(Boolean)
                        )
                      }
                    />
                  </th>
                  <th>Slug</th>
                  <th>Title</th>
                  <th>Status</th>
                  <th>Export</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {safeForms
                  .filter((form) => form && typeof form.slug === "string")
                  .map((form) => (
                  <tr key={form.id || form.slug}>
                    <td>
                      <input
                        type="checkbox"
                        className="form-check-input"
                        checked={selectedForms.has(form.slug)}
                        onChange={() => toggleSelected(setSelectedForms, form.slug)}
                      />
                    </td>
                    <td>
                      <a href={`${PUBLIC_BASE}#/f/${form.slug}`} target="_blank" rel="noreferrer">
                        {form.slug}
                      </a>
                    </td>
                    <td>{form.title}</td>
                    <td>
                      <div className="status-badges status-badges--forms">
                        <span
                          className={`badge status-pill status-pill--lock border-0 ${
                            form.is_locked ? "text-bg-danger" : "text-bg-success"
                          }`}
                          role="button"
                          title="Click to toggle lock"
                          onClick={() => updateFormStatus(form.slug, { is_locked: !form.is_locked })}
                        >
                          <i className={`bi ${getLockIcon(form.is_locked)}`} aria-hidden="true" />{" "}
                          {form.is_locked ? "Locked" : "Unlocked"}
                        </span>
                        <span
                          className={`badge status-pill status-pill--visibility border-0 ${
                            form.is_public ? "text-bg-primary" : "text-bg-secondary"
                          }`}
                          role="button"
                          title="Click to toggle visibility"
                          onClick={() => updateFormStatus(form.slug, { is_public: !form.is_public })}
                        >
                          <i className={`bi ${getVisibilityIcon(form.is_public)}`} aria-hidden="true" />{" "}
                          {form.is_public ? "Public" : "Private"}
                        </span>
                        <span
                          className="badge status-pill status-pill--auth text-bg-info border-0"
                          title={
                            form.auth_policy === "required"
                              ? "Login required"
                              : form.auth_policy === "google"
                              ? "Google login required"
                              : form.auth_policy === "github"
                              ? "GitHub login required"
                              : form.auth_policy === "either"
                              ? "Google or GitHub login required"
                              : "Login optional"
                          }
                          role="button"
                          onClick={() =>
                            updateFormStatus(form.slug, {
                              auth_policy: nextAuthPolicy(form.auth_policy)
                            })
                          }
                        >
                          <i
                            className={`bi ${getAuthPolicyIcon(form.auth_policy)}`}
                            aria-hidden="true"
                          />{" "}
                          {getAuthPolicyLabel(form.auth_policy)}
                        </span>
                      </div>
                    </td>
                    <td>
                      <div className="btn-group btn-group-sm" role="group" aria-label="Export">
                        <button
                          type="button"
                          className="btn btn-outline-secondary"
                          onClick={() => handleExport(form.slug, "csv")}
                        >
                          <i className="bi bi-download" aria-hidden="true" /> CSV
                        </button>
                        <button
                          type="button"
                          className="btn btn-outline-secondary"
                          onClick={() => handleExport(form.slug, "txt")}
                        >
                          <i className="bi bi-download" aria-hidden="true" /> TXT
                        </button>
                      </div>
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn btn-outline-danger btn-sm"
                        onClick={() => handleDeleteForm(form.slug)}
                      >
                        <i className="bi bi-trash" aria-hidden="true" /> Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <button
            type="button"
            className="btn btn-outline-danger btn-sm mt-2"
            disabled={selectedForms.size === 0}
            onClick={bulkDeleteForms}
          >
            <i className="bi bi-trash" aria-hidden="true" /> Delete selected
          </button>
        </div>
        <div>
          <h3>Templates</h3>
          <div className="table-responsive">
            <table className="table table-sm">
              <thead>
                <tr>
                  <th>
                    <input
                      type="checkbox"
                      className="form-check-input"
                      checked={
                        safeTemplates.length > 0 &&
                        safeTemplates.every((item) => item?.key && selectedTemplates.has(item.key))
                      }
                      onChange={() =>
                        toggleAllSelected(
                          setSelectedTemplates,
                          safeTemplates.map((item) => item.key).filter(Boolean)
                        )
                      }
                    />
                  </th>
                  <th>Key</th>
                  <th>Name</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {safeTemplates
                  .filter((tpl) => tpl && typeof tpl.key === "string")
                  .map((tpl) => (
                  <tr key={tpl.id || tpl.key}>
                    <td>
                      <input
                        type="checkbox"
                        className="form-check-input"
                        checked={selectedTemplates.has(tpl.key)}
                        onChange={() => toggleSelected(setSelectedTemplates, tpl.key)}
                      />
                    </td>
                    <td>
                      <a
                        href={`${API_BASE}/api/admin/templates/${encodeURIComponent(tpl.key)}`}
                        target="_blank"
                        rel="noreferrer"
                      >
                        {tpl.key}
                      </a>
                    </td>
                    <td>{tpl.name}</td>
                    <td>
                      <button
                        type="button"
                        className="btn btn-outline-danger btn-sm"
                        onClick={() => handleDeleteTemplate(tpl.key)}
                      >
                        <i className="bi bi-trash" aria-hidden="true" /> Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <button
            type="button"
            className="btn btn-outline-danger btn-sm mt-2"
            disabled={selectedTemplates.size === 0}
            onClick={bulkDeleteTemplates}
          >
            <i className="bi bi-trash" aria-hidden="true" /> Delete selected
          </button>
        </div>
        <div>
          <h3>Users</h3>
          <div className="table-responsive">
            <table className="table table-sm">
              <thead>
                <tr>
                  <th>
                    <input
                      type="checkbox"
                      className="form-check-input"
                      checked={
                        safeUsers.length > 0 &&
                        safeUsers.every((item) => item?.id && selectedUsers.has(item.id))
                      }
                      onChange={() =>
                        toggleAllSelected(
                          setSelectedUsers,
                          safeUsers.map((item) => item.id).filter(Boolean)
                        )
                      }
                    />
                  </th>
                  <th>User ID</th>
                  <th>Email</th>
                  <th>GitHub</th>
                  <th>Admin</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {safeUsers.map((item) => (
                  <tr key={item.id}>
                    <td>
                      <input
                        type="checkbox"
                        className="form-check-input"
                        checked={selectedUsers.has(item.id)}
                        onChange={() => toggleSelected(setSelectedUsers, item.id)}
                      />
                    </td>
                    <td>{item.id}</td>
                    <td>{item.email || "n/a"}</td>
                    <td>{item.provider_login || "n/a"}</td>
                    <td>{String(item.is_admin)}</td>
                    <td>
                      <button
                        type="button"
                        className="btn btn-outline-danger btn-sm"
                        onClick={() => handleDeleteUser(item.id)}
                      >
                        <i className="bi bi-trash" aria-hidden="true" /> Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <button
            type="button"
            className="btn btn-outline-danger btn-sm mt-2"
            disabled={selectedUsers.size === 0}
            onClick={bulkDeleteUsers}
          >
            <i className="bi bi-trash" aria-hidden="true" /> Delete selected
          </button>
        </div>
        <div>
          <h3>Recent uploads</h3>
          <div className="table-responsive">
            {uploadActionError ? <div className="alert alert-warning">{uploadActionError}</div> : null}
            <table className="table table-sm">
              <thead>
                <tr>
                  <th>Form</th>
                  <th>User</th>
                  <th>Submission</th>
                  <th>Field</th>
                  <th>Name</th>
                  <th>Size</th>
                  <th>Uploaded</th>
                  <th>VirusTotal Status</th>
                  <th>Drive File</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {safeUploads.length === 0 ? (
                  <tr>
                    <td colSpan={12}>No uploads found.</td>
                  </tr>
                ) : (
                  safeUploads.map((item: any) => {
                    const statusLabel = item.vt_status || "unknown";
                    const reportUrl = item.sha256
                      ? `https://www.virustotal.com/gui/file/${item.sha256}`
                      : null;
                    const driveUrl = item.drive_web_view_link || null;
                    return (
                      <tr key={item.id}>
                        <td>
                          {item.form_slug ? (
                            <a href={`${PUBLIC_BASE}#/f/${item.form_slug}`} target="_blank" rel="noreferrer">
                              {item.form_slug}
                            </a>
                          ) : (
                            <span className="muted">n/a</span>
                          )}
                        </td>
                        <td>{item.submitter_display || "n/a"}</td>
                        <td>{item.submission_id}</td>
                        <td>{item.field_key}</td>
                        <td>{item.original_name}</td>
                        <td>{item.size_bytes}</td>
                        <td>{item.uploaded_at ? formatTimeICT(item.uploaded_at) : "n/a"}</td>
                        <td>
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
                        </td>
                        <td>
                          {driveUrl ? (
                            <a href={driveUrl} target="_blank" rel="noreferrer">
                              open
                            </a>
                          ) : (
                            <span className="muted">n/a</span>
                          )}
                        </td>
                        <td>
                          <button
                            type="button"
                            className="btn btn-outline-danger btn-sm"
                            onClick={() => handleDeleteUpload(item.id)}
                          >
                            <i className="bi bi-trash" aria-hidden="true" /> Delete
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
        <div>
        </div>
      </div>
    </section>
  );
}

function TrashPage({
  user,
  onLogin,
  onNotice
}: {
  user: UserInfo | null;
  onLogin: (provider: "google" | "github") => void;
  onNotice: (message: string, type?: NoticeType) => void;
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
        { value: "files", label: "Files" }
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
          <button type="button" className="btn btn-primary" onClick={() => onLogin("google")}>
            <i className="bi bi-google" aria-hidden="true" /> Login with Google
          </button>
          <button type="button" className="btn btn-outline-dark" onClick={() => onLogin("github")}>
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
    if (!response.ok) {
      const payload = await response.json().catch(() => null);
      setError(payload?.error || "Restore failed.");
      return;
    }
    onNotice("Item restored.", "success");
    await loadTrash();
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
    if (!response.ok) {
      const payload = await response.json().catch(() => null);
      setError(payload?.error || "Permanent delete failed.");
      return;
    }
    onNotice("Item deleted.", "success");
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
    if (!response.ok) {
      const payload = await response.json().catch(() => null);
      setError(payload?.error || "Empty trash failed.");
      setBulkStatus(null);
      return;
    }
    advanceBulk();
    finishBulk("Trash emptied.");
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
    for (const id of ids) {
      await purgeItem(toSingular(type), id);
      advanceBulk();
    }
    setSelected((prev) => ({ ...prev, [type]: new Set() }));
    finishBulk("Items deleted.");
  }

  const forms = Array.isArray(data.forms) ? data.forms : [];
  const templates = Array.isArray(data.templates) ? data.templates : [];
  const users = Array.isArray(data.users) ? data.users : [];
  const submissions = Array.isArray(data.submissions) ? data.submissions : [];
  const files = Array.isArray(data.files) ? data.files : [];

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
        <button
          type="button"
          className="btn btn-outline-danger btn-sm"
          disabled={(selected[type] ?? new Set()).size === 0}
          onClick={() => bulkPurge(type)}
        >
          <i className="bi bi-trash" aria-hidden="true" /> Delete selected
        </button>
      </div>
    );
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Trash</h2>
        {user ? <span className="badge">{user.email || user.userId}</span> : null}
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
        <button
          type="button"
          className="btn btn-outline-danger btn-sm ms-auto"
          onClick={emptyTrash}
        >
          <i className="bi bi-trash3" aria-hidden="true" /> Empty trash
        </button>
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
                    <td>{item.slug}</td>
                    <td>{item.deleted_at ? formatTimeICT(item.deleted_at) : "n/a"}</td>
                    <td>{item.deleted_reason || "n/a"}</td>
                    <td className="d-flex gap-2">
                      <button
                        type="button"
                        className="btn btn-outline-secondary btn-sm"
                        onClick={() => restoreItem("form", item.slug)}
                      >
                        <i className="bi bi-arrow-counterclockwise" aria-hidden="true" /> Restore
                      </button>
                      <button
                        type="button"
                        className="btn btn-outline-danger btn-sm"
                        onClick={() => purgeItem("form", item.slug)}
                      >
                        <i className="bi bi-trash" aria-hidden="true" /> Delete
                      </button>
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
                    <td>{item.key}</td>
                    <td>{item.deleted_at ? formatTimeICT(item.deleted_at) : "n/a"}</td>
                    <td>{item.deleted_reason || "n/a"}</td>
                    <td className="d-flex gap-2">
                      <button
                        type="button"
                        className="btn btn-outline-secondary btn-sm"
                        onClick={() => restoreItem("template", item.key)}
                      >
                        <i className="bi bi-arrow-counterclockwise" aria-hidden="true" /> Restore
                      </button>
                      <button
                        type="button"
                        className="btn btn-outline-danger btn-sm"
                        onClick={() => purgeItem("template", item.key)}
                      >
                        <i className="bi bi-trash" aria-hidden="true" /> Delete
                      </button>
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
                    <td className="d-flex gap-2">
                      <button
                        type="button"
                        className="btn btn-outline-secondary btn-sm"
                        onClick={() => restoreItem("user", item.id)}
                      >
                        <i className="bi bi-arrow-counterclockwise" aria-hidden="true" /> Restore
                      </button>
                      <button
                        type="button"
                        className="btn btn-outline-danger btn-sm"
                        onClick={() => purgeItem("user", item.id)}
                      >
                        <i className="bi bi-trash" aria-hidden="true" /> Delete
                      </button>
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
                    <td>{item.id}</td>
                    <td>{item.form_slug || "n/a"}</td>
                    <td>{item.deleted_at ? formatTimeICT(item.deleted_at) : "n/a"}</td>
                    <td>{item.deleted_reason || "n/a"}</td>
                    <td className="d-flex gap-2">
                      <button
                        type="button"
                        className="btn btn-outline-secondary btn-sm"
                        onClick={() => restoreItem("submission", item.id)}
                      >
                        <i className="bi bi-arrow-counterclockwise" aria-hidden="true" /> Restore
                      </button>
                      <button
                        type="button"
                        className="btn btn-outline-danger btn-sm"
                        onClick={() => purgeItem("submission", item.id)}
                      >
                        <i className="bi bi-trash" aria-hidden="true" /> Delete
                      </button>
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
                    <td>{item.form_slug || "n/a"}</td>
                    <td>{item.submission_id || "n/a"}</td>
                    <td>{item.deleted_at ? formatTimeICT(item.deleted_at) : "n/a"}</td>
                    <td>{item.deleted_reason || "n/a"}</td>
                    <td className="d-flex gap-2">
                      <button
                        type="button"
                        className="btn btn-outline-secondary btn-sm"
                        onClick={() => restoreItem("file", item.id)}
                      >
                        <i className="bi bi-arrow-counterclockwise" aria-hidden="true" /> Restore
                      </button>
                      <button
                        type="button"
                        className="btn btn-outline-danger btn-sm"
                        onClick={() => purgeItem("file", item.id)}
                      >
                        <i className="bi bi-trash" aria-hidden="true" /> Delete
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
          {renderBulkControls("files", files.map((item: any) => item.id).filter(Boolean))}
        </div>
      ) : null}
    </section>
  );
}

function BuilderPage({
  user,
  onLogin
}: {
  user: UserInfo | null;
  onLogin: (p: "google" | "github") => void;
}) {
  const [status, setStatus] = useState<"loading" | "ok" | "forbidden">("loading");
  const [forms, setForms] = useState<any[]>([]);
  const [templates, setTemplates] = useState<any[]>([]);
  const [lastRefresh, setLastRefresh] = useState<string | null>(null);
  const [templateEditorKey, setTemplateEditorKey] = useState("");
  const [templateEditorName, setTemplateEditorName] = useState("");
  const [templateEditorSchema, setTemplateEditorSchema] = useState("");
  const [templateEditorStatus, setTemplateEditorStatus] = useState<string | null>(null);
  const [templateBuilderMode, setTemplateBuilderMode] = useState<"create" | "edit">("edit");
  const [builderType, setBuilderType] = useState("text");
  const [builderCustomType, setBuilderCustomType] = useState("");
  const [builderId, setBuilderId] = useState("");
  const [builderLabel, setBuilderLabel] = useState("");
  const [builderRequired, setBuilderRequired] = useState(false);
  const [builderPlaceholder, setBuilderPlaceholder] = useState("");
  const [builderOptions, setBuilderOptions] = useState("");
  const [builderMultiple, setBuilderMultiple] = useState(false);
  const [builderEmailDomain, setBuilderEmailDomain] = useState("");
  const [builderAutofillFromLogin, setBuilderAutofillFromLogin] = useState(false);
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
  const [formBuilderSchema, setFormBuilderSchema] = useState("");
  const [formBuilderStatus, setFormBuilderStatus] = useState<string | null>(null);
  const [formBuilderDescription, setFormBuilderDescription] = useState("");
  const [formBuilderPublic, setFormBuilderPublic] = useState(true);
  const [formBuilderLocked, setFormBuilderLocked] = useState(false);
  const [formBuilderAuthPolicy, setFormBuilderAuthPolicy] = useState("optional");
  const [formBuilderMode, setFormBuilderMode] = useState<"create" | "edit">("edit");
  const [formFieldType, setFormFieldType] = useState("text");
  const [formFieldCustomType, setFormFieldCustomType] = useState("");
  const [formFieldId, setFormFieldId] = useState("");
  const [formFieldLabel, setFormFieldLabel] = useState("");
  const [formFieldRequired, setFormFieldRequired] = useState(false);
  const [formFieldPlaceholder, setFormFieldPlaceholder] = useState("");
  const [formFieldOptions, setFormFieldOptions] = useState("");
  const [formFieldMultiple, setFormFieldMultiple] = useState(false);
  const [formEmailDomain, setFormEmailDomain] = useState("");
  const [formAutofillFromLogin, setFormAutofillFromLogin] = useState(false);
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
  const [formCreateAuthPolicy, setFormCreateAuthPolicy] = useState("optional");
  const [formCreatePublic, setFormCreatePublic] = useState(true);
  const [formCreateLocked, setFormCreateLocked] = useState(false);
  const [formCreateStatus, setFormCreateStatus] = useState<string | null>(null);

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

  useEffect(() => {
    let active = true;
    loadBuilder().catch(() => {
      if (active) setStatus("forbidden");
    });
    return () => {
      active = false;
    };
  }, []);

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
          <button type="button" className="btn btn-primary" onClick={() => onLogin("google")}>
            <i className="bi bi-google" aria-hidden="true" /> Login with Google
          </button>
          <button type="button" className="btn btn-outline-primary" onClick={() => onLogin("github")}>
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
    const response = await apiFetch(
      `${API_BASE}/api/admin/templates/${encodeURIComponent(templateEditorKey)}`,
      {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
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
    await loadBuilder();
  }

  function handleAddField() {
    const nextSchema = applyAddFieldToSchema(templateEditorSchema, {
      type: builderType,
      customType: builderCustomType,
      id: builderId,
      label: builderLabel,
      required: builderRequired,
      placeholder: builderPlaceholder,
      options: builderOptions,
      multiple: builderMultiple,
      emailDomain: builderEmailDomain,
      autofillFromLogin: builderAutofillFromLogin
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
    setBuilderPlaceholder("");
    setBuilderOptions("");
    setBuilderMultiple(false);
    setBuilderEmailDomain("");
    setBuilderAutofillFromLogin(false);
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
      ["text", "full_name", "email", "github_username", "date", "number", "textarea", "select", "checkbox"].includes(type)
        ? type
        : "custom"
    );
    setBuilderCustomType(
      ["text", "full_name", "email", "github_username", "date", "number", "textarea", "select", "checkbox"].includes(type)
        ? ""
        : type
    );
    setBuilderId(String(field.id || ""));
    setBuilderLabel(String(field.label || ""));
    setBuilderRequired(Boolean(field.required));
    setBuilderPlaceholder(String(field.placeholder || ""));
    const options = Array.isArray((field as any).options) ? (field as any).options : [];
    setBuilderOptions(options.join(","));
    setBuilderMultiple(Boolean((field as any).multiple));
    setBuilderEmailDomain(type === "email" ? String(domain) : "");
    setBuilderAutofillFromLogin(
      type === "email" || type === "github_username" ? Boolean(rules.autofill) : false
    );
  }

  function handleUpdateTemplateField() {
    const nextSchema = updateFieldInSchemaText(templateEditorSchema, templateFieldEditId, {
      type: builderType,
      customType: builderCustomType,
      id: builderId,
      label: builderLabel,
      required: builderRequired,
      placeholder: builderPlaceholder,
      options: builderOptions,
      multiple: builderMultiple,
      emailDomain: builderEmailDomain,
      autofillFromLogin: builderAutofillFromLogin
    });
    if (nextSchema.error) {
      setTemplateEditorStatus(nextSchema.error);
      return;
    }
    if (nextSchema.text) {
      setTemplateEditorSchema(nextSchema.text);
    }
    setTemplateEditorStatus("Field updated.");
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
      return;
    }
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
      setFormBuilderPublic(Boolean(selected.is_public));
      setFormBuilderLocked(Boolean(selected.is_locked));
      setFormBuilderAuthPolicy(String(selected.auth_policy || "optional"));
    }
  }

  async function handleUpdateFormSchema() {
    setFormBuilderStatus(null);
    if (!formBuilderSlug) {
      setFormBuilderStatus("Select a form to update.");
      return;
    }
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
    const response = await apiFetch(`${API_BASE}/api/admin/forms/${encodeURIComponent(formBuilderSlug)}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ schema_json: formBuilderSchema })
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setFormBuilderStatus(payload?.error || "Failed to update form.");
      return;
    }
    setFormBuilderStatus("Form schema updated.");
    await loadBuilder();
  }

  async function handleUpdateFormSettings() {
    setFormBuilderStatus(null);
    if (!formBuilderSlug) {
      setFormBuilderStatus("Select a form to update.");
      return;
    }
    const response = await apiFetch(`${API_BASE}/api/admin/forms/${encodeURIComponent(formBuilderSlug)}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        description: formBuilderDescription || null,
        is_public: formBuilderPublic,
        is_locked: formBuilderLocked,
        auth_policy: formBuilderAuthPolicy
      })
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setFormBuilderStatus(payload?.error || "Failed to update form settings.");
      return;
    }
    setFormBuilderStatus("Form settings updated.");
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
      placeholder: formFieldPlaceholder,
      options: formFieldOptions,
      multiple: formFieldMultiple,
      emailDomain: formEmailDomain,
      autofillFromLogin: formAutofillFromLogin
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
    setFormFieldPlaceholder("");
    setFormFieldOptions("");
    setFormFieldMultiple(false);
    setFormEmailDomain("");
    setFormAutofillFromLogin(false);
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
      ["text", "full_name", "email", "github_username", "date", "number", "textarea", "select", "checkbox"].includes(type)
        ? type
        : "custom"
    );
    setFormFieldCustomType(
      ["text", "full_name", "email", "github_username", "date", "number", "textarea", "select", "checkbox"].includes(type)
        ? ""
        : type
    );
    setFormFieldId(String(field.id || ""));
    setFormFieldLabel(String(field.label || ""));
    setFormFieldRequired(Boolean(field.required));
    setFormFieldPlaceholder(String(field.placeholder || ""));
    const options = Array.isArray((field as any).options) ? (field as any).options : [];
    setFormFieldOptions(options.join(","));
    setFormFieldMultiple(Boolean((field as any).multiple));
    setFormEmailDomain(type === "email" ? String(domain) : "");
    setFormAutofillFromLogin(
      type === "email" || type === "github_username" ? Boolean(rules.autofill) : false
    );
  }

  function handleUpdateFormField() {
    const nextSchema = updateFieldInSchemaText(formBuilderSchema, formFieldEditId, {
      type: formFieldType,
      customType: formFieldCustomType,
      id: formFieldId,
      label: formFieldLabel,
      required: formFieldRequired,
      placeholder: formFieldPlaceholder,
      options: formFieldOptions,
      multiple: formFieldMultiple,
      emailDomain: formEmailDomain,
      autofillFromLogin: formAutofillFromLogin
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
    if (!formCreateSlug || !formCreateTitle || !formCreateTemplateKey) {
      setFormCreateStatus("Slug, title, and template are required.");
      return;
    }
    const response = await apiFetch(`${API_BASE}/api/admin/forms`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        slug: formCreateSlug,
        title: formCreateTitle,
        templateKey: formCreateTemplateKey,
        description: formCreateDescription || null,
        is_public: formCreatePublic,
        is_locked: formCreateLocked,
        auth_policy: formCreateAuthPolicy
      })
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      setFormCreateStatus(payload?.error || "Failed to create form.");
      return;
    }
    setFormCreateStatus("Form created.");
    setFormCreateSlug("");
    setFormCreateTitle("");
    setFormCreateDescription("");
    setFormCreateLocked(false);
    await loadBuilder();
  }

  const safeForms = Array.isArray(forms) ? forms.filter((form) => form && typeof form === "object") : [];
  const safeTemplates = Array.isArray(templates)
    ? templates.filter((tpl) => tpl && typeof tpl === "object")
    : [];
  const parsedTemplateSchema = parseSchemaText(templateEditorSchema);
  const schemaFields = Array.isArray(parsedTemplateSchema.fields)
    ? (parsedTemplateSchema.fields as Array<Record<string, unknown>>)
    : [];
  const templateTextFields = schemaFields.filter((field) => field.type !== "file");
  const templateFileFields = schemaFields.filter((field) => field.type === "file");
  const templateRulesError = validateFileRulesInSchema(parsedTemplateSchema.schema);
  const parsedFormSchema = parseSchemaText(formBuilderSchema);
  const formSchemaFields = Array.isArray(parsedFormSchema.fields)
    ? (parsedFormSchema.fields as Array<Record<string, unknown>>)
    : [];
  const formTextFields = formSchemaFields.filter((field) => field.type !== "file");
  const formFileFields = formSchemaFields.filter((field) => field.type === "file");
  const formRulesError = validateFileRulesInSchema(parsedFormSchema.schema);

  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Builder</h2>
        {user ? <span className="badge">{user.email || user.userId}</span> : null}
      </div>
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
                    setFormBuilderSchema("");
                    setFormBuilderStatus(null);
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
                </div>
                <div className="col-md-4">
                  <label className="form-label">Template</label>
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
                </div>
                <div className="col-md-6">
                  <label className="form-label">Description</label>
                  <input
                    className="form-control"
                    value={formCreateDescription}
                    onChange={(event) => setFormCreateDescription(event.target.value)}
                  />
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
                <label className="form-label">Description</label>
                <input
                  className="form-control"
                  value={formBuilderDescription}
                  onChange={(event) => setFormBuilderDescription(event.target.value)}
                  disabled={!formBuilderSlug}
                />
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
                  builderPlaceholder={formFieldPlaceholder}
                  builderOptions={formFieldOptions}
                  builderMultiple={formFieldMultiple}
                  builderEmailDomain={formEmailDomain}
                  builderAutofillFromLogin={formAutofillFromLogin}
                  onTypeChange={setFormFieldType}
                  onCustomTypeChange={setFormFieldCustomType}
                  onIdChange={setFormFieldId}
                  onLabelChange={setFormFieldLabel}
                  onRequiredChange={setFormFieldRequired}
                  onPlaceholderChange={setFormFieldPlaceholder}
                  onOptionsChange={setFormFieldOptions}
                  onMultipleChange={setFormFieldMultiple}
                  onEmailDomainChange={setFormEmailDomain}
                  onAutofillFromLoginChange={setFormAutofillFromLogin}
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
                className="btn btn-outline-primary"
                onClick={handleCopyFormLink}
                disabled={!formBuilderSlug}
              >
                <i className="bi bi-link-45deg" aria-hidden="true" /> Copy form link
              </button>
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
          <div className="panel panel--compact">
            <div className="d-flex flex-wrap gap-2 mb-3">
              <div className="btn-group" role="group">
                <button
                  type="button"
                  className={`btn ${templateBuilderMode === "create" ? "btn-primary" : "btn-outline-primary"}`}
                  onClick={() => {
                    setTemplateBuilderMode("create");
                    setTemplateEditorKey("");
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
                  builderPlaceholder={builderPlaceholder}
                  builderOptions={builderOptions}
                  builderMultiple={builderMultiple}
                  builderEmailDomain={builderEmailDomain}
                  builderAutofillFromLogin={builderAutofillFromLogin}
                  onTypeChange={setBuilderType}
                  onCustomTypeChange={setBuilderCustomType}
                  onIdChange={setBuilderId}
                  onLabelChange={setBuilderLabel}
                  onRequiredChange={setBuilderRequired}
                  onPlaceholderChange={setBuilderPlaceholder}
                  onOptionsChange={setBuilderOptions}
                  onMultipleChange={setBuilderMultiple}
                  onEmailDomainChange={setBuilderEmailDomain}
                  onAutofillFromLoginChange={setBuilderAutofillFromLogin}
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
                <button
                  type="button"
                  className="btn btn-outline-secondary"
                  onClick={handleUpdateTemplate}
                  disabled={!templateEditorKey}
                >
                  <i className="bi bi-save" aria-hidden="true" /> Update template
                </button>
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
  const [routeKey, setRouteKey] = useState(0);
  const [toasts, setToasts] = useState<ToastNotice[]>([]);
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

  function handleLogout() {
    apiFetch(`${API_BASE}/auth/logout`).finally(() => {
      clearToken();
      setUser(null);
      setRouteKey((prev) => prev + 1);
      pushNotice("Logged out successfully.", "success");
      navigate("/", { replace: true });
    });
  }

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
              className={`alert shadow ${
                toast.type === "success"
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
      <nav className="navbar navbar-expand navbar-light bg-light rounded px-3 mb-4">
        <div className="navbar-nav me-auto">
          <Link className="nav-link" to="/">
            Home
          </Link>
          {user ? (
            <Link className="nav-link" to="/dashboard">
              My Dashboard
            </Link>
          ) : null}
          {user ? (
            <Link className="nav-link" to="/trash">
              Trash
            </Link>
          ) : null}
          {user ? (
            <Link className="nav-link" to="/account">
              Account
            </Link>
          ) : null}
          {user?.isAdmin ? (
            <Link className="nav-link" to="/admin">
              Admin Dashboard
            </Link>
          ) : null}
          {user?.isAdmin ? (
            <Link className="nav-link" to="/admin/builder">
              Builder
            </Link>
          ) : null}
        </div>
        <AuthBar user={user} onLogin={handleLogin} onLogout={handleLogout} />
      </nav>

      <Routes>
        <Route path="/" element={<HomePage forms={forms} loading={loading} error={error} user={user} />} />
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
          element={<FormRoute user={user} onLogin={handleLogin} onNotice={pushNotice} />}
        />
        <Route
          path="/me"
          element={<DashboardPage user={user} onLogin={handleLogin} />}
        />
        <Route
          path="/dashboard"
          element={<DashboardPage user={user} onLogin={handleLogin} />}
        />
        <Route
          path="/account"
          element={<AccountPage user={user} onLogin={handleLogin} onLogout={handleLogout} />}
        />
        <Route
          path="/me/submissions/:id"
          element={<SubmissionDetailPage user={user} onLogin={handleLogin} />}
        />
        <Route path="/docs" element={<DocsPage />} />
        <Route
          path="/admin"
          element={<AdminPage user={user} onLogin={handleLogin} onNotice={pushNotice} />}
        />
        <Route
          path="/trash"
          element={<TrashPage user={user} onLogin={handleLogin} onNotice={pushNotice} />}
        />
        <Route
          path="/admin/builder"
          element={
            user?.isAdmin ? (
              <BuilderPage user={user} onLogin={handleLogin} />
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
        <div>
          (c) {new Date().getFullYear()} {APP_INFO.author}. {APP_INFO.license}.{" "}
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
