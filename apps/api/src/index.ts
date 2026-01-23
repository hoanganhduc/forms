const BUILD_TIME = new Date().toISOString();
let EMAIL_LOGS_SOFT_DELETE: boolean | null = null;

type CorsHeaders = Record<string, string>;

interface Env {
  ALLOWED_ORIGIN?: string;
  GIT_SHA?: string;
  GIT_COMMIT?: string;
  BASE_URL_API?: string;
  BASE_URL_WEB?: string;
  JWT_SECRET?: string;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  GMAIL_SENDER_EMAIL?: string;
  GMAIL_REFRESH_TOKEN?: string;
  ADMIN_GOOGLE_SUB?: string;
  ADMIN_EMAIL?: string;
  ADMIN_GITHUB?: string;
  ADMIN_GITHUB_ID?: string;
  VT_API_KEY?: string;
  VT_STRICT?: string;
  INTERNAL_CRON_SECRET?: string;
  DRIVE_CLIENT_EMAIL?: string;
  DRIVE_PRIVATE_KEY?: string;
  DRIVE_SERVICE_ACCOUNT_JSON?: string;
  DRIVE_PARENT_FOLDER_ID?: string;
  DRIVE_SHARED_DRIVE_ID?: string;
  CANVAS_BASE_URL?: string;
  CANVAS_ACCOUNT_ID?: string;
  CANVAS_API_TOKEN?: string;
  DB: D1Database;
  OAUTH_KV: KVNamespace;
  form_app_files?: R2Bucket;
}

type FormListRow = {
  slug: string;
  title: string;
  is_locked: number;
  is_public: number;
  auth_policy?: string | null;
  canvas_enabled?: number | null;
  canvas_course_id?: string | null;
  available_from?: string | null;
  available_until?: string | null;
  password_required?: number | null;
  password_require_access?: number | null;
  password_require_submit?: number | null;
  save_all_versions?: number | null;
};

type FormDetailRow = {
  slug: string;
  title: string;
  description: string | null;
  is_locked: number;
  is_public: number;
  auth_policy: string;
  templateKey: string | null;
  templateVersion: number | null;
  schema_json: string | null;
  template_file_rules_json?: string | null;
  form_file_rules_json?: string | null;
  canvas_enabled?: number | null;
  canvas_course_id?: string | null;
  canvas_allowed_section_ids_json?: string | null;
  available_from?: string | null;
  available_until?: string | null;
  password_required?: number | null;
  password_require_access?: number | null;
  password_require_submit?: number | null;
  password_salt?: string | null;
  password_hash?: string | null;
  canvas_fields_position?: string | null;
  reminder_enabled?: number;
  reminder_frequency?: string | null;
  reminder_until?: string | null;
  save_all_versions?: number | null;
  submission_backup_enabled?: number | null;
  submission_backup_formats?: string | null;
};

type FormSubmissionRow = {
  id: string;
  auth_policy: string;
  is_locked: number;
  is_public: number;
};

type AdminFormRow = {
  id: string;
  slug: string;
  title: string;
  description: string | null;
  is_locked: number;
  is_public: number;
  auth_policy: string;
  templateKey: string | null;
  canvas_enabled?: number | null;
  canvas_course_id?: string | null;
  canvas_allowed_section_ids_json?: string | null;
  available_from?: string | null;
  available_until?: string | null;
  password_required?: number | null;
  password_require_access?: number | null;
  password_require_submit?: number | null;
  canvas_fields_position?: string | null;
  reminder_enabled?: number;
  reminder_frequency?: string | null;
  reminder_until?: string | null;
  save_all_versions?: number | null;
};

type TemplateRow = {
  id: string;
  key: string;
  schema_json: string;
  file_rules_json?: string | null;
};

type SubmissionRow = {
  id: string;
  form_id: string;
  form_slug: string;
  user_id: string | null;
  payload_json: string;
  created_at: string;
  created_ip?: string | null;
  created_user_agent?: string | null;
};

type SubmissionDetailRow = {
  id: string;
  payload_json: string;
  created_at: string;
  updated_at: string | null;
};

type SubmissionVersionRow = {
  id: string;
  submission_id: string;
  form_id: string;
  user_id: string | null;
  payload_json: string;
  version_number: number;
  created_at: string;
  created_by: string | null;
};

type FileRules = {
  enabled: boolean;
  maxFiles: number;
  maxSizeBytes: number;
  maxFileSizeBytes?: number;
  allowedExtensions: string[];
  required: boolean;
};

type FieldFileRule = {
  extensions: string[];
  maxBytes: number;
  maxFiles: number;
};

type FieldFileRules = {
  fields: Record<string, FieldFileRule>;
  defaultRule: FieldFileRule;
};

type UploadSessionRow = {
  id: string;
  form_id: string;
  form_slug: string;
  field_id: string;
  submission_id: string;
  user_id: string | null;
  original_name: string;
  content_type: string | null;
  size_bytes: number;
  sha256: string | null;
  r2_key: string;
  status: string;
  file_item_id: string | null;
};

type UploadInitFile = {
  fieldKey: string;
  name: string;
  contentType?: string;
  size: number;
};

type UploadCompleteFile = {
  fieldKey: string;
  r2Key: string;
  name: string;
  contentType?: string;
  size: number;
  sha256?: string;
};

type IdentityRow = {
  userId: string;
  isAdmin: number;
};

type JwtPayload = {
  userId: string;
  provider: "google" | "github";
  email?: string | null;
  sub: string;
  isAdmin: boolean;
  iat: number;
  exp: number;
};

const TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7;
const OAUTH_STATE_TTL_SECONDS = 60 * 10;
const UPLOAD_TOKEN_TTL_SECONDS = 60 * 15;
const VT_POLL_TIMEOUT_MS = 20000;

function parseAllowedOrigins(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(",")
    .map((origin) => origin.trim())
    .filter((origin) => origin.length > 0);
}

const APP_SETTING_DEFAULT_TIMEZONE = "timezone_default";
const APP_SETTING_CANVAS_COURSE_SYNC_MODE = "canvas_course_sync_mode";
const APP_SETTING_CANVAS_DELETE_SYNC = "canvas_delete_sync";
const APP_SETTING_MARKDOWN_ENABLED = "markdown_enabled";
const APP_SETTING_MATHJAX_ENABLED = "mathjax_enabled";

async function getAppSetting(env: Env, key: string): Promise<string | null> {
  try {
    const row = await env.DB.prepare("SELECT value FROM app_settings WHERE key=?")
      .bind(key)
      .first<{ value: string }>();
    return row?.value ?? null;
  } catch {
    return null;
  }
}

async function setAppSetting(env: Env, key: string, value: string): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, datetime('now')) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=datetime('now')"
  )
    .bind(key, value)
    .run();
}

async function deleteAppSetting(env: Env, key: string): Promise<void> {
  await env.DB.prepare("DELETE FROM app_settings WHERE key=?").bind(key).run();
}

function getCorsHeaders(request: Request, env: Env): CorsHeaders {
  const origin = request.headers.get("Origin");
  if (!origin) return {};

  const allowedOrigins = parseAllowedOrigins(env.ALLOWED_ORIGIN);
  if (!allowedOrigins.includes(origin)) return {};

  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers": "authorization, content-type",
    "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    Vary: "Origin"
  };
}

function jsonResponse(
  status: number,
  body: unknown,
  requestId: string,
  extraHeaders: CorsHeaders
) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      "x-request-id": requestId,
      ...extraHeaders
    }
  });
}

function errorResponse(
  status: number,
  message: string,
  requestId: string,
  extraHeaders: CorsHeaders,
  detail?: unknown
) {
  const body: Record<string, unknown> = { error: message, requestId };
  if (detail !== undefined) {
    body.detail = detail;
  }
  return jsonResponse(status, body, requestId, extraHeaders);
}

function toBoolean(value: number | null): boolean {
  return value ? value !== 0 : false;
}

async function hasColumn(env: Env, table: string, column: string): Promise<boolean> {
  if (!/^[a-zA-Z0-9_]+$/.test(table) || !/^[a-zA-Z0-9_]+$/.test(column)) {
    return false;
  }
  const row = await env.DB.prepare(
    `SELECT 1 FROM pragma_table_info('${table}') WHERE name=? LIMIT 1`
  )
    .bind(column)
    .first<{ "1": number }>();
  return Boolean(row);
}

async function hasEmailLogsSoftDelete(env: Env): Promise<boolean> {
  if (EMAIL_LOGS_SOFT_DELETE === null) {
    EMAIL_LOGS_SOFT_DELETE = await hasColumn(env, "email_logs", "deleted_at");
    if (EMAIL_LOGS_SOFT_DELETE) {
      try {
        await env.DB.prepare("SELECT deleted_at FROM email_logs LIMIT 1").first();
      } catch {
        EMAIL_LOGS_SOFT_DELETE = false;
      }
    }
  }
  return EMAIL_LOGS_SOFT_DELETE;
}

async function parseJsonBody<T>(request: Request): Promise<T> {
  return (await request.json()) as T;
}

async function resolveUserId(env: Env, authPayload: JwtPayload | null): Promise<string | null> {
  if (!authPayload?.userId) return null;
  const row = await env.DB.prepare("SELECT id FROM users WHERE id=? AND deleted_at IS NULL")
    .bind(authPayload.userId)
    .first<{ id: string }>();
  return row ? authPayload.userId : null;
}

function toNumber(value: string | null, fallback: number): number {
  if (!value) return fallback;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

async function hashSha256(buffer: ArrayBuffer) {
  const hash = await crypto.subtle.digest("SHA-256", buffer);
  const bytes = Array.from(new Uint8Array(hash));
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
}

function parseIsoTime(value: string | null | undefined): number | null {
  if (!value) return null;
  const time = Date.parse(value);
  return Number.isNaN(time) ? null : time;
}

function normalizeDateTimeInput(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  const time = parseIsoTime(trimmed);
  if (!time) return null;
  return new Date(time).toISOString();
}

function getFormAvailability(form: {
  available_from?: string | null;
  available_until?: string | null;
  is_locked?: number | boolean;
}) {
  if (toBoolean(typeof form.is_locked === 'number' ? form.is_locked : (form.is_locked ? 1 : 0))) {
    return { open: false, reason: "locked" as const };
  }
  const now = Date.now();
  const start = parseIsoTime(form.available_from);
  const end = parseIsoTime(form.available_until);
  if (start && now < start) {
    return { open: false, reason: "not_started" as const };
  }
  if (end && now > end) {
    return { open: false, reason: "ended" as const };
  }
  return { open: true as const, reason: null };
}

async function hashPasswordWithSalt(password: string, salt: string) {
  const encoder = new TextEncoder();
  const buffer = encoder.encode(`${salt}:${password}`);
  return hashSha256(buffer.buffer as ArrayBuffer);
}

async function verifyFormPassword(
  form: {
    password_required?: number | null;
    password_require_access?: number | null;
    password_require_submit?: number | null;
    password_salt?: string | null;
    password_hash?: string | null;
  },
  rawPassword: string | null | undefined,
  action: "access" | "submit" = "submit"
) {
  const requireAccess = toBoolean(form.password_require_access ?? 0);
  let requireSubmit = toBoolean(form.password_require_submit ?? 0);
  const legacyRequired = toBoolean(form.password_required ?? 0);
  if (!requireAccess && !requireSubmit && legacyRequired) {
    requireSubmit = true;
  }
  const required = action === "access" ? requireAccess : requireSubmit;
  if (!required) {
    return { ok: true };
  }
  if (!rawPassword) {
    return { ok: false, message: "password_required" as const };
  }
  if (!form.password_salt || !form.password_hash) {
    return { ok: false, message: "password_not_configured" as const };
  }
  const hashed = await hashPasswordWithSalt(rawPassword, form.password_salt);
  if (hashed !== form.password_hash) {
    return { ok: false, message: "invalid_password" as const };
  }
  return { ok: true };
}

function sanitizeFilename(name: string) {
  return name.replace(/[/\\?%*:|"<>]/g, "_").slice(0, 150);
}

async function parseSubmissionRequest(request: Request): Promise<{
  formSlug?: string;
  data?: Record<string, unknown>;
  files?: Array<{ fieldKey: string; file: File }>;
  uploads?: UploadCompleteFile[];
  fileRefs?: Array<{ fieldKey: string; uploadId: string }>;
  formPassword?: string;
}> {
  const contentType = request.headers.get("content-type") || "";
  if (contentType.includes("multipart/form-data")) {
    const formData = await request.formData();
    const files: Array<{ fieldKey: string; file: File }> = [];
    const dataFields: Record<string, unknown> = {};
    let dataJson: Record<string, unknown> | null = null;
    let formSlug: string | undefined;
    let formPassword: string | undefined;

    for (const [key, value] of formData.entries()) {
      if (key === "formSlug" && typeof value === "string") {
        formSlug = value;
        continue;
      }
      if (key === "formPassword" && typeof value === "string") {
        formPassword = value;
        continue;
      }
      if (key === "data" && typeof value === "string") {
        try {
          dataJson = JSON.parse(value);
        } catch (error) {
          dataJson = null;
        }
        continue;
      }
      const dataMatch = key.match(/^data\[(.+)\]$/);
      if (dataMatch && typeof value === "string") {
        dataFields[dataMatch[1]] = value;
        continue;
      }
      if (typeof value === 'object' && value !== null && 'size' in value && 'type' in value) {
        let fieldKey = "";
        if (key.startsWith("file:")) {
          fieldKey = key.slice("file:".length);
        } else if (key === "files" || key === "files[]") {
          fieldKey = "files";
        }
        if (fieldKey) {
          files.push({ fieldKey, file: value });
        }
      }
    }

    return {
      formSlug,
      data: dataJson ?? dataFields,
      files,
      formPassword
    };
  }

  const body = await parseJsonBody<{
    formSlug?: string;
    data?: Record<string, unknown>;
    uploads?: UploadCompleteFile[];
    fileRefs?: Array<{ fieldKey: string; uploadId: string }>;
    formPassword?: string;
  }>(request);
  return {
    formSlug: body?.formSlug,
    data: body?.data,
    uploads: body?.uploads,
    files: [],
    fileRefs: body?.fileRefs,
    formPassword: body?.formPassword
  };
}

function extractFields(schema: unknown): Array<{
  id: string;
  label: string;
  type: string;
  required: boolean;
  rules?: Record<string, unknown>;
  placeholder?: string;
  options?: string[];
  multiple?: boolean;
  description?: string;
}> {
  if (!schema || typeof schema !== "object") return [];
  const fields = (schema as { fields?: unknown }).fields;
  if (!Array.isArray(fields)) return [];
  const filtered = fields
    .map((field) => {
      if (!field || typeof field !== "object") return null;
      const record = field as Record<string, unknown>;
      const id = typeof record.id === "string" ? record.id : "";
      const label = typeof record.label === "string" ? record.label : id;
      const description = typeof record.description === "string" ? record.description : undefined;
      const type = typeof record.type === "string" ? record.type : "text";
      const required = Boolean(record.required);
      const placeholder =
        typeof record.placeholder === "string" && record.placeholder.trim()
          ? record.placeholder
          : undefined;
      const rules = record.rules && typeof record.rules === "object" ? (record.rules as Record<string, unknown>) : undefined;
      const options = Array.isArray(record.options)
        ? record.options.filter((option) => typeof option === "string")
        : undefined;
      const multiple = typeof record.multiple === "boolean" ? record.multiple : undefined;
      if (!id) return null;
      return { id, label, type, required, rules, placeholder, options, multiple, description };
    })
    .filter((field) => field !== null);
  return filtered as Array<{
    id: string;
    label: string;
    type: string;
    required: boolean;
    rules?: Record<string, unknown>;
    placeholder?: string;
    options?: string[];
    multiple?: boolean;
    description?: string;
  }>;
}

function normalizeRules(input: unknown): FileRules {
  const fallback: FileRules = {
    enabled: true,
    maxFiles: 3,
    maxSizeBytes: 10 * 1024 * 1024,
    maxFileSizeBytes: 10 * 1024 * 1024,
    allowedExtensions: [],
    required: false
  };
  if (!input || typeof input !== "object") return fallback;
  const record = input as Record<string, unknown>;
  const maxFileSizeBytes =
    typeof record.maxFileSizeBytes === "number"
      ? record.maxFileSizeBytes
      : typeof record.maxSizeBytes === "number"
        ? record.maxSizeBytes
        : fallback.maxFileSizeBytes!;
  return {
    enabled:
      typeof record.enabled === "boolean"
        ? record.enabled
        : Boolean(
          record.maxFiles ||
          record.maxFileSizeBytes ||
          record.maxSizeBytes ||
          record.allowedExtensions
        ) || fallback.enabled,
    maxFiles: typeof record.maxFiles === "number" ? record.maxFiles : fallback.maxFiles,
    maxSizeBytes: maxFileSizeBytes,
    maxFileSizeBytes,
    allowedExtensions: Array.isArray(record.allowedExtensions)
      ? record.allowedExtensions
        .map((ext) => (typeof ext === "string" ? ext.toLowerCase().replace(/^\./, "") : ""))
        .filter((ext) => ext.length > 0)
      : fallback.allowedExtensions,
    required: Boolean(record.required)
  };
}

function mergeRules(templateRules: FileRules, overrideRules?: FileRules | null): FileRules {
  if (!overrideRules) return templateRules;
  return {
    enabled: overrideRules.enabled ?? templateRules.enabled,
    maxFiles: overrideRules.maxFiles ?? templateRules.maxFiles,
    maxSizeBytes: overrideRules.maxSizeBytes ?? templateRules.maxSizeBytes,
    allowedExtensions:
      overrideRules.allowedExtensions.length > 0
        ? overrideRules.allowedExtensions
        : templateRules.allowedExtensions,
    required: overrideRules.required ?? templateRules.required
  };
}

function parseFieldRules(raw: string | null): FieldFileRules {
  const defaultRule: FieldFileRule = {
    extensions: [],
    maxBytes: 10 * 1024 * 1024,
    maxFiles: 3
  };
  if (!raw) {
    return { fields: {}, defaultRule };
  }
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const fields: Record<string, FieldFileRule> = {};
    if (parsed && typeof parsed === "object" && "fields" in parsed) {
      const fieldRules = (parsed as { fields?: Record<string, unknown> }).fields || {};
      Object.entries(fieldRules).forEach(([fieldId, value]) => {
        if (!value || typeof value !== "object") return;
        const record = value as Record<string, unknown>;
        const extensions = Array.isArray(record.extensions)
          ? record.extensions
            .map((ext) => (typeof ext === "string" ? ext.toLowerCase().replace(/^\./, "") : ""))
            .filter((ext) => ext.length > 0)
          : [];
        const maxBytes =
          typeof record.maxBytes === "number" && Number.isFinite(record.maxBytes)
            ? record.maxBytes
            : defaultRule.maxBytes;
        const maxFiles =
          typeof record.maxFiles === "number" && Number.isFinite(record.maxFiles)
            ? record.maxFiles
            : defaultRule.maxFiles;
        fields[fieldId] = { extensions, maxBytes, maxFiles };
      });
    }

    if (Object.keys(fields).length > 0) {
      return { fields, defaultRule };
    }

    if (parsed && typeof parsed === "object") {
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
      return {
        fields: {},
        defaultRule: {
          extensions,
          maxBytes,
          maxFiles
        }
      };
    }
  } catch (error) {
    return { fields: {}, defaultRule };
  }
  return { fields: {}, defaultRule };
}

function getFieldRule(rules: FieldFileRules, fieldId: string): FieldFileRule {
  return rules.fields[fieldId] || rules.defaultRule;
}

function extractFieldRulesFromSchema(schema: unknown): FieldFileRules {
  const defaultRule: FieldFileRule = {
    extensions: [],
    maxBytes: 10 * 1024 * 1024,
    maxFiles: 3
  };
  const fields: Record<string, FieldFileRule> = {};
  if (!schema || typeof schema !== "object") {
    return { fields, defaultRule };
  }
  const list = (schema as { fields?: unknown }).fields;
  if (!Array.isArray(list)) {
    return { fields, defaultRule };
  }
  list.forEach((field) => {
    if (!field || typeof field !== "object") return;
    const record = field as Record<string, unknown>;
    if (record.type !== "file") return;
    const fieldId = typeof record.id === "string" ? record.id : "";
    if (!fieldId) return;
    const rules =
      (record.rules && typeof record.rules === "object" ? record.rules : null) ||
      (record.fileRules && typeof record.fileRules === "object" ? record.fileRules : null) ||
      {};
    const ruleRecord = rules as Record<string, unknown>;
    const extensions = Array.isArray(ruleRecord.allowedExtensions)
      ? ruleRecord.allowedExtensions
        .map((ext) => (typeof ext === "string" ? ext.toLowerCase().replace(/^\./, "") : ""))
        .filter((ext) => ext.length > 0)
      : Array.isArray(ruleRecord.extensions)
        ? ruleRecord.extensions
          .map((ext) => (typeof ext === "string" ? ext.toLowerCase().replace(/^\./, "") : ""))
          .filter((ext) => ext.length > 0)
        : [];
    const maxBytes =
      typeof ruleRecord.maxFileSizeBytes === "number"
        ? ruleRecord.maxFileSizeBytes
        : typeof ruleRecord.maxBytes === "number"
          ? ruleRecord.maxBytes
          : typeof ruleRecord.maxSizeBytes === "number"
            ? ruleRecord.maxSizeBytes
            : defaultRule.maxBytes;
    const maxFiles =
      typeof ruleRecord.maxFiles === "number"
        ? ruleRecord.maxFiles
        : typeof ruleRecord.maxCount === "number"
          ? ruleRecord.maxCount
          : defaultRule.maxFiles;
    fields[fieldId] = { extensions, maxBytes, maxFiles };
  });
  return { fields, defaultRule };
}

function validateFileRulesFromSchema(schema: unknown): { fieldId: string; message: string } | null {
  if (!schema || typeof schema !== "object") return null;
  const list = (schema as { fields?: unknown }).fields;
  if (!Array.isArray(list)) return null;
  for (const field of list) {
    if (!field || typeof field !== "object") continue;
    const record = field as Record<string, unknown>;
    if (record.type !== "file") continue;
    const fieldId = typeof record.id === "string" ? record.id : "";
    const rules =
      (record.rules && typeof record.rules === "object" ? record.rules : null) ||
      (record.fileRules && typeof record.fileRules === "object" ? record.fileRules : null);
    if (!rules) continue;
    if (typeof rules !== "object" || Array.isArray(rules)) {
      return { fieldId, message: "invalid_rules" };
    }
    const ruleRecord = rules as Record<string, unknown>;
    const allowedExtensions = ruleRecord.allowedExtensions ?? ruleRecord.extensions;
    if (allowedExtensions !== undefined && !Array.isArray(allowedExtensions)) {
      return { fieldId, message: "invalid_extensions" };
    }
    if (Array.isArray(allowedExtensions)) {
      const invalid = allowedExtensions.some(
        (ext) => typeof ext !== "string" || ext.trim().length === 0
      );
      if (invalid) {
        return { fieldId, message: "invalid_extensions" };
      }
    }
    const maxBytes =
      ruleRecord.maxFileSizeBytes ??
      ruleRecord.maxBytes ??
      ruleRecord.maxSizeBytes;
    if (maxBytes !== undefined && (typeof maxBytes !== "number" || maxBytes <= 0)) {
      return { fieldId, message: "invalid_max_bytes" };
    }
    const maxFiles = ruleRecord.maxFiles ?? ruleRecord.maxCount;
    if (maxFiles !== undefined && (typeof maxFiles !== "number" || maxFiles <= 0)) {
      return { fieldId, message: "invalid_max_files" };
    }
  }
  return null;
}

function buildFileRulesJsonFromSchema(schemaJson: string | null): string | null {
  if (!schemaJson) return null;
  try {
    const parsed = JSON.parse(schemaJson);
    const rules = extractFieldRulesFromSchema(parsed);
    if (Object.keys(rules.fields).length === 0) return null;
    return JSON.stringify({ fields: rules.fields });
  } catch (error) {
    return null;
  }
}

async function handleSubmissionUploadInit(
  request: Request,
  env: Env,
  url: URL,
  requestId: string,
  corsHeaders: CorsHeaders,
  body: {
    formSlug?: string;
    fieldKey?: string;
    filename?: string;
    contentType?: string;
    sizeBytes?: number;
    sha256?: string;
    formPassword?: string;
  }
): Promise<Response> {
  // Create a draft submission (if needed) and a draft upload session for the file.
  if (
    !body?.formSlug ||
    !body.fieldKey ||
    !body.filename ||
    typeof body.sizeBytes !== "number"
  ) {
    return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
      message: "formSlug, fieldKey, filename, sizeBytes are required"
    });
  }

  if (!env.form_app_files) {
    return errorResponse(500, "uploads_unavailable", requestId, corsHeaders);
  }

  const formRow = await getFormWithRules(env, body.formSlug.trim());
  if (!formRow) {
    return errorResponse(404, "not_found", requestId, corsHeaders);
  }
  const availability = getFormAvailability(formRow);
  if (!availability.open) {
    return errorResponse(403, "form_closed", requestId, corsHeaders, {
      reason: availability.reason
    });
  }

  const authPayload = await getAuthPayload(request, env);
  const authCheck = checkAuthPolicy(formRow.auth_policy, authPayload);
  if (!authCheck.ok) {
    return errorResponse(authCheck.status!, authCheck.code!, requestId, corsHeaders);
  }

  const passwordCheck = await verifyFormPassword(
    {
      ...formRow,
      password_require_access: formRow.password_require_access as number | null,
      password_require_submit: formRow.password_require_submit as number | null
    },
    body.formPassword,
    "submit"
  );
  if (!passwordCheck.ok) {
    return errorResponse(403, "invalid_payload", requestId, corsHeaders, {
      field: "formPassword",
      message: passwordCheck.message
    });
  }

  let schema: unknown = null;
  if (formRow.schema_json) {
    try {
      schema = JSON.parse(formRow.schema_json);
    } catch (error) {
      return errorResponse(500, "invalid_schema", requestId, corsHeaders);
    }
  }
  const fields = extractFields(schema);
  const field = fields.find((item) => item.id === body.fieldKey);
  if (!field || field.type !== "file") {
    return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
      message: "invalid_field",
      fieldKey: body.fieldKey
    });
  }

  const rulesSource = formRow.form_file_rules_json ?? formRow.template_file_rules_json ?? null;
  const rules = parseFieldRules(rulesSource);
  const rule = getFieldRule(rules, body.fieldKey);
  if (rule.maxBytes && body.sizeBytes > rule.maxBytes) {
    return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
      message: "file_too_large",
      fieldKey: body.fieldKey,
      maxBytes: rule.maxBytes
    });
  }
  if (rule.extensions.length > 0) {
    const ext = getExtension(body.filename);
    if (!ext || !rule.extensions.includes(ext)) {
      return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
        message: "invalid_extension",
        fieldKey: body.fieldKey
      });
    }
  }

  const userId = await resolveUserId(env, authPayload);
  let submissionId: string | null = null;
  if (userId) {
    const existing = await env.DB.prepare(
      "SELECT id FROM submissions WHERE form_id=? AND user_id=? AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1"
    )
      .bind(formRow.id, userId)
      .first<{ id: string }>();
    if (existing?.id) {
      submissionId = existing.id;
    }
  }
  if (!submissionId) {
    submissionId = crypto.randomUUID();
    await env.DB.prepare(
      "INSERT INTO submissions (id, form_id, user_id, payload_json, canvas_course_id) VALUES (?, ?, ?, ?, ?)"
    )
      .bind(
        submissionId,
        formRow.id,
        userId,
        JSON.stringify({ data: {} }),
        formRow.canvas_course_id ?? null
      )
      .run();
  }

  const existingCount = await env.DB.prepare(
    "SELECT COUNT(1) as count FROM submission_file_items WHERE submission_id=? AND field_id=? AND deleted_at IS NULL"
  )
    .bind(submissionId, body.fieldKey)
    .first<{ count: number }>();
  const pendingCount = await env.DB.prepare(
    "SELECT COUNT(1) as count FROM submission_upload_sessions WHERE submission_id=? AND field_id=? AND status IN ('initialized','uploaded')"
  )
    .bind(submissionId, body.fieldKey)
    .first<{ count: number }>();
  const currentCount = (existingCount?.count ?? 0) + (pendingCount?.count ?? 0);
  if (rule.maxFiles && currentCount + 1 > rule.maxFiles) {
    return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
      message: "max_files_exceeded",
      fieldKey: body.fieldKey,
      maxFiles: rule.maxFiles
    });
  }

  const uploadId = crypto.randomUUID();
  const safeName = sanitizeFilename(body.filename);
  const r2Key = `drafts/${formRow.slug}/${submissionId}/${body.fieldKey}/${uploadId}-${safeName}`;
  await env.DB.prepare(
    "INSERT INTO submission_upload_sessions (id, form_id, form_slug, field_id, submission_id, user_id, original_name, content_type, size_bytes, sha256, r2_key, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'initialized')"
  )
    .bind(
      uploadId,
      formRow.id,
      formRow.slug,
      body.fieldKey,
      submissionId,
      userId,
      body.filename,
      body.contentType ?? null,
      body.sizeBytes,
      body.sha256 ?? null,
      r2Key
    )
    .run();

  const uploadUrl = `${url.origin}/api/submissions/upload/put?uploadId=${uploadId}`;
  return jsonResponse(
    200,
    { uploadId, r2Key, uploadUrl, submissionId, requestId },
    requestId,
    corsHeaders
  );
}

function getExtension(name: string) {
  const idx = name.lastIndexOf(".");
  if (idx === -1) return "";
  return name.slice(idx + 1).toLowerCase();
}

function csvEscape(value: string) {
  if (value.includes('"') || value.includes(",") || value.includes("\n") || value.includes("\r")) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

function formatExportTimestamp(value: Date) {
  const pad = (num: number) => String(num).padStart(2, "0");
  const year = value.getFullYear();
  const month = pad(value.getMonth() + 1);
  const day = pad(value.getDate());
  const hour = pad(value.getHours());
  const minute = pad(value.getMinutes());
  return `${year}${month}${day}_${hour}${minute}`;
}

function isMissingColumn(error: unknown, columnName: string) {
  const message = (error as { message?: string })?.message || String(error);
  return message.includes("no such column") && message.includes(columnName);
}

function stringifyCsvValue(value: unknown) {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value);
  } catch (error) {
    return String(value);
  }
}

function getRequestIp(request: Request): string | null {
  const cfIp = request.headers.get("cf-connecting-ip");
  if (cfIp) return cfIp;
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) return forwarded.split(",")[0].trim();
  return null;
}

function getSubmitterSnapshot(authPayload: JwtPayload | null) {
  if (!authPayload) {
    return { provider: null, email: null, github: null };
  }
  const provider = authPayload.provider;
  const email = authPayload.email ?? null;
  const github = authPayload.provider === "github" ? authPayload.sub : null;
  return { provider, email, github };
}

function normalizeEmailDomain(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim().toLowerCase().replace(/^@/, "");
  return trimmed ? trimmed : null;
}

function isValidGithubUsername(value: string): boolean {
  return /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$/.test(value);
}

function isValidHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function ensureUrlWithScheme(rawValue: string): string {
  const trimmed = rawValue.trim();
  if (!trimmed) return trimmed;
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed)) {
    return trimmed;
  }
  return `https://${trimmed}`;
}

async function githubUserExists(username: string): Promise<boolean> {
  const response = await fetch(`https://api.github.com/users/${encodeURIComponent(username)}`, {
    headers: {
      "user-agent": "form-app"
    }
  });
  if (response.status === 404) return false;
  if (!response.ok) {
    throw new Error(`github_lookup_failed:${response.status}`);
  }
  return true;
}

async function getGithubLoginForUser(env: Env, userId: string): Promise<string | null> {
  const row = await env.DB.prepare(
    "SELECT provider_login FROM user_identities WHERE user_id=? AND provider='github' ORDER BY created_at DESC LIMIT 1"
  )
    .bind(userId)
    .first<{ provider_login: string | null }>();
  return row?.provider_login ?? null;
}

async function getFormWithRules(env: Env, slug: string) {
  const baseColumns = [
    "id",
    "slug",
    "title",
    "description",
    "is_locked",
    "is_public",
    "auth_policy"
  ];
  const optionalColumns = [
    "canvas_enabled",
    "canvas_course_id",
    "canvas_allowed_section_ids_json",
    "canvas_fields_position",
    "available_from",
    "available_until",
    "password_required",
    "password_require_access",
    "password_require_submit",
    "password_salt",
    "password_hash",
    "reminder_enabled",
    "reminder_frequency",
    "save_all_versions"
  ];
  const columnSelects = baseColumns.map((column) => `f.${column}`);
  for (const column of optionalColumns) {
    const select = (await hasColumn(env, "forms", column)) ? `f.${column}` : `NULL as ${column}`;
    columnSelects.push(select);
  }
  const templateFileRulesSelect = (await hasColumn(env, "templates", "file_rules_json"))
    ? "t.file_rules_json as template_file_rules_json"
    : "NULL as template_file_rules_json";
  const formFileRulesSelect = (await hasColumn(env, "forms", "file_rules_json"))
    ? "f.file_rules_json as form_file_rules_json"
    : "NULL as form_file_rules_json";

  return env.DB.prepare(
    `SELECT ${columnSelects.join(",")},t.key as templateKey,fv.schema_json,${templateFileRulesSelect},${formFileRulesSelect} FROM forms f LEFT JOIN templates t ON t.id=f.template_id LEFT JOIN form_versions fv ON fv.form_id=f.id AND fv.version=1 WHERE f.slug=? AND f.deleted_at IS NULL`
  )
    .bind(slug)
    .first<
      FormDetailRow & {
        id: string;
      }
    >();
}

function buildEffectiveRules(row: {
  template_file_rules_json?: string | null;
  form_file_rules_json?: string | null;
}) {
  let templateRules = normalizeRules(null);
  let formRules: FileRules | null = null;
  if (row.template_file_rules_json) {
    try {
      templateRules = normalizeRules(JSON.parse(row.template_file_rules_json));
    } catch (error) {
      templateRules = normalizeRules(null);
    }
  }
  if (row.form_file_rules_json) {
    try {
      formRules = normalizeRules(JSON.parse(row.form_file_rules_json));
    } catch (error) {
      formRules = null;
    }
  }
  return mergeRules(templateRules, formRules);
}

async function buildFormDetailPayload(env: Env, row: FormDetailRow) {
  let schema: unknown = null;
  if (row.schema_json) {
    try {
      schema = JSON.parse(row.schema_json);
    } catch (error) {
      return { error: "invalid_schema" as const };
    }
  }

  const fields = extractFields(schema);
  const fileRules = buildEffectiveRules(row);
  let allowedSectionIds: string[] | null = null;
  if (row.canvas_allowed_section_ids_json) {
    try {
      const parsed = JSON.parse(row.canvas_allowed_section_ids_json);
      if (Array.isArray(parsed)) {
        allowedSectionIds = parsed.filter((id) => typeof id === "string");
      }
    } catch (error) {
      allowedSectionIds = null;
    }
  }
  const canvasSections =
    toBoolean(row.canvas_enabled ?? 0) && row.canvas_course_id
      ? await getCanvasAllowedSections(env, row.canvas_course_id, allowedSectionIds)
      : [];
  let canvasCourseName: string | null = null;
  if (row.canvas_course_id) {
    const courseRow = await env.DB.prepare("SELECT name FROM canvas_courses_cache WHERE id=?")
      .bind(row.canvas_course_id)
      .first<{ name?: string }>();
    if (courseRow?.name) {
      canvasCourseName = courseRow.name;
    }
  }

  return {
    data: {
      slug: row.slug,
      title: row.title,
      description: row.description,
      is_locked: toBoolean(row.is_locked),
      is_public: toBoolean(row.is_public),
      auth_policy: row.auth_policy,
      templateKey: row.templateKey,
      templateVersion: row.templateVersion,
      formVersion: row.templateVersion,
      available_from: row.available_from ?? null,
      available_until: row.available_until ?? null,
      password_required: toBoolean(row.password_required ?? 0),
      password_require_access: toBoolean(row.password_require_access ?? 0),
      password_require_submit: toBoolean(row.password_require_submit ?? 0),
      is_open: getFormAvailability(row).open,
      template_schema_json: row.schema_json,
      file_rules_json: row.form_file_rules_json ?? row.template_file_rules_json ?? null,
      fields,
      file_rules: fileRules,
      canvas_enabled: toBoolean(row.canvas_enabled ?? 0),
      canvas_course_id: row.canvas_course_id ?? null,
      canvas_course_name: canvasCourseName,
      canvas_allowed_sections: canvasSections,
      canvas_fields_position: row.canvas_fields_position ?? "bottom",
      reminder_enabled: toBoolean(row.reminder_enabled ?? 0),
      reminder_frequency: row.reminder_frequency ?? "weekly",
      save_all_versions: toBoolean(row.save_all_versions ?? 0)
    }
  };
}

type CanvasCourse = {
  id: string;
  name: string;
  course_code?: string | null;
  workflow_state?: string | null;
  account_id?: string | null;
  term_id?: string | null;
};

type CanvasSection = {
  id: string;
  course_id: string;
  name: string;
};

type CanvasCourseUser = {
  id: string;
  name?: string | null;
  loginId?: string | null;
  shortName?: string | null;
  sortableName?: string | null;
  pronouns?: string | null;
  email?: string | null;
  roles?: string[];
  error?: string | null;
};

type RoutineTaskRow = {
  id: string;
  name: string;
  cron: string;
  enabled: number;
  last_run_at: string | null;
  last_status: string | null;
  last_error: string | null;
  last_log_id: string | null;
};

function getCanvasBaseUrl(env: Env): string {
  return env.CANVAS_BASE_URL?.trim() || "https://canvas.instructure.com";
}

function getCanvasAccountId(env: Env): string | null {
  const value = env.CANVAS_ACCOUNT_ID?.trim();
  if (value) {
    return value;
  }
  const base = getCanvasBaseUrl(env);
  if (base.includes("canvas.instructure.com")) {
    return "10";
  }
  return "1";
}

function parseLinkHeader(header: string | null): Record<string, string> {
  if (!header) return {};
  const parts = header.split(",");
  const links: Record<string, string> = {};
  for (const part of parts) {
    const match = part.match(/<([^>]+)>;\s*rel="([^"]+)"/);
    if (match) {
      links[match[2]] = match[1];
    }
  }
  return links;
}

function maskEmail(email: string): string {
  const trimmed = email.trim();
  const at = trimmed.indexOf("@");
  if (at <= 1) {
    return "***";
  }
  return `${trimmed[0]}***${trimmed.slice(at - 1)}`;
}

function normalizeCanvasCourseSyncMode(value: string | null): "active" | "concluded" | "all" {
  const mode = (value || "").trim().toLowerCase();
  if (mode === "concluded") return "concluded";
  if (mode === "all") return "all";
  return "active";
}

function normalizeCanvasDeleteSyncEnabled(value: string | null): boolean {
  if (!value) return true;
  const normalized = String(value).trim().toLowerCase();
  if (["0", "false", "disabled", "off", "no"].includes(normalized)) {
    return false;
  }
  return true;
}

function normalizeAppToggle(value: string | null, defaultValue: boolean): boolean {
  if (!value) return defaultValue;
  const normalized = String(value).trim().toLowerCase();
  if (["0", "false", "disabled", "off", "no"].includes(normalized)) {
    return false;
  }
  if (["1", "true", "enabled", "on", "yes"].includes(normalized)) {
    return true;
  }
  return defaultValue;
}

async function isCanvasDeleteSyncEnabled(env: Env): Promise<boolean> {
  const value = await getAppSetting(env, APP_SETTING_CANVAS_DELETE_SYNC);
  return normalizeCanvasDeleteSyncEnabled(value);
}

async function getCanvasCourseSyncMode(env: Env): Promise<"active" | "concluded" | "all"> {
  const value = await getAppSetting(env, APP_SETTING_CANVAS_COURSE_SYNC_MODE);
  return normalizeCanvasCourseSyncMode(value);
}

function buildCanvasCourseFilter(mode: "active" | "concluded" | "all"): string {
  if (mode === "concluded") {
    return "workflow_state IN ('completed','concluded')";
  }
  if (mode === "all") {
    return "(workflow_state IS NULL OR workflow_state != 'deleted')";
  }
  return "(workflow_state IS NULL OR workflow_state NOT IN ('completed','concluded','deleted'))";
}

function cronFieldMatches(expr: string, value: number): boolean {
  const trimmed = expr.trim();
  if (trimmed === "*") return true;
  if (trimmed.includes(",")) {
    return trimmed
      .split(",")
      .map((part) => part.trim())
      .some((part) => cronFieldMatches(part, value));
  }
  if (trimmed.startsWith("*/")) {
    const step = Number(trimmed.slice(2));
    if (!Number.isFinite(step) || step <= 0) return false;
    return value % step === 0;
  }
  const num = Number(trimmed);
  if (!Number.isFinite(num)) return false;
  return value === num;
}

function cronMatchesNow(cron: string, now: Date): boolean {
  const parts = cron.trim().split(/\s+/);
  if (parts.length !== 5) return false;
  const [min, hour, dom, month, dow] = parts;
  const utc = new Date(now.toISOString());
  const minute = utc.getUTCMinutes();
  const hourVal = utc.getUTCHours();
  const domVal = utc.getUTCDate();
  const monthVal = utc.getUTCMonth() + 1;
  const dowVal = utc.getUTCDay();
  return (
    cronFieldMatches(min, minute) &&
    cronFieldMatches(hour, hourVal) &&
    cronFieldMatches(dom, domVal) &&
    cronFieldMatches(month, monthVal) &&
    cronFieldMatches(dow, dowVal)
  );
}

async function updateRoutineStatus(
  env: Env,
  id: string,
  status: string,
  errorMessage: string | null
) {
  await env.DB.prepare(
    "UPDATE routine_tasks SET last_run_at=datetime('now'), last_status=?, last_error=?, updated_at=datetime('now') WHERE id=?"
  )
    .bind(status, errorMessage, id)
    .run();
}

async function recordRoutineRun(
  env: Env,
  taskId: string,
  status: string,
  message: string | null
) {
  const runId = crypto.randomUUID();
  await env.DB.prepare(
    "INSERT INTO routine_task_runs (id, task_id, status, message) VALUES (?, ?, ?, ?)"
  )
    .bind(runId, taskId, status, message)
    .run();
  await env.DB.prepare(
    "UPDATE routine_tasks SET last_log_id=? WHERE id=?"
  )
    .bind(runId, taskId)
    .run();
  await env.DB.prepare(
    "DELETE FROM routine_task_runs WHERE task_id=? AND run_at < datetime('now','-30 days')"
  )
    .bind(taskId)
    .run();
  await env.DB.prepare(
    "DELETE FROM routine_task_runs WHERE task_id=? AND id NOT IN (SELECT id FROM routine_task_runs WHERE task_id=? ORDER BY run_at DESC LIMIT 100)"
  )
    .bind(taskId, taskId)
    .run();
}

function getHealthServiceTitle(service: string, fallback?: string | null) {
  const serviceTitleById: Record<string, string> = {
    canvas_sync: "Canvas sync",
    canvas_retry_queue: "Canvas retry queue",
    canvas_name_mismatch_checker: "Canvas name mismatch checker",
    canvas_name_mismatch: "Canvas name mismatch checker",
    gmail_send: "Gmail send",
    backup_forms: "Backup forms",
    backup_templates: "Backup templates",
    backup_forms_templates: "Backup forms + templates",
    empty_trash: "Empty trash",
    health_summary: "Health summary",
    health_history: "Health history"
  };
  return fallback || serviceTitleById[service] || service;
}

async function recordHealthStatus(
  env: Env,
  service: string,
  status: string,
  message: string | null
) {
  const serviceTitle = getHealthServiceTitle(service);
  await env.DB.prepare(
    "INSERT INTO health_status_logs (id, service, status, message, service_title) VALUES (?, ?, ?, ?, ?)"
  )
    .bind(crypto.randomUUID(), service, status, message, serviceTitle)
    .run();
}

function shouldRetryCanvasError(error: string | null | undefined): boolean {
  if (!error) return false;
  const lower = error.toLowerCase();
  if (lower.includes("timeout")) return true;
  if (lower.includes("canvas_request_failed:429")) return true;
  const match = lower.match(/canvas_request_failed:(\d{3})/);
  if (match) {
    const code = Number(match[1]);
    if (code >= 500 && code <= 599) return true;
  }
  if (lower.includes("enroll_failed") && lower.includes("retry")) return true;
  return false;
}

async function enqueueCanvasRetry(
  env: Env,
  submissionId: string,
  formId: string,
  courseId: string,
  sectionId: string | null,
  submitterName: string | null,
  submitterEmail: string | null,
  errorMessage: string
) {
  const existing = await env.DB.prepare(
    "SELECT id, attempts FROM canvas_enroll_queue WHERE submission_id=?"
  )
    .bind(submissionId)
    .first<{ id: string; attempts: number }>();
  const nextRunAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  if (existing?.id) {
    await env.DB.prepare(
      "UPDATE canvas_enroll_queue SET attempts=?, last_error=?, next_run_at=?, updated_at=datetime('now') WHERE id=?"
    )
      .bind(existing.attempts + 1, errorMessage, nextRunAt, existing.id)
      .run();
    return;
  }
  await env.DB.prepare(
    "INSERT INTO canvas_enroll_queue (id, submission_id, form_id, course_id, section_id, submitter_name, submitter_email, attempts, last_error, next_run_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
  )
    .bind(
      crypto.randomUUID(),
      submissionId,
      formId,
      courseId,
      sectionId,
      submitterName,
      submitterEmail,
      0,
      errorMessage,
      nextRunAt
    )
    .run();
}

async function processCanvasRetryQueue(env: Env, limit = 10) {
  if (!env.CANVAS_API_TOKEN) {
    return { processed: 0, failed: 0, deadlettered: 0 };
  }
  const { results } = await env.DB.prepare(
    "SELECT id, submission_id, form_id, course_id, section_id, submitter_name, submitter_email, attempts FROM canvas_enroll_queue WHERE next_run_at <= datetime('now') ORDER BY next_run_at ASC LIMIT ?"
  )
    .bind(limit)
    .all<{
      id: string;
      submission_id: string;
      form_id: string;
      course_id: string;
      section_id: string | null;
      submitter_name: string | null;
      submitter_email: string | null;
      attempts: number;
    }>();
  let processed = 0;
  let failed = 0;
  let deadlettered = 0;
  for (const row of results) {
    processed += 1;
    const form = await env.DB.prepare(
      "SELECT id, slug, title, canvas_course_id, canvas_enabled FROM forms WHERE id=? AND deleted_at IS NULL"
    )
      .bind(row.form_id)
      .first<{ id: string; slug: string; title: string; canvas_course_id: string | null; canvas_enabled: number | null }>();
    if (!form || !form.canvas_enabled || !form.canvas_course_id) {
      await env.DB.prepare("DELETE FROM canvas_enroll_queue WHERE id=?").bind(row.id).run();
      continue;
    }
    const enrollment = await handleCanvasEnrollment(
      env,
      form,
      row.submitter_name || "",
      row.submitter_email || "",
      row.section_id
    );
    if (enrollment.status === "invited") {
      await env.DB.prepare(
        "UPDATE submissions SET canvas_enroll_status=?, canvas_enroll_error=?, canvas_course_id=?, canvas_section_id=?, canvas_enrolled_at=?, canvas_user_id=?, canvas_user_name=? WHERE id=?"
      )
        .bind(
          enrollment.status,
          enrollment.error,
          form.canvas_course_id,
          enrollment.sectionId,
          enrollment.enrolledAt,
          enrollment.canvasUserId ?? null,
          enrollment.canvasUserName ?? null,
          row.submission_id
        )
        .run();
      await env.DB.prepare("DELETE FROM canvas_enroll_queue WHERE id=?").bind(row.id).run();
      continue;
    }
    failed += 1;
    const attempts = row.attempts + 1;
    const error = enrollment.error || "canvas_retry_failed";
    if (attempts >= 5) {
      await env.DB.prepare(
        "INSERT INTO canvas_enroll_deadletters (id, submission_id, course_id, section_id, submitter_email, error, attempts) VALUES (?, ?, ?, ?, ?, ?, ?)"
      )
        .bind(
          crypto.randomUUID(),
          row.submission_id,
          row.course_id,
          row.section_id,
          row.submitter_email,
          error,
          attempts
        )
        .run();
      await env.DB.prepare("DELETE FROM canvas_enroll_queue WHERE id=?").bind(row.id).run();
      deadlettered += 1;
    } else {
      const backoffMinutes = Math.min(60, 5 * attempts);
      const nextRunAt = new Date(Date.now() + backoffMinutes * 60 * 1000).toISOString();
      await env.DB.prepare(
        "UPDATE canvas_enroll_queue SET attempts=?, last_error=?, next_run_at=?, updated_at=datetime('now') WHERE id=?"
      )
        .bind(attempts, error, nextRunAt, row.id)
        .run();
    }
  }
  return { processed, failed, deadlettered };
}

async function runPeriodicReminders(env: Env) {
  const { results: forms } = await env.DB.prepare(
    "SELECT id, slug, title, reminder_frequency, reminder_until, available_from, available_until FROM forms WHERE reminder_enabled=1 AND deleted_at IS NULL"
  ).all<{ id: string; slug: string; title: string; reminder_frequency: string; reminder_until: string | null; available_from: string | null; available_until: string | null }>();

  if (!forms || forms.length === 0) return;

  const now = new Date();
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  for (const form of forms) {
    // Skip if form is not yet open (available_from is in the future)
    if (form.available_from) {
      const openDate = new Date(form.available_from);
      if (now < openDate) continue;
    }

    // Skip if form is already closed (available_until is in the past)
    if (form.available_until) {
      const closeDate = new Date(form.available_until);
      if (now > closeDate) continue;
    }

    // Skip if reminder_until has passed
    if (form.reminder_until) {
      const untilDate = new Date(form.reminder_until);
      untilDate.setHours(23, 59, 59, 999);
      if (today > untilDate) continue;
    }
    // Only support weekly/monthly for now to avoid spam
    // Actually, user wants daily/weekly/monthly. Let's support what we have.
    // 'daily', 'weekly', 'monthly'.
    const frequency = form.reminder_frequency || "weekly";

    // Get all submissions for this form
    const { results: submissions } = await env.DB.prepare(
      "SELECT user_id, submitter_email, created_at FROM submissions WHERE form_id=? AND deleted_at IS NULL ORDER BY created_at ASC"
    ).bind(form.id).all<{ user_id: string | null; submitter_email: string | null; created_at: string }>();

    // Group by user (email or user_id)
    const userMap = new Map<string, { email: string; firstSubmission: Date }>();

    for (const sub of submissions) {
      const email = sub.submitter_email ? sub.submitter_email.trim().toLowerCase() : null;
      // If we don't have an email, we can't email them.
      // If user_id is present but no email in submission, we might need to look up identity?
      // For now rely on submitter_email which is populated for auth users or if they fill email field (if we map it)
      // Actually submitter_email is only populated if authenticated or logic sets it.
      if (!email) continue;

      if (!userMap.has(email)) {
        userMap.set(email, { email, firstSubmission: new Date(sub.created_at) });
      }
    }

    for (const user of userMap.values()) {
      const firstSub = user.firstSubmission;
      firstSub.setHours(0, 0, 0, 0);

      const diffTime = Math.abs(today.getTime() - firstSub.getTime());
      const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

      let shouldSend = false;
      const freq = frequency || "1:weeks";
      let value = 1;
      let unit = "weeks";

      if (freq.includes(":")) {
        const parts = freq.split(":");
        value = parseInt(parts[0]) || 1;
        unit = parts[1] || "weeks";
      } else {
        // Backward compatibility
        if (freq === "daily") { value = 1; unit = "days"; }
        else if (freq === "monthly") { value = 1; unit = "months"; }
        else { value = 1; unit = "weeks"; }
      }

      if (unit === "days") {
        if (diffDays > 0 && diffDays % value === 0) shouldSend = true;
      } else if (unit === "weeks") {
        if (diffDays > 0 && diffDays % (value * 7) === 0) shouldSend = true;
      } else if (unit === "months") {
        const monthDiff = (today.getFullYear() - firstSub.getFullYear()) * 12 + (today.getMonth() - firstSub.getMonth());
        if (monthDiff > 0 && monthDiff % value === 0 && today.getDate() === firstSub.getDate()) {
          shouldSend = true;
        }
      }

      if (shouldSend) {
        // Check if we already sent an email today to this user for this form
        // We can check email_logs
        // This is expensive per user. Optimally we'd do a batch check or have a reminders table.
        // For MVP, we'll just check loosely or assume the cron runs once.
        // But if we want to be safe:
        const sentToday = await env.DB.prepare(
          "SELECT id FROM email_logs WHERE to_address=? AND form_id=? AND trigger_source='periodic_reminder' AND created_at > datetime('now', '-20 hours')"
        ).bind(user.email, form.id).first();

        if (!sentToday) {
          const subject = {
            vi: `Nhắc nhở: ${form.title}`,
            en: `Reminder: ${form.title}`
          };
          const body = {
            vi: `Xin chào,\n\nĐây là email nhắc nhở bạn điền biểu mẫu "${form.title}".\n\nVui lòng truy cập liên kết dưới đây để điền biểu mẫu:\n${env.BASE_URL_WEB || ""}/#/f/${form.slug}\n\n---\n\nĐây là email tự động. Vui lòng không trả lời email này.`,
            en: `Hello,\n\nThis is a reminder to fill out the form "${form.title}".\n\nPlease visit the link below to fill out the form:\n${env.BASE_URL_WEB || ""}/#/f/${form.slug}\n\n---\n\nThis is an automated message. Please do not reply to this email.`
          };
          // Simple bilingual content
          const mailBody = `${body.vi}\n\n---\n\n${body.en}`;

          await sendGmailMessage(env, {
            to: user.email,
            subject: `${subject.vi} / ${subject.en}`,
            body: mailBody
          });

          await logEmailSend(env, {
            to: user.email,
            subject: `${subject.vi} / ${subject.en}`,
            body: mailBody,
            status: "sent",
            formId: form.id,
            formSlug: form.slug,
            formTitle: form.title,
            triggerSource: "periodic_reminder"
          });
        }
      }
    }
  }
}

const SUBMISSION_BACKUP_TASK_PREFIX = "backup_submissions:";
const DEFAULT_SUBMISSION_BACKUP_CRON = "0 3 * * 0";
const SUBMISSION_BACKUP_FORMATS = ["json", "markdown", "csv"] as const;
type SubmissionBackupFormat = (typeof SUBMISSION_BACKUP_FORMATS)[number];

function getSubmissionBackupTaskId(formSlug: string) {
  return `${SUBMISSION_BACKUP_TASK_PREFIX}${formSlug}`;
}

function getSubmissionBackupTaskName(formSlug: string, formTitle?: string | null) {
  const label = formTitle && formTitle.trim() ? formTitle.trim() : formSlug;
  return `Backup submissions: ${label} (${formSlug})`;
}

function parseSubmissionBackupFormats(value: unknown): SubmissionBackupFormat[] {
  if (Array.isArray(value)) {
    const formats = value
      .filter((entry): entry is string => typeof entry === "string")
      .map((entry) => entry.trim().toLowerCase())
      .filter((entry): entry is SubmissionBackupFormat =>
        SUBMISSION_BACKUP_FORMATS.includes(entry as SubmissionBackupFormat)
      );
    return formats.length > 0 ? formats : ["json"];
  }
  if (typeof value === "string" && value.trim()) {
    try {
      const parsed = JSON.parse(value);
      return parseSubmissionBackupFormats(parsed);
    } catch (error) {
      const parts = value.split(",").map((entry) => entry.trim().toLowerCase());
      const formats = parts.filter((entry): entry is SubmissionBackupFormat =>
        SUBMISSION_BACKUP_FORMATS.includes(entry as SubmissionBackupFormat)
      );
      return formats.length > 0 ? formats : ["json"];
    }
  }
  return ["json"];
}

function serializeSubmissionBackupFormats(formats: SubmissionBackupFormat[]) {
  const normalized = formats
    .map((entry) => entry.trim().toLowerCase())
    .filter((entry): entry is SubmissionBackupFormat =>
      SUBMISSION_BACKUP_FORMATS.includes(entry as SubmissionBackupFormat)
    );
  const finalFormats = normalized.length > 0 ? Array.from(new Set(normalized)) : ["json"];
  return JSON.stringify(finalFormats);
}

async function ensureSubmissionBackupTask(
  env: Env,
  formSlug: string,
  formTitle: string | null,
  enabled: boolean
) {
  const taskId = getSubmissionBackupTaskId(formSlug);
  const name = getSubmissionBackupTaskName(formSlug, formTitle);
  const existing = await env.DB.prepare("SELECT id, cron FROM routine_tasks WHERE id=?")
    .bind(taskId)
    .first<{ id: string; cron: string }>();
  if (!existing?.id) {
    if (!enabled) return;
    await env.DB.prepare(
      "INSERT INTO routine_tasks (id, name, cron, enabled) VALUES (?, ?, ?, ?)"
    )
      .bind(taskId, name, DEFAULT_SUBMISSION_BACKUP_CRON, enabled ? 1 : 0)
      .run();
    return;
  }
  await env.DB.prepare(
    "UPDATE routine_tasks SET name=?, enabled=?, updated_at=datetime('now') WHERE id=?"
  )
    .bind(name, enabled ? 1 : 0, taskId)
    .run();
}

async function renameSubmissionBackupTask(
  env: Env,
  oldSlug: string,
  newSlug: string,
  formTitle: string | null
) {
  const oldId = getSubmissionBackupTaskId(oldSlug);
  const newId = getSubmissionBackupTaskId(newSlug);
  if (oldId === newId) return;
  const existing = await env.DB.prepare("SELECT id FROM routine_tasks WHERE id=?")
    .bind(oldId)
    .first<{ id: string }>();
  if (!existing?.id) return;
  const newExisting = await env.DB.prepare("SELECT id FROM routine_tasks WHERE id=?")
    .bind(newId)
    .first<{ id: string }>();
  if (newExisting?.id) {
    await env.DB.prepare("DELETE FROM routine_tasks WHERE id=?")
      .bind(oldId)
      .run();
    return;
  }
  const name = getSubmissionBackupTaskName(newSlug, formTitle);
  await env.DB.prepare(
    "UPDATE routine_tasks SET id=?, name=?, updated_at=datetime('now') WHERE id=?"
  )
    .bind(newId, name, oldId)
    .run();
}

async function backupFormSubmissionsToDrive(env: Env, formSlug: string) {
  if (!env.DRIVE_PARENT_FOLDER_ID || !getDriveCredentials(env)) {
    throw new Error("drive_not_configured");
  }
  const accessToken = await getDriveAccessToken(env);
  if (!accessToken) {
    throw new Error("drive_access_failed");
  }

  const submissionBackupFormatsSelect = (await hasColumn(env, "forms", "submission_backup_formats"))
    ? "submission_backup_formats"
    : "NULL as submission_backup_formats";
  const form = await env.DB.prepare(
    `SELECT id, slug, title, description, is_locked, is_public, auth_policy, ${submissionBackupFormatsSelect} FROM forms WHERE slug=? AND deleted_at IS NULL`
  )
    .bind(formSlug)
    .first<{
      id: string;
      slug: string;
      title: string;
      description: string | null;
      is_locked: number;
      is_public: number;
      auth_policy: string | null;
      submission_backup_formats: string | null;
    }>();
  if (!form) {
    throw new Error("form_not_found");
  }
  const formats = parseSubmissionBackupFormats(form.submission_backup_formats);

  const createdIpSelect = (await hasColumn(env, "submissions", "created_ip"))
    ? "s.created_ip as created_ip"
    : "NULL as created_ip";
  const createdUserAgentSelect = (await hasColumn(env, "submissions", "created_user_agent"))
    ? "s.created_user_agent as created_user_agent"
    : "NULL as created_user_agent";
  const submitterProviderSelect = (await hasColumn(env, "submissions", "submitter_provider"))
    ? "COALESCE(s.submitter_provider,(SELECT provider FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1)) as submitter_provider"
    : "(SELECT provider FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1) as submitter_provider";
  const submitterEmailSelect = (await hasColumn(env, "submissions", "submitter_email"))
    ? "COALESCE(s.submitter_email,(SELECT email FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1)) as submitter_email"
    : "(SELECT email FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1) as submitter_email";
  const submitterGithubSelect = (await hasColumn(env, "submissions", "submitter_github_username"))
    ? "COALESCE(s.submitter_github_username,(SELECT provider_login FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1)) as submitter_github_username"
    : "(SELECT provider_login FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1) as submitter_github_username";

  const { results: submissions } = await env.DB.prepare(
    `SELECT s.id,s.user_id,s.payload_json,s.created_at,s.updated_at,${createdIpSelect},${createdUserAgentSelect},${submitterProviderSelect},${submitterEmailSelect},${submitterGithubSelect},s.canvas_enroll_status,s.canvas_enroll_error,s.canvas_course_id,s.canvas_section_id,s.canvas_enrolled_at,s.canvas_user_id,s.canvas_user_name FROM submissions s WHERE s.form_id=? AND s.deleted_at IS NULL ORDER BY s.created_at ASC`
  )
    .bind(form.id)
    .all<any>();

  const submissionIds = submissions.map((row) => row.id).filter(Boolean) as string[];
  const filesBySubmission = new Map<string, any[]>();
  if (submissionIds.length > 0) {
    const placeholders = submissionIds.map(() => "?").join(",");
    const { results: files } = await env.DB.prepare(
      `SELECT submission_id, field_id, original_name, size_bytes, mime_type, sha256, vt_status, vt_verdict, vt_malicious, vt_suspicious, vt_undetected, vt_timeout, vt_error, final_drive_file_id, finalized_at, drive_web_view_link FROM submission_file_items WHERE submission_id IN (${placeholders}) AND deleted_at IS NULL ORDER BY uploaded_at DESC`
    )
      .bind(...submissionIds)
      .all<any>();
    files.forEach((file) => {
      const bucket = filesBySubmission.get(file.submission_id) || [];
      bucket.push(file);
      filesBySubmission.set(file.submission_id, bucket);
    });
  }

  const normalized = submissions.map((row) => {
    let dataJson: unknown = null;
    try {
      const payload = JSON.parse(row.payload_json);
      dataJson = payload?.data ?? null;
    } catch (error) {
      dataJson = null;
    }
    return {
      id: row.id,
      user_id: row.user_id ?? null,
      submitter: {
        provider: row.submitter_provider ?? null,
        email: row.submitter_email ?? null,
        github_username: row.submitter_github_username ?? null
      },
      created_at: row.created_at ?? null,
      updated_at: row.updated_at ?? null,
      created_ip: row.created_ip ?? null,
      created_user_agent: row.created_user_agent ?? null,
      canvas: {
        status: row.canvas_enroll_status ?? null,
        error: row.canvas_enroll_error ?? null,
        course_id: row.canvas_course_id ?? null,
        section_id: row.canvas_section_id ?? null,
        enrolled_at: row.canvas_enrolled_at ?? null,
        user_id: row.canvas_user_id ?? null,
        user_name: row.canvas_user_name ?? null
      },
      data_json: dataJson,
      files: filesBySubmission.get(row.id) || []
    };
  });

  const timestamp = new Date();
  const timestampIso = timestamp.toISOString();
  const safeTimestamp = timestampIso.replace(/[:.]/g, "-");
  const payload = {
    type: "submission_backup",
    generated_at: timestampIso,
    form: {
      slug: form.slug,
      title: form.title,
      description: form.description ?? null,
      is_locked: Boolean(form.is_locked),
      is_public: Boolean(form.is_public),
      auth_policy: form.auth_policy ?? "optional"
    },
    submissions: normalized
  };

  const backupsFolder = await getOrCreateFolder(env, accessToken, env.DRIVE_PARENT_FOLDER_ID, "backups");
  if (!backupsFolder.id) {
    throw new Error("drive_backups_folder_failed");
  }
  const submissionsFolder = await getOrCreateFolder(env, accessToken, backupsFolder.id, "submissions");
  if (!submissionsFolder.id) {
    throw new Error("drive_backups_subfolder_failed");
  }
  const formFolder = await getOrCreateFolder(
    env,
    accessToken,
    submissionsFolder.id,
    sanitizeDriveName(form.slug)
  );
  if (!formFolder.id) {
    throw new Error("drive_backups_subfolder_failed");
  }
  const uploads: Array<{ id: string; name: string }> = [];

  if (formats.includes("json")) {
    const body = JSON.stringify(payload, null, 2);
    const buffer = new TextEncoder().encode(body);
    const fileName = `submissions-${form.slug}-${safeTimestamp}.json`;
    const uploaded = await uploadFileToDrive(
      env,
      accessToken,
      formFolder.id,
      fileName,
      "application/json",
      buffer
    );
    if (!uploaded?.id) {
      throw new Error("drive_upload_failed");
    }
    uploads.push({ id: uploaded.id, name: fileName });
  }

  if (formats.includes("markdown")) {
    const lines: string[] = [
      "# Submission backup",
      "",
      `Generated at: ${payload.generated_at}`,
      `Form: ${payload.form.title} (${payload.form.slug})`,
      ""
    ];
    if (payload.form.description) {
      lines.push(payload.form.description, "");
    }
    lines.push(`Total submissions: ${payload.submissions.length}`, "");
    payload.submissions.forEach((submission) => {
      lines.push(`## Submission ${submission.id}`);
      lines.push(`- User ID: ${submission.user_id ?? "n/a"}`);
      lines.push(`- Submitter email: ${submission.submitter?.email ?? "n/a"}`);
      lines.push(`- Submitter provider: ${submission.submitter?.provider ?? "n/a"}`);
      lines.push(`- Submitter GitHub: ${submission.submitter?.github_username ?? "n/a"}`);
      lines.push(`- Created: ${submission.created_at ?? "n/a"}`);
      lines.push(`- Updated: ${submission.updated_at ?? "n/a"}`);
      if (submission.created_ip) lines.push(`- Created IP: ${submission.created_ip}`);
      if (submission.created_user_agent) lines.push(`- User agent: ${submission.created_user_agent}`);
      if (submission.canvas?.status) {
        lines.push(`- Canvas status: ${submission.canvas.status}`);
        if (submission.canvas.error) lines.push(`- Canvas error: ${submission.canvas.error}`);
      }
      lines.push("", "### Data");
      const data = submission.data_json && typeof submission.data_json === "object" ? submission.data_json : {};
      const dataEntries = Object.entries(data as Record<string, unknown>);
      if (dataEntries.length === 0) {
        lines.push("_No data_", "");
      } else {
        lines.push("| Field | Value |", "| --- | --- |");
        dataEntries.forEach(([key, value]) => {
          lines.push(`| ${key} | ${stringifyCsvValue(value).replace(/\r?\n/g, "<br>")} |`);
        });
        lines.push("");
      }
      lines.push("### Files");
      if (!submission.files || submission.files.length === 0) {
        lines.push("_No files_", "");
      } else {
        lines.push("| Field | File | Size | VirusTotal | Drive |", "| --- | --- | --- | --- | --- |");
        submission.files.forEach((file: any) => {
          const driveLink = file.drive_web_view_link ? file.drive_web_view_link : file.final_drive_file_id || "";
          const vt = file.vt_verdict
            ? `${file.vt_status || "pending"} (${file.vt_verdict})`
            : file.vt_status || "pending";
          lines.push(
            `| ${file.field_id || ""} | ${file.original_name || ""} | ${file.size_bytes ?? ""} | ${vt} | ${driveLink} |`
          );
        });
        lines.push("");
      }
    });
    const body = lines.join("\n");
    const buffer = new TextEncoder().encode(body);
    const fileName = `submissions-${form.slug}-${safeTimestamp}.md`;
    const uploaded = await uploadFileToDrive(
      env,
      accessToken,
      formFolder.id,
      fileName,
      "text/markdown",
      buffer
    );
    if (!uploaded?.id) {
      throw new Error("drive_upload_failed");
    }
    uploads.push({ id: uploaded.id, name: fileName });
  }

  if (formats.includes("csv")) {
    const headers = [
      "submission_id",
      "user_id",
      "submitter_email",
      "submitter_provider",
      "submitter_github_username",
      "created_at",
      "updated_at",
      "created_ip",
      "created_user_agent",
      "canvas_status",
      "canvas_error",
      "canvas_course_id",
      "canvas_section_id",
      "canvas_user_id",
      "canvas_user_name",
      "data_json",
      "files_json"
    ];
    const lines = [headers.join(",")];
    normalized.forEach((row) => {
      const values = [
        row.id,
        row.user_id ?? "",
        row.submitter?.email ?? "",
        row.submitter?.provider ?? "",
        row.submitter?.github_username ?? "",
        row.created_at ?? "",
        row.updated_at ?? "",
        row.created_ip ?? "",
        row.created_user_agent ?? "",
        row.canvas?.status ?? "",
        row.canvas?.error ?? "",
        row.canvas?.course_id ?? "",
        row.canvas?.section_id ?? "",
        row.canvas?.user_id ?? "",
        row.canvas?.user_name ?? "",
        JSON.stringify(row.data_json ?? {}),
        JSON.stringify(row.files ?? [])
      ].map((value) => csvEscape(String(value ?? "")));
      lines.push(values.join(","));
    });
    const body = `\ufeff${lines.join("\n")}`;
    const buffer = new TextEncoder().encode(body);
    const fileName = `submissions-${form.slug}-${safeTimestamp}.csv`;
    const uploaded = await uploadFileToDrive(
      env,
      accessToken,
      formFolder.id,
      fileName,
      "text/csv; charset=utf-8",
      buffer
    );
    if (!uploaded?.id) {
      throw new Error("drive_upload_failed");
    }
    uploads.push({ id: uploaded.id, name: fileName });
  }
  return { uploads };
}

async function runRoutineTaskById(env: Env, taskId: string) {
  if (taskId === "periodic_reminders") {
    await runPeriodicReminders(env);
    const message = "processed";
    await updateRoutineStatus(env, taskId, "ok", message);
    await recordRoutineRun(env, taskId, "ok", message);
    await recordHealthStatus(env, "periodic_reminders", "ok", message);
    return;
  }
  if (taskId === "canvas_sync") {
    if (!env.CANVAS_API_TOKEN) {
      await updateRoutineStatus(env, taskId, "skipped", "canvas_token_missing");
      await recordRoutineRun(env, taskId, "skipped", "canvas_token_missing");
      await recordHealthStatus(env, "canvas_sync", "skipped", "canvas_token_missing");
      return;
    }
    const mode = await getCanvasCourseSyncMode(env);
    const courseCount = await syncCanvasCourses(env, mode);
    const { results } = await env.DB.prepare(
      "SELECT DISTINCT canvas_course_id as course_id FROM forms WHERE canvas_enabled=1 AND canvas_course_id IS NOT NULL AND deleted_at IS NULL"
    ).all<{ course_id: string | null }>();
    const courseIds = results.map((row) => row.course_id).filter(Boolean) as string[];
    let sectionsSynced = 0;
    for (const courseId of courseIds) {
      sectionsSynced += await syncCanvasSections(env, courseId);
    }
    const message = `courses ${courseCount}, sections ${sectionsSynced}`;
    await updateRoutineStatus(env, taskId, "ok", message);
    await recordRoutineRun(env, taskId, "ok", message);
    await recordHealthStatus(env, "canvas_sync", "ok", message);
    return;
  }
  if (taskId === "canvas_name_mismatch") {
    if (!env.CANVAS_API_TOKEN) {
      await updateRoutineStatus(env, taskId, "skipped", "canvas_token_missing");
      await recordRoutineRun(env, taskId, "skipped", "canvas_token_missing");
      await recordHealthStatus(env, "canvas_name_mismatch", "skipped", "canvas_token_missing");
      return;
    }
    const summary = await runCanvasNameMismatchChecks(env);
    const message = `checked ${summary.checked}, mismatched ${summary.mismatched}, resolved ${summary.resolved}, skipped ${summary.skipped}`;
    await updateRoutineStatus(env, taskId, "ok", message);
    await recordRoutineRun(env, taskId, "ok", message);
    await recordHealthStatus(env, "canvas_name_mismatch", "ok", message);
    return;
  }
  if (taskId === "canvas_retry_queue") {
    if (!env.CANVAS_API_TOKEN) {
      await updateRoutineStatus(env, taskId, "skipped", "canvas_token_missing");
      await recordRoutineRun(env, taskId, "skipped", "canvas_token_missing");
      await recordHealthStatus(env, "canvas_retry_queue", "skipped", "canvas_token_missing");
      return;
    }
    try {
      const result = await processCanvasRetryQueue(env, 20);
      const message = `processed ${result.processed}, failed ${result.failed}, deadlettered ${result.deadlettered}`;
      await updateRoutineStatus(env, taskId, "ok", message);
      await recordRoutineRun(env, taskId, "ok", message);
      await recordHealthStatus(env, "canvas_retry_queue", "ok", message);
    } catch (error) {
      const message = String((error as Error | undefined)?.message || error);
      await updateRoutineStatus(env, taskId, "error", message);
      await recordRoutineRun(env, taskId, "error", message);
      await recordHealthStatus(env, "canvas_retry_queue", "error", message);
    }
    return;
  }
  if (taskId === "backup_forms_templates") {
    try {
      const key = await backupFormsAndTemplates(env);
      const message = `saved:${key}`;
      await updateRoutineStatus(env, taskId, "ok", message);
      await recordRoutineRun(env, taskId, "ok", message);
      await recordHealthStatus(env, "backup_forms_templates", "ok", message);
    } catch (error) {
      const message = String((error as Error | undefined)?.message || error);
      await updateRoutineStatus(env, taskId, "error", message);
      await recordRoutineRun(env, taskId, "error", message);
      await recordHealthStatus(env, "backup_forms_templates", "error", message);
    }
    return;
  }
  if (taskId.startsWith(SUBMISSION_BACKUP_TASK_PREFIX)) {
    const slug = taskId.slice(SUBMISSION_BACKUP_TASK_PREFIX.length).trim();
    if (!slug) {
      await updateRoutineStatus(env, taskId, "skipped", "missing_slug");
      await recordRoutineRun(env, taskId, "skipped", "missing_slug");
      await recordHealthStatus(env, taskId, "skipped", "missing_slug");
      return;
    }
    try {
      const result = await backupFormSubmissionsToDrive(env, slug);
      const names = result.uploads.map((item) => item.name).join(",");
      const message = names ? `saved:${names}` : "saved";
      await updateRoutineStatus(env, taskId, "ok", message);
      await recordRoutineRun(env, taskId, "ok", message);
      await recordHealthStatus(env, taskId, "ok", message);
    } catch (error) {
      const message = String((error as Error | undefined)?.message || error);
      await updateRoutineStatus(env, taskId, "error", message);
      await recordRoutineRun(env, taskId, "error", message);
      await recordHealthStatus(env, taskId, "error", message);
    }
    return;
  }
  if (taskId === "empty_trash") {
    const counts = await emptyAllTrash(env);
    const message = `forms ${counts.forms}, templates ${counts.templates}, users ${counts.users}, submissions ${counts.submissions}, files ${counts.files}, emails ${counts.emails}`;
    await updateRoutineStatus(env, taskId, "ok", message);
    await recordRoutineRun(env, taskId, "ok", message);
    await recordHealthStatus(env, "empty_trash", "ok", message);
    return;
  }
  if (taskId === "test_notice") {
    await updateRoutineStatus(env, taskId, "ok", "notice_triggered");
    await recordRoutineRun(env, taskId, "ok", "notice_triggered");
    await recordHealthStatus(env, "test_notice", "ok", "notice_triggered");
    return;
  }
  await updateRoutineStatus(env, taskId, "skipped", "unknown_task");
  await recordRoutineRun(env, taskId, "skipped", "unknown_task");
  await recordHealthStatus(env, "routine_unknown", "skipped", "unknown_task");
}

async function backupFormsAndTemplates(env: Env) {
  if (!env.form_app_files) {
    throw new Error("r2_not_configured");
  }
  if (!env.DRIVE_PARENT_FOLDER_ID || !getDriveCredentials(env)) {
    throw new Error("drive_not_configured");
  }
  const accessToken = await getDriveAccessToken(env);
  if (!accessToken) {
    throw new Error("drive_access_failed");
  }
  const submissionBackupSelect = (await hasColumn(env, "forms", "submission_backup_enabled"))
    ? "f.submission_backup_enabled as submission_backup_enabled"
    : "NULL as submission_backup_enabled";
  const submissionBackupFormatsSelect = (await hasColumn(env, "forms", "submission_backup_formats"))
    ? "f.submission_backup_formats as submission_backup_formats"
    : "NULL as submission_backup_formats";
  const { results: formRows } = await env.DB.prepare(
    `SELECT f.slug,f.title,f.description,f.is_locked,f.is_public,f.auth_policy,f.template_id,t.key as templateKey,f.file_rules_json,f.canvas_enabled,f.canvas_course_id,f.canvas_allowed_section_ids_json,f.canvas_fields_position,f.available_from,f.available_until,f.password_required,f.password_require_access,f.password_require_submit,f.password_salt,f.password_hash,${submissionBackupSelect},${submissionBackupFormatsSelect},fv.schema_json as form_schema_json FROM forms f LEFT JOIN templates t ON t.id=f.template_id LEFT JOIN form_versions fv ON fv.form_id=f.id AND fv.version=1 WHERE f.deleted_at IS NULL`
  ).all<Record<string, unknown>>();
  const { results: templateRows } = await env.DB.prepare(
    "SELECT key,name,schema_json,file_rules_json FROM templates WHERE deleted_at IS NULL"
  ).all<Record<string, unknown>>();
  const timestamp = new Date().toISOString();
  const formsPayload = {
    type: "forms_backup",
    generated_at: timestamp,
    forms: formRows.map((row) => ({
      slug: row.slug,
      title: row.title,
      description: row.description ?? null,
      is_locked: Boolean(row.is_locked),
      is_public: Boolean(row.is_public),
      auth_policy: row.auth_policy,
      templateKey: row.templateKey,
      file_rules_json: row.file_rules_json ?? null,
      schema_json: row.form_schema_json ? JSON.parse(String(row.form_schema_json)) : null,
      canvas_enabled: Boolean(row.canvas_enabled),
      canvas_course_id: row.canvas_course_id ?? null,
      canvas_allowed_section_ids_json: row.canvas_allowed_section_ids_json ?? null,
      canvas_fields_position: row.canvas_fields_position ?? null,
      available_from: row.available_from ?? null,
      available_until: row.available_until ?? null,
      password_required: Boolean(row.password_required),
      submission_backup_enabled: Boolean((row as any).submission_backup_enabled ?? 0),
      submission_backup_formats: parseSubmissionBackupFormats((row as any).submission_backup_formats),
      password_salt: row.password_salt ?? null,
      password_hash: row.password_hash ?? null
    }))
  };
  const templatesPayload = {
    type: "templates_backup",
    generated_at: timestamp,
    templates: templateRows.map((row) => ({
      key: row.key,
      name: row.name,
      schema_json: row.schema_json,
      file_rules_json: row.file_rules_json ?? null
    }))
  };
  const safeTimestamp = timestamp.replace(/[:.]/g, "-");
  const formsKey = `backups/forms-${safeTimestamp}.json`;
  const templatesKey = `backups/templates-${safeTimestamp}.json`;
  const formsBody = JSON.stringify(formsPayload, null, 2);
  const templatesBody = JSON.stringify(templatesPayload, null, 2);
  await env.form_app_files.put(formsKey, formsBody, {
    httpMetadata: { contentType: "application/json" }
  });
  await env.form_app_files.put(templatesKey, templatesBody, {
    httpMetadata: { contentType: "application/json" }
  });
  const backupsFolder = await getOrCreateFolder(
    env,
    accessToken,
    env.DRIVE_PARENT_FOLDER_ID,
    "backups"
  );
  if (!backupsFolder.id) {
    throw new Error("drive_backups_folder_failed");
  }
  const formsFolder = await getOrCreateFolder(env, accessToken, backupsFolder.id, "forms");
  const templatesFolder = await getOrCreateFolder(env, accessToken, backupsFolder.id, "templates");
  if (!formsFolder.id || !templatesFolder.id) {
    throw new Error("drive_backups_subfolder_failed");
  }
  const formsBytes = new TextEncoder().encode(formsBody);
  const templatesBytes = new TextEncoder().encode(templatesBody);
  const driveForms = await uploadFileToDrive(
    env,
    accessToken,
    formsFolder.id,
    `forms-${safeTimestamp}.json`,
    "application/json",
    formsBytes
  );
  const driveTemplates = await uploadFileToDrive(
    env,
    accessToken,
    templatesFolder.id,
    `templates-${safeTimestamp}.json`,
    "application/json",
    templatesBytes
  );
  if (!driveForms?.id || !driveTemplates?.id) {
    throw new Error("drive_upload_failed");
  }
  return `${formsKey},${templatesKey}`;
}

async function emptyAllTrash(env: Env): Promise<{
  forms: number;
  templates: number;
  users: number;
  submissions: number;
  files: number;
  emails: number;
}> {
  const counts = { forms: 0, templates: 0, users: 0, submissions: 0, files: 0, emails: 0 };
  const { results: forms } = await env.DB.prepare("SELECT slug FROM forms WHERE deleted_at IS NOT NULL")
    .all<{ slug: string }>();
  for (const row of forms) {
    if (row?.slug) await hardDeleteForm(env, row.slug);
  }
  counts.forms = forms.length;
  const { results: templates } = await env.DB.prepare(
    "SELECT key FROM templates WHERE deleted_at IS NOT NULL"
  ).all<{ key: string }>();
  for (const row of templates) {
    if (row?.key) await hardDeleteTemplate(env, row.key);
  }
  counts.templates = templates.length;
  const { results: users } = await env.DB.prepare("SELECT id FROM users WHERE deleted_at IS NOT NULL")
    .all<{ id: string }>();
  for (const row of users) {
    if (row?.id) await hardDeleteUser(env, row.id);
  }
  counts.users = users.length;
  const { results: submissions } = await env.DB.prepare(
    "SELECT id FROM submissions WHERE deleted_at IS NOT NULL"
  ).all<{ id: string }>();
  for (const row of submissions) {
    if (row?.id) await hardDeleteSubmission(env, row.id);
  }
  counts.submissions = submissions.length;
  const { results: files } = await env.DB.prepare(
    "SELECT id FROM submission_file_items WHERE deleted_at IS NOT NULL"
  ).all<{ id: string }>();
  for (const row of files) {
    if (row?.id) await hardDeleteFileItem(env, row.id);
  }
  counts.files = files.length;
  if (await hasEmailLogsSoftDelete(env)) {
    const { results: emails } = await env.DB.prepare(
      "SELECT id FROM email_logs WHERE deleted_at IS NOT NULL"
    ).all<{ id: string }>();
    for (const row of emails) {
      if (row?.id) {
        await env.DB.prepare("DELETE FROM email_logs WHERE id=?").bind(row.id).run();
      }
    }
    counts.emails = emails.length;
  }
  return counts;
}

async function canvasFetch(
  env: Env,
  url: string,
  init?: RequestInit
): Promise<Response> {
  if (!env.CANVAS_API_TOKEN) {
    throw new Error("canvas_not_configured");
  }
  const headers = new Headers(init?.headers || {});
  headers.set("Authorization", `Bearer ${env.CANVAS_API_TOKEN}`);
  return fetch(url, { ...init, headers });
}

async function canvasFetchAll<T>(env: Env, url: string): Promise<T[]> {
  const results: T[] = [];
  let nextUrl: string | null = url;
  while (nextUrl) {
    const response = await canvasFetch(env, nextUrl);
    if (!response.ok) {
      const text = await response.text().catch(() => "");
      throw new Error(`canvas_request_failed:${response.status}:${text}`);
    }
    const batch = (await response.json()) as T[];
    if (Array.isArray(batch)) {
      results.push(...batch);
    }
    const links = parseLinkHeader(response.headers.get("link"));
    nextUrl = links.next || null;
  }
  return results;
}

async function syncCanvasCourses(
  env: Env,
  mode: "active" | "concluded" | "all"
): Promise<number> {
  const base = getCanvasBaseUrl(env);
  let url = `${base}/api/v1/courses?per_page=100`;
  if (mode === "active") {
    url += "&enrollment_state=active&state[]=available";
  } else if (mode === "concluded") {
    url += "&state[]=completed&state[]=concluded";
  } else {
    url += "&state[]=available&state[]=completed&state[]=concluded";
  }
  const courses = await canvasFetchAll<CanvasCourse & Record<string, unknown>>(env, url);
  const now = new Date().toISOString();
  for (const course of courses) {
    if (!course?.id) continue;
    await env.DB.prepare(
      "INSERT INTO canvas_courses_cache (id, name, code, workflow_state, account_id, term_id, updated_at, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET name=excluded.name, code=excluded.code, workflow_state=excluded.workflow_state, account_id=excluded.account_id, term_id=excluded.term_id, updated_at=excluded.updated_at, raw_json=excluded.raw_json"
    )
      .bind(
        String(course.id),
        String(course.name ?? ""),
        course.course_code ?? null,
        course.workflow_state ?? null,
        course.account_id ? String(course.account_id) : null,
        course.term_id ? String(course.term_id) : null,
        now,
        JSON.stringify(course)
      )
      .run();
  }
  return courses.length;
}

async function syncCanvasSections(env: Env, courseId: string): Promise<number> {
  const base = getCanvasBaseUrl(env);
  const url = `${base}/api/v1/courses/${encodeURIComponent(courseId)}/sections?per_page=100`;
  const sections = await canvasFetchAll<CanvasSection & Record<string, unknown>>(env, url);
  const now = new Date().toISOString();
  for (const section of sections) {
    if (!section?.id) continue;
    await env.DB.prepare(
      "INSERT INTO canvas_sections_cache (id, course_id, name, updated_at, raw_json) VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET course_id=excluded.course_id, name=excluded.name, updated_at=excluded.updated_at, raw_json=excluded.raw_json"
    )
      .bind(
        String(section.id),
        courseId,
        String(section.name ?? ""),
        now,
        JSON.stringify(section)
      )
      .run();
  }
  return sections.length;
}

async function getCanvasAllowedSections(
  env: Env,
  courseId: string,
  allowedIds: string[] | null
): Promise<Array<{ id: string; name: string }>> {
  const { results } = await env.DB.prepare(
    "SELECT id, name FROM canvas_sections_cache WHERE course_id=? ORDER BY name"
  )
    .bind(courseId)
    .all<{ id: string; name: string }>();
  let sections = results.map((row) => ({ id: String(row.id), name: row.name }));
  if (allowedIds && allowedIds.length > 0) {
    const allowed = new Set(allowedIds);
    sections = sections.filter((section) => allowed.has(section.id));
  }
  return sections;
}

async function canvasFindUserByEmail(
  env: Env,
  email: string,
  accountIdOverride?: string | null
): Promise<{ id: string | null; name?: string | null; loginId?: string | null; error?: string | null }> {
  const base = getCanvasBaseUrl(env);
  const target = email.toLowerCase();
  const urls = [
    `${base}/api/v1/accounts/self/users?search_term=${encodeURIComponent(email)}&per_page=100`
  ];
  const accountId = accountIdOverride || getCanvasAccountId(env);
  if (accountId) {
    urls.push(
      `${base}/api/v1/accounts/${encodeURIComponent(accountId)}/users?search_term=${encodeURIComponent(
        email
      )}&per_page=100`
    );
  }
  let lastError: string | null = null;
  for (const url of urls) {
    try {
      const res = await canvasFetch(env, url);
      if (!res.ok) {
        lastError = `${res.status}:${await res.text().catch(() => "")}`;
        continue;
      }
      const users = (await res.json()) as Array<{
        id?: string | number;
        login_id?: string;
        email?: string;
        sis_user_id?: string;
      }>;
      if (Array.isArray(users) && users.length > 0) {
        const match = users.find((user) => {
          const loginId = user?.login_id?.toLowerCase();
          const userEmail = user?.email?.toLowerCase();
          const sis = user?.sis_user_id?.toLowerCase();
          return loginId === target || userEmail === target || sis === target;
        });
        if (match?.id !== undefined && match?.id !== null) {
          return { id: String(match.id), name: (match as any)?.name ?? null, loginId: match?.login_id ?? null };
        }
        if (users.length === 1 && users[0]?.id !== undefined && users[0]?.id !== null) {
          return {
            id: String(users[0].id),
            name: (users[0] as any)?.name ?? null,
            loginId: (users[0] as any)?.login_id ?? null
          };
        }
      }
    } catch (error) {
      lastError = String((error as Error | undefined)?.message || error);
      continue;
    }
  }
  return { id: null, error: lastError };
}

async function canvasFindUserByEmailInCourse(
  env: Env,
  courseId: string,
  email: string
): Promise<CanvasCourseUser> {
  const results = await canvasSearchUsersInCourse(env, courseId, email);
  const target = email.toLowerCase();
  const match =
    results.find((user) => {
      const loginId = user?.loginId?.toLowerCase();
      const userEmail = user?.email?.toLowerCase();
      return loginId === target || userEmail === target;
    }) || results[0];
  if (match?.id) {
    return match;
  }
  return { id: null as unknown as string, error: "not_found" };
}

async function canvasSearchUsersInCourse(
  env: Env,
  courseId: string,
  query: string
): Promise<CanvasCourseUser[]> {
  const base = getCanvasBaseUrl(env);
  const url = `${base}/api/v1/courses/${encodeURIComponent(
    courseId
  )}/users?search_term=${encodeURIComponent(query)}&per_page=100&include[]=email&include[]=sis_user_id&include[]=enrollments`;
  try {
    const users = await canvasFetchAll<{
      id?: string | number;
      name?: string;
      login_id?: string;
      short_name?: string;
      sortable_name?: string;
      pronouns?: string;
      email?: string;
      sis_user_id?: string;
      enrollments?: Array<{ type?: string }>;
    }>(env, url);
    if (!Array.isArray(users) || users.length === 0) {
      return [];
    }
    return users
      .filter((user) => user?.id !== undefined && user?.id !== null)
      .map((user) => ({
        id: String(user.id),
        name: user?.name ?? null,
        loginId: user?.login_id ?? null,
        shortName: user?.short_name ?? null,
        sortableName: user?.sortable_name ?? null,
        pronouns: user?.pronouns ?? null,
        email: user?.email ?? null,
        roles: Array.isArray(user?.enrollments)
          ? Array.from(
            new Set(
              user.enrollments
                .map((enrollment) => enrollment?.type || "")
                .filter((value) => value.length > 0)
                .map((value) => value.replace("Enrollment", ""))
            )
          )
          : []
      }));
  } catch (error) {
    return [];
  }
}

async function canvasSearchUsersGlobal(
  env: Env,
  query: string
): Promise<CanvasCourseUser[]> {
  const base = getCanvasBaseUrl(env);
  const accountId = getCanvasAccountId(env);
  const url = accountId
    ? `${base}/api/v1/accounts/${encodeURIComponent(
      accountId
    )}/users?search_term=${encodeURIComponent(query)}&per_page=100&include[]=email&include[]=sis_user_id`
    : `${base}/api/v1/accounts/self/users?search_term=${encodeURIComponent(
      query
    )}&per_page=100&include[]=email&include[]=sis_user_id`;
  try {
    const users = await canvasFetchAll<{
      id?: string | number;
      name?: string;
      login_id?: string;
      short_name?: string;
      sortable_name?: string;
      pronouns?: string;
      email?: string;
      sis_user_id?: string;
    }>(env, url);
    if (!Array.isArray(users) || users.length === 0) {
      return [];
    }
    return users
      .filter((user) => user?.id !== undefined && user?.id !== null)
      .map((user) => ({
        id: String(user.id),
        name: user?.name ?? null,
        loginId: user?.login_id ?? null,
        shortName: user?.short_name ?? null,
        sortableName: user?.sortable_name ?? null,
        pronouns: user?.pronouns ?? null,
        email: user?.email ?? null,
        roles: []
      }));
  } catch {
    return [];
  }
}

async function canvasSearchUsersAllCourses(
  env: Env,
  query: string
): Promise<Array<CanvasCourseUser & { courses: Array<{ id: string; name: string; roles: string[] }> }>> {
  const { results: courses } = await env.DB.prepare(
    "SELECT id,name FROM canvas_courses_cache WHERE (workflow_state IS NULL OR workflow_state NOT IN ('completed','concluded','deleted')) ORDER BY name"
  ).all<{ id: string; name: string }>();
  if (courses.length === 0) {
    return [];
  }
  const map = new Map<
    string,
    CanvasCourseUser & { courses: Array<{ id: string; name: string; roles: string[] }> }
  >();
  for (const course of courses) {
    const matches = await canvasSearchUsersInCourse(env, String(course.id), query);
    matches.forEach((user) => {
      if (!user?.id) return;
      const existing = map.get(user.id);
      const courseEntry = {
        id: String(course.id),
        name: course.name,
        roles: Array.isArray(user.roles) ? user.roles : []
      };
      if (existing) {
        existing.courses.push(courseEntry);
      } else {
        map.set(user.id, {
          ...user,
          courses: [courseEntry]
        });
      }
    });
  }
  return Array.from(map.values());
}

async function canvasCreateUser(
  env: Env,
  name: string,
  email: string,
  accountIdOverride?: string | null
): Promise<{ id: string | null; error?: string | null }> {
  const accountId = accountIdOverride || getCanvasAccountId(env);
  if (!accountId) {
    return { id: null, error: "canvas_account_id_missing" };
  }
  const base = getCanvasBaseUrl(env);
  const nameParts = name.trim().split(/\s+/).filter(Boolean);
  const firstName = nameParts[0] || name;
  const lastName = nameParts.length > 1 ? nameParts[nameParts.length - 1] : name;
  const shortName = `${firstName} ${lastName}`.trim();
  const sortableName = `${lastName}, ${firstName}`.trim();
  const createPayload = {
    user: {
      name,
      short_name: shortName || name,
      sortable_name: sortableName || name,
      terms_of_use: true
    },
    pseudonym: {
      unique_id: email,
      force_self_registration: true
    }
  };
  const res = await canvasFetch(env, `${base}/api/v1/accounts/${accountId}/users`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(createPayload)
  });
  if (res.status === 400) {
    const text = await res.text().catch(() => "");
    const lower = text.toLowerCase();
    if (lower.includes("already belongs to a user") || lower.includes("id already in use")) {
      const existing = await canvasFindUserByEmail(env, email, accountId);
      return { id: existing?.id || null, error: existing?.id ? null : "user_exists_but_not_found" };
    }
    return { id: null, error: text || "canvas_user_create_failed" };
  }
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    return { id: null, error: text || `canvas_user_create_failed:${res.status}` };
  }
  const responsePayload = (await res.json()) as {
    id?: string | number;
    user?: { id?: string | number };
  };
  const userId = responsePayload?.id ?? responsePayload?.user?.id;
  if (userId === undefined || userId === null) {
    return { id: null, error: "canvas_user_create_missing_id" };
  }
  return { id: String(userId) };
}

async function canvasEnrollUser(
  env: Env,
  courseId: string,
  userId: string,
  sectionId: string | null,
  enrollmentState = "active",
  enrollmentType = "StudentEnrollment"
): Promise<{ ok: boolean; status: number; error?: string }> {
  const trimmedUserId = `${userId}`.trim();
  const isSpecialId =
    trimmedUserId.startsWith("sis_login_id:") ||
    trimmedUserId.startsWith("login_id:") ||
    trimmedUserId.startsWith("sis_user_id:");
  if (!trimmedUserId || trimmedUserId === "null" || trimmedUserId === "undefined") {
    return { ok: false, status: 400, error: "missing_user_id" };
  }
  if (!isSpecialId && !/^\d+$/.test(trimmedUserId)) {
    return { ok: false, status: 400, error: "invalid_user_id" };
  }
  const base = getCanvasBaseUrl(env);
  const params = new URLSearchParams();
  params.set("enrollment[type]", enrollmentType);
  params.set("enrollment[enrollment_state]", enrollmentState);
  params.set("enrollment[notify]", "true");
  params.set("enrollment[user_id]", trimmedUserId);
  if (sectionId) {
    params.set("enrollment[course_section_id]", sectionId);
    params.set("enrollment[limit_privileges_to_course_section]", "true");
  }
  const res = await canvasFetch(env, `${base}/api/v1/courses/${courseId}/enrollments`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: params
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    return { ok: false, status: res.status, error: text || "enroll_failed" };
  }
  return { ok: true, status: res.status };
}

async function canvasFindEnrollment(
  env: Env,
  courseId: string,
  canvasUserId: string
): Promise<{ id: string | null; error?: string | null }> {
  const base = getCanvasBaseUrl(env);
  const params = new URLSearchParams();
  params.set("user_id", canvasUserId);
  params.set("per_page", "100");
  params.append("type[]", "StudentEnrollment");
  ["active", "invited", "completed", "inactive"].forEach((state) => {
    params.append("state[]", state);
  });
  const url = `${base}/api/v1/courses/${encodeURIComponent(courseId)}/enrollments?${params.toString()}`;
  const enrollments = await canvasFetchAll<any>(env, url);
  const match = enrollments.find((enrollment) => enrollment?.id);
  if (!match?.id) {
    return { id: null, error: "enrollment_not_found" };
  }
  return { id: String(match.id) };
}

async function canvasFindEnrollmentByEmail(
  env: Env,
  courseId: string,
  email: string
): Promise<{ id: string | null; state?: string | null; canvasUserId?: string | null; error?: string | null }> {
  const base = getCanvasBaseUrl(env);
  const params = new URLSearchParams();
  params.set("per_page", "100");
  params.append("type[]", "StudentEnrollment");
  params.append("include[]", "user");
  ["active", "invited", "completed", "inactive"].forEach((state) => {
    params.append("state[]", state);
  });
  const url = `${base}/api/v1/courses/${encodeURIComponent(courseId)}/enrollments?${params.toString()}`;
  try {
    const enrollments = await canvasFetchAll<any>(env, url);
    const target = email.toLowerCase();
    const match = enrollments.find((enrollment) => {
      const loginId = enrollment?.user?.login_id;
      return typeof loginId === "string" && loginId.toLowerCase() === target;
    });
    if (!match?.id) {
      return { id: null, error: "enrollment_not_found" };
    }
    return {
      id: String(match.id),
      state: match?.enrollment_state ?? match?.state ?? null,
      canvasUserId: match?.user?.id ? String(match.user.id) : null
    };
  } catch (error) {
    return { id: null, error: String((error as Error | undefined)?.message || error) };
  }
}

async function canvasApplyEnrollmentTask(
  env: Env,
  courseId: string,
  enrollmentId: string,
  task: "deactivate" | "delete" | "reactivate"
): Promise<{ ok: boolean; error?: string | null }> {
  const base = getCanvasBaseUrl(env);
  const url = `${base}/api/v1/courses/${encodeURIComponent(courseId)}/enrollments/${encodeURIComponent(
    enrollmentId
  )}?task=${task}`;
  const res = await canvasFetch(env, url, { method: "DELETE" });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    return { ok: false, error: text || `enrollment_${task}_failed` };
  }
  return { ok: true };
}

async function canvasReactivateEnrollment(
  env: Env,
  courseId: string,
  enrollmentId: string
): Promise<{ ok: boolean; error?: string | null }> {
  const base = getCanvasBaseUrl(env);
  const url = `${base}/api/v1/courses/${encodeURIComponent(courseId)}/enrollments/${encodeURIComponent(
    enrollmentId
  )}/reactivate`;
  const res = await canvasFetch(env, url, { method: "PUT" });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    return { ok: false, error: text || "enrollment_reactivate_failed" };
  }
  return { ok: true };
}

async function canvasApplyEnrollmentTaskByEmail(
  env: Env,
  courseId: string,
  email: string,
  task: "deactivate" | "delete" | "reactivate"
): Promise<{ ok: boolean; error?: string | null; canvasUserId?: string | null }> {
  if (!env.CANVAS_API_TOKEN) {
    return { ok: false, error: "canvas_not_configured" };
  }
  const lookup = await canvasFindUserByEmail(env, email);
  let canvasUserId = lookup?.id || null;
  let lookupError = lookup?.error || null;
  if (!canvasUserId) {
    const courseLookup = await canvasFindUserByEmailInCourse(env, courseId, email);
    canvasUserId = courseLookup?.id || null;
    if (!canvasUserId) {
      const courseError = courseLookup?.error || "not_found";
      const combined = lookupError ? `${lookupError}|${courseError}` : courseError;
      const enrollmentByEmail = await canvasFindEnrollmentByEmail(env, courseId, email);
      if (enrollmentByEmail.id) {
        const result = await canvasApplyEnrollmentTask(env, courseId, enrollmentByEmail.id, task);
        if (!result.ok) {
          return { ok: false, error: result.error || `enrollment_${task}_failed` };
        }
        return { ok: true, canvasUserId: enrollmentByEmail.canvasUserId ?? null };
      }
      return { ok: false, error: `user_lookup_failed:${combined}` };
    }
  }
  let enrollment = await canvasFindEnrollment(env, courseId, canvasUserId);
  if (!enrollment.id) {
    const enrollmentByEmail = await canvasFindEnrollmentByEmail(env, courseId, email);
    if (enrollmentByEmail.id) {
      enrollment = { id: enrollmentByEmail.id };
      canvasUserId = enrollmentByEmail.canvasUserId ?? canvasUserId;
    }
  }
  if (!enrollment.id) {
    return { ok: false, error: enrollment.error || "enrollment_not_found" };
  }
  const result = await canvasApplyEnrollmentTask(env, courseId, enrollment.id, task);
  if (!result.ok) {
    return { ok: false, error: result.error || `enrollment_${task}_failed` };
  }
  return { ok: true, canvasUserId };
}

async function canvasReactivateByEmail(
  env: Env,
  courseId: string,
  email: string
): Promise<{ ok: boolean; error?: string | null; canvasUserId?: string | null }> {
  if (!env.CANVAS_API_TOKEN) {
    return { ok: false, error: "canvas_not_configured" };
  }
  const enrollment = await canvasFindEnrollmentByEmail(env, courseId, email);
  if (!enrollment.id) {
    return { ok: false, error: enrollment.error || "enrollment_not_found" };
  }
  const result = await canvasReactivateEnrollment(env, courseId, enrollment.id);
  if (!result.ok) {
    return { ok: false, error: result.error || "enrollment_reactivate_failed" };
  }
  return { ok: true, canvasUserId: enrollment.canvasUserId ?? null };
}

async function canvasSendMessage(
  env: Env,
  recipientId: string,
  subject: string,
  body: string
): Promise<{ ok: boolean; error?: string | null }> {
  const base = getCanvasBaseUrl(env);
  const params = new URLSearchParams();
  params.append("recipients[]", recipientId);
  params.set("subject", subject);
  params.set("body", body);
  const res = await canvasFetch(env, `${base}/api/v1/conversations`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    return { ok: false, error: text || `message_failed:${res.status}` };
  }
  return { ok: true };
}

async function ensureCanvasNameCheckRow(env: Env, userId: string, courseId: string) {
  if (!userId || !courseId) return;
  await env.DB.prepare(
    "INSERT INTO canvas_name_checks (user_id, course_id, first_submission_at) VALUES (?, ?, datetime('now')) ON CONFLICT(user_id, course_id) DO NOTHING"
  )
    .bind(userId, courseId)
    .run();
}

async function runCanvasNameMismatchChecks(
  env: Env
): Promise<{ checked: number; mismatched: number; resolved: number; skipped: number }> {
  if (!env.CANVAS_API_TOKEN) {
    return { checked: 0, mismatched: 0, resolved: 0, skipped: 0 };
  }
  const { results } = await env.DB.prepare(
    "SELECT user_id, course_id, first_submission_at, last_alert_at, resolved_at FROM canvas_name_checks WHERE resolved_at IS NULL"
  ).all<{
    user_id: string;
    course_id: string;
    first_submission_at: string;
    last_alert_at: string | null;
    resolved_at: string | null;
  }>();
  if (!Array.isArray(results) || results.length === 0) {
    return { checked: 0, mismatched: 0, resolved: 0, skipped: 0 };
  }
  const now = Date.now();
  const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;
  let checked = 0;
  let mismatched = 0;
  let resolved = 0;
  let skipped = 0;
  for (const row of results) {
    const firstAt = Date.parse(row.first_submission_at);
    if (!Number.isFinite(firstAt)) {
      skipped += 1;
      continue;
    }
    if (now - firstAt < sevenDaysMs) {
      skipped += 1;
      continue;
    }
    if (row.last_alert_at) {
      const lastAlertAt = Date.parse(row.last_alert_at);
      if (Number.isFinite(lastAlertAt) && now - lastAlertAt < sevenDaysMs) {
        skipped += 1;
        continue;
      }
    }
    checked += 1;
    const submission = await env.DB.prepare(
      "SELECT s.id,s.payload_json,s.submitter_email,f.slug as form_slug,f.title as form_title FROM submissions s JOIN forms f ON f.id=s.form_id WHERE s.user_id=? AND s.canvas_course_id=? AND s.deleted_at IS NULL AND f.deleted_at IS NULL ORDER BY COALESCE(s.updated_at, s.created_at) DESC LIMIT 1"
    )
      .bind(row.user_id, row.course_id)
      .first<{
        id: string;
        payload_json: string;
        submitter_email: string | null;
        form_slug: string | null;
        form_title: string | null;
      }>();
    if (!submission) {
      skipped += 1;
      continue;
    }
    let payloadData: Record<string, unknown> | null = null;
    try {
      const parsed = JSON.parse(submission.payload_json) as { data?: Record<string, unknown> };
      if (parsed?.data && typeof parsed.data === "object") {
        payloadData = parsed.data as Record<string, unknown>;
      }
    } catch {
      payloadData = null;
    }
    const submittedName = pickNameFromPayload(payloadData);
    if (!submittedName) {
      await env.DB.prepare(
        "UPDATE canvas_name_checks SET last_checked_at=datetime('now') WHERE user_id=? AND course_id=?"
      )
        .bind(row.user_id, row.course_id)
        .run();
      skipped += 1;
      continue;
    }
    let email =
      (typeof payloadData?.email === "string" && payloadData.email.trim()) ||
      submission.submitter_email ||
      null;
    if (!email) {
      const emailRow = await env.DB.prepare(
        "SELECT email FROM user_identities WHERE user_id=? AND email IS NOT NULL ORDER BY created_at DESC LIMIT 1"
      )
        .bind(row.user_id)
        .first<{ email: string | null }>();
      email = emailRow?.email ?? null;
    }
    if (!email) {
      await env.DB.prepare(
        "UPDATE canvas_name_checks SET last_checked_at=datetime('now') WHERE user_id=? AND course_id=?"
      )
        .bind(row.user_id, row.course_id)
        .run();
      skipped += 1;
      continue;
    }
    const canvasUser = await canvasFindUserByEmailInCourse(env, row.course_id, email);
    const canvasFullName = canvasUser?.name?.trim() || null;
    const canvasDisplayName = canvasUser?.shortName?.trim() || null;
    const trimmedSubmitted = submittedName.trim();
    const namesMissing = !canvasFullName || !canvasDisplayName;
    const namesMatch =
      Boolean(trimmedSubmitted) &&
      canvasFullName === trimmedSubmitted &&
      canvasDisplayName === trimmedSubmitted;
    if (!namesMissing && namesMatch) {
      await env.DB.prepare(
        "UPDATE canvas_name_checks SET resolved_at=datetime('now'), last_checked_at=datetime('now') WHERE user_id=? AND course_id=?"
      )
        .bind(row.user_id, row.course_id)
        .run();
      resolved += 1;
      continue;
    }
    mismatched += 1;
    const baseWeb = env.BASE_URL_WEB ? String(env.BASE_URL_WEB).replace(/\/$/, "") : "";
    const formLink =
      baseWeb && submission.form_slug ? `${baseWeb}/#/f/${submission.form_slug}` : null;
    const message = buildCanvasNameAlertMessage({
      submittedName,
      canvasFullName,
      canvasDisplayName,
      formLink
    });
    const result = await sendGmailMessage(env, {
      to: email,
      subject: message.subject,
      body: message.body
    });
    await logEmailSend(env, {
      to: email,
      subject: message.subject,
      body: message.body,
      status: result.ok ? "sent" : "failed",
      error: result.ok ? null : result.error || "send_failed",
      submissionId: submission.id,
      formSlug: submission.form_slug ?? null,
      formTitle: submission.form_title ?? null,
      canvasCourseId: row.course_id,
      triggeredBy: row.user_id,
      triggerSource: "auto_alert"
    });
    await env.DB.prepare(
      "UPDATE canvas_name_checks SET last_alert_at=datetime('now'), last_checked_at=datetime('now') WHERE user_id=? AND course_id=?"
    )
      .bind(row.user_id, row.course_id)
      .run();
  }
  return { checked, mismatched, resolved, skipped };
}

function pickFirstStringValue(
  data: Record<string, unknown> | null,
  keys: string[]
): string | null {
  if (!data) return null;
  for (const key of keys) {
    const value = data[key];
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }
  return null;
}

function pickFirstStringEntry(
  data: Record<string, unknown> | null,
  keys: string[]
): { key: string; value: string } | null {
  if (!data) return null;
  for (const key of keys) {
    const value = data[key];
    if (typeof value === "string" && value.trim()) {
      return { key, value: value.trim() };
    }
  }
  return null;
}

function formatDateValueForMessage(
  rawValue: string,
  mode: "date" | "time" | "datetime",
  timeZone: string | null,
  showTimezone: boolean
): string {
  const date = new Date(rawValue);
  if (Number.isNaN(date.getTime())) {
    return rawValue;
  }
  const options: Intl.DateTimeFormatOptions =
    mode === "time"
      ? { hour: "2-digit", minute: "2-digit" }
      : mode === "date"
        ? { year: "numeric", month: "2-digit", day: "2-digit" }
        : {
          year: "numeric",
          month: "2-digit",
          day: "2-digit",
          hour: "2-digit",
          minute: "2-digit"
        };
  let formatted = "";
  if (timeZone) {
    try {
      formatted = new Intl.DateTimeFormat("en-GB", { ...options, timeZone }).format(date);
    } catch {
      formatted = new Intl.DateTimeFormat("en-GB", options).format(date);
    }
  } else {
    formatted = new Intl.DateTimeFormat("en-GB", options).format(date);
  }
  if (showTimezone && timeZone) {
    return `${formatted} (${timeZone})`;
  }
  return formatted;
}

function joinLines(lines: Array<string | null | undefined>): string {
  return lines
    .filter((line): line is string => line !== null && line !== undefined)
    .join("\n");
}

function buildCanvasNameAlertMessage(input: {
  submittedName: string;
  canvasFullName: string | null;
  canvasDisplayName: string | null;
  formLink?: string | null;
}): { subject: string; body: string } {
  const subject =
    "Update your Canvas display name (C\u1eadp nh\u1eadt t\u00ean hi\u1ec3n th\u1ecb tr\u00ean Canvas)";
  const submittedName = input.submittedName.trim();
  const canvasFullName = input.canvasFullName?.trim() || "n/a";
  const canvasDisplayName = input.canvasDisplayName?.trim() || "n/a";
  const englishLines = [
    "Hello,",
    "",
    "Your Canvas display name is missing or does not match the name you registered through the form.",
    "Please update your Canvas display name.",
    "Please check your email for the Canvas invitation.",
    "",
    `Name in form: ${submittedName}`,
    `Canvas full name: ${canvasFullName}`,
    `Canvas display name: ${canvasDisplayName}`,
    "",
    input.formLink ? `Form link: ${input.formLink}` : null,
    "",
    "This message was sent automatically."
  ];
  const vietnameseLines = [
    "Xin ch\u00e0o,",
    "",
    "T\u00ean hi\u1ec3n th\u1ecb tr\u00ean Canvas c\u1ee7a b\u1ea1n \u0111ang b\u1ecb thi\u1ebfu ho\u1eb7c ch\u01b0a kh\u1edbp v\u1edbi t\u00ean b\u1ea1n \u0111\u0103ng k\u00fd th\u00f4ng qua form.",
    "Vui l\u00f2ng c\u1eadp nh\u1eadt t\u00ean hi\u1ec3n th\u1ecb tr\u00ean Canvas.",
    "Vui l\u00f2ng ki\u1ec3m tra email \u0111\u1ec3 nh\u1eadn l\u1eddi m\u1eddi t\u1eeb Canvas.",
    "",
    `T\u00ean \u0111\u00e3 \u0111i\u1ec1n trong form: ${submittedName}`,
    `H\u1ecd t\u00ean tr\u00ean Canvas: ${canvasFullName}`,
    `T\u00ean hi\u1ec3n th\u1ecb tr\u00ean Canvas: ${canvasDisplayName}`,
    "",
    input.formLink ? `Link form: ${input.formLink}` : null,
    "",
    "Th\u00f4ng b\u00e1o n\u00e0y \u0111\u01b0\u1ee3c g\u1eedi t\u1ef1 \u0111\u1ed9ng."
  ];
  return {
    subject,
    body: joinLines([...englishLines, "", ...vietnameseLines])
  };
}

function buildCanvasWelcomeMessage(input: {
  formTitle?: string | null;
  courseLabel?: string | null;
  sectionLabel?: string | null;
  submittedName: string;
  submittedEmail?: string | null;
  studentId?: string | null;
  className?: string | null;
  dob?: string | null;
  formLink?: string | null;
}): { subject: string; body: string } {
  const subject = "Welcome to the course (Ch\u00e0o m\u1eebng b\u1ea1n)";
  const submittedName = input.submittedName.trim();
  const submittedEmail = input.submittedEmail?.trim() || "n/a";
  const studentId = input.studentId?.trim() || "n/a";
  const className = input.className?.trim() || "n/a";
  const dob = input.dob?.trim() || null;
  const englishLines = [
    "Hello,",
    "",
    "Welcome!",
    "We received your information.",
    "Please check your email for the Canvas invitation.",
    "",
    "Your submission summary:",
    `- Form: ${input.formTitle || "n/a"}`,
    `- Course: ${input.courseLabel || "n/a"}`,
    `- Section (L\u1edbp h\u1ecdc ph\u1ea7n): ${input.sectionLabel || "n/a"}`,
    `- Full name: ${submittedName}`,
    `- Email: ${submittedEmail}`,
    `- Student ID: ${studentId}`,
    `- Class: ${className}`,
    dob ? `- Date of birth: ${dob}` : null,
    input.formLink ? `Form link: ${input.formLink}` : null,
    "",
    "This message was sent automatically."
  ];
  const vietnameseLines = [
    "Xin ch\u00e0o,",
    "",
    "Ch\u00e0o m\u1eebng b\u1ea1n!",
    "Ch\u00fang t\u00f4i \u0111\u00e3 nh\u1eadn \u0111\u01b0\u1ee3c th\u00f4ng tin t\u1eeb b\u1ea1n.",
    "Vui l\u00f2ng ki\u1ec3m tra email \u0111\u1ec3 nh\u1eadn l\u1eddi m\u1eddi t\u1eeb Canvas.",
    "",
    "T\u00f3m t\u1eaft n\u1ed9i dung b\u1ea1n \u0111\u00e3 \u0111i\u1ec1n:",
    `- Form: ${input.formTitle || "n/a"}`,
    `- M\u00f4n h\u1ecdc: ${input.courseLabel || "n/a"}`,
    `- L\u1edbp h\u1ecdc ph\u1ea7n: ${input.sectionLabel || "n/a"}`,
    `- H\u1ecd v\u00e0 t\u00ean: ${submittedName}`,
    `- Email: ${submittedEmail}`,
    `- M\u00e3 sinh vi\u00ean: ${studentId}`,
    `- L\u1edbp: ${className}`,
    dob ? `- Ng\u00e0y sinh: ${dob}` : null,
    input.formLink ? `Link form: ${input.formLink}` : null,
    "",
    "Th\u00f4ng b\u00e1o n\u00e0y \u0111\u01b0\u1ee3c g\u1eedi t\u1ef1 \u0111\u1ed9ng."
  ];
  return {
    subject,
    body: joinLines([...englishLines, "", ...vietnameseLines])
  };
}

function buildCanvasInformMessage(input: {
  formTitle?: string | null;
  courseLabel?: string | null;
  sectionLabel?: string | null;
  submittedName: string;
  submittedEmail?: string | null;
  studentId?: string | null;
  className?: string | null;
  dob?: string | null;
  formLink?: string | null;
}): { subject: string; body: string } {
  const subject = "Submission updated (C\u1eadp nh\u1eadt th\u00f4ng tin)";
  const submittedName = input.submittedName.trim();
  const submittedEmail = input.submittedEmail?.trim() || "n/a";
  const studentId = input.studentId?.trim() || "n/a";
  const className = input.className?.trim() || "n/a";
  const dob = input.dob?.trim() || null;
  const englishLines = [
    "Hello,",
    "",
    "We received your latest updated information.",
    "",
    "Your latest submission summary:",
    `- Form: ${input.formTitle || "n/a"}`,
    `- Course: ${input.courseLabel || "n/a"}`,
    `- Section (L\u1edbp h\u1ecdc ph\u1ea7n): ${input.sectionLabel || "n/a"}`,
    `- Full name: ${submittedName}`,
    `- Email: ${submittedEmail}`,
    `- Student ID: ${studentId}`,
    `- Class: ${className}`,
    dob ? `- Date of birth: ${dob}` : null,
    "",
    input.formLink ? `Form link: ${input.formLink}` : null,
    "",
    "This message was sent automatically."
  ];
  const vietnameseLines = [
    "Xin ch\u00e0o,",
    "",
    "Ch\u00fang t\u00f4i \u0111\u00e3 nh\u1eadn \u0111\u01b0\u1ee3c th\u00f4ng tin c\u1eadp nh\u1eadt m\u1edbi nh\u1ea5t t\u1eeb b\u1ea1n.",
    "",
    "T\u00f3m t\u1eaft th\u00f4ng tin m\u1edbi nh\u1ea5t:",
    `- Form: ${input.formTitle || "n/a"}`,
    `- M\u00f4n h\u1ecdc: ${input.courseLabel || "n/a"}`,
    `- L\u1edbp h\u1ecdc ph\u1ea7n: ${input.sectionLabel || "n/a"}`,
    `- H\u1ecd v\u00e0 t\u00ean: ${submittedName}`,
    `- Email: ${submittedEmail}`,
    `- M\u00e3 sinh vi\u00ean: ${studentId}`,
    `- L\u1edbp: ${className}`,
    dob ? `- Ng\u00e0y sinh: ${dob}` : null,
    "",
    input.formLink ? `Link form: ${input.formLink}` : null,
    "",
    "Th\u00f4ng b\u00e1o n\u00e0y \u0111\u01b0\u1ee3c g\u1eedi t\u1ef1 \u0111\u1ed9ng."
  ];
  return {
    subject,
    body: joinLines([...englishLines, "", ...vietnameseLines])
  };
}

function buildAccountGoodbyeMessage(): { subject: string; body: string } {
  const subject = "Account deleted (T\u00e0i kho\u1ea3n \u0111\u00e3 b\u1ecb x\u00f3a)";
  const englishLines = [
    "Hello,",
    "",
    "Your account has been deleted and your form submission has been moved to trash.",
    "If you want to restore your account, please contact an admin.",
    "",
    "Delete policy:",
    "- Your account is soft-deleted (moved to trash).",
    "- Your form submission content and uploaded files are moved to trash.",
    "- The Canvas account you registered with us will be deactivated in the course.",
    "- Restoration is only possible by an admin.",
    "",
    "This message was sent automatically."
  ];
  const vietnameseLines = [
    "Xin ch\u00e0o,",
    "",
    "T\u00e0i kho\u1ea3n c\u1ee7a b\u1ea1n \u0111\u00e3 b\u1ecb x\u00f3a v\u00e0 c\u00e1c n\u1ed9i dung \u0111i\u1ec1n form \u0111\u00e3 \u0111\u01b0\u1ee3c chuy\u1ec3n v\u00e0o th\u00f9ng r\u00e1c.",
    "N\u1ebfu b\u1ea1n mu\u1ed1n kh\u00f4i ph\u1ee5c t\u00e0i kho\u1ea3n, vui l\u00f2ng li\u00ean h\u1ec7 qu\u1ea3n tr\u1ecb vi\u00ean.",
    "",
    "Ch\u00ednh s\u00e1ch x\u00f3a:",
    "- T\u00e0i kho\u1ea3n c\u1ee7a b\u1ea1n ch\u1ec9 b\u1ecb x\u00f3a m\u1ec1m (chuy\u1ec3n v\u00e0o th\u00f9ng r\u00e1c).",
    "- C\u00e1c n\u1ed9i dung \u0111i\u1ec1n form v\u00e0 t\u1ec7p \u0111\u00e3 t\u1ea3i l\u00ean \u0111\u01b0\u1ee3c chuy\u1ec3n v\u00e0o th\u00f9ng r\u00e1c.",
    "- T\u00e0i kho\u1ea3n Canvas b\u1ea1n \u0111\u0103ng k\u00fd v\u1edbi ch\u00fang t\u00f4i s\u1ebd b\u1ecb v\u00f4 hi\u1ec7u h\u00f3a trong kh\u00f3a h\u1ecdc.",
    "- Vi\u1ec7c kh\u00f4i ph\u1ee5c ch\u1ec9 c\u00f3 th\u1ec3 th\u1ef1c hi\u1ec7n b\u1edfi qu\u1ea3n tr\u1ecb vi\u00ean.",
    "",
    "Th\u00f4ng b\u00e1o n\u00e0y \u0111\u01b0\u1ee3c g\u1eedi t\u1ef1 \u0111\u1ed9ng."
  ];
  return {
    subject,
    body: joinLines([...englishLines, "", ...vietnameseLines])
  };
}
function base64UrlFromBytes(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64FromBytes(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function encodeEmailHeader(value: string): string {
  const encoded = base64FromBytes(new TextEncoder().encode(value));
  return `=?UTF-8?B?${encoded}?=`;
}

async function sendGmailMessage(
  env: Env,
  input: { to: string; subject: string; body: string }
): Promise<{ ok: boolean; error?: string | null }> {
  if (!env.GMAIL_REFRESH_TOKEN || !env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) {
    await recordHealthStatus(env, "gmail_send", "skipped", "gmail_not_configured");
    return { ok: false, error: "gmail_not_configured" };
  }
  const sender = env.GMAIL_SENDER_EMAIL?.trim();
  if (!sender) {
    await recordHealthStatus(env, "gmail_send", "skipped", "gmail_sender_missing");
    return { ok: false, error: "gmail_sender_missing" };
  }
  const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      refresh_token: env.GMAIL_REFRESH_TOKEN,
      grant_type: "refresh_token"
    })
  });
  if (!tokenResponse.ok) {
    const text = await tokenResponse.text();
    await recordHealthStatus(env, "gmail_send", "error", text || "gmail_token_failed");
    return { ok: false, error: text || "gmail_token_failed" };
  }
  const tokenPayload = (await tokenResponse.json()) as { access_token?: string };
  if (!tokenPayload.access_token) {
    await recordHealthStatus(env, "gmail_send", "error", "gmail_token_missing");
    return { ok: false, error: "gmail_token_missing" };
  }
  const subjectHeader = encodeEmailHeader(input.subject);
  const mime = [
    `From: ${sender}`,
    `To: ${input.to}`,
    `Subject: ${subjectHeader}`,
    'Content-Type: text/plain; charset="UTF-8"',
    "Content-Transfer-Encoding: 8bit",
    "",
    input.body
  ].join("\r\n");
  const raw = base64UrlFromBytes(new TextEncoder().encode(mime));
  const sendResponse = await fetch("https://gmail.googleapis.com/gmail/v1/users/me/messages/send", {
    method: "POST",
    headers: {
      authorization: `Bearer ${tokenPayload.access_token}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({ raw })
  });
  if (!sendResponse.ok) {
    const text = await sendResponse.text();
    await recordHealthStatus(env, "gmail_send", "error", text || "gmail_send_failed");
    return { ok: false, error: text || "gmail_send_failed" };
  }
  await recordHealthStatus(env, "gmail_send", "ok", "sent");
  return { ok: true };
}

async function logEmailSend(
  env: Env,
  input: {
    to: string;
    subject: string;
    body: string;
    status: "sent" | "failed";
    error?: string | null;
    submissionId?: string | null;
    formId?: string | null;
    formSlug?: string | null;
    formTitle?: string | null;
    canvasCourseId?: string | null;
    canvasSectionId?: string | null;
    triggeredBy?: string | null;
    triggerSource?: string;
  }
): Promise<void> {
  try {
    await env.DB.prepare(
      "INSERT INTO email_logs (id, to_email, subject, body, status, error, submission_id, form_id, form_slug, form_title, canvas_course_id, canvas_section_id, triggered_by, trigger_source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
      .bind(
        crypto.randomUUID(),
        input.to,
        input.subject,
        input.body,
        input.status,
        input.error || null,
        input.submissionId ?? null,
        input.formId ?? null,
        input.formSlug ?? null,
        input.formTitle ?? null,
        input.canvasCourseId ?? null,
        input.canvasSectionId ?? null,
        input.triggeredBy ?? null,
        input.triggerSource ?? null
      )
      .run();
  } catch (error) {
    console.error("email_log_failed", String((error as Error | undefined)?.message || error));
  }
}

async function getUserPrimaryEmail(env: Env, userId: string): Promise<string | null> {
  const row = await env.DB.prepare(
    "SELECT email FROM user_identities WHERE user_id=? AND email IS NOT NULL ORDER BY CASE provider WHEN 'google' THEN 0 ELSE 1 END, created_at ASC LIMIT 1"
  )
    .bind(userId)
    .first<{ email: string | null }>();
  return row?.email ?? null;
}

async function canvasApplyTaskForUserCourses(
  env: Env,
  userId: string,
  task: "deactivate" | "delete" | "reactivate"
): Promise<{ attempted: number; failed: number }> {
  const email = await getUserPrimaryEmail(env, userId);
  if (!email) return { attempted: 0, failed: 0 };
  const { results } = await env.DB.prepare(
    "SELECT DISTINCT canvas_course_id as course_id FROM submissions WHERE user_id=? AND canvas_course_id IS NOT NULL"
  )
    .bind(userId)
    .all<{ course_id: string }>();
  let attempted = 0;
  let failed = 0;
  for (const row of results) {
    if (!row?.course_id) continue;
    try {
      attempted += 1;
      if (task === "reactivate") {
        const result = await canvasReactivateByEmail(env, String(row.course_id), email);
        if (!result.ok) {
          await handleCanvasEnrollment(
            env,
            { canvas_enabled: 1, canvas_course_id: String(row.course_id) },
            titleCaseFromEmail(email),
            email,
            null
          );
        }
      } else {
        await canvasApplyEnrollmentTaskByEmail(env, String(row.course_id), email, task);
      }
    } catch {
      failed += 1;
      // Best effort; do not block deletion flows.
    }
  }
  await env.DB.prepare(
    "UPDATE submissions SET canvas_enroll_status=?, canvas_enroll_error=? WHERE user_id=? AND canvas_course_id IS NOT NULL"
  )
    .bind(
      task === "delete" ? "deleted" : task === "reactivate" ? "invited" : "deactivated",
      task === "reactivate" ? "user_restored" : "user_deleted",
      userId
    )
    .run();
  return { attempted, failed };
}

function titleCaseFromEmail(email: string) {
  const local = email.split("@")[0] || "";
  const parts = local.replace(/[._-]+/g, " ").split(/\s+/).filter(Boolean);
  if (parts.length === 0) return "User";
  return parts
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join(" ");
}

function pickNameFromPayload(payload: Record<string, unknown> | null): string | null {
  if (!payload) return null;
  const preferredKeys = ["full_name", "fullName", "fullname", "full-name", "name"];
  for (const key of preferredKeys) {
    const value = payload[key];
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }
  const nameKey = Object.keys(payload).find((key) => key.toLowerCase().includes("name"));
  if (nameKey) {
    const value = payload[nameKey];
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }
  return null;
}

async function getSubmissionCanvasInfo(
  env: Env,
  submissionId: string
): Promise<{
  email: string | null;
  name: string | null;
  courseId: string | null;
  sectionId: string | null;
  userId: string | null;
}> {
  const row = await env.DB.prepare(
    "SELECT s.id,s.user_id,s.payload_json,s.canvas_course_id,s.canvas_section_id,s.submitter_email,f.canvas_course_id as form_canvas_course_id FROM submissions s LEFT JOIN forms f ON f.id=s.form_id WHERE s.id=?"
  )
    .bind(submissionId)
    .first<{
      user_id: string | null;
      payload_json: string;
      canvas_course_id: string | null;
      canvas_section_id: string | null;
      submitter_email: string | null;
      form_canvas_course_id: string | null;
    }>();
  if (!row) {
    return { email: null, name: null, courseId: null, sectionId: null, userId: null };
  }
  let payloadData: Record<string, unknown> | null = null;
  try {
    const payload = JSON.parse(row.payload_json) as { data?: Record<string, unknown> };
    if (payload?.data && typeof payload.data === "object") {
      payloadData = payload.data as Record<string, unknown>;
    }
  } catch {
    payloadData = null;
  }
  const email =
    (typeof payloadData?.email === "string" && payloadData.email.trim()) ||
    row.submitter_email ||
    (row.user_id ? await getUserPrimaryEmail(env, row.user_id) : null) ||
    null;
  const name = pickNameFromPayload(payloadData);
  const courseId = row.canvas_course_id || row.form_canvas_course_id || null;
  return {
    email,
    name,
    courseId,
    sectionId: row.canvas_section_id ?? null,
    userId: row.user_id ?? null
  };
}

async function deactivateCanvasForSubmission(
  env: Env,
  submissionId: string
): Promise<{ ok: boolean; attempted: boolean; error?: string | null }> {
  try {
    const info = await getSubmissionCanvasInfo(env, submissionId);
    if (!info.courseId || !info.email) return { ok: true, attempted: false };
    const result = await canvasApplyEnrollmentTaskByEmail(env, info.courseId, info.email, "deactivate");
    if (!result.ok) {
      return { ok: false, attempted: true, error: result.error || "canvas_deactivate_failed" };
    }
    await env.DB.prepare(
      "UPDATE submissions SET canvas_enroll_status=?, canvas_enroll_error=? WHERE id=?"
    )
      .bind("deactivated", "submission_deleted", submissionId)
      .run();
    return { ok: true, attempted: true };
  } catch (error) {
    return {
      ok: false,
      attempted: true,
      error: error instanceof Error ? error.message : "canvas_deactivate_failed"
    };
  }
}

async function reactivateCanvasForSubmission(
  env: Env,
  submissionId: string
): Promise<{ ok: boolean; attempted: boolean; status?: string | null; error?: string | null }> {
  try {
    const info = await getSubmissionCanvasInfo(env, submissionId);
    if (!info.courseId || !info.email) {
      return { ok: true, attempted: false, status: "skipped" };
    }
    const reactivate = await canvasReactivateByEmail(env, info.courseId, info.email);
    if (!reactivate.ok) {
      await handleCanvasEnrollment(
        env,
        { canvas_enabled: 1, canvas_course_id: info.courseId },
        info.name || (info.email ? titleCaseFromEmail(info.email) : "User"),
        info.email,
        info.sectionId
      );
    }
    await env.DB.prepare(
      "UPDATE submissions SET canvas_enroll_status=?, canvas_enroll_error=? WHERE id=?"
    )
      .bind("invited", "submission_restored", submissionId)
      .run();
    return {
      ok: true,
      attempted: true,
      status: reactivate.ok ? "reactivated" : "invited"
    };
  } catch (error) {
    return {
      ok: false,
      attempted: true,
      status: "failed",
      error: error instanceof Error ? error.message : "canvas_reactivate_failed"
    };
  }
}

async function unenrollCanvasForSubmission(env: Env, submissionId: string) {
  try {
    const info = await getSubmissionCanvasInfo(env, submissionId);
    if (!info.courseId || !info.email) return;
    await canvasApplyEnrollmentTaskByEmail(env, info.courseId, info.email, "delete");
    await env.DB.prepare(
      "UPDATE submissions SET canvas_enroll_status=?, canvas_enroll_error=? WHERE id=?"
    )
      .bind("deleted", "submission_hard_deleted", submissionId)
      .run();
  } catch {
    // Best effort.
  }
}

async function getCanvasCourseAccountId(env: Env, courseId: string): Promise<string | null> {
  const base = getCanvasBaseUrl(env);
  const res = await canvasFetch(env, `${base}/api/v1/courses/${courseId}`);
  if (!res.ok) return null;
  const payload = (await res.json()) as { account_id?: number | string };
  if (!payload?.account_id) return null;
  return String(payload.account_id);
}

async function canvasIsUserEnrolled(
  env: Env,
  courseId: string,
  email: string
): Promise<boolean> {
  const base = getCanvasBaseUrl(env);
  const url = `${base}/api/v1/courses/${courseId}/enrollments?type[]=StudentEnrollment&include[]=user&per_page=100`;
  try {
    const enrollments = await canvasFetchAll<any>(env, url);
    const target = email.toLowerCase();
    return enrollments.some((enrollment) => {
      const loginId = enrollment?.user?.login_id;
      return typeof loginId === "string" && loginId.toLowerCase() === target;
    });
  } catch (error) {
    return false;
  }
}

async function handleCanvasEnrollment(
  env: Env,
  form: { canvas_enabled?: number | null; canvas_course_id?: string | null },
  name: string,
  email: string,
  sectionId: string | null
): Promise<{
  status: string;
  error: string | null;
  enrolledAt: string | null;
  sectionId: string | null;
  canvasUserId: string | null;
  canvasUserName: string | null;
}> {
  if (!toBoolean(form.canvas_enabled ?? 0) || !form.canvas_course_id) {
    return {
      status: "skipped",
      error: null,
      enrolledAt: null,
      sectionId: null,
      canvasUserId: null,
      canvasUserName: null
    };
  }
  if (!env.CANVAS_API_TOKEN) {
    return {
      status: "failed",
      error: "canvas_not_configured",
      enrolledAt: null,
      sectionId,
      canvasUserId: null,
      canvasUserName: null
    };
  }
  const debugContext = {
    courseId: form.canvas_course_id,
    sectionId: sectionId ?? null,
    email: maskEmail(email)
  };

  console.info("[canvas_enroll]", { ...debugContext, stage: "lookup_start" });
  let accountIdOverride: string | null = null;
  const user = await canvasFindUserByEmail(env, email);
  let canvasUserId = user?.id || null;
  let createError: string | null = null;
  let canvasUserName = user?.name || null;
  console.info("[canvas_enroll]", {
    ...debugContext,
    stage: "lookup_result",
    found: Boolean(canvasUserId),
    lookupError: user?.error ?? null
  });
  const alreadyEnrolled = await canvasIsUserEnrolled(env, form.canvas_course_id, email);
  if (alreadyEnrolled) {
    console.info("[canvas_enroll]", { ...debugContext, stage: "already_enrolled" });
    return {
      status: "invited",
      error: null,
      enrolledAt: new Date().toISOString(),
      sectionId,
      canvasUserId,
      canvasUserName
    };
  }
  if (!canvasUserId) {
    accountIdOverride = await getCanvasCourseAccountId(env, form.canvas_course_id);
    console.info("[canvas_enroll]", {
      ...debugContext,
      stage: "create_user_start",
      accountIdOverride
    });
    const created = await canvasCreateUser(env, name, email, accountIdOverride);
    canvasUserId = created?.id || null;
    createError = created?.error || user?.error || null;
    console.info("[canvas_enroll]", {
      ...debugContext,
      stage: "create_user_result",
      created: Boolean(canvasUserId),
      createError
    });
  }
  if (!canvasUserId) {
    if (accountIdOverride) {
      const retry = await canvasFindUserByEmail(env, email, accountIdOverride);
      if (retry?.id) {
        canvasUserId = retry.id;
        canvasUserName = retry.name ?? canvasUserName;
        console.info("[canvas_enroll]", {
          ...debugContext,
          stage: "lookup_retry_success",
          accountIdOverride
        });
      } else if (retry?.error) {
        createError = `${createError || "user_lookup_failed"}:${retry.error}`;
        console.info("[canvas_enroll]", {
          ...debugContext,
          stage: "lookup_retry_failed",
          accountIdOverride,
          retryError: retry.error
        });
      }
    }
  }
  if (!canvasUserId) {
    const courseLookup = await canvasFindUserByEmailInCourse(
      env,
      form.canvas_course_id,
      email
    );
    if (courseLookup?.id) {
      canvasUserId = courseLookup.id;
      canvasUserName = courseLookup.name ?? canvasUserName;
      console.info("[canvas_enroll]", {
        ...debugContext,
        stage: "course_lookup_success"
      });
    } else if (courseLookup?.error) {
      createError = `${createError || "user_lookup_failed"}:${courseLookup.error}`;
      console.info("[canvas_enroll]", {
        ...debugContext,
        stage: "course_lookup_failed",
        error: courseLookup.error
      });
    }
  }
  if (!canvasUserId) {
    if (
      createError &&
      createError.includes("403") &&
      createError.toLowerCase().includes("not authorized")
    ) {
      const fallbackId = `sis_login_id:${email}`;
      console.info("[canvas_enroll]", {
        ...debugContext,
        stage: "enroll_fallback_sis_login"
      });
      let fallbackEnroll = await canvasEnrollUser(env, form.canvas_course_id, fallbackId, sectionId);
      if (!fallbackEnroll.ok && sectionId) {
        fallbackEnroll = await canvasEnrollUser(env, form.canvas_course_id, fallbackId, null);
      }
      if (fallbackEnroll.ok) {
        console.info("[canvas_enroll]", { ...debugContext, stage: "enroll_fallback_ok" });
        return {
          status: "invited",
          error: null,
          enrolledAt: new Date().toISOString(),
          sectionId,
          canvasUserId: null,
          canvasUserName
        };
      }
      console.info("[canvas_enroll]", {
        ...debugContext,
        stage: "enroll_fallback_failed",
        error: fallbackEnroll.error ?? null
      });
      return {
        status: "failed",
        error: fallbackEnroll.error || "enroll_failed",
        enrolledAt: null,
        sectionId,
        canvasUserId: null,
        canvasUserName
      };
    }
    console.info("[canvas_enroll]", {
      ...debugContext,
      stage: "lookup_failed",
      error: createError ? `user_lookup_failed:${createError}` : "user_lookup_failed"
    });
    return {
      status: "failed",
      error: createError ? `user_lookup_failed:${createError}` : "user_lookup_failed",
      enrolledAt: null,
      sectionId,
      canvasUserId: null,
      canvasUserName
    };
  }
  if (!/^\d+$/.test(String(canvasUserId))) {
    console.info("[canvas_enroll]", {
      ...debugContext,
      stage: "invalid_user_id",
      userId: String(canvasUserId)
    });
    return {
      status: "failed",
      error: "user_lookup_failed:invalid_user_id",
      enrolledAt: null,
      sectionId,
      canvasUserId: null,
      canvasUserName
    };
  }

  console.info("[canvas_enroll]", {
    ...debugContext,
    stage: "enroll_start",
    userId: String(canvasUserId)
  });
  let enrollment = await canvasEnrollUser(env, form.canvas_course_id, canvasUserId, sectionId);
  if (!enrollment.ok && sectionId) {
    console.info("[canvas_enroll]", {
      ...debugContext,
      stage: "enroll_retry_no_section",
      error: enrollment.error ?? null
    });
    enrollment = await canvasEnrollUser(env, form.canvas_course_id, canvasUserId, null);
  }
  if (!enrollment.ok) {
    console.info("[canvas_enroll]", {
      ...debugContext,
      stage: "enroll_failed",
      error: enrollment.error ?? null
    });
    return {
      status: "failed",
      error: enrollment.error || "enroll_failed",
      enrolledAt: null,
      sectionId,
      canvasUserId,
      canvasUserName
    };
  }
  console.info("[canvas_enroll]", { ...debugContext, stage: "enroll_ok" });
  return {
    status: "invited",
    error: null,
    enrolledAt: new Date().toISOString(),
    sectionId,
    canvasUserId,
    canvasUserName
  };
}

async function adminEnrollCanvasUser(env: Env, input: {
  courseId: string;
  sectionId: string | null;
  name: string;
  email: string;
  role: "student" | "teacher" | "ta" | "observer" | "designer";
}): Promise<{ ok: boolean; status: string; error: string | null; canvasUserId: string | null }> {
  if (!env.CANVAS_API_TOKEN) {
    return { ok: false, status: "failed", error: "canvas_not_configured", canvasUserId: null };
  }
  const roleMap: Record<string, string> = {
    student: "StudentEnrollment",
    teacher: "TeacherEnrollment",
    ta: "TaEnrollment",
    observer: "ObserverEnrollment",
    designer: "DesignerEnrollment"
  };
  const enrollmentType = roleMap[input.role] || "StudentEnrollment";
  let canvasUserId: string | null = null;
  let createError: string | null = null;
  const user = await canvasFindUserByEmail(env, input.email);
  canvasUserId = user?.id || null;
  let accountIdOverride: string | null = null;
  if (!canvasUserId) {
    accountIdOverride = await getCanvasCourseAccountId(env, input.courseId);
    const created = await canvasCreateUser(env, input.name, input.email, accountIdOverride);
    canvasUserId = created?.id || null;
    createError = created?.error || user?.error || null;
  }
  if (!canvasUserId && accountIdOverride) {
    const retry = await canvasFindUserByEmail(env, input.email, accountIdOverride);
    if (retry?.id) {
      canvasUserId = retry.id;
    } else if (retry?.error) {
      createError = `${createError || "user_lookup_failed"}:${retry.error}`;
    }
  }
  if (!canvasUserId) {
    const courseLookup = await canvasFindUserByEmailInCourse(env, input.courseId, input.email);
    if (courseLookup?.id) {
      canvasUserId = courseLookup.id;
    } else if (courseLookup?.error) {
      createError = `${createError || "user_lookup_failed"}:${courseLookup.error}`;
    }
  }
  if (!canvasUserId && createError && createError.includes("403")) {
    const fallbackId = `sis_login_id:${input.email}`;
    let fallbackEnroll = await canvasEnrollUser(
      env,
      input.courseId,
      fallbackId,
      input.sectionId,
      "invited",
      enrollmentType
    );
    if (!fallbackEnroll.ok && input.sectionId) {
      fallbackEnroll = await canvasEnrollUser(
        env,
        input.courseId,
        fallbackId,
        null,
        "invited",
        enrollmentType
      );
    }
    if (fallbackEnroll.ok) {
      return { ok: true, status: "invited", error: null, canvasUserId: null };
    }
    return {
      ok: false,
      status: "failed",
      error: fallbackEnroll.error || "enroll_failed",
      canvasUserId: null
    };
  }
  if (!canvasUserId) {
    return {
      ok: false,
      status: "failed",
      error: createError ? `user_lookup_failed:${createError}` : "user_lookup_failed",
      canvasUserId: null
    };
  }
  let enrollment = await canvasEnrollUser(
    env,
    input.courseId,
    canvasUserId,
    input.sectionId,
    "invited",
    enrollmentType
  );
  if (!enrollment.ok && input.sectionId) {
    enrollment = await canvasEnrollUser(
      env,
      input.courseId,
      canvasUserId,
      null,
      "invited",
      enrollmentType
    );
  }
  if (!enrollment.ok) {
    return { ok: false, status: "failed", error: enrollment.error || "enroll_failed", canvasUserId };
  }
  return { ok: true, status: "invited", error: null, canvasUserId };
}

function isMissingDeletedReasonColumn(error: unknown) {
  const message = (error as { message?: string })?.message || String(error);
  return message.includes("no such column") && message.includes("deleted_reason");
}

async function updateSubmissionsSoftDelete(
  env: Env,
  whereClause: string,
  bindings: Array<string | null>,
  deletedBy: string | null,
  reason: string
) {
  const sqlWithReason = `UPDATE submissions SET deleted_at=datetime('now'), deleted_by=?, deleted_reason=? WHERE ${whereClause} AND deleted_at IS NULL`;
  const sqlWithoutReason = `UPDATE submissions SET deleted_at=datetime('now'), deleted_by=? WHERE ${whereClause} AND deleted_at IS NULL`;
  try {
    await env.DB.prepare(sqlWithReason)
      .bind(deletedBy, reason, ...bindings)
      .run();
  } catch (error) {
    if (!isMissingDeletedReasonColumn(error)) {
      throw error;
    }
    await env.DB.prepare(sqlWithoutReason)
      .bind(deletedBy, ...bindings)
      .run();
  }
}

async function updateSubmissionsRestore(
  env: Env,
  whereClause: string,
  bindings: Array<string | null>
) {
  const sqlWithReason = `UPDATE submissions SET deleted_at=NULL, deleted_by=NULL, deleted_reason=NULL WHERE ${whereClause}`;
  const sqlWithoutReason = `UPDATE submissions SET deleted_at=NULL, deleted_by=NULL WHERE ${whereClause}`;
  try {
    await env.DB.prepare(sqlWithReason)
      .bind(...bindings)
      .run();
  } catch (error) {
    if (!isMissingDeletedReasonColumn(error)) {
      throw error;
    }
    await env.DB.prepare(sqlWithoutReason)
      .bind(...bindings)
      .run();
  }
}

async function updateSoftDeleteTable(
  env: Env,
  table: "submission_file_items" | "submission_uploads" | "submission_files",
  whereClause: string,
  bindings: Array<string | null>,
  deletedBy: string | null,
  reason: string
) {
  const sqlWithReason = `UPDATE ${table} SET deleted_at=datetime('now'), deleted_by=?, deleted_reason=? WHERE ${whereClause} AND deleted_at IS NULL`;
  const sqlWithoutReason = `UPDATE ${table} SET deleted_at=datetime('now'), deleted_by=? WHERE ${whereClause} AND deleted_at IS NULL`;
  try {
    await env.DB.prepare(sqlWithReason)
      .bind(deletedBy, reason, ...bindings)
      .run();
  } catch (error) {
    if (!isMissingDeletedReasonColumn(error)) {
      throw error;
    }
    await env.DB.prepare(sqlWithoutReason)
      .bind(deletedBy, ...bindings)
      .run();
  }
}

async function updateRestoreTable(
  env: Env,
  table: "submission_file_items" | "submission_uploads" | "submission_files",
  whereClause: string,
  bindings: Array<string | null>
) {
  const sqlWithReason = `UPDATE ${table} SET deleted_at=NULL, deleted_by=NULL, deleted_reason=NULL WHERE ${whereClause}`;
  const sqlWithoutReason = `UPDATE ${table} SET deleted_at=NULL, deleted_by=NULL WHERE ${whereClause}`;
  try {
    await env.DB.prepare(sqlWithReason)
      .bind(...bindings)
      .run();
  } catch (error) {
    if (!isMissingDeletedReasonColumn(error)) {
      throw error;
    }
    await env.DB.prepare(sqlWithoutReason)
      .bind(...bindings)
      .run();
  }
}

function hasFileFields(schemaJson: string | null | undefined): boolean {
  if (!schemaJson) return false;
  try {
    const parsed = JSON.parse(schemaJson);
    const fields = extractFields(parsed);
    return fields.some((field) => field.type === "file");
  } catch (error) {
    return false;
  }
}

async function softDeleteForm(
  env: Env,
  slug: string,
  deletedBy: string | null,
  reason: string
) {
  const form = await env.DB.prepare("SELECT id FROM forms WHERE slug=? AND deleted_at IS NULL")
    .bind(slug)
    .first<{ id: string }>();
  if (!form) return false;
  await env.DB.prepare(
    "UPDATE forms SET deleted_at=datetime('now'), deleted_by=?, deleted_reason=? WHERE id=?"
  )
    .bind(deletedBy, reason, form.id)
    .run();
  await updateSubmissionsSoftDelete(env, "form_id=?", [form.id], deletedBy, reason);
  await updateSoftDeleteTable(env, "submission_file_items", "form_id=?", [form.id], deletedBy, reason);
  await updateSoftDeleteTable(env, "submission_uploads", "form_id=?", [form.id], deletedBy, reason);
  await updateSoftDeleteTable(
    env,
    "submission_files",
    "submission_id IN (SELECT id FROM submissions WHERE form_id=?)",
    [form.id],
    deletedBy,
    reason
  );
  return true;
}

async function softDeleteTemplate(
  env: Env,
  key: string,
  deletedBy: string | null,
  reason: string
) {
  const result = await env.DB.prepare(
    "UPDATE templates SET deleted_at=datetime('now'), deleted_by=?, deleted_reason=? WHERE key=? AND deleted_at IS NULL"
  )
    .bind(deletedBy, reason, key)
    .run();
  return result.success === true;
}

async function softDeleteUser(
  env: Env,
  userId: string,
  deletedBy: string | null,
  reason: string
): Promise<{ ok: boolean; canvas?: { attempted: number; failed: number } }> {
  // Soft-delete user and cascade soft-delete to their submissions and uploads.
  const canvasDeleteSyncEnabled = await isCanvasDeleteSyncEnabled(env);
  const canvasResult = canvasDeleteSyncEnabled
    ? await canvasApplyTaskForUserCourses(env, userId, "deactivate")
    : { attempted: 0, failed: 0 };
  const result = await env.DB.prepare(
    "UPDATE users SET deleted_at=datetime('now'), deleted_by=?, deleted_reason=? WHERE id=? AND deleted_at IS NULL"
  )
    .bind(deletedBy, reason, userId)
    .run();
  await updateSubmissionsSoftDelete(env, "user_id=?", [userId], deletedBy, reason);
  await updateSoftDeleteTable(
    env,
    "submission_file_items",
    "submission_id IN (SELECT id FROM submissions WHERE user_id=?)",
    [userId],
    deletedBy,
    reason
  );
  await updateSoftDeleteTable(env, "submission_uploads", "user_id=?", [userId], deletedBy, reason);
  await updateSoftDeleteTable(
    env,
    "submission_files",
    "submission_id IN (SELECT id FROM submissions WHERE user_id=?)",
    [userId],
    deletedBy,
    reason
  );
  return { ok: result.success === true, canvas: canvasResult };
}

async function softDeleteSubmissionForUser(
  env: Env,
  formId: string,
  userId: string,
  deletedBy: string | null,
  reason: string
): Promise<{
  ok: boolean;
  error?: string | null;
  canvas?: { attempted: number; failed: number };
}> {
  const { results: submissions } = await env.DB.prepare(
    "SELECT id FROM submissions WHERE form_id=? AND user_id=? AND deleted_at IS NULL"
  )
    .bind(formId, userId)
    .all<{ id: string }>();
  let attempted = 0;
  let failed = 0;
  const canvasDeleteSyncEnabled = await isCanvasDeleteSyncEnabled(env);
  if (canvasDeleteSyncEnabled) {
    for (const row of submissions) {
      if (row?.id) {
        const result = await deactivateCanvasForSubmission(env, row.id);
        if (result.attempted) {
          attempted += 1;
        }
        if (!result.ok) {
          failed += 1;
          return {
            ok: false,
            error: result.error || "canvas_deactivate_failed",
            canvas: { attempted, failed }
          };
        }
      }
    }
  }
  await updateSubmissionsSoftDelete(env, "form_id=? AND user_id=?", [formId, userId], deletedBy, reason);
  await updateSoftDeleteTable(
    env,
    "submission_file_items",
    "submission_id IN (SELECT id FROM submissions WHERE form_id=? AND user_id=?)",
    [formId, userId],
    deletedBy,
    reason
  );
  await updateSoftDeleteTable(
    env,
    "submission_uploads",
    "submission_id IN (SELECT id FROM submissions WHERE form_id=? AND user_id=?)",
    [formId, userId],
    deletedBy,
    reason
  );
  await updateSoftDeleteTable(
    env,
    "submission_files",
    "submission_id IN (SELECT id FROM submissions WHERE form_id=? AND user_id=?)",
    [formId, userId],
    deletedBy,
    reason
  );
  return { ok: true, canvas: { attempted, failed } };
}

async function softDeleteSubmissionById(
  env: Env,
  submissionId: string,
  deletedBy: string | null,
  reason: string
): Promise<{ ok: boolean; canvas?: { attempted: number; failed: number } }> {
  const canvasDeleteSyncEnabled = await isCanvasDeleteSyncEnabled(env);
  let attempted = 0;
  let failed = 0;
  if (canvasDeleteSyncEnabled) {
    const result = await deactivateCanvasForSubmission(env, submissionId);
    if (result.attempted) attempted += 1;
    if (!result.ok && result.attempted) failed += 1;
  }
  await updateSubmissionsSoftDelete(env, "id=?", [submissionId], deletedBy, reason);
  await updateSoftDeleteTable(env, "submission_file_items", "submission_id=?", [submissionId], deletedBy, reason);
  await updateSoftDeleteTable(env, "submission_uploads", "submission_id=?", [submissionId], deletedBy, reason);
  await updateSoftDeleteTable(env, "submission_files", "submission_id=?", [submissionId], deletedBy, reason);
  return { ok: true, canvas: { attempted, failed } };
}

async function restoreForm(env: Env, slug: string) {
  const form = await env.DB.prepare("SELECT id FROM forms WHERE slug=?")
    .bind(slug)
    .first<{ id: string }>();
  if (!form) return false;
  await env.DB.prepare(
    "UPDATE forms SET deleted_at=NULL, deleted_by=NULL, deleted_reason=NULL WHERE id=?"
  )
    .bind(form.id)
    .run();
  await updateSubmissionsRestore(env, "form_id=?", [form.id]);
  await updateRestoreTable(env, "submission_file_items", "form_id=?", [form.id]);
  await updateRestoreTable(env, "submission_uploads", "form_id=?", [form.id]);
  await updateRestoreTable(
    env,
    "submission_files",
    "submission_id IN (SELECT id FROM submissions WHERE form_id=?)",
    [form.id]
  );
  return true;
}

async function restoreTemplate(env: Env, key: string) {
  const result = await env.DB.prepare(
    "UPDATE templates SET deleted_at=NULL, deleted_by=NULL, deleted_reason=NULL WHERE key=?"
  )
    .bind(key)
    .run();
  return result.success === true;
}

async function restoreUser(env: Env, userId: string) {
  const result = await env.DB.prepare(
    "UPDATE users SET deleted_at=NULL, deleted_by=NULL, deleted_reason=NULL WHERE id=?"
  )
    .bind(userId)
    .run();
  await updateSubmissionsRestore(env, "user_id=?", [userId]);
  await updateRestoreTable(
    env,
    "submission_file_items",
    "submission_id IN (SELECT id FROM submissions WHERE user_id=?)",
    [userId]
  );
  await updateRestoreTable(env, "submission_uploads", "user_id=?", [userId]);
  await updateRestoreTable(
    env,
    "submission_files",
    "submission_id IN (SELECT id FROM submissions WHERE user_id=?)",
    [userId]
  );
  const canvasDeleteSyncEnabled = await isCanvasDeleteSyncEnabled(env);
  if (canvasDeleteSyncEnabled) {
    await canvasApplyTaskForUserCourses(env, userId, "reactivate");
  }
  return result.success === true;
}

async function restoreSubmission(
  env: Env,
  submissionId: string
): Promise<{ ok: boolean; canvasError?: string | null; canvasStatus?: string | null }> {
  await updateSubmissionsRestore(env, "id=?", [submissionId]);
  await updateRestoreTable(env, "submission_file_items", "submission_id=?", [submissionId]);
  await updateRestoreTable(env, "submission_uploads", "submission_id=?", [submissionId]);
  await updateRestoreTable(env, "submission_files", "submission_id=?", [submissionId]);
  const canvasDeleteSyncEnabled = await isCanvasDeleteSyncEnabled(env);
  if (!canvasDeleteSyncEnabled) {
    return { ok: true, canvasError: null, canvasStatus: "skipped" };
  }
  const canvasResult = await reactivateCanvasForSubmission(env, submissionId);
  return {
    ok: true,
    canvasError: canvasResult.ok ? null : canvasResult.error || null,
    canvasStatus: canvasResult.status || null
  };
}

async function restoreFileItem(env: Env, fileId: string) {
  await updateRestoreTable(env, "submission_file_items", "id=?", [fileId]);
  const result = await env.DB.prepare(
    "SELECT id FROM submission_file_items WHERE id=? AND deleted_at IS NULL"
  )
    .bind(fileId)
    .run();
  return result.success === true;
}

async function hardDeleteForm(env: Env, slug: string) {
  const form = await env.DB.prepare("SELECT id FROM forms WHERE slug=?")
    .bind(slug)
    .first<{ id: string }>();
  if (!form) return false;
  const accessToken = await getDriveAccessToken(env);
  const submissionIds = await env.DB.prepare(
    "SELECT id FROM submissions WHERE form_id=?"
  )
    .bind(form.id)
    .all<{ id: string }>();
  if (accessToken) {
    for (const row of submissionIds.results) {
      if (row?.id) {
        await deleteDriveFilesForSubmission(env, row.id, accessToken);
      }
    }
  }
  if (env.form_app_files) {
    const { results } = await env.DB.prepare(
      "SELECT r2_key FROM submission_file_items WHERE form_id=?"
    )
      .bind(form.id)
      .all<{ r2_key: string }>();
    for (const row of results) {
      if (row?.r2_key) {
        await env.form_app_files.delete(row.r2_key);
      }
    }
    try {
      const { results: legacyFiles } = await env.DB.prepare(
        "SELECT r2_key FROM submission_files WHERE submission_id IN (SELECT id FROM submissions WHERE form_id=?)"
      )
        .bind(form.id)
        .all<{ r2_key: string | null }>();
      for (const row of legacyFiles) {
        if (row?.r2_key) {
          await env.form_app_files.delete(row.r2_key);
        }
      }
    } catch {
      // Ignore legacy table errors.
    }
  }
  await env.DB.prepare("DELETE FROM submission_file_items WHERE form_id=?")
    .bind(form.id)
    .run();
  await env.DB.prepare("DELETE FROM submission_uploads WHERE form_id=?")
    .bind(form.id)
    .run();
  await env.DB.prepare(
    "DELETE FROM submission_files WHERE submission_id IN (SELECT id FROM submissions WHERE form_id=?)"
  )
    .bind(form.id)
    .run();
  await env.DB.prepare("DELETE FROM submission_upload_sessions WHERE form_id=?")
    .bind(form.id)
    .run();
  await env.DB.prepare("DELETE FROM submissions WHERE form_id=?")
    .bind(form.id)
    .run();
  await env.DB.prepare("DELETE FROM form_versions WHERE form_id=?")
    .bind(form.id)
    .run();
  await env.DB.prepare("DELETE FROM drive_user_folders WHERE form_slug=?")
    .bind(slug)
    .run();
  if (accessToken) {
    const formFolder = await env.DB.prepare(
      "SELECT drive_folder_id FROM drive_folders WHERE form_slug=?"
    )
      .bind(slug)
      .first<{ drive_folder_id: string }>();
    if (formFolder?.drive_folder_id) {
      await deleteDriveFile(accessToken, formFolder.drive_folder_id);
    }
  }
  await env.DB.prepare("DELETE FROM drive_folders WHERE form_slug=?")
    .bind(slug)
    .run();
  await env.DB.prepare("DELETE FROM forms WHERE id=?")
    .bind(form.id)
    .run();
  return true;
}

async function hardDeleteTemplate(env: Env, key: string) {
  const template = await env.DB.prepare("SELECT id FROM templates WHERE key=?")
    .bind(key)
    .first<{ id: string }>();
  if (!template) return false;
  const { results } = await env.DB.prepare("SELECT slug FROM forms WHERE template_id=?")
    .bind(template.id)
    .all<{ slug: string }>();
  for (const row of results) {
    if (row?.slug) {
      await hardDeleteForm(env, row.slug);
    }
  }
  await env.DB.prepare("DELETE FROM templates WHERE id=?")
    .bind(template.id)
    .run();
  return true;
}

async function hardDeleteUser(env: Env, userId: string) {
  const accessToken = await getDriveAccessToken(env);
  const canvasDeleteSyncEnabled = await isCanvasDeleteSyncEnabled(env);
  if (canvasDeleteSyncEnabled) {
    await canvasApplyTaskForUserCourses(env, userId, "delete");
  }
  if (accessToken) {
    const userKeys = await getUserDriveKeys(env, userId);
    if (userKeys.length > 0) {
      const placeholders = userKeys.map(() => "?").join(",");
      const { results } = await env.DB.prepare(
        `SELECT drive_user_folder_id FROM drive_user_folders WHERE user_key IN (${placeholders})`
      )
        .bind(...userKeys)
        .all<{ drive_user_folder_id: string }>();
      for (const row of results) {
        if (row?.drive_user_folder_id) {
          await deleteDriveFile(accessToken, row.drive_user_folder_id);
        }
      }
      await env.DB.prepare(
        `DELETE FROM drive_user_folders WHERE user_key IN (${placeholders})`
      )
        .bind(...userKeys)
        .run();
    }
    const submissionIds = await env.DB.prepare(
      "SELECT id FROM submissions WHERE user_id=?"
    )
      .bind(userId)
      .all<{ id: string }>();
    for (const row of submissionIds.results) {
      if (row?.id) {
        await deleteDriveFilesForSubmission(env, row.id, accessToken);
      }
    }
  }
  if (env.form_app_files) {
    const { results } = await env.DB.prepare(
      "SELECT r2_key FROM submission_file_items WHERE submission_id IN (SELECT id FROM submissions WHERE user_id=?)"
    )
      .bind(userId)
      .all<{ r2_key: string }>();
    for (const row of results) {
      if (row?.r2_key) {
        await env.form_app_files.delete(row.r2_key);
      }
    }
    try {
      const { results: legacyFiles } = await env.DB.prepare(
        "SELECT r2_key FROM submission_files WHERE submission_id IN (SELECT id FROM submissions WHERE user_id=?)"
      )
        .bind(userId)
        .all<{ r2_key: string | null }>();
      for (const row of legacyFiles) {
        if (row?.r2_key) {
          await env.form_app_files.delete(row.r2_key);
        }
      }
    } catch {
      // Ignore legacy table errors.
    }
  }
  await env.DB.prepare(
    "DELETE FROM submission_file_items WHERE submission_id IN (SELECT id FROM submissions WHERE user_id=?)"
  )
    .bind(userId)
    .run();
  await env.DB.prepare(
    "DELETE FROM submission_files WHERE submission_id IN (SELECT id FROM submissions WHERE user_id=?)"
  )
    .bind(userId)
    .run();
  await env.DB.prepare("DELETE FROM submission_uploads WHERE user_id=?")
    .bind(userId)
    .run();
  await env.DB.prepare("DELETE FROM submissions WHERE user_id=?")
    .bind(userId)
    .run();
  await env.DB.prepare("DELETE FROM user_identities WHERE user_id=?")
    .bind(userId)
    .run();
  await env.DB.prepare("DELETE FROM users WHERE id=?")
    .bind(userId)
    .run();
  return true;
}

async function hardDeleteFileItem(env: Env, fileId: string) {
  const file = await env.DB.prepare(
    "SELECT r2_key, final_drive_file_id FROM submission_file_items WHERE id=?"
  )
    .bind(fileId)
    .first<{ r2_key: string | null; final_drive_file_id: string | null }>();

  if (env.form_app_files && file?.r2_key) {
    await env.form_app_files.delete(file.r2_key);
  }

  if (file?.final_drive_file_id) {
    const accessToken = await getDriveAccessToken(env);
    if (accessToken) {
      try {
        await deleteDriveFile(accessToken, file.final_drive_file_id);
      } catch {
        // Best-effort Drive cleanup; ignore failures.
      }
    }
  }
  await env.DB.prepare("DELETE FROM submission_file_items WHERE id=?")
    .bind(fileId)
    .run();
  return true;
}

async function hardDeleteSubmission(env: Env, submissionId: string) {
  const canvasDeleteSyncEnabled = await isCanvasDeleteSyncEnabled(env);
  if (canvasDeleteSyncEnabled) {
    await unenrollCanvasForSubmission(env, submissionId);
  }
  const accessToken = await getDriveAccessToken(env);
  if (accessToken) {
    await deleteDriveFilesForSubmission(env, submissionId, accessToken);
  }

  if (env.form_app_files) {
    const { results: fileItems } = await env.DB.prepare(
      "SELECT r2_key FROM submission_file_items WHERE submission_id=?"
    )
      .bind(submissionId)
      .all<{ r2_key: string | null }>();
    for (const row of fileItems) {
      if (row?.r2_key) {
        await env.form_app_files.delete(row.r2_key);
      }
    }

    try {
      const { results: legacyItems } = await env.DB.prepare(
        "SELECT r2_key FROM submission_uploads WHERE submission_id=?"
      )
        .bind(submissionId)
        .all<{ r2_key: string | null }>();
      for (const row of legacyItems) {
        if (row?.r2_key) {
          await env.form_app_files.delete(row.r2_key);
        }
      }
    } catch {
      // Ignore legacy table errors.
    }
    try {
      const { results: legacyFiles } = await env.DB.prepare(
        "SELECT r2_key FROM submission_files WHERE submission_id=?"
      )
        .bind(submissionId)
        .all<{ r2_key: string | null }>();
      for (const row of legacyFiles) {
        if (row?.r2_key) {
          await env.form_app_files.delete(row.r2_key);
        }
      }
    } catch {
      // Ignore legacy table errors.
    }
  }

  await env.DB.prepare("DELETE FROM submission_file_items WHERE submission_id=?")
    .bind(submissionId)
    .run();
  await env.DB.prepare("DELETE FROM submission_uploads WHERE submission_id=?")
    .bind(submissionId)
    .run();
  await env.DB.prepare("DELETE FROM submission_files WHERE submission_id=?")
    .bind(submissionId)
    .run();
  await env.DB.prepare("DELETE FROM submission_upload_sessions WHERE submission_id=?")
    .bind(submissionId)
    .run();
  await env.DB.prepare("DELETE FROM submissions WHERE id=?")
    .bind(submissionId)
    .run();
  return true;
}

async function getUserDriveKeys(env: Env, userId: string): Promise<string[]> {
  const { results } = await env.DB.prepare(
    "SELECT provider_login, email FROM user_identities WHERE user_id=?"
  )
    .bind(userId)
    .all<{ provider_login: string | null; email: string | null }>();
  const keys = new Set<string>();
  for (const row of results) {
    if (row?.email) {
      keys.add(sanitizeDriveName(row.email.split("@")[0]));
    }
    if (row?.provider_login) {
      keys.add(sanitizeDriveName(row.provider_login));
    }
  }
  keys.add(sanitizeDriveName(userId));
  return Array.from(keys);
}

async function deleteDriveFilesForSubmission(
  env: Env,
  submissionId: string,
  accessToken: string
): Promise<void> {
  const ids = new Set<string>();
  const { results: fileItems } = await env.DB.prepare(
    "SELECT final_drive_file_id FROM submission_file_items WHERE submission_id=?"
  )
    .bind(submissionId)
    .all<{ final_drive_file_id: string | null }>();
  for (const row of fileItems) {
    if (row?.final_drive_file_id) ids.add(row.final_drive_file_id);
  }
  try {
    const { results: legacyItems } = await env.DB.prepare(
      "SELECT final_drive_file_id FROM submission_uploads WHERE submission_id=?"
    )
      .bind(submissionId)
      .all<{ final_drive_file_id: string | null }>();
    for (const row of legacyItems) {
      if (row?.final_drive_file_id) ids.add(row.final_drive_file_id);
    }
  } catch {
    // Ignore legacy table errors.
  }
  try {
    const { results: legacyFiles } = await env.DB.prepare(
      "SELECT final_drive_file_id FROM submission_files WHERE submission_id=?"
    )
      .bind(submissionId)
      .all<{ final_drive_file_id: string | null }>();
    for (const row of legacyFiles) {
      if (row?.final_drive_file_id) ids.add(row.final_drive_file_id);
    }
  } catch {
    // Ignore legacy table errors.
  }
  for (const id of ids) {
    await deleteDriveFile(accessToken, id);
  }
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  bytes.forEach((value) => {
    binary += String.fromCharCode(value);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecode(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  const binary = atob(`${normalized}${padding}`);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function signJwt(payload: JwtPayload, secret: string): Promise<string> {
  const header = { alg: "HS256", typ: "JWT" };
  const encoder = new TextEncoder();
  const headerPart = base64UrlEncode(encoder.encode(JSON.stringify(header)));
  const payloadPart = base64UrlEncode(encoder.encode(JSON.stringify(payload)));
  const data = `${headerPart}.${payloadPart}`;
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  const signaturePart = base64UrlEncode(new Uint8Array(signature));
  return `${data}.${signaturePart}`;
}

async function verifyJwt(token: string, secret: string): Promise<JwtPayload | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [headerPart, payloadPart, signaturePart] = parts;
  const encoder = new TextEncoder();
  const data = `${headerPart}.${payloadPart}`;
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  const signature = base64UrlDecode(signaturePart);
  const valid = await crypto.subtle.verify("HMAC", key, signature, encoder.encode(data));
  if (!valid) return null;

  try {
    const payload = JSON.parse(
      new TextDecoder().decode(base64UrlDecode(payloadPart))
    ) as JwtPayload;
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }
    return payload;
  } catch (error) {
    return null;
  }
}

function getTokenFromRequest(request: Request): string | null {
  const authHeader = request.headers.get("Authorization");
  if (authHeader && authHeader.startsWith("Bearer ")) {
    return authHeader.slice("Bearer ".length).trim();
  }

  const cookieHeader = request.headers.get("Cookie");
  if (!cookieHeader) return null;
  const cookieParts = cookieHeader.split(";").map((part) => part.trim());
  for (const part of cookieParts) {
    if (part.startsWith("formapp_token=")) {
      return part.slice("formapp_token=".length);
    }
  }
  return null;
}

function createRedirectResponse(url: string, requestId: string): Response {
  return new Response(null, {
    status: 302,
    headers: {
      Location: url,
      "x-request-id": requestId
    }
  });
}

async function createOauthState(
  env: Env,
  provider: "google" | "github",
  returnTo: string | null,
  extra?: { intent?: "link"; userId?: string }
) {
  const state = crypto.randomUUID();
  await env.OAUTH_KV.put(
    `oauth_state:${state}`,
    JSON.stringify({ provider, returnTo, ...extra }),
    { expirationTtl: OAUTH_STATE_TTL_SECONDS }
  );
  return state;
}

async function consumeOauthState(env: Env, state: string) {
  const key = `oauth_state:${state}`;
  const stored = await env.OAUTH_KV.get(key);
  if (!stored) return null;
  await env.OAUTH_KV.delete(key);
  return JSON.parse(stored) as {
    provider: "google" | "github";
    returnTo?: string | null;
    intent?: "link";
    userId?: string;
  };
}

async function createUploadToken(
  env: Env,
  payload: {
    formSlug: string;
    fieldKey: string;
    r2Key: string;
    size: number;
    contentType?: string;
  }
) {
  const token = crypto.randomUUID();
  await env.OAUTH_KV.put(
    `upload_token:${token}`,
    JSON.stringify(payload),
    { expirationTtl: UPLOAD_TOKEN_TTL_SECONDS }
  );
  return token;
}

async function consumeUploadToken(env: Env, token: string) {
  const key = `upload_token:${token}`;
  const stored = await env.OAUTH_KV.get(key);
  if (!stored) return null;
  await env.OAUTH_KV.delete(key);
  return JSON.parse(stored) as {
    formSlug: string;
    fieldKey: string;
    r2Key: string;
    size: number;
    contentType?: string;
  };
}

function sanitizeReturnTo(value: string | null, env: Env): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    if (env.BASE_URL_WEB && !url.toString().startsWith(env.BASE_URL_WEB)) {
      return null;
    }
    return url.toString();
  } catch (error) {
    return null;
  }
}

function appendTokenToUrl(target: string, token: string): string {
  const [base, hash] = target.split("#");
  const tokenFragment = hash ? `${hash}&token=${token}` : `token=${token}`;
  return `${base}#${tokenFragment}`;
}

function buildAccountReturnUrl(env: Env, params?: Record<string, string>) {
  const base = env.BASE_URL_WEB ?? "/";
  const accountBase = base.endsWith("/") ? `${base}#/account` : `${base}/#/account`;
  if (!params || Object.keys(params).length === 0) return accountBase;
  const search = new URLSearchParams(params);
  return `${accountBase}?${search.toString()}`;
}

function ensureEnv(value: string | undefined, name: string): string {
  if (!value) {
    throw new Error(`Missing env: ${name}`);
  }
  return value;
}

function getMissingEnv(env: Env, keys: Array<keyof Env>): string[] {
  return keys
    .filter((key) => !env[key])
    .map((key) => String(key));
}

async function saveSubmissionVersion(
  env: Env,
  submissionId: string,
  formId: string,
  userId: string | null,
  createdBy: string | null
): Promise<void> {
  // Get the current submission data before it gets updated
  const currentSubmission = await env.DB.prepare(
    "SELECT payload_json FROM submissions WHERE id=?"
  )
    .bind(submissionId)
    .first<{ payload_json: string }>();

  if (!currentSubmission) {
    return; // Nothing to save if submission doesn't exist
  }

  // Get the next version number
  const versionCount = await env.DB.prepare(
    "SELECT COUNT(*) as count FROM submission_versions WHERE submission_id=?"
  )
    .bind(submissionId)
    .first<{ count: number }>();

  const versionNumber = (versionCount?.count ?? 0) + 1;

  // Insert the version record
  await env.DB.prepare(
    "INSERT INTO submission_versions (id, submission_id, form_id, user_id, payload_json, version_number, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)"
  )
    .bind(
      crypto.randomUUID(),
      submissionId,
      formId,
      userId,
      currentSubmission.payload_json,
      versionNumber,
      createdBy
    )
    .run();
}

async function getAuthPayload(request: Request, env: Env): Promise<JwtPayload | null> {
  if (!env.JWT_SECRET) return null;
  const token = getTokenFromRequest(request);
  if (!token) return null;
  return verifyJwt(token, env.JWT_SECRET);
}

function checkAuthPolicy(authPolicy: string, authPayload: JwtPayload | null) {
  if (authPolicy === "optional") return { ok: true };
  if (authPolicy === "required") {
    if (!authPayload) return { ok: false, status: 401, code: "auth_required" };
    return { ok: true };
  }
  if (!authPayload) return { ok: false, status: 401, code: "auth_required" };
  if (authPolicy === "google" && authPayload.provider !== "google") {
    return { ok: false, status: 403, code: "auth_forbidden" };
  }
  if (authPolicy === "github" && authPayload.provider !== "github") {
    return { ok: false, status: 403, code: "auth_forbidden" };
  }
  if (
    authPolicy === "either" &&
    authPayload.provider !== "google" &&
    authPayload.provider !== "github"
  ) {
    return { ok: false, status: 403, code: "auth_forbidden" };
  }
  return { ok: true };
}

function isVtStrict(env: Env) {
  return String(env.VT_STRICT || "").toLowerCase() === "true";
}

async function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function deriveVtVerdict(stats: {
  malicious: number;
  suspicious: number;
  undetected: number;
  timeout: number;
}) {
  if (stats.malicious > 0) return "malicious";
  if (stats.suspicious > 0) return "suspicious";
  if (stats.undetected >= 0) return "clean";
  return "unknown";
}

function normalizeVtStats(stats: {
  malicious?: number;
  suspicious?: number;
  undetected?: number;
  timeout?: number;
}) {
  return {
    malicious: stats.malicious ?? 0,
    suspicious: stats.suspicious ?? 0,
    undetected: stats.undetected ?? 0,
    timeout: stats.timeout ?? 0
  };
}

function deriveVtVerdictFromStats(
  stats: { malicious: number; suspicious: number; undetected: number; timeout: number },
  completed: boolean
) {
  if (stats.malicious > 0) return "malicious";
  if (stats.suspicious > 0) return "suspicious";
  if (completed) return "clean";
  return "unknown";
}

async function vtFetch(env: Env, url: string, init: RequestInit = {}) {
  const attempts = 3;
  let lastResponse: Response | null = null;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const response = await fetch(url, {
      ...init,
      headers: {
        "x-apikey": env.VT_API_KEY || "",
        ...(init.headers || {})
      }
    });
    lastResponse = response;
    if (response.status !== 429 || attempt === attempts - 1) {
      return response;
    }
    const retryAfter = response.headers.get("retry-after");
    const delay = retryAfter ? Number.parseInt(retryAfter, 10) * 1000 : 1500;
    await sleep(Number.isNaN(delay) ? 1500 : delay);
  }
  return lastResponse!;
}

async function vtGetFileReport(env: Env, sha256: string) {
  if (!env.VT_API_KEY) {
    return { error: "missing_api_key" as const };
  }
  const response = await vtFetch(env, `https://www.virustotal.com/api/v3/files/${sha256}`);
  if (response.status === 404) {
    return { notFound: true as const };
  }
  if (!response.ok) {
    return { error: `vt_http_${response.status}` as const };
  }
  const payload = (await response.json()) as {
    data?: {
      attributes?: {
        last_analysis_stats?: {
          malicious?: number;
          suspicious?: number;
          undetected?: number;
          timeout?: number;
        };
      };
    };
  };
  const stats = normalizeVtStats(payload.data?.attributes?.last_analysis_stats || {});
  const verdict = deriveVtVerdictFromStats(stats, true);
  return { status: "completed" as const, verdict, stats };
}

async function vtUploadFile(env: Env, buffer: ArrayBuffer, filename: string) {
  if (!env.VT_API_KEY) {
    return { error: "missing_api_key" as const };
  }
  let uploadUrl: string | null = null;
  if (buffer.byteLength > 32 * 1024 * 1024) {
    const uploadResponse = await vtFetch(env, "https://www.virustotal.com/api/v3/files/upload_url");
    if (!uploadResponse.ok) {
      return { error: `vt_http_${uploadResponse.status}` as const };
    }
    const payload = (await uploadResponse.json()) as { data?: string };
    uploadUrl = payload.data ?? null;
    if (!uploadUrl) {
      return { error: "missing_upload_url" as const };
    }
  }
  const form = new FormData();
  form.append("file", new Blob([buffer]), filename);
  const response = await vtFetch(env, uploadUrl || "https://www.virustotal.com/api/v3/files", {
    method: "POST",
    body: form
  });
  if (!response.ok) {
    return { error: `vt_http_${response.status}` as const };
  }
  const payload = (await response.json()) as { data?: { id?: string } };
  const analysisId = payload.data?.id;
  if (!analysisId) {
    return { error: "missing_analysis_id" as const };
  }
  return { analysisId };
}

async function vtGetAnalysis(env: Env, analysisId: string) {
  if (!env.VT_API_KEY) {
    return { error: "missing_api_key" as const };
  }
  const response = await vtFetch(env, `https://www.virustotal.com/api/v3/analyses/${analysisId}`);
  if (!response.ok) {
    return { error: `vt_http_${response.status}` as const };
  }
  const payload = (await response.json()) as {
    data?: {
      attributes?: {
        status?: string;
        stats?: {
          malicious?: number;
          suspicious?: number;
          undetected?: number;
          timeout?: number;
        };
      };
    };
  };
  const status = payload.data?.attributes?.status || "queued";
  const stats = normalizeVtStats(payload.data?.attributes?.stats || {});
  const verdict = deriveVtVerdictFromStats(stats, status === "completed");
  return { status, verdict, stats };
}

async function vtWaitForCompletion(env: Env, analysisId: string, timeoutMs: number) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const analysis = await vtGetAnalysis(env, analysisId);
    if ("error" in analysis) {
      return analysis;
    }
    if (analysis.status === "completed") {
      return analysis;
    }
    await sleep(2000);
  }
  return { status: "running" as const, verdict: "unknown" as const, stats: normalizeVtStats({}) };
}

async function vtScanBuffer(env: Env, buffer: ArrayBuffer, filename: string, sha256: string) {
  if (!env.VT_API_KEY) {
    return { status: "error", verdict: "error", stats: normalizeVtStats({}), error: "missing_api_key" };
  }
  const report = await vtGetFileReport(env, sha256);
  if ("error" in report) {
    return { status: "error", verdict: "error", stats: normalizeVtStats({}), error: report.error };
  }
  if (!("notFound" in report)) {
    return {
      status: report.status,
      verdict: report.verdict,
      stats: report.stats
    };
  }
  const upload = await vtUploadFile(env, buffer, filename);
  if ("error" in upload) {
    return { status: "error", verdict: "error", stats: normalizeVtStats({}), error: upload.error };
  }
  const analysis = await vtGetAnalysis(env, upload.analysisId);
  if ("error" in analysis) {
    return {
      status: "running",
      verdict: "unknown",
      stats: normalizeVtStats({}),
      analysisId: upload.analysisId,
      error: analysis.error
    };
  }
  return {
    status: analysis.status,
    verdict: analysis.verdict,
    stats: analysis.stats,
    analysisId: upload.analysisId
  };
}

async function updateUploadVtStatus(
  env: Env,
  uploadId: string,
  data: {
    analysisId?: string | null;
    status?: string | null;
    verdict?: string | null;
    malicious?: number | null;
    suspicious?: number | null;
    undetected?: number | null;
    timeout?: number | null;
    error?: string | null;
  }
) {
  await env.DB.prepare(
    "UPDATE submission_uploads SET vt_analysis_id=COALESCE(?, vt_analysis_id), vt_status=?, vt_verdict=?, vt_malicious=?, vt_suspicious=?, vt_undetected=?, vt_timeout=?, vt_last_checked_at=datetime('now'), vt_error=? WHERE id=?"
  )
    .bind(
      data.analysisId ?? null,
      data.status ?? null,
      data.verdict ?? null,
      data.malicious ?? null,
      data.suspicious ?? null,
      data.undetected ?? null,
      data.timeout ?? null,
      data.error ?? null,
      uploadId
    )
    .run();
}

async function updateFileItemVtStatus(
  env: Env,
  fileItemId: string,
  data: {
    analysisId?: string | null;
    status?: string | null;
    verdict?: string | null;
    malicious?: number | null;
    suspicious?: number | null;
    undetected?: number | null;
    timeout?: number | null;
    error?: string | null;
  }
) {
  await env.DB.prepare(
    "UPDATE submission_file_items SET vt_analysis_id=COALESCE(?, vt_analysis_id), vt_status=?, vt_verdict=?, vt_malicious=?, vt_suspicious=?, vt_undetected=?, vt_timeout=?, vt_last_checked_at=datetime('now'), vt_error=? WHERE id=?"
  )
    .bind(
      data.analysisId ?? null,
      data.status ?? null,
      data.verdict ?? null,
      data.malicious ?? null,
      data.suspicious ?? null,
      data.undetected ?? null,
      data.timeout ?? null,
      data.error ?? null,
      fileItemId
    )
    .run();
}

async function finalizeFileItemForUser(
  env: Env,
  item: {
    id: string;
    submission_id: string;
    r2_key: string;
    original_name: string;
    mime_type?: string | null;
    vt_status?: string | null;
    final_drive_file_id?: string | null;
  },
  formSlug: string,
  userId: string | null
) {
  if (!env.form_app_files || !env.DRIVE_PARENT_FOLDER_ID || !getDriveCredentials(env)) {
    return { ok: false as const, error: "drive_not_configured" };
  }
  const accessToken = await getDriveAccessToken(env);
  if (!accessToken) {
    return { ok: false as const, error: "drive_not_configured" };
  }
  const formFolder = await getOrCreateFormFolder(env, accessToken, formSlug);
  const userKey = await getUserFolderName(env, userId);
  const userFolder = formFolder.id
    ? await getOrCreateUserFolder(env, accessToken, formSlug, formFolder.id, userKey)
    : { id: null };
  if (!userFolder.id) {
    return { ok: false as const, error: "drive_unavailable" };
  }
  const object = await env.form_app_files.get(item.r2_key);
  if (!object) {
    return { ok: false as const, error: "missing_r2" };
  }
  const buffer = await object.arrayBuffer();
  const contentType = object.httpMetadata?.contentType || item.mime_type || "application/octet-stream";
  const uploaded = await uploadFileToDrive(
    env,
    accessToken,
    userFolder.id,
    item.original_name,
    contentType,
    new Uint8Array(buffer)
  );
  if (!uploaded || !uploaded.id) {
    return { ok: false as const, error: "drive_error" };
  }
  await env.DB.prepare(
    "UPDATE submission_file_items SET final_drive_file_id=?, finalized_at=datetime('now'), drive_web_view_link=? WHERE id=?"
  )
    .bind(uploaded.id, uploaded.webViewLink ?? null, item.id)
    .run();
  return { ok: true as const, driveFileId: uploaded.id, webViewLink: uploaded.webViewLink ?? null };
}

async function finalizeSubmissionFileItemsForUser(
  env: Env,
  submissionId: string,
  formSlug: string,
  userId: string | null
): Promise<Array<{ id: string; status: string; driveFileId?: string | null; webViewLink?: string | null }>> {
  if (!env.form_app_files || !env.DRIVE_PARENT_FOLDER_ID || !getDriveCredentials(env)) {
    return [];
  }
  const { results } = await env.DB.prepare(
    "SELECT id, r2_key, original_name, mime_type, vt_status, vt_verdict, final_drive_file_id, drive_web_view_link FROM submission_file_items WHERE submission_id=? AND deleted_at IS NULL"
  )
    .bind(submissionId)
    .all<{
      id: string;
      r2_key: string;
      original_name: string;
      mime_type: string | null;
      vt_status: string | null;
      vt_verdict: string | null;
      final_drive_file_id: string | null;
      drive_web_view_link: string | null;
    }>();

  if (results.length === 0) {
    return [];
  }

  if (isVtStrict(env)) {
    const blocked = results.filter((item) => item.vt_status !== "clean");
    if (blocked.length > 0) {
      return blocked.map((item) => ({
        id: item.id,
        status: item.vt_status || "vt_not_ready",
        driveFileId: item.final_drive_file_id ?? null,
        webViewLink: item.drive_web_view_link ?? null
      }));
    }
  }

  const accessToken = await getDriveAccessToken(env);
  if (!accessToken) {
    return results.map((item) => ({
      id: item.id,
      status: "drive_not_configured",
      driveFileId: item.final_drive_file_id ?? null,
      webViewLink: item.drive_web_view_link ?? null
    }));
  }

  const formFolder = await getOrCreateFormFolder(env, accessToken, formSlug);
  const userKey = await getUserFolderName(env, userId);
  const userFolder = formFolder.id
    ? await getOrCreateUserFolder(env, accessToken, formSlug, formFolder.id, userKey)
    : { id: null };

  const finalized: Array<{ id: string; status: string; driveFileId?: string | null; webViewLink?: string | null }> = [];
  for (const item of results) {
    if (item.final_drive_file_id || item.vt_status !== "clean") {
      finalized.push({
        id: item.id,
        status: item.vt_status || "skipped",
        driveFileId: item.final_drive_file_id ?? null,
        webViewLink: item.drive_web_view_link ?? null
      });
      continue;
    }
    if (!userFolder.id) {
      finalized.push({ id: item.id, status: "drive_unavailable" });
      continue;
    }
    const object = await env.form_app_files.get(item.r2_key);
    if (!object) {
      finalized.push({ id: item.id, status: "missing_r2" });
      continue;
    }
    const buffer = await object.arrayBuffer();
    const contentType = item.mime_type || object.httpMetadata?.contentType || "application/octet-stream";
    const uploaded = await uploadFileToDrive(
      env,
      accessToken,
      userFolder.id,
      item.original_name,
      contentType,
      new Uint8Array(buffer)
    );
    if (uploaded && uploaded.id) {
      await env.DB.prepare(
        "UPDATE submission_file_items SET final_drive_file_id=?, finalized_at=datetime('now'), drive_web_view_link=? WHERE id=?"
      )
        .bind(uploaded.id, uploaded.webViewLink ?? null, item.id)
        .run();
      finalized.push({
        id: item.id,
        status: "finalized",
        driveFileId: uploaded.id,
        webViewLink: uploaded.webViewLink ?? null
      });
    } else {
      finalized.push({ id: item.id, status: "drive_error" });
    }
  }

  return finalized;
}

async function startVirusTotalScan(
  env: Env,
  r2Key: string,
  filename: string
): Promise<string | null> {
  if (!env.VT_API_KEY || !env.form_app_files) return null;
  const object = await env.form_app_files.get(r2Key);
  if (!object) return null;
  const buffer = await object.arrayBuffer();
  const form = new FormData();
  form.append("file", new Blob([buffer]), filename);
  const response = await fetch("https://www.virustotal.com/api/v3/files", {
    method: "POST",
    headers: {
      "x-apikey": env.VT_API_KEY
    },
    body: form
  });
  if (!response.ok) {
    return null;
  }
  const payload = (await response.json()) as { data?: { id?: string } };
  return payload.data?.id ?? null;
}

async function pollVirusTotal(
  env: Env,
  analysisId: string
): Promise<{
  status: string;
  verdict: string;
  malicious: number;
  suspicious: number;
  undetected: number;
  timeout: number;
} | null> {
  if (!env.VT_API_KEY) return null;
  const response = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
    headers: {
      "x-apikey": env.VT_API_KEY
    }
  });
  if (!response.ok) return null;
  const payload = (await response.json()) as {
    data?: {
      attributes?: {
        status?: string;
        stats?: {
          malicious?: number;
          suspicious?: number;
          undetected?: number;
          timeout?: number;
        };
      };
    };
  };
  const status = payload.data?.attributes?.status || "unknown";
  const stats = payload.data?.attributes?.stats || {};
  const malicious = stats.malicious ?? 0;
  const suspicious = stats.suspicious ?? 0;
  const undetected = stats.undetected ?? 0;
  const timeout = stats.timeout ?? 0;
  const verdict = status === "completed" ? deriveVtVerdict({ malicious, suspicious, undetected, timeout }) : "unknown";
  return { status, verdict, malicious, suspicious, undetected, timeout };
}

async function updateVtStatus(
  env: Env,
  fileId: string,
  data: {
    analysisId?: string | null;
    status?: string | null;
    verdict?: string | null;
    malicious?: number | null;
    suspicious?: number | null;
    undetected?: number | null;
    timeout?: number | null;
  }
) {
  await env.DB.prepare(
    "UPDATE submission_files SET vt_analysis_id=COALESCE(?, vt_analysis_id), vt_status=?, vt_verdict=?, vt_malicious=?, vt_suspicious=?, vt_undetected=?, vt_timeout=?, vt_last_checked_at=datetime('now') WHERE id=?"
  )
    .bind(
      data.analysisId ?? null,
      data.status ?? null,
      data.verdict ?? null,
      data.malicious ?? null,
      data.suspicious ?? null,
      data.undetected ?? null,
      data.timeout ?? null,
      fileId
    )
    .run();
}

function getDriveCredentials(env: Env): { clientEmail: string; privateKey: string } | null {
  if (env.DRIVE_SERVICE_ACCOUNT_JSON) {
    try {
      const parsed = JSON.parse(env.DRIVE_SERVICE_ACCOUNT_JSON) as {
        client_email?: string;
        private_key?: string;
      };
      if (parsed.client_email && parsed.private_key) {
        return { clientEmail: parsed.client_email, privateKey: parsed.private_key };
      }
    } catch (error) {
      return null;
    }
  }
  if (!env.DRIVE_CLIENT_EMAIL || !env.DRIVE_PRIVATE_KEY) {
    return null;
  }
  return { clientEmail: env.DRIVE_CLIENT_EMAIL, privateKey: env.DRIVE_PRIVATE_KEY };
}

async function getDriveAccessToken(env: Env): Promise<string | null> {
  const creds = getDriveCredentials(env);
  if (!creds) {
    return null;
  }
  const keyPem = creds.privateKey.replace(/\\n/g, "\n");
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const claim = {
    iss: creds.clientEmail,
    scope: "https://www.googleapis.com/auth/drive",
    aud: "https://oauth2.googleapis.com/token",
    exp: now + 3600,
    iat: now
  };
  const encoder = new TextEncoder();
  const headerPart = base64UrlEncode(encoder.encode(JSON.stringify(header)));
  const claimPart = base64UrlEncode(encoder.encode(JSON.stringify(claim)));
  const toSign = `${headerPart}.${claimPart}`;
  const keyData = keyPem
    .replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "")
    .replace(/\s+/g, "");
  const binary = Uint8Array.from(atob(keyData), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey(
    "pkcs8",
    binary.buffer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    encoder.encode(toSign)
  );
  const jwt = `${toSign}.${base64UrlEncode(new Uint8Array(signature))}`;
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt
    }).toString()
  });
  if (!response.ok) {
    return null;
  }
  const payload = (await response.json()) as { access_token?: string };
  return payload.access_token ?? null;
}

async function getOrCreateFolder(
  env: Env,
  accessToken: string,
  parentId: string,
  name: string
): Promise<{ id: string | null; webViewLink: string | null; created: boolean }> {
  const query = `mimeType='application/vnd.google-apps.folder' and name='${name.replace(/'/g, "\\'")}' and '${parentId}' in parents and trashed=false`;
  const params = new URLSearchParams({
    q: query,
    fields: "files(id,name,parents,webViewLink)",
    supportsAllDrives: "true",
    includeItemsFromAllDrives: "true"
  });
  if (env.DRIVE_SHARED_DRIVE_ID) {
    params.set("corpora", "drive");
    params.set("driveId", env.DRIVE_SHARED_DRIVE_ID);
  }
  const listRes = await fetch(`https://www.googleapis.com/drive/v3/files?${params.toString()}`, {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  if (listRes.ok) {
    const payload = (await listRes.json()) as {
      files?: Array<{ id: string; webViewLink?: string | null }>;
    };
    const existing = payload.files?.[0];
    if (existing) {
      return { id: existing.id, webViewLink: existing.webViewLink ?? null, created: false };
    }
  }

  const createRes = await fetch(
    "https://www.googleapis.com/drive/v3/files?supportsAllDrives=true&fields=id,webViewLink",
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "content-type": "application/json"
      },
      body: JSON.stringify({
        name,
        mimeType: "application/vnd.google-apps.folder",
        parents: [parentId]
      })
    }
  );
  if (!createRes.ok) return { id: null, webViewLink: null, created: false };
  const created = (await createRes.json()) as { id?: string; webViewLink?: string | null };
  return { id: created.id ?? null, webViewLink: created.webViewLink ?? null, created: true };
}

async function driveEnsureFolder(
  env: Env,
  parentId: string,
  folderName: string
): Promise<{ id: string | null; created: boolean }> {
  const accessToken = await getDriveAccessToken(env);
  if (!accessToken) return { id: null, created: false };
  const result = await getOrCreateFolder(env, accessToken, parentId, folderName);
  return { id: result.id, created: result.created };
}

function buildMultipartBody(
  boundary: string,
  metadata: Record<string, unknown>,
  fileBytes: Uint8Array,
  contentType: string
) {
  const encoder = new TextEncoder();
  const part1 = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(metadata)}\r\n`;
  const part2 = `--${boundary}\r\nContent-Type: ${contentType}\r\n\r\n`;
  const part3 = `\r\n--${boundary}--\r\n`;
  const body = new Uint8Array(
    encoder.encode(part1).length + encoder.encode(part2).length + fileBytes.length + encoder.encode(part3).length
  );
  let offset = 0;
  body.set(encoder.encode(part1), offset);
  offset += encoder.encode(part1).length;
  body.set(encoder.encode(part2), offset);
  offset += encoder.encode(part2).length;
  body.set(fileBytes, offset);
  offset += fileBytes.length;
  body.set(encoder.encode(part3), offset);
  return body;
}

function sanitizeDriveName(value: string) {
  const sanitized = value.replace(/[^a-zA-Z0-9._-]/g, "-").replace(/-+/g, "-").trim();
  if (!sanitized) return "anonymous";
  return sanitized.slice(0, 64);
}

async function getOrCreateFormFolder(env: Env, accessToken: string, formSlug: string) {
  const existing = await env.DB.prepare(
    "SELECT drive_folder_id FROM drive_folders WHERE form_slug=?"
  )
    .bind(formSlug)
    .first<{ drive_folder_id: string }>();
  if (existing?.drive_folder_id) {
    return { id: existing.drive_folder_id, webViewLink: null, created: false };
  }

  const formRow = await env.DB.prepare(
    "SELECT id, drive_folder_id FROM forms WHERE slug=? AND deleted_at IS NULL"
  )
    .bind(formSlug)
    .first<{ id: string; drive_folder_id: string | null }>();
  if (!formRow) return { id: null, webViewLink: null, created: false };
  if (formRow.drive_folder_id) {
    await env.DB.prepare(
      "INSERT OR IGNORE INTO drive_folders (form_slug, drive_folder_id) VALUES (?, ?)"
    )
      .bind(formSlug, formRow.drive_folder_id)
      .run();
    return { id: formRow.drive_folder_id, webViewLink: null, created: false };
  }

  const created = await getOrCreateFolder(env, accessToken, env.DRIVE_PARENT_FOLDER_ID!, formSlug);
  if (created.id) {
    await env.DB.prepare(
      "INSERT OR IGNORE INTO drive_folders (form_slug, drive_folder_id) VALUES (?, ?)"
    )
      .bind(formSlug, created.id)
      .run();
    await env.DB.prepare("UPDATE forms SET drive_folder_id=? WHERE id=?")
      .bind(created.id, formRow.id)
      .run();
  }
  return created;
}

async function getUserFolderName(env: Env, userId: string | null) {
  if (!userId) return "anonymous";
  const identity = await env.DB.prepare(
    "SELECT provider, provider_login, email FROM user_identities WHERE user_id=? ORDER BY created_at DESC LIMIT 1"
  )
    .bind(userId)
    .first<{ provider: string; provider_login: string | null; email: string | null }>();
  if (identity?.email) {
    return sanitizeDriveName(identity.email.split("@")[0]);
  }
  if (identity?.provider_login) {
    return sanitizeDriveName(identity.provider_login);
  }
  return sanitizeDriveName(userId);
}

async function getOrCreateUserFolder(
  env: Env,
  accessToken: string,
  formSlug: string,
  formFolderId: string,
  userKey: string
) {
  const existing = await env.DB.prepare(
    "SELECT drive_user_folder_id FROM drive_user_folders WHERE form_slug=? AND user_key=?"
  )
    .bind(formSlug, userKey)
    .first<{ drive_user_folder_id: string }>();
  if (existing?.drive_user_folder_id) {
    return { id: existing.drive_user_folder_id, webViewLink: null, created: false };
  }
  const created = await getOrCreateFolder(env, accessToken, formFolderId, userKey);
  if (created.id) {
    await env.DB.prepare(
      "INSERT OR IGNORE INTO drive_user_folders (form_slug, user_key, drive_user_folder_id) VALUES (?, ?, ?)"
    )
      .bind(formSlug, userKey, created.id)
      .run();
  }
  return created;
}

async function uploadFileToDrive(
  env: Env,
  accessToken: string,
  parentId: string,
  fileName: string,
  contentType: string,
  bytes: Uint8Array
): Promise<{ id: string; webViewLink: string | null } | null> {
  const boundary = `formapp_${crypto.randomUUID()}`;
  const metadata = {
    name: fileName,
    parents: [parentId]
  };
  const body = buildMultipartBody(boundary, metadata, bytes, contentType);
  const uploadRes = await fetch(
    "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&supportsAllDrives=true&fields=id,webViewLink",
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "content-type": `multipart/related; boundary=${boundary}`
      },
      body
    }
  );
  if (!uploadRes.ok) {
    const text = await uploadRes.text().catch(() => "");
    await recordHealthStatus(env, "drive_upload", "error", text || "drive_upload_failed");
    return null;
  }
  const payload = (await uploadRes.json()) as { id?: string; webViewLink?: string | null };
  if (!payload.id) {
    await recordHealthStatus(env, "drive_upload", "error", "drive_upload_missing_id");
    return null;
  }
  await recordHealthStatus(env, "drive_upload", "ok", fileName);
  return { id: payload.id, webViewLink: payload.webViewLink ?? null };
}

async function deleteDriveFile(accessToken: string, fileId: string): Promise<boolean> {
  const response = await fetch(
    `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(
      fileId
    )}?supportsAllDrives=true`,
    {
      method: "DELETE",
      headers: { Authorization: `Bearer ${accessToken}` }
    }
  );
  return response.ok;
}

async function finalizeSubmissionUploads(
  env: Env,
  submissionId: string,
  userKey: string
): Promise<
  Array<{ id: string; status: string; driveFileId?: string | null; webViewLink?: string | null; error?: string }>
> {
  if (!env.form_app_files) return [];
  if (!env.DRIVE_PARENT_FOLDER_ID) return [];
  const accessToken = await getDriveAccessToken(env);
  if (!accessToken) return [];

  const submission = await env.DB.prepare(
    "SELECT s.id, s.form_id, f.slug, f.is_locked FROM submissions s JOIN forms f ON f.id=s.form_id WHERE s.id=? AND s.deleted_at IS NULL AND f.deleted_at IS NULL"
  )
    .bind(submissionId)
    .first<{ id: string; form_id: string; slug: string; is_locked: number }>();
  if (!submission) return [];
  if (toBoolean(submission.is_locked)) {
    return [{ id: submissionId, status: "locked" }];
  }

  const formFolder = await getOrCreateFormFolder(env, accessToken, submission.slug);
  if (!formFolder.id) return [];
  const userFolder = await getOrCreateUserFolder(env, accessToken, submission.slug, formFolder.id, userKey);
  if (!userFolder.id) return [];

  const existingNames = new Set<string>();
  const { results: previous } = await env.DB.prepare(
    "SELECT original_name FROM submission_uploads WHERE submission_id=? AND finalized_at IS NOT NULL"
  )
    .bind(submissionId)
    .all<{ original_name: string }>();
  for (const row of previous) {
    existingNames.add(row.original_name);
  }

  const { results } = await env.DB.prepare(
    "SELECT id, original_name, content_type, r2_key, vt_status, vt_verdict, vt_error, sha256 FROM submission_uploads WHERE submission_id=? AND finalized_at IS NULL AND deleted_at IS NULL"
  )
    .bind(submissionId)
    .all<{
      id: string;
      original_name: string;
      content_type: string | null;
      r2_key: string;
      vt_status: string | null;
      vt_verdict: string | null;
      vt_error: string | null;
      sha256: string;
    }>();

  const strictMode = isVtStrict(env);
  const resultsPayload: Array<{
    id: string;
    status: string;
    driveFileId?: string | null;
    webViewLink?: string | null;
    error?: string;
  }> = [];
  const usedNames = new Set<string>(existingNames);

  for (const file of results) {
    if (strictMode) {
      if (file.vt_verdict === "malicious" || file.vt_verdict === "suspicious") {
        resultsPayload.push({ id: file.id, status: "vt_blocked", error: file.vt_verdict || "vt_blocked" });
        continue;
      }
      if (file.vt_verdict !== "clean") {
        resultsPayload.push({ id: file.id, status: "vt_not_ready", error: file.vt_error || "vt_not_ready" });
        continue;
      }
    }

    const object = await env.form_app_files.get(file.r2_key);
    if (!object) {
      resultsPayload.push({ id: file.id, status: "missing_r2" });
      continue;
    }
    const buffer = new Uint8Array(await object.arrayBuffer());
    const contentType = file.content_type || "application/octet-stream";
    let targetName = file.original_name;
    if (usedNames.has(targetName)) {
      const parts = targetName.split(".");
      const suffix = crypto.randomUUID().slice(0, 8);
      if (parts.length > 1) {
        const ext = parts.pop();
        targetName = `${parts.join(".")}-${suffix}.${ext}`;
      } else {
        targetName = `${targetName}-${suffix}`;
      }
    }
    usedNames.add(targetName);
    const driveFile = await uploadFileToDrive(env, accessToken, userFolder.id, targetName, contentType, buffer);
    if (!driveFile) {
      resultsPayload.push({ id: file.id, status: "upload_failed" });
      continue;
    }
    await env.DB.prepare(
      "UPDATE submission_uploads SET final_drive_file_id=?, finalized_at=datetime('now'), drive_web_view_link=? WHERE id=?"
    )
      .bind(driveFile.id, driveFile.webViewLink, file.id)
      .run();
    resultsPayload.push({
      id: file.id,
      status: "finalized",
      driveFileId: driveFile.id,
      webViewLink: driveFile.webViewLink
    });
  }

  return resultsPayload;
}

function isAdminUser(provider: "google" | "github", data: { sub?: string; email?: string | null; login?: string; id?: string }, env: Env): boolean {
  if (provider === "google") {
    if (env.ADMIN_GOOGLE_SUB && data.sub === env.ADMIN_GOOGLE_SUB) {
      return true;
    }
    if (env.ADMIN_EMAIL && data.email && data.email === env.ADMIN_EMAIL) {
      return true;
    }
  }
  if (provider === "github") {
    if (env.ADMIN_GITHUB && data.login === env.ADMIN_GITHUB) {
      return true;
    }
    if (env.ADMIN_GITHUB_ID && data.id === env.ADMIN_GITHUB_ID) {
      return true;
    }
  }
  return false;
}

async function upsertGoogleUser(env: Env, sub: string, email: string | null): Promise<IdentityRow> {
  const identity = await env.DB.prepare(
    "SELECT ui.user_id as userId, u.is_admin as isAdmin, u.deleted_at as deletedAt FROM user_identities ui LEFT JOIN users u ON u.id=ui.user_id WHERE ui.provider='google' AND ui.provider_sub=?"
  )
    .bind(sub)
    .first<IdentityRow & { deletedAt: string | null }>();

  const adminFlag = isAdminUser("google", { sub, email }, env) ? 1 : 0;

  if (identity) {
    if (identity.deletedAt) {
      throw new Error("user_deleted");
    }
    await env.DB.prepare("UPDATE users SET is_admin=?, updated_at=datetime('now') WHERE id=?")
      .bind(adminFlag, identity.userId)
      .run();
    await env.DB.prepare("UPDATE user_identities SET email=? WHERE provider='google' AND provider_sub=?")
      .bind(email, sub)
      .run();
    return { userId: identity.userId, isAdmin: adminFlag };
  }

  const userId = crypto.randomUUID();
  const identityId = crypto.randomUUID();
  await env.DB.prepare("INSERT INTO users (id, is_admin) VALUES (?, ?)")
    .bind(userId, adminFlag)
    .run();
  try {
    await env.DB.prepare(
      "INSERT INTO user_identities (id, user_id, provider, provider_sub, email) VALUES (?, ?, 'google', ?, ?)"
    )
      .bind(identityId, userId, sub, email)
      .run();
  } catch (error) {
    const existing = await env.DB.prepare(
      "SELECT ui.user_id as userId, u.deleted_at as deletedAt FROM user_identities ui LEFT JOIN users u ON u.id=ui.user_id WHERE ui.provider='google' AND ui.provider_sub=?"
    )
      .bind(sub)
      .first<{ userId: string; deletedAt: string | null }>();
    if (existing?.userId) {
      if (existing.deletedAt) {
        throw new Error("user_deleted");
      }
      return { userId: existing.userId, isAdmin: adminFlag };
    }
    throw error;
  }

  return { userId, isAdmin: adminFlag };
}

async function upsertGithubUser(env: Env, login: string, githubId: string, email: string | null): Promise<IdentityRow> {
  const identity = await env.DB.prepare(
    "SELECT ui.user_id as userId, u.is_admin as isAdmin, u.deleted_at as deletedAt FROM user_identities ui LEFT JOIN users u ON u.id=ui.user_id WHERE ui.provider='github' AND (ui.provider_sub=? OR ui.provider_login=?)"
  )
    .bind(githubId, login)
    .first<IdentityRow & { deletedAt: string | null }>();

  const adminFlag = isAdminUser("github", { login, id: githubId }, env) ? 1 : 0;

  if (identity) {
    if (identity.deletedAt) {
      throw new Error("user_deleted");
    }
    await env.DB.prepare("UPDATE users SET is_admin=?, updated_at=datetime('now') WHERE id=?")
      .bind(adminFlag, identity.userId)
      .run();
    await env.DB.prepare(
      "UPDATE user_identities SET provider_login=?, provider_sub=?, email=? WHERE provider='github' AND user_id=?"
    )
      .bind(login, githubId, email, identity.userId)
      .run();
    return { userId: identity.userId, isAdmin: adminFlag };
  }

  const userId = crypto.randomUUID();
  const identityId = crypto.randomUUID();
  await env.DB.prepare("INSERT INTO users (id, is_admin) VALUES (?, ?)")
    .bind(userId, adminFlag)
    .run();
  try {
    await env.DB.prepare(
      "INSERT INTO user_identities (id, user_id, provider, provider_sub, provider_login, email) VALUES (?, ?, 'github', ?, ?, ?)"
    )
      .bind(identityId, userId, githubId, login, email)
      .run();
  } catch (error) {
    const existing = await env.DB.prepare(
      "SELECT ui.user_id as userId, u.deleted_at as deletedAt FROM user_identities ui LEFT JOIN users u ON u.id=ui.user_id WHERE ui.provider='github' AND (ui.provider_sub=? OR ui.provider_login=?)"
    )
      .bind(githubId, login)
      .first<{ userId: string; deletedAt: string | null }>();
    if (existing?.userId) {
      if (existing.deletedAt) {
        throw new Error("user_deleted");
      }
      return { userId: existing.userId, isAdmin: adminFlag };
    }
    throw error;
  }

  return { userId, isAdmin: adminFlag };
}

async function getUserIdentities(env: Env, userId: string) {
  const { results } = await env.DB.prepare(
    "SELECT provider, provider_sub, provider_login, email, created_at FROM user_identities WHERE user_id=? ORDER BY created_at ASC"
  )
    .bind(userId)
    .all<{
      provider: string;
      provider_sub: string | null;
      provider_login: string | null;
      email: string | null;
      created_at: string;
    }>();
  return results.map((row) => ({
    provider: row.provider,
    providerSub: row.provider_sub,
    providerLogin: row.provider_login,
    email: row.email,
    created_at: row.created_at
  }));
}

async function ensureIdentityFromAuthPayload(env: Env, authPayload: JwtPayload) {
  const userId = authPayload.userId;
  if (!userId || !authPayload.provider || !authPayload.sub) return;

  const userRow = await env.DB.prepare("SELECT id, deleted_at FROM users WHERE id=?")
    .bind(userId)
    .first<{ id: string; deleted_at: string | null }>();
  if (!userRow) {
    await env.DB.prepare("INSERT INTO users (id, is_admin) VALUES (?, ?)")
      .bind(userId, authPayload.isAdmin ? 1 : 0)
      .run();
  } else if (userRow.deleted_at) {
    return;
  }

  const existingByUser = await env.DB.prepare(
    "SELECT id FROM user_identities WHERE user_id=? AND provider=? LIMIT 1"
  )
    .bind(userId, authPayload.provider)
    .first<{ id: string }>();

  if (existingByUser?.id) return;

  if (authPayload.provider === "google") {
    const existingBySub = await env.DB.prepare(
      "SELECT user_id FROM user_identities WHERE provider='google' AND provider_sub=? LIMIT 1"
    )
      .bind(authPayload.sub)
      .first<{ user_id: string }>();
    if (existingBySub?.user_id && existingBySub.user_id !== userId) {
      console.warn("[identity_repair_skip]", {
        provider: "google",
        userId,
        existingUserId: existingBySub.user_id
      });
      return;
    }
    await env.DB.prepare(
      "INSERT INTO user_identities (id, user_id, provider, provider_sub, email) VALUES (?, ?, 'google', ?, ?)"
    )
      .bind(crypto.randomUUID(), userId, authPayload.sub, authPayload.email ?? null)
      .run();
    return;
  }

  if (authPayload.provider === "github") {
    const existingByLogin = await env.DB.prepare(
      "SELECT user_id FROM user_identities WHERE provider='github' AND provider_login=? LIMIT 1"
    )
      .bind(authPayload.sub)
      .first<{ user_id: string }>();
    if (existingByLogin?.user_id && existingByLogin.user_id !== userId) {
      console.warn("[identity_repair_skip]", {
        provider: "github",
        userId,
        existingUserId: existingByLogin.user_id
      });
      return;
    }
    await env.DB.prepare(
      "INSERT INTO user_identities (id, user_id, provider, provider_sub, provider_login, email) VALUES (?, ?, 'github', ?, ?, ?)"
    )
      .bind(crypto.randomUUID(), userId, authPayload.sub, authPayload.sub, authPayload.email ?? null)
      .run();
  }
}

async function requireAdmin(request: Request, env: Env): Promise<JwtPayload | null> {
  const payload = await getAuthPayload(request, env);
  if (!payload || !payload.isAdmin) return null;
  return payload;
}

async function exchangeGoogleCode(env: Env, code: string, redirectUri: string) {
  const clientId = ensureEnv(env.GOOGLE_CLIENT_ID, "GOOGLE_CLIENT_ID");
  const clientSecret = ensureEnv(env.GOOGLE_CLIENT_SECRET, "GOOGLE_CLIENT_SECRET");
  const body = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    code,
    grant_type: "authorization_code",
    redirect_uri: redirectUri
  });
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: body.toString()
  });
  if (!response.ok) {
    throw new Error("google_token_exchange_failed");
  }
  return (await response.json()) as { id_token?: string };
}

function decodeGoogleIdToken(idToken: string, clientId: string) {
  const parts = idToken.split(".");
  if (parts.length < 2) {
    throw new Error("invalid_id_token");
  }
  const payload = JSON.parse(
    new TextDecoder().decode(base64UrlDecode(parts[1]))
  ) as { sub?: string; email?: string; aud?: string; exp?: number };
  if (!payload.aud || payload.aud !== clientId) {
    throw new Error("invalid_id_token_aud");
  }
  if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) {
    throw new Error("invalid_id_token_exp");
  }
  // TODO: validate JWT signature against Google's public keys.
  return payload;
}

async function exchangeGithubCode(env: Env, code: string, redirectUri: string) {
  const clientId = ensureEnv(env.GITHUB_CLIENT_ID, "GITHUB_CLIENT_ID");
  const clientSecret = ensureEnv(env.GITHUB_CLIENT_SECRET, "GITHUB_CLIENT_SECRET");
  const response = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "content-type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: redirectUri
    }).toString()
  });
  if (!response.ok) {
    throw new Error("github_token_exchange_failed");
  }
  return (await response.json()) as { access_token?: string };
}

async function fetchGithubUser(accessToken: string) {
  const response = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "User-Agent": "form-app"
    }
  });
  if (!response.ok) {
    throw new Error("github_user_fetch_failed");
  }
  return (await response.json()) as { login?: string; id?: number };
}

async function fetchGithubEmail(accessToken: string) {
  const response = await fetch("https://api.github.com/user/emails", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "User-Agent": "form-app"
    }
  });
  if (!response.ok) {
    return null;
  }
  const emails = (await response.json()) as Array<{
    email?: string;
    primary?: boolean;
    verified?: boolean;
  }>;
  const primary = emails.find((item) => item.primary && item.verified);
  return primary?.email || emails.find((item) => item.email)?.email || null;
}

function buildAuthCookie(token: string, secure: boolean): string {
  const parts = [
    `formapp_token=${token}`,
    "HttpOnly",
    "SameSite=Lax",
    "Path=/",
    `Max-Age=${TOKEN_TTL_SECONDS}`
  ];
  if (secure) {
    parts.push("Secure");
  }
  return parts.join("; ");
}

export default {
  async fetch(request: Request, env: Env) {
    const url = new URL(request.url);
    const requestId = crypto.randomUUID();
    const corsHeaders = getCorsHeaders(request, env);

    if (
      request.method === "OPTIONS" &&
      (url.pathname.startsWith("/api/") || url.pathname.startsWith("/auth/"))
    ) {
      return new Response(null, {
        status: 204,
        headers: {
          "x-request-id": requestId,
          ...corsHeaders
        }
      });
    }

    if (request.method === "GET" && url.pathname === "/auth/link/google") {
      const authPayload = await getAuthPayload(request, env);
      if (!authPayload) {
        return errorResponse(401, "auth_required", requestId, corsHeaders);
      }
      const missing = getMissingEnv(env, [
        "BASE_URL_API",
        "GOOGLE_CLIENT_ID",
        "GOOGLE_CLIENT_SECRET",
        "JWT_SECRET"
      ]);
      if (missing.length > 0) {
        console.error("[oauth_init_failed]", {
          requestId,
          stage: "missing_env",
          message: `Missing env: ${missing.join(", ")}`
        });
        return jsonResponse(
          500,
          {
            error: "oauth_init_failed",
            detail: {
              missing,
              baseUrlApi: env.BASE_URL_API ?? null,
              hasKv: !!env.OAUTH_KV
            },
            requestId
          },
          requestId,
          corsHeaders
        );
      }

      let state: string;
      try {
        state = await createOauthState(env, "google", buildAccountReturnUrl(env, { linked: "google" }), {
          intent: "link",
          userId: authPayload.userId
        });
      } catch (error) {
        console.error("[oauth_init_failed]", {
          requestId,
          stage: "kv_put",
          message: String((error as Error | undefined)?.stack || (error as Error | undefined)?.message || error)
        });
        return jsonResponse(
          500,
          {
            error: "oauth_init_failed",
            detail: { kvError: String((error as Error | undefined)?.message || error) },
            requestId
          },
          requestId,
          corsHeaders
        );
      }

      try {
        const clientId = ensureEnv(env.GOOGLE_CLIENT_ID, "GOOGLE_CLIENT_ID");
        const redirectUri = `${env.BASE_URL_API}/auth/callback/google`;
        const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
        authUrl.searchParams.set("client_id", clientId);
        authUrl.searchParams.set("redirect_uri", redirectUri);
        authUrl.searchParams.set("response_type", "code");
        authUrl.searchParams.set("scope", "openid email profile");
        authUrl.searchParams.set("state", state);
        return createRedirectResponse(authUrl.toString(), requestId);
      } catch (error) {
        console.error("[oauth_init_failed]", {
          requestId,
          stage: "url_build",
          message: String((error as Error | undefined)?.stack || (error as Error | undefined)?.message || error)
        });
        return jsonResponse(
          500,
          {
            error: "oauth_init_failed",
            detail: { urlError: String((error as Error | undefined)?.message || error) },
            requestId
          },
          requestId,
          corsHeaders
        );
      }
    }

    if (request.method === "GET" && url.pathname === "/auth/link/github") {
      const authPayload = await getAuthPayload(request, env);
      if (!authPayload) {
        return errorResponse(401, "auth_required", requestId, corsHeaders);
      }
      const missing = getMissingEnv(env, [
        "BASE_URL_API",
        "GITHUB_CLIENT_ID",
        "GITHUB_CLIENT_SECRET",
        "JWT_SECRET"
      ]);
      if (missing.length > 0) {
        return jsonResponse(
          500,
          {
            error: "oauth_init_failed",
            detail: { missing, baseUrlApi: env.BASE_URL_API ?? null, hasKv: !!env.OAUTH_KV },
            requestId
          },
          requestId,
          corsHeaders
        );
      }
      const returnTo = buildAccountReturnUrl(env, { linked: "github" });
      const state = await createOauthState(env, "github", returnTo, {
        intent: "link",
        userId: authPayload.userId
      });
      const clientId = ensureEnv(env.GITHUB_CLIENT_ID, "GITHUB_CLIENT_ID");
      const authUrl = new URL("https://github.com/login/oauth/authorize");
      authUrl.searchParams.set("client_id", clientId);
      authUrl.searchParams.set("scope", "read:user user:email");
      authUrl.searchParams.set("state", state);
      return createRedirectResponse(authUrl.toString(), requestId);
    }

    if (request.method === "GET" && url.pathname === "/auth/login/google") {
      const returnTo = sanitizeReturnTo(url.searchParams.get("return_to"), env);
      const missing = getMissingEnv(env, [
        "BASE_URL_API",
        "GOOGLE_CLIENT_ID",
        "GOOGLE_CLIENT_SECRET",
        "JWT_SECRET"
      ]);
      if (missing.length > 0) {
        console.error("[oauth_init_failed]", {
          requestId,
          stage: "missing_env",
          message: `Missing env: ${missing.join(", ")}`
        });
        return jsonResponse(
          500,
          {
            error: "oauth_init_failed",
            detail: {
              missing,
              baseUrlApi: env.BASE_URL_API ?? null,
              hasKv: !!env.OAUTH_KV
            },
            requestId
          },
          requestId,
          corsHeaders
        );
      }

      let state: string;
      try {
        state = await createOauthState(env, "google", returnTo);
      } catch (error) {
        console.error("[oauth_init_failed]", {
          requestId,
          stage: "kv_put",
          message: String((error as Error | undefined)?.stack || (error as Error | undefined)?.message || error)
        });
        return jsonResponse(
          500,
          {
            error: "oauth_init_failed",
            detail: { kvError: String((error as Error | undefined)?.message || error) },
            requestId
          },
          requestId,
          corsHeaders
        );
      }

      try {
        const clientId = ensureEnv(env.GOOGLE_CLIENT_ID, "GOOGLE_CLIENT_ID");
        const redirectUri = `${env.BASE_URL_API}/auth/callback/google`;
        const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
        authUrl.searchParams.set("client_id", clientId);
        authUrl.searchParams.set("redirect_uri", redirectUri);
        authUrl.searchParams.set("response_type", "code");
        authUrl.searchParams.set("scope", "openid email profile");
        authUrl.searchParams.set("state", state);
        return createRedirectResponse(authUrl.toString(), requestId);
      } catch (error) {
        console.error("[oauth_init_failed]", {
          requestId,
          stage: "url_build",
          message: String((error as Error | undefined)?.stack || (error as Error | undefined)?.message || error)
        });
        return jsonResponse(
          500,
          {
            error: "oauth_init_failed",
            detail: { urlError: String((error as Error | undefined)?.message || error) },
            requestId
          },
          requestId,
          corsHeaders
        );
      }
    }

    if (request.method === "GET" && url.pathname === "/auth/callback/google") {
      const state = url.searchParams.get("state");
      const code = url.searchParams.get("code");
      if (!state || !code) {
        return errorResponse(400, "invalid_request", requestId, corsHeaders);
      }
      const stateRecord = await consumeOauthState(env, state);
      if (!stateRecord || stateRecord.provider !== "google") {
        return errorResponse(400, "invalid_state", requestId, corsHeaders);
      }
      try {
        const redirectUri = new URL("/auth/callback/google", ensureEnv(env.BASE_URL_API, "BASE_URL_API")).toString();
        const tokenResponse = await exchangeGoogleCode(env, code, redirectUri);
        if (!tokenResponse.id_token) {
          return errorResponse(500, "missing_id_token", requestId, corsHeaders);
        }
        const clientId = ensureEnv(env.GOOGLE_CLIENT_ID, "GOOGLE_CLIENT_ID");
        const googlePayload = decodeGoogleIdToken(tokenResponse.id_token, clientId);
        if (!googlePayload.sub) {
          return errorResponse(500, "invalid_id_token", requestId, corsHeaders);
        }
        if (stateRecord.intent === "link") {
          if (!stateRecord.userId) {
            return errorResponse(400, "invalid_state", requestId, corsHeaders);
          }
          const existing = await env.DB.prepare(
            "SELECT user_id FROM user_identities WHERE provider='google' AND provider_sub=?"
          )
            .bind(googlePayload.sub)
            .first<{ user_id: string }>();
          if (existing && existing.user_id !== stateRecord.userId) {
            console.warn("[oauth_link_conflict]", {
              requestId,
              provider: "google",
              userId: stateRecord.userId,
              existingUserId: existing.user_id
            });
            return jsonResponse(
              409,
              { error: "identity_already_linked", provider: "google", requestId },
              requestId,
              corsHeaders
            );
          }
          const adminFlag = isAdminUser("google", { sub: googlePayload.sub, email: googlePayload.email ?? null }, env) ? 1 : 0;
          const current = await env.DB.prepare("SELECT is_admin FROM users WHERE id=?")
            .bind(stateRecord.userId)
            .first<{ is_admin: number }>();
          const nextAdmin = current?.is_admin ? 1 : adminFlag;
          await env.DB.prepare("UPDATE users SET is_admin=?, updated_at=datetime('now') WHERE id=?")
            .bind(nextAdmin, stateRecord.userId)
            .run();
          if (!existing) {
            await env.DB.prepare(
              "INSERT INTO user_identities (id, user_id, provider, provider_sub, email) VALUES (?, ?, 'google', ?, ?)"
            )
              .bind(crypto.randomUUID(), stateRecord.userId, googlePayload.sub, googlePayload.email ?? null)
              .run();
          } else {
            await env.DB.prepare(
              "UPDATE user_identities SET email=? WHERE provider='google' AND provider_sub=? AND user_id=?"
            )
              .bind(googlePayload.email ?? null, googlePayload.sub, stateRecord.userId)
              .run();
          }
          console.info("[oauth_link_success]", {
            requestId,
            provider: "google",
            userId: stateRecord.userId
          });
          const redirectTarget = stateRecord.returnTo ?? buildAccountReturnUrl(env, { linked: "google" });
          return createRedirectResponse(redirectTarget, requestId);
        }

        const identity = await upsertGoogleUser(env, googlePayload.sub, googlePayload.email ?? null);
        const issuedAt = Math.floor(Date.now() / 1000);
        const jwt = await signJwt(
          {
            userId: identity.userId,
            provider: "google",
            email: googlePayload.email ?? null,
            sub: googlePayload.sub,
            isAdmin: identity.isAdmin === 1,
            iat: issuedAt,
            exp: issuedAt + TOKEN_TTL_SECONDS
          },
          ensureEnv(env.JWT_SECRET, "JWT_SECRET")
        );
        const fallbackReturn = env.BASE_URL_WEB ?? "/";
        const redirectTarget = stateRecord.returnTo ?? fallbackReturn;
        const redirectTo = appendTokenToUrl(redirectTarget, jwt);
        const response = createRedirectResponse(redirectTo, requestId);
        response.headers.set("Set-Cookie", buildAuthCookie(jwt, url.protocol === "https:"));
        return response;
      } catch (error) {
        const message = String((error as Error | undefined)?.message || error);
        // Block login for soft-deleted users and redirect to account page.
        if (message.includes("user_deleted")) {
          const redirectTarget = buildAccountReturnUrl(env, { error: "user_deleted" });
          return createRedirectResponse(redirectTarget, requestId);
        }
        console.error("[oauth_callback_failed]", {
          requestId,
          provider: "google",
          message: String((error as Error | undefined)?.stack || message || error)
        });
        return jsonResponse(
          500,
          {
            error: "oauth_callback_failed",
            detail: { message },
            requestId
          },
          requestId,
          corsHeaders
        );
      }
    }

    if (request.method === "GET" && url.pathname === "/auth/login/github") {
      try {
        const returnTo = sanitizeReturnTo(url.searchParams.get("return_to"), env);
        const state = await createOauthState(env, "github", returnTo);
        const clientId = ensureEnv(env.GITHUB_CLIENT_ID, "GITHUB_CLIENT_ID");
        const redirectUri = new URL("/auth/callback/github", ensureEnv(env.BASE_URL_API, "BASE_URL_API")).toString();
        const authUrl = new URL("https://github.com/login/oauth/authorize");
        authUrl.searchParams.set("client_id", clientId);
        authUrl.searchParams.set("scope", "read:user user:email");
        authUrl.searchParams.set("state", state);
        return createRedirectResponse(authUrl.toString(), requestId);
      } catch (error) {
        return errorResponse(500, "oauth_init_failed", requestId, corsHeaders);
      }
    }

    if (request.method === "GET" && url.pathname === "/auth/callback/github") {
      const state = url.searchParams.get("state");
      const code = url.searchParams.get("code");
      if (!state || !code) {
        return errorResponse(400, "invalid_request", requestId, corsHeaders);
      }
      const stateRecord = await consumeOauthState(env, state);
      if (!stateRecord || stateRecord.provider !== "github") {
        return errorResponse(400, "invalid_state", requestId, corsHeaders);
      }
      try {
        const redirectUri = new URL("/auth/callback/github", ensureEnv(env.BASE_URL_API, "BASE_URL_API")).toString();
        const tokenResponse = await exchangeGithubCode(env, code, redirectUri);
        if (!tokenResponse.access_token) {
          return errorResponse(500, "missing_access_token", requestId, corsHeaders);
        }
        const profile = await fetchGithubUser(tokenResponse.access_token);
        if (!profile.login || !profile.id) {
          return errorResponse(500, "invalid_github_profile", requestId, corsHeaders);
        }
        const email = await fetchGithubEmail(tokenResponse.access_token);
        if (stateRecord.intent === "link") {
          if (!stateRecord.userId) {
            return errorResponse(400, "invalid_state", requestId, corsHeaders);
          }
          const existing = await env.DB.prepare(
            "SELECT user_id FROM user_identities WHERE provider='github' AND (provider_sub=? OR provider_login=?)"
          )
            .bind(String(profile.id), profile.login)
            .first<{ user_id: string }>();
          if (existing && existing.user_id !== stateRecord.userId) {
            console.warn("[oauth_link_conflict]", {
              requestId,
              provider: "github",
              userId: stateRecord.userId,
              existingUserId: existing.user_id
            });
            return jsonResponse(
              409,
              { error: "identity_already_linked", provider: "github", requestId },
              requestId,
              corsHeaders
            );
          }
          const adminFlag = isAdminUser("github", { login: profile.login, id: String(profile.id) }, env) ? 1 : 0;
          const current = await env.DB.prepare("SELECT is_admin FROM users WHERE id=?")
            .bind(stateRecord.userId)
            .first<{ is_admin: number }>();
          const nextAdmin = current?.is_admin ? 1 : adminFlag;
          await env.DB.prepare("UPDATE users SET is_admin=?, updated_at=datetime('now') WHERE id=?")
            .bind(nextAdmin, stateRecord.userId)
            .run();
          if (!existing) {
            await env.DB.prepare(
              "INSERT INTO user_identities (id, user_id, provider, provider_sub, provider_login, email) VALUES (?, ?, 'github', ?, ?, ?)"
            )
              .bind(crypto.randomUUID(), stateRecord.userId, String(profile.id), profile.login, email)
              .run();
          } else {
            await env.DB.prepare(
              "UPDATE user_identities SET provider_login=?, provider_sub=?, email=? WHERE provider='github' AND user_id=?"
            )
              .bind(profile.login, String(profile.id), email, stateRecord.userId)
              .run();
          }
          console.info("[oauth_link_success]", {
            requestId,
            provider: "github",
            userId: stateRecord.userId
          });
          const redirectTarget = stateRecord.returnTo ?? buildAccountReturnUrl(env, { linked: "github" });
          return createRedirectResponse(redirectTarget, requestId);
        }

        const identity = await upsertGithubUser(env, profile.login, String(profile.id), email);
        const issuedAt = Math.floor(Date.now() / 1000);
        const jwt = await signJwt(
          {
            userId: identity.userId,
            provider: "github",
            email,
            sub: profile.login,
            isAdmin: identity.isAdmin === 1,
            iat: issuedAt,
            exp: issuedAt + TOKEN_TTL_SECONDS
          },
          ensureEnv(env.JWT_SECRET, "JWT_SECRET")
        );
        const fallbackReturn = env.BASE_URL_WEB ?? "/";
        const redirectTarget = stateRecord.returnTo ?? fallbackReturn;
        const redirectTo = appendTokenToUrl(redirectTarget, jwt);
        const response = createRedirectResponse(redirectTo, requestId);
        response.headers.set("Set-Cookie", buildAuthCookie(jwt, url.protocol === "https:"));
        return response;
      } catch (error) {
        const message = String((error as Error | undefined)?.message || error);
        // Block login for soft-deleted users and redirect to account page.
        if (message.includes("user_deleted")) {
          const redirectTarget = buildAccountReturnUrl(env, { error: "user_deleted" });
          return createRedirectResponse(redirectTarget, requestId);
        }
        console.error("[oauth_callback_failed]", {
          requestId,
          provider: "github",
          message: String((error as Error | undefined)?.stack || message || error)
        });
        return jsonResponse(
          500,
          {
            error: "oauth_callback_failed",
            detail: { message },
            requestId
          },
          requestId,
          corsHeaders
        );
      }
    }

    if (request.method === "GET" && url.pathname === "/auth/me") {
      const payload = await getAuthPayload(request, env);
      if (!payload) {
        return jsonResponse(
          200,
          { authenticated: false, user: null, requestId },
          requestId,
          corsHeaders
        );
      }
      return jsonResponse(
        200,
        {
          authenticated: true,
          user: {
            userId: payload.userId,
            provider: payload.provider,
            email: payload.email ?? null,
            username: payload.provider === "github" ? payload.sub : null,
            isAdmin: payload.isAdmin
          },
          requestId
        },
        requestId,
        corsHeaders
      );
    }

    if (request.method === "GET" && url.pathname === "/auth/logout") {
      const response = jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
      response.headers.set(
        "Set-Cookie",
        "formapp_token=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
      );
      return response;
    }

    if (
      request.method !== "GET" &&
      request.method !== "POST" &&
      request.method !== "PUT" &&
      request.method !== "PATCH" &&
      request.method !== "DELETE"
    ) {
      return errorResponse(405, "method_not_allowed", requestId, corsHeaders);
    }

    if (request.method === "GET" && url.pathname === "/api/health") {
      const version = env.GIT_SHA || "dev";
      return jsonResponse(
        200,
        { ok: true, version, time: new Date().toISOString() },
        requestId,
        corsHeaders
      );
    }

    if (request.method === "GET" && url.pathname === "/api/debug/version") {
      return jsonResponse(
        200,
        {
          ok: true,
          buildTime: BUILD_TIME,
          gitCommit: env.GIT_COMMIT ?? null,
          routesHash: "v1",
          requestId
        },
        requestId,
        corsHeaders
      );
    }

    if (
      request.method === "GET" &&
      (url.pathname === "/api/debug/oauth" || url.pathname === "/api/debug/oauth-config")
    ) {
      return jsonResponse(
        200,
        {
          ok: true,
          requestId,
          env: {
            baseUrlApi: env.BASE_URL_API ?? null,
            baseUrlWeb: env.BASE_URL_WEB ?? null,
            allowedOrigin: env.ALLOWED_ORIGIN ?? null,
            hasGoogleClientId: !!env.GOOGLE_CLIENT_ID,
            hasGoogleClientSecret: !!env.GOOGLE_CLIENT_SECRET,
            hasGithubClientId: !!env.GITHUB_CLIENT_ID,
            hasGithubClientSecret: !!env.GITHUB_CLIENT_SECRET,
            hasJwtSecret: !!env.JWT_SECRET,
            hasAdminGoogleSub: !!env.ADMIN_GOOGLE_SUB,
            hasAdminGithub: !!env.ADMIN_GITHUB
          },
          bindings: {
            hasOauthKv: !!env.OAUTH_KV,
            hasDb: !!env.DB,
            hasR2: !!env.form_app_files
          },
          computed: {
            googleRedirectUri: env.BASE_URL_API
              ? `${env.BASE_URL_API}/auth/callback/google`
              : null,
            githubRedirectUri: env.BASE_URL_API
              ? `${env.BASE_URL_API}/auth/callback/github`
              : null
          }
        },
        requestId,
        corsHeaders
      );
    }

    if (request.method === "GET" && url.pathname === "/api/settings") {
      const timezoneDefault = await getAppSetting(env, APP_SETTING_DEFAULT_TIMEZONE);
      const canvasCourseSyncMode = await getAppSetting(env, APP_SETTING_CANVAS_COURSE_SYNC_MODE);
      const canvasDeleteSync = await getAppSetting(env, APP_SETTING_CANVAS_DELETE_SYNC);
      const markdownEnabled = await getAppSetting(env, APP_SETTING_MARKDOWN_ENABLED);
      const mathjaxEnabled = await getAppSetting(env, APP_SETTING_MATHJAX_ENABLED);
      return jsonResponse(
        200,
        {
          timezoneDefault,
          canvasCourseSyncMode: normalizeCanvasCourseSyncMode(canvasCourseSyncMode),
          canvasDeleteSyncEnabled: normalizeAppToggle(canvasDeleteSync, true),
          markdownEnabled: normalizeAppToggle(markdownEnabled, true),
          mathjaxEnabled: normalizeAppToggle(mathjaxEnabled, true),
          requestId
        },
        requestId,
        corsHeaders
      );
    }

    if (url.pathname.startsWith("/api/admin")) {
      const adminPayload = await requireAdmin(request, env);
      if (!adminPayload) {
        return errorResponse(403, "forbidden", requestId, corsHeaders);
      }

      if (request.method === "GET" && url.pathname === "/api/admin/health") {
        const hasDriveServiceAccount = Boolean(getDriveCredentials(env));
        const hasDriveParentFolderId = Boolean(env.DRIVE_PARENT_FOLDER_ID);
        return jsonResponse(
          200,
          {
            ok: true,
            requestId,
            hasDriveServiceAccount,
            hasDriveParentFolderId,
            driveParentFolderId: env.DRIVE_PARENT_FOLDER_ID ?? null
          },
          requestId,
          corsHeaders
        );
      }

      if (request.method === "GET" && url.pathname === "/api/admin/health/summary") {
        const { results } = await env.DB.prepare(
          "SELECT h1.service,h1.service_title,h1.status,h1.message,h1.checked_at FROM health_status_logs h1 JOIN (SELECT service, MAX(checked_at) as max_checked FROM health_status_logs GROUP BY service) h2 ON h1.service=h2.service AND h1.checked_at=h2.max_checked ORDER BY h1.service"
        ).all<{
          service: string;
          service_title: string | null;
          status: string;
          message: string | null;
          checked_at: string;
        }>();
        const data = results.map((row) => ({
          ...row,
          service_title: getHealthServiceTitle(row.service, row.service_title)
        }));
        return jsonResponse(200, { data, requestId }, requestId, corsHeaders);
      }

      if (request.method === "GET" && url.pathname === "/api/admin/health/history") {
        const service = (url.searchParams.get("service") || "").trim();
        const limit = Math.min(Math.max(toNumber(url.searchParams.get("limit"), 50), 1), 200);
        let query = "SELECT id,service,service_title,status,message,created_at FROM health_status_logs";
        const params: unknown[] = [];
        if (service) {
          query += " WHERE service=?";
          params.push(service);
        }
        query = query.replace("created_at", "checked_at");
        query += " ORDER BY checked_at DESC LIMIT ?";
        params.push(limit);
        const { results } = await env.DB.prepare(query)
          .bind(...params)
          .all<{
            id: string;
            service: string;
            status: string;
            message: string | null;
            checked_at: string;
          }>();
        const data = results.map((row) => ({
          ...row,
          service_title: getHealthServiceTitle(row.service, (row as any).service_title ?? null)
        }));
        return jsonResponse(200, { data, requestId }, requestId, corsHeaders);
      }

      if (request.method === "POST" && url.pathname === "/api/admin/health/clear") {
        let service: string | null = null;
        try {
          const body = await parseJsonBody<{ service?: string }>(request);
          if (typeof body?.service === "string" && body.service.trim()) {
            service = body.service.trim();
          }
        } catch {
          service = null;
        }
        if (service) {
          await env.DB.prepare("DELETE FROM health_status_logs WHERE service=?")
            .bind(service)
            .run();
        } else {
          await env.DB.prepare("DELETE FROM health_status_logs").run();
        }
        return jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
      }

      if (request.method === "GET" && url.pathname === "/api/admin/canvas/courses") {
        const q = (url.searchParams.get("q") || "").trim();
        const page = Math.max(toNumber(url.searchParams.get("page"), 1), 1);
        const pageSize = Math.min(Math.max(toNumber(url.searchParams.get("pageSize"), 50), 1), 200);
        const limit = pageSize;
        const offset = (page - 1) * pageSize;
        const like = `%${q}%`;
        const mode = await getCanvasCourseSyncMode(env);
        const filter = buildCanvasCourseFilter(mode);
        const totalRow = await env.DB.prepare(
          `SELECT COUNT(1) as total FROM canvas_courses_cache WHERE ${filter} AND (?='' OR name LIKE ? OR code LIKE ?)`
        )
          .bind(q, like, like)
          .first<{ total: number }>();
        const total = totalRow?.total ?? 0;
        const { results } = await env.DB.prepare(
          `SELECT id,name,code,workflow_state,account_id,term_id,updated_at FROM canvas_courses_cache WHERE ${filter} AND (?='' OR name LIKE ? OR code LIKE ?) ORDER BY name LIMIT ? OFFSET ?`
        )
          .bind(q, like, like, limit, offset)
          .all();
        return jsonResponse(
          200,
          { data: results, page, pageSize, total, needsSync: total === 0, requestId },
          requestId,
          corsHeaders
        );
      }


      if (request.method === "GET" && url.pathname === "/api/admin/canvas/overview") {
        const mode = await getCanvasCourseSyncMode(env);
        const filter = buildCanvasCourseFilter(mode);
        const { results: courses } = await env.DB.prepare(
          `SELECT id,name,code,workflow_state,updated_at FROM canvas_courses_cache WHERE ${filter} ORDER BY name`
        ).all<{
          id: string;
          name: string;
          code: string | null;
          workflow_state: string | null;
          updated_at: string | null;
        }>();

        if (!courses.length) {
          return jsonResponse(200, { data: [], requestId }, requestId, corsHeaders);
        }

        const courseIds = courses.map((course) => String(course.id));
        const placeholders = courseIds.map(() => "?").join(",");
        const { results: sectionRows } = await env.DB.prepare(
          `SELECT id,course_id,name FROM canvas_sections_cache WHERE course_id IN (${placeholders})`
        )
          .bind(...courseIds)
          .all<{ id: string; course_id: string; name: string }>();
        const sectionNameMap = new Map<string, Map<string, string>>();
        sectionRows.forEach((row) => {
          const courseId = String(row.course_id);
          if (!sectionNameMap.has(courseId)) {
            sectionNameMap.set(courseId, new Map());
          }
          sectionNameMap.get(courseId)!.set(String(row.id), row.name);
        });

        const { results: submissions } = await env.DB.prepare(
          `SELECT s.id,s.user_id,s.payload_json,s.canvas_enroll_status,s.canvas_enroll_error,s.canvas_course_id,s.canvas_section_id,s.canvas_enrolled_at,s.canvas_user_id,s.canvas_user_name,s.created_at,s.updated_at,s.deleted_at as submission_deleted,f.slug as form_slug,f.title as form_title,COALESCE(s.submitter_email,(SELECT email FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1)) as submitter_email,COALESCE(s.submitter_github_username,(SELECT provider_login FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1)) as submitter_github_username FROM submissions s JOIN forms f ON f.id=s.form_id WHERE s.deleted_at IS NULL AND f.deleted_at IS NULL AND s.canvas_course_id IN (${placeholders}) ORDER BY COALESCE(s.canvas_enrolled_at, s.updated_at, s.created_at) DESC`
        )
          .bind(...courseIds)
          .all<{
            id: string;
            user_id: string | null;
            payload_json: string;
            canvas_enroll_status: string | null;
            canvas_enroll_error: string | null;
            canvas_course_id: string | null;
            canvas_section_id: string | null;
            canvas_enrolled_at: string | null;
            canvas_user_id: string | null;
            canvas_user_name: string | null;
            created_at: string | null;
            updated_at: string | null;
            submission_deleted: string | null;
            form_slug: string;
            form_title: string;
            submitter_email: string | null;
            submitter_github_username: string | null;
          }>();

        const submissionsByCourse = new Map<string, any[]>();
        for (const row of submissions) {
          if (!row.canvas_course_id) continue;
          const courseId = String(row.canvas_course_id);
          const sectionId = row.canvas_section_id ? String(row.canvas_section_id) : null;
          let payloadData: Record<string, unknown> | null = null;
          try {
            const payload = JSON.parse(row.payload_json) as { data?: Record<string, unknown> };
            if (payload?.data && typeof payload.data === "object") {
              payloadData = payload.data as Record<string, unknown>;
            }
          } catch {
            payloadData = null;
          }
          const displayName = pickNameFromPayload(payloadData);
          const dataEmail =
            typeof payloadData?.email === "string" && payloadData.email.trim()
              ? payloadData.email.trim()
              : null;
          const email = dataEmail || row.submitter_email;
          const status = row.canvas_enroll_status || "not_invited";
          const sectionName =
            sectionId && sectionNameMap.has(courseId)
              ? sectionNameMap.get(courseId)!.get(sectionId) || null
              : null;
          let canvasFullName: string | null = null;
          let canvasDisplayName: string | null = row.canvas_user_name || null;
          if (email) {
            const canvasUser = await canvasFindUserByEmailInCourse(env, courseId, email);
            canvasFullName = canvasUser?.name?.trim() || null;
            canvasDisplayName = canvasUser?.shortName?.trim() || canvasDisplayName;
          }
          const entry = {
            submission_id: row.id,
            submission_link: `/forms/#/me/submissions/${row.id}`,
            submission_deleted: Boolean(row.submission_deleted),
            user_id: row.user_id,
            name: displayName,
            email,
            github_username: row.submitter_github_username,
            status,
            error: row.canvas_enroll_error,
            enrolled_at: row.canvas_enrolled_at,
            section_id: sectionId,
            section_name: sectionName,
            canvas_user_id: row.canvas_user_id,
            canvas_user_name: row.canvas_user_name,
            canvas_full_name: canvasFullName,
            canvas_display_name: canvasDisplayName,
            form_slug: row.form_slug,
            form_title: row.form_title
          };
          if (!submissionsByCourse.has(courseId)) {
            submissionsByCourse.set(courseId, []);
          }
          submissionsByCourse.get(courseId)!.push(entry);
        }

        const data = courses.map((course) => ({
          id: String(course.id),
          name: course.name,
          code: course.code ?? null,
          workflow_state: course.workflow_state ?? null,
          updated_at: course.updated_at ?? null,
          registrations: submissionsByCourse.get(String(course.id)) ?? []
        }));

        return jsonResponse(200, { data, requestId }, requestId, corsHeaders);
      }

      if (request.method === "GET" && url.pathname === "/api/admin/canvas/retry-queue") {
        const limit = Math.min(Math.max(toNumber(url.searchParams.get("limit"), 50), 1), 200);
        const { results: queue } = await env.DB.prepare(
          "SELECT q.id,q.submission_id,q.course_id,q.section_id,q.submitter_email,q.attempts,q.last_error,q.next_run_at,q.created_at,s.form_id,f.slug as form_slug,f.title as form_title FROM canvas_enroll_queue q LEFT JOIN submissions s ON s.id=q.submission_id LEFT JOIN forms f ON f.id=s.form_id ORDER BY q.next_run_at ASC LIMIT ?"
        )
          .bind(limit)
          .all();
        const { results: deadletters } = await env.DB.prepare(
          "SELECT id,submission_id,course_id,section_id,submitter_email,error,attempts,created_at FROM canvas_enroll_deadletters ORDER BY created_at DESC LIMIT ?"
        )
          .bind(limit)
          .all();
        return jsonResponse(200, { queue, deadletters, requestId }, requestId, corsHeaders);
      }

      const retryMatch = url.pathname.match(/^\/api\/admin\/canvas\/retry-queue\/([^/]+)\/retry$/);
      if (request.method === "POST" && retryMatch) {
        const entryId = decodeURIComponent(retryMatch[1]);
        const source = (url.searchParams.get("source") || "queue").trim();
        if (source === "deadletter") {
          const deadletter = await env.DB.prepare(
            "SELECT id,submission_id,course_id,section_id,submitter_email FROM canvas_enroll_deadletters WHERE id=?"
          )
            .bind(entryId)
            .first<{
              id: string;
              submission_id: string;
              course_id: string;
              section_id: string | null;
              submitter_email: string | null;
            }>();
          if (!deadletter) {
            return errorResponse(404, "not_found", requestId, corsHeaders);
          }
          const submission = await env.DB.prepare(
            "SELECT form_id,payload_json FROM submissions WHERE id=?"
          )
            .bind(deadletter.submission_id)
            .first<{ form_id: string; payload_json: string }>();
          if (!submission) {
            return errorResponse(404, "not_found", requestId, corsHeaders);
          }
          let payloadData: Record<string, unknown> | null = null;
          try {
            const payload = JSON.parse(submission.payload_json) as { data?: Record<string, unknown> };
            if (payload?.data && typeof payload.data === "object") {
              payloadData = payload.data as Record<string, unknown>;
            }
          } catch {
            payloadData = null;
          }
          const submitterName = pickNameFromPayload(payloadData);
          await env.DB.prepare(
            "INSERT INTO canvas_enroll_queue (id, submission_id, form_id, course_id, section_id, submitter_name, submitter_email, attempts, last_error, next_run_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))"
          )
            .bind(
              crypto.randomUUID(),
              deadletter.submission_id,
              submission.form_id,
              deadletter.course_id,
              deadletter.section_id,
              submitterName,
              deadletter.submitter_email,
              0,
              "retry_from_deadletter"
            )
            .run();
          await env.DB.prepare("DELETE FROM canvas_enroll_deadletters WHERE id=?")
            .bind(entryId)
            .run();
          return jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
        }

        const updated = await env.DB.prepare(
          "UPDATE canvas_enroll_queue SET next_run_at=datetime('now') WHERE id=?"
        )
          .bind(entryId)
          .run();
        if (updated.meta.changes === 0) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        return jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
      }

      const dropMatch = url.pathname.match(/^\/api\/admin\/canvas\/retry-queue\/([^/]+)\/drop$/);
      if (request.method === "POST" && dropMatch) {
        const entryId = decodeURIComponent(dropMatch[1]);
        const source = (url.searchParams.get("source") || "queue").trim();
        const table = source === "deadletter" ? "canvas_enroll_deadletters" : "canvas_enroll_queue";
        const result = await env.DB.prepare(`DELETE FROM ${table} WHERE id=?`)
          .bind(entryId)
          .run();
        if (result.meta.changes === 0) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        return jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
      }

      if (request.method === "GET" && url.pathname === "/api/admin/canvas/user-lookup") {
        const query = (url.searchParams.get("q") || url.searchParams.get("email") || "").trim();
        const courseId = (url.searchParams.get("courseId") || "").trim();
        if (!query) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "q",
            message: "required"
          });
        }
        if (courseId) {
          const users = await canvasSearchUsersInCourse(env, courseId, query);
          if (users.length === 0) {
            return errorResponse(404, "not_found", requestId, corsHeaders, {
              message: "not_found"
            });
          }
          return jsonResponse(
            200,
            {
              ok: true,
              requestId,
              data: users.map((user) => ({
                id: user.id,
                full_name: user.name ?? null,
                display_name: user.shortName ?? null,
                sortable_name: user.sortableName ?? null,
                pronouns: user.pronouns ?? null,
                email: user.email ?? null,
                login_id: user.loginId ?? null,
                roles: Array.isArray(user.roles) ? user.roles : []
              }))
            },
            requestId,
            corsHeaders
          );
        }

        const users = await canvasSearchUsersAllCourses(env, query);
        if (users.length === 0) {
          return errorResponse(404, "not_found", requestId, corsHeaders, {
            message: "not_found"
          });
        }
        return jsonResponse(
          200,
          {
            ok: true,
            requestId,
            data: users.map((user) => ({
              id: user.id,
              full_name: user.name ?? null,
              display_name: user.shortName ?? null,
              sortable_name: user.sortableName ?? null,
              pronouns: user.pronouns ?? null,
              email: user.email ?? null,
              login_id: user.loginId ?? null,
              roles: Array.isArray(user.roles) ? user.roles : [],
              courses: user.courses
            }))
          },
          requestId,
          corsHeaders
        );
      }

      if (request.method === "POST" && url.pathname === "/api/admin/canvas/enroll") {
        const body = (await request.json().catch(() => null)) as {
          name?: string;
          email?: string;
          role?: string;
          courseId?: string;
          sectionId?: string | null;
        } | null;
        if (!body || typeof body !== "object") {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "expected_object"
          });
        }
        const name = typeof body.name === "string" ? body.name.trim() : "";
        const email = typeof body.email === "string" ? body.email.trim() : "";
        const courseId = typeof body.courseId === "string" ? body.courseId.trim() : "";
        const sectionId =
          typeof body.sectionId === "string" && body.sectionId.trim()
            ? body.sectionId.trim()
            : null;
        const roleRaw = typeof body.role === "string" ? body.role.trim().toLowerCase() : "student";
        const role =
          roleRaw === "teacher" || roleRaw === "ta" || roleRaw === "observer" || roleRaw === "designer"
            ? roleRaw
            : "student";
        if (!name) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "name",
            message: "required"
          });
        }
        if (!email) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "email",
            message: "required"
          });
        }
        if (!courseId) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "courseId",
            message: "required"
          });
        }
        const result = await adminEnrollCanvasUser(env, {
          courseId,
          sectionId,
          name,
          email,
          role: role as "student" | "teacher" | "ta" | "observer" | "designer"
        });
        if (!result.ok) {
          return errorResponse(500, "canvas_enroll_failed", requestId, corsHeaders, {
            message: result.error || "canvas_enroll_failed"
          });
        }
        return jsonResponse(
          200,
          {
            ok: true,
            status: result.status,
            canvasUserId: result.canvasUserId,
            requestId
          },
          requestId,
          corsHeaders
        );
      }

      if (request.method === "PATCH" && url.pathname === "/api/admin/settings") {
        const body = (await request.json().catch(() => null)) as {
          timezoneDefault?: string | null;
          canvasCourseSyncMode?: string | null;
          canvasDeleteSyncEnabled?: boolean | null;
          markdownEnabled?: boolean | null;
          mathjaxEnabled?: boolean | null;
        } | null;
        if (
          !body ||
          (!("timezoneDefault" in body) &&
            !("canvasCourseSyncMode" in body) &&
            !("canvasDeleteSyncEnabled" in body) &&
            !("markdownEnabled" in body) &&
            !("mathjaxEnabled" in body))
        ) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "settings_required"
          });
        }

        const responsePayload: Record<string, unknown> = { ok: true, requestId };
        if ("timezoneDefault" in body) {
          if (body.timezoneDefault === null) {
            await deleteAppSetting(env, APP_SETTING_DEFAULT_TIMEZONE);
            responsePayload.timezoneDefault = null;
          } else if (typeof body.timezoneDefault !== "string" || !body.timezoneDefault.trim()) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "timezoneDefault",
              message: "invalid_timezone"
            });
          } else {
            const value = body.timezoneDefault.trim();
            await setAppSetting(env, APP_SETTING_DEFAULT_TIMEZONE, value);
            responsePayload.timezoneDefault = value;
          }
        }

        if ("canvasCourseSyncMode" in body) {
          if (body.canvasCourseSyncMode === null) {
            await deleteAppSetting(env, APP_SETTING_CANVAS_COURSE_SYNC_MODE);
            responsePayload.canvasCourseSyncMode = "active";
          } else if (typeof body.canvasCourseSyncMode !== "string") {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "canvasCourseSyncMode",
              message: "invalid_mode"
            });
          } else {
            const mode = normalizeCanvasCourseSyncMode(body.canvasCourseSyncMode);
            await setAppSetting(env, APP_SETTING_CANVAS_COURSE_SYNC_MODE, mode);
            responsePayload.canvasCourseSyncMode = mode;
          }
        }

        if ("canvasDeleteSyncEnabled" in body) {
          if (body.canvasDeleteSyncEnabled === null) {
            await deleteAppSetting(env, APP_SETTING_CANVAS_DELETE_SYNC);
            responsePayload.canvasDeleteSyncEnabled = true;
          } else if (typeof body.canvasDeleteSyncEnabled !== "boolean") {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "canvasDeleteSyncEnabled",
              message: "invalid_value"
            });
          } else {
            const value = body.canvasDeleteSyncEnabled ? "enabled" : "disabled";
            await setAppSetting(env, APP_SETTING_CANVAS_DELETE_SYNC, value);
            responsePayload.canvasDeleteSyncEnabled = body.canvasDeleteSyncEnabled;
          }
        }

        if ("markdownEnabled" in body) {
          if (body.markdownEnabled === null) {
            await deleteAppSetting(env, APP_SETTING_MARKDOWN_ENABLED);
            responsePayload.markdownEnabled = true;
          } else if (typeof body.markdownEnabled !== "boolean") {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "markdownEnabled",
              message: "invalid_value"
            });
          } else {
            const value = body.markdownEnabled ? "enabled" : "disabled";
            await setAppSetting(env, APP_SETTING_MARKDOWN_ENABLED, value);
            responsePayload.markdownEnabled = body.markdownEnabled;
          }
        }

        if ("mathjaxEnabled" in body) {
          if (body.mathjaxEnabled === null) {
            await deleteAppSetting(env, APP_SETTING_MATHJAX_ENABLED);
            responsePayload.mathjaxEnabled = true;
          } else if (typeof body.mathjaxEnabled !== "boolean") {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "mathjaxEnabled",
              message: "invalid_value"
            });
          } else {
            const value = body.mathjaxEnabled ? "enabled" : "disabled";
            await setAppSetting(env, APP_SETTING_MATHJAX_ENABLED, value);
            responsePayload.mathjaxEnabled = body.mathjaxEnabled;
          }
        }

        return jsonResponse(200, responsePayload, requestId, corsHeaders);
      }
      if (request.method === "GET" && url.pathname === "/api/admin/routines") {
        const routineTitleById: Record<string, string> = {
          backup_forms: "Backup forms",
          backup_templates: "Backup templates",
          backup_forms_templates: "Backup forms + templates",
          canvas_name_mismatch_checker: "Canvas name mismatch checker",
          canvas_name_mismatch: "Canvas name mismatch checker",
          canvas_retry_queue: "Canvas retry queue",
          canvas_sync: "Canvas sync",
          gmail_send: "Gmail send",
          test_notice: "Test notice",
          empty_trash: "Empty trash"
        };
        const { results } = await env.DB.prepare(
          "SELECT id,name,cron,enabled,last_run_at,last_status,last_error,last_log_id FROM routine_tasks ORDER BY id"
        ).all<RoutineTaskRow>();
        const data = results.map((row) => ({
          ...row,
          title: row.name || routineTitleById[row.id] || row.id
        }));
        return jsonResponse(200, { data, requestId }, requestId, corsHeaders);
      }
      if (request.method === "GET" && url.pathname === "/api/admin/routines/logs") {
        const taskId = url.searchParams.get("taskId")?.trim() || "";
        const limit = Math.min(Math.max(toNumber(url.searchParams.get("limit"), 20), 1), 200);
        if (!taskId) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "taskId is required"
          });
        }
        const { results } = await env.DB.prepare(
          "SELECT id,task_id,run_at,status,message FROM routine_task_runs WHERE task_id=? ORDER BY run_at DESC LIMIT ?"
        )
          .bind(taskId, limit)
          .all();
        return jsonResponse(200, { data: results, requestId }, requestId, corsHeaders);
      }
      if (request.method === "POST" && url.pathname === "/api/admin/routines/logs/clear") {
        let body: { taskId?: string } | null = null;
        try {
          body = await parseJsonBody(request);
        } catch (error) {
          return errorResponse(400, "invalid_json", requestId, corsHeaders);
        }
        const taskId = body?.taskId?.trim();
        if (!taskId) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "taskId is required"
          });
        }
        await env.DB.prepare("DELETE FROM routine_task_runs WHERE task_id=?")
          .bind(taskId)
          .run();
        await env.DB.prepare(
          "UPDATE routine_tasks SET last_log_id=NULL, last_run_at=NULL, last_status=NULL, last_error=NULL WHERE id=?"
        )
          .bind(taskId)
          .run();
        return jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
      }
      if (request.method === "POST" && url.pathname === "/api/admin/routines") {
        let body: { id?: string; cron?: string; enabled?: boolean } | null = null;
        try {
          body = await parseJsonBody(request);
        } catch (error) {
          return errorResponse(400, "invalid_json", requestId, corsHeaders);
        }
        const id = body?.id?.trim();
        const cron = typeof body?.cron === "string" ? body?.cron.trim() : "";
        if (!id || !cron) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "id and cron are required"
          });
        }
        const enabled = body?.enabled === false ? 0 : 1;
        const existing = await env.DB.prepare("SELECT id FROM routine_tasks WHERE id=?")
          .bind(id)
          .first<{ id: string }>();
        if (!existing?.id) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        await env.DB.prepare(
          "UPDATE routine_tasks SET cron=?, enabled=?, updated_at=datetime('now') WHERE id=?"
        )
          .bind(cron, enabled, id)
          .run();
        return jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
      }
      if (request.method === "POST" && url.pathname === "/api/admin/routines/run") {
        let body: { id?: string } | null = null;
        try {
          body = await parseJsonBody(request);
        } catch (error) {
          return errorResponse(400, "invalid_json", requestId, corsHeaders);
        }
        const id = body?.id?.trim();
        if (!id) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "id is required"
          });
        }
        const existing = await env.DB.prepare("SELECT id FROM routine_tasks WHERE id=?")
          .bind(id)
          .first<{ id: string }>();
        if (!existing?.id) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        await runRoutineTaskById(env, id);
        return jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
      }

      const canvasRegistrationMatch = url.pathname.match(
        /^\/api\/admin\/canvas\/registrations\/([^/]+)\/(deactivate|delete|reactivate)$/
      );
      if (request.method === "POST" && canvasRegistrationMatch) {
        const submissionId = decodeURIComponent(canvasRegistrationMatch[1] || "").trim();
        const task = canvasRegistrationMatch[2] as "deactivate" | "delete" | "reactivate";
        if (!submissionId) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "submissionId",
            message: "required"
          });
        }
        const submission = await env.DB.prepare(
          "SELECT s.id,s.form_id,s.user_id,s.payload_json,s.canvas_course_id,s.canvas_section_id,COALESCE(s.submitter_email,(SELECT email FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1)) as submitter_email,f.canvas_enabled,f.canvas_course_id as form_canvas_course_id FROM submissions s LEFT JOIN forms f ON f.id=s.form_id WHERE s.id=? AND s.deleted_at IS NULL"
        )
          .bind(submissionId)
          .first<{
            id: string;
            form_id: string | null;
            user_id: string | null;
            payload_json: string;
            canvas_course_id: string | null;
            canvas_section_id: string | null;
            submitter_email: string | null;
            canvas_enabled: number | null;
            form_canvas_course_id: string | null;
          }>();
        if (!submission) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        const courseId = submission.canvas_course_id || submission.form_canvas_course_id || null;
        if (!courseId && task !== "delete") {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        let payloadData: Record<string, unknown> | null = null;
        try {
          const payload = JSON.parse(submission.payload_json) as { data?: Record<string, unknown> };
          if (payload?.data && typeof payload.data === "object") {
            payloadData = payload.data as Record<string, unknown>;
          }
        } catch {
          payloadData = null;
        }
        const email =
          (typeof payloadData?.email === "string" && payloadData.email.trim()) ||
          submission.submitter_email ||
          null;
        if (!email) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "email",
            message: "required"
          });
        }
        if (task === "reactivate") {
          const enrollment = await canvasFindEnrollmentByEmail(env, courseId ?? "", email);
          if (!enrollment.id) {
            return errorResponse(500, "canvas_update_failed", requestId, corsHeaders, {
              message: enrollment.error || "enrollment_not_found"
            });
          }
          const result = await canvasReactivateEnrollment(env, courseId ?? "", enrollment.id);
          if (!result.ok) {
            return errorResponse(500, "canvas_update_failed", requestId, corsHeaders, {
              message: result.error || "canvas_update_failed"
            });
          }
          await env.DB.prepare(
            "UPDATE submissions SET canvas_enroll_status=?, canvas_enroll_error=?, canvas_user_id=? WHERE id=?"
          )
            .bind("invited", "canvas_reactivate", enrollment.canvasUserId ?? null, submissionId)
            .run();
          return jsonResponse(
            200,
            { ok: true, status: "invited", requestId },
            requestId,
            corsHeaders
          );
        }
        if (task === "delete" && !courseId) {
          const ap = await getAuthPayload(request, env);
          await updateSubmissionsSoftDelete(env, "id=?", [submissionId], ap?.userId ?? null, "user_deleted");
          return jsonResponse(
            200,
            { ok: true, status: "deleted", requestId },
            requestId,
            corsHeaders
          );
        }
        const result = await canvasApplyEnrollmentTaskByEmail(env, courseId ?? "", email, task);
        if (!result.ok) {
          return errorResponse(500, "canvas_update_failed", requestId, corsHeaders, {
            message: result.error || "canvas_update_failed"
          });
        }
        await env.DB.prepare(
          "UPDATE submissions SET canvas_enroll_status=?, canvas_enroll_error=? WHERE id=?"
        )
          .bind(task === "delete" ? "deleted" : "deactivated", `canvas_${task}`, submissionId)
          .run();
        return jsonResponse(
          200,
          {
            ok: true,
            status: task === "delete" ? "deleted" : "deactivated",
            requestId
          },
          requestId,
          corsHeaders
        );
      }

      const canvasSubmissionDeleteMatch = url.pathname.match(
        /^\/api\/admin\/canvas\/registrations\/([^/]+)\/submission-delete$/
      );
      if (request.method === "POST" && canvasSubmissionDeleteMatch) {
        const submissionId = decodeURIComponent(canvasSubmissionDeleteMatch[1] || "").trim();
        if (!submissionId) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "submissionId",
            message: "required"
          });
        }
        const result = await softDeleteSubmissionById(env, submissionId, adminPayload?.userId ?? null, "admin_delete");
        const attempted = result.canvas?.attempted ?? 0;
        const failed = result.canvas?.failed ?? 0;
        const canvasAction = attempted === 0 ? "skipped" : failed > 0 ? "failed" : "deactivated";
        return jsonResponse(
          200,
          { ok: result.ok, canvasAction, canvasAttempts: attempted, canvasFailed: failed, requestId },
          requestId,
          corsHeaders
        );
      }

      const canvasReinviteMatch = url.pathname.match(
        /^\/api\/admin\/canvas\/registrations\/([^/]+)\/reinvite$/
      );
      if (request.method === "POST" && canvasReinviteMatch) {
        const submissionId = decodeURIComponent(canvasReinviteMatch[1] || "").trim();
        if (!submissionId) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "submissionId",
            message: "required"
          });
        }
        const submission = await env.DB.prepare(
          "SELECT s.id,s.form_id,s.user_id,s.payload_json,s.canvas_course_id,s.canvas_section_id,s.submitter_email,f.canvas_enabled,f.canvas_course_id as form_canvas_course_id FROM submissions s JOIN forms f ON f.id=s.form_id WHERE s.id=? AND s.deleted_at IS NULL"
        )
          .bind(submissionId)
          .first<{
            id: string;
            form_id: string;
            user_id: string | null;
            payload_json: string;
            canvas_course_id: string | null;
            canvas_section_id: string | null;
            submitter_email: string | null;
            canvas_enabled: number | null;
            form_canvas_course_id: string | null;
          }>();
        if (!submission) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        const courseId = submission.canvas_course_id || submission.form_canvas_course_id;
        if (!toBoolean(submission.canvas_enabled) || !courseId) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "canvas_not_configured"
          });
        }
        let payloadData: Record<string, unknown> | null = null;
        try {
          const payload = JSON.parse(submission.payload_json) as { data?: Record<string, unknown> };
          if (payload?.data && typeof payload.data === "object") {
            payloadData = payload.data as Record<string, unknown>;
          }
        } catch {
          payloadData = null;
        }
        const nameFromPayload =
          (typeof payloadData?.full_name === "string" && payloadData.full_name.trim()) ||
          (typeof payloadData?.name === "string" && payloadData.name.trim()) ||
          "";
        let email =
          typeof payloadData?.email === "string" && payloadData.email.trim()
            ? payloadData.email.trim()
            : submission.submitter_email || "";
        if (!email && submission.user_id) {
          const primary = await getUserPrimaryEmail(env, submission.user_id);
          email = primary || "";
        }
        const name = nameFromPayload || (email ? titleCaseFromEmail(email) : "");
        if (!email) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "email",
            message: "required"
          });
        }
        const form = { canvas_enabled: 1, canvas_course_id: courseId };
        const enrollment = await handleCanvasEnrollment(
          env,
          form,
          name,
          email,
          submission.canvas_section_id ?? null
        );
        await env.DB.prepare(
          "UPDATE submissions SET canvas_enroll_status=?, canvas_enroll_error=?, canvas_course_id=?, canvas_section_id=?, canvas_enrolled_at=?, canvas_user_id=?, canvas_user_name=? WHERE id=?"
        )
          .bind(
            enrollment.status,
            enrollment.error,
            courseId,
            enrollment.sectionId,
            enrollment.enrolledAt,
            enrollment.canvasUserId ?? null,
            enrollment.canvasUserName ?? null,
            submissionId
          )
          .run();
        return jsonResponse(
          200,
          {
            ok: true,
            status: enrollment.status,
            error: enrollment.error,
            requestId
          },
          requestId,
          corsHeaders
        );
      }

      const canvasNotifyMatch = url.pathname.match(
        /^\/api\/admin\/canvas\/registrations\/([^/]+)\/notify$/
      );
      if (request.method === "POST" && canvasNotifyMatch) {
        const submissionId = decodeURIComponent(canvasNotifyMatch[1] || "").trim();
        if (!submissionId) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "submissionId",
            message: "required"
          });
        }
        const submission = await env.DB.prepare(
          "SELECT s.id,s.payload_json,s.canvas_course_id,s.canvas_section_id,s.canvas_user_id,s.canvas_user_name,COALESCE(s.submitter_email,(SELECT email FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1)) as submitter_email,f.title as form_title,f.slug as form_slug FROM submissions s JOIN forms f ON f.id=s.form_id WHERE s.id=? AND s.deleted_at IS NULL"
        )
          .bind(submissionId)
          .first<{
            id: string;
            payload_json: string;
            canvas_course_id: string | null;
            canvas_section_id: string | null;
            canvas_user_id: string | null;
            canvas_user_name: string | null;
            submitter_email: string | null;
            form_title: string | null;
            form_slug: string | null;
          }>();
        if (!submission) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        let payloadData: Record<string, unknown> | null = null;
        try {
          const payload = JSON.parse(submission.payload_json) as { data?: Record<string, unknown> };
          if (payload?.data && typeof payload.data === "object") {
            payloadData = payload.data as Record<string, unknown>;
          }
        } catch {
          payloadData = null;
        }
        const submittedName = pickNameFromPayload(payloadData);
        const email =
          (typeof payloadData?.email === "string" && payloadData.email.trim()) ||
          submission.submitter_email ||
          null;
        if (!email) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "email",
            message: "required"
          });
        }
        let canvasFullName: string | null = null;
        let canvasDisplayName: string | null = submission.canvas_user_name || null;
        if (submission.canvas_course_id && email) {
          const canvasUser = await canvasFindUserByEmailInCourse(
            env,
            submission.canvas_course_id,
            email
          );
          canvasFullName = canvasUser?.name?.trim() || null;
          canvasDisplayName = canvasUser?.shortName?.trim() || canvasDisplayName;
        }
        let courseTitle: string | null = null;
        let courseCode: string | null = null;
        let sectionName: string | null = null;
        if (submission.canvas_course_id) {
          const courseRow = await env.DB.prepare(
            "SELECT name, code FROM canvas_courses_cache WHERE id=?"
          )
            .bind(submission.canvas_course_id)
            .first<{ name: string | null; code: string | null }>();
          courseTitle = courseRow?.name ?? null;
          courseCode = courseRow?.code ?? null;
        }
        if (submission.canvas_course_id && submission.canvas_section_id) {
          const sectionRow = await env.DB.prepare(
            "SELECT name FROM canvas_sections_cache WHERE id=?"
          )
            .bind(submission.canvas_section_id)
            .first<{ name: string | null }>();
          sectionName = sectionRow?.name ?? null;
        }
        const courseLabel = courseTitle
          ? `${courseTitle}${courseCode ? ` (${courseCode})` : ""}`
          : submission.canvas_course_id
            ? `Course ${submission.canvas_course_id}`
            : null;
        const sectionLabel = sectionName
          ? sectionName
          : submission.canvas_section_id
            ? `Section ${submission.canvas_section_id}`
            : null;
        const baseWeb = env.BASE_URL_WEB ? String(env.BASE_URL_WEB).replace(/\/$/, "") : "";
        const formLink =
          baseWeb && submission.form_slug ? `${baseWeb}/#/f/${submission.form_slug}` : null;
        const message = buildCanvasNameAlertMessage({
          submittedName: submittedName || titleCaseFromEmail(email),
          canvasFullName,
          canvasDisplayName,
          formLink
        });
        const result = await sendGmailMessage(env, {
          to: email,
          subject: message.subject,
          body: message.body
        });
        await logEmailSend(env, {
          to: email,
          subject: message.subject,
          body: message.body,
          status: result.ok ? "sent" : "failed",
          error: result.ok ? null : result.error || "send_failed",
          submissionId,
          formSlug: submission.form_slug ?? null,
          formTitle: submission.form_title ?? null,
          canvasCourseId: submission.canvas_course_id ?? null,
          canvasSectionId: submission.canvas_section_id ?? null,
          triggeredBy: adminPayload?.userId ?? null,
          triggerSource: "manual"
        });
        if (!result.ok) {
          return errorResponse(500, "email_send_failed", requestId, corsHeaders, {
            message: result.error || "send_failed"
          });
        }
        return jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
      }

      if (request.method === "GET" && url.pathname === "/api/admin/emails") {
        let canSoftDelete = await hasEmailLogsSoftDelete(env);
        const page = Math.max(toNumber(url.searchParams.get("page"), 1), 1);
        const pageSize = Math.min(Math.max(toNumber(url.searchParams.get("pageSize"), 50), 1), 200);
        const status = (url.searchParams.get("status") || "").trim();
        const email = (url.searchParams.get("email") || "").trim();
        const userId = (url.searchParams.get("userId") || "").trim();
        const submissionId = (url.searchParams.get("submissionId") || "").trim();
        const formSlug = (url.searchParams.get("formSlug") || "").trim();
        const includeBody = url.searchParams.get("includeBody") === "1";
        const where: string[] = [];
        const params: Array<string | number> = [];
        if (userId) {
          const { results } = await env.DB.prepare(
            "SELECT email FROM user_identities WHERE user_id=? AND email IS NOT NULL"
          )
            .bind(userId)
            .all<{ email: string }>();
          const emails = results.map((row) => row.email?.trim().toLowerCase()).filter(Boolean);
          if (emails.length === 0) {
            return jsonResponse(200, { data: [], page, pageSize, total: 0, requestId }, requestId, corsHeaders);
          }
          const placeholders = emails.map(() => "?").join(",");
          where.push(`lower(l.to_email) IN (${placeholders})`);
          params.push(...emails);
        }
        if (status) {
          where.push("l.status=?");
          params.push(status);
        }
        if (email) {
          where.push("l.to_email LIKE ?");
          params.push(`%${email}%`);
        }
        if (submissionId) {
          where.push("l.submission_id=?");
          params.push(submissionId);
        }
        if (formSlug) {
          where.push("(l.form_slug=? OR f.slug=?)");
          params.push(formSlug, formSlug);
        }
        if (canSoftDelete) {
          where.push("l.deleted_at IS NULL");
        }
        let whereClause = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";
        let total = 0;
        const limit = pageSize;
        const offset = (page - 1) * pageSize;
        const selectFields = includeBody
          ? "l.id,l.to_email,l.subject,l.body,l.status,l.error,l.submission_id,l.canvas_course_id,l.canvas_section_id,l.triggered_by,l.trigger_source,l.created_at,COALESCE(l.form_slug,f.slug) as form_slug,COALESCE(l.form_title,f.title) as form_title"
          : "l.id,l.to_email,l.subject,l.status,l.error,l.submission_id,l.canvas_course_id,l.canvas_section_id,l.triggered_by,l.trigger_source,l.created_at,COALESCE(l.form_slug,f.slug) as form_slug,COALESCE(l.form_title,f.title) as form_title";
        let results: unknown[] = [];
        try {
          const totalRow = await env.DB.prepare(
            `SELECT COUNT(1) as total FROM email_logs l ${whereClause}`
          )
            .bind(...params)
            .first<{ total: number }>();
          total = totalRow?.total ?? 0;
          const response = await env.DB.prepare(
            `SELECT ${selectFields} FROM email_logs l LEFT JOIN forms f ON f.id=l.form_id ${whereClause} ORDER BY l.created_at DESC LIMIT ? OFFSET ?`
          )
            .bind(...params, limit, offset)
            .all();
          results = response.results;
        } catch (error) {
          const message = String((error as Error)?.message || error);
          if (canSoftDelete && message.includes("no such column: l.deleted_at")) {
            EMAIL_LOGS_SOFT_DELETE = false;
            canSoftDelete = false;
            const idx = where.indexOf("l.deleted_at IS NULL");
            if (idx >= 0) {
              where.splice(idx, 1);
            }
            whereClause = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";
            const totalRow = await env.DB.prepare(
              `SELECT COUNT(1) as total FROM email_logs l ${whereClause}`
            )
              .bind(...params)
              .first<{ total: number }>();
            total = totalRow?.total ?? 0;
            const response = await env.DB.prepare(
              `SELECT ${selectFields} FROM email_logs l LEFT JOIN forms f ON f.id=l.form_id ${whereClause} ORDER BY l.created_at DESC LIMIT ? OFFSET ?`
            )
              .bind(...params, limit, offset)
              .all();
            results = response.results;
          } else {
            throw error;
          }
        }
        return jsonResponse(
          200,
          { data: results, page, pageSize, total, requestId },
          requestId,
          corsHeaders
        );
      }

      if (request.method === "GET" && url.pathname === "/api/admin/emails/presets") {
        const sampleFormLink = `${env.BASE_URL_WEB ?? ""}#/f/hus-demo-1`;
        const welcomeMessage = buildCanvasWelcomeMessage({
          formTitle: "HUS Demo 1",
          courseLabel: "Demo Course",
          sectionLabel: "Section 1",
          submittedName: "Nguyễn Văn An",
          submittedEmail: "anhduc.hoang1990@gmail.com",
          studentId: "23001234",
          className: "K63A5",
          dob: "1999-11-11",
          formLink: sampleFormLink
        });
        const informMessage = buildCanvasInformMessage({
          formTitle: "HUS Demo 1",
          courseLabel: "Demo Course",
          sectionLabel: "Section 1",
          submittedName: "Nguyễn Văn An",
          submittedEmail: "anhduc.hoang1990@gmail.com",
          studentId: "23001234",
          className: "K63A5",
          dob: "1999-11-11",
          formLink: sampleFormLink
        });
        const alertMessage = buildCanvasNameAlertMessage({
          submittedName: "Nguyễn Văn An",
          canvasFullName: "Nguyen Van An",
          canvasDisplayName: "Nguyen Van An",
          formLink: sampleFormLink
        });
        const goodbyeMessage = buildAccountGoodbyeMessage();
        const sampleFormTitle = "HUS Demo 1";
        const sampleFormSlug = "hus-demo-1";
        const reminderSubject = {
          vi: `Nhắc nhở: ${sampleFormTitle}`,
          en: `Reminder: ${sampleFormTitle}`
        };
        const reminderBody = {
          vi: `Xin chào,\n\nĐây là email nhắc nhở bạn điền biểu mẫu "${sampleFormTitle}".\n\nVui lòng truy cập liên kết dưới đây để điền biểu mẫu:\n${env.BASE_URL_WEB || ""}/#/f/${sampleFormSlug}\n\n---\n\nĐây là email tự động. Vui lòng không trả lời email này.`,
          en: `Hello,\n\nThis is a reminder to fill out the form "${sampleFormTitle}".\n\nPlease visit the link below to fill out the form:\n${env.BASE_URL_WEB || ""}/#/f/${sampleFormSlug}\n\n---\n\nThis is an automated message. Please do not reply to this email.`
        };
        const data = [
          {
            key: "welcome",
            label: "Welcome message",
            subject: welcomeMessage.subject,
            body: welcomeMessage.body
          },
          {
            key: "update",
            label: "Update message",
            subject: informMessage.subject,
            body: informMessage.body
          },
          {
            key: "alert",
            label: "Name mismatch alert",
            subject: alertMessage.subject,
            body: alertMessage.body
          },
          {
            key: "goodbye",
            label: "Goodbye message",
            subject: goodbyeMessage.subject,
            body: goodbyeMessage.body
          },
          {
            key: "reminder",
            label: "Periodic reminder",
            subject: `${reminderSubject.vi} / ${reminderSubject.en}`,
            body: `${reminderBody.vi}\n\n---\n\n${reminderBody.en}`
          }
        ];
        return jsonResponse(200, { data, requestId }, requestId, corsHeaders);
      }

      const adminEmailDeleteMatch = url.pathname.match(/^\/api\/admin\/emails\/([^/]+)$/);
      if (request.method === "DELETE" && adminEmailDeleteMatch) {
        const emailId = decodeURIComponent(adminEmailDeleteMatch[1] || "").trim();
        if (!emailId) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "id",
            message: "required"
          });
        }
        if (await hasEmailLogsSoftDelete(env)) {
          await env.DB.prepare(
            "UPDATE email_logs SET deleted_at=datetime('now'), deleted_by=?, deleted_reason=? WHERE id=? AND deleted_at IS NULL"
          )
            .bind(adminPayload?.userId ?? null, "admin_deleted", emailId)
            .run();
        } else {
          await env.DB.prepare("DELETE FROM email_logs WHERE id=?")
            .bind(emailId)
            .run();
        }
        return jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
      }

      if (request.method === "POST" && url.pathname === "/api/admin/emails/test") {
        let body: { to?: string; subject?: string; body?: string } | null = null;
        try {
          body = await parseJsonBody(request);
        } catch {
          body = null;
        }
        const to = typeof body?.to === "string" ? body.to.trim() : "";
        const subject =
          typeof body?.subject === "string" && body.subject.trim()
            ? body.subject.trim()
            : "Test email from Form App";
        const bodyText =
          typeof body?.body === "string" && body.body.trim()
            ? body.body.trim()
            : "This is a test email from Form App.";
        if (!to) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "to",
            message: "required"
          });
        }
        const result = await sendGmailMessage(env, { to, subject, body: bodyText });
        if (!result.ok) {
          console.error("email_test_failed", result.error || "send_failed");
        }
        await logEmailSend(env, {
          to,
          subject,
          body: bodyText,
          status: result.ok ? "sent" : "failed",
          error: result.ok ? null : result.error || "send_failed",
          triggeredBy: adminPayload?.userId ?? null,
          triggerSource: "manual"
        });
        if (!result.ok) {
          return errorResponse(500, "email_send_failed", requestId, corsHeaders, {
            message: result.error || "send_failed"
          });
        }
        return jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
      }

      const canvasSectionsMatch = url.pathname.match(/^\/api\/admin\/canvas\/courses\/([^/]+)\/sections$/);
      if (request.method === "GET" && canvasSectionsMatch) {
        const courseId = decodeURIComponent(canvasSectionsMatch[1] || "").trim();
        const q = (url.searchParams.get("q") || "").trim();
        const page = Math.max(toNumber(url.searchParams.get("page"), 1), 1);
        const pageSize = Math.min(Math.max(toNumber(url.searchParams.get("pageSize"), 50), 1), 200);
        const limit = pageSize;
        const offset = (page - 1) * pageSize;
        const like = `%${q}%`;
        const totalRow = await env.DB.prepare(
          "SELECT COUNT(1) as total FROM canvas_sections_cache WHERE course_id=? AND (?='' OR name LIKE ?)"
        )
          .bind(courseId, q, like)
          .first<{ total: number }>();
        const total = totalRow?.total ?? 0;
        const { results } = await env.DB.prepare(
          "SELECT id,course_id,name,updated_at FROM canvas_sections_cache WHERE course_id=? AND (?='' OR name LIKE ?) ORDER BY name LIMIT ? OFFSET ?"
        )
          .bind(courseId, q, like, limit, offset)
          .all();
        return jsonResponse(
          200,
          { data: results, page, pageSize, total, needsSync: total === 0, requestId },
          requestId,
          corsHeaders
        );
      }


      if (request.method === "POST" && url.pathname === "/api/admin/canvas/sync") {
        let body: { mode?: string; courseId?: string } | null = null;
        try {
          body = await parseJsonBody(request);
        } catch (error) {
          return errorResponse(400, "invalid_json", requestId, corsHeaders);
        }
        const mode = (body?.mode || "").toLowerCase();
        const courseId = body?.courseId?.trim();
        if (!env.CANVAS_API_TOKEN) {
          return errorResponse(500, "canvas_not_configured", requestId, corsHeaders);
        }
        let coursesSynced = 0;
        let sectionsSynced = 0;
        const syncMode = await getCanvasCourseSyncMode(env);
        try {
          if (mode === "courses") {
            coursesSynced = await syncCanvasCourses(env, syncMode);
          } else if (mode === "course_sections") {
            if (!courseId) {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: "courseId",
                message: "required"
              });
            }
            sectionsSynced = await syncCanvasSections(env, courseId);
          } else if (mode === "all") {
            coursesSynced = await syncCanvasCourses(env, syncMode);
            const { results } = await env.DB.prepare(
              "SELECT DISTINCT canvas_course_id as course_id FROM forms WHERE canvas_enabled=1 AND canvas_course_id IS NOT NULL AND deleted_at IS NULL"
            ).all<{ course_id: string | null }>();
            const courseIds = results.filter((row): row is { course_id: string } => row.course_id !== null).map((row) => row.course_id);
            for (const id of courseIds) {
              sectionsSynced += await syncCanvasSections(env, id);
            }
          } else {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "mode",
              allowed: ["courses", "course_sections", "all"]
            });
          }
        } catch (error) {
          return errorResponse(500, "canvas_sync_failed", requestId, corsHeaders, {
            message: String((error as Error | undefined)?.message || error)
          });
        }
        return jsonResponse(
          200,
          { ok: true, coursesSynced, sectionsSynced, requestId },
          requestId,
          corsHeaders
        );
      }

      if (request.method === "GET" && url.pathname === "/api/admin/forms") {
        const reminderEnabledSelect = (await hasColumn(env, "forms", "reminder_enabled"))
          ? "f.reminder_enabled"
          : "NULL as reminder_enabled";
        const reminderFrequencySelect = (await hasColumn(env, "forms", "reminder_frequency"))
          ? "f.reminder_frequency"
          : "NULL as reminder_frequency";
        const reminderUntilSelect = (await hasColumn(env, "forms", "reminder_until"))
          ? "f.reminder_until"
          : "NULL as reminder_until";
        const submissionBackupSelect = (await hasColumn(env, "forms", "submission_backup_enabled"))
          ? "f.submission_backup_enabled as submission_backup_enabled"
          : "NULL as submission_backup_enabled";
        const submissionBackupFormatsSelect = (await hasColumn(env, "forms", "submission_backup_formats"))
          ? "f.submission_backup_formats as submission_backup_formats"
          : "NULL as submission_backup_formats";
        const { results } = await env.DB.prepare(
          `SELECT f.id,f.slug,f.title,f.description,f.is_locked,f.is_public,f.auth_policy,f.canvas_enabled,f.canvas_course_id,f.canvas_allowed_section_ids_json,f.canvas_fields_position,f.available_from,f.available_until,f.password_required,f.password_require_access,f.password_require_submit,f.save_all_versions,${reminderEnabledSelect},${reminderFrequencySelect},${reminderUntilSelect},${submissionBackupSelect},${submissionBackupFormatsSelect},f.updated_at,f.created_at,t.key as templateKey,COALESCE(s.submission_count,0) as submission_count FROM forms f LEFT JOIN templates t ON t.id=f.template_id LEFT JOIN (SELECT form_id, COUNT(*) as submission_count FROM submissions WHERE deleted_at IS NULL GROUP BY form_id) s ON s.form_id=f.id WHERE f.deleted_at IS NULL ORDER BY f.created_at DESC`
        ).all<AdminFormRow & { submission_count?: number; updated_at?: string | null; created_at?: string | null }>();

        const data = results.map((row) => ({
          id: row.id,
          slug: row.slug,
          title: row.title,
          description: row.description,
          is_locked: toBoolean(row.is_locked),
          is_public: toBoolean(row.is_public),
          auth_policy: row.auth_policy,
          templateKey: row.templateKey,
          submission_count: Number(row.submission_count ?? 0),
          updated_at: row.updated_at ?? null,
          created_at: row.created_at ?? null,
          canvas_enabled: toBoolean(row.canvas_enabled ?? 0),
          canvas_course_id: row.canvas_course_id ?? null,
          canvas_allowed_section_ids_json: row.canvas_allowed_section_ids_json ?? null,
          canvas_fields_position: row.canvas_fields_position ?? "bottom",
          available_from: row.available_from ?? null,
          available_until: row.available_until ?? null,
          password_required: toBoolean(row.password_required ?? 0),
          password_require_access: toBoolean(row.password_require_access ?? 0),
          password_require_submit: toBoolean(row.password_require_submit ?? 0),
          save_all_versions: toBoolean(row.save_all_versions ?? 0),
          reminder_enabled: toBoolean((row as any).reminder_enabled ?? 0),
          reminder_frequency: (row as any).reminder_frequency ?? null,
          reminder_until: (row as any).reminder_until ?? null,
          submission_backup_enabled: toBoolean((row as any).submission_backup_enabled ?? 0),
          submission_backup_formats: parseSubmissionBackupFormats((row as any).submission_backup_formats)
        }));

        return jsonResponse(200, { data, requestId }, requestId, corsHeaders);
      }

      const formBackupMatch = url.pathname.match(/^\/api\/admin\/forms\/([^/]+)\/backup$/);
      if (request.method === "GET" && formBackupMatch) {
        const slug = decodeURIComponent(formBackupMatch[1]);
        const submissionBackupSelect = (await hasColumn(env, "forms", "submission_backup_enabled"))
          ? "f.submission_backup_enabled as submission_backup_enabled"
          : "NULL as submission_backup_enabled";
        const submissionBackupFormatsSelect = (await hasColumn(env, "forms", "submission_backup_formats"))
          ? "f.submission_backup_formats as submission_backup_formats"
          : "NULL as submission_backup_formats";
        const formRow = await env.DB.prepare(
          `SELECT f.id,f.slug,f.title,f.description,f.is_locked,f.is_public,f.auth_policy,f.canvas_enabled,f.canvas_course_id,f.canvas_allowed_section_ids_json,f.canvas_fields_position,f.available_from,f.available_until,f.password_required,f.password_require_access,f.password_require_submit,f.password_salt,f.password_hash,f.file_rules_json,f.save_all_versions,f.reminder_enabled,f.reminder_frequency,${submissionBackupSelect},${submissionBackupFormatsSelect},t.key as template_key,t.name as template_name,t.schema_json as template_schema_json,t.file_rules_json as template_file_rules_json,fv.schema_json as form_schema_json FROM forms f LEFT JOIN templates t ON t.id=f.template_id LEFT JOIN form_versions fv ON fv.form_id=f.id AND fv.version=1 WHERE f.slug=? AND f.deleted_at IS NULL`
        )
          .bind(slug)
          .first<{
            id: string;
            slug: string;
            title: string;
            description: string | null;
            is_locked: number;
            is_public: number;
            auth_policy: string | null;
            canvas_enabled: number | null;
            canvas_course_id: string | null;
            canvas_allowed_section_ids_json: string | null;
            canvas_fields_position: string | null;
            available_from: string | null;
            available_until: string | null;
            password_required: number | null;
            password_require_access: number | null;
            password_require_submit: number | null;
            password_salt: string | null;
            password_hash: string | null;
            file_rules_json: string | null;
            reminder_enabled: number;
            reminder_frequency: string | null;
            submission_backup_enabled: number | null;
            submission_backup_formats: string | null;
            template_key: string | null;
            template_name: string | null;
            template_schema_json: string | null;
            template_file_rules_json: string | null;
            form_schema_json: string | null;
          }>();
        if (!formRow) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        const parseSchema = (value: string | null) => {
          if (!value) return null;
          try {
            return JSON.parse(value);
          } catch {
            return value;
          }
        };
        const payload = {
          type: "form",
          form: {
            slug: formRow.slug,
            reminder_enabled: toBoolean(formRow.reminder_enabled),
            reminder_frequency: formRow.reminder_frequency,
            submission_backup_enabled: toBoolean(formRow.submission_backup_enabled ?? 0),
            submission_backup_formats: parseSubmissionBackupFormats(formRow.submission_backup_formats),
            title: formRow.title,
            description: formRow.description ?? null,
            is_locked: toBoolean(formRow.is_locked),
            is_public: toBoolean(formRow.is_public),
            auth_policy: formRow.auth_policy ?? "optional",
            templateKey: formRow.template_key ?? null,
            file_rules_json: formRow.file_rules_json ?? null,
            schema_json: parseSchema(formRow.form_schema_json || formRow.template_schema_json),
            canvas_enabled: toBoolean(formRow.canvas_enabled),
            canvas_course_id: formRow.canvas_course_id ?? null,
            canvas_allowed_section_ids_json: formRow.canvas_allowed_section_ids_json ?? null,
            canvas_fields_position: formRow.canvas_fields_position ?? "bottom",
            available_from: formRow.available_from ?? null,
            available_until: formRow.available_until ?? null,
            password_required: toBoolean(formRow.password_required ?? 0),
            password_require_access: toBoolean(formRow.password_require_access ?? 0),
            password_require_submit: toBoolean(formRow.password_require_submit ?? 0),
            password_salt: formRow.password_salt ?? null,
            password_hash: formRow.password_hash ?? null
          }
        };
        const body = JSON.stringify({ data: payload, requestId });
        return new Response(body, {
          status: 200,
          headers: {
            ...corsHeaders,
            "content-type": "application/json; charset=utf-8",
            "content-disposition": `attachment; filename="${formRow.slug}.form.json"`,
            "access-control-expose-headers": "Content-Disposition",
            "x-request-id": requestId
          }
        });
      }

      if (request.method === "GET" && url.pathname === "/api/admin/templates") {
        const { results } = await env.DB.prepare(
          "SELECT id,key,name,created_at,updated_at FROM templates WHERE deleted_at IS NULL ORDER BY created_at DESC"
        ).all();
        const data = results.map((row: any) => ({
          id: row.id,
          key: row.key,
          name: row.name,
          created_at: row.created_at,
          updated_at: row.updated_at ?? null
        }));
        return jsonResponse(200, { data, requestId }, requestId, corsHeaders);
      }

      const templateBackupMatch = url.pathname.match(/^\/api\/admin\/templates\/([^/]+)\/backup$/);
      if (request.method === "GET" && templateBackupMatch) {
        const key = decodeURIComponent(templateBackupMatch[1]);
        const template = await env.DB.prepare(
          "SELECT id,key,name,schema_json,file_rules_json FROM templates WHERE key=? AND deleted_at IS NULL"
        )
          .bind(key)
          .first<{
            id: string;
            key: string;
            name: string;
            schema_json: string;
            file_rules_json: string | null;
          }>();
        if (!template) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        const payload = {
          type: "template",
          template: {
            key: template.key,
            name: template.name,
            schema_json: template.schema_json,
            file_rules_json: template.file_rules_json ?? "{}"
          }
        };
        const body = JSON.stringify({ data: payload, requestId });
        return new Response(body, {
          status: 200,
          headers: {
            ...corsHeaders,
            "content-type": "application/json; charset=utf-8",
            "content-disposition": `attachment; filename="${template.key}.template.json"`,
            "access-control-expose-headers": "Content-Disposition",
            "x-request-id": requestId
          }
        });
      }

      if (request.method === "POST" && url.pathname === "/api/admin/templates") {
        let body: {
          key?: string;
          name?: string;
          schema_json?: string;
        } | null = null;
        try {
          body = await parseJsonBody(request);
        } catch (error) {
          return errorResponse(400, "invalid_json", requestId, corsHeaders);
        }

        if (
          !body ||
          typeof body.key !== "string" ||
          body.key.trim() === "" ||
          typeof body.name !== "string" ||
          body.name.trim() === "" ||
          typeof body.schema_json !== "string" ||
          body.schema_json.trim() === ""
        ) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            missing: ["key", "name", "schema_json"].filter(
              (key) => !body || typeof (body as Record<string, unknown>)[key] !== "string"
            )
          });
        }

        let parsedSchema: unknown = null;
        try {
          parsedSchema = JSON.parse(body.schema_json);
        } catch (error) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "schema_json",
            message: "invalid_json"
          });
        }
        const ruleError = validateFileRulesFromSchema(parsedSchema);
        if (ruleError) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "schema_json",
            message: "invalid_file_rules",
            detail: ruleError
          });
        }

        const fileRulesJson = buildFileRulesJsonFromSchema(body.schema_json);
        const authPayload = await getAuthPayload(request, env);
        const templateId = crypto.randomUUID();
        try {
          await env.DB.prepare(
            "INSERT INTO templates (id, key, name, schema_json, file_rules_json, created_by) VALUES (?, ?, ?, ?, ?, ?)"
          )
            .bind(
              templateId,
              body.key.trim(),
              body.name.trim(),
              JSON.stringify(parsedSchema),
              fileRulesJson ?? "{}",
              authPayload?.userId ?? null
            )
            .run();
        } catch (error) {
          const message = String((error as Error | undefined)?.message || error);
          return errorResponse(409, "conflict", requestId, corsHeaders, {
            message: message.includes("UNIQUE") ? "key_exists" : "template_create_failed"
          });
        }

        return jsonResponse(
          201,
          {
            data: {
              id: templateId,
              key: body.key.trim(),
              name: body.name.trim()
            },
            requestId
          },
          requestId,
          corsHeaders
        );
      }

      if (request.method === "GET") {
        const templateMatch = url.pathname.match(/^\/api\/admin\/templates\/([^/]+)$/);
        if (templateMatch) {
          const key = decodeURIComponent(templateMatch[1]);
          const template = await env.DB.prepare(
            "SELECT id,key,name,schema_json,file_rules_json,created_at FROM templates WHERE key=? AND deleted_at IS NULL"
          )
            .bind(key)
            .first<any>();
          if (!template) {
            return errorResponse(404, "not_found", requestId, corsHeaders);
          }
          return jsonResponse(200, { data: template, requestId }, requestId, corsHeaders);
        }
      }

      if (request.method === "PATCH") {
        const templateMatch = url.pathname.match(/^\/api\/admin\/templates\/([^/]+)$/);
        if (templateMatch) {
          const key = decodeURIComponent(templateMatch[1]);
          let body: {
            newKey?: string;
            name?: string;
            schema_json?: string;
          } | null = null;
          try {
            body = await parseJsonBody(request);
          } catch (error) {
            return errorResponse(400, "invalid_json", requestId, corsHeaders);
          }

          const updates: string[] = [];
          const params: Array<string | number | null> = [];
          let canvasWarning: string | null = null;
          if (body?.newKey !== undefined) {
            if (typeof body.newKey !== "string" || !body.newKey.trim()) {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: "newKey",
                message: "expected_string"
              });
            }
            const nextKey = body.newKey.trim();
            if (nextKey !== key) {
              const existing = await env.DB.prepare(
                "SELECT id FROM templates WHERE key=? AND deleted_at IS NULL"
              )
                .bind(nextKey)
                .first<{ id: string }>();
              if (existing?.id) {
                return errorResponse(409, "conflict", requestId, corsHeaders, {
                  message: "key_exists"
                });
              }
              updates.push("key=?");
              params.push(nextKey);
            }
          }
          if (body?.name && typeof body.name === "string") {
            updates.push("name=?");
            params.push(body.name.trim());
          }
          if (body?.schema_json && typeof body.schema_json === "string") {
            let parsedSchema: unknown = null;
            try {
              parsedSchema = JSON.parse(body.schema_json);
            } catch (error) {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: "schema_json",
                message: "invalid_json"
              });
            }
            const ruleError = validateFileRulesFromSchema(parsedSchema);
            if (ruleError) {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: "schema_json",
                message: "invalid_file_rules",
                detail: ruleError
              });
            }
            updates.push("schema_json=?");
            params.push(JSON.stringify(parsedSchema));
            const fileRulesJson = buildFileRulesJsonFromSchema(body.schema_json);
            updates.push("file_rules_json=?");
            params.push(fileRulesJson ?? "{}");
          }
          if (updates.length === 0) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              message: "no_fields_to_update"
            });
          }

          params.push(key);
          const result = await env.DB.prepare(
            `UPDATE templates SET ${updates.join(", ")}, updated_at=datetime('now') WHERE key=? AND deleted_at IS NULL`
          )
            .bind(...params)
            .run();
          if (result.success !== true) {
            return errorResponse(500, "template_update_failed", requestId, corsHeaders);
          }
          return jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
        }
      }

      if (request.method === "DELETE") {
        const templateMatch = url.pathname.match(/^\/api\/admin\/templates\/([^/]+)$/);
        if (templateMatch) {
          const key = decodeURIComponent(templateMatch[1]);
          const authPayload = await getAuthPayload(request, env);
          await softDeleteTemplate(env, key, authPayload?.userId ?? null, "admin_deleted");
          return jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
        }
      }

      if (request.method === "GET" && url.pathname === "/api/admin/users") {
        const { results } = await env.DB.prepare(
          "SELECT u.id,u.is_admin,u.created_at,(SELECT provider FROM user_identities ui WHERE ui.user_id=u.id ORDER BY ui.created_at DESC LIMIT 1) as provider,(SELECT email FROM user_identities ui WHERE ui.user_id=u.id ORDER BY ui.created_at DESC LIMIT 1) as email,(SELECT provider_login FROM user_identities ui WHERE ui.user_id=u.id ORDER BY ui.created_at DESC LIMIT 1) as provider_login,(SELECT email FROM user_identities ui WHERE ui.user_id=u.id AND ui.provider='google' ORDER BY ui.created_at DESC LIMIT 1) as google_email,(SELECT provider_login FROM user_identities ui WHERE ui.user_id=u.id AND ui.provider='github' ORDER BY ui.created_at DESC LIMIT 1) as github_login,(SELECT s.canvas_enroll_status FROM submissions s WHERE s.user_id=u.id AND s.canvas_course_id IS NOT NULL AND s.deleted_at IS NULL ORDER BY COALESCE(s.updated_at, s.created_at) DESC LIMIT 1) as canvas_status FROM users u WHERE u.deleted_at IS NULL ORDER BY u.created_at DESC"
        ).all();
        const data = results.map((row: any) => ({
          id: row.id,
          is_admin: row.is_admin,
          provider: row.provider ?? null,
          email: row.email ?? null,
          provider_login: row.provider_login ?? null,
          google_email: row.google_email ?? null,
          github_login: row.github_login ?? null,
          canvas_status: row.canvas_status ?? null,
          created_at: row.created_at
        }));
        return jsonResponse(200, { data, requestId }, requestId, corsHeaders);
      }

      if (request.method === "DELETE") {
        const userMatch = url.pathname.match(/^\/api\/admin\/users\/([^/]+)$/);
        if (userMatch) {
          const userId = decodeURIComponent(userMatch[1]);
          const authPayload = await getAuthPayload(request, env);
          const result = await softDeleteUser(env, userId, authPayload?.userId ?? null, "admin_deleted");
          const attempted = result.canvas?.attempted ?? 0;
          const failed = result.canvas?.failed ?? 0;
          const canvasAction = attempted === 0 ? "skipped" : failed > 0 ? "failed" : "deactivated";
          return jsonResponse(
            200,
            { ok: result.ok, canvasAction, canvasAttempts: attempted, canvasFailed: failed, requestId },
            requestId,
            corsHeaders
          );
        }
      }

      const userPromoteMatch = url.pathname.match(/^\/api\/admin\/users\/([^/]+)\/promote$/);
      if (request.method === "POST" && userPromoteMatch) {
        const userId = decodeURIComponent(userPromoteMatch[1]);
        if (!userId) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "userId",
            message: "required"
          });
        }
        const userRow = await env.DB.prepare(
          "SELECT id, is_admin FROM users WHERE id=? AND deleted_at IS NULL"
        )
          .bind(userId)
          .first<{ id: string; is_admin: number | null }>();
        if (!userRow) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        if (toBoolean(userRow.is_admin)) {
          return jsonResponse(200, { ok: true, alreadyAdmin: true, requestId }, requestId, corsHeaders);
        }
        await env.DB.prepare("UPDATE users SET is_admin=1 WHERE id=?")
          .bind(userId)
          .run();
        return jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
      }

      if (request.method === "GET" && url.pathname === "/api/admin/trash") {
        const type = (url.searchParams.get("type") || "all").toLowerCase();
        const page = Math.max(toNumber(url.searchParams.get("page"), 1), 1);
        const pageSize = Math.min(Math.max(toNumber(url.searchParams.get("pageSize"), 50), 1), 200);
        const limit = pageSize;
        const offset = (page - 1) * pageSize;
        const data: Record<string, unknown> = {};
        const totals: Record<string, number> = {};

        if (type === "all" || type === "forms") {
          const total = await env.DB.prepare(
            "SELECT COUNT(1) as total FROM forms WHERE deleted_at IS NOT NULL"
          )
            .first<{ total: number }>();
          totals.forms = total?.total ?? 0;
          const { results } = await env.DB.prepare(
            "SELECT id, slug, title, deleted_at, deleted_by, deleted_reason,(SELECT email FROM user_identities ui WHERE ui.user_id=deleted_by ORDER BY ui.created_at DESC LIMIT 1) as deleted_by_email FROM forms WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC LIMIT ? OFFSET ?"
          )
            .bind(limit, offset)
            .all();
          data.forms = results;
        }

        if (type === "all" || type === "templates") {
          const total = await env.DB.prepare(
            "SELECT COUNT(1) as total FROM templates WHERE deleted_at IS NOT NULL"
          )
            .first<{ total: number }>();
          totals.templates = total?.total ?? 0;
          const { results } = await env.DB.prepare(
            "SELECT id, key, name, deleted_at, deleted_by, deleted_reason, created_by,(SELECT email FROM user_identities ui WHERE ui.user_id=deleted_by ORDER BY ui.created_at DESC LIMIT 1) as deleted_by_email FROM templates WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC LIMIT ? OFFSET ?"
          )
            .bind(limit, offset)
            .all();
          data.templates = results;
        }

        if (type === "all" || type === "users") {
          const total = await env.DB.prepare(
            "SELECT COUNT(1) as total FROM users WHERE deleted_at IS NOT NULL"
          )
            .first<{ total: number }>();
          totals.users = total?.total ?? 0;
          const { results } = await env.DB.prepare(
            "SELECT u.id,u.is_admin,u.deleted_at,u.deleted_by,u.deleted_reason,(SELECT email FROM user_identities ui WHERE ui.user_id=u.id ORDER BY ui.created_at DESC LIMIT 1) as email,(SELECT provider_login FROM user_identities ui WHERE ui.user_id=u.id ORDER BY ui.created_at DESC LIMIT 1) as provider_login,(SELECT email FROM user_identities ui WHERE ui.user_id=u.deleted_by ORDER BY ui.created_at DESC LIMIT 1) as deleted_by_email FROM users u WHERE u.deleted_at IS NOT NULL ORDER BY u.deleted_at DESC LIMIT ? OFFSET ?"
          )
            .bind(limit, offset)
            .all();
          data.users = results;
        }

        if (type === "all" || type === "submissions") {
          const total = await env.DB.prepare(
            "SELECT COUNT(1) as total FROM submissions WHERE deleted_at IS NOT NULL"
          )
            .first<{ total: number }>();
          totals.submissions = total?.total ?? 0;
          const { results } = await env.DB.prepare(
            "SELECT s.id,s.form_id,f.slug as form_slug,f.title as form_title,s.deleted_at,s.deleted_by,s.deleted_reason,(SELECT email FROM user_identities ui WHERE ui.user_id=s.deleted_by ORDER BY ui.created_at DESC LIMIT 1) as deleted_by_email FROM submissions s LEFT JOIN forms f ON f.id=s.form_id WHERE s.deleted_at IS NOT NULL ORDER BY s.deleted_at DESC LIMIT ? OFFSET ?"
          )
            .bind(limit, offset)
            .all();
          data.submissions = results;
        }

        if (type === "all" || type === "files") {
          const total = await env.DB.prepare(
            "SELECT COUNT(1) as total FROM submission_file_items WHERE deleted_at IS NOT NULL"
          )
            .first<{ total: number }>();
          totals.files = total?.total ?? 0;
          const { results } = await env.DB.prepare(
            "SELECT sfi.id, sfi.form_slug, f.title as form_title, sfi.submission_id, sfi.field_id, sfi.original_name, sfi.size_bytes, sfi.deleted_at, sfi.deleted_by, sfi.deleted_reason,(SELECT email FROM user_identities ui WHERE ui.user_id=sfi.deleted_by ORDER BY ui.created_at DESC LIMIT 1) as deleted_by_email FROM submission_file_items sfi LEFT JOIN forms f ON f.slug=sfi.form_slug WHERE sfi.deleted_at IS NOT NULL ORDER BY sfi.deleted_at DESC LIMIT ? OFFSET ?"
          )
            .bind(limit, offset)
            .all();
          data.files = results;
        }

        if (type === "all" || type === "emails") {
          if (await hasEmailLogsSoftDelete(env)) {
            const total = await env.DB.prepare(
              "SELECT COUNT(1) as total FROM email_logs WHERE deleted_at IS NOT NULL"
            )
              .first<{ total: number }>();
            totals.emails = total?.total ?? 0;
            const { results } = await env.DB.prepare(
              "SELECT l.id,l.to_email,l.subject,l.status,l.error,l.submission_id,COALESCE(l.form_slug,f.slug) as form_slug,COALESCE(l.form_title,f.title) as form_title,l.deleted_at,l.deleted_by,l.deleted_reason,(SELECT email FROM user_identities ui WHERE ui.user_id=l.deleted_by ORDER BY ui.created_at DESC LIMIT 1) as deleted_by_email FROM email_logs l LEFT JOIN forms f ON f.id=l.form_id WHERE l.deleted_at IS NOT NULL ORDER BY l.deleted_at DESC LIMIT ? OFFSET ?"
            )
              .bind(limit, offset)
              .all();
            data.emails = results;
          } else {
            totals.emails = 0;
            data.emails = [];
          }
        }

        return jsonResponse(200, { data, totals, page, pageSize, requestId }, requestId, corsHeaders);
      }

      if (request.method === "POST" && url.pathname === "/api/admin/trash/restore") {
        let body: { type?: string; id?: string } | null = null;
        try {
          body = await parseJsonBody(request);
        } catch (error) {
          return errorResponse(400, "invalid_json", requestId, corsHeaders);
        }
        const type = body?.type?.toLowerCase();
        const id = body?.id?.trim();
        if (!type || !id) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "type and id are required"
          });
        }
        let ok = false;
        let canvasWarning: string | null = null;
        let canvasAction: string | null = null;
        if (type === "form") {
          ok = await restoreForm(env, id);
        } else if (type === "template") {
          ok = await restoreTemplate(env, id);
        } else if (type === "user") {
          ok = await restoreUser(env, id);
        } else if (type === "submission") {
          const result = await restoreSubmission(env, id);
          ok = result.ok;
          canvasWarning = result.canvasError || null;
          canvasAction = result.canvasStatus || null;
        } else if (type === "file") {
          ok = await restoreFileItem(env, id);
        } else if (type === "email") {
          if (!(await hasEmailLogsSoftDelete(env))) {
            return errorResponse(400, "not_supported", requestId, corsHeaders, {
              message: "email_soft_delete_unavailable"
            });
          }
          await env.DB.prepare("UPDATE email_logs SET deleted_at=NULL, deleted_by=NULL, deleted_reason=NULL WHERE id=?")
            .bind(id)
            .run();
          ok = true;
        } else {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "unsupported_type"
          });
        }
        return jsonResponse(
          200,
          { ok, canvasWarning, canvasAction, requestId },
          requestId,
          corsHeaders
        );
      }

      if (request.method === "POST" && url.pathname === "/api/admin/templates/restore") {
        let body: { type?: string; template?: any; restoreTrash?: boolean } | null = null;
        try {
          body = await parseJsonBody(request);
        } catch (error) {
          return errorResponse(400, "invalid_json", requestId, corsHeaders);
        }
        if (!body || body.type !== "template" || !body.template) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "invalid_backup"
          });
        }
        const tpl = body.template;
        if (!tpl.key || !tpl.name || tpl.schema_json === undefined) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "missing_template_fields"
          });
        }
        let parsedSchema: unknown = null;
        try {
          parsedSchema =
            typeof tpl.schema_json === "string" ? JSON.parse(tpl.schema_json) : tpl.schema_json;
        } catch (error) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "schema_json",
            message: "invalid_json"
          });
        }
        const ruleError = validateFileRulesFromSchema(parsedSchema);
        if (ruleError) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "schema_json",
            message: "invalid_file_rules",
            detail: ruleError
          });
        }
        const fileRulesJson = buildFileRulesJsonFromSchema(JSON.stringify(parsedSchema));
        const existing = await env.DB.prepare(
          "SELECT id, deleted_at FROM templates WHERE key=?"
        )
          .bind(tpl.key)
          .first<{ id: string; deleted_at: string | null }>();
        if (existing?.id && existing.deleted_at !== null && body?.restoreTrash !== true) {
          return errorResponse(409, "conflict", requestId, corsHeaders, {
            message: "slug_in_trash"
          });
        }
        if (existing?.id) {
          await env.DB.prepare(
            "UPDATE templates SET name=?, schema_json=?, file_rules_json=?, deleted_at=NULL, deleted_by=NULL, deleted_reason=NULL WHERE id=?"
          )
            .bind(tpl.name, JSON.stringify(parsedSchema), fileRulesJson ?? "{}", existing.id)
            .run();
          return jsonResponse(
            200,
            { ok: true, updated: true, restored: existing.deleted_at !== null, requestId },
            requestId,
            corsHeaders
          );
        }
        const templateId = crypto.randomUUID();
        await env.DB.prepare(
          "INSERT INTO templates (id, key, name, schema_json, file_rules_json) VALUES (?, ?, ?, ?, ?)"
        )
          .bind(templateId, tpl.key, tpl.name, JSON.stringify(parsedSchema), fileRulesJson ?? "{}")
          .run();
        return jsonResponse(201, { ok: true, created: true, requestId }, requestId, corsHeaders);
      }

      if (request.method === "POST" && url.pathname === "/api/admin/trash/purge") {
        let body: { type?: string; id?: string } | null = null;
        try {
          body = await parseJsonBody(request);
        } catch (error) {
          return errorResponse(400, "invalid_json", requestId, corsHeaders);
        }
        const type = body?.type?.toLowerCase();
        const id = body?.id?.trim();
        if (!type || !id) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "type and id are required"
          });
        }
        let ok = false;
        let canvasAction: string | null = null;
        if (type === "form") {
          ok = await hardDeleteForm(env, id);
        } else if (type === "template") {
          ok = await hardDeleteTemplate(env, id);
        } else if (type === "user") {
          ok = await hardDeleteUser(env, id);
          if (ok) {
            const enabled = await isCanvasDeleteSyncEnabled(env);
            canvasAction = enabled ? "unenrolled" : "skipped";
          }
        } else if (type === "submission") {
          ok = await hardDeleteSubmission(env, id);
          if (ok) {
            const enabled = await isCanvasDeleteSyncEnabled(env);
            canvasAction = enabled ? "unenrolled" : "skipped";
          }
        } else if (type === "file") {
          ok = await hardDeleteFileItem(env, id);
        } else if (type === "email") {
          await env.DB.prepare("DELETE FROM email_logs WHERE id=?")
            .bind(id)
            .run();
          ok = true;
        } else {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "unsupported_type"
          });
        }
        return jsonResponse(200, { ok, canvasAction, requestId }, requestId, corsHeaders);
      }

      if (request.method === "POST") {
        const purgeSubmissionMatch = url.pathname.match(/^\/api\/admin\/submissions\/([^/]+)\/purge$/);
        if (purgeSubmissionMatch) {
          const submissionId = decodeURIComponent(purgeSubmissionMatch[1]);
          const ok = await hardDeleteSubmission(env, submissionId);
          return jsonResponse(200, { ok, requestId }, requestId, corsHeaders);
        }
      }

      if (request.method === "POST" && url.pathname === "/api/admin/trash/empty") {
        let body: { type?: string } | null = null;
        try {
          body = await parseJsonBody(request);
        } catch (error) {
          return errorResponse(400, "invalid_json", requestId, corsHeaders);
        }
        const type = (body?.type || "all").toLowerCase();
        const canvasDeleteSyncEnabled = await isCanvasDeleteSyncEnabled(env);
        const canvasSummary = {
          users: { unenrolled: 0, skipped: 0 },
          submissions: { unenrolled: 0, skipped: 0 }
        };
        if (type === "all" || type === "forms") {
          const { results } = await env.DB.prepare("SELECT slug FROM forms WHERE deleted_at IS NOT NULL")
            .all<{ slug: string }>();
          for (const row of results) {
            if (row?.slug) {
              await hardDeleteForm(env, row.slug);
            }
          }
        }
        if (type === "all" || type === "templates") {
          const { results } = await env.DB.prepare("SELECT key FROM templates WHERE deleted_at IS NOT NULL")
            .all<{ key: string }>();
          for (const row of results) {
            if (row?.key) {
              await hardDeleteTemplate(env, row.key);
            }
          }
        }
        if (type === "all" || type === "users") {
          const { results } = await env.DB.prepare("SELECT id FROM users WHERE deleted_at IS NOT NULL")
            .all<{ id: string }>();
          for (const row of results) {
            if (row?.id) {
              const ok = await hardDeleteUser(env, row.id);
              if (ok) {
                if (canvasDeleteSyncEnabled) {
                  canvasSummary.users.unenrolled += 1;
                } else {
                  canvasSummary.users.skipped += 1;
                }
              }
            }
          }
        }
        if (type === "all" || type === "submissions") {
          const { results } = await env.DB.prepare(
            "SELECT id FROM submissions WHERE deleted_at IS NOT NULL"
          )
            .all<{ id: string }>();
          for (const row of results) {
            if (row?.id) {
              const ok = await hardDeleteSubmission(env, row.id);
              if (ok) {
                if (canvasDeleteSyncEnabled) {
                  canvasSummary.submissions.unenrolled += 1;
                } else {
                  canvasSummary.submissions.skipped += 1;
                }
              }
            }
          }
        }
        if (type === "all" || type === "files") {
          const { results } = await env.DB.prepare("SELECT id FROM submission_file_items WHERE deleted_at IS NOT NULL")
            .all<{ id: string }>();
          for (const row of results) {
            if (row?.id) {
              await hardDeleteFileItem(env, row.id);
            }
          }
        }
        if (type === "all" || type === "emails") {
          if (await hasEmailLogsSoftDelete(env)) {
            const { results } = await env.DB.prepare("SELECT id FROM email_logs WHERE deleted_at IS NOT NULL")
              .all<{ id: string }>();
            for (const row of results) {
              if (row?.id) {
                await env.DB.prepare("DELETE FROM email_logs WHERE id=?")
                  .bind(row.id)
                  .run();
              }
            }
          }
        }
        return jsonResponse(200, { ok: true, canvasSummary, requestId }, requestId, corsHeaders);
      }
      if (request.method === "POST" && url.pathname === "/api/admin/forms/restore") {
        let body: { type?: string; form?: any; template?: any; restoreTrash?: boolean; reminderEnabled?: boolean; reminderFrequency?: string; reminderUntil?: string | null } | null = null;
        try {
          body = await parseJsonBody(request);
        } catch (error) {
          return errorResponse(400, "invalid_json", requestId, corsHeaders);
        }
        if (!body || body.type !== "form" || !body.form) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "invalid_backup"
          });
        }
        const form = body.form;
        if (!form.slug || !form.title || !form.templateKey) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "missing_form_fields"
          });
        }
        let templateId: string | null = null;
        let templateSchemaJson: string | null = null;
        let formSchemaJson: string | null = null;
        let parsedFormSchema: unknown = null;
        if (form.schema_json !== undefined && form.schema_json !== null) {
          try {
            parsedFormSchema =
              typeof form.schema_json === "string" ? JSON.parse(form.schema_json) : form.schema_json;
            formSchemaJson = JSON.stringify(parsedFormSchema);
          } catch (error) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "schema_json",
              message: "invalid_json"
            });
          }
          const ruleError = validateFileRulesFromSchema(parsedFormSchema);
          if (ruleError) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "schema_json",
              message: "invalid_file_rules",
              detail: ruleError
            });
          }
        }
        if (body.template?.key) {
          const tpl = body.template;
          let parsedSchema: unknown = null;
          try {
            parsedSchema =
              typeof tpl.schema_json === "string" ? JSON.parse(tpl.schema_json) : tpl.schema_json;
          } catch (error) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "schema_json",
              message: "invalid_json"
            });
          }
          const ruleError = validateFileRulesFromSchema(parsedSchema);
          if (ruleError) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "schema_json",
              message: "invalid_file_rules",
              detail: ruleError
            });
          }
          const fileRulesJson = buildFileRulesJsonFromSchema(JSON.stringify(parsedSchema));
          const existingTpl = await env.DB.prepare(
            "SELECT id FROM templates WHERE key=? AND deleted_at IS NULL"
          )
            .bind(tpl.key)
            .first<{ id: string }>();
          if (existingTpl?.id) {
            templateId = existingTpl.id;
            await env.DB.prepare(
              "UPDATE templates SET name=?, schema_json=?, file_rules_json=? WHERE id=?"
            )
              .bind(
                tpl.name || tpl.key,
                JSON.stringify(parsedSchema),
                fileRulesJson ?? "{}",
                templateId
              )
              .run();
          } else {
            templateId = crypto.randomUUID();
            await env.DB.prepare(
              "INSERT INTO templates (id, key, name, schema_json, file_rules_json) VALUES (?, ?, ?, ?, ?)"
            )
              .bind(
                templateId,
                tpl.key,
                tpl.name || tpl.key,
                JSON.stringify(parsedSchema),
                fileRulesJson ?? "{}"
              )
              .run();
          }
        } else {
          const existingTpl = await env.DB.prepare(
            "SELECT id, schema_json FROM templates WHERE key=? AND deleted_at IS NULL"
          )
            .bind(form.templateKey)
            .first<{ id: string; schema_json: string }>();
          if (existingTpl?.id) {
            templateId = existingTpl.id;
            templateSchemaJson = existingTpl.schema_json;
          } else if (formSchemaJson) {
            templateId = crypto.randomUUID();
            await env.DB.prepare(
              "INSERT INTO templates (id, key, name, schema_json, file_rules_json) VALUES (?, ?, ?, ?, ?)"
            )
              .bind(
                templateId,
                form.templateKey,
                form.templateName || form.templateKey,
                formSchemaJson,
                buildFileRulesJsonFromSchema(formSchemaJson) ?? "{}"
              )
              .run();
            templateSchemaJson = formSchemaJson;
          } else {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "templateKey",
              message: "template_not_found"
            });
          }
        }

        const existingForm = await env.DB.prepare(
          "SELECT id, deleted_at FROM forms WHERE slug=?"
        )
          .bind(form.slug)
          .first<{ id: string; deleted_at: string | null }>();

        const authPolicy = form.auth_policy ?? "optional";
        if (!["optional", "google", "github", "either", "required"].includes(authPolicy)) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "auth_policy",
            allowed: ["optional", "google", "github", "either", "required"]
          });
        }

        const isPublic = Boolean(form.is_public);
        const isLocked = Boolean(form.is_locked);
        const availableFrom = normalizeDateTimeInput(form.available_from ?? null);
        const availableUntil = normalizeDateTimeInput(form.available_until ?? null);
        if (availableFrom && availableUntil) {
          const start = parseIsoTime(availableFrom);
          const end = parseIsoTime(availableUntil);
          if (start && end && start >= end) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "availableUntil",
              message: "must_be_after_start"
            });
          }
        }
        const passwordRequired = Boolean(form.password_required);
        let passwordRequireAccess = Boolean(form.password_require_access);
        let passwordRequireSubmit = Boolean(form.password_require_submit);
        if (!passwordRequireAccess && !passwordRequireSubmit && passwordRequired) {
          passwordRequireSubmit = true;
        }
        const passwordSalt =
          typeof form.password_salt === "string" && form.password_salt.trim()
            ? form.password_salt.trim()
            : null;
        const passwordHash =
          typeof form.password_hash === "string" && form.password_hash.trim()
            ? form.password_hash.trim()
            : null;
        if (passwordRequired && (!passwordSalt || !passwordHash)) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "password",
            message: "missing_password_hash"
          });
        }
        const canvasEnabled = Boolean(form.canvas_enabled);
        const canvasAllowed =
          Array.isArray(form.canvas_allowed_section_ids_json)
            ? JSON.stringify(form.canvas_allowed_section_ids_json)
            : typeof form.canvas_allowed_section_ids_json === "string"
              ? form.canvas_allowed_section_ids_json
              : null;
        const fileRulesJson = formSchemaJson
          ? buildFileRulesJsonFromSchema(formSchemaJson)
          : typeof form.file_rules_json === "string"
            ? form.file_rules_json
            : form.file_rules_json
              ? JSON.stringify(form.file_rules_json)
              : null;
        const submissionBackupEnabled = Boolean(form.submission_backup_enabled);
        const submissionBackupFormats = parseSubmissionBackupFormats(form.submission_backup_formats);
        const formVersionSchema = formSchemaJson || templateSchemaJson;

        if (existingForm?.id && existingForm.deleted_at !== null && body?.restoreTrash !== true) {
          return errorResponse(409, "conflict", requestId, corsHeaders, {
            message: "slug_in_trash"
          });
        }
        if (existingForm?.id) {
          await env.DB.prepare(
            "UPDATE forms SET title=?, description=?, template_id=?, is_public=?, is_locked=?, auth_policy=?, file_rules_json=?, canvas_enabled=?, canvas_course_id=?, canvas_allowed_section_ids_json=?, canvas_fields_position=?, available_from=?, available_until=?, password_required=?, password_require_access=?, password_require_submit=?, password_salt=?, password_hash=?, submission_backup_enabled=?, submission_backup_formats=?, deleted_at=NULL, deleted_by=NULL, deleted_reason=NULL WHERE id=?"
          )
            .bind(
              form.title,
              form.description ?? null,
              templateId,
              isPublic ? 1 : 0,
              isLocked ? 1 : 0,
              authPolicy,
              fileRulesJson,
              canvasEnabled ? 1 : 0,
              form.canvas_course_id ?? null,
              canvasAllowed ?? null,
              form.canvas_fields_position ?? "bottom",
              availableFrom,
              availableUntil,
              passwordRequired ? 1 : 0,
              passwordRequireAccess ? 1 : 0,
              passwordRequireSubmit ? 1 : 0,
              passwordRequired ? passwordSalt : null,
              passwordRequired ? passwordHash : null,
              submissionBackupEnabled ? 1 : 0,
              serializeSubmissionBackupFormats(submissionBackupFormats),
              existingForm.id
            )
            .run();
          if (formVersionSchema) {
            const existingVersion = await env.DB.prepare(
              "SELECT id FROM form_versions WHERE form_id=? AND version=1"
            )
              .bind(existingForm.id)
              .first<{ id: string }>();
            if (existingVersion?.id) {
              await env.DB.prepare("UPDATE form_versions SET schema_json=? WHERE id=?")
                .bind(formVersionSchema, existingVersion.id)
                .run();
            } else {
              await env.DB.prepare(
                "INSERT INTO form_versions (id, form_id, version, schema_json) VALUES (?, ?, 1, ?)"
              )
                .bind(crypto.randomUUID(), existingForm.id, formVersionSchema)
                .run();
            }
          }
          if (await hasColumn(env, "forms", "submission_backup_enabled")) {
            await ensureSubmissionBackupTask(env, form.slug, form.title, submissionBackupEnabled);
          }
          return jsonResponse(
            200,
            { ok: true, updated: true, restored: existingForm.deleted_at !== null, requestId },
            requestId,
            corsHeaders
          );
        }

        const formId = crypto.randomUUID();
        await env.DB.prepare(
          "INSERT INTO forms (id, slug, title, description, template_id, is_public, is_locked, auth_policy, file_rules_json, canvas_enabled, canvas_course_id, canvas_allowed_section_ids_json, canvas_fields_position, available_from, available_until, password_required, password_require_access, password_require_submit, password_salt, password_hash, reminder_enabled, reminder_frequency, reminder_until, submission_backup_enabled, submission_backup_formats) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
          .bind(
            formId,
            form.slug,
            form.title,
            form.description ?? null,
            templateId,
            isPublic ? 1 : 0,
            isLocked ? 1 : 0,
            authPolicy,
            fileRulesJson,
            canvasEnabled ? 1 : 0,
            form.canvas_course_id ?? null,
            canvasAllowed ?? null,
            form.canvas_fields_position ?? "bottom",
            availableFrom,
            availableUntil,
            passwordRequired ? 1 : 0,
            passwordRequireAccess ? 1 : 0,
            passwordRequireSubmit ? 1 : 0,
            passwordRequired ? passwordSalt : null,
            passwordRequired ? passwordHash : null,
            body.reminderEnabled ? 1 : 0,
            body.reminderFrequency || "weekly",
            body.reminderUntil || null,
            submissionBackupEnabled ? 1 : 0,
            serializeSubmissionBackupFormats(submissionBackupFormats)
          )
          .run();

        if (formVersionSchema) {
          await env.DB.prepare(
            "INSERT INTO form_versions (id, form_id, version, schema_json) VALUES (?, ?, 1, ?)"
          )
            .bind(crypto.randomUUID(), formId, formVersionSchema)
            .run();
        }
        if (await hasColumn(env, "forms", "submission_backup_enabled")) {
          await ensureSubmissionBackupTask(env, form.slug, form.title, submissionBackupEnabled);
        }

        return jsonResponse(201, { ok: true, created: true, requestId }, requestId, corsHeaders);
      }
      if (request.method === "POST" && url.pathname === "/api/admin/templates/from-form") {
        let body: { type?: string; form?: any; restoreTrash?: boolean } | null = null;
        try {
          body = await parseJsonBody(request);
        } catch (error) {
          return errorResponse(400, "invalid_json", requestId, corsHeaders);
        }
        if (!body || body.type !== "form" || !body.form) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "invalid_backup"
          });
        }
        const form = body.form;
        const templateKey =
          typeof form.templateKey === "string" && form.templateKey.trim()
            ? form.templateKey.trim()
            : typeof form.slug === "string" && form.slug.trim()
              ? form.slug.trim()
              : "";
        if (!templateKey || form.schema_json === undefined || form.schema_json === null) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "missing_form_schema"
          });
        }
        let parsedSchema: unknown = null;
        try {
          parsedSchema =
            typeof form.schema_json === "string" ? JSON.parse(form.schema_json) : form.schema_json;
        } catch (error) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "schema_json",
            message: "invalid_json"
          });
        }
        const ruleError = validateFileRulesFromSchema(parsedSchema);
        if (ruleError) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "schema_json",
            message: "invalid_file_rules",
            detail: ruleError
          });
        }
        const fileRulesJson = buildFileRulesJsonFromSchema(JSON.stringify(parsedSchema));
        const existing = await env.DB.prepare(
          "SELECT id, deleted_at FROM templates WHERE key=?"
        )
          .bind(templateKey)
          .first<{ id: string; deleted_at: string | null }>();
        if (existing?.id && existing.deleted_at !== null && body?.restoreTrash !== true) {
          return errorResponse(409, "conflict", requestId, corsHeaders, {
            message: "slug_in_trash"
          });
        }
        if (existing?.id) {
          await env.DB.prepare(
            "UPDATE templates SET name=?, schema_json=?, file_rules_json=?, deleted_at=NULL, deleted_by=NULL, deleted_reason=NULL WHERE id=?"
          )
            .bind(
              form.templateName || form.title || templateKey,
              JSON.stringify(parsedSchema),
              fileRulesJson ?? "{}",
              existing.id
            )
            .run();
          return jsonResponse(
            200,
            { ok: true, updated: true, restored: existing.deleted_at !== null, requestId },
            requestId,
            corsHeaders
          );
        }
        const templateId = crypto.randomUUID();
        await env.DB.prepare(
          "INSERT INTO templates (id, key, name, schema_json, file_rules_json) VALUES (?, ?, ?, ?, ?)"
        )
          .bind(
            templateId,
            templateKey,
            form.templateName || form.title || templateKey,
            JSON.stringify(parsedSchema),
            fileRulesJson ?? "{}"
          )
          .run();
        return jsonResponse(201, { ok: true, created: true, requestId }, requestId, corsHeaders);
      }

      if (request.method === "POST" && url.pathname === "/api/admin/forms") {
        let body: {
          slug?: string;
          title?: string;
          templateKey?: string;
          schema_json?: string | null;
          description?: string | null;
          is_public?: boolean;
          auth_policy?: string;
          file_rules?: unknown;
          canvasEnabled?: boolean;
          canvasCourseId?: string | null;
          canvasAllowedSectionIds?: string[] | null;
          canvasFieldsPosition?: string | null;
          availableFrom?: string | null;
          availableUntil?: string | null;
          passwordRequired?: boolean;
          passwordRequireAccess?: boolean;
          passwordRequireSubmit?: boolean;
          formPassword?: string | null;
          reminderEnabled?: boolean;
          reminderFrequency?: string;
          reminderUntil?: string | null;
          saveAllVersions?: boolean | number;
          submissionBackupEnabled?: boolean;
          submissionBackupFormats?: string[];
        } | null = null;
        try {
          body = await parseJsonBody(request);
        } catch (error) {
          return errorResponse(400, "invalid_json", requestId, corsHeaders);
        }

        if (
          !body ||
          typeof body.slug !== "string" ||
          body.slug.trim() === "" ||
          typeof body.title !== "string" ||
          body.title.trim() === ""
        ) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            missing: ["slug", "title"].filter(
              (key) => !body || typeof (body as Record<string, unknown>)[key] !== "string"
            )
          });
        }
        const hasTemplateKey =
          typeof body.templateKey === "string" && body.templateKey.trim().length > 0;
        const hasSchemaJson =
          typeof body.schema_json === "string" && body.schema_json.trim().length > 0;
        if (!hasTemplateKey && !hasSchemaJson) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            missing: ["templateKey", "schema_json"]
          });
        }

        if (body?.saveAllVersions !== undefined) {
          const val = body.saveAllVersions;
          const isBool = typeof val === "boolean";
          const isNum = typeof val === "number" && (val === 0 || val === 1);
          if (!isBool && !isNum) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "saveAllVersions",
              message: "expected_boolean_or_0_1"
            });
          }
        }

        const authPolicy = body.auth_policy ?? "optional";
        if (!["optional", "google", "github", "either", "required"].includes(authPolicy)) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "auth_policy",
            allowed: ["optional", "google", "github", "either", "required"]
          });
        }

        if (body.is_public !== undefined && typeof body.is_public !== "boolean") {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "is_public",
            message: "expected_boolean"
          });
        }

        if (body.passwordRequired !== undefined && typeof body.passwordRequired !== "boolean") {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "passwordRequired",
            message: "expected_boolean"
          });
        }

        const canvasEnabled = Boolean(body.canvasEnabled);
        let canvasWarning: string | null = null;
        const canvasCourseId =
          typeof body.canvasCourseId === "string" && body.canvasCourseId.trim()
            ? body.canvasCourseId.trim()
            : null;
        const canvasAllowedSectionIds = Array.isArray(body.canvasAllowedSectionIds)
          ? body.canvasAllowedSectionIds
            .filter((id): id is string => typeof id === "string")
            .map((id) => id.trim())
            .filter((id) => id.length > 0)
          : null;
        if (body.canvasAllowedSectionIds !== undefined && !Array.isArray(body.canvasAllowedSectionIds)) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "canvasAllowedSectionIds",
            message: "expected_array"
          });
        }
        if (canvasEnabled && !canvasCourseId) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "canvasCourseId",
            message: "required"
          });
        }
        if (canvasEnabled && canvasCourseId && canvasAllowedSectionIds && canvasAllowedSectionIds.length > 0) {
          const { results } = await env.DB.prepare(
            "SELECT id FROM canvas_sections_cache WHERE course_id=?"
          )
            .bind(canvasCourseId)
            .all<{ id: string }>();
          if (results.length > 0) {
            const allowedSet = new Set(results.map((row) => String(row.id)));
            const invalid = canvasAllowedSectionIds.find((id) => !allowedSet.has(id));
            if (invalid) {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: "canvasAllowedSectionIds",
                message: "section_not_in_course",
                detail: invalid
              });
            }
          } else {
            canvasWarning = "canvas_sections_not_cached";
          }
        }
        const canvasFieldsPosition =
          typeof body.canvasFieldsPosition === "string" && body.canvasFieldsPosition.trim()
            ? body.canvasFieldsPosition.trim()
            : "bottom";
        if (!["top", "after_identity", "bottom"].includes(canvasFieldsPosition)) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "canvasFieldsPosition",
            message: "invalid_value"
          });
        }

        let template: TemplateRow | null = null;
        let schemaJsonSource = "";
        if (hasTemplateKey) {
          template = await env.DB.prepare(
            "SELECT id, key, schema_json FROM templates WHERE key=? AND deleted_at IS NULL"
          )
            .bind(body.templateKey)
            .first<TemplateRow>();

          if (!template) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "templateKey",
              message: "template_not_found"
            });
          }

          let parsedTemplateSchema: unknown = null;
          try {
            parsedTemplateSchema = JSON.parse(template.schema_json);
          } catch (error) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "templateKey",
              message: "invalid_template_schema"
            });
          }
          const templateRuleError = validateFileRulesFromSchema(parsedTemplateSchema);
          if (templateRuleError) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "templateKey",
              message: "invalid_file_rules",
              detail: templateRuleError
            });
          }
          schemaJsonSource = template.schema_json;
        } else {
          let parsedSchema: unknown = null;
          try {
            parsedSchema = JSON.parse(body.schema_json as string);
          } catch (error) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "schema_json",
              message: "invalid_json"
            });
          }
          const schemaRuleError = validateFileRulesFromSchema(parsedSchema);
          if (schemaRuleError) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "schema_json",
              message: "invalid_file_rules",
              detail: schemaRuleError
            });
          }
          schemaJsonSource = JSON.stringify(parsedSchema);
        }

        const needsDrive = hasFileFields(schemaJsonSource);
        if (needsDrive && (!env.DRIVE_PARENT_FOLDER_ID || !getDriveCredentials(env))) {
          return errorResponse(500, "drive_not_configured", requestId, corsHeaders);
        }

        let driveFolderId: string | null = null;
        if (env.DRIVE_PARENT_FOLDER_ID) {
          const ensure = await driveEnsureFolder(env, env.DRIVE_PARENT_FOLDER_ID, body.slug.trim());
          driveFolderId = ensure.id;
        }

        const authPayload = await getAuthPayload(request, env);
        const formId = crypto.randomUUID();
        const versionId = crypto.randomUUID();
        const isPublic = body.is_public === undefined ? 1 : body.is_public ? 1 : 0;

        if (body.reminderEnabled !== undefined && typeof body.reminderEnabled !== "boolean") {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "reminderEnabled",
            message: "expected_boolean"
          });
        }
        if (body.submissionBackupEnabled !== undefined && typeof body.submissionBackupEnabled !== "boolean") {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "submissionBackupEnabled",
            message: "expected_boolean"
          });
        }
        if (body.submissionBackupFormats !== undefined && !Array.isArray(body.submissionBackupFormats)) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "submissionBackupFormats",
            message: "expected_array"
          });
        }
        const submissionBackupFormats = parseSubmissionBackupFormats(body.submissionBackupFormats ?? ["json"]);
        if (body.submissionBackupFormats !== undefined && submissionBackupFormats.length === 0) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "submissionBackupFormats",
            message: "unsupported"
          });
        }

        if (body.reminderFrequency !== undefined && body.reminderFrequency !== null) {
          if (!["daily", "weekly", "monthly"].includes(body.reminderFrequency) && !/^\d+:(days|weeks|months)$/.test(body.reminderFrequency)) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "reminderFrequency",
              message: "invalid_value"
            });
          }
        }
        const description = body.description ?? null;
        const mirroredRules = buildFileRulesJsonFromSchema(schemaJsonSource);
        const availableFrom = normalizeDateTimeInput(body.availableFrom ?? null);
        const availableUntil = normalizeDateTimeInput(body.availableUntil ?? null);
        if (availableFrom && availableUntil) {
          const start = parseIsoTime(availableFrom);
          const end = parseIsoTime(availableUntil);
          if (start && end && start >= end) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "availableUntil",
              message: "must_be_after_start"
            });
          }
        }
        if (body.passwordRequired !== undefined && typeof body.passwordRequired !== "boolean") {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "passwordRequired",
            message: "expected_boolean"
          });
        }
        if (
          body.passwordRequireAccess !== undefined &&
          typeof body.passwordRequireAccess !== "boolean"
        ) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "passwordRequireAccess",
            message: "expected_boolean"
          });
        }
        if (
          body.passwordRequireSubmit !== undefined &&
          typeof body.passwordRequireSubmit !== "boolean"
        ) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "passwordRequireSubmit",
            message: "expected_boolean"
          });
        }
        const roleFlagsProvided =
          body.passwordRequireAccess !== undefined || body.passwordRequireSubmit !== undefined;
        let passwordRequireAccess = Boolean(body.passwordRequireAccess);
        let passwordRequireSubmit = Boolean(body.passwordRequireSubmit);
        let passwordRequired = Boolean(body.passwordRequired);
        if (!roleFlagsProvided && passwordRequired) {
          passwordRequireSubmit = true;
        }
        if (roleFlagsProvided) {
          passwordRequired = passwordRequireAccess || passwordRequireSubmit;
        }
        let passwordSalt: string | null = null;
        let passwordHash: string | null = null;
        if (passwordRequired) {
          const rawPassword =
            typeof body.formPassword === "string" ? body.formPassword.trim() : "";
          if (!rawPassword) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "formPassword",
              message: "required"
            });
          }
          passwordSalt = crypto.randomUUID();
          passwordHash = await hashPasswordWithSalt(rawPassword, passwordSalt);
        }
        const canvasAllowedJson =
          canvasAllowedSectionIds && canvasAllowedSectionIds.length > 0
            ? JSON.stringify(canvasAllowedSectionIds)
            : null;
        const formInsertBase = [
          { name: "id", value: formId },
          { name: "slug", value: body.slug.trim() },
          { name: "title", value: body.title.trim() },
          { name: "description", value: description },
          { name: "template_id", value: template?.id ?? null },
          { name: "is_public", value: isPublic },
          { name: "auth_policy", value: authPolicy },
          { name: "created_by", value: authPayload?.userId ?? null }
        ];
        const formInsertOptional = [
          { name: "drive_folder_id", value: driveFolderId },
          { name: "file_rules_json", value: mirroredRules },
          { name: "canvas_enabled", value: canvasEnabled ? 1 : 0 },
          { name: "canvas_course_id", value: canvasCourseId },
          { name: "canvas_allowed_section_ids_json", value: canvasAllowedJson },
          { name: "canvas_fields_position", value: canvasFieldsPosition },
          { name: "available_from", value: availableFrom },
          { name: "available_until", value: availableUntil },
          { name: "password_required", value: passwordRequired ? 1 : 0 },
          { name: "password_require_access", value: passwordRequireAccess ? 1 : 0 },
          { name: "password_require_submit", value: passwordRequireSubmit ? 1 : 0 },
          { name: "password_salt", value: passwordSalt },
          { name: "password_hash", value: passwordHash },
          { name: "save_all_versions", value: body?.saveAllVersions ? 1 : 0 },
          { name: "reminder_enabled", value: body.reminderEnabled ? 1 : 0 },
          { name: "reminder_frequency", value: body.reminderFrequency || "weekly" },
          { name: "reminder_until", value: body.reminderUntil || null },
          { name: "submission_backup_enabled", value: body.submissionBackupEnabled ? 1 : 0 },
          { name: "submission_backup_formats", value: serializeSubmissionBackupFormats(submissionBackupFormats) }
        ];
        const formInsertColumns = formInsertBase.map((item) => item.name);
        const formInsertValues = formInsertBase.map((item) => item.value);
        for (const column of formInsertOptional) {
          if (await hasColumn(env, "forms", column.name)) {
            formInsertColumns.push(column.name);
            formInsertValues.push(column.value);
          }
        }
        const formInsertSql = `INSERT INTO forms (${formInsertColumns.join(", ")}) VALUES (${formInsertColumns
          .map(() => "?")
          .join(", ")})`;
        // Optimistic approach: Try to insert. If conflict, cleanup and retry.
        // This handles cases where pre-checks miss the form (replication lag, case sensitivity) but INSERT enforces uniqueness.
        let createdFormId = null;
        for (let attempt = 0; attempt < 2; attempt++) {
          try {
            const statements = [
              env.DB.prepare(formInsertSql).bind(...formInsertValues),
              env.DB.prepare(
                "INSERT INTO form_versions (id, form_id, version, schema_json) VALUES (?, ?, 1, ?)"
              ).bind(versionId, formId, schemaJsonSource)
            ];

            await env.DB.batch(statements);
            createdFormId = formId;
            break; // Success
          } catch (error) {
            const message = String((error as Error | undefined)?.message || error);
            if (message.includes("UNIQUE") && attempt === 0) {
              // Conflict detected. Try to clean up "Ghost" or "Trash" form.
              const slugTarget = body.slug.trim();

              // Check if it is valid to delete (e.g. is it trash?). 
              // We check simply: If it exists, we assume we can overwrite if we are in this retry loop?
              // Wait, if it is ACTIVE, we should NOT delete.
              // So we MUST checking status first.
              const existing = await env.DB.prepare("SELECT id, deleted_at FROM forms WHERE lower(slug)=lower(?)").bind(slugTarget).first<{ id: string, deleted_at: string | null }>();

              if (existing && existing.deleted_at === null) {
                // Active form exists. Report conflict.
                return errorResponse(409, "conflict", requestId, corsHeaders, { message: "slug_exists" });
              }

              // If existing (Trash) OR Not Found (Ghost), we try to delete dependencies.
              // Query based delete.
              // Note: If Not Found, ID is null. checking by slug.
              await env.DB.batch([
                env.DB.prepare("DELETE FROM email_logs WHERE form_id IN (SELECT id FROM forms WHERE lower(slug)=lower(?))").bind(slugTarget),
                env.DB.prepare("DELETE FROM submission_file_items WHERE submission_id IN (SELECT id FROM submissions WHERE form_id IN (SELECT id FROM forms WHERE lower(slug)=lower(?)))").bind(slugTarget),
                env.DB.prepare("DELETE FROM submission_uploads WHERE form_id IN (SELECT id FROM forms WHERE lower(slug)=lower(?))").bind(slugTarget),
                env.DB.prepare("DELETE FROM submissions WHERE form_id IN (SELECT id FROM forms WHERE lower(slug)=lower(?))").bind(slugTarget),
                env.DB.prepare("DELETE FROM form_versions WHERE form_id IN (SELECT id FROM forms WHERE lower(slug)=lower(?))").bind(slugTarget),
                env.DB.prepare("DELETE FROM forms WHERE lower(slug)=lower(?)").bind(slugTarget)
              ]);
              continue; // Retry Insert
            }

            // Other error or retry failed
            return errorResponse(409, "conflict", requestId, corsHeaders, {
              message: message.includes("UNIQUE") ? "slug_exists" : "form_create_failed",
              detail: message // Expose raw error for debugging
            });
          }
        }

        if (createdFormId && await hasColumn(env, "forms", "submission_backup_enabled")) {
          await ensureSubmissionBackupTask(
            env,
            body.slug.trim(),
            body.title.trim(),
            Boolean(body.submissionBackupEnabled)
          );
        }

        return jsonResponse(
          201,
          {
            data: {
              id: formId,
              slug: body.slug.trim(),
              title: body.title.trim(),
              description,
              is_public: isPublic === 1,
              auth_policy: authPolicy,
              templateKey: template?.key ?? null,
              driveFolderId,
              canvas_enabled: canvasEnabled,
              canvas_course_id: canvasCourseId,
              canvas_allowed_section_ids_json: canvasAllowedJson,
              canvas_fields_position: canvasFieldsPosition,
              available_from: availableFrom,
              available_until: availableUntil,
              password_required: passwordRequired,
              password_require_access: passwordRequireAccess,
              password_require_submit: passwordRequireSubmit
            },
            warning: canvasWarning ? { code: canvasWarning } : null,
            requestId
          },
          requestId,
          corsHeaders
        );
      }

      if (request.method === "PATCH") {
        const formMatch = url.pathname.match(/^\/api\/admin\/forms\/([^/]+)$/);
        if (formMatch) {
          const slug = decodeURIComponent(formMatch[1]);
          let body: {
            newSlug?: string;
            title?: string;
            description?: string | null;
            is_public?: boolean;
            is_locked?: boolean;
            auth_policy?: string;
            templateKey?: string;
            refreshTemplate?: boolean;
            schema_json?: string;
            canvasEnabled?: boolean;
            canvasCourseId?: string | null;
            canvasAllowedSectionIds?: string[] | null;
            canvasFieldsPosition?: string | null;
            availableFrom?: string | null;
            availableUntil?: string | null;
            passwordRequired?: boolean;
            passwordRequireAccess?: boolean;
            passwordRequireSubmit?: boolean;
            formPassword?: string | null;
            reminderEnabled?: boolean;
            reminderFrequency?: string;
            reminderUntil?: string | null;
            saveAllVersions?: boolean | number;
            submissionBackupEnabled?: boolean;
            submissionBackupFormats?: string[];
          } | null = null;
          try {
            body = await parseJsonBody(request);
          } catch (error) {
            return errorResponse(400, "invalid_json", requestId, corsHeaders);
          }

          const updates: string[] = [];
          const params: Array<string | number | null> = [];
          let canvasWarning: string | null = null;
          const missingColumns: string[] = [];
          const optionalColumns = [
            "available_from",
            "available_until",
            "password_required",
            "password_require_access",
            "password_require_submit",
            "password_salt",
            "password_hash",
            "canvas_enabled",
            "canvas_course_id",
            "canvas_allowed_section_ids_json",
            "canvas_fields_position",
            "reminder_enabled",
            "reminder_frequency",
            "reminder_until",
            "save_all_versions",
            "submission_backup_enabled",
            "submission_backup_formats",
            "file_rules_json",
            "template_id"
          ];
          const supportedColumns = new Map<string, boolean>();
          for (const column of optionalColumns) {
            supportedColumns.set(column, await hasColumn(env, "forms", column));
          }
          const formRowColumns = ["id", "slug", "title"];
          const formRowOptionalColumns = [
            "password_required",
            "password_require_access",
            "password_require_submit",
            "password_salt",
            "password_hash",
            "available_from",
            "available_until",
            "reminder_until",
            "canvas_course_id",
            "submission_backup_enabled"
          ];
          for (const column of formRowOptionalColumns) {
            const select = (await hasColumn(env, "forms", column)) ? column : `NULL as ${column}`;
            formRowColumns.push(select);
          }
          const formRow = await env.DB.prepare(
            `SELECT ${formRowColumns.join(", ")} FROM forms WHERE slug=? AND deleted_at IS NULL`
          )
            .bind(slug)
            .first<{
              id: string;
              slug: string;
              title: string;
              password_required: number | null;
              password_require_access: number | null;
              password_require_submit: number | null;
              password_salt: string | null;
              password_hash: string | null;
              available_from: string | null;
              available_until: string | null;
              reminder_until: string | null;
              canvas_course_id: string | null;
              submission_backup_enabled: number | null;
            }>();
          if (!formRow) {
            return errorResponse(404, "not_found", requestId, corsHeaders);
          }
          if (
            body?.passwordRequired === true &&
            (formRow.password_hash === null || formRow.password_salt === null) &&
            (body.formPassword === undefined || (typeof body.formPassword === "string" && !body.formPassword.trim()))
          ) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "formPassword",
              message: "required"
            });
          }
          let newSlug: string | null = null;
          if (body?.newSlug !== undefined) {
            if (typeof body.newSlug !== "string" || !body.newSlug.trim()) {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: "newSlug",
                message: "expected_string"
              });
            }
            const candidate = body.newSlug.trim();
            if (candidate !== slug) {
              const existing = await env.DB.prepare(
                "SELECT id, deleted_at FROM forms WHERE slug=?"
              )
                .bind(candidate)
                .first<{ id: string; deleted_at: string | null }>();
              if (existing?.id && existing.id !== formRow.id) {
                return errorResponse(409, "conflict", requestId, corsHeaders, {
                  message: existing.deleted_at !== null ? "slug_in_trash" : "slug_exists"
                });
              }
              newSlug = candidate;
            }
          }

          if (body?.title && typeof body.title === "string") {
            updates.push("title=?");
            params.push(body.title.trim());
          }
          if (body?.description !== undefined) {
            updates.push("description=?");
            params.push(body.description ?? null);
          }
          if (body?.is_locked !== undefined) {
            if (typeof body.is_locked !== "boolean") {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: "is_locked",
                message: "expected_boolean"
              });
            }
            updates.push("is_locked=?");
            params.push(body.is_locked ? 1 : 0);
            updates.push("locked_at=?");
            params.push(body.is_locked ? new Date().toISOString() : null);
          }
          if (body?.is_public !== undefined) {
            if (typeof body.is_public !== "boolean") {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: "is_public",
                message: "expected_boolean"
              });
            }
            updates.push("is_public=?");
            params.push(body.is_public ? 1 : 0);
          }
          const nextAvailableFrom =
            body?.availableFrom !== undefined
              ? normalizeDateTimeInput(body.availableFrom ?? null)
              : formRow.available_from ?? null;
          const nextAvailableUntil =
            body?.availableUntil !== undefined
              ? normalizeDateTimeInput(body.availableUntil ?? null)
              : formRow.available_until ?? null;
          if (nextAvailableFrom && nextAvailableUntil) {
            const start = parseIsoTime(nextAvailableFrom);
            const end = parseIsoTime(nextAvailableUntil);
            if (start && end && start >= end) {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: "availableUntil",
                message: "must_be_after_start"
              });
            }
          }
          const pushOptionalUpdate = (column: string, value: string | number | null, requested: boolean) => {
            if (!requested) return;
            if (supportedColumns.get(column) !== true) {
              missingColumns.push(column);
              return;
            }
            updates.push(`${column}=?`);
            params.push(value);
          };
          if (body?.availableFrom !== undefined) {
            pushOptionalUpdate("available_from", nextAvailableFrom, true);
          }
          if (body?.availableUntil !== undefined) {
            pushOptionalUpdate("available_until", nextAvailableUntil, true);
          }
          if (body?.passwordRequired !== undefined && typeof body.passwordRequired !== "boolean") {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "passwordRequired",
              message: "expected_boolean"
            });
          }
          if (
            body?.passwordRequireAccess !== undefined &&
            typeof body.passwordRequireAccess !== "boolean"
          ) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "passwordRequireAccess",
              message: "expected_boolean"
            });
          }
          if (
            body?.passwordRequireSubmit !== undefined &&
            typeof body.passwordRequireSubmit !== "boolean"
          ) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "passwordRequireSubmit",
              message: "expected_boolean"
            });
          }
          const accessProvided = body?.passwordRequireAccess !== undefined;
          const submitProvided = body?.passwordRequireSubmit !== undefined;
          let nextRequireAccess = accessProvided
            ? Boolean(body?.passwordRequireAccess)
            : toBoolean(formRow.password_require_access ?? 0);
          let nextRequireSubmit = submitProvided
            ? Boolean(body?.passwordRequireSubmit)
            : toBoolean(formRow.password_require_submit ?? 0);
          const roleFlagsProvided = accessProvided || submitProvided;
          let nextPasswordRequired = toBoolean(formRow.password_required ?? 0);
          if (roleFlagsProvided) {
            nextPasswordRequired = nextRequireAccess || nextRequireSubmit;
          } else if (body?.passwordRequired !== undefined) {
            nextPasswordRequired = Boolean(body.passwordRequired);
            if (nextPasswordRequired && !nextRequireAccess && !nextRequireSubmit) {
              nextRequireSubmit = true;
            }
          }
          if (body?.formPassword !== undefined) {
            const raw = typeof body.formPassword === "string" ? body.formPassword.trim() : "";
            if (raw) {
              const salt = crypto.randomUUID();
              const hash = await hashPasswordWithSalt(raw, salt);
              pushOptionalUpdate("password_salt", salt, true);
              pushOptionalUpdate("password_hash", hash, true);
              nextPasswordRequired = true;
              if (!nextRequireAccess && !nextRequireSubmit) {
                nextRequireSubmit = true;
              }
            }
          }
          if (roleFlagsProvided || body?.passwordRequired !== undefined || body?.formPassword !== undefined) {
            pushOptionalUpdate("password_required", nextPasswordRequired ? 1 : 0, true);
            pushOptionalUpdate("password_require_access", nextRequireAccess ? 1 : 0, true);
            pushOptionalUpdate("password_require_submit", nextRequireSubmit ? 1 : 0, true);
            if (!nextPasswordRequired) {
              pushOptionalUpdate("password_salt", null, true);
              pushOptionalUpdate("password_hash", null, true);
            }
          }
          if (body?.auth_policy) {
            if (!["optional", "google", "github", "either", "required"].includes(body.auth_policy)) {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: "auth_policy",
                allowed: ["optional", "google", "github", "either", "required"]
              });
            }
            updates.push("auth_policy=?");
            params.push(body.auth_policy);
          }

          if (body?.submissionBackupEnabled !== undefined) {
            if (typeof body.submissionBackupEnabled !== "boolean") {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: "submissionBackupEnabled",
                message: "expected_boolean"
              });
            }
            pushOptionalUpdate("submission_backup_enabled", body.submissionBackupEnabled ? 1 : 0, true);
          }
          if (body?.submissionBackupFormats !== undefined) {
            if (!Array.isArray(body.submissionBackupFormats)) {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: "submissionBackupFormats",
                message: "expected_array"
              });
            }
            const formats = parseSubmissionBackupFormats(body.submissionBackupFormats);
            if (formats.length === 0) {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: "submissionBackupFormats",
                message: "unsupported"
              });
            }
            pushOptionalUpdate("submission_backup_formats", serializeSubmissionBackupFormats(formats), true);
          }

          if (body?.canvasEnabled !== undefined) {
            if (typeof body.canvasEnabled !== "boolean") {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: "canvasEnabled",
                message: "expected_boolean"
              });
            }
            if (body.canvasEnabled && body.canvasCourseId === null) {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: "canvasCourseId",
                message: "required"
              });
            }
            if (body.canvasEnabled && body.canvasCourseId === undefined && supportedColumns.get("canvas_course_id") === true) {
              const formRow = await env.DB.prepare(
                "SELECT canvas_course_id FROM forms WHERE slug=? AND deleted_at IS NULL"
              )
                .bind(slug)
                .first<{ canvas_course_id: string | null }>();
              if (formRow?.canvas_course_id === null) {
                return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                  field: "canvasCourseId",
                  message: "required"
                });
              }
            }
            pushOptionalUpdate("canvas_enabled", body.canvasEnabled ? 1 : 0, true);
          }
          if (body?.canvasCourseId !== undefined) {
            if (body.canvasCourseId !== null && typeof body.canvasCourseId !== "string") {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: "canvasCourseId",
                message: "expected_string"
              });
            }
            pushOptionalUpdate("canvas_course_id", body.canvasCourseId ? body.canvasCourseId.trim() : null, true);
          }
          if (body?.canvasAllowedSectionIds !== undefined) {
            if (!Array.isArray(body.canvasAllowedSectionIds)) {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: "canvasAllowedSectionIds",
                message: "expected_array"
              });
            }
            const filtered = body.canvasAllowedSectionIds
              .filter((id): id is string => typeof id === "string")
              .map((id) => id.trim())
              .filter((id) => id.length > 0);
            const courseId =
              body.canvasCourseId !== undefined
                ? body.canvasCourseId?.trim() || null
                : supportedColumns.get("canvas_course_id") === true
                  ? (await env.DB.prepare(
                    "SELECT canvas_course_id FROM forms WHERE slug=? AND deleted_at IS NULL"
                  )
                    .bind(slug)
                    .first<{ canvas_course_id: string | null }>())?.canvas_course_id ?? null
                  : null;
            if (courseId && filtered.length > 0) {
              const { results } = await env.DB.prepare(
                "SELECT id FROM canvas_sections_cache WHERE course_id=?"
              )
                .bind(courseId)
                .all<{ id: string }>();
              if (results.length > 0) {
                const allowedSet = new Set(results.map((row) => String(row.id)));
                const invalid = filtered.find((id) => !allowedSet.has(id));
                if (invalid) {
                  return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                    field: "canvasAllowedSectionIds",
                    message: "section_not_in_course",
                    detail: invalid
                  });
                }
              } else {
                canvasWarning = "canvas_sections_not_cached";
              }
            }
            pushOptionalUpdate(
              "canvas_allowed_section_ids_json",
              filtered.length > 0 ? JSON.stringify(filtered) : null,
              true
            );
          }
          if (body?.canvasFieldsPosition !== undefined) {
            if (body.canvasFieldsPosition !== null && typeof body.canvasFieldsPosition !== "string") {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: "canvasFieldsPosition",
                message: "expected_string"
              });
            }
            const value =
              typeof body.canvasFieldsPosition === "string" && body.canvasFieldsPosition.trim()
                ? body.canvasFieldsPosition.trim()
                : "bottom";
            if (!["top", "after_identity", "bottom"].includes(value)) {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: "canvasFieldsPosition",
                message: "invalid_value"
              });
            }
            pushOptionalUpdate("canvas_fields_position", value, true);
          }

          if (body?.reminderEnabled !== undefined) {
            if (typeof body.reminderEnabled !== "boolean") {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: "reminderEnabled",
                message: "expected_boolean"
              });
            }
            pushOptionalUpdate("reminder_enabled", body.reminderEnabled ? 1 : 0, true);
          }

          if (body?.reminderFrequency !== undefined) {
            if (body.reminderFrequency !== null && !["daily", "weekly", "monthly"].includes(body.reminderFrequency) && !/^\d+:(days|weeks|months)$/.test(body.reminderFrequency)) {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: "reminderFrequency",
                message: "invalid_value"
              });
            }
            pushOptionalUpdate("reminder_frequency", body.reminderFrequency || "weekly", true);
          }

          if (body?.reminderUntil !== undefined) {
            pushOptionalUpdate(
              "reminder_until",
              normalizeDateTimeInput(body.reminderUntil ?? null),
              true
            );
          }

          if (body?.saveAllVersions !== undefined) {
            const val = body.saveAllVersions;
            const isBool = typeof val === "boolean";
            const isNum = typeof val === "number" && (val === 0 || val === 1);
            if (!isBool && !isNum) {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: "saveAllVersions",
                message: "expected_boolean_or_0_1"
              });
            }
            pushOptionalUpdate("save_all_versions", val ? 1 : 0, true);
          }

          let formId: string | null = null;
          if (body?.templateKey !== undefined) {
            if (body.refreshTemplate !== undefined && typeof body.refreshTemplate !== "boolean") {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: "refreshTemplate",
                message: "expected_boolean"
              });
            }
            const refreshTemplate = body.refreshTemplate !== undefined ? body.refreshTemplate === true : true;
            if (body.templateKey === null) {
              pushOptionalUpdate("template_id", null, true);
            } else if (typeof body.templateKey === "string") {
              const templateKey = body.templateKey.trim();
              if (!templateKey) {
                pushOptionalUpdate("template_id", null, true);
              } else {
                const template = await env.DB.prepare(
                  "SELECT id, schema_json FROM templates WHERE key=? AND deleted_at IS NULL"
                )
                  .bind(templateKey)
                  .first<{ id: string; schema_json: string }>();
                if (!template) {
                  return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                    field: "templateKey",
                    message: "template_not_found"
                  });
                }
                let parsedTemplateSchema: unknown = null;
                try {
                  parsedTemplateSchema = JSON.parse(template.schema_json);
                } catch (error) {
                  return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                    field: "templateKey",
                    message: "invalid_template_schema"
                  });
                }
                const templateRuleError = validateFileRulesFromSchema(parsedTemplateSchema);
                if (templateRuleError) {
                  return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                    field: "templateKey",
                    message: "invalid_file_rules",
                    detail: templateRuleError
                  });
                }
                pushOptionalUpdate("template_id", template.id, true);
                if (refreshTemplate) {
                  const formRow = await env.DB.prepare("SELECT id FROM forms WHERE slug=? AND deleted_at IS NULL")
                    .bind(slug)
                    .first<{ id: string }>();
                  if (!formRow) {
                    return errorResponse(404, "not_found", requestId, corsHeaders);
                  }
                  formId = formRow.id;
                  await env.DB.prepare(
                    "UPDATE form_versions SET schema_json=? WHERE form_id=? AND version=1"
                  )
                    .bind(template.schema_json, formId)
                    .run();
                  const mirroredRules = buildFileRulesJsonFromSchema(template.schema_json);
                  pushOptionalUpdate("file_rules_json", mirroredRules, true);
                }
              }
            } else {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: "templateKey",
                message: "expected_string"
              });
            }
          }

          if (body?.schema_json && typeof body.schema_json === "string") {
            let parsedSchema: unknown = null;
            try {
              parsedSchema = JSON.parse(body.schema_json);
            } catch (error) {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: "schema_json",
                message: "invalid_json"
              });
            }
            const ruleError = validateFileRulesFromSchema(parsedSchema);
            if (ruleError) {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: "schema_json",
                message: "invalid_file_rules",
                detail: ruleError
              });
            }
            const formRow = await env.DB.prepare("SELECT id FROM forms WHERE slug=? AND deleted_at IS NULL")
              .bind(slug)
              .first<{ id: string }>();
            if (!formRow) {
              return errorResponse(404, "not_found", requestId, corsHeaders);
            }
            formId = formRow.id;
            await env.DB.prepare(
              "UPDATE form_versions SET schema_json=? WHERE form_id=? AND version=1"
            )
              .bind(JSON.stringify(parsedSchema), formId)
              .run();
            const mirroredRules = buildFileRulesJsonFromSchema(body.schema_json);
            pushOptionalUpdate("file_rules_json", mirroredRules, true);
          }
          if (newSlug) {
            updates.push("slug=?");
            params.push(newSlug);
          }

          if (updates.length === 0) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              message: "no_fields_to_update"
            });
          }

          params.push(slug);
          await env.DB.prepare(
            `UPDATE forms SET ${updates.join(", ")}, updated_at=datetime('now') WHERE slug=? AND deleted_at IS NULL`
          )
            .bind(...params)
            .run();
          const nextSlug = newSlug ?? slug;
          if (await hasColumn(env, "forms", "submission_backup_enabled")) {
            const nextTitle = body?.title ? body.title.trim() : formRow.title;
            const currentBackupEnabled = toBoolean(formRow.submission_backup_enabled ?? 0);
            const nextBackupEnabled =
              body?.submissionBackupEnabled !== undefined
                ? Boolean(body.submissionBackupEnabled)
                : currentBackupEnabled;
            if (newSlug) {
              await renameSubmissionBackupTask(env, slug, nextSlug, nextTitle);
            }
            await ensureSubmissionBackupTask(env, nextSlug, nextTitle, nextBackupEnabled);
          }
          if (newSlug) {
            if (await hasColumn(env, "submissions", "form_slug")) {
              try {
                await env.DB.prepare("UPDATE submissions SET form_slug=? WHERE form_id=?")
                  .bind(newSlug, formRow.id)
                  .run();
              } catch (error) {
                if (!isMissingColumn(error, "form_slug")) {
                  throw error;
                }
              }
            }
            if (await hasColumn(env, "submission_file_items", "form_slug")) {
              try {
                await env.DB.prepare("UPDATE submission_file_items SET form_slug=? WHERE form_id=?")
                  .bind(newSlug, formRow.id)
                  .run();
              } catch (error) {
                if (!isMissingColumn(error, "form_slug")) {
                  throw error;
                }
              }
            }
            if (await hasColumn(env, "submission_upload_sessions", "form_slug")) {
              try {
                await env.DB.prepare("UPDATE submission_upload_sessions SET form_slug=? WHERE form_id=?")
                  .bind(newSlug, formRow.id)
                  .run();
              } catch (error) {
                if (!isMissingColumn(error, "form_slug")) {
                  throw error;
                }
              }
            }
            if (await hasColumn(env, "drive_folders", "form_slug")) {
              try {
                await env.DB.prepare("UPDATE drive_folders SET form_slug=? WHERE form_slug=?")
                  .bind(newSlug, slug)
                  .run();
              } catch (error) {
                if (!isMissingColumn(error, "form_slug")) {
                  throw error;
                }
              }
            }
            if (await hasColumn(env, "drive_user_folders", "form_slug")) {
              try {
                await env.DB.prepare("UPDATE drive_user_folders SET form_slug=? WHERE form_slug=?")
                  .bind(newSlug, slug)
                  .run();
              } catch (error) {
                if (!isMissingColumn(error, "form_slug")) {
                  throw error;
                }
              }
            }
            if (await hasColumn(env, "email_logs", "form_slug")) {
              try {
                await env.DB.prepare("UPDATE email_logs SET form_slug=? WHERE form_slug=?")
                  .bind(newSlug, slug)
                  .run();
              } catch (error) {
                if (!isMissingColumn(error, "form_slug")) {
                  throw error;
                }
              }
            }
          }

          const uniqueMissingColumns = Array.from(new Set(missingColumns));
          const warnings = [
            ...(canvasWarning ? [{ code: canvasWarning }] : []),
            ...(uniqueMissingColumns.length > 0
              ? [{ code: "missing_columns", columns: uniqueMissingColumns }]
              : [])
          ];
          return jsonResponse(
            200,
            { ok: true, warning: warnings.length > 0 ? warnings : null, requestId },
            requestId,
            corsHeaders
          );
        }
      }

      if (request.method === "DELETE") {
        const formMatch = url.pathname.match(/^\/api\/admin\/forms\/([^/]+)$/);
        if (formMatch) {
          const slug = decodeURIComponent(formMatch[1]);
          const authPayload = await getAuthPayload(request, env);
          await softDeleteForm(env, slug, authPayload?.userId ?? null, "admin_deleted");
          return jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
        }
      }

      if (request.method === "GET" && url.pathname === "/api/admin/submissions") {
        const formSlug = url.searchParams.get("formSlug");
        const includeData =
          url.searchParams.get("includeData") === "true" ||
          url.searchParams.get("includeData") === "1";
        const page = Math.max(toNumber(url.searchParams.get("page"), 1), 1);
        const pageSize = Math.min(
          Math.max(toNumber(url.searchParams.get("pageSize"), 50), 1),
          200
        );
        const limit = pageSize;
        const offset = (page - 1) * pageSize;
        const params: Array<string | number> = [];
        let query =
          "SELECT s.id,s.form_id,f.slug as form_slug,f.title as form_title,s.user_id,s.payload_json,s.created_at,s.updated_at,s.created_ip,s.created_user_agent,COALESCE(s.submitter_provider,(SELECT provider FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1)) as submitter_provider,COALESCE(s.submitter_email,(SELECT email FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1)) as submitter_email,COALESCE(s.submitter_github_username,(SELECT provider_login FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1)) as submitter_github_username FROM submissions s JOIN forms f ON f.id=s.form_id WHERE s.deleted_at IS NULL AND f.deleted_at IS NULL";
        if (formSlug) {
          query += " AND f.slug=?";
          params.push(formSlug);
        }
        query += " ORDER BY COALESCE(s.updated_at, s.created_at) DESC LIMIT ? OFFSET ?";
        params.push(limit, offset);

        const totalResult = await env.DB.prepare(
          `SELECT COUNT(1) as total FROM submissions s JOIN forms f ON f.id=s.form_id WHERE s.deleted_at IS NULL AND f.deleted_at IS NULL${formSlug ? " AND f.slug=?" : ""
          }`
        )
          .bind(...(formSlug ? [formSlug] : []))
          .first<{ total: number }>();

        const { results } = await env.DB.prepare(query)
          .bind(...params)
          .all<SubmissionRow>();

        const data = results.map((row) => {
          let dataJson: unknown = null;
          if (includeData) {
            try {
              const payload = JSON.parse(row.payload_json) as { data?: unknown };
              dataJson = payload?.data ?? payload ?? null;
            } catch (error) {
              dataJson = null;
            }
          }
          const extended = row as SubmissionRow & {
            submitter_provider?: string | null;
            submitter_email?: string | null;
            submitter_github_username?: string | null;
            updated_at?: string | null;
          };
          return {
            id: row.id,
            form_slug: row.form_slug,
            form_title: (row as SubmissionRow & { form_title?: string | null }).form_title ?? null,
            form_id: row.form_id,
            form_version: null,
            created_at: row.created_at,
            updated_at: extended.updated_at ?? null,
            user_id: row.user_id,
            submitter_provider: extended.submitter_provider ?? null,
            submitter_email: extended.submitter_email ?? null,
            submitter_github_username: extended.submitter_github_username ?? null,
            created_ip: (row as any).created_ip ?? null,
            created_user_agent: (row as any).created_user_agent ?? null,
            data_json: includeData ? dataJson : undefined
          };
        });

        return jsonResponse(
          200,
          { data, page, pageSize, total: totalResult?.total ?? 0, requestId },
          requestId,
          corsHeaders
        );
      }

      if (request.method === "DELETE") {
        const submissionMatch = url.pathname.match(/^\/api\/admin\/submissions\/([^/]+)$/);
        if (submissionMatch) {
          const submissionId = decodeURIComponent(submissionMatch[1]);
          const result = await softDeleteSubmissionById(env, submissionId, adminPayload.userId, "admin_deleted");
          const attempted = result.canvas?.attempted ?? 0;
          const failed = result.canvas?.failed ?? 0;
          const canvasAction = attempted === 0 ? "skipped" : failed > 0 ? "failed" : "deactivated";
          return jsonResponse(
            200,
            { ok: result.ok, canvasAction, canvasAttempts: attempted, canvasFailed: failed, requestId },
            requestId,
            corsHeaders
          );
        }
      }

      if (request.method === "GET") {
        const newExportMatch = url.pathname.match(/^\/api\/admin\/forms\/([^/]+)\/submissions\/export$/);
        if (newExportMatch) {
          const formSlug = decodeURIComponent(newExportMatch[1]).trim();
          const format = (url.searchParams.get("format") || "csv").toLowerCase();
          const includeDeleted = url.searchParams.get("includeDeleted") === "1";
          const includeDeletedUsers = url.searchParams.get("includeDeletedUsers") === "1";
          const fieldsParam = url.searchParams.get("fields");
          const requestedFields = fieldsParam
            ? fieldsParam
              .split(",")
              .map((item) => item.trim())
              .filter((item) => item.length > 0)
            : [];
          if (fieldsParam && requestedFields.length === 0) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "fields",
              message: "empty"
            });
          }
          if (!formSlug) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "formSlug",
              message: "required"
            });
          }
          if (format !== "csv" && format !== "txt") {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "format",
              message: "unsupported"
            });
          }

          const form = await env.DB.prepare("SELECT id, slug FROM forms WHERE slug=?")
            .bind(formSlug)
            .first<{ id: string; slug: string }>();
          if (!form) {
            return errorResponse(404, "not_found", requestId, corsHeaders);
          }

          const baseQuery =
            "SELECT s.id,s.form_id,s.user_id,s.payload_json,s.created_at,s.updated_at," +
            "COALESCE(s.submitter_provider,(SELECT provider FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1)) as provider," +
            "COALESCE(s.submitter_email,(SELECT email FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1)) as submitter_email," +
            "COALESCE(s.submitter_github_username,(SELECT provider_login FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1)) as submitter_github_username," +
            "f.slug as form_slug " +
            "FROM submissions s JOIN forms f ON f.id=s.form_id LEFT JOIN users u ON u.id=s.user_id WHERE f.slug=?";

          const conditions: string[] = [];
          const params: Array<string | null> = [formSlug];
          if (!includeDeleted) {
            conditions.push("s.deleted_at IS NULL");
          }
          if (!includeDeletedUsers) {
            conditions.push("(s.user_id IS NULL OR u.deleted_at IS NULL)");
          }
          let query = baseQuery;
          if (conditions.length > 0) {
            query += ` AND ${conditions.join(" AND ")}`;
          }
          query += " ORDER BY s.created_at ASC";

          let results: Array<any> = [];
          try {
            const response = await env.DB.prepare(query).bind(...params).all<any>();
            results = response.results || [];
          } catch (error) {
            if (!includeDeleted && isMissingColumn(error, "deleted_at")) {
              const response = await env.DB.prepare(baseQuery + " ORDER BY s.created_at ASC")
                .bind(formSlug)
                .all<any>();
              results = response.results || [];
            } else {
              throw error;
            }
          }

          const includeDataJson = requestedFields.length === 0;
          const rows = results.map((row: any) => {
            let dataObj: Record<string, unknown> = {};
            try {
              const payload = JSON.parse(row.payload_json) as { data?: Record<string, unknown> };
              dataObj = payload?.data && typeof payload.data === "object" ? payload.data : {};
            } catch (error) {
              dataObj = {};
            }
            if (requestedFields.length > 0) {
              const filtered: Record<string, unknown> = {};
              requestedFields.forEach((key) => {
                if (Object.prototype.hasOwnProperty.call(dataObj, key)) {
                  filtered[key] = (dataObj as Record<string, unknown>)[key];
                }
              });
              dataObj = filtered;
            }
            return {
              submission_id: row.id,
              form_slug: row.form_slug,
              form_version: null,
              created_at: row.created_at,
              updated_at: row.updated_at ?? null,
              user_id: row.user_id ?? null,
              provider: row.provider ?? null,
              email: row.submitter_email ?? null,
              github_username: row.submitter_github_username ?? null,
              data_json: JSON.stringify(dataObj ?? {}),
              data: dataObj
            };
          });

          const keySet = new Set<string>();
          rows.forEach((row) => {
            Object.keys(row.data || {}).forEach((key) => keySet.add(key));
          });
          const dataKeys = requestedFields.length > 0 ? requestedFields : Array.from(keySet).sort();
          const headers = [
            "submission_id",
            "form_slug",
            "form_version",
            "created_at",
            "updated_at",
            "user_id",
            "provider",
            "email",
            "github_username",
            ...(includeDataJson ? ["data_json"] : []),
            ...dataKeys.map((key) => `data.${key}`)
          ];

          const delimiter = format === "csv" ? "," : ",";
          const lines = [headers.join(delimiter)];
          rows.forEach((row) => {
            const baseValues = [
              row.submission_id,
              row.form_slug,
              row.form_version ?? "",
              row.created_at,
              row.updated_at ?? "",
              row.user_id ?? "",
              row.provider ?? "",
              row.email ?? "",
              row.github_username ?? "",
              ...(includeDataJson ? [row.data_json ?? ""] : [])
            ];
            const dataValues = dataKeys.map((key) => stringifyCsvValue(row.data?.[key]));
            const values = [...baseValues, ...dataValues].map((value) =>
              format === "csv" ? csvEscape(String(value ?? "")) : String(value ?? "")
            );
            lines.push(values.join(delimiter));
          });

          const timestamp = formatExportTimestamp(new Date());
          const filename = `submissions_${formSlug}_${timestamp}.${format}`;
          const body = format === "csv" ? `\ufeff${lines.join("\n")}` : lines.join("\n");
          return new Response(body, {
            status: 200,
            headers: {
              "content-type": format === "csv" ? "text/csv; charset=utf-8" : "text/plain; charset=utf-8",
              "content-disposition": `attachment; filename="${filename}"`,
              "cache-control": "no-store",
              "access-control-expose-headers": "Content-Disposition",
              "x-export-fields": requestedFields.join(","),
              "x-export-delimiter": delimiter,
              "x-request-id": requestId,
              ...corsHeaders
            }
          });
        }
      }

      if (
        request.method === "GET" &&
        (url.pathname === "/api/admin/submissions/export" ||
          url.pathname.match(/^\/api\/admin\/forms\/[^/]+\/export$/) ||
          url.pathname.match(/^\/api\/admin\/forms\/[^/]+\/submissions\/export$/))
      ) {
        const formSlug =
          url.pathname === "/api/admin/submissions/export"
            ? url.searchParams.get("formSlug")?.trim()
            : decodeURIComponent(url.pathname.split("/")[4] || "").trim();
        if (!formSlug) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "formSlug",
            message: "required"
          });
        }
        const format = (url.searchParams.get("format") || "csv").toLowerCase();
        const mode = (url.searchParams.get("mode") || "flat").toLowerCase();
        const includeMeta = url.searchParams.get("includeMeta") !== "0";
        const maxRows = Math.min(Math.max(toNumber(url.searchParams.get("maxRows"), 5000), 1), 50000);
        const fieldsParam = url.searchParams.get("fields");
        const requestedFields = fieldsParam
          ? fieldsParam
            .split(",")
            .map((item) => item.trim())
            .filter((item) => item.length > 0)
          : [];
        if (fieldsParam && requestedFields.length === 0) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "fields",
            message: "empty"
          });
        }
        const includeMetaEffective = requestedFields.length > 0 ? false : includeMeta;
        if (format !== "csv" && format !== "txt") {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "format",
            message: "unsupported"
          });
        }
        if (mode !== "flat" && mode !== "json") {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "mode",
            message: "unsupported"
          });
        }

        const { results } = await env.DB.prepare(
          "SELECT s.id,s.user_id,s.payload_json,s.created_at,s.updated_at,COALESCE(s.submitter_provider,(SELECT provider FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1)) as provider,COALESCE(s.submitter_email,(SELECT email FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1)) as submitter_email,COALESCE(s.submitter_github_username,(SELECT provider_login FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1)) as submitter_github_username FROM submissions s JOIN forms f ON f.id=s.form_id WHERE s.deleted_at IS NULL AND f.deleted_at IS NULL AND f.slug=? ORDER BY s.created_at DESC LIMIT ?"
        )
          .bind(formSlug, maxRows)
          .all<any>();

        const rows = results.map((row: any) => {
          let dataObj: Record<string, unknown> = {};
          try {
            const payload = JSON.parse(row.payload_json) as { data?: Record<string, unknown> };
            dataObj = payload?.data && typeof payload.data === "object" ? payload.data : {};
          } catch (error) {
            dataObj = {};
          }
          if (requestedFields.length > 0) {
            const filtered: Record<string, unknown> = {};
            requestedFields.forEach((key) => {
              if (Object.prototype.hasOwnProperty.call(dataObj, key)) {
                filtered[key] = (dataObj as Record<string, unknown>)[key];
              }
            });
            dataObj = filtered;
          }
          return {
            submission_id: row.id,
            created_at: row.created_at,
            updated_at: row.updated_at ?? null,
            user_id: row.user_id ?? null,
            provider: row.provider ?? null,
            email: row.submitter_email ?? null,
            github_username: row.submitter_github_username ?? null,
            data: dataObj
          };
        });

        const keySet = new Set<string>();
        rows.forEach((row) => {
          Object.keys(row.data || {}).forEach((key) => keySet.add(key));
        });
        const dataKeys = requestedFields.length > 0 ? requestedFields : Array.from(keySet).sort();

        const escapeDelimited = (value: string, delimiter: string) => {
          if (value.includes('"') || value.includes("\n") || value.includes("\r") || value.includes(delimiter)) {
            return `"${value.replace(/"/g, '""')}"`;
          }
          return value;
        };

        const metaHeaders = includeMetaEffective
          ? ["submission_id", "created_at", "updated_at", "user_id", "provider", "email", "github_username"]
          : [];

        const filenamePrefix =
          url.pathname === "/api/admin/submissions/export"
            ? `${formSlug}-submissions`
            : `submissions_${formSlug}`;

        if (format === "csv") {
          const headers =
            mode === "json"
              ? [...metaHeaders, "data_json"]
              : [...metaHeaders, ...dataKeys];
          const lines = [headers.join(",")];
          rows.forEach((row) => {
            const metaValues = includeMetaEffective
              ? [
                row.submission_id,
                row.created_at,
                row.updated_at ?? "",
                row.user_id ?? "",
                row.provider ?? "",
                row.email ?? "",
                row.github_username ?? ""
              ]
              : [];
            const dataValues =
              mode === "json"
                ? [JSON.stringify(row.data ?? {})]
                : dataKeys.map((key) => stringifyCsvValue(row.data?.[key]));
            const values = [...metaValues, ...dataValues].map((value) => escapeDelimited(String(value ?? ""), ","));
            lines.push(values.join(","));
          });
          const csv = `\ufeff${lines.join("\n")}`;
          return new Response(csv, {
            status: 200,
            headers: {
              "content-type": "text/csv; charset=utf-8",
              "content-disposition": `attachment; filename="${filenamePrefix}.csv"`,
              "cache-control": "no-store",
              "access-control-expose-headers": "Content-Disposition",
              "x-export-fields": requestedFields.join(","),
              "x-request-id": requestId,
              ...corsHeaders
            }
          });
        }

        if (mode === "json") {
          const lines = rows.map((row) => {
            const record: Record<string, unknown> = {};
            if (includeMetaEffective) {
              record.submission_id = row.submission_id;
              record.created_at = row.created_at;
              record.updated_at = row.updated_at ?? null;
              record.user_id = row.user_id ?? null;
              record.provider = row.provider ?? null;
              record.email = row.email ?? null;
              record.github_username = row.github_username ?? null;
            }
            record.data = row.data ?? {};
            return JSON.stringify(record);
          });
          const output = lines.join("\n");
          return new Response(output, {
            status: 200,
            headers: {
              "content-type": "text/plain; charset=utf-8",
              "content-disposition": `attachment; filename="${filenamePrefix}.txt"`,
              "cache-control": "no-store",
              "access-control-expose-headers": "Content-Disposition",
              "x-export-fields": requestedFields.join(","),
              "x-request-id": requestId,
              ...corsHeaders
            }
          });
        }

        const delimiter = ",";
        const headers = [...metaHeaders, ...dataKeys];
        const lines = [headers.join(delimiter)];
        rows.forEach((row) => {
          const metaValues = includeMetaEffective
            ? [
              row.submission_id,
              row.created_at,
              row.updated_at ?? "",
              row.user_id ?? "",
              row.provider ?? "",
              row.email ?? "",
              row.github_username ?? ""
            ]
            : [];
          const dataValues = dataKeys.map((key) => stringifyCsvValue(row.data?.[key]));
          const values = [...metaValues, ...dataValues].map((value) =>
            escapeDelimited(String(value ?? ""), delimiter)
          );
          lines.push(values.join(delimiter));
        });
        const output = lines.join("\n");
        return new Response(output, {
          status: 200,
          headers: {
            "content-type": "text/plain; charset=utf-8",
            "content-disposition": `attachment; filename="${filenamePrefix}.txt"`,
            "cache-control": "no-store",
            "access-control-expose-headers": "Content-Disposition",
            "x-export-fields": requestedFields.join(","),
            "x-export-delimiter": delimiter,
            "x-request-id": requestId,
            ...corsHeaders
          }
        });
      }

      if (request.method === "GET" && url.pathname === "/api/admin/uploads") {
        const formSlug = url.searchParams.get("formSlug");
        const limit = Math.min(toNumber(url.searchParams.get("limit"), 50), 200);
        const offset = Math.max(toNumber(url.searchParams.get("offset"), 0), 0);
        const params: Array<string | number> = [];
        let query =
          "SELECT i.id,i.submission_id,i.form_id,i.form_slug,s.user_id,i.field_id as field_key,i.original_name,i.mime_type as content_type,i.size_bytes,i.sha256,i.r2_key,i.uploaded_at,i.vt_status,i.vt_verdict,i.vt_malicious,i.vt_suspicious,i.vt_undetected,i.vt_timeout,i.vt_error,i.final_drive_file_id,i.finalized_at,i.drive_web_view_link,(SELECT email FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1) as submitter_email,(SELECT provider_login FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1) as submitter_github_username FROM submission_file_items i JOIN submissions s ON s.id=i.submission_id WHERE s.deleted_at IS NULL AND i.deleted_at IS NULL";
        if (formSlug) {
          query += " AND i.form_slug=?";
          params.push(formSlug);
        }
        query += " ORDER BY i.uploaded_at DESC LIMIT ? OFFSET ?";
        params.push(limit, offset);

        const { results } = await env.DB.prepare(query).bind(...params).all();
        const data = results.map((row: any) => ({
          id: row.id,
          submission_id: row.submission_id,
          form_slug: row.form_slug,
          user_id: row.user_id,
          submitter_display: row.submitter_email || row.submitter_github_username || null,
          field_key: row.field_key,
          original_name: row.original_name,
          content_type: row.content_type,
          size_bytes: row.size_bytes,
          sha256: row.sha256,
          r2_key: row.r2_key,
          uploaded_at: row.uploaded_at,
          vt_status: row.vt_status,
          vt_verdict: row.vt_verdict,
          vt_malicious: row.vt_malicious,
          vt_suspicious: row.vt_suspicious,
          vt_undetected: row.vt_undetected,
          vt_timeout: row.vt_timeout,
          vt_error: row.vt_error,
          final_drive_file_id: row.final_drive_file_id,
          finalized_at: row.finalized_at,
          drive_web_view_link: row.drive_web_view_link
        }));

        return jsonResponse(200, { data, requestId }, requestId, corsHeaders);
      }

      if (request.method === "DELETE") {
        const uploadMatch = url.pathname.match(/^\/api\/admin\/uploads\/([^/]+)$/);
        if (uploadMatch) {
          const uploadId = decodeURIComponent(uploadMatch[1]);
          await env.DB.prepare(
            "UPDATE submission_file_items SET deleted_at=datetime('now'), deleted_by=?, deleted_reason='admin_deleted' WHERE id=? AND deleted_at IS NULL"
          )
            .bind(adminPayload?.userId ?? null, uploadId)
            .run();
          return jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
        }
      }

      if (request.method === "GET" && url.pathname === "/api/admin/r2/list") {
        const prefix = url.searchParams.get("prefix") || "";
        if (!env.form_app_files) {
          return errorResponse(500, "uploads_unavailable", requestId, corsHeaders);
        }
        const listing = await env.form_app_files.list({ prefix, limit: 1000 });
        const data = listing.objects.map((obj) => ({
          key: obj.key,
          size: obj.size,
          uploaded: obj.uploaded
        }));
        return jsonResponse(200, { ok: true, prefix, data, requestId }, requestId, corsHeaders);
      }

      if (request.method === "GET" && url.pathname === "/api/admin/uploads/verify") {
        const submissionId = url.searchParams.get("submissionId");
        if (!submissionId) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "submissionId",
            message: "required"
          });
        }
        if (!env.form_app_files) {
          return errorResponse(500, "uploads_unavailable", requestId, corsHeaders);
        }
        const rows = await env.DB.prepare(
          "SELECT id, r2_key FROM submission_uploads WHERE submission_id=? AND deleted_at IS NULL"
        )
          .bind(submissionId)
          .all<{ id: string; r2_key: string }>();
        const results: Array<{ id: string; r2Key: string; exists: boolean }> = [];
        const missing: string[] = [];
        for (const row of rows.results) {
          const exists = Boolean(await env.form_app_files.head(row.r2_key));
          results.push({ id: row.id, r2Key: row.r2_key, exists });
          if (!exists) {
            missing.push(row.r2_key);
          }
        }
        return jsonResponse(
          200,
          {
            ok: missing.length === 0,
            submissionId,
            total: results.length,
            missing,
            data: results,
            requestId
          },
          requestId,
          corsHeaders
        );
      }

      const adminUploadsMatch = url.pathname.match(/^\/api\/admin\/submissions\/([^/]+)\/uploads$/);
      if (request.method === "GET" && adminUploadsMatch) {
        const submissionId = decodeURIComponent(adminUploadsMatch[1]);
        const limit = Math.min(toNumber(url.searchParams.get("limit"), 50), 200);
        const offset = Math.max(toNumber(url.searchParams.get("offset"), 0), 0);
        const { results } = await env.DB.prepare(
          "SELECT id, submission_id, form_id, user_id, field_key, original_name, content_type, size_bytes, sha256, r2_key, uploaded_at, vt_status, vt_verdict, vt_error FROM submission_uploads WHERE submission_id=? AND deleted_at IS NULL ORDER BY uploaded_at DESC LIMIT ? OFFSET ?"
        )
          .bind(submissionId, limit, offset)
          .all();
        return jsonResponse(200, { data: results, requestId }, requestId, corsHeaders);
      }

      if (request.method === "GET" && url.pathname === "/api/admin/canvas/test") {
        if (!env.CANVAS_API_TOKEN) {
          return errorResponse(500, "canvas_not_configured", requestId, corsHeaders);
        }
        const base = getCanvasBaseUrl(env);
        const response = await canvasFetch(env, `${base}/api/v1/users/self`);
        const text = await response.text();
        if (!response.ok) {
          return errorResponse(500, "canvas_test_failed", requestId, corsHeaders, {
            message: `canvas_request_failed:${response.status}:${text}`
          });
        }
        let payload: Record<string, unknown> | null = null;
        try {
          payload = JSON.parse(text) as Record<string, unknown>;
        } catch {
          payload = null;
        }
        return jsonResponse(
          200,
          {
            ok: true,
            canvas_user_id: payload?.id ?? null,
            canvas_name: payload?.name ?? null,
            requestId
          },
          requestId,
          corsHeaders
        );
      }

      const adminFormUploadsMatch = url.pathname.match(/^\/api\/admin\/forms\/([^/]+)\/uploads$/);
      if (request.method === "GET" && adminFormUploadsMatch) {
        const formSlug = decodeURIComponent(adminFormUploadsMatch[1]);
        const limit = Math.min(toNumber(url.searchParams.get("limit"), 50), 200);
        const offset = Math.max(toNumber(url.searchParams.get("offset"), 0), 0);
        const { results } = await env.DB.prepare(
          "SELECT u.id,u.submission_id,u.form_id,u.user_id,u.field_key,u.original_name,u.content_type,u.size_bytes,u.sha256,u.r2_key,u.uploaded_at,u.vt_status,u.vt_verdict,u.vt_error FROM submission_uploads u JOIN forms f ON f.id=u.form_id WHERE f.slug=? AND u.deleted_at IS NULL ORDER BY u.uploaded_at DESC LIMIT ? OFFSET ?"
        )
          .bind(formSlug, limit, offset)
          .all();
        return jsonResponse(200, { data: results, requestId }, requestId, corsHeaders);
      }

      const adminFinalizeMatch = url.pathname.match(/^\/api\/admin\/submissions\/([^/]+)\/finalize$/);
      if (request.method === "POST" && adminFinalizeMatch) {
        const submissionId = decodeURIComponent(adminFinalizeMatch[1]);
        if (!env.DRIVE_PARENT_FOLDER_ID || !getDriveCredentials(env)) {
          return errorResponse(500, "drive_not_configured", requestId, corsHeaders);
        }
        const submission = await env.DB.prepare(
          "SELECT s.id, s.user_id, f.slug, f.is_locked FROM submissions s JOIN forms f ON f.id=s.form_id WHERE s.id=? AND s.deleted_at IS NULL AND f.deleted_at IS NULL"
        )
          .bind(submissionId)
          .first<{ id: string; user_id: string | null; slug: string; is_locked: number }>();
        if (!submission) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        if (toBoolean(submission.is_locked)) {
          return errorResponse(409, "locked", requestId, corsHeaders);
        }
        const userKey = await getUserFolderName(env, submission.user_id);
        const results = await finalizeSubmissionUploads(env, submissionId, userKey);
        return jsonResponse(200, { ok: true, results, requestId }, requestId, corsHeaders);
      }

      if (request.method === "GET" && url.pathname === "/api/admin/drive/form-folder") {
        const slug = url.searchParams.get("slug");
        if (!slug) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "slug required"
          });
        }
        if (!env.DRIVE_PARENT_FOLDER_ID || !getDriveCredentials(env)) {
          return errorResponse(500, "drive_not_configured", requestId, corsHeaders);
        }
        const accessToken = await getDriveAccessToken(env);
        if (!accessToken) {
          return errorResponse(500, "drive_not_configured", requestId, corsHeaders);
        }
        const formFolder = await getOrCreateFormFolder(env, accessToken, slug);
        const created = formFolder.created;
        const formFolderId = formFolder.id;
        return jsonResponse(
          200,
          {
            ok: true,
            slug,
            driveParentId: env.DRIVE_PARENT_FOLDER_ID,
            formFolderId,
            created,
            requestId
          },
          requestId,
          corsHeaders
        );
      }

      if (request.method === "GET" && url.pathname === "/api/admin/drive/check") {
        const formSlug = url.searchParams.get("formSlug");
        const username = url.searchParams.get("username");
        if (!env.DRIVE_PARENT_FOLDER_ID || !getDriveCredentials(env)) {
          return errorResponse(500, "drive_not_configured", requestId, corsHeaders);
        }
        const accessToken = await getDriveAccessToken(env);
        if (!accessToken) {
          return errorResponse(500, "drive_not_configured", requestId, corsHeaders);
        }
        let formFolder: { id: string | null; webViewLink: string | null; created: boolean } | null = null;
        let userFolder: { id: string | null; webViewLink: string | null; created: boolean } | null = null;
        if (formSlug) {
          formFolder = await getOrCreateFormFolder(env, accessToken, formSlug);
        }
        if (formSlug && username && formFolder?.id) {
          const safeName = sanitizeDriveName(username);
          userFolder = await getOrCreateUserFolder(env, accessToken, formSlug, formFolder.id, safeName);
        }
        return jsonResponse(
          200,
          {
            ok: true,
            driveParentId: env.DRIVE_PARENT_FOLDER_ID,
            formFolder,
            userFolder,
            requestId
          },
          requestId,
          corsHeaders
        );
      }

      return errorResponse(404, "not_found", requestId, corsHeaders);
    }

    if (request.method === "GET" && url.pathname === "/api/forms") {
      const { results } = await env.DB.prepare(
        "SELECT slug,title,description,is_locked,is_public,auth_policy,canvas_enabled,canvas_course_id,available_from,available_until,password_required,password_require_access,password_require_submit FROM forms WHERE deleted_at IS NULL AND is_public=1 ORDER BY created_at DESC"
      ).all<FormListRow & { auth_policy: string; description: string | null }>();

      const data = results.map((row) => ({
        slug: row.slug,
        title: row.title,
        description: row.description ?? null,
        is_locked: toBoolean(row.is_locked),
        is_public: toBoolean(row.is_public),
        auth_policy: row.auth_policy,
        canvas_enabled: toBoolean(row.canvas_enabled ?? 0),
        canvas_course_id: row.canvas_course_id ?? null,
        available_from: row.available_from ?? null,
        available_until: row.available_until ?? null,
        password_required: toBoolean(row.password_required ?? 0),
        password_require_access: toBoolean(row.password_require_access ?? 0),
        password_require_submit: toBoolean(row.password_require_submit ?? 0),
        is_open: getFormAvailability(row).open
      }));

      return jsonResponse(200, { data, requestId }, requestId, corsHeaders);
    }

    if (request.method === "GET") {
      const formMatch = url.pathname.match(/^\/api\/forms\/([^/]+)$/);
      if (formMatch) {
        const slug = decodeURIComponent(formMatch[1]);
        const row = await getFormWithRules(env, slug);

        if (!row) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        const accessPassword =
          url.searchParams.get("formPassword") || request.headers.get("x-form-password");
        const accessCheck = await verifyFormPassword(row, accessPassword, "access");
        if (!accessCheck.ok) {
          return errorResponse(403, "invalid_payload", requestId, corsHeaders, {
            field: "formPassword",
            message: accessCheck.message
          });
        }

        const detail = await buildFormDetailPayload(env, row);
        if ("error" in detail) {
          return errorResponse(500, detail.error ?? "unknown_error", requestId, corsHeaders);
        }
        return jsonResponse(200, { data: detail.data, requestId }, requestId, corsHeaders);
      }
    }

    if (request.method === "POST") {
      const accessMatch = url.pathname.match(/^\/api\/forms\/([^/]+)\/access$/);
      if (accessMatch) {
        const slug = decodeURIComponent(accessMatch[1] || "");
        let body: { formPassword?: string } | null = null;
        try {
          body = await parseJsonBody(request);
        } catch (error) {
          return errorResponse(400, "invalid_json", requestId, corsHeaders);
        }
        const row = await getFormWithRules(env, slug);
        if (!row) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        const accessCheck = await verifyFormPassword(row, body?.formPassword, "access");
        if (!accessCheck.ok) {
          return errorResponse(403, "invalid_payload", requestId, corsHeaders, {
            field: "formPassword",
            message: accessCheck.message
          });
        }
        const updateDetail = await buildFormDetailPayload(env, row);
        if ("error" in updateDetail) {
          return errorResponse(500, updateDetail.error ?? "unknown_error", requestId, corsHeaders);
        }
        return jsonResponse(200, { data: updateDetail.data, requestId }, requestId, corsHeaders);
      }

      if (url.pathname === "/api/submissions/upload/init") {
        let body: {
          formSlug?: string;
          fieldKey?: string;
          filename?: string;
          contentType?: string;
          sizeBytes?: number;
          sha256?: string;
          formPassword?: string;
        } | null = null;
        try {
          body = await parseJsonBody(request);
        } catch (error) {
          return errorResponse(400, "invalid_json", requestId, corsHeaders);
        }

        return handleSubmissionUploadInit(request, env, url, requestId, corsHeaders, body || {});
      }

      if (url.pathname === "/api/submissions/upload/put") {
        if (!env.form_app_files) {
          return errorResponse(500, "uploads_unavailable", requestId, corsHeaders);
        }
        const uploadIdParam = url.searchParams.get("uploadId");
        const formData = await request.formData();
        const uploadIdValue = uploadIdParam || formData.get("uploadId");
        const uploadId = typeof uploadIdValue === "string" ? uploadIdValue : "";
        if (!uploadId) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "uploadId",
            message: "required"
          });
        }
        const fileValue = formData.get("file");
        if (!fileValue || typeof fileValue !== 'object' || !('size' in fileValue) || !('type' in fileValue)) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "file",
            message: "required"
          });
        }
        const file = fileValue as File;
        const session = await env.DB.prepare(
          "SELECT id, form_slug, submission_id, user_id, original_name, content_type, size_bytes, sha256, r2_key, status FROM submission_upload_sessions WHERE id=?"
        )
          .bind(uploadId)
          .first<UploadSessionRow>();
        if (!session) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        const authPayload = await getAuthPayload(request, env);
        if (session.user_id && authPayload?.userId && session.user_id !== authPayload.userId) {
          return errorResponse(403, "forbidden", requestId, corsHeaders);
        }
        if (session.size_bytes !== file.size) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "size_mismatch"
          });
        }
        const form = await env.DB.prepare(
          "SELECT is_locked FROM forms WHERE id=? AND deleted_at IS NULL"
        )
          .bind(session.form_id)
          .first<{ is_locked: number }>();
        if (!form) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        if (toBoolean(form.is_locked)) {
          return errorResponse(423, "form_locked", requestId, corsHeaders);
        }

        const buffer = await file.arrayBuffer();
        const sha256 = await hashSha256(buffer);
        if (session.sha256 && session.sha256 !== sha256) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "sha256_mismatch"
          });
        }
        await env.form_app_files.put(session.r2_key, buffer, {
          httpMetadata: {
            contentType: file.type || session.content_type || "application/octet-stream"
          }
        });
        await env.DB.prepare(
          "UPDATE submission_upload_sessions SET sha256=?, status='uploaded' WHERE id=?"
        )
          .bind(sha256, session.id)
          .run();

        return jsonResponse(200, { ok: true, uploadId: session.id, sha256, requestId }, requestId, corsHeaders);
      }

      if (url.pathname === "/api/submissions/upload/commit") {
        let body: { uploadId?: string } | null = null;
        try {
          body = await parseJsonBody(request);
        } catch (error) {
          return errorResponse(400, "invalid_json", requestId, corsHeaders);
        }
        const uploadId = body?.uploadId?.trim();
        if (!uploadId) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "uploadId",
            message: "required"
          });
        }
        if (!env.form_app_files) {
          return errorResponse(500, "uploads_unavailable", requestId, corsHeaders);
        }
        const session = await env.DB.prepare(
          "SELECT id, form_id, form_slug, field_id, submission_id, user_id, original_name, content_type, size_bytes, sha256, r2_key, status FROM submission_upload_sessions WHERE id=?"
        )
          .bind(uploadId)
          .first<UploadSessionRow>();
        if (!session) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        const authPayload = await getAuthPayload(request, env);
        if (session.user_id && authPayload?.userId && session.user_id !== authPayload.userId) {
          return errorResponse(403, "forbidden", requestId, corsHeaders);
        }
        const form = await env.DB.prepare(
          "SELECT id, auth_policy, is_locked FROM forms WHERE id=? AND deleted_at IS NULL"
        )
          .bind(session.form_id)
          .first<FormSubmissionRow & { id: string }>();
        if (!form) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        if (toBoolean(form.is_locked)) {
          return errorResponse(409, "locked", requestId, corsHeaders);
        }
        const authCheck = checkAuthPolicy(form.auth_policy, authPayload);
        if (!authCheck.ok) {
          return errorResponse(authCheck.status!, authCheck.code!, requestId, corsHeaders);
        }

        const object = await env.form_app_files.get(session.r2_key);
        if (!object) {
          return errorResponse(404, "not_found", requestId, corsHeaders, {
            message: "missing_r2_object"
          });
        }
        const buffer = await object.arrayBuffer();
        const sha256 = session.sha256 ?? (await hashSha256(buffer));

        let vtStatus = "skipped";
        let vtVerdict: string | null = null;
        let vtStats = normalizeVtStats({});
        let vtAnalysisId: string | null = null;
        let vtError: string | null = null;
        if (env.VT_API_KEY) {
          const scan = await vtScanBuffer(env, buffer, session.original_name, sha256);
          vtAnalysisId = scan.analysisId ?? null;
          vtStats = scan.stats;
          vtError = scan.error ?? null;
          if (scan.status === "error") {
            vtStatus = "error";
            vtVerdict = "error";
          } else if (scan.status === "completed") {
            vtVerdict = scan.verdict;
            if (scan.verdict === "malicious" || scan.verdict === "suspicious") {
              vtStatus = "malicious";
            } else if (scan.verdict === "clean") {
              vtStatus = "clean";
            } else {
              vtStatus = "pending";
            }
          } else {
            vtVerdict = scan.verdict;
            vtStatus = "pending";
          }
        }

        const fileItemId = crypto.randomUUID();
        await env.DB.prepare(
          "INSERT INTO submission_file_items (id, submission_id, form_id, form_slug, field_id, original_name, mime_type, size_bytes, sha256, r2_key, vt_analysis_id, vt_status, vt_verdict, vt_malicious, vt_suspicious, vt_undetected, vt_timeout, vt_last_checked_at, vt_error, drive_web_view_link) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?, ?)"
        )
          .bind(
            fileItemId,
            session.submission_id,
            session.form_id,
            session.form_slug,
            session.field_id,
            session.original_name,
            session.content_type ?? null,
            session.size_bytes,
            sha256,
            session.r2_key,
            vtAnalysisId,
            vtStatus,
            vtVerdict,
            vtStats.malicious,
            vtStats.suspicious,
            vtStats.undetected,
            vtStats.timeout,
            vtError,
            null
          )
          .run();

        await env.DB.prepare(
          "UPDATE submission_upload_sessions SET status='committed', file_item_id=? WHERE id=?"
        )
          .bind(fileItemId, session.id)
          .run();

        return jsonResponse(
          200,
          {
            ok: true,
            uploadId: session.id,
            fileItemId,
            vt_status: vtStatus,
            vt_verdict: vtVerdict,
            requestId
          },
          requestId,
          corsHeaders
        );
      }

      if (url.pathname === "/api/submissions/upload/finalize") {
        let body: { uploadId?: string } | null = null;
        try {
          body = await parseJsonBody(request);
        } catch (error) {
          return errorResponse(400, "invalid_json", requestId, corsHeaders);
        }
        const uploadId = body?.uploadId?.trim();
        if (!uploadId) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "uploadId",
            message: "required"
          });
        }
        const session = await env.DB.prepare(
          "SELECT id, form_id, form_slug, submission_id, user_id, file_item_id FROM submission_upload_sessions WHERE id=?"
        )
          .bind(uploadId)
          .first<UploadSessionRow>();
        if (!session || !session.file_item_id) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        const authPayload = await getAuthPayload(request, env);
        if (session.user_id && authPayload?.userId && session.user_id !== authPayload.userId) {
          return errorResponse(403, "forbidden", requestId, corsHeaders);
        }
        const form = await env.DB.prepare(
          "SELECT is_locked FROM forms WHERE id=? AND deleted_at IS NULL"
        )
          .bind(session.form_id)
          .first<{ is_locked: number }>();
        if (!form) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        if (toBoolean(form.is_locked)) {
          return errorResponse(409, "locked", requestId, corsHeaders);
        }
        const item = await env.DB.prepare(
          "SELECT id, submission_id, r2_key, original_name, mime_type, vt_status, vt_verdict, final_drive_file_id FROM submission_file_items WHERE id=? AND deleted_at IS NULL"
        )
          .bind(session.file_item_id)
          .first<any>();
        if (!item) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        if (isVtStrict(env) && item.vt_status !== "clean") {
          return errorResponse(409, "vt_not_ready", requestId, corsHeaders, {
            status: item.vt_status,
            verdict: item.vt_verdict
          });
        }
        if (item.final_drive_file_id) {
          return jsonResponse(
            200,
            { ok: true, final_drive_file_id: item.final_drive_file_id, requestId },
            requestId,
            corsHeaders
          );
        }
        const finalized = await finalizeFileItemForUser(env, item, session.form_slug, session.user_id);
        if (!finalized.ok) {
          return errorResponse(500, finalized.error, requestId, corsHeaders);
        }
        return jsonResponse(
          200,
          { ok: true, final_drive_file_id: finalized.driveFileId, requestId },
          requestId,
          corsHeaders
        );
      }



      const uploadMatch = url.pathname.match(/^\/api\/forms\/([^/]+)\/upload$/);
      if (uploadMatch) {
        if (!env.form_app_files) {
          return errorResponse(500, "uploads_unavailable", requestId, corsHeaders);
        }

        const slug = decodeURIComponent(uploadMatch[1]);
        const formRow = await getFormWithRules(env, slug);
        if (!formRow) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        const availability = getFormAvailability(formRow);
        if (!availability.open) {
          return errorResponse(403, "form_closed", requestId, corsHeaders, {
            reason: availability.reason
          });
        }

        const authPayload = await getAuthPayload(request, env);
        const authCheck = checkAuthPolicy(formRow.auth_policy, authPayload);
        if (!authCheck.ok) {
          return errorResponse(authCheck.status!, authCheck.code!, requestId, corsHeaders);
        }

        const formData = await request.formData();
        const fieldIdValue = formData.get("fieldId");
        const submissionIdValue = formData.get("submissionId");
        const passwordValue = formData.get("formPassword");
        const formPassword = typeof passwordValue === "string" ? passwordValue : null;
        const fieldId = typeof fieldIdValue === "string" ? fieldIdValue.trim() : "";
        const submissionId =
          typeof submissionIdValue === "string" && submissionIdValue.trim()
            ? submissionIdValue.trim()
            : null;

        const files: Array<{ fieldKey: string; file: File }> = [];
        for (const entry of formData.entries()) {
          const key = entry[0];
          const value = entry[1];
          if ((key === "files" || key === "files[]") && (value as any) instanceof File) {
            files.push({ fieldKey: "unknown", file: value as any });
          }
        }

        if (!fieldId || files.length === 0) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "fieldId and files are required"
          });
        }
        const passwordCheck = await verifyFormPassword(
          {
            ...formRow,
            password_require_access: formRow.password_require_access as number | null,
            password_require_submit: formRow.password_require_submit as number | null
          },
          formPassword,
          "submit"
        );
        if (!passwordCheck.ok) {
          return errorResponse(403, "invalid_payload", requestId, corsHeaders, {
            field: "formPassword",
            message: passwordCheck.message
          });
        }

        let schema: unknown = null;
        if (formRow.schema_json) {
          try {
            schema = JSON.parse(formRow.schema_json);
          } catch (error) {
            return errorResponse(500, "invalid_schema", requestId, corsHeaders);
          }
        }
        const fields = extractFields(schema);
        const field = fields.find((item) => item.id === fieldId);
        if (!field || field.type !== "file") {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "invalid_field",
            fieldId
          });
        }

        const rulesSource = formRow.form_file_rules_json ?? formRow.template_file_rules_json ?? null;
        const rules = parseFieldRules(rulesSource);
        const rule = getFieldRule(rules, fieldId);

        for (const fileItem of files) {
          const file = fileItem.file;
          if (rule.maxBytes && file.size > rule.maxBytes) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              message: "file_too_large",
              fieldId,
              maxBytes: rule.maxBytes,
              filename: file.name
            });
          }
          if (rule.extensions.length > 0) {
            const ext = getExtension(file.name);
            if (!ext || !rule.extensions.includes(ext)) {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                message: "invalid_extension",
                fieldId,
                filename: file.name
              });
            }
          }
        }

        const userId = await resolveUserId(env, authPayload);
        let targetSubmissionId = submissionId;
        if (!targetSubmissionId && userId) {
          const existing = await env.DB.prepare(
            "SELECT id FROM submissions WHERE form_id=? AND user_id=? AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1"
          )
            .bind(formRow.id, userId)
            .first<{ id: string }>();
          targetSubmissionId = existing?.id ?? null;
        }

        if (!targetSubmissionId) {
          targetSubmissionId = crypto.randomUUID();
          const submitter = getSubmitterSnapshot(authPayload);
          const createdIp = getRequestIp(request);
          const createdUserAgent = request.headers.get("user-agent");
          await env.DB.prepare(
            "INSERT INTO submissions (id, form_id, user_id, payload_json, created_ip, created_user_agent, submitter_provider, submitter_email, submitter_github_username) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
          )
            .bind(
              targetSubmissionId,
              formRow.id,
              userId ?? null,
              "{}",
              createdIp,
              createdUserAgent,
              submitter.provider,
              submitter.email,
              submitter.github
            )
            .run();
        }

        const existingCount = await env.DB.prepare(
          "SELECT COUNT(1) as count FROM submission_file_items WHERE submission_id=? AND field_id=? AND deleted_at IS NULL"
        )
          .bind(targetSubmissionId, fieldId)
          .first<{ count: number }>();
        const currentCount = existingCount?.count ?? 0;
        if (rule.maxFiles && currentCount + files.length > rule.maxFiles) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "max_files_exceeded",
            fieldId,
            maxFiles: rule.maxFiles
          });
        }

        const submission = await env.DB.prepare(
          "SELECT id, user_id FROM submissions WHERE id=? AND form_id=? AND deleted_at IS NULL"
        )
          .bind(targetSubmissionId, formRow.id)
          .first<{ id: string; user_id: string | null }>();
        if (!submission) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "invalid_submission"
          });
        }
        if (userId && submission.user_id && submission.user_id !== userId) {
          return errorResponse(403, "forbidden", requestId, corsHeaders);
        }
        if (userId && !submission.user_id) {
          await env.DB.prepare("UPDATE submissions SET user_id=? WHERE id=?")
            .bind(userId, submission.id)
            .run();
        }

        const strictMode = isVtStrict(env);
        if (!env.VT_API_KEY && strictMode) {
          return errorResponse(500, "vt_not_configured", requestId, corsHeaders);
        }

        const uploaded: Array<{ id: string; original_name: string; size_bytes: number; vt_status: string }> = [];
        for (const fileItem of files) {
          const file = fileItem.file;
          const buffer = await file.arrayBuffer();
          const sha256 = await hashSha256(buffer);
          const safeName = sanitizeFilename(file.name);
          const r2Key = `drafts/${formRow.slug}/${targetSubmissionId}/${fieldId}/${crypto.randomUUID()}-${safeName}`;
          await env.form_app_files.put(r2Key, buffer, {
            httpMetadata: { contentType: file.type || "application/octet-stream" }
          });

          let vtStatus = "skipped";
          let vtVerdict: string | null = null;
          let vtStats = normalizeVtStats({});
          let vtAnalysisId: string | null = null;
          let vtError: string | null = null;

          if (env.VT_API_KEY) {
            const scan = await vtScanBuffer(env, buffer, file.name, sha256);
            vtAnalysisId = scan.analysisId ?? null;
            vtStats = scan.stats;
            vtError = scan.error ?? null;
            if (scan.status === "error") {
              vtStatus = "error";
              vtVerdict = "error";
            } else if (scan.status === "completed") {
              vtVerdict = scan.verdict;
              if (scan.verdict === "malicious" || scan.verdict === "suspicious") {
                vtStatus = "malicious";
              } else if (scan.verdict === "clean") {
                vtStatus = "clean";
              } else {
                vtStatus = "pending";
              }
            } else {
              vtVerdict = scan.verdict;
              vtStatus = "pending";
            }
          }

          const fileItemId = crypto.randomUUID();
          await env.DB.prepare(
            "INSERT INTO submission_file_items (id, submission_id, form_id, form_slug, field_id, original_name, mime_type, size_bytes, sha256, r2_key, vt_analysis_id, vt_status, vt_verdict, vt_malicious, vt_suspicious, vt_undetected, vt_timeout, vt_last_checked_at, vt_error, drive_web_view_link) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?, ?)"
          )
            .bind(
              fileItemId,
              submission.id,
              formRow.id,
              formRow.slug,
              fieldId,
              file.name,
              file.type || null,
              file.size,
              sha256,
              r2Key,
              vtAnalysisId,
              vtStatus,
              vtVerdict,
              vtStats.malicious,
              vtStats.suspicious,
              vtStats.undetected,
              vtStats.timeout,
              vtError,
              null
            )
            .run();

          uploaded.push({ id: fileItemId, original_name: file.name, size_bytes: file.size, vt_status: vtStatus });
        }

        return jsonResponse(
          200,
          { ok: true, uploaded, submissionId: targetSubmissionId, requestId },
          requestId,
          corsHeaders
        );
      }
    }

    if (request.method === "GET") {
      if (url.pathname === "/api/submissions/upload/status") {
        const uploadId = url.searchParams.get("uploadId");
        if (!uploadId) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "uploadId",
            message: "required"
          });
        }
        const session = await env.DB.prepare(
          "SELECT id, form_slug, submission_id, user_id, status, file_item_id FROM submission_upload_sessions WHERE id=?"
        )
          .bind(uploadId)
          .first<UploadSessionRow>();
        if (!session) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        const authPayload = await getAuthPayload(request, env);
        if (session.user_id && authPayload?.userId && session.user_id !== authPayload.userId) {
          return errorResponse(403, "forbidden", requestId, corsHeaders);
        }
        if (!session.file_item_id) {
          return jsonResponse(
            200,
            { data: { uploadId: session.id, status: session.status }, requestId },
            requestId,
            corsHeaders
          );
        }
        const item = await env.DB.prepare(
          "SELECT id, vt_status, vt_verdict, final_drive_file_id, drive_web_view_link FROM submission_file_items WHERE id=? AND deleted_at IS NULL"
        )
          .bind(session.file_item_id)
          .first<any>();
        if (!item) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        return jsonResponse(
          200,
          {
            data: {
              uploadId: session.id,
              status: "committed",
              vt_status: item.vt_status,
              vt_verdict: item.vt_verdict,
              final_drive_file_id: item.final_drive_file_id,
              drive_web_view_link: item.drive_web_view_link
            },
            requestId
          },
          requestId,
          corsHeaders
        );
      }

      const filesMatch = url.pathname.match(/^\/api\/forms\/([^/]+)\/files$/);
      if (filesMatch) {
        const slug = decodeURIComponent(filesMatch[1]);
        const submissionId = url.searchParams.get("submissionId");
        if (!submissionId) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "submissionId",
            message: "required"
          });
        }

        const form = await env.DB.prepare(
          "SELECT id, auth_policy, is_locked, is_public FROM forms WHERE slug=? AND deleted_at IS NULL"
        )
          .bind(slug)
          .first<FormSubmissionRow & { id: string }>();
        if (!form) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }

        const authPayload = await getAuthPayload(request, env);
        if (form.auth_policy !== "optional" && !authPayload) {
          return errorResponse(401, "auth_required", requestId, corsHeaders);
        }

        const submission = await env.DB.prepare(
          "SELECT id, user_id FROM submissions WHERE id=? AND form_id=? AND deleted_at IS NULL"
        )
          .bind(submissionId, form.id)
          .first<{ id: string; user_id: string | null }>();
        if (!submission) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        if (submission.user_id && authPayload?.userId && submission.user_id !== authPayload.userId) {
          return errorResponse(403, "forbidden", requestId, corsHeaders);
        }

        const { results } = await env.DB.prepare(
          "SELECT id, field_id, original_name, mime_type, size_bytes, sha256, r2_key, uploaded_at, vt_status, vt_verdict, vt_malicious, vt_suspicious, vt_undetected, vt_timeout, vt_last_checked_at, final_drive_file_id, finalized_at, drive_web_view_link FROM submission_file_items WHERE submission_id=? AND deleted_at IS NULL ORDER BY uploaded_at DESC"
        )
          .bind(submissionId)
          .all();
        return jsonResponse(200, { data: results, requestId }, requestId, corsHeaders);
      }
    }

    if (request.method === "POST") {
      const checkMatch = url.pathname.match(/^\/api\/forms\/([^/]+)\/files\/([^/]+)\/check$/);
      if (checkMatch) {
        const slug = decodeURIComponent(checkMatch[1]);
        const fileItemId = decodeURIComponent(checkMatch[2]);
        const form = await env.DB.prepare(
          "SELECT id, auth_policy, is_locked, is_public FROM forms WHERE slug=? AND deleted_at IS NULL"
        )
          .bind(slug)
          .first<FormSubmissionRow & { id: string }>();
        if (!form) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }

        const authPayload = await getAuthPayload(request, env);
        if (form.auth_policy !== "optional" && !authPayload) {
          return errorResponse(401, "auth_required", requestId, corsHeaders);
        }

        const item = await env.DB.prepare(
          "SELECT id, submission_id, r2_key, original_name, mime_type, size_bytes, sha256, vt_analysis_id, vt_status, vt_verdict, vt_malicious, vt_suspicious, vt_undetected, vt_timeout, final_drive_file_id, finalized_at, drive_web_view_link FROM submission_file_items WHERE id=? AND form_slug=? AND deleted_at IS NULL"
        )
          .bind(fileItemId, slug)
          .first<any>();
        if (!item) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }

        const submission = await env.DB.prepare("SELECT user_id FROM submissions WHERE id=? AND deleted_at IS NULL")
          .bind(item.submission_id)
          .first<{ user_id: string | null }>();
        if (submission?.user_id && authPayload?.userId && submission.user_id !== authPayload.userId) {
          return errorResponse(403, "forbidden", requestId, corsHeaders);
        }

        if (item.vt_status === "pending" && item.vt_analysis_id && env.VT_API_KEY) {
          const analysis = await vtGetAnalysis(env, item.vt_analysis_id);
          if (!("error" in analysis)) {
            let nextStatus = "pending";
            let nextVerdict = analysis.verdict;
            if (analysis.status === "completed") {
              if (analysis.verdict === "clean") {
                nextStatus = "clean";
              } else if (analysis.verdict === "malicious" || analysis.verdict === "suspicious") {
                nextStatus = "malicious";
              } else {
                nextStatus = "pending";
              }
            }
            await updateFileItemVtStatus(env, item.id, {
              analysisId: item.vt_analysis_id,
              status: nextStatus,
              verdict: nextVerdict,
              malicious: analysis.stats.malicious,
              suspicious: analysis.stats.suspicious,
              undetected: analysis.stats.undetected,
              timeout: analysis.stats.timeout,
              error: null
            });
            item.vt_status = nextStatus;
            item.vt_verdict = nextVerdict;
            item.vt_malicious = analysis.stats.malicious;
            item.vt_suspicious = analysis.stats.suspicious;
            item.vt_undetected = analysis.stats.undetected;
            item.vt_timeout = analysis.stats.timeout;
          }
        }

        if (
          item.vt_status === "clean" &&
          !item.final_drive_file_id &&
          env.form_app_files &&
          env.DRIVE_PARENT_FOLDER_ID &&
          getDriveCredentials(env)
        ) {
          const accessToken = await getDriveAccessToken(env);
          if (!accessToken) {
            return errorResponse(500, "drive_not_configured", requestId, corsHeaders);
          }
          const formFolder = await getOrCreateFormFolder(env, accessToken, slug);
          const userKey = await getUserFolderName(env, submission?.user_id ?? null);
          const userFolder = formFolder.id
            ? await getOrCreateUserFolder(env, accessToken, slug, formFolder.id, userKey)
            : { id: null };
          if (userFolder.id) {
            const object = await env.form_app_files.get(item.r2_key);
            if (object) {
              const buffer = await object.arrayBuffer();
              const contentType = object.httpMetadata?.contentType || "application/octet-stream";
              const uploaded = await uploadFileToDrive(
                env,
                accessToken,
                userFolder.id,
                item.original_name,
                contentType,
                new Uint8Array(buffer)
              );
              if (uploaded && uploaded.id) {
                await env.DB.prepare(
                  "UPDATE submission_file_items SET final_drive_file_id=?, finalized_at=datetime('now'), drive_web_view_link=? WHERE id=?"
                )
                  .bind(uploaded.id, uploaded.webViewLink ?? null, item.id)
                  .run();
                item.final_drive_file_id = uploaded.id;
                item.finalized_at = new Date().toISOString();
                item.drive_web_view_link = uploaded.webViewLink ?? null;
              }
            }
          }
        }

        return jsonResponse(200, { data: item, requestId }, requestId, corsHeaders);
      }
    }

    if (request.method === "DELETE") {
      const deleteMatch = url.pathname.match(/^\/api\/forms\/([^/]+)\/files\/([^/]+)$/);
      if (deleteMatch) {
        const slug = decodeURIComponent(deleteMatch[1]);
        const fileItemId = decodeURIComponent(deleteMatch[2]);
        const form = await env.DB.prepare(
          "SELECT id, auth_policy, is_locked, is_public FROM forms WHERE slug=? AND deleted_at IS NULL"
        )
          .bind(slug)
          .first<FormSubmissionRow & { id: string }>();
        if (!form) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        if (toBoolean(form.is_locked)) {
          return errorResponse(409, "locked", requestId, corsHeaders);
        }

        const authPayload = await getAuthPayload(request, env);
        const authCheck = checkAuthPolicy(form.auth_policy, authPayload);
        if (!authCheck.ok) {
          return errorResponse(authCheck.status!, authCheck.code!, requestId, corsHeaders);
        }

        const item = await env.DB.prepare(
          "SELECT id, submission_id, r2_key FROM submission_file_items WHERE id=? AND form_slug=? AND deleted_at IS NULL"
        )
          .bind(fileItemId, slug)
          .first<{ id: string; submission_id: string; r2_key: string }>();
        if (!item) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }

        const submission = await env.DB.prepare("SELECT user_id FROM submissions WHERE id=? AND deleted_at IS NULL")
          .bind(item.submission_id)
          .first<{ user_id: string | null }>();
        if (submission?.user_id && authPayload?.userId && submission.user_id !== authPayload.userId) {
          return errorResponse(403, "forbidden", requestId, corsHeaders);
        }

        if (env.form_app_files) {
          await env.form_app_files.delete(item.r2_key);
        }
        await env.DB.prepare(
          "UPDATE submission_file_items SET deleted_at=datetime('now'), deleted_by=?, deleted_reason='user_deleted' WHERE id=?"
        )
          .bind(authPayload?.userId ?? null, item.id)
          .run();

        return jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
      }
    }

    if (request.method === "POST") {
      const finalizeMatch = url.pathname.match(/^\/api\/forms\/([^/]+)\/files\/finalize-all$/);
      if (finalizeMatch) {
        const slug = decodeURIComponent(finalizeMatch[1]);
        const submissionId = url.searchParams.get("submissionId");
        if (!submissionId) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "submissionId",
            message: "required"
          });
        }

        const form = await env.DB.prepare(
          "SELECT id, auth_policy, is_locked, is_public FROM forms WHERE slug=? AND deleted_at IS NULL"
        )
          .bind(slug)
          .first<FormSubmissionRow & { id: string }>();
        if (!form) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }

        const authPayload = await getAuthPayload(request, env);
        const authCheck = checkAuthPolicy(form.auth_policy, authPayload);
        if (!authCheck.ok) {
          return errorResponse(authCheck.status!, authCheck.code!, requestId, corsHeaders);
        }

        const submission = await env.DB.prepare("SELECT user_id FROM submissions WHERE id=? AND form_id=? AND deleted_at IS NULL")
          .bind(submissionId, form.id)
          .first<{ user_id: string | null }>();
        if (!submission) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        if (submission.user_id && authPayload?.userId && submission.user_id !== authPayload.userId) {
          return errorResponse(403, "forbidden", requestId, corsHeaders);
        }

        const { results } = await env.DB.prepare(
          "SELECT id, r2_key, original_name, vt_status, vt_verdict, final_drive_file_id, drive_web_view_link FROM submission_file_items WHERE submission_id=? AND deleted_at IS NULL"
        )
          .bind(submissionId)
          .all<any>();

        if (isVtStrict(env)) {
          const blocked = results.filter((item) => item.vt_status !== "clean");
          if (blocked.length > 0) {
            return errorResponse(409, "vt_not_ready", requestId, corsHeaders, {
              blocked: blocked.map((item) => ({ id: item.id, status: item.vt_status, verdict: item.vt_verdict }))
            });
          }
        }

        if (!env.form_app_files || !env.DRIVE_PARENT_FOLDER_ID || !getDriveCredentials(env)) {
          return errorResponse(500, "drive_not_configured", requestId, corsHeaders);
        }

        const accessToken = await getDriveAccessToken(env);
        if (!accessToken) {
          return errorResponse(500, "drive_not_configured", requestId, corsHeaders);
        }
        const formFolder = await getOrCreateFormFolder(env, accessToken, slug);
        const userKey = await getUserFolderName(env, submission?.user_id ?? null);
        const userFolder = formFolder.id
          ? await getOrCreateUserFolder(env, accessToken, slug, formFolder.id, userKey)
          : { id: null };

        const finalized: Array<{ id: string; status: string; driveFileId?: string | null }> = [];
        for (const item of results) {
          if (item.final_drive_file_id || item.vt_status !== "clean") {
            finalized.push({ id: item.id, status: item.vt_status || "skipped", driveFileId: item.final_drive_file_id });
            continue;
          }
          if (!userFolder.id) {
            finalized.push({ id: item.id, status: "drive_unavailable" });
            continue;
          }
          const object = await env.form_app_files.get(item.r2_key);
          if (!object) {
            finalized.push({ id: item.id, status: "missing_r2" });
            continue;
          }
          const buffer = await object.arrayBuffer();
          const contentType = object.httpMetadata?.contentType || "application/octet-stream";
          const uploaded = await uploadFileToDrive(
            env,
            accessToken,
            userFolder.id,
            item.original_name,
            contentType,
            new Uint8Array(buffer)
          );
          if (uploaded && uploaded.id) {
            await env.DB.prepare(
              "UPDATE submission_file_items SET final_drive_file_id=?, finalized_at=datetime('now'), drive_web_view_link=? WHERE id=?"
            )
              .bind(uploaded.id, uploaded.webViewLink ?? null, item.id)
              .run();
          }
          if (uploaded && uploaded.id) {
            finalized.push({ id: item.id, status: "finalized", driveFileId: uploaded.id });
          } else {
            finalized.push({ id: item.id, status: "drive_error" });
          }
        }

        return jsonResponse(200, { data: finalized, requestId }, requestId, corsHeaders);
      }
    }

    if (request.method === "GET") {
      const mySubmissionMatch = url.pathname.match(/^\/api\/forms\/([^/]+)\/my-submission$/);
      if (mySubmissionMatch) {
        const slug = decodeURIComponent(mySubmissionMatch[1]);
        const form = await env.DB.prepare(
          "SELECT id, auth_policy, is_locked, is_public FROM forms WHERE slug=? AND deleted_at IS NULL"
        )
          .bind(slug)
          .first<FormSubmissionRow>();

        if (!form) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }

        const authPayload = await getAuthPayload(request, env);
        if (form.auth_policy !== "optional") {
          if (!authPayload) {
            return errorResponse(401, "auth_required", requestId, corsHeaders);
          }
          if (form.auth_policy === "google" && authPayload.provider !== "google") {
            return errorResponse(403, "auth_forbidden", requestId, corsHeaders);
          }
          if (form.auth_policy === "github" && authPayload.provider !== "github") {
            return errorResponse(403, "auth_forbidden", requestId, corsHeaders);
          }
          if (
            form.auth_policy === "either" &&
            authPayload.provider !== "google" &&
            authPayload.provider !== "github"
          ) {
            return errorResponse(403, "auth_forbidden", requestId, corsHeaders);
          }
        } else if (!authPayload) {
          return jsonResponse(200, { data: null, requestId }, requestId, corsHeaders);
        }

        const submission = await env.DB.prepare(
          "SELECT id,payload_json,created_at,updated_at FROM submissions WHERE form_id=? AND user_id=? AND deleted_at IS NULL ORDER BY COALESCE(updated_at, created_at) DESC LIMIT 1"
        )
          .bind(form.id, authPayload?.userId ?? null)
          .first<SubmissionDetailRow>();

        if (!submission) {
          return jsonResponse(200, { data: null, requestId }, requestId, corsHeaders);
        }

        let payload: { data?: unknown; files?: unknown } | null = null;
        try {
          payload = JSON.parse(submission.payload_json);
        } catch (error) {
          payload = null;
        }

        return jsonResponse(
          200,
          {
            data: {
              id: submission.id,
              data: payload?.data ?? null,
              files: payload?.files ?? null,
              created_at: submission.created_at,
              updated_at: submission.updated_at
            },
            requestId
          },
          requestId,
          corsHeaders
        );
      }
    }

    if (request.method === "GET" && url.pathname === "/api/me/dashboard") {
      const authPayload = await getAuthPayload(request, env);
      if (!authPayload) {
        return errorResponse(401, "auth_required", requestId, corsHeaders);
      }

      const { results } = await env.DB.prepare(
        "SELECT f.slug as form_slug,f.title as form_title,f.is_locked,f.is_public,MAX(COALESCE(s.updated_at, s.created_at)) as last_submitted_at FROM submissions s JOIN forms f ON f.id=s.form_id WHERE s.user_id=? AND s.deleted_at IS NULL AND f.deleted_at IS NULL GROUP BY f.id ORDER BY last_submitted_at DESC"
      )
        .bind(authPayload.userId)
        .all<{
          form_slug: string;
          form_title: string;
          is_locked: number;
          is_public: number;
          last_submitted_at: string;
        }>();

      const data = results.map((row) => ({
        form_slug: row.form_slug,
        form_title: row.form_title,
        is_locked: toBoolean(row.is_locked),
        is_public: toBoolean(row.is_public),
        last_submitted_at: row.last_submitted_at,
        link: `/forms/#/f/${row.form_slug}`
      }));

      return jsonResponse(200, { data, requestId }, requestId, corsHeaders);
    }

    if (request.method === "GET" && url.pathname === "/api/me") {
      const authPayload = await getAuthPayload(request, env);
      if (!authPayload) {
        return errorResponse(401, "auth_required", requestId, corsHeaders);
      }
      await ensureIdentityFromAuthPayload(env, authPayload);
      const identities = await getUserIdentities(env, authPayload.userId);
      let canvasInfo: {
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
      } | null = null;
      if (authPayload.email && env.CANVAS_API_TOKEN) {
        const lookup = await canvasFindUserByEmail(env, authPayload.email);
        let courseId: string | null = null;
        let courseName: string | null = null;
        let courseCode: string | null = null;
        let enrolledAt: string | null = null;
        let status: string | null = null;
        let sectionId: string | null = null;
        let sectionName: string | null = null;
        let submissionDeleted = false;
        const courseRow = await env.DB.prepare(
          "SELECT s.id as submission_id,s.canvas_course_id as course_id,s.canvas_section_id as section_id,s.canvas_enroll_status as status,s.canvas_enrolled_at as enrolled_at,s.deleted_at as submission_deleted,cc.name as course_name,cc.code as course_code,cs.name as section_name,f.title as form_title FROM submissions s LEFT JOIN canvas_courses_cache cc ON cc.id=s.canvas_course_id LEFT JOIN canvas_sections_cache cs ON cs.id=s.canvas_section_id LEFT JOIN forms f ON f.id=s.form_id WHERE s.user_id=? AND s.canvas_course_id IS NOT NULL ORDER BY COALESCE(s.canvas_enrolled_at, s.updated_at, s.created_at) DESC LIMIT 1"
        )
          .bind(authPayload.userId)
          .first<{
            submission_id: string | null;
            course_id: string | null;
            section_id: string | null;
            status: string | null;
            enrolled_at: string | null;
            submission_deleted: string | null;
            course_name: string | null;
            course_code: string | null;
            section_name: string | null;
            form_title: string | null;
          }>();
        if (courseRow) {
          courseId = courseRow.course_id ?? null;
          courseName = courseRow.course_name ?? null;
          courseCode = courseRow.course_code ?? null;
          sectionId = courseRow.section_id ?? null;
          sectionName = courseRow.section_name ?? null;
          enrolledAt = courseRow.enrolled_at ?? null;
          status = courseRow.status ?? null;
          submissionDeleted = Boolean(courseRow.submission_deleted);
        }
        canvasInfo = {
          user_id: lookup.id ?? null,
          name: lookup.name ?? null,
          course_id: courseId,
          course_name: courseName,
          course_code: courseCode,
          section_id: sectionId,
          section_name: sectionName,
          status,
          enrolled_at: enrolledAt,
          form_title: courseRow?.form_title ?? null,
          submission_id: courseRow?.submission_id ?? null,
          submission_deleted: submissionDeleted
        };
      }
      return jsonResponse(
        200,
        {
          user: {
            userId: authPayload.userId,
            provider: authPayload.provider,
            email: authPayload.email ?? null,
            isAdmin: authPayload.isAdmin
          },
          identities,
          canvas: canvasInfo,
          requestId
        },
        requestId,
        corsHeaders
      );
    }

    if (request.method === "GET" && url.pathname === "/api/me/identities") {
      const authPayload = await getAuthPayload(request, env);
      if (!authPayload) {
        return errorResponse(401, "auth_required", requestId, corsHeaders);
      }
      await ensureIdentityFromAuthPayload(env, authPayload);
      const identities = await getUserIdentities(env, authPayload.userId);
      return jsonResponse(200, { data: identities, requestId }, requestId, corsHeaders);
    }

    if (request.method === "GET" && url.pathname === "/api/me/emails") {
      const authPayload = await getAuthPayload(request, env);
      if (!authPayload) {
        return errorResponse(401, "auth_required", requestId, corsHeaders);
      }
      await ensureIdentityFromAuthPayload(env, authPayload);
      const identities = await getUserIdentities(env, authPayload.userId);
      const emails = new Set<string>();
      if (authPayload.email) {
        emails.add(authPayload.email.trim().toLowerCase());
      }
      identities.forEach((identity) => {
        if (identity.email) {
          emails.add(identity.email.trim().toLowerCase());
        }
      });
      const emailList = Array.from(emails).filter(Boolean);
      if (emailList.length === 0) {
        return jsonResponse(200, { data: [], page: 1, pageSize: 50, total: 0, requestId }, requestId, corsHeaders);
      }
      const page = Math.max(toNumber(url.searchParams.get("page"), 1), 1);
      const pageSize = Math.min(Math.max(toNumber(url.searchParams.get("pageSize"), 50), 1), 200);
      let canSoftDelete = await hasEmailLogsSoftDelete(env);
      const where: string[] = [];
      const params: Array<string | number> = [];
      const placeholders = emailList.map(() => "?").join(",");
      where.push(`lower(l.to_email) IN (${placeholders})`);
      params.push(...emailList);
      if (canSoftDelete) {
        where.push("l.deleted_at IS NULL");
      }
      const whereClause = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";
      const deletedAtSelect = (await hasColumn(env, "email_logs", "deleted_at"))
        ? "l.deleted_at as deleted_at"
        : "NULL as deleted_at";
      const deletedBySelect = (await hasColumn(env, "email_logs", "deleted_by"))
        ? "l.deleted_by as deleted_by"
        : "NULL as deleted_by";
      const deletedReasonSelect = (await hasColumn(env, "email_logs", "deleted_reason"))
        ? "l.deleted_reason as deleted_reason"
        : "NULL as deleted_reason";
      const formSlugSelect = (await hasColumn(env, "email_logs", "form_slug"))
        ? "COALESCE(l.form_slug,f.slug) as form_slug"
        : "f.slug as form_slug";
      const formTitleSelect = (await hasColumn(env, "email_logs", "form_title"))
        ? "COALESCE(l.form_title,f.title) as form_title"
        : "f.title as form_title";
      const selectFields = [
        "l.id",
        "l.to_email",
        "l.subject",
        "l.body",
        "l.status",
        "l.error",
        "l.submission_id",
        "l.form_id",
        formSlugSelect,
        formTitleSelect,
        "l.canvas_course_id",
        "l.canvas_section_id",
        "l.triggered_by",
        "l.trigger_source",
        "l.created_at",
        deletedAtSelect,
        deletedBySelect,
        deletedReasonSelect
      ].join(",");
      const limit = pageSize;
      const offset = (page - 1) * pageSize;
      let total = 0;
      let results: unknown[] = [];
      try {
        const totalRow = await env.DB.prepare(
          `SELECT COUNT(1) as total FROM email_logs l ${whereClause}`
        )
          .bind(...params)
          .first<{ total: number }>();
        total = totalRow?.total ?? 0;
        const response = await env.DB.prepare(
          `SELECT ${selectFields} FROM email_logs l LEFT JOIN forms f ON f.id=l.form_id ${whereClause} ORDER BY l.created_at DESC LIMIT ? OFFSET ?`
        )
          .bind(...params, limit, offset)
          .all();
        results = response.results;
      } catch (error) {
        const message = String((error as Error)?.message || error);
        if (canSoftDelete && message.includes("no such column: l.deleted_at")) {
          EMAIL_LOGS_SOFT_DELETE = false;
          const idx = where.indexOf("l.deleted_at IS NULL");
          if (idx >= 0) {
            where.splice(idx, 1);
          }
          const nextWhereClause = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";
          const totalRow = await env.DB.prepare(
            `SELECT COUNT(1) as total FROM email_logs l ${nextWhereClause}`
          )
            .bind(...params)
            .first<{ total: number }>();
          total = totalRow?.total ?? 0;
          const response = await env.DB.prepare(
            `SELECT ${selectFields} FROM email_logs l LEFT JOIN forms f ON f.id=l.form_id ${nextWhereClause} ORDER BY l.created_at DESC LIMIT ? OFFSET ?`
          )
            .bind(...params, limit, offset)
            .all();
          results = response.results;
        } else {
          throw error;
        }
      }
      return jsonResponse(200, { data: results, page, pageSize, total, requestId }, requestId, corsHeaders);
    }

    if (request.method === "GET" && url.pathname === "/api/me/submissions") {
      const authPayload = await getAuthPayload(request, env);
      if (!authPayload) {
        return errorResponse(401, "auth_required", requestId, corsHeaders);
      }

      const { results } = await env.DB.prepare(
        "SELECT f.slug as form_slug,f.title as form_title,f.is_locked,f.is_public,f.auth_policy,f.deleted_at as form_deleted_at,MAX(COALESCE(s.updated_at, s.created_at)) as last_submitted_at,COUNT(s.id) as submissions_count,(SELECT s2.id FROM submissions s2 WHERE s2.form_id=f.id AND s2.user_id=? AND s2.deleted_at IS NULL ORDER BY COALESCE(s2.updated_at, s2.created_at) DESC LIMIT 1) as submission_id,(SELECT s2.created_at FROM submissions s2 WHERE s2.form_id=f.id AND s2.user_id=? AND s2.deleted_at IS NULL ORDER BY COALESCE(s2.updated_at, s2.created_at) DESC LIMIT 1) as created_at,(SELECT s2.updated_at FROM submissions s2 WHERE s2.form_id=f.id AND s2.user_id=? AND s2.deleted_at IS NULL ORDER BY COALESCE(s2.updated_at, s2.created_at) DESC LIMIT 1) as updated_at FROM submissions s LEFT JOIN forms f ON f.id=s.form_id WHERE s.user_id=? AND s.deleted_at IS NULL GROUP BY f.id ORDER BY last_submitted_at DESC"
      )
        .bind(authPayload.userId, authPayload.userId, authPayload.userId, authPayload.userId)
        .all<{
          form_slug: string | null;
          form_title: string | null;
          is_locked: number | null;
          is_public: number | null;
          auth_policy: string | null;
          form_deleted_at: string | null;
          last_submitted_at: string;
          submissions_count: number | null;
          submission_id: string | null;
          created_at: string | null;
          updated_at: string | null;
        }>();

      const data = results.map((row) => {
        const isLocked = toBoolean(row.is_locked);
        const isDeleted = Boolean(row.form_deleted_at);
        return {
          form_slug: row.form_slug ?? "unknown",
          form_title: row.form_title ?? "Deleted form",
          is_locked: isLocked,
          is_public: toBoolean(row.is_public),
          auth_policy: row.auth_policy ?? "optional",
          latest_submission_id: row.submission_id ?? null,
          latest_created_at: row.created_at ?? null,
          latest_updated_at: row.updated_at ?? null,
          count_submissions: row.submissions_count ?? 0,
          form: {
            slug: row.form_slug ?? "unknown",
            title: row.form_title ?? "Deleted form",
            is_locked: isLocked,
            is_public: toBoolean(row.is_public),
            auth_policy: row.auth_policy ?? "optional",
            deleted_at: row.form_deleted_at ?? null
          },
          latestSubmission: {
            id: row.submission_id ?? null,
            created_at: row.created_at ?? null,
            updated_at: row.updated_at ?? null
          },
          canEdit: !isLocked && !isDeleted
        };
      });

      return jsonResponse(200, { data, requestId }, requestId, corsHeaders);
    }

    const meSubmissionMatch = url.pathname.match(/^\/api\/me\/submissions\/([^/]+)$/);
    if (request.method === "GET" && meSubmissionMatch) {
      const submissionId = decodeURIComponent(meSubmissionMatch[1] || "").trim();
      if (!submissionId) {
        return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
          field: "id",
          message: "required"
        });
      }

      const authPayload = await getAuthPayload(request, env);
      if (!authPayload) {
        return errorResponse(401, "auth_required", requestId, corsHeaders);
      }

      const reminderEnabledSelect = (await hasColumn(env, "forms", "reminder_enabled"))
        ? "f.reminder_enabled as reminder_enabled"
        : "NULL as reminder_enabled";
      const reminderFrequencySelect = (await hasColumn(env, "forms", "reminder_frequency"))
        ? "f.reminder_frequency as reminder_frequency"
        : "NULL as reminder_frequency";
      const reminderUntilSelect = (await hasColumn(env, "forms", "reminder_until"))
        ? "f.reminder_until as reminder_until"
        : "NULL as reminder_until";
      const createdIpSelect = (await hasColumn(env, "submissions", "created_ip"))
        ? "s.created_ip as created_ip"
        : "NULL as created_ip";
      const createdUserAgentSelect = (await hasColumn(env, "submissions", "created_user_agent"))
        ? "s.created_user_agent as created_user_agent"
        : "NULL as created_user_agent";
      const submitterProviderSelect = (await hasColumn(env, "submissions", "submitter_provider"))
        ? "COALESCE(s.submitter_provider,(SELECT provider FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1)) as submitter_provider"
        : "(SELECT provider FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1) as submitter_provider";
      const submitterEmailSelect = (await hasColumn(env, "submissions", "submitter_email"))
        ? "COALESCE(s.submitter_email,(SELECT email FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1)) as submitter_email"
        : "(SELECT email FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1) as submitter_email";
      const submitterGithubSelect = (await hasColumn(env, "submissions", "submitter_github_username"))
        ? "COALESCE(s.submitter_github_username,(SELECT provider_login FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1)) as submitter_github_username"
        : "(SELECT provider_login FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1) as submitter_github_username";
      const submission = await env.DB.prepare(
        `SELECT s.id,s.form_id,s.user_id,s.payload_json,s.created_at,s.updated_at,${createdIpSelect},${createdUserAgentSelect},${submitterProviderSelect},${submitterEmailSelect},${submitterGithubSelect},s.canvas_enroll_status,s.canvas_enroll_error,s.canvas_course_id,s.canvas_section_id,s.canvas_enrolled_at,s.canvas_user_id,s.canvas_user_name,f.slug as form_slug,f.title as form_title,f.is_locked,f.is_public,f.auth_policy,f.save_all_versions,${reminderEnabledSelect},${reminderFrequencySelect},${reminderUntilSelect} FROM submissions s JOIN forms f ON f.id=s.form_id WHERE s.id=? AND s.deleted_at IS NULL`
      )
        .bind(submissionId)
        .first<{
          id: string;
          form_id: string;
          user_id: string | null;
          payload_json: string;
          created_at: string | null;
          updated_at: string | null;
          created_ip: string | null;
          created_user_agent: string | null;
          submitter_provider: string | null;
          submitter_email: string | null;
          submitter_github_username: string | null;
          canvas_enroll_status: string | null;
          canvas_enroll_error: string | null;
          canvas_course_id: string | null;
          canvas_section_id: string | null;
          canvas_enrolled_at: string | null;
          canvas_user_id: string | null;
          canvas_user_name: string | null;
          form_slug: string;
          form_title: string;
          is_locked: number;
          is_public: number;
          auth_policy: string | null;
          save_all_versions: number | null;
          reminder_enabled: number | null;
          reminder_frequency: string | null;
          reminder_until: string | null;
        }>();

      if (!submission) {
        return errorResponse(404, "not_found", requestId, corsHeaders);
      }

      if (!authPayload.isAdmin && submission.user_id !== authPayload.userId) {
        return errorResponse(403, "forbidden", requestId, corsHeaders);
      }

      let payload: { data?: unknown } | null = null;
      try {
        payload = JSON.parse(submission.payload_json);
      } catch (error) {
        payload = null;
      }

      const filesResult = await env.DB.prepare(
        "SELECT id, field_id, original_name, size_bytes, vt_status, vt_verdict, final_drive_file_id, finalized_at, drive_web_view_link FROM submission_file_items WHERE submission_id=? AND deleted_at IS NULL ORDER BY uploaded_at DESC"
      )
        .bind(submission.id)
        .all();

      let canvasFullName: string | null = null;
      let canvasDisplayName: string | null = submission.canvas_user_name || null;
      if (submission.canvas_course_id) {
        let email =
          (payload?.data && typeof (payload as any).data?.email === "string"
            ? String((payload as any).data.email).trim()
            : "") || "";
        if (!email) {
          const emailRow = await env.DB.prepare(
            "SELECT email FROM user_identities WHERE user_id=? AND email IS NOT NULL ORDER BY created_at DESC LIMIT 1"
          )
            .bind(submission.user_id ?? "")
            .first<{ email: string | null }>();
          email = emailRow?.email ?? "";
        }
        if (email) {
          const canvasUser = await canvasFindUserByEmailInCourse(env, submission.canvas_course_id, email);
          canvasFullName = canvasUser?.name?.trim() || null;
          canvasDisplayName = canvasUser?.shortName?.trim() || canvasDisplayName;
        }
      }

      return jsonResponse(
        200,
        {
          data: {
            submissionId: submission.id,
            user_id: submission.user_id ?? null,
            submitter: {
              provider: submission.submitter_provider ?? null,
              email: submission.submitter_email ?? null,
              github_username: submission.submitter_github_username ?? null
            },
            created_ip: submission.created_ip ?? null,
            created_user_agent: submission.created_user_agent ?? null,
            data_json: payload?.data ?? null,
            files: Array.isArray(filesResult?.results) ? filesResult.results : [],
            created_at: submission.created_at,
            updated_at: submission.updated_at,
            canvas: {
              status: submission.canvas_enroll_status,
              error: submission.canvas_enroll_error,
              course_id: submission.canvas_course_id,
              section_id: submission.canvas_section_id,
              enrolled_at: submission.canvas_enrolled_at,
              user_id: submission.canvas_user_id,
              user_name: submission.canvas_user_name,
              full_name: canvasFullName,
              display_name: canvasDisplayName
            },
            form: {
              slug: submission.form_slug,
              title: submission.form_title,
              is_locked: toBoolean(submission.is_locked),
              is_public: toBoolean(submission.is_public),
              auth_policy: submission.auth_policy ?? "optional",
              save_all_versions: toBoolean(submission.save_all_versions ?? 0),
              reminder_enabled: toBoolean(submission.reminder_enabled ?? 0),
              reminder_frequency: submission.reminder_frequency ?? null,
              reminder_until: submission.reminder_until ?? null
            }
          },
          requestId
        },
        requestId,
        corsHeaders
      );
    }

    if (request.method === "GET" && url.pathname === "/api/me/trash") {
      const authPayload = await getAuthPayload(request, env);
      if (!authPayload) {
        return errorResponse(401, "auth_required", requestId, corsHeaders);
      }
      const type = (url.searchParams.get("type") || "all").toLowerCase();
      const page = Math.max(toNumber(url.searchParams.get("page"), 1), 1);
      const pageSize = Math.min(Math.max(toNumber(url.searchParams.get("pageSize"), 50), 1), 200);
      const limit = pageSize;
      const offset = (page - 1) * pageSize;
      const data: Record<string, unknown> = {};
      const totals: Record<string, number> = {};

      if (type === "all" || type === "submissions") {
        const total = await env.DB.prepare(
          "SELECT COUNT(1) as total FROM submissions WHERE deleted_at IS NOT NULL AND user_id=?"
        )
          .bind(authPayload.userId)
          .first<{ total: number }>();
        totals.submissions = total?.total ?? 0;
        const { results } = await env.DB.prepare(
          "SELECT s.id,s.form_id,f.slug as form_slug,f.title as form_title,s.deleted_at,s.deleted_by,s.deleted_reason FROM submissions s LEFT JOIN forms f ON f.id=s.form_id WHERE s.deleted_at IS NOT NULL AND s.user_id=? ORDER BY s.deleted_at DESC LIMIT ? OFFSET ?"
        )
          .bind(authPayload.userId, limit, offset)
          .all();
        data.submissions = results;
      }

      if (type === "all" || type === "files") {
        const total = await env.DB.prepare(
          "SELECT COUNT(1) as total FROM submission_file_items WHERE deleted_at IS NOT NULL AND submission_id IN (SELECT id FROM submissions WHERE user_id=?)"
        )
          .bind(authPayload.userId)
          .first<{ total: number }>();
        totals.files = total?.total ?? 0;
        const { results } = await env.DB.prepare(
          "SELECT sfi.id, sfi.form_slug, f.title as form_title, sfi.submission_id, sfi.field_id, sfi.original_name, sfi.size_bytes, sfi.deleted_at, sfi.deleted_by, sfi.deleted_reason FROM submission_file_items sfi LEFT JOIN forms f ON f.slug=sfi.form_slug WHERE sfi.deleted_at IS NOT NULL AND sfi.submission_id IN (SELECT id FROM submissions WHERE user_id=?) ORDER BY sfi.deleted_at DESC LIMIT ? OFFSET ?"
        )
          .bind(authPayload.userId, limit, offset)
          .all();
        data.files = results;
      }

      return jsonResponse(200, { data, totals, page, pageSize, requestId }, requestId, corsHeaders);
    }

    if (request.method === "POST" && url.pathname === "/api/me/trash/restore") {
      const authPayload = await getAuthPayload(request, env);
      if (!authPayload) {
        return errorResponse(401, "auth_required", requestId, corsHeaders);
      }
      let body: { type?: string; id?: string } | null = null;
      try {
        body = await parseJsonBody(request);
      } catch (error) {
        return errorResponse(400, "invalid_json", requestId, corsHeaders);
      }
      const type = body?.type?.toLowerCase();
      const id = body?.id?.trim();
      if (!type || !id) {
        return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
          message: "type and id are required"
        });
      }
      if (type === "submission") {
        const row = await env.DB.prepare(
          "SELECT id FROM submissions WHERE id=? AND user_id=? AND deleted_at IS NOT NULL"
        )
          .bind(id, authPayload.userId)
          .first<{ id: string }>();
        if (!row) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        const result = await restoreSubmission(env, id);
        return jsonResponse(
          200,
          {
            ok: true,
            canvasWarning: result.canvasError || null,
            canvasAction: result.canvasStatus || null,
            requestId
          },
          requestId,
          corsHeaders
        );
      }

      if (type === "file") {
        const row = await env.DB.prepare(
          "SELECT sfi.id FROM submission_file_items sfi WHERE sfi.id=? AND sfi.deleted_at IS NOT NULL AND sfi.submission_id IN (SELECT id FROM submissions WHERE user_id=?)"
        )
          .bind(id, authPayload.userId)
          .first<{ id: string }>();
        if (!row) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        await restoreFileItem(env, id);
        return jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
      }
      return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
        message: "unsupported_type"
      });
    }

    if (request.method === "POST" && url.pathname === "/api/me/trash/purge") {
      const authPayload = await getAuthPayload(request, env);
      if (!authPayload) {
        return errorResponse(401, "auth_required", requestId, corsHeaders);
      }
      return errorResponse(403, "forbidden", requestId, corsHeaders);
    }
    if (request.method === "POST" && url.pathname === "/api/me/trash/empty") {
      const authPayload = await getAuthPayload(request, env);
      if (!authPayload) {
        return errorResponse(401, "auth_required", requestId, corsHeaders);
      }
      return errorResponse(403, "forbidden", requestId, corsHeaders);
    }
    if (request.method === "GET" && url.pathname.match(/^\/api\/me\/submissions\/[^/]+$/)) {
      const submissionId = decodeURIComponent(url.pathname.split("/")[4] || "").trim();
      if (!submissionId) {
        return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
          field: "submissionId",
          message: "required"
        });
      }
      const authPayload = await getAuthPayload(request, env);
      if (!authPayload) {
        return errorResponse(401, "auth_required", requestId, corsHeaders);
      }

      const submission = await env.DB.prepare(
        "SELECT s.id,s.payload_json,s.created_at,s.updated_at,s.canvas_enroll_status,s.canvas_enroll_error,s.canvas_course_id,s.canvas_section_id,s.canvas_enrolled_at,s.canvas_user_id,s.canvas_user_name,f.slug as form_slug,f.title as form_title,f.is_locked,f.is_public,f.auth_policy FROM submissions s JOIN forms f ON f.id=s.form_id WHERE s.id=? AND s.user_id=? AND s.deleted_at IS NULL AND f.deleted_at IS NULL"
      )
        .bind(submissionId, authPayload.userId)
        .first<{
          id: string;
          payload_json: string;
          created_at: string;
          updated_at: string | null;
          canvas_enroll_status: string | null;
          canvas_enroll_error: string | null;
          canvas_course_id: string | null;
          canvas_section_id: string | null;
          canvas_enrolled_at: string | null;
          canvas_user_id: string | null;
          canvas_user_name: string | null;
          form_slug: string;
          form_title: string;
          is_locked: number;
          is_public: number;
          auth_policy: string | null;
        }>();

      if (!submission) {
        return errorResponse(404, "not_found", requestId, corsHeaders);
      }

      let payload: { data?: unknown } | null = null;
      try {
        payload = JSON.parse(submission.payload_json);
      } catch (error) {
        payload = null;
      }

      const filesResult = await env.DB.prepare(
        "SELECT id, field_id, original_name, size_bytes, sha256, vt_status, vt_verdict, final_drive_file_id, finalized_at, drive_web_view_link FROM submission_file_items WHERE submission_id=? AND deleted_at IS NULL ORDER BY uploaded_at DESC"
      )
        .bind(submission.id)
        .all();

      let canvasFullName: string | null = null;
      let canvasDisplayName: string | null = submission.canvas_user_name || null;
      if (submission.canvas_course_id) {
        let email =
          (payload?.data && typeof (payload as any).data?.email === "string"
            ? String((payload as any).data.email).trim()
            : "") || "";
        if (email) {
          const canvasUser = await canvasFindUserByEmailInCourse(env, submission.canvas_course_id, email);
          canvasFullName = canvasUser?.name?.trim() || null;
          canvasDisplayName = canvasUser?.shortName?.trim() || canvasDisplayName;
        }
      }

      return jsonResponse(
        200,
        {
          data: {
            submission_id: submission.id,
            created_at: submission.created_at,
            updated_at: submission.updated_at,
            data_json: payload?.data ?? null,
            files: Array.isArray(filesResult?.results) ? filesResult.results : [],
            canvas: {
              status: submission.canvas_enroll_status,
              error: submission.canvas_enroll_error,
              course_id: submission.canvas_course_id,
              section_id: submission.canvas_section_id,
              enrolled_at: submission.canvas_enrolled_at,
              user_id: submission.canvas_user_id,
              user_name: submission.canvas_user_name,
              full_name: canvasFullName,
              display_name: canvasDisplayName
            },
            form: {
              slug: submission.form_slug,
              title: submission.form_title,
              is_locked: toBoolean(submission.is_locked),
              is_public: toBoolean(submission.is_public),
              auth_policy: submission.auth_policy ?? "optional"
            }
          },
          requestId
        },
        requestId,
        corsHeaders
      );
    }

    if (request.method === "DELETE" && url.pathname === "/api/me") {
      const authPayload = await getAuthPayload(request, env);
      if (!authPayload) {
        return errorResponse(401, "auth_required", requestId, corsHeaders);
      }
      const emailRow = await env.DB.prepare(
        "SELECT email FROM user_identities WHERE user_id=? AND email IS NOT NULL ORDER BY created_at DESC LIMIT 1"
      )
        .bind(authPayload.userId)
        .first<{ email: string | null }>();
      const goodbyeEmail = authPayload.email ?? emailRow?.email ?? null;
      await softDeleteUser(env, authPayload.userId, authPayload.userId, "user_deleted");
      if (goodbyeEmail) {
        try {
          const message = buildAccountGoodbyeMessage();
          const result = await sendGmailMessage(env, {
            to: goodbyeEmail,
            subject: message.subject,
            body: message.body
          });
          await logEmailSend(env, {
            to: goodbyeEmail,
            subject: message.subject,
            body: message.body,
            status: result.ok ? "sent" : "failed",
            error: result.ok ? null : result.error || "send_failed",
            triggeredBy: authPayload.userId,
            triggerSource: "account_deleted"
          });
        } catch (error) {
          console.error(
            "gmail_goodbye_failed",
            String((error as Error | undefined)?.message || error)
          );
        }
      }
      const response = jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
      response.headers.set(
        "Set-Cookie",
        "formapp_token=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
      );
      return response;
    }

    if (request.method === "DELETE") {
      const myFormMatch = url.pathname.match(/^\/api\/me\/forms\/([^/]+)$/);
      if (myFormMatch) {
        const slug = decodeURIComponent(myFormMatch[1]);
        const authPayload = await getAuthPayload(request, env);
        if (!authPayload) {
          return errorResponse(401, "auth_required", requestId, corsHeaders);
        }
        const form = await env.DB.prepare(
          "SELECT created_by FROM forms WHERE slug=? AND deleted_at IS NULL"
        )
          .bind(slug)
          .first<{ created_by: string | null }>();
        if (!form) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        if (!form.created_by || form.created_by !== authPayload.userId) {
          return errorResponse(403, "forbidden", requestId, corsHeaders);
        }
        await softDeleteForm(env, slug, authPayload.userId, "user_deleted");
        return jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
      }
      const myTemplateMatch = url.pathname.match(/^\/api\/me\/templates\/([^/]+)$/);
      if (myTemplateMatch) {
        const key = decodeURIComponent(myTemplateMatch[1]);
        const authPayload = await getAuthPayload(request, env);
        if (!authPayload) {
          return errorResponse(401, "auth_required", requestId, corsHeaders);
        }
        const template = await env.DB.prepare(
          "SELECT created_by FROM templates WHERE key=? AND deleted_at IS NULL"
        )
          .bind(key)
          .first<{ created_by: string | null }>();
        if (!template) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        if (!template.created_by || template.created_by !== authPayload.userId) {
          return errorResponse(403, "forbidden", requestId, corsHeaders);
        }
        await softDeleteTemplate(env, key, authPayload.userId, "user_deleted");
        return jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
      }
    }

    if (
      request.method === "GET" &&
      (url.pathname === "/api/me/submission" ||
        url.pathname.match(/^\/api\/forms\/[^/]+\/submission$/))
    ) {
      const formSlug =
        url.pathname === "/api/me/submission"
          ? url.searchParams.get("formSlug")?.trim()
          : decodeURIComponent(url.pathname.split("/")[3] || "").trim();
      if (!formSlug) {
        return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
          field: "formSlug",
          message: "required"
        });
      }

      const versionParam = url.searchParams.get("version")?.trim() || "latest";

      const authPayload = await getAuthPayload(request, env);
      if (!authPayload) {
        return errorResponse(401, "auth_required", requestId, corsHeaders);
      }

      const form = await env.DB.prepare(
        "SELECT id, slug, title, is_locked, is_public, auth_policy, save_all_versions FROM forms WHERE slug=? AND deleted_at IS NULL"
      )
        .bind(formSlug)
        .first<{
          id: string;
          slug: string;
          title: string;
          is_locked: number;
          is_public: number;
          auth_policy: string | null;
          save_all_versions: number | null;
        }>();

      if (!form) {
        return errorResponse(404, "not_found", requestId, corsHeaders);
      }

      const authCheck = checkAuthPolicy(form.auth_policy ?? "optional", authPayload);
      if (!authCheck.ok) {
        return errorResponse(authCheck.status!, authCheck.code!, requestId, corsHeaders);
      }

      // Handle "none" or "blank" to return empty form
      if (versionParam === "none" || versionParam === "blank") {
        return jsonResponse(
          200,
          {
            data: {
              submissionId: null,
              data_json: null,
              files: [],
              created_at: null,
              updated_at: null,
              form: {
                slug: form.slug,
                title: form.title,
                is_locked: toBoolean(form.is_locked),
                is_public: toBoolean(form.is_public),
                auth_policy: form.auth_policy ?? "optional",
                save_all_versions: toBoolean(form.save_all_versions ?? 0)
              }
            },
            requestId
          },
          requestId,
          corsHeaders
        );
      }

      const submission = await env.DB.prepare(
        "SELECT id,payload_json,created_at,updated_at FROM submissions WHERE form_id=? AND user_id=? AND deleted_at IS NULL ORDER BY COALESCE(updated_at, created_at) DESC LIMIT 1"
      )
        .bind(form.id, authPayload.userId)
        .first<SubmissionDetailRow>();

      if (!submission) {
        return errorResponse(404, "no_submission", requestId, corsHeaders);
      }

      let payload: { data?: unknown } | null = null;
      let versionNumber: number | null = null;
      let versionCreatedAt: string | null = null;

      // Handle specific version number request
      if (versionParam !== "latest" && /^\d+$/.test(versionParam)) {
        const requestedVersion = parseInt(versionParam, 10);
        if (!toBoolean(form.save_all_versions ?? 0)) {
          return errorResponse(400, "versioning_not_enabled", requestId, corsHeaders);
        }

        const version = await env.DB.prepare(
          "SELECT v.id, v.payload_json, v.version_number, v.created_at FROM submission_versions v WHERE v.submission_id=? AND v.version_number=?"
        )
          .bind(submission.id, requestedVersion)
          .first<{ id: string; payload_json: string; version_number: number; created_at: string }>();

        if (!version) {
          return errorResponse(404, "version_not_found", requestId, corsHeaders);
        }

        try {
          payload = JSON.parse(version.payload_json);
        } catch (error) {
          payload = null;
        }
        versionNumber = version.version_number;
        versionCreatedAt = version.created_at;
      } else {
        // Use latest submission (current behavior)
        try {
          payload = JSON.parse(submission.payload_json);
        } catch (error) {
          payload = null;
        }
      }

      const filesResult = await env.DB.prepare(
        "SELECT id, field_id, original_name, size_bytes, vt_status, vt_verdict, final_drive_file_id, finalized_at FROM submission_file_items WHERE submission_id=? AND deleted_at IS NULL ORDER BY uploaded_at DESC"
      )
        .bind(submission.id)
        .all();

      return jsonResponse(
        200,
        {
          data: {
            submissionId: submission.id,
            data_json: payload?.data ?? null,
            files: Array.isArray(filesResult?.results) ? filesResult.results : [],
            created_at: versionCreatedAt || submission.created_at,
            updated_at: submission.updated_at,
            version_number: versionNumber,
            form: {
              slug: form.slug,
              title: form.title,
              is_locked: toBoolean(form.is_locked),
              is_public: toBoolean(form.is_public),
              auth_policy: form.auth_policy ?? "optional",
              save_all_versions: toBoolean(form.save_all_versions ?? 0)
            }
          },
          requestId
        },
        requestId,
        corsHeaders
      );
    }

    // GET /api/me/submissions/:submissionId/versions - List all versions for a user's submission
    if (request.method === "GET" && url.pathname.match(/^\/api\/me\/submissions\/([^/]+)\/versions$/)) {
      const match = url.pathname.match(/^\/api\/me\/submissions\/([^/]+)\/versions$/);
      const submissionId = decodeURIComponent(match![1]);

      const authPayload = await getAuthPayload(request, env);
      if (!authPayload) {
        return errorResponse(401, "auth_required", requestId, corsHeaders);
      }

      const submission = await env.DB.prepare(
        "SELECT s.id, s.user_id, s.form_id, f.slug, f.save_all_versions FROM submissions s JOIN forms f ON f.id=s.form_id WHERE s.id=?"
      )
        .bind(submissionId)
        .first<{ id: string; user_id: string | null; form_id: string; slug: string; save_all_versions: number | null }>();

      if (!submission) {
        return errorResponse(404, "not_found", requestId, corsHeaders);
      }

      // Verify user owns this submission (admin can view all)
      if (!authPayload.isAdmin && submission.user_id !== authPayload.userId) {
        return errorResponse(403, "forbidden", requestId, corsHeaders);
      }

      if (!toBoolean(submission.save_all_versions ?? 0)) {
        return errorResponse(400, "versioning_not_enabled", requestId, corsHeaders);
      }

      const { results: versions } = await env.DB.prepare(
        "SELECT id, version_number, created_at, created_by FROM submission_versions WHERE submission_id=? ORDER BY version_number DESC"
      )
        .bind(submissionId)
        .all<{ id: string; version_number: number; created_at: string; created_by: string | null }>();

      return jsonResponse(200, { versions, requestId }, requestId, corsHeaders);
    }

    // GET /api/me/submissions/:submissionId/versions/:versionNumber - Get specific version data
    if (request.method === "GET" && url.pathname.match(/^\/api\/me\/submissions\/([^/]+)\/versions\/(\d+)$/)) {
      const match = url.pathname.match(/^\/api\/me\/submissions\/([^/]+)\/versions\/(\d+)$/);
      const submissionId = decodeURIComponent(match![1]);
      const versionNumber = Number(match![2]);

      const authPayload = await getAuthPayload(request, env);
      if (!authPayload) {
        return errorResponse(401, "auth_required", requestId, corsHeaders);
      }

      const submission = await env.DB.prepare(
        "SELECT s.id, s.user_id, s.form_id, f.save_all_versions FROM submissions s JOIN forms f ON f.id=s.form_id WHERE s.id=?"
      )
        .bind(submissionId)
        .first<{ id: string; user_id: string | null; form_id: string; save_all_versions: number | null }>();

      if (!submission) {
        return errorResponse(404, "not_found", requestId, corsHeaders);
      }

      // Verify user owns this submission (admin can view all)
      if (!authPayload.isAdmin && submission.user_id !== authPayload.userId) {
        return errorResponse(403, "forbidden", requestId, corsHeaders);
      }

      if (!toBoolean(submission.save_all_versions ?? 0)) {
        return errorResponse(400, "versioning_not_enabled", requestId, corsHeaders);
      }

      const version = await env.DB.prepare(
        "SELECT v.id, v.payload_json, v.version_number, v.created_at, v.created_by FROM submission_versions v WHERE v.submission_id=? AND v.version_number=?"
      )
        .bind(submissionId, versionNumber)
        .first<{ id: string; payload_json: string; version_number: number; created_at: string; created_by: string | null }>();

      if (!version) {
        return errorResponse(404, "not_found", requestId, corsHeaders);
      }

      let data = null;
      try {
        const parsed = JSON.parse(version.payload_json);
        data = parsed.data || null;
      } catch {
        data = null;
      }

      return jsonResponse(
        200,
        {
          data,
          version: {
            id: version.id,
            version_number: version.version_number,
            data,
            created_at: version.created_at,
            created_by: version.created_by
          },
          requestId
        },
        requestId,
        corsHeaders
      );
    }

    if (
      request.method === "DELETE" &&
      (url.pathname === "/api/me/submission" ||
        url.pathname.match(/^\/api\/forms\/[^/]+\/submission$/))
    ) {
      const formSlug =
        url.pathname === "/api/me/submission"
          ? url.searchParams.get("formSlug")?.trim()
          : decodeURIComponent(url.pathname.split("/")[3] || "").trim();
      if (!formSlug) {
        return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
          field: "formSlug",
          message: "required"
        });
      }
      const authPayload = await getAuthPayload(request, env);
      if (!authPayload) {
        return errorResponse(401, "auth_required", requestId, corsHeaders);
      }
      const form = await env.DB.prepare(
        "SELECT id, auth_policy FROM forms WHERE slug=? AND deleted_at IS NULL"
      )
        .bind(formSlug)
        .first<{ id: string; auth_policy: string | null }>();
      if (!form) {
        return errorResponse(404, "not_found", requestId, corsHeaders);
      }
      const authCheck = checkAuthPolicy(form.auth_policy ?? "optional", authPayload);
      if (!authCheck.ok) {
        return errorResponse(authCheck.status!, authCheck.code!, requestId, corsHeaders);
      }
      const deleteResult = await softDeleteSubmissionForUser(
        env,
        form.id,
        authPayload.userId,
        authPayload.userId,
        "user_deleted"
      );
      if (!deleteResult.ok) {
        return errorResponse(502, "canvas_deactivate_failed", requestId, corsHeaders, {
          message: deleteResult.error || "canvas_deactivate_failed"
        });
      }
      const attempted = deleteResult.canvas?.attempted ?? 0;
      const failed = deleteResult.canvas?.failed ?? 0;
      const canvasAction = attempted === 0 ? "skipped" : failed > 0 ? "failed" : "deactivated";
      return jsonResponse(
        200,
        { ok: true, canvasAction, canvasAttempts: attempted, canvasFailed: failed, requestId },
        requestId,
        corsHeaders
      );
    }

    if (request.method === "POST") {
      const hardDeleteMatch = url.pathname.match(/^\/api\/me\/submissions\/([^/]+)\/purge$/);
      if (hardDeleteMatch) {
        const submissionId = decodeURIComponent(hardDeleteMatch[1]);
        const authPayload = await getAuthPayload(request, env);
        if (!authPayload) {
          return errorResponse(401, "auth_required", requestId, corsHeaders);
        }
        const submission = await env.DB.prepare(
          "SELECT user_id FROM submissions WHERE id=? AND deleted_at IS NULL"
        )
          .bind(submissionId)
          .first<{ user_id: string | null }>();
        if (!submission) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        if (!submission.user_id || submission.user_id !== authPayload.userId) {
          return errorResponse(403, "forbidden", requestId, corsHeaders);
        }
        const ok = await hardDeleteSubmission(env, submissionId);
        return jsonResponse(200, { ok, requestId }, requestId, corsHeaders);
      }
    }

    if (request.method === "GET") {
      const versionsMatch = url.pathname.match(
        /^\/api\/me\/submissions\/([^/]+)\/versions$/
      );
      if (versionsMatch) {
        const submissionId = decodeURIComponent(versionsMatch[1]);
        const authPayload = await getAuthPayload(request, env);
        if (!authPayload) {
          return errorResponse(401, "auth_required", requestId, corsHeaders);
        }
        const submission = await env.DB.prepare(
          "SELECT user_id, form_id FROM submissions WHERE id=? AND deleted_at IS NULL"
        )
          .bind(submissionId)
          .first<{ user_id: string; form_id: string }>();

        if (!submission) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        if (!submission.user_id || submission.user_id !== authPayload.userId) {
          return errorResponse(403, "forbidden", requestId, corsHeaders);
        }

        const versions = await env.DB.prepare(
          "SELECT version_number, created_at FROM submission_versions WHERE submission_id=? ORDER BY version_number DESC"
        )
          .bind(submissionId)
          .all<SubmissionVersionRow>();

        return jsonResponse(
          200,
          { versions: versions?.results || [], requestId },
          requestId,
          corsHeaders
        );
      }

      const versionDetailMatch = url.pathname.match(
        /^\/api\/me\/submissions\/([^/]+)\/versions\/([^/]+)$/
      );
      if (versionDetailMatch) {
        const submissionId = decodeURIComponent(versionDetailMatch[1]);
        const versionStr = decodeURIComponent(versionDetailMatch[2]);
        const versionNum = parseInt(versionStr, 10);

        const authPayload = await getAuthPayload(request, env);
        if (!authPayload) {
          return errorResponse(401, "auth_required", requestId, corsHeaders);
        }

        const submission = await env.DB.prepare(
          "SELECT user_id FROM submissions WHERE id=? AND deleted_at IS NULL"
        )
          .bind(submissionId)
          .first<{ user_id: string }>();

        if (!submission) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        if (!submission.user_id || submission.user_id !== authPayload.userId) {
          return errorResponse(403, "forbidden", requestId, corsHeaders);
        }

        const version = await env.DB.prepare(
          "SELECT payload_json, created_at FROM submission_versions WHERE submission_id=? AND version_number=?"
        )
          .bind(submissionId, versionNum)
          .first<{ payload_json: string; created_at: string }>();

        if (!version) {
          return errorResponse(404, "version_not_found", requestId, corsHeaders);
        }

        let data = null;
        try {
          const parsed = JSON.parse(version.payload_json);
          data = parsed.data || null;
        } catch (e) {
          data = null;
        }

        return jsonResponse(200, { data, createdAt: version.created_at, requestId }, requestId, corsHeaders);
      }
    }

    if (request.method === "POST") {
      const submitMatch = url.pathname.match(/^\/api\/forms\/([^/]+)\/submit$/);
      if (submitMatch) {
        let body: { data?: Record<string, unknown>; formPassword?: string } | null = null;
        try {
          body = await parseJsonBody(request);
        } catch (error) {
          return errorResponse(400, "invalid_json", requestId, corsHeaders);
        }

        const slug = decodeURIComponent(submitMatch[1]);
        const form = await getFormWithRules(env, slug);
        if (!form) {
          return errorResponse(404, "not_found", requestId, corsHeaders);
        }
        const availability = getFormAvailability(form);
        if (!availability.open) {
          return errorResponse(403, "form_closed", requestId, corsHeaders, {
            reason: availability.reason
          });
        }
        if (!body?.data || typeof body.data !== "object") {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "data_required"
          });
        }

        const authPayload = await getAuthPayload(request, env);
        const authCheck = checkAuthPolicy(form.auth_policy, authPayload);
        if (!authCheck.ok) {
          return errorResponse(authCheck.status!, authCheck.code!, requestId, corsHeaders);
        }
        const passwordCheck = await verifyFormPassword(
          {
            ...form,
            password_require_access: form.password_require_access as number | null,
            password_require_submit: form.password_require_submit as number | null
          },
          (body as any)?.formPassword,
          "submit"
        );
        if (!passwordCheck.ok) {
          return errorResponse(403, "invalid_payload", requestId, corsHeaders, {
            field: "formPassword",
            message: passwordCheck.message
          });
        }
        const userId = await resolveUserId(env, authPayload);
        const submitter = getSubmitterSnapshot(authPayload);
        const createdIp = getRequestIp(request);
        const createdUserAgent = request.headers.get("user-agent");
        const payloadJson = JSON.stringify({ data: body.data });
        let submissionId = crypto.randomUUID();
        let updated = false;

        if (userId) {
          const existing = await env.DB.prepare(
            "SELECT id FROM submissions WHERE form_id=? AND user_id=? AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1"
          )
            .bind(form.id, userId)
            .first<{ id: string }>();
          if (existing) {
            submissionId = existing.id;
            updated = true;

            if (toBoolean(form.save_all_versions ?? 0)) {
              await saveSubmissionVersion(env, submissionId, form.id, userId, userId);
            }

            await env.DB.prepare(
              "UPDATE submissions SET payload_json=?, updated_at=datetime('now'), submitter_provider=?, submitter_email=?, submitter_github_username=?, canvas_course_id=? WHERE id=?"
            )
              .bind(
                payloadJson,
                submitter.provider,
                submitter.email,
                submitter.github,
                form.canvas_course_id ?? null,
                submissionId
              )
              .run();
          } else {
            await env.DB.prepare(
              "INSERT INTO submissions (id, form_id, user_id, payload_json, created_ip, created_user_agent, submitter_provider, submitter_email, submitter_github_username, canvas_course_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            )
              .bind(
                submissionId,
                form.id,
                userId,
                payloadJson,
                createdIp,
                createdUserAgent,
                submitter.provider,
                submitter.email,
                submitter.github,
                form.canvas_course_id ?? null
              )
              .run();
          }
        } else {
          await env.DB.prepare(
            "INSERT INTO submissions (id, form_id, user_id, payload_json, created_ip, created_user_agent, submitter_provider, submitter_email, submitter_github_username, canvas_course_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
          )
            .bind(
              submissionId,
              form.id,
              null,
              payloadJson,
              createdIp,
              createdUserAgent,
              submitter.provider,
              submitter.email,
              submitter.github,
              form.canvas_course_id ?? null
            )
            .run();
        }

        return jsonResponse(
          200,
          { ok: true, submissionId, updated, requestId },
          requestId,
          corsHeaders
        );
      }
    }

    if (request.method === "GET" && url.pathname === "/api/submissions/me") {
      const formSlug = url.searchParams.get("formSlug");
      if (!formSlug) {
        return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
          field: "formSlug",
          message: "required"
        });
      }

      const form = await env.DB.prepare(
        "SELECT id, auth_policy, is_locked, is_public FROM forms WHERE slug=? AND deleted_at IS NULL"
      )
        .bind(formSlug)
        .first<FormSubmissionRow>();

      if (!form) {
        return errorResponse(404, "not_found", requestId, corsHeaders);
      }

      const authPayload = await getAuthPayload(request, env);
      if (form.auth_policy !== "optional") {
        if (!authPayload) {
          return errorResponse(401, "auth_required", requestId, corsHeaders);
        }
        if (
          form.auth_policy === "google" &&
          authPayload.provider !== "google"
        ) {
          return errorResponse(403, "auth_forbidden", requestId, corsHeaders);
        }
        if (
          form.auth_policy === "github" &&
          authPayload.provider !== "github"
        ) {
          return errorResponse(403, "auth_forbidden", requestId, corsHeaders);
        }
        if (
          form.auth_policy === "either" &&
          authPayload.provider !== "google" &&
          authPayload.provider !== "github"
        ) {
          return errorResponse(403, "auth_forbidden", requestId, corsHeaders);
        }
      } else if (!authPayload) {
        return jsonResponse(200, { data: null, requestId }, requestId, corsHeaders);
      }

      const submission = await env.DB.prepare(
        "SELECT id,payload_json,created_at,updated_at FROM submissions WHERE form_id=? AND user_id=? AND deleted_at IS NULL ORDER BY COALESCE(updated_at, created_at) DESC LIMIT 1"
      )
        .bind(form.id, authPayload?.userId ?? null)
        .first<SubmissionDetailRow>();

      if (!submission) {
        return jsonResponse(200, { data: null, requestId }, requestId, corsHeaders);
      }

      let payload: { data?: unknown; files?: unknown } | null = null;
      try {
        payload = JSON.parse(submission.payload_json);
      } catch (error) {
        payload = null;
      }

      const filesResult = await env.DB.prepare(
        "SELECT id, field_id, original_name, size_bytes, vt_status, vt_verdict, final_drive_file_id, finalized_at FROM submission_file_items WHERE submission_id=? AND deleted_at IS NULL ORDER BY uploaded_at DESC"
      )
        .bind(submission.id)
        .all();

      return jsonResponse(
        200,
        {
          data: {
            id: submission.id,
            data: payload?.data ?? null,
            files: Array.isArray(filesResult?.results) ? filesResult.results : [],
            created_at: submission.created_at,
            updated_at: submission.updated_at
          },
          requestId
        },
        requestId,
        corsHeaders
      );
    }

    if (request.method === "POST" && url.pathname === "/api/uploads/init") {
      let body:
        | {
          formSlug?: string;
          files?: UploadInitFile[];
          uploadSessionId?: string;
          fieldKey?: string;
          filename?: string;
          contentType?: string;
          sizeBytes?: number;
          sha256?: string;
          formPassword?: string;
        }
        | null = null;
      try {
        body = await parseJsonBody(request);
      } catch (error) {
        return errorResponse(400, "invalid_json", requestId, corsHeaders);
      }

      if (body?.fieldKey || body?.filename || typeof body?.sizeBytes === "number") {
        return handleSubmissionUploadInit(request, env, url, requestId, corsHeaders, {
          formSlug: body?.formSlug,
          fieldKey: body?.fieldKey,
          filename: body?.filename,
          contentType: body?.contentType,
          sizeBytes: body?.sizeBytes,
          sha256: body?.sha256,
          formPassword: body?.formPassword
        });
      }

      if (!body?.formSlug || !Array.isArray(body.files) || body.files.length === 0) {
        return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
          message: "formSlug and files are required"
        });
      }

      const formRow = await getFormWithRules(env, body.formSlug.trim());
      if (!formRow) {
        return errorResponse(404, "not_found", requestId, corsHeaders);
      }
      const availability = getFormAvailability(formRow);
      if (!availability.open) {
        return errorResponse(403, "form_closed", requestId, corsHeaders, {
          reason: availability.reason
        });
      }

      const authPayload = await getAuthPayload(request, env);
      const authCheck = checkAuthPolicy(formRow.auth_policy, authPayload);
      if (!authCheck.ok) {
        return errorResponse(authCheck.status!, authCheck.code!, requestId, corsHeaders);
      }
      const passwordCheck = await verifyFormPassword(
        {
          ...formRow,
          password_require_access: formRow.password_require_access as number | null,
          password_require_submit: formRow.password_require_submit as number | null
        },
        body.formPassword,
        "submit"
      );
      if (!passwordCheck.ok) {
        return errorResponse(403, "invalid_payload", requestId, corsHeaders, {
          field: "formPassword",
          message: passwordCheck.message
        });
      }
      const safeUserId = await resolveUserId(env, authPayload);

      const fileRules = buildEffectiveRules(formRow);
      if (!fileRules.enabled) {
        return errorResponse(400, "uploads_disabled", requestId, corsHeaders);
      }
      if (body.files.length > fileRules.maxFiles) {
        return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
          message: "too_many_files",
          maxFiles: fileRules.maxFiles
        });
      }

      let schema: unknown = null;
      if (formRow.schema_json) {
        try {
          schema = JSON.parse(formRow.schema_json);
        } catch (error) {
          return errorResponse(500, "invalid_schema", requestId, corsHeaders);
        }
      }
      const fields = extractFields(schema);
      const fileFieldKeys = new Set(
        fields.filter((field) => field.type === "file").map((field) => field.id)
      );
      const rulesSource = formRow.form_file_rules_json ?? formRow.template_file_rules_json ?? null;
      const fieldRules = parseFieldRules(rulesSource);

      const perFieldCounts = new Map<string, number>();
      body.files.forEach((file) => {
        if (file && typeof file.fieldKey === "string") {
          perFieldCounts.set(file.fieldKey, (perFieldCounts.get(file.fieldKey) ?? 0) + 1);
        }
      });
      for (const [fieldKey, count] of perFieldCounts.entries()) {
        const rule = getFieldRule(fieldRules, fieldKey);
        if (rule.maxFiles && count > rule.maxFiles) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "max_files_exceeded",
            fieldKey,
            maxFiles: rule.maxFiles
          });
        }
      }

      const uploadSessionId = body.uploadSessionId ?? crypto.randomUUID();
      const uploads = [];

      for (const file of body.files) {
        if (!file || typeof file.fieldKey !== "string" || typeof file.name !== "string") {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "invalid_file_metadata"
          });
        }
        if (!fileFieldKeys.has(file.fieldKey)) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "invalid_field",
            fieldKey: file.fieldKey
          });
        }
        const rule = getFieldRule(fieldRules, file.fieldKey);
        if (rule.maxBytes && file.size > rule.maxBytes) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "file_too_large",
            fieldKey: file.fieldKey,
            maxBytes: rule.maxBytes
          });
        }
        const ext = getExtension(file.name);
        if (rule.extensions.length > 0 && !rule.extensions.includes(ext)) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "file_extension_not_allowed",
            fieldKey: file.fieldKey,
            allowedExtensions: rule.extensions
          });
        }

        const r2Key = `uploads/${formRow.slug}/${uploadSessionId}/${file.fieldKey}/${crypto.randomUUID()}_${file.name}`;
        const token = await createUploadToken(env, {
          formSlug: formRow.slug,
          fieldKey: file.fieldKey,
          r2Key,
          size: file.size,
          contentType: file.contentType
        });
        const uploadUrl = new URL("/api/uploads/put", url.origin);
        uploadUrl.searchParams.set("token", token);

        uploads.push({
          fieldKey: file.fieldKey,
          name: file.name,
          r2Key,
          uploadUrl: uploadUrl.toString(),
          headers: {
            "content-type": file.contentType || "application/octet-stream"
          }
        });
      }

      return jsonResponse(
        200,
        { uploadSessionId, uploads, requestId },
        requestId,
        corsHeaders
      );
    }

    if (request.method === "PUT" && url.pathname === "/api/uploads/put") {
      const token = url.searchParams.get("token");
      if (!token) {
        return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
          message: "missing_token"
        });
      }
      const upload = await consumeUploadToken(env, token);
      if (!upload) {
        return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
          message: "invalid_token"
        });
      }
      if (!env.form_app_files) {
        return errorResponse(500, "uploads_unavailable", requestId, corsHeaders);
      }
      const contentLength = request.headers.get("content-length");
      if (contentLength && Number(contentLength) !== upload.size) {
        return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
          message: "size_mismatch"
        });
      }
      const bodyStream = request.body;
      if (!bodyStream) {
        return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
          message: "missing_body"
        });
      }
      if (!contentLength) {
        const buffer = new Uint8Array(await new Response(bodyStream).arrayBuffer());
        if (buffer.length !== upload.size) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "size_mismatch"
          });
        }
        await env.form_app_files.put(upload.r2Key, buffer, {
          httpMetadata: {
            contentType: upload.contentType || "application/octet-stream"
          }
        });
      } else {
        await env.form_app_files.put(upload.r2Key, bodyStream, {
          httpMetadata: {
            contentType: upload.contentType || "application/octet-stream"
          }
        });
      }
      return jsonResponse(
        200,
        { ok: true, r2Key: upload.r2Key, requestId },
        requestId,
        corsHeaders
      );
    }

    if (request.method === "POST" && url.pathname === "/api/uploads/complete") {
      let body:
        | {
          formSlug?: string;
          submissionId?: string;
          uploadSessionId?: string;
          files?: UploadCompleteFile[];
        }
        | null = null;
      try {
        body = await parseJsonBody(request);
      } catch (error) {
        return errorResponse(400, "invalid_json", requestId, corsHeaders);
      }

      if (!body?.formSlug || !Array.isArray(body.files) || body.files.length === 0) {
        return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
          message: "formSlug and files are required"
        });
      }

      const formRow = await getFormWithRules(env, body.formSlug.trim());
      if (!formRow) {
        return errorResponse(404, "not_found", requestId, corsHeaders);
      }
      if (toBoolean(formRow.is_locked)) {
        return errorResponse(409, "locked", requestId, corsHeaders);
      }

      const authPayload = await getAuthPayload(request, env);
      const authCheck = checkAuthPolicy(formRow.auth_policy, authPayload);
      if (!authCheck.ok) {
        return errorResponse(authCheck.status!, authCheck.code!, requestId, corsHeaders);
      }
      const safeUserId = await resolveUserId(env, authPayload);

      if (!env.form_app_files) {
        return errorResponse(500, "uploads_unavailable", requestId, corsHeaders);
      }

      const fileRules = buildEffectiveRules(formRow);
      if (!fileRules.enabled) {
        return errorResponse(400, "uploads_disabled", requestId, corsHeaders);
      }
      if (body.files.length > fileRules.maxFiles) {
        return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
          message: "too_many_files",
          maxFiles: fileRules.maxFiles
        });
      }

      let schema: unknown = null;
      if (formRow.schema_json) {
        try {
          schema = JSON.parse(formRow.schema_json);
        } catch (error) {
          return errorResponse(500, "invalid_schema", requestId, corsHeaders);
        }
      }
      const fields = extractFields(schema);
      const fileFieldKeys = new Set(
        fields.filter((field) => field.type === "file").map((field) => field.id)
      );

      const submissionId = body.submissionId ?? body.uploadSessionId ?? crypto.randomUUID();
      const scans: Array<{
        fieldKey: string;
        filename: string;
        status: string;
        verdict: string;
        malicious: number;
        suspicious: number;
        undetected: number;
        timeout: number;
        reportUrl: string;
        error?: string | null;
      }> = [];
      const strictMode = isVtStrict(env);

      await env.DB.prepare(
        "INSERT OR IGNORE INTO submissions (id, form_id, user_id, payload_json) VALUES (?, ?, ?, ?)"
      )
        .bind(submissionId, formRow.id, safeUserId, "{}")
        .run();
      const submissionExists = await env.DB.prepare("SELECT id FROM submissions WHERE id=? AND deleted_at IS NULL")
        .bind(submissionId)
        .first<{ id: string }>();
      if (!submissionExists) {
        await env.DB.prepare(
          "INSERT OR IGNORE INTO submissions (id, form_id, user_id, payload_json) VALUES (?, ?, ?, ?)"
        )
          .bind(submissionId, formRow.id, null, "{}")
          .run();
      }

      for (const file of body.files) {
        if (!file || typeof file.fieldKey !== "string" || typeof file.name !== "string") {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "invalid_file_metadata"
          });
        }
        if (!fileFieldKeys.has(file.fieldKey)) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "invalid_field",
            fieldKey: file.fieldKey
          });
        }
        const rule = getFieldRule(fileRules as any, file.fieldKey);
        if (rule.maxBytes && file.size > rule.maxBytes) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "file_too_large",
            fieldKey: file.fieldKey,
            maxBytes: rule.maxBytes
          });
        }
        const ext = getExtension(file.name);
        if (rule.extensions.length > 0 && !rule.extensions.includes(ext)) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "file_extension_not_allowed",
            fieldKey: file.fieldKey,
            allowedExtensions: rule.extensions
          });
        }

        const head = await env.form_app_files.head(file.r2Key);
        if (!head) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "missing_r2_object"
          });
        }

        const object = await env.form_app_files.get(file.r2Key);
        if (!object) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "missing_r2_object"
          });
        }
        const buffer = await object.arrayBuffer();
        const sha256 = await hashSha256(buffer);
        if (file.sha256 && file.sha256 !== sha256) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "sha_mismatch"
          });
        }

        const scan = await vtScanBuffer(env, buffer, file.name, sha256);
        const stats = scan.stats;
        let status =
          scan.status === "completed" ? "completed" : scan.status === "error" ? "error" : "running";
        let verdict = status === "error" ? "error" : scan.verdict;
        const vtError = scan.error ?? null;
        const uploadId = crypto.randomUUID();
        await env.DB.prepare(
          "INSERT OR IGNORE INTO submission_uploads (id, submission_id, form_id, user_id, field_key, original_name, content_type, size_bytes, sha256, r2_key, vt_analysis_id, vt_status, vt_verdict, vt_malicious, vt_suspicious, vt_undetected, vt_timeout, vt_last_checked_at, vt_error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?)"
        )
          .bind(
            uploadId,
            submissionId,
            formRow.id,
            safeUserId,
            file.fieldKey,
            file.name,
            file.contentType || object.httpMetadata?.contentType || null,
            file.size,
            sha256,
            file.r2Key,
            scan.analysisId ?? null,
            status,
            verdict,
            stats.malicious,
            stats.suspicious,
            stats.undetected,
            stats.timeout,
            vtError
          )
          .run();

        scans.push({
          fieldKey: file.fieldKey,
          filename: file.name,
          status,
          verdict,
          malicious: stats.malicious,
          suspicious: stats.suspicious,
          undetected: stats.undetected,
          timeout: stats.timeout,
          reportUrl: `https://www.virustotal.com/gui/file/${sha256}`,
          error: vtError
        });

        if (strictMode) {
          if (status !== "completed" && scan.analysisId && env.VT_API_KEY) {
            const waited = await vtWaitForCompletion(env, scan.analysisId, 20000);
            if (!("error" in waited)) {
              const nextStatus = waited.status === "completed" ? "completed" : "running";
              const nextVerdict = waited.verdict;
              const nextStats = waited.stats;
              await updateUploadVtStatus(env, uploadId, {
                analysisId: scan.analysisId,
                status: nextStatus,
                verdict: nextVerdict,
                malicious: nextStats.malicious,
                suspicious: nextStats.suspicious,
                undetected: nextStats.undetected,
                timeout: nextStats.timeout,
                error: null
              });
              scans[scans.length - 1] = {
                ...scans[scans.length - 1],
                status: nextStatus,
                verdict: nextVerdict,
                malicious: nextStats.malicious,
                suspicious: nextStats.suspicious,
                undetected: nextStats.undetected,
                timeout: nextStats.timeout,
                error: null
              };
              status = nextStatus;
              verdict = nextVerdict;
            }
          }
          if (status === "error") {
            return errorResponse(502, "vt_error", requestId, corsHeaders, {
              message: vtError || "vt_error",
              fieldKey: file.fieldKey,
              filename: file.name
            });
          }
          if (status !== "completed") {
            return errorResponse(409, "vt_pending", requestId, corsHeaders, {
              message: "vt_pending",
              fieldKey: file.fieldKey,
              filename: file.name
            });
          }
          if (verdict === "malicious") {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              message: "vt_malicious",
              fieldKey: file.fieldKey,
              filename: file.name
            });
          }
          if (verdict === "suspicious") {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              message: "vt_suspicious",
              fieldKey: file.fieldKey,
              filename: file.name
            });
          }
        }
      }

      return jsonResponse(200, { submissionId, scans, requestId }, requestId, corsHeaders);
    }

    const userFinalizeMatch = url.pathname.match(/^\/api\/submissions\/([^/]+)\/finalize$/);
    if (request.method === "POST" && userFinalizeMatch) {
      const submissionId = decodeURIComponent(userFinalizeMatch[1]);
      const authPayload = await getAuthPayload(request, env);
      if (!authPayload) {
        return errorResponse(401, "auth_required", requestId, corsHeaders);
      }
      const submission = await env.DB.prepare(
        "SELECT s.id, s.user_id, f.slug, f.is_locked FROM submissions s JOIN forms f ON f.id=s.form_id WHERE s.id=? AND s.deleted_at IS NULL AND f.deleted_at IS NULL"
      )
        .bind(submissionId)
        .first<{ id: string; user_id: string | null; slug: string; is_locked: number }>();
      if (!submission) {
        return errorResponse(404, "not_found", requestId, corsHeaders);
      }
      if (!submission.user_id || submission.user_id !== authPayload.userId) {
        return errorResponse(403, "forbidden", requestId, corsHeaders);
      }
      if (toBoolean(submission.is_locked)) {
        return errorResponse(409, "locked", requestId, corsHeaders);
      }
      if (!env.DRIVE_PARENT_FOLDER_ID || !getDriveCredentials(env)) {
        return errorResponse(500, "drive_not_configured", requestId, corsHeaders);
      }
      const userKey = await getUserFolderName(env, authPayload.userId);
      const results = await finalizeSubmissionUploads(env, submissionId, userKey);
      return jsonResponse(200, { ok: true, results, requestId }, requestId, corsHeaders);
    }

    if (request.method === "POST" && url.pathname === "/api/submissions") {
      let parsed: {
        formSlug?: string;
        data?: Record<string, unknown>;
        files?: Array<{ fieldKey: string; file: File }>;
        uploads?: UploadCompleteFile[];
      } | null = null;
      try {
        parsed = await parseSubmissionRequest(request);
      } catch (error) {
        return errorResponse(400, "invalid_json", requestId, corsHeaders);
      }

      const formSlug = parsed?.formSlug?.trim();
      if (!formSlug) {
        return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
          field: "formSlug",
          message: "required"
        });
      }

      if (!parsed?.data || typeof parsed.data !== "object") {
        return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
          field: "data",
          message: "expected_object"
        });
      }

      const form = await getFormWithRules(env, formSlug);
      if (!form) {
        return errorResponse(404, "not_found", requestId, corsHeaders);
      }
      const availability = getFormAvailability(form);
      if (!availability.open) {
        return errorResponse(403, "form_closed", requestId, corsHeaders, {
          reason: availability.reason
        });
      }

      let schema: unknown = null;
      if (form.schema_json) {
        try {
          schema = JSON.parse(form.schema_json);
        } catch (error) {
          return errorResponse(500, "invalid_schema", requestId, corsHeaders);
        }
      }
      const fields = extractFields(schema);
      const fileFieldKeys = new Set(
        fields.filter((field) => field.type === "file").map((field) => field.id)
      );

      const authPayload = await getAuthPayload(request, env);
      const authCheck = checkAuthPolicy(form.auth_policy, authPayload);
      if (!authCheck.ok) {
        return errorResponse(authCheck.status!, authCheck.code!, requestId, corsHeaders);
      }
      const passwordCheck = await verifyFormPassword(
        {
          ...form,
          password_require_access: form.password_require_access as number | null,
          password_require_submit: form.password_require_submit as number | null
        },
        (parsed as any)?.formPassword,
        "submit"
      );
      if (!passwordCheck.ok) {
        return errorResponse(403, "invalid_payload", requestId, corsHeaders, {
          field: "formPassword",
          message: passwordCheck.message
        });
      }

      const dataObj: Record<string, unknown> = { ...(parsed.data as Record<string, unknown>) };
      const rawCanvasSectionId =
        typeof dataObj._canvas_section_id === "string" ? dataObj._canvas_section_id.trim() : "";
      let canvasSectionId = rawCanvasSectionId || null;
      delete dataObj._canvas_section_id;
      const githubLogin =
        authPayload?.userId ? await getGithubLoginForUser(env, authPayload.userId) : null;
      for (const field of fields) {
        if (field.type !== "email" && field.type !== "github_username" && field.type !== "url") {
          continue;
        }
        const raw = dataObj[field.id];
        if (raw !== undefined && raw !== null && typeof raw !== "string") {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: field.id,
            message: "expected_string"
          });
        }
        const value = typeof raw === "string" ? raw.trim() : "";
        if (field.type === "email") {
          const domain = normalizeEmailDomain(field.rules?.domain);
          const allowAutofill = Boolean(field.rules?.autofill);
          if (!value && allowAutofill && authPayload?.email) {
            const email = authPayload.email.trim();
            if (!domain || email.toLowerCase().endsWith(`@${domain}`)) {
              dataObj[field.id] = email;
              continue;
            }
          }
          if (!value) {
            if (field.required) {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: field.id,
                message: "required"
              });
            }
            continue;
          }
          let normalizedEmail = value;
          if (domain && normalizedEmail && !normalizedEmail.includes("@")) {
            normalizedEmail = `${normalizedEmail}@${domain}`;
            dataObj[field.id] = normalizedEmail;
          }
          const emailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail);
          if (!emailValid) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: field.id,
              message: "invalid_email"
            });
          }
          if (domain && !normalizedEmail.toLowerCase().endsWith(`@${domain}`)) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: field.id,
              message: "email_domain_mismatch",
              domain
            });
          }
        }
        if (field.type === "github_username") {
          const allowAutofill = Boolean(field.rules?.autofill);
          if (!value && allowAutofill && authPayload?.provider === "github" && githubLogin) {
            dataObj[field.id] = githubLogin;
            continue;
          }
          if (!value) {
            if (field.required) {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: field.id,
                message: "required"
              });
            }
            continue;
          }
          if (!isValidGithubUsername(value)) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: field.id,
              message: "invalid_github_username"
            });
          }
          if (!allowAutofill) {
            try {
              const exists = await githubUserExists(value);
              if (!exists) {
                return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                  field: field.id,
                  message: "github_user_not_found"
                });
              }
            } catch (error) {
              return errorResponse(502, "github_lookup_failed", requestId, corsHeaders, {
                field: field.id
              });
            }
          }
        }
        if (field.type === "url") {
          if (!value) {
            if (field.required) {
              return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                field: field.id,
                message: "required"
              });
            }
            continue;
          }
          const normalizedUrl = ensureUrlWithScheme(value);
          if (normalizedUrl !== value) {
            dataObj[field.id] = normalizedUrl;
          }
          if (!isValidHttpUrl(normalizedUrl)) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: field.id,
              message: "invalid_url"
            });
          }
        }
      }

      const canvasEnabled = toBoolean(form.canvas_enabled ?? 0) && Boolean(form.canvas_course_id);
      let canvasAllowedSectionIds: string[] | null = null;
      if (form.canvas_allowed_section_ids_json) {
        try {
          const parsedAllowed = JSON.parse(form.canvas_allowed_section_ids_json);
          if (Array.isArray(parsedAllowed)) {
            canvasAllowedSectionIds = parsedAllowed.map((id) => String(id));
          }
        } catch (error) {
          canvasAllowedSectionIds = null;
        }
      }
      if (canvasEnabled && form.canvas_course_id) {
        const allowedSections = await getCanvasAllowedSections(
          env,
          form.canvas_course_id,
          canvasAllowedSectionIds
        );
        if (allowedSections.length > 1 && !canvasSectionId) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "_canvas_section_id",
            message: "required"
          });
        }
        if (!canvasSectionId && allowedSections.length === 1) {
          canvasSectionId = allowedSections[0].id;
        }
        if (canvasSectionId && allowedSections.length > 0) {
          const allowed = new Set(allowedSections.map((section) => section.id));
          if (!allowed.has(canvasSectionId)) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              field: "_canvas_section_id",
              message: "invalid_canvas_section"
            });
          }
        }
      }

      let canvasName: string | null = null;
      let canvasEmail: string | null = null;
      if (canvasEnabled) {
        const nameField = fields.find((field) => field.type === "full_name");
        const emailField = fields.find((field) => field.type === "email");
        if (!nameField || !emailField) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "canvas_missing_fields"
          });
        }
        const nameVal = nameField
          ? typeof (dataObj as any)[nameField.id] === "string" ? (dataObj as any)[nameField.id].trim() : ""
          : "";
        const emailVal = emailField
          ? typeof (dataObj as any)[emailField.id] === "string" ? (dataObj as any)[emailField.id].trim() : ""
          : "";
        if (!nameVal) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: nameField.id,
            message: "required"
          });
        }
        if (!emailVal) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: emailField.id,
            message: "required"
          });
        }
        canvasName = nameVal;
        canvasEmail = emailVal;
      }

      const userId = await resolveUserId(env, authPayload);
      const submitter = getSubmitterSnapshot(authPayload);
      const createdIp = getRequestIp(request);
      const createdUserAgent = request.headers.get("user-agent");
      const payloadJson = JSON.stringify({ data: dataObj });

      const fileRules = buildEffectiveRules(form);
      const maxFiles = fileRules.maxFiles ?? 3;
      const maxSize = fileRules.maxFileSizeBytes ?? fileRules.maxSizeBytes;
      const allowedExtensions = fileRules.allowedExtensions || [];

      const files = parsed.files || [];
      const uploads = parsed.uploads || [];
      const fileRefs = Array.isArray((parsed as any).fileRefs) ? (parsed as any).fileRefs : [];
      if (files.length > 0 && uploads.length > 0) {
        return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
          message: "mixed_uploads_not_supported"
        });
      }
      const totalFiles = files.length + uploads.length;
      if (totalFiles > maxFiles) {
        return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
          message: "too_many_files",
          maxFiles
        });
      }

      if (totalFiles > 0 && !env.form_app_files) {
        return errorResponse(500, "uploads_unavailable", requestId, corsHeaders);
      }

      for (const item of files) {
        if (!fileFieldKeys.has(item.fieldKey)) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "invalid_field",
            fieldKey: item.fieldKey
          });
        }
        const ext = getExtension(item.file.name);
        if (allowedExtensions.length > 0 && !allowedExtensions.includes(ext)) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "file_extension_not_allowed",
            allowedExtensions
          });
        }
        if (item.file.size > maxSize) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "file_too_large",
            maxFileSizeBytes: maxSize
          });
        }
      }

      for (const item of uploads) {
        if (!item || !item.fieldKey || !item.name || !item.r2Key) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "invalid_file_metadata"
          });
        }
        if (!fileFieldKeys.has(item.fieldKey)) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "invalid_field",
            fieldKey: item.fieldKey
          });
        }
        if (!item.r2Key.startsWith(`uploads/${form.slug}/`)) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "invalid_r2_key"
          });
        }
        if (!item.r2Key.includes(`/${item.fieldKey}/`)) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "invalid_r2_key"
          });
        }
        const ext = getExtension(item.name);
        if (allowedExtensions.length > 0 && !allowedExtensions.includes(ext)) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "file_extension_not_allowed",
            allowedExtensions
          });
        }
        if (item.size > maxSize) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "file_too_large",
            maxFileSizeBytes: maxSize
          });
        }
      }

      const uploadSessionIds = new Set<string>();
      for (const item of uploads) {
        const parts = item.r2Key.split("/");
        if (parts.length >= 3 && parts[0] === "uploads" && parts[1] === form.slug) {
          uploadSessionIds.add(parts[2]);
        }
      }

      let submissionId = crypto.randomUUID();
      let existingSubmissionId: string | null = null;
      if (userId) {
        const existing = await env.DB.prepare(
          "SELECT id FROM submissions WHERE form_id=? AND user_id=? AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1"
        )
          .bind(form.id, userId)
          .first<{ id: string }>();
        if (existing) {
          existingSubmissionId = existing.id;
          submissionId = existing.id;
        } else if (uploadSessionIds.size === 1) {
          submissionId = Array.from(uploadSessionIds)[0];
        }
      } else if (uploadSessionIds.size === 1) {
        submissionId = Array.from(uploadSessionIds)[0];
        const existing = await env.DB.prepare(
          "SELECT id, payload_json, updated_at FROM submissions WHERE id=? AND deleted_at IS NULL"
        )
          .bind(submissionId)
          .first<{ id: string; payload_json: string; updated_at: string | null }>();
        if (existing) {
          if (existing.payload_json && existing.payload_json !== "{}") {
            return errorResponse(401, "auth_required", requestId, corsHeaders);
          }
          if (existing.updated_at) {
            return errorResponse(401, "auth_required", requestId, corsHeaders);
          }
        }
      }
      if (userId && !existingSubmissionId) {
        const anyExisting = await env.DB.prepare(
          "SELECT id, deleted_at FROM submissions WHERE form_id=? AND user_id=? ORDER BY created_at DESC LIMIT 1"
        )
          .bind(form.id, userId)
          .first<{ id: string; deleted_at: string | null }>();
        if (anyExisting) {
          existingSubmissionId = anyExisting.id;
          submissionId = anyExisting.id;
        }
      }
      const isResubmission = Boolean(existingSubmissionId);

      if (existingSubmissionId) {
        if (userId && toBoolean(form.save_all_versions ?? 0)) {
          await saveSubmissionVersion(env, submissionId, form.id, userId, userId);
        }

        await env.DB.prepare(
          "UPDATE submissions SET payload_json=?, updated_at=datetime('now'), submitter_provider=?, submitter_email=?, submitter_github_username=?, canvas_course_id=?, deleted_at=NULL, deleted_by=NULL, deleted_reason=NULL WHERE id=?"
        )
          .bind(
            payloadJson,
            submitter.provider,
            submitter.email,
            submitter.github,
            form.canvas_course_id ?? null,
            submissionId
          )
          .run();
        if (totalFiles > 0) {
          await env.DB.prepare(
            "UPDATE submission_uploads SET deleted_at=datetime('now'), deleted_reason='replaced' WHERE submission_id=? AND deleted_at IS NULL"
          )
            .bind(submissionId)
            .run();
        }
      }

      if (!userId) {
        const exists = await env.DB.prepare("SELECT id, payload_json FROM submissions WHERE id=? AND deleted_at IS NULL")
          .bind(submissionId)
          .first<{ id: string; payload_json: string }>();
        if (exists) {
          if (exists.payload_json && exists.payload_json !== "{}") {
            return errorResponse(401, "auth_required", requestId, corsHeaders);
          }
          await env.DB.prepare(
            "UPDATE submissions SET payload_json=?, updated_at=datetime('now'), canvas_course_id=? WHERE id=?"
          )
            .bind(payloadJson, form.canvas_course_id ?? null, submissionId)
            .run();
        } else {
          await env.DB.prepare(
            "INSERT INTO submissions (id, form_id, user_id, payload_json, created_ip, created_user_agent, submitter_provider, submitter_email, submitter_github_username, canvas_course_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
          )
            .bind(
              submissionId,
              form.id,
              null,
              payloadJson,
              createdIp,
              createdUserAgent,
              submitter.provider,
              submitter.email,
              submitter.github,
              form.canvas_course_id ?? null
            )
            .run();
        }
      } else {
        const exists = await env.DB.prepare("SELECT id FROM submissions WHERE id=? AND deleted_at IS NULL")
          .bind(submissionId)
          .first<{ id: string }>();
        if (!exists) {
          await env.DB.prepare(
            "INSERT INTO submissions (id, form_id, user_id, payload_json, created_ip, created_user_agent, submitter_provider, submitter_email, submitter_github_username, canvas_course_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
          )
            .bind(
              submissionId,
              form.id,
              userId,
              payloadJson,
              createdIp,
              createdUserAgent,
              submitter.provider,
              submitter.email,
              submitter.github,
              form.canvas_course_id ?? null
            )
            .run();
        }
      }

      if (fileRefs.length > 0) {
        for (const ref of fileRefs) {
          if (!ref || typeof ref.uploadId !== "string" || typeof ref.fieldKey !== "string") {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              message: "invalid_file_ref"
            });
          }
          const existing = await env.DB.prepare(
            "SELECT id FROM submission_file_items WHERE id=? AND submission_id=? AND field_id=? AND deleted_at IS NULL"
          )
            .bind(ref.uploadId, submissionId, ref.fieldKey)
            .first<{ id: string }>();
          if (!existing) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              message: "invalid_file_ref",
              uploadId: ref.uploadId
            });
          }
        }
      }

      const scans: Array<{
        fieldKey: string;
        filename: string;
        status: string;
        verdict: string;
        malicious: number;
        suspicious: number;
        undetected: number;
        timeout: number;
        reportUrl: string;
        error?: string | null;
      }> = [];
      const strictMode = isVtStrict(env);

      if (files.length > 0 && env.form_app_files) {
        const seen = new Set<string>();
        for (const item of files) {
          const buffer = await item.file.arrayBuffer();
          const sha256 = await hashSha256(buffer);
          const dupeKey = `${item.fieldKey}:${sha256}`;
          if (seen.has(dupeKey)) {
            return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
              message: "duplicate_upload",
              fieldKey: item.fieldKey,
              filename: item.file.name
            });
          }
          seen.add(dupeKey);

          const r2Key = `uploads/${form.slug}/${submissionId}/${item.fieldKey}/${sha256}_${sanitizeFilename(
            item.file.name
          )}`;
          await env.form_app_files.put(r2Key, buffer, {
            httpMetadata: {
              contentType: item.file.type || "application/octet-stream"
            }
          });

          const uploadId = crypto.randomUUID();
          await env.DB.prepare(
            "INSERT INTO submission_uploads (id, submission_id, form_id, user_id, field_key, original_name, content_type, size_bytes, sha256, r2_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
          )
            .bind(
              uploadId,
              submissionId,
              form.id,
              userId,
              item.fieldKey,
              item.file.name,
              item.file.type || null,
              item.file.size,
              sha256,
              r2Key
            )
            .run();

          let status = "completed";
          let verdict = "clean";
          let stats = normalizeVtStats({});
          let vtError: string | null = null;
          if (env.VT_API_KEY) {
            const scan = await vtScanBuffer(env, buffer, item.file.name, sha256);
            status = scan.status === "completed" ? "completed" : "running";
            verdict = scan.verdict;
            stats = scan.stats;
            vtError = scan.error ?? null;
            await updateUploadVtStatus(env, uploadId, {
              analysisId: scan.analysisId,
              status,
              verdict,
              malicious: stats.malicious,
              suspicious: stats.suspicious,
              undetected: stats.undetected,
              timeout: stats.timeout,
              error: vtError
            });

            if (strictMode) {
              if (status !== "completed" && scan.analysisId && env.VT_API_KEY) {
                const waited = await vtWaitForCompletion(env, scan.analysisId, 20000);
                if (!("error" in waited)) {
                  const nextStatus = waited.status === "completed" ? "completed" : "running";
                  const nextVerdict = waited.verdict;
                  const nextStats = waited.stats;
                  await updateUploadVtStatus(env, uploadId, {
                    analysisId: scan.analysisId,
                    status: nextStatus,
                    verdict: nextVerdict,
                    malicious: nextStats.malicious,
                    suspicious: nextStats.suspicious,
                    undetected: nextStats.undetected,
                    timeout: nextStats.timeout,
                    error: null
                  });
                  scans[scans.length - 1] = {
                    ...scans[scans.length - 1],
                    status: nextStatus,
                    verdict: nextVerdict,
                    malicious: nextStats.malicious,
                    suspicious: nextStats.suspicious,
                    undetected: nextStats.undetected,
                    timeout: nextStats.timeout,
                    error: null
                  };
                  status = nextStatus;
                  verdict = nextVerdict;
                }
              }
              if (status === "error") {
                return errorResponse(502, "vt_error", requestId, corsHeaders, {
                  message: vtError || "vt_error",
                  fieldKey: item.fieldKey,
                  filename: item.file.name
                });
              }
              if (status !== "completed") {
                return errorResponse(409, "vt_pending", requestId, corsHeaders, {
                  message: "vt_pending",
                  fieldKey: item.fieldKey,
                  filename: item.file.name
                });
              }
              if (verdict === "malicious") {
                return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                  message: "vt_malicious",
                  fieldKey: item.fieldKey,
                  filename: item.file.name
                });
              }
              if (verdict === "suspicious") {
                return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
                  message: "vt_suspicious",
                  fieldKey: item.fieldKey,
                  filename: item.file.name
                });
              }
            }
          }

          scans.push({
            fieldKey: item.fieldKey,
            filename: item.file.name,
            status,
            verdict,
            malicious: stats.malicious,
            suspicious: stats.suspicious,
            undetected: stats.undetected,
            timeout: stats.timeout,
            reportUrl: `https://www.virustotal.com/gui/file/${sha256}`,
            error: vtError
          });
        }
      }

      let canvasResult: { status: string; error: string | null; user_id?: string | null; user_name?: string | null } | null = null;
      if (canvasEnabled && canvasName && canvasEmail) {
        const enrollment = await handleCanvasEnrollment(env, form, canvasName, canvasEmail, canvasSectionId);
        let finalStatus = enrollment.status;
        let finalError = enrollment.error;
        if (finalStatus !== "invited" && shouldRetryCanvasError(finalError)) {
          await enqueueCanvasRetry(
            env,
            submissionId,
            form.id,
            form.canvas_course_id ?? "",
            canvasSectionId,
            canvasName,
            canvasEmail,
            finalError || "canvas_enroll_failed"
          );
          finalStatus = "pending_retry";
          finalError = `queued:${finalError || "canvas_enroll_failed"}`;
        }
        canvasResult = {
          status: finalStatus,
          error: finalError,
          user_id: enrollment.canvasUserId ?? null,
          user_name: enrollment.canvasUserName ?? null
        };
        await env.DB.prepare(
          "UPDATE submissions SET canvas_enroll_status=?, canvas_enroll_error=?, canvas_course_id=?, canvas_section_id=?, canvas_enrolled_at=?, canvas_user_id=?, canvas_user_name=? WHERE id=?"
        )
          .bind(
            finalStatus,
            finalError,
            form.canvas_course_id ?? null,
            enrollment.sectionId,
            enrollment.enrolledAt,
            enrollment.canvasUserId ?? null,
            enrollment.canvasUserName ?? null,
            submissionId
          )
          .run();
        if (userId && form.canvas_course_id) {
          await ensureCanvasNameCheckRow(env, userId, form.canvas_course_id);
        }
        if (canvasResult.status === "invited" && canvasEmail) {
          const canvasUserName = canvasResult.user_name ?? null;
          try {
            let courseTitle: string | null = null;
            let courseCode: string | null = null;
            let sectionName: string | null = null;
            if (form.canvas_course_id) {
              const courseRow = await env.DB.prepare(
                "SELECT name, code FROM canvas_courses_cache WHERE id=?"
              )
                .bind(form.canvas_course_id)
                .first<{ name: string | null; code: string | null }>();
              courseTitle = courseRow?.name ?? null;
              courseCode = courseRow?.code ?? null;
            }
            if (form.canvas_course_id && canvasSectionId) {
              const sectionRow = await env.DB.prepare(
                "SELECT name FROM canvas_sections_cache WHERE id=?"
              )
                .bind(canvasSectionId)
                .first<{ name: string | null }>();
              sectionName = sectionRow?.name ?? null;
            }
            const courseLabel = courseTitle
              ? `${courseTitle}${courseCode ? ` (${courseCode})` : ""}`
              : form.canvas_course_id
                ? `Course ${form.canvas_course_id}`
                : null;
            const sectionLabel = sectionName
              ? sectionName
              : canvasSectionId
                ? `Section ${canvasSectionId}`
                : null;
            const baseWeb = env.BASE_URL_WEB ? String(env.BASE_URL_WEB).replace(/\/$/, "") : "";
            const formLink = baseWeb ? `${baseWeb}/#/f/${form.slug}` : null;
            const submittedName =
              pickNameFromPayload(dataObj) ||
              canvasName ||
              titleCaseFromEmail(canvasEmail);
            const studentId = pickFirstStringValue(dataObj, [
              "student-id",
              "student_id",
              "studentId",
              "mssv"
            ]);
            const className = pickFirstStringValue(dataObj, [
              "class",
              "class_name",
              "className",
              "lop"
            ]);
            const dobEntry = pickFirstStringEntry(dataObj, [
              "dob",
              "date_of_birth",
              "birthday"
            ]);
            let dobDisplay = dobEntry?.value ?? null;
            if (dobEntry) {
              const dobField = fields.find(
                (field) => field.id === dobEntry.key && field.type === "date"
              );
              if (dobField) {
                const rawMode = String(dobField.rules?.mode || "date");
                const mode =
                  rawMode === "time" ? "time" : rawMode === "datetime" ? "datetime" : "date";
                const tzRaw = dataObj[`${dobEntry.key}__tz`];
                const tzValue = typeof tzRaw === "string" && tzRaw.trim() ? tzRaw.trim() : null;
                const showTimezone = dobField.rules?.timezoneOptional !== true;
                dobDisplay = formatDateValueForMessage(
                  dobEntry.value,
                  mode,
                  tzValue,
                  showTimezone
                );
              }
            }

            if (isResubmission) {
              const message = buildCanvasInformMessage({
                submittedName,
                submittedEmail: canvasEmail,
                studentId,
                className,
                dob: dobDisplay,
                courseLabel,
                sectionLabel,
                formTitle: form.title,
                formLink
              });
              const informResult = await sendGmailMessage(env, {
                to: canvasEmail,
                subject: message.subject,
                body: message.body
              });
              await logEmailSend(env, {
                to: canvasEmail,
                subject: message.subject,
                body: message.body,
                status: informResult.ok ? "sent" : "failed",
                error: informResult.ok ? null : informResult.error || "send_failed",
                submissionId,
                formId: form.id ?? null,
                formSlug: form.slug ?? null,
                formTitle: form.title ?? null,
                canvasCourseId: form.canvas_course_id ?? null,
                canvasSectionId: canvasSectionId ?? null,
                triggerSource: "auto_inform"
              });
            } else {
              const welcomeMessage = buildCanvasWelcomeMessage({
                courseLabel,
                sectionLabel,
                formTitle: form.title,
                submittedName,
                submittedEmail: canvasEmail,
                studentId,
                className,
                dob: dobDisplay,
                formLink
              });
              const welcomeResult = await sendGmailMessage(env, {
                to: canvasEmail,
                subject: welcomeMessage.subject,
                body: welcomeMessage.body
              });
              await logEmailSend(env, {
                to: canvasEmail,
                subject: welcomeMessage.subject,
                body: welcomeMessage.body,
                status: welcomeResult.ok ? "sent" : "failed",
                error: welcomeResult.ok ? null : welcomeResult.error || "send_failed",
                submissionId,
                formId: form.id ?? null,
                formSlug: form.slug ?? null,
                formTitle: form.title ?? null,
                canvasCourseId: form.canvas_course_id ?? null,
                canvasSectionId: canvasSectionId ?? null,
                triggerSource: "auto_welcome"
              });
            }
          } catch (error) {
            console.error(
              "gmail_auto_notify_failed",
              String((error as Error | undefined)?.message || error)
            );
          }
        }
      }

      return jsonResponse(200, { submissionId, scans, canvas: canvasResult, requestId }, requestId, corsHeaders);
    }

    return errorResponse(404, "not_found", requestId, corsHeaders);
  },

  async scheduled(_event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(
      (async () => {
        try {
          const { results: tasks } = await env.DB.prepare(
            "SELECT id,cron,enabled FROM routine_tasks"
          ).all<{ id: string; cron: string; enabled: number }>();
          const now = new Date();
          for (const task of tasks) {
            if (!task.enabled) continue;
            if (!cronMatchesNow(task.cron, now)) continue;
            await runRoutineTaskById(env, task.id);
          }
        } catch (error) {
          console.error("canvas_sync_failed", String((error as Error | undefined)?.message || error));
        }
      })()
    );
  }
};
