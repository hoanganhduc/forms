const BUILD_TIME = new Date().toISOString();

type CorsHeaders = Record<string, string>;

interface Env {
  ALLOWED_ORIGIN?: string;
  GIT_SHA?: string;
  BASE_URL_API?: string;
  BASE_URL_WEB?: string;
  JWT_SECRET?: string;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
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
  DB: D1Database;
  OAUTH_KV: KVNamespace;
  form_app_files?: R2Bucket;
}

type FormListRow = {
  slug: string;
  title: string;
  is_locked: number;
  is_public: number;
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
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  const bytes = Array.from(new Uint8Array(digest));
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
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
}> {
  const contentType = request.headers.get("content-type") || "";
  if (contentType.includes("multipart/form-data")) {
    const formData = await request.formData();
    const files: Array<{ fieldKey: string; file: File }> = [];
    const dataFields: Record<string, unknown> = {};
    let dataJson: Record<string, unknown> | null = null;
    let formSlug: string | undefined;

    for (const [key, value] of formData.entries()) {
      if (key === "formSlug" && typeof value === "string") {
        formSlug = value;
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
      if (value instanceof File) {
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
      files
    };
  }

  const body = await parseJsonBody<{
    formSlug?: string;
    data?: Record<string, unknown>;
    uploads?: UploadCompleteFile[];
    fileRefs?: Array<{ fieldKey: string; uploadId: string }>;
  }>(request);
  return {
    formSlug: body?.formSlug,
    data: body?.data,
    uploads: body?.uploads,
    files: [],
    fileRefs: body?.fileRefs
  };
}

function extractFields(schema: unknown): Array<{
  id: string;
  label: string;
  type: string;
  required: boolean;
  rules?: Record<string, unknown>;
  placeholder?: string;
}> {
  if (!schema || typeof schema !== "object") return [];
  const fields = (schema as { fields?: unknown }).fields;
  if (!Array.isArray(fields)) return [];
  return fields
    .map((field) => {
      if (!field || typeof field !== "object") return null;
      const record = field as Record<string, unknown>;
      const id = typeof record.id === "string" ? record.id : "";
      const label = typeof record.label === "string" ? record.label : id;
      const type = typeof record.type === "string" ? record.type : "text";
      const required = Boolean(record.required);
      const placeholder =
        typeof record.placeholder === "string" && record.placeholder.trim()
          ? record.placeholder
          : undefined;
      const rules = record.rules && typeof record.rules === "object" ? (record.rules as Record<string, unknown>) : undefined;
      if (!id) return null;
      return { id, label, type, required, rules, placeholder };
    })
    .filter(
      (field): field is {
        id: string;
        label: string;
        type: string;
        required: boolean;
        rules?: Record<string, unknown>;
        placeholder?: string;
      } =>
        Boolean(field)
    );
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
  corsHeaders: HeadersInit,
  body: {
    formSlug?: string;
    fieldKey?: string;
    filename?: string;
    contentType?: string;
    sizeBytes?: number;
    sha256?: string;
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
  if (toBoolean(formRow.is_locked)) {
    return errorResponse(409, "locked", requestId, corsHeaders);
  }

  const authPayload = await getAuthPayload(request, env);
  const authCheck = checkAuthPolicy(formRow.auth_policy, authPayload);
  if (!authCheck.ok) {
    return errorResponse(authCheck.status!, authCheck.code!, requestId, corsHeaders);
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
      "INSERT INTO submissions (id, form_id, user_id, payload_json) VALUES (?, ?, ?, ?)"
    )
      .bind(submissionId, formRow.id, userId, JSON.stringify({ data: {} }))
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

async function getGithubLoginForUser(env: Env, userId: string): Promise<string | null> {
  const row = await env.DB.prepare(
    "SELECT provider_login FROM user_identities WHERE user_id=? AND provider='github' ORDER BY created_at DESC LIMIT 1"
  )
    .bind(userId)
    .first<{ provider_login: string | null }>();
  return row?.provider_login ?? null;
}

async function getFormWithRules(env: Env, slug: string) {
  return env.DB.prepare(
    "SELECT f.id,f.slug,f.title,f.description,f.is_locked,f.is_public,f.auth_policy,t.key as templateKey,fv.schema_json,t.file_rules_json as template_file_rules_json,f.file_rules_json as form_file_rules_json FROM forms f LEFT JOIN templates t ON t.id=f.template_id LEFT JOIN form_versions fv ON fv.form_id=f.id AND fv.version=1 WHERE f.slug=? AND f.deleted_at IS NULL"
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
  return result.success !== false;
}

async function softDeleteUser(
  env: Env,
  userId: string,
  deletedBy: string | null,
  reason: string
) {
  // Soft-delete user and cascade soft-delete to their submissions and uploads.
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
  return result.success !== false;
}

async function softDeleteSubmissionForUser(
  env: Env,
  formId: string,
  userId: string,
  deletedBy: string | null,
  reason: string
) {
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
}

async function softDeleteSubmissionById(
  env: Env,
  submissionId: string,
  deletedBy: string | null,
  reason: string
) {
  await updateSubmissionsSoftDelete(env, "id=?", [submissionId], deletedBy, reason);
  await updateSoftDeleteTable(env, "submission_file_items", "submission_id=?", [submissionId], deletedBy, reason);
  await updateSoftDeleteTable(env, "submission_uploads", "submission_id=?", [submissionId], deletedBy, reason);
  await updateSoftDeleteTable(env, "submission_files", "submission_id=?", [submissionId], deletedBy, reason);
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
  return result.success !== false;
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
  return result.success !== false;
}

async function restoreSubmission(env: Env, submissionId: string) {
  await updateSubmissionsRestore(env, "id=?", [submissionId]);
  await updateRestoreTable(env, "submission_file_items", "submission_id=?", [submissionId]);
  await updateRestoreTable(env, "submission_uploads", "submission_id=?", [submissionId]);
  await updateRestoreTable(env, "submission_files", "submission_id=?", [submissionId]);
  return true;
}

async function restoreFileItem(env: Env, fileId: string) {
  await updateRestoreTable(env, "submission_file_items", "id=?", [fileId]);
  const result = await env.DB.prepare(
    "SELECT id FROM submission_file_items WHERE id=? AND deleted_at IS NULL"
  )
    .bind(fileId)
    .run();
  return result.success !== false;
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
  if (!uploaded.id) {
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
    if (uploaded.id) {
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
  if (!uploadRes.ok) return null;
  const payload = (await uploadRes.json()) as { id?: string; webViewLink?: string | null };
  if (!payload.id) return null;
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
        authUrl.searchParams.set("redirect_uri", redirectUri);
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

      if (request.method === "GET" && url.pathname === "/api/admin/forms") {
        const { results } = await env.DB.prepare(
          "SELECT f.id,f.slug,f.title,f.description,f.is_locked,f.is_public,f.auth_policy,t.key as templateKey FROM forms f LEFT JOIN templates t ON t.id=f.template_id WHERE f.deleted_at IS NULL ORDER BY f.created_at DESC"
        ).all<AdminFormRow>();

        const data = results.map((row) => ({
          id: row.id,
          slug: row.slug,
          title: row.title,
          description: row.description,
          is_locked: toBoolean(row.is_locked),
          is_public: toBoolean(row.is_public),
          auth_policy: row.auth_policy,
          templateKey: row.templateKey
        }));

        return jsonResponse(200, { data, requestId }, requestId, corsHeaders);
      }

      if (request.method === "GET" && url.pathname === "/api/admin/templates") {
        const { results } = await env.DB.prepare(
          "SELECT id,key,name,created_at FROM templates WHERE deleted_at IS NULL ORDER BY created_at DESC"
        ).all();
        const data = results.map((row: any) => ({
          id: row.id,
          key: row.key,
          name: row.name,
          created_at: row.created_at
        }));
        return jsonResponse(200, { data, requestId }, requestId, corsHeaders);
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
          if (result.success === false) {
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
          "SELECT u.id,u.is_admin,u.created_at,(SELECT provider FROM user_identities ui WHERE ui.user_id=u.id ORDER BY ui.created_at DESC LIMIT 1) as provider,(SELECT email FROM user_identities ui WHERE ui.user_id=u.id ORDER BY ui.created_at DESC LIMIT 1) as email,(SELECT provider_login FROM user_identities ui WHERE ui.user_id=u.id ORDER BY ui.created_at DESC LIMIT 1) as provider_login FROM users u WHERE u.deleted_at IS NULL ORDER BY u.created_at DESC"
        ).all();
        const data = results.map((row: any) => ({
          id: row.id,
          is_admin: row.is_admin,
          provider: row.provider ?? null,
          email: row.email ?? null,
          provider_login: row.provider_login ?? null,
          created_at: row.created_at
        }));
        return jsonResponse(200, { data, requestId }, requestId, corsHeaders);
      }

      if (request.method === "DELETE") {
        const userMatch = url.pathname.match(/^\/api\/admin\/users\/([^/]+)$/);
        if (userMatch) {
          const userId = decodeURIComponent(userMatch[1]);
          const authPayload = await getAuthPayload(request, env);
          await softDeleteUser(env, userId, authPayload?.userId ?? null, "admin_deleted");
          return jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
        }
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
            "SELECT s.id,s.form_id,f.slug as form_slug,s.deleted_at,s.deleted_by,s.deleted_reason,(SELECT email FROM user_identities ui WHERE ui.user_id=s.deleted_by ORDER BY ui.created_at DESC LIMIT 1) as deleted_by_email FROM submissions s LEFT JOIN forms f ON f.id=s.form_id WHERE s.deleted_at IS NOT NULL ORDER BY s.deleted_at DESC LIMIT ? OFFSET ?"
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
            "SELECT id, form_slug, submission_id, field_id, original_name, size_bytes, deleted_at, deleted_by, deleted_reason,(SELECT email FROM user_identities ui WHERE ui.user_id=deleted_by ORDER BY ui.created_at DESC LIMIT 1) as deleted_by_email FROM submission_file_items WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC LIMIT ? OFFSET ?"
          )
            .bind(limit, offset)
            .all();
          data.files = results;
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
        if (type === "form") {
          ok = await restoreForm(env, id);
        } else if (type === "template") {
          ok = await restoreTemplate(env, id);
        } else if (type === "user") {
          ok = await restoreUser(env, id);
        } else if (type === "submission") {
          ok = await restoreSubmission(env, id);
        } else if (type === "file") {
          ok = await restoreFileItem(env, id);
        } else {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "unsupported_type"
          });
        }
        return jsonResponse(200, { ok, requestId }, requestId, corsHeaders);
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
        if (type === "form") {
          ok = await hardDeleteForm(env, id);
        } else if (type === "template") {
          ok = await hardDeleteTemplate(env, id);
        } else if (type === "user") {
          ok = await hardDeleteUser(env, id);
        } else if (type === "submission") {
          ok = await hardDeleteSubmission(env, id);
        } else if (type === "file") {
          ok = await hardDeleteFileItem(env, id);
        } else {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "unsupported_type"
          });
        }
        return jsonResponse(200, { ok, requestId }, requestId, corsHeaders);
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
              await hardDeleteUser(env, row.id);
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
              await hardDeleteSubmission(env, row.id);
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
        return jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
      }

      if (request.method === "POST" && url.pathname === "/api/admin/forms") {
        let body: {
          slug?: string;
          title?: string;
          templateKey?: string;
          description?: string | null;
          is_public?: boolean;
          auth_policy?: string;
          file_rules?: unknown;
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
          body.title.trim() === "" ||
          typeof body.templateKey !== "string" ||
          body.templateKey.trim() === ""
        ) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            missing: ["slug", "title", "templateKey"].filter(
              (key) => !body || typeof (body as Record<string, unknown>)[key] !== "string"
            )
          });
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

        const template = await env.DB.prepare(
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

        const needsDrive = hasFileFields(template.schema_json);
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
        const description = body.description ?? null;
        const mirroredRules = buildFileRulesJsonFromSchema(template.schema_json);
        const statements = [
          env.DB.prepare(
            "INSERT INTO forms (id, slug, title, description, template_id, is_public, auth_policy, drive_folder_id, file_rules_json, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
          ).bind(
            formId,
            body.slug.trim(),
            body.title.trim(),
            description,
            template.id,
            isPublic,
            authPolicy,
            driveFolderId,
            mirroredRules,
            authPayload?.userId ?? null
          ),
          env.DB.prepare(
            "INSERT INTO form_versions (id, form_id, version, schema_json) VALUES (?, ?, 1, ?)"
          ).bind(versionId, formId, template.schema_json)
        ];

        try {
          await env.DB.batch(statements);
        } catch (error) {
          const message = String((error as Error | undefined)?.message || error);
          return errorResponse(409, "conflict", requestId, corsHeaders, {
            message: message.includes("UNIQUE") ? "slug_exists" : "form_create_failed"
          });
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
              templateKey: template.key,
              driveFolderId
            },
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
            title?: string;
            description?: string | null;
            is_public?: boolean;
            is_locked?: boolean;
            auth_policy?: string;
            templateKey?: string;
            schema_json?: string;
          } | null = null;
          try {
            body = await parseJsonBody(request);
          } catch (error) {
            return errorResponse(400, "invalid_json", requestId, corsHeaders);
          }

          const updates: string[] = [];
          const params: Array<string | number | null> = [];

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

          let formId: string | null = null;
          if (body?.templateKey) {
            const template = await env.DB.prepare(
              "SELECT id, schema_json FROM templates WHERE key=? AND deleted_at IS NULL"
            )
              .bind(body.templateKey)
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
            updates.push("template_id=?");
            params.push(template.id);
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
            updates.push("file_rules_json=?");
            params.push(mirroredRules);
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
            updates.push("file_rules_json=?");
            params.push(mirroredRules);
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

          return jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
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
          "SELECT s.id,s.form_id,f.slug as form_slug,s.user_id,s.payload_json,s.created_at,s.updated_at,s.created_ip,s.created_user_agent,COALESCE(s.submitter_provider,(SELECT provider FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1)) as submitter_provider,COALESCE(s.submitter_email,(SELECT email FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1)) as submitter_email,COALESCE(s.submitter_github_username,(SELECT provider_login FROM user_identities ui WHERE ui.user_id=s.user_id ORDER BY ui.created_at DESC LIMIT 1)) as submitter_github_username FROM submissions s JOIN forms f ON f.id=s.form_id WHERE s.deleted_at IS NULL AND f.deleted_at IS NULL";
        if (formSlug) {
          query += " AND f.slug=?";
          params.push(formSlug);
        }
        query += " ORDER BY COALESCE(s.updated_at, s.created_at) DESC LIMIT ? OFFSET ?";
        params.push(limit, offset);

        const totalResult = await env.DB.prepare(
          `SELECT COUNT(1) as total FROM submissions s JOIN forms f ON f.id=s.form_id WHERE s.deleted_at IS NULL AND f.deleted_at IS NULL${
            formSlug ? " AND f.slug=?" : ""
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
          await softDeleteSubmissionById(env, submissionId, adminPayload.userId, "admin_deleted");
          return jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
        }
      }

      if (request.method === "GET") {
        const newExportMatch = url.pathname.match(/^\/api\/admin\/forms\/([^/]+)\/submissions\/export$/);
        if (newExportMatch) {
          const formSlug = decodeURIComponent(newExportMatch[1]).trim();
          const format = (url.searchParams.get("format") || "csv").toLowerCase();
          const includeDeleted = url.searchParams.get("includeDeleted") === "1";
          const includeDeletedUsers = url.searchParams.get("includeDeletedUsers") === "1";
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

          const rows = results.map((row: any) => {
            let dataObj: Record<string, unknown> = {};
            try {
              const payload = JSON.parse(row.payload_json) as { data?: Record<string, unknown> };
              dataObj = payload?.data && typeof payload.data === "object" ? payload.data : {};
            } catch (error) {
              dataObj = {};
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
          const dataKeys = Array.from(keySet).sort();
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
            "data_json",
            ...dataKeys.map((key) => `data.${key}`)
          ];

          const delimiter = format === "csv" ? "," : "\t";
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
              row.data_json ?? ""
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
              "access-control-expose-headers": "Content-Disposition",
              "x-request-id": requestId,
              ...corsHeaders
            }
          });
        }
      }

      if (
        request.method === "GET" &&
        (url.pathname === "/api/admin/submissions/export" ||
          url.pathname.match(/^\/api\/admin\/forms\/[^/]+\/export$/))
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
        const dataKeys = Array.from(keySet).sort();

        const escapeDelimited = (value: string, delimiter: string) => {
          if (value.includes('"') || value.includes("\n") || value.includes("\r") || value.includes(delimiter)) {
            return `"${value.replace(/"/g, '""')}"`;
          }
          return value;
        };

        const metaHeaders = includeMeta
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
            const metaValues = includeMeta
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
              "access-control-expose-headers": "Content-Disposition",
              "x-request-id": requestId,
              ...corsHeaders
            }
          });
        }

        if (mode === "json") {
          const lines = rows.map((row) => {
            const record: Record<string, unknown> = {};
            if (includeMeta) {
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
              "access-control-expose-headers": "Content-Disposition",
              "x-request-id": requestId,
              ...corsHeaders
            }
          });
        }

        const headers = [...metaHeaders, ...dataKeys];
        const lines = [headers.join("\t")];
        rows.forEach((row) => {
          const metaValues = includeMeta
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
          const values = [...metaValues, ...dataValues].map((value) => escapeDelimited(String(value ?? ""), "\t"));
          lines.push(values.join("\t"));
        });
        const output = lines.join("\n");
        return new Response(output, {
          status: 200,
          headers: {
            "content-type": "text/plain; charset=utf-8",
            "content-disposition": `attachment; filename="${filenamePrefix}.txt"`,
            "access-control-expose-headers": "Content-Disposition",
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
        "SELECT slug,title,is_locked,is_public,auth_policy FROM forms WHERE deleted_at IS NULL AND is_public=1 ORDER BY created_at DESC"
      ).all<FormListRow & { auth_policy: string }>();

      const data = results.map((row) => ({
        slug: row.slug,
        title: row.title,
        is_locked: toBoolean(row.is_locked),
        is_public: toBoolean(row.is_public),
        auth_policy: row.auth_policy
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

        let schema: unknown = null;
        if (row.schema_json) {
          try {
            schema = JSON.parse(row.schema_json);
          } catch (error) {
            return errorResponse(500, "invalid_schema", requestId, corsHeaders);
          }
        }

        const fields = extractFields(schema);
        const fileRules = buildEffectiveRules(row);
        const data = {
          slug: row.slug,
          title: row.title,
          description: row.description,
          is_locked: toBoolean(row.is_locked),
          is_public: toBoolean(row.is_public),
          auth_policy: row.auth_policy,
          templateKey: row.templateKey,
          templateVersion: row.templateVersion,
          formVersion: row.templateVersion,
          template_schema_json: row.schema_json,
          file_rules_json: row.form_file_rules_json ?? row.template_file_rules_json ?? null,
          fields,
          file_rules: fileRules
        };

        return jsonResponse(200, { data, requestId }, requestId, corsHeaders);
      }
    }

    if (request.method === "POST") {
      

      if (url.pathname === "/api/submissions/upload/init") {
        let body: {
          formSlug?: string;
          fieldKey?: string;
          filename?: string;
          contentType?: string;
          sizeBytes?: number;
          sha256?: string;
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
        if (!(fileValue instanceof File)) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            field: "file",
            message: "required"
          });
        }
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
        if (session.size_bytes !== fileValue.size) {
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

        const buffer = await fileValue.arrayBuffer();
        const sha256 = await hashSha256(buffer);
        if (session.sha256 && session.sha256 !== sha256) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "sha256_mismatch"
          });
        }
        await env.form_app_files.put(session.r2_key, buffer, {
          httpMetadata: {
            contentType: fileValue.type || session.content_type || "application/octet-stream"
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
        if (toBoolean(formRow.is_locked)) {
          return errorResponse(409, "locked", requestId, corsHeaders);
        }

        const authPayload = await getAuthPayload(request, env);
        const authCheck = checkAuthPolicy(formRow.auth_policy, authPayload);
        if (!authCheck.ok) {
          return errorResponse(authCheck.status!, authCheck.code!, requestId, corsHeaders);
        }

        const formData = await request.formData();
        const fieldIdValue = formData.get("fieldId");
        const submissionIdValue = formData.get("submissionId");
        const fieldId = typeof fieldIdValue === "string" ? fieldIdValue.trim() : "";
        const submissionId =
          typeof submissionIdValue === "string" && submissionIdValue.trim()
            ? submissionIdValue.trim()
            : null;

        const files: File[] = [];
        for (const [key, value] of formData.entries()) {
          if ((key === "files" || key === "files[]") && value instanceof File) {
            files.push(value);
          }
        }

        if (!fieldId || files.length === 0) {
          return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
            message: "fieldId and files are required"
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

        for (const file of files) {
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
        for (const file of files) {
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
              if (uploaded.id) {
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
          if (uploaded.id) {
            await env.DB.prepare(
              "UPDATE submission_file_items SET final_drive_file_id=?, finalized_at=datetime('now'), drive_web_view_link=? WHERE id=?"
            )
              .bind(uploaded.id, uploaded.webViewLink ?? null, item.id)
              .run();
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
      const identities = await getUserIdentities(env, authPayload.userId);
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
      const identities = await getUserIdentities(env, authPayload.userId);
      return jsonResponse(200, { data: identities, requestId }, requestId, corsHeaders);
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

      const submission = await env.DB.prepare(
        "SELECT s.id,s.form_id,s.user_id,s.payload_json,s.created_at,s.updated_at,f.slug as form_slug,f.title as form_title,f.is_locked,f.is_public,f.auth_policy FROM submissions s JOIN forms f ON f.id=s.form_id WHERE s.id=? AND s.deleted_at IS NULL"
      )
        .bind(submissionId)
        .first<{
          id: string;
          form_id: string;
          user_id: string | null;
          payload_json: string;
          created_at: string | null;
          updated_at: string | null;
          form_slug: string;
          form_title: string;
          is_locked: number;
          is_public: number;
          auth_policy: string | null;
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

      return jsonResponse(
        200,
        {
          data: {
            submissionId: submission.id,
            data_json: payload?.data ?? null,
            files: Array.isArray(filesResult?.results) ? filesResult.results : [],
            created_at: submission.created_at,
            updated_at: submission.updated_at,
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
          "SELECT s.id,s.form_id,f.slug as form_slug,s.deleted_at,s.deleted_by,s.deleted_reason FROM submissions s LEFT JOIN forms f ON f.id=s.form_id WHERE s.deleted_at IS NOT NULL AND s.user_id=? ORDER BY s.deleted_at DESC LIMIT ? OFFSET ?"
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
          "SELECT sfi.id, sfi.form_slug, sfi.submission_id, sfi.field_id, sfi.original_name, sfi.size_bytes, sfi.deleted_at, sfi.deleted_by, sfi.deleted_reason FROM submission_file_items sfi WHERE sfi.deleted_at IS NOT NULL AND sfi.submission_id IN (SELECT id FROM submissions WHERE user_id=?) ORDER BY sfi.deleted_at DESC LIMIT ? OFFSET ?"
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
        await restoreSubmission(env, id);
        return jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
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
        const ok = await hardDeleteSubmission(env, id);
        return jsonResponse(200, { ok, requestId }, requestId, corsHeaders);
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
        const ok = await hardDeleteFileItem(env, id);
        return jsonResponse(200, { ok, requestId }, requestId, corsHeaders);
      }
      return errorResponse(400, "invalid_payload", requestId, corsHeaders, {
        message: "unsupported_type"
      });
    }

    if (request.method === "POST" && url.pathname === "/api/me/trash/empty") {
      const authPayload = await getAuthPayload(request, env);
      if (!authPayload) {
        return errorResponse(401, "auth_required", requestId, corsHeaders);
      }
      let body: { type?: string } | null = null;
      try {
        body = await parseJsonBody(request);
      } catch (error) {
        return errorResponse(400, "invalid_json", requestId, corsHeaders);
      }
      const type = (body?.type || "all").toLowerCase();
      if (type === "all" || type === "submissions") {
        const { results } = await env.DB.prepare(
          "SELECT id FROM submissions WHERE deleted_at IS NOT NULL AND user_id=?"
        )
          .bind(authPayload.userId)
          .all<{ id: string }>();
        for (const row of results) {
          if (row?.id) {
            await hardDeleteSubmission(env, row.id);
          }
        }
      }
      if (type === "all" || type === "files") {
        const { results } = await env.DB.prepare(
          "SELECT sfi.id FROM submission_file_items sfi WHERE sfi.deleted_at IS NOT NULL AND sfi.submission_id IN (SELECT id FROM submissions WHERE user_id=?)"
        )
          .bind(authPayload.userId)
          .all<{ id: string }>();
        for (const row of results) {
          if (row?.id) {
            await hardDeleteFileItem(env, row.id);
          }
        }
      }
      return jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
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
        "SELECT s.id,s.payload_json,s.created_at,s.updated_at,f.slug as form_slug,f.title as form_title,f.is_locked,f.is_public,f.auth_policy FROM submissions s JOIN forms f ON f.id=s.form_id WHERE s.id=? AND s.user_id=? AND s.deleted_at IS NULL AND f.deleted_at IS NULL"
      )
        .bind(submissionId, authPayload.userId)
        .first<{
          id: string;
          payload_json: string;
          created_at: string;
          updated_at: string | null;
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

      return jsonResponse(
        200,
        {
          data: {
            submission_id: submission.id,
            created_at: submission.created_at,
            updated_at: submission.updated_at,
            data_json: payload?.data ?? null,
            files: Array.isArray(filesResult?.results) ? filesResult.results : [],
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
      await softDeleteUser(env, authPayload.userId, authPayload.userId, "user_deleted");
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

      const authPayload = await getAuthPayload(request, env);
      if (!authPayload) {
        return errorResponse(401, "auth_required", requestId, corsHeaders);
      }

      const form = await env.DB.prepare(
        "SELECT id, slug, title, is_locked, is_public, auth_policy FROM forms WHERE slug=? AND deleted_at IS NULL"
      )
        .bind(formSlug)
        .first<{
          id: string;
          slug: string;
          title: string;
          is_locked: number;
          is_public: number;
          auth_policy: string | null;
        }>();

      if (!form) {
        return errorResponse(404, "not_found", requestId, corsHeaders);
      }

      const authCheck = checkAuthPolicy(form.auth_policy ?? "optional", authPayload);
      if (!authCheck.ok) {
        return errorResponse(authCheck.status!, authCheck.code!, requestId, corsHeaders);
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
            submissionId: submission.id,
            data_json: payload?.data ?? null,
            files: Array.isArray(filesResult?.results) ? filesResult.results : [],
            created_at: submission.created_at,
            updated_at: submission.updated_at,
            form: {
              slug: form.slug,
              title: form.title,
              is_locked: toBoolean(form.is_locked),
              is_public: toBoolean(form.is_public),
              auth_policy: form.auth_policy ?? "optional"
            }
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
      await softDeleteSubmissionForUser(
        env,
        form.id,
        authPayload.userId,
        authPayload.userId,
        "user_deleted"
      );
      return jsonResponse(200, { ok: true, requestId }, requestId, corsHeaders);
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

    if (request.method === "POST") {
      const submitMatch = url.pathname.match(/^\/api\/forms\/([^/]+)\/submit$/);
      if (submitMatch) {
        let body: { data?: Record<string, unknown> } | null = null;
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
        if (toBoolean(form.is_locked)) {
          return errorResponse(409, "locked", requestId, corsHeaders);
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
            await env.DB.prepare(
              "UPDATE submissions SET payload_json=?, updated_at=datetime('now'), submitter_provider=?, submitter_email=?, submitter_github_username=? WHERE id=?"
            )
              .bind(
                payloadJson,
                submitter.provider,
                submitter.email,
                submitter.github,
                submissionId
              )
              .run();
          } else {
            await env.DB.prepare(
              "INSERT INTO submissions (id, form_id, user_id, payload_json, created_ip, created_user_agent, submitter_provider, submitter_email, submitter_github_username) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
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
                submitter.github
              )
              .run();
          }
        } else {
          await env.DB.prepare(
            "INSERT INTO submissions (id, form_id, user_id, payload_json, created_ip, created_user_agent, submitter_provider, submitter_email, submitter_github_username) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
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
              submitter.github
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
          sha256: body?.sha256
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
      if (toBoolean(formRow.is_locked)) {
        return errorResponse(409, "locked", requestId, corsHeaders);
      }

      const authPayload = await getAuthPayload(request, env);
      const authCheck = checkAuthPolicy(formRow.auth_policy, authPayload);
      if (!authCheck.ok) {
        return errorResponse(authCheck.status!, authCheck.code!, requestId, corsHeaders);
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
      if (toBoolean(form.is_locked)) {
        return errorResponse(403, "form_locked", requestId, corsHeaders);
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

      const dataObj: Record<string, unknown> = { ...(parsed.data as Record<string, unknown>) };
      const githubLogin =
        authPayload?.userId ? await getGithubLoginForUser(env, authPayload.userId) : null;
      for (const field of fields) {
        if (field.type !== "email" && field.type !== "github_username") continue;
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
        }
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
      const fileRefs = Array.isArray(parsed.fileRefs) ? parsed.fileRefs : [];
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

      if (existingSubmissionId) {
        await env.DB.prepare(
          "UPDATE submissions SET payload_json=?, updated_at=datetime('now'), submitter_provider=?, submitter_email=?, submitter_github_username=? WHERE id=?"
        )
          .bind(
            payloadJson,
            submitter.provider,
            submitter.email,
            submitter.github,
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
            "UPDATE submissions SET payload_json=?, updated_at=datetime('now') WHERE id=?"
          )
            .bind(payloadJson, submissionId)
            .run();
        } else {
          await env.DB.prepare(
            "INSERT INTO submissions (id, form_id, user_id, payload_json, created_ip, created_user_agent, submitter_provider, submitter_email, submitter_github_username) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
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
              submitter.github
            )
            .run();
        }
      } else {
        const exists = await env.DB.prepare("SELECT id FROM submissions WHERE id=? AND deleted_at IS NULL")
          .bind(submissionId)
          .first<{ id: string }>();
        if (!exists) {
          await env.DB.prepare(
            "INSERT INTO submissions (id, form_id, user_id, payload_json, created_ip, created_user_agent, submitter_provider, submitter_email, submitter_github_username) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
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
              submitter.github
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

      return jsonResponse(200, { submissionId, scans, requestId }, requestId, corsHeaders);
    }

    return errorResponse(404, "not_found", requestId, corsHeaders);
  }
};
