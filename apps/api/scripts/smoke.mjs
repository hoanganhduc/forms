const baseUrl = process.env.API_BASE || "http://127.0.0.1:8787";
const token = process.env.TOKEN || "";

async function requestJson(method, path, options = {}) {
  const url = `${baseUrl}${path}`;
  const response = await fetch(url, { ...options, method });
  let bodyText = "";
  try {
    bodyText = await response.text();
  } catch (error) {
    bodyText = "";
  }
  let json = null;
  try {
    json = JSON.parse(bodyText);
  } catch (error) {
    json = bodyText;
  }
  return { status: response.status, json };
}

async function requestRaw(method, path, options = {}) {
  const url = `${baseUrl}${path}`;
  const response = await fetch(url, { ...options, method });
  const contentType = response.headers.get("content-type") || "";
  let bodyText = "";
  try {
    bodyText = await response.text();
  } catch (error) {
    bodyText = "";
  }
  return { status: response.status, contentType, bodyText };
}

async function requestMultipart(path, formData, headers = {}) {
  const url = `${baseUrl}${path}`;
  const response = await fetch(url, {
    method: "POST",
    body: formData,
    headers
  });
  let bodyText = "";
  try {
    bodyText = await response.text();
  } catch (error) {
    bodyText = "";
  }
  let json = null;
  try {
    json = JSON.parse(bodyText);
  } catch (error) {
    json = bodyText;
  }
  return { status: response.status, json };
}

function parseFieldRule(rawRules, fieldId) {
  const fallback = { maxFiles: 3 };
  if (!rawRules) return fallback;
  let parsed = null;
  try {
    parsed = typeof rawRules === "string" ? JSON.parse(rawRules) : rawRules;
  } catch (error) {
    parsed = null;
  }
  if (!parsed || typeof parsed !== "object") return fallback;
  if (parsed.fields && typeof parsed.fields === "object") {
    const fieldRule = parsed.fields[fieldId];
    if (fieldRule && typeof fieldRule.maxFiles === "number") {
      return { maxFiles: fieldRule.maxFiles };
    }
  }
  if (typeof parsed.maxFiles === "number") {
    return { maxFiles: parsed.maxFiles };
  }
  return fallback;
}

async function run() {
  const failures = [];
  let total = 0;

  const versionRes = await requestJson("GET", "/api/debug/version");
  console.log("GET /api/debug/version", versionRes.status, versionRes.json);
  total += 1;
  if (versionRes.status !== 200) {
    failures.push(`FAIL GET /api/debug/version status=${versionRes.status} body=${JSON.stringify(versionRes.json)}`);
  }

  const publicRes = await requestJson("GET", "/api/forms");
  console.log("GET /api/forms", publicRes.status, publicRes.json);
  total += 1;
  if (publicRes.status !== 200) {
    failures.push(`FAIL GET /api/forms status=${publicRes.status} body=${JSON.stringify(publicRes.json)}`);
  }

  let firstSlug = null;
  if (publicRes.status === 200 && publicRes.json && Array.isArray(publicRes.json.data)) {
    firstSlug = publicRes.json.data[0]?.slug || null;
  }

  if (firstSlug) {
    const formRes = await requestJson("GET", `/api/forms/${firstSlug}`);
    console.log("GET /api/forms/:slug", formRes.status, formRes.json);
    total += 1;
    if (formRes.status !== 200) {
      failures.push(
        `FAIL GET /api/forms/${firstSlug} status=${formRes.status} body=${JSON.stringify(formRes.json)}`
      );
    }
  }

  let lastSubmissionId = null;
  let formSubmissionId = null;
  let fileFieldKey = null;
  let authPolicy = "optional";
  let fileRulesJson = null;
  if (firstSlug) {
    const formDetail = await requestJson("GET", `/api/forms/${firstSlug}`);
    console.log("GET /api/forms/:slug (for upload field)", formDetail.status, formDetail.json);
    total += 1;
    if (formDetail.status !== 200) {
      failures.push(
        `FAIL GET /api/forms/${firstSlug} status=${formDetail.status} body=${JSON.stringify(formDetail.json)}`
      );
    } else if (Array.isArray(formDetail.json?.data?.fields)) {
      const fileField = formDetail.json.data.fields.find((field) => field.type === "file");
      fileFieldKey = fileField?.id || null;
      authPolicy = formDetail.json?.data?.auth_policy || "optional";
      fileRulesJson = formDetail.json?.data?.file_rules_json || null;
    }
  }

  if (firstSlug) {
    if (!token && authPolicy !== "optional") {
      console.warn("Skipping submit: auth required but TOKEN not set.");
    } else {
      const submitRes = await requestJson("POST", "/api/submissions", {
        headers: {
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
          "content-type": "application/json"
        },
        body: JSON.stringify({
          formSlug: firstSlug,
          data: { smoke: true, time: new Date().toISOString() }
        })
      });
      console.log("POST /api/submissions", submitRes.status, submitRes.json);
      total += 1;
      if (submitRes.status !== 201 && submitRes.status !== 200) {
        failures.push(
          `FAIL POST /api/submissions status=${submitRes.status} body=${JSON.stringify(submitRes.json)}`
        );
      } else {
        formSubmissionId = submitRes.json?.data?.id || submitRes.json?.submissionId || null;
      }
    }
  }

  if (firstSlug && token) {
    const meSubmission = await requestJson(
      "GET",
      `/api/me/submission?formSlug=${encodeURIComponent(firstSlug)}`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    console.log("GET /api/me/submission", meSubmission.status, meSubmission.json);
    total += 1;
    if (meSubmission.status !== 200) {
      failures.push(
        `FAIL GET /api/me/submission status=${meSubmission.status} body=${JSON.stringify(meSubmission.json)}`
      );
    } else {
      lastSubmissionId = meSubmission.json?.data?.submissionId || formSubmissionId || null;
    }
  }

  if (firstSlug && token && formSubmissionId) {
    const resubmitRes = await requestJson("POST", "/api/submissions", {
      headers: {
        Authorization: `Bearer ${token}`,
        "content-type": "application/json"
      },
      body: JSON.stringify({
        formSlug: firstSlug,
        data: { smoke: "resubmit", time: new Date().toISOString() }
      })
    });
    console.log("POST /api/submissions (update)", resubmitRes.status, resubmitRes.json);
    total += 1;
    if (resubmitRes.status !== 201 && resubmitRes.status !== 200) {
      failures.push(
        `FAIL POST /api/submissions update status=${resubmitRes.status} body=${JSON.stringify(
          resubmitRes.json
        )}`
      );
    }
  }

  if (firstSlug && fileFieldKey && lastSubmissionId) {
    const filesList = await requestJson(
      "GET",
      `/api/forms/${firstSlug}/files?submissionId=${encodeURIComponent(lastSubmissionId)}`,
      { headers: token ? { Authorization: `Bearer ${token}` } : {} }
    );
    total += 1;
    if (filesList.status !== 200) {
      failures.push(
        `FAIL GET /api/forms/${firstSlug}/files status=${filesList.status} body=${JSON.stringify(filesList.json)}`
      );
    }
    const existingCount = Array.isArray(filesList.json?.data)
      ? filesList.json.data.filter((item) => item.field_id === fileFieldKey).length
      : 0;
    const rule = parseFieldRule(fileRulesJson, fileFieldKey);
    const remaining = rule.maxFiles ? Math.max(rule.maxFiles - existingCount, 0) : 1;
    if (remaining <= 0) {
      console.warn("Skipping upload: max files reached for field", fileFieldKey);
    } else {
      const blob = new Blob(["smoke upload"], { type: "text/plain" });
      const formData = new FormData();
      formData.append("fieldId", fileFieldKey);
      formData.append("submissionId", lastSubmissionId);
      formData.append("files", blob, "smoke.txt");
      const uploadRes = await requestMultipart(`/api/forms/${firstSlug}/upload`, formData, {
        ...(token ? { Authorization: `Bearer ${token}` } : {})
      });
      console.log("POST /api/forms/:slug/upload", uploadRes.status, uploadRes.json);
      total += 1;
      if (uploadRes.status === 400 && uploadRes.json?.detail?.message === "max_files_exceeded") {
        console.warn("Skipping upload: max files exceeded for field", fileFieldKey);
      } else if (uploadRes.status !== 200) {
        failures.push(
          `FAIL POST /api/forms/${firstSlug}/upload status=${uploadRes.status} body=${JSON.stringify(
            uploadRes.json
          )}`
        );
      }
    }
  }

  if (!token) {
    console.warn("WARNING: Missing TOKEN, skipping admin smoke checks.");
  } else {
    const authHeaders = { Authorization: `Bearer ${token}` };
    const adminHealth = await requestJson("GET", "/api/admin/health", { headers: authHeaders });
    console.log("GET /api/admin/health", adminHealth.status, adminHealth.json);
    total += 1;
    if (adminHealth.status !== 200) {
      failures.push(`FAIL GET /api/admin/health status=${adminHealth.status} body=${JSON.stringify(adminHealth.json)}`);
    }

    const adminForms = await requestJson("GET", "/api/admin/forms", { headers: authHeaders });
    console.log("GET /api/admin/forms", adminForms.status, adminForms.json);
    total += 1;
    if (adminForms.status !== 200) {
      failures.push(`FAIL GET /api/admin/forms status=${adminForms.status} body=${JSON.stringify(adminForms.json)}`);
    }

    const adminSubs = await requestJson("GET", "/api/admin/submissions", { headers: authHeaders });
    console.log("GET /api/admin/submissions", adminSubs.status, adminSubs.json);
    total += 1;
    if (adminSubs.status !== 200) {
      failures.push(
        `FAIL GET /api/admin/submissions status=${adminSubs.status} body=${JSON.stringify(adminSubs.json)}`
      );
    }

    const adminSubsWithData = await requestJson("GET", "/api/admin/submissions?includeData=true", {
      headers: authHeaders
    });
    console.log("GET /api/admin/submissions?includeData=true", adminSubsWithData.status, adminSubsWithData.json);
    total += 1;
    if (adminSubsWithData.status !== 200) {
      failures.push(
        `FAIL GET /api/admin/submissions?includeData=true status=${adminSubsWithData.status} body=${JSON.stringify(
          adminSubsWithData.json
        )}`
      );
    }

    if (firstSlug) {
      const exportSubsCsv = await requestRaw(
        "GET",
        `/api/admin/submissions/export?formSlug=${encodeURIComponent(firstSlug)}&format=csv&mode=flat`,
        { headers: authHeaders }
      );
      console.log("GET /api/admin/submissions/export csv", exportSubsCsv.status, exportSubsCsv.contentType);
      total += 1;
      if (exportSubsCsv.status !== 200 || !exportSubsCsv.contentType.includes("text/csv")) {
        failures.push(
          `FAIL GET /api/admin/submissions/export csv status=${exportSubsCsv.status} contentType=${exportSubsCsv.contentType} body=${JSON.stringify(
            exportSubsCsv.bodyText
          )}`
        );
      }

      const exportSubsTxt = await requestRaw(
        "GET",
        `/api/admin/submissions/export?formSlug=${encodeURIComponent(firstSlug)}&format=txt&mode=json`,
        { headers: authHeaders }
      );
      console.log("GET /api/admin/submissions/export txt", exportSubsTxt.status, exportSubsTxt.contentType);
      total += 1;
      if (exportSubsTxt.status !== 200 || !exportSubsTxt.contentType.includes("text/plain")) {
        failures.push(
          `FAIL GET /api/admin/submissions/export txt status=${exportSubsTxt.status} contentType=${exportSubsTxt.contentType} body=${JSON.stringify(
            exportSubsTxt.bodyText
          )}`
        );
      }

      const exportFormsCsv = await requestRaw(
        "GET",
        `/api/admin/forms/${encodeURIComponent(firstSlug)}/export?format=csv`,
        { headers: authHeaders }
      );
      console.log("GET /api/admin/forms/:slug/export csv", exportFormsCsv.status, exportFormsCsv.contentType);
      total += 1;
      if (exportFormsCsv.status !== 200 || !exportFormsCsv.contentType.includes("text/csv")) {
        failures.push(
          `FAIL GET /api/admin/forms/${firstSlug}/export csv status=${exportFormsCsv.status} contentType=${exportFormsCsv.contentType} body=${JSON.stringify(
            exportFormsCsv.bodyText
          )}`
        );
      }

      const exportFormsTxt = await requestRaw(
        "GET",
        `/api/admin/forms/${encodeURIComponent(firstSlug)}/export?format=txt`,
        { headers: authHeaders }
      );
      console.log("GET /api/admin/forms/:slug/export txt", exportFormsTxt.status, exportFormsTxt.contentType);
      total += 1;
      if (exportFormsTxt.status !== 200 || !exportFormsTxt.contentType.includes("text/plain")) {
        failures.push(
          `FAIL GET /api/admin/forms/${firstSlug}/export txt status=${exportFormsTxt.status} contentType=${exportFormsTxt.contentType} body=${JSON.stringify(
            exportFormsTxt.bodyText
          )}`
        );
      }
    }

    const templateKey = `smoke_template_${Date.now()}`;
    const schemaBody = {
      fields: [
        { id: "smoke_email", type: "email", label: "Email", required: false, rules: {} },
        { id: "smoke_text", type: "text", label: "Feedback", required: false }
      ]
    };
    const templateRes = await requestJson("POST", "/api/admin/templates", {
      headers: {
        ...authHeaders,
        "content-type": "application/json"
      },
      body: JSON.stringify({
        key: templateKey,
        name: "Smoke Template",
        schema_json: JSON.stringify(schemaBody)
      })
    });
    console.log("POST /api/admin/templates", templateRes.status, templateRes.json);
    total += 1;
    if (templateRes.status !== 201 && templateRes.status !== 409) {
      failures.push(
        `FAIL POST /api/admin/templates status=${templateRes.status} body=${JSON.stringify(templateRes.json)}`
      );
    }

    const slug = `drive-auto-test-${Date.now()}`;
    const createRes = await requestJson("POST", "/api/admin/forms", {
      headers: {
        ...authHeaders,
        "content-type": "application/json"
      },
      body: JSON.stringify({
        slug,
        title: "Drive Auto Test",
        templateKey,
        is_public: false,
        auth_policy: "optional"
      })
    });
    console.log("POST /api/admin/forms", createRes.status, createRes.json);
    total += 1;
    if (createRes.status !== 201) {
      failures.push(
        `FAIL POST /api/admin/forms status=${createRes.status} body=${JSON.stringify(createRes.json)}`
      );
    } else {
      const driveRes = await requestJson(
        "GET",
        `/api/admin/drive/form-folder?slug=${encodeURIComponent(slug)}`,
        { headers: authHeaders }
      );
      console.log("GET /api/admin/drive/form-folder", driveRes.status, driveRes.json);
      total += 1;
      if (driveRes.status !== 200) {
        failures.push(
          `FAIL GET /api/admin/drive/form-folder status=${driveRes.status} body=${JSON.stringify(driveRes.json)}`
        );
      }

      const lockRes = await requestJson("PATCH", `/api/admin/forms/${encodeURIComponent(slug)}`, {
        headers: {
          ...authHeaders,
          "content-type": "application/json"
        },
        body: JSON.stringify({ is_locked: true })
      });
      console.log("PATCH /api/admin/forms (lock)", lockRes.status, lockRes.json);
      total += 1;
      if (lockRes.status !== 200) {
        failures.push(
          `FAIL PATCH /api/admin/forms lock status=${lockRes.status} body=${JSON.stringify(lockRes.json)}`
        );
      } else {
        const lockedSubmit = await requestJson("POST", "/api/submissions", {
          headers: {
            ...authHeaders,
            "content-type": "application/json"
          },
          body: JSON.stringify({
            formSlug: slug,
            data: { smoke: "locked" }
          })
        });
        console.log("POST /api/submissions (locked)", lockedSubmit.status, lockedSubmit.json);
        total += 1;
        if (lockedSubmit.status !== 423 && lockedSubmit.status !== 409) {
          failures.push(
            `FAIL POST /api/submissions locked status=${lockedSubmit.status} body=${JSON.stringify(
              lockedSubmit.json
            )}`
          );
        }
      }
    }

    const meDash = await requestJson("GET", "/api/me/submissions", { headers: authHeaders });
    console.log("GET /api/me/submissions", meDash.status, meDash.json);
    total += 1;
    if (meDash.status !== 200) {
      failures.push(
        `FAIL GET /api/me/submissions status=${meDash.status} body=${JSON.stringify(meDash.json)}`
      );
    }

    if (adminSubs.status === 200 && Array.isArray(adminSubs.json?.data) && adminSubs.json.data.length > 0) {
      const submissionId = lastSubmissionId || adminSubs.json.data[0].id;
      const uploadsRes = await requestJson(
        "GET",
        `/api/admin/submissions/${submissionId}/uploads`,
        { headers: authHeaders }
      );
      console.log("GET /api/admin/submissions/:id/uploads", uploadsRes.status, uploadsRes.json);
      total += 1;
      if (uploadsRes.status !== 200) {
        failures.push(
          `FAIL GET /api/admin/submissions/:id/uploads status=${uploadsRes.status} body=${JSON.stringify(uploadsRes.json)}`
        );
      } else {
        const firstUpload = uploadsRes.json?.data?.[0];
        if (firstUpload && !firstUpload.vt_status && !firstUpload.vt_verdict && !firstUpload.vt_error) {
          failures.push("FAIL uploads missing vt_status/vt_verdict/vt_error");
        }
      }

      const verifyRes = await requestJson(
        "GET",
        `/api/admin/uploads/verify?submissionId=${encodeURIComponent(submissionId)}`,
        { headers: authHeaders }
      );
      console.log("GET /api/admin/uploads/verify", verifyRes.status, verifyRes.json);
      total += 1;
      if (verifyRes.status !== 200) {
        failures.push(
          `FAIL GET /api/admin/uploads/verify status=${verifyRes.status} body=${JSON.stringify(verifyRes.json)}`
        );
      }

      if (adminHealth.json?.hasDriveServiceAccount && adminHealth.json?.hasDriveParentFolderId) {
        const finalizeRes = await requestJson(
          "POST",
          `/api/admin/submissions/${encodeURIComponent(submissionId)}/finalize`,
          { headers: authHeaders }
        );
        console.log("POST /api/admin/submissions/:id/finalize", finalizeRes.status, finalizeRes.json);
        total += 1;
        if (finalizeRes.status !== 200) {
          failures.push(
            `FAIL POST /api/admin/submissions/:id/finalize status=${finalizeRes.status} body=${JSON.stringify(
              finalizeRes.json
            )}`
          );
        }
      }
    }
  }

  if (failures.length > 0) {
    failures.forEach((line) => console.error(line));
  }
  const passed = total - failures.length;
  console.log(`Summary: passed ${passed} / failed ${failures.length} / total ${total}`);
  process.exit(failures.length > 0 ? 1 : 0);
}

run().catch((error) => {
  console.error("Smoke test failed", error?.message || error);
  process.exit(1);
});
