/* 
 * VERSIONING API ENDPOINTS - REFERENCE CODE
 * 
 * This file contains reference code snippets to be manually integrated into index.ts
 * around line 10426 (within the handler function where request, env, url, etc. are available).
 * 
 * This file will show lint errors because it's not a standalone module - that's expected.
 * The code is meant to be copied into the handler function context in index.ts.
 */

// @ts-nocheck
export { }; // Make this a module to suppress some errors

// GET /api/admin/submissions/:submissionId/versions - List all versions
if (request.method === "GET" && url.pathname.match(/^\/api\/admin\/submissions\/([^/]+)\/versions$/)) {
    const authPayload = await getAuthPayload(request, env);
    if (!authPayload?.isAdmin) {
        return errorResponse(403, "forbidden", requestId, corsHeaders);
    }

    const match = url.pathname.match(/^\/api\/admin\/submissions\/([^/]+)\/versions$/);
    const submissionId = decodeURIComponent(match![1]);

    const submission = await env.DB.prepare(
        "SELECT s.id, s.form_id, f.slug, f.save_all_versions FROM submissions s JOIN forms f ON f.id=s.form_id WHERE s.id=?"
    )
        .bind(submissionId)
        .first<{ id: string; form_id: string; slug: string; save_all_versions: number | null }>();

    if (!submission) {
        return errorResponse(404, "not_found", requestId, corsHeaders);
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

// GET /api/admin/submissions/:submissionId/versions/:versionNumber - Get specific version
if (request.method === "GET" && url.pathname.match(/^\/api\/admin\/submissions\/([^/]+)\/versions\/(\d+)$/)) {
    const authPayload = await getAuthPayload(request, env);
    if (!authPayload?.isAdmin) {
        return errorResponse(403, "forbidden", requestId, corsHeaders);
    }

    const match = url.pathname.match(/^\/api\/admin\/submissions\/([^/]+)\/versions\/(\d+)$/);
    const submissionId = decodeURIComponent(match![1]);
    const versionNumber = Number(match![2]);

    const version = await env.DB.prepare(
        "SELECT v.id, v.payload_json, v.version_number, v.created_at, v.created_by FROM submission_versions v JOIN submissions s ON s.id=v.submission_id JOIN forms f ON f.id=s.form_id WHERE v.submission_id=? AND v.version_number=?"
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

    return jsonResponse(200, {
        version: {
            id: version.id,
            version_number: version.version_number,
            data,
            created_at: version.created_at,
            created_by: version.created_by
        },
        requestId
    }, requestId, corsHeaders);
}
