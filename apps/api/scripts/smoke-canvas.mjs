const API_BASE = process.env.API_BASE || "http://127.0.0.1:8787";
const TOKEN = process.env.TOKEN;

if (!TOKEN) {
  console.error("TOKEN is required for canvas smoke test.");
  process.exit(1);
}

const headers = {
  Authorization: `Bearer ${TOKEN}`
};

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      ...headers,
      ...(options.headers || {})
    }
  });
  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return { response, text, json };
}

async function main() {
  const health = await request("/api/admin/health");
  if (!health.response.ok) {
    console.error("FAIL admin health", health.response.status, health.text);
    process.exit(1);
  }

  const syncCourses = await request("/api/admin/canvas/sync", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ mode: "courses" })
  });
  if (!syncCourses.response.ok) {
    console.error("FAIL sync courses", syncCourses.response.status, syncCourses.text);
    process.exit(1);
  }

  const courses = await request("/api/admin/canvas/courses?page=1&pageSize=5");
  if (!courses.response.ok) {
    console.error("FAIL list courses", courses.response.status, courses.text);
    process.exit(1);
  }
  const courseList = Array.isArray(courses.json?.data) ? courses.json.data : [];
  if (courseList.length === 0) {
    console.error("FAIL no courses found in cache");
    process.exit(1);
  }
  const courseId = String(courseList[0].id);

  const syncSections = await request(`/api/admin/canvas/sync`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ mode: "course_sections", courseId })
  });
  if (!syncSections.response.ok) {
    console.error("FAIL sync sections", syncSections.response.status, syncSections.text);
    process.exit(1);
  }

  const sections = await request(
    `/api/admin/canvas/courses/${encodeURIComponent(courseId)}/sections?page=1&pageSize=5`
  );
  if (!sections.response.ok) {
    console.error("FAIL list sections", sections.response.status, sections.text);
    process.exit(1);
  }

  const templateKey = process.env.CANVAS_TEST_TEMPLATE_KEY || "hus_vi_1";
  const formSlug = `canvas-test-${Date.now()}`;
  const create = await request("/api/admin/forms", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      slug: formSlug,
      title: `Canvas Test ${new Date().toISOString()}`,
      templateKey,
      is_public: false,
      is_locked: false,
      auth_policy: "optional",
      canvasEnabled: true,
      canvasCourseId: courseId,
      canvasAllowedSectionIds: Array.isArray(sections.json?.data)
        ? sections.json.data.slice(0, 2).map((item) => String(item.id))
        : null
    })
  });
  if (!create.response.ok) {
    const detail = create.json?.detail?.message;
    if (detail === "template_not_found") {
      console.warn("WARN template not found; skipping form creation.");
    } else {
      console.error("FAIL create canvas form", create.response.status, create.text);
      process.exit(1);
    }
  }

  console.log("Canvas smoke test OK");
  process.exit(0);
}

main().catch((err) => {
  console.error("FAIL canvas smoke test", err);
  process.exit(1);
});
