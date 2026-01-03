import pkg from "../../../package.json";

const repoLicense =
  typeof pkg === "object" && pkg && "license" in pkg && typeof pkg.license === "string"
    ? pkg.license
    : "MIT";

export const APP_INFO = {
  title: "Form App",
  author: "Duc A. Hoang",
  license: repoLicense || "MIT",
  repoUrl: "https://github.com/hoanganhduc/forms",
  description: "Browse and submit public forms with secure authentication."
};
