import { defineConfig } from "vitepress";

const base = process.env.BASE_URL ?? "/";

export default defineConfig({
  base,
  title: "Argis Docs",
  description: "Documentation for Argis (Phish Email Detection Agent)",
  cleanUrls: true,
  themeConfig: {
    nav: [
      { text: "Get started", link: "/get-started/" },
      { text: "Using Argis", link: "/using-argis/" },
      { text: "Configuration", link: "/configuration/" },
      { text: "Releases", link: "/releases/" },
    ],
    sidebar: {
      "/get-started/": [
        {
          text: "Get started",
          items: [
            { text: "Overview", link: "/get-started/overview/" },
            { text: "Quickstart", link: "/get-started/quickstart" },
            { text: "Concepts", link: "/get-started/concepts/" },
          ],
        },
      ],
      "/using-argis/": [
        {
          text: "Using Argis",
          items: [
            { text: "Overview", link: "/using-argis/" },
            { text: "CLI", link: "/using-argis/cli" },
            { text: "Gradio demo", link: "/using-argis/gradio-demo" },
            { text: "Connectors", link: "/using-argis/connectors/" },
            { text: "Deployment", link: "/using-argis/deployment/" },
            { text: "Reporting", link: "/using-argis/reporting/" },
          ],
        },
      ],
      "/configuration/": [
        {
          text: "Configuration",
          items: [
            { text: "Overview", link: "/configuration/" },
            { text: "Config file", link: "/configuration/config-file" },
            { text: "Rules and weights", link: "/configuration/rules" },
            { text: "Skills", link: "/configuration/skills/" },
            { text: "Extending Argis", link: "/configuration/extending/" },
          ],
        },
      ],
      "/releases/": [
        {
          text: "Releases",
          items: [
            { text: "Overview", link: "/releases/" },
            { text: "Changelog", link: "/releases/changelog" },
            { text: "Feature maturity", link: "/releases/feature-maturity" },
            { text: "Open source", link: "/releases/open-source" },
          ],
        },
      ],
    },
    footer: {
      message: "Evidence-first, deterministic, and auditable.",
      copyright: "Copyright © Argis",
    },
  },
});
