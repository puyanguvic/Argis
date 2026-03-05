import { defineConfig } from "vitepress";
import { withMermaid } from "vitepress-plugin-mermaid";

export default withMermaid(
  defineConfig({
  title: "Argis Docs",
  description: "Phishing email detection agent documentation",
  base: "/Argis/",
  cleanUrls: true,
  lastUpdated: true,
  themeConfig: {
    nav: [
      { text: "Home", link: "/" },
      { text: "Design", link: "/design" },
      { text: "Manual", link: "/manual" },
      { text: "API", link: "/api-contract" },
      { text: "Runbook", link: "/runbook" },
      { text: "Changelog", link: "/changelog" },
      { text: "Release", link: "/releases" }
    ],
    sidebar: [
      {
        text: "Overview",
        items: [
          { text: "Home", link: "/" },
          { text: "Manual", link: "/manual" },
          { text: "Design", link: "/design" },
          { text: "API Contract", link: "/api-contract" },
          { text: "Migration Guide", link: "/migration-guide" }
        ]
      },
      {
        text: "Operations",
        items: [
          { text: "Runbook", link: "/runbook" },
          { text: "Observability", link: "/observability" },
          { text: "Security Boundary", link: "/security-boundary" },
          { text: "Release Gates", link: "/release-gates" }
        ]
      },
      {
        text: "Project History",
        items: [
          { text: "Changelog", link: "/changelog" },
          { text: "Release Notes", link: "/releases" }
        ]
      }
    ],
    socialLinks: [{ icon: "github", link: "https://github.com/puyanguvic/Argis" }],
    search: {
      provider: "local"
    }
  }
  })
);
