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
        {
          text: "API",
          items: [
            { text: "API Home", link: "/api/" },
            { text: "Guides and Concepts", link: "/api/guides-concepts" },
            { text: "API Reference", link: "/api/reference" }
          ]
        },
        {
          text: "Argis",
          items: [
            { text: "Argis Home", link: "/argis/" },
            { text: "Overview", link: "/argis/getting-started/overview" },
            { text: "Quickstart", link: "/argis/getting-started/quickstart" },
            { text: "App", link: "/argis/using-argis/app" },
            { text: "CLI", link: "/argis/using-argis/cli" },
            { text: "Config File", link: "/argis/configurations/config-file" },
            { text: "Architecture", link: "/argis/architecture/" },
            { text: "Operations", link: "/argis/operations/" }
          ]
        },
        {
          text: "Blog",
          items: [
            { text: "Blog Home", link: "/blog/" },
            { text: "Latest Post", link: "/blog/2026-03-05-docs-ia-update" }
          ]
        }
      ],
      sidebar: {
        "/argis/": [
          {
            text: "Getting Started",
            items: [
              { text: "Overview", link: "/argis/getting-started/overview" },
              { text: "Quickstart", link: "/argis/getting-started/quickstart" },
              { text: "Explore", link: "/argis/getting-started/explore" },
              { text: "Concepts", link: "/argis/getting-started/concepts" }
            ]
          },
          {
            text: "Using Argis",
            items: [
              { text: "App", link: "/argis/using-argis/app" },
              { text: "CLI", link: "/argis/using-argis/cli" },
              { text: "Integrations", link: "/argis/using-argis/integrations" }
            ]
          },
          {
            text: "Configurations",
            items: [
              { text: "Config File", link: "/argis/configurations/config-file" },
              { text: "Rules", link: "/argis/configurations/rules" },
              { text: "Agents.md", link: "/argis/configurations/agents-md" },
              { text: "MCP", link: "/argis/configurations/mcp" },
              { text: "Skills", link: "/argis/configurations/skills" },
              { text: "Context Manage", link: "/argis/configurations/context-manage" }
            ]
          },
          {
            text: "Architecture",
            items: [
              { text: "Architecture Home", link: "/argis/architecture/" },
              { text: "Design Overview", link: "/argis/architecture/design-overview" },
              { text: "Runtime Flow", link: "/argis/architecture/runtime-flow" }
            ]
          },
          {
            text: "Operations",
            items: [
              { text: "Operations Home", link: "/argis/operations/" },
              { text: "Runbook", link: "/argis/operations/runbook" },
              { text: "Observability", link: "/argis/operations/observability" },
              { text: "Security Boundary", link: "/argis/operations/security-boundary" },
              { text: "Release Gates", link: "/argis/operations/release-gates" }
            ]
          }
        ],
        "/api/": [
          {
            text: "API",
            items: [
              { text: "Guides and Concepts", link: "/api/guides-concepts" },
              { text: "API Reference", link: "/api/reference" }
            ]
          }
        ],
        "/blog/": [
          {
            text: "Blog",
            items: [
              { text: "Blog Home", link: "/blog/" },
              { text: "2026-03-05: IA Update", link: "/blog/2026-03-05-docs-ia-update" },
              { text: "Post Template", link: "/blog/post-template" }
            ]
          }
        ],
        "/": [
          {
            text: "Legacy Docs",
            items: [
              { text: "Manual", link: "/manual" },
              { text: "Design", link: "/design" },
              { text: "Migration Guide", link: "/migration-guide" },
              { text: "Runbook", link: "/runbook" },
              { text: "Observability", link: "/observability" },
              { text: "Security Boundary", link: "/security-boundary" },
              { text: "Release Gates", link: "/release-gates" },
              { text: "Changelog", link: "/changelog" },
              { text: "Release Notes", link: "/releases" }
            ]
          }
        ]
      },
      socialLinks: [{ icon: "github", link: "https://github.com/puyanguvic/Argis" }],
      search: {
        provider: "local"
      }
    }
  })
);
