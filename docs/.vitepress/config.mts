import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vitepress";
import { withMermaid } from "vitepress-plugin-mermaid";

function packageNameFromId(id: string): string | null {
  const [, pkgPath] = id.split("node_modules/");
  if (!pkgPath) {
    return null;
  }

  const parts = pkgPath.split("/");
  if (parts[0].startsWith("@") && parts.length > 1) {
    return `${parts[0]}/${parts[1]}`;
  }

  return parts[0] ?? null;
}

export default withMermaid(
  defineConfig({
    title: "Argis Developers",
    description: "Documentation for the Argis phishing email detection platform",
    base: "/Argis/",
    cleanUrls: true,
    lastUpdated: true,
    vite: {
      resolve: {
        alias: {
          "vitepress-plugin-mermaid/Mermaid.vue": fileURLToPath(
            new URL("./theme/Mermaid.vue", import.meta.url)
          )
        }
      },
      build: {
        // Mermaid remains a large async-only dependency even after code splitting.
        chunkSizeWarningLimit: 2100,
        rollupOptions: {
          output: {
            manualChunks(id) {
              if (!id.includes("node_modules")) {
                return;
              }

              const pkg = packageNameFromId(id);
              if (!pkg) {
                return;
              }

              if (pkg.includes("mermaid") || pkg === "dagre-d3-es" || pkg === "khroma") {
                return "mermaid-vendor";
              }

              if (pkg === "cytoscape") {
                return "cytoscape-vendor";
              }

              if (pkg === "katex") {
                return "katex-vendor";
              }

              if (pkg.startsWith("d3-")) {
                return "d3-vendor";
              }
            }
          }
        }
      }
    },
    themeConfig: {
      outline: {
        level: [2, 3],
        label: "On This Page"
      },
      docFooter: {
        prev: "Previous",
        next: "Next"
      },
      editLink: {
        pattern: "https://github.com/puyanguvic/Argis/edit/main/docs/:path",
        text: "Edit this page"
      },
      nav: [
        { text: "Home", link: "/" },
        { text: "Docs", link: "/argis/" },
        { text: "API", link: "/api/" },
        { text: "Architecture", link: "/argis/architecture/" },
        { text: "Operations", link: "/argis/operations/" },
        { text: "Blog", link: "/blog/" }
      ],
      sidebar: {
        "/argis/": [
          {
            text: "Getting Started",
            items: [
              { text: "Overview", link: "/argis/getting-started/overview" },
              { text: "Quickstart", link: "/argis/getting-started/quickstart" },
              { text: "Explore", link: "/argis/getting-started/explore" },
              { text: "Concepts", link: "/argis/getting-started/concepts" },
              { text: "Glossary", link: "/argis/getting-started/glossary" }
            ]
          },
          {
            text: "Using Argis",
            items: [
              { text: "Overview", link: "/argis/using-argis/" },
              { text: "App", link: "/argis/using-argis/app" },
              { text: "CLI", link: "/argis/using-argis/cli" },
              { text: "Integrations", link: "/argis/using-argis/integrations" }
            ]
          },
          {
            text: "Configurations",
            items: [
              { text: "Overview", link: "/argis/configurations/" },
              { text: "Config File", link: "/argis/configurations/config-file" },
              { text: "Rules", link: "/argis/configurations/rules" },
              { text: "Agents.md", link: "/argis/configurations/agents-md" },
              { text: "MCP", link: "/argis/configurations/mcp" },
              { text: "Skills", link: "/argis/configurations/skills" },
              { text: "Context Management", link: "/argis/configurations/context-management" }
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
              { text: "Release Gates", link: "/argis/operations/release-gates" },
              { text: "Docs Style Guide", link: "/argis/operations/docs-style-guide" }
            ]
          }
        ],
        "/api/": [
          {
            text: "API",
            items: [
              { text: "Overview", link: "/api/" },
              { text: "Guides and Concepts", link: "/api/guides-concepts" },
              { text: "API Reference", link: "/api/reference" },
              { text: "API Contract", link: "/api/contract" },
              { text: "Migration Guide", link: "/api/migration-guide" }
            ]
          }
        ],
        "/blog/": [
          {
            text: "Technical Documents",
            items: [
              { text: "Overview", link: "/blog/technical-docs/" },
              {
                text: "When One GPU Is No Longer Enough",
                link: "/blog/technical-docs/when-one-gpu-is-no-longer-enough"
              },
              {
                text: "2026-03-05: IA Update",
                link: "/blog/technical-docs/2026-03-05-docs-ia-update"
              }
            ]
          },
          {
            text: "Cookbook",
            items: [
              { text: "Overview", link: "/blog/cookbook/" }
            ]
          },
          {
            text: "Templates",
            items: [
              { text: "Post Template", link: "/blog/post-template" }
            ]
          }
        ],
        "/": [
          {
            text: "Start Here",
            items: [
              { text: "Home", link: "/" },
              { text: "Docs Overview", link: "/argis/" },
              { text: "Quickstart", link: "/argis/getting-started/quickstart" },
              { text: "API Overview", link: "/api/" },
              { text: "Architecture", link: "/argis/architecture/" },
              { text: "Operations", link: "/argis/operations/" },
              { text: "Blog", link: "/blog/" }
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
