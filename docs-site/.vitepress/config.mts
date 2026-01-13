import { defineConfig } from "vitepress";

export default defineConfig({
  title: "Argis",
  description: "Phish Email Detection Agent documentation",
  srcDir: "../docs",
  outDir: "dist",
  cleanUrls: true,
  vite: {
    resolve: {
      alias: {
        "vue/server-renderer": "@vue/server-renderer"
      }
    }
  },
  themeConfig: {
    search: {
      provider: "local"
    },
    nav: [
      { text: "Get Started", link: "/get-started/" },
      { text: "Using Argis", link: "/using-argis/" },
      { text: "Configuration", link: "/configuration/" },
      { text: "Releases", link: "/releases/" }
    ],
    sidebar: {
      "/get-started/": [
        { text: "Get Started", link: "/get-started/" },
        {
          text: "Overview",
          items: [
            { text: "Overview", link: "/get-started/overview/" },
            { text: "Problem Statement", link: "/get-started/overview/problem-statement" },
            { text: "Threat Landscape", link: "/get-started/overview/threat-landscape" },
            { text: "Design Goals", link: "/get-started/overview/design-goals" }
          ]
        },
        { text: "Quickstart", link: "/get-started/quickstart" },
        {
          text: "Concepts",
          items: [
            { text: "Concepts", link: "/get-started/concepts/" },
            {
              text: "Architecture",
              items: [
                { text: "System Overview", link: "/get-started/concepts/architecture/system-overview" },
                { text: "Agent Components", link: "/get-started/concepts/architecture/agent-components" },
                { text: "Workflow Pipeline", link: "/get-started/concepts/architecture/workflow-pipeline" },
                { text: "Toolchain", link: "/get-started/concepts/architecture/toolchain" },
                { text: "Execution Model", link: "/get-started/concepts/architecture/execution-model" }
              ]
            },
            {
              text: "Agent",
              items: [
                { text: "Roles", link: "/get-started/concepts/agent/roles" },
                { text: "Decision Logic", link: "/get-started/concepts/agent/decision-logic" },
                { text: "Reasoning Policy", link: "/get-started/concepts/agent/reasoning-policy" },
                { text: "Failure Modes", link: "/get-started/concepts/agent/failure-modes" }
              ]
            },
            {
              text: "Detection Pipeline",
              items: [
                { text: "Ingestion", link: "/get-started/concepts/pipeline/ingestion" },
                { text: "Parsing", link: "/get-started/concepts/pipeline/parsing" },
                { text: "Normalization", link: "/get-started/concepts/pipeline/normalization" },
                { text: "Evidence Collection", link: "/get-started/concepts/pipeline/evidence-collection" },
                { text: "Risk Scoring", link: "/get-started/concepts/pipeline/risk-scoring" }
              ]
            },
            {
              text: "Policies",
              items: [
                { text: "Security", link: "/get-started/concepts/policies/security" },
                { text: "Privacy", link: "/get-started/concepts/policies/privacy" },
                { text: "Compliance", link: "/get-started/concepts/policies/compliance" },
                { text: "Escalation", link: "/get-started/concepts/policies/escalation" }
              ]
            },
            {
              text: "Evaluation",
              items: [
                { text: "Metrics", link: "/get-started/concepts/evaluation/metrics" },
                { text: "Benchmarks", link: "/get-started/concepts/evaluation/benchmarks" },
                { text: "Limitations", link: "/get-started/concepts/evaluation/limitations" }
              ]
            },
            {
              text: "Governance",
              items: [
                { text: "Model Updates", link: "/get-started/concepts/governance/model-updates" },
                { text: "Audit Traceability", link: "/get-started/concepts/governance/audit-traceability" }
              ]
            },
            {
              text: "Protocol",
              items: [
                { text: "Protocol v1", link: "/get-started/concepts/protocol/v1" }
              ]
            },
            { text: "Glossary", link: "/get-started/concepts/glossary" },
            {
              text: "Legacy",
              items: [
                { text: "Architecture (Legacy)", link: "/get-started/concepts/legacy/architecture" },
                { text: "Methodology (Legacy)", link: "/get-started/concepts/legacy/methodology" },
                { text: "Threat Model (Legacy)", link: "/get-started/concepts/legacy/threat-model" }
              ]
            }
          ]
        }
      ],
      "/using-argis/": [
        { text: "Using Argis", link: "/using-argis/" },
        { text: "CLI", link: "/using-argis/cli" },
        { text: "Gradio Demo", link: "/using-argis/gradio-demo" },
        {
          text: "Connectors",
          items: [
            { text: "Connectors", link: "/using-argis/connectors/" },
            { text: "IMAP", link: "/using-argis/connectors/imap" },
            { text: "Gmail", link: "/using-argis/connectors/gmail" }
          ]
        },
        {
          text: "Deployment",
          items: [
            { text: "Deployment", link: "/using-argis/deployment/" },
            { text: "Models", link: "/using-argis/deployment/models" },
            { text: "Integration", link: "/using-argis/deployment/integration" },
            { text: "Operations", link: "/using-argis/deployment/operations" }
          ]
        },
        {
          text: "Reporting",
          items: [
            { text: "Reporting", link: "/using-argis/reporting/" },
            { text: "Overview", link: "/using-argis/reporting/overview" },
            { text: "Executive Summary", link: "/using-argis/reporting/executive-summary" },
            { text: "Evidence Table", link: "/using-argis/reporting/evidence-table" },
            { text: "Attack Narrative", link: "/using-argis/reporting/attack-narrative" },
            { text: "Recommendations", link: "/using-argis/reporting/recommendation" },
            { text: "Machine Output", link: "/using-argis/reporting/machine-output" }
          ]
        }
      ],
      "/configuration/": [
        { text: "Configuration", link: "/configuration/" },
        { text: "Config File", link: "/configuration/config-file" },
        { text: "Rules", link: "/configuration/rules" },
        { text: "AGENTS", link: "/configuration/agents-md" },
        { text: "Custom Prompts", link: "/configuration/custom-prompts" },
        { text: "MCP", link: "/configuration/mcp" },
        {
          text: "Skills",
          items: [
            { text: "Skills", link: "/configuration/skills/" },
            { text: "Overview", link: "/configuration/skills/overview" },
            { text: "Brand Impersonation", link: "/configuration/skills/brand-impersonation" },
            { text: "BEC Detection", link: "/configuration/skills/bec-detection" },
            { text: "URL Analysis", link: "/configuration/skills/url-analysis" },
            { text: "Header Forensics", link: "/configuration/skills/header-forensics" },
            { text: "Attachment Analysis", link: "/configuration/skills/attachment-analysis" }
          ]
        },
        {
          text: "Extending",
          items: [
            { text: "Extending", link: "/configuration/extending/" },
            { text: "Code Structure", link: "/configuration/extending/code-structure" },
            { text: "Adding Skills", link: "/configuration/extending/adding-skills" },
            { text: "Adding Tools", link: "/configuration/extending/adding-tools" },
            { text: "Debugging", link: "/configuration/extending/debugging" }
          ]
        }
      ],
      "/releases/": [
        { text: "Releases", link: "/releases/" },
        { text: "Changelog", link: "/releases/changelog" },
        { text: "Feature Maturity", link: "/releases/feature-maturity" },
        { text: "Open Source", link: "/releases/open-source" }
      ]
    }
  }
});
