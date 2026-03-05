import { defineConfig } from "vitepress";

export default defineConfig({
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
      { text: "Changelog", link: "/changelog" },
      { text: "Release", link: "/releases" }
    ],
    sidebar: [
      {
        text: "Overview",
        items: [
          { text: "Home", link: "/" },
          { text: "Manual", link: "/manual" },
          { text: "Design", link: "/design" }
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
});
