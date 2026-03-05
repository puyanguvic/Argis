import DefaultTheme from "vitepress/theme";
import { h } from "vue";
import VPNavBarSearch from "vitepress/dist/client/theme-default/components/VPNavBarSearch.vue";
import "./custom.css";

export default {
  ...DefaultTheme,
  Layout: () =>
    h(DefaultTheme.Layout, null, {
      "sidebar-nav-before": () =>
        h("div", { class: "VPDocSidebarSearch" }, [h(VPNavBarSearch)]),
    }),
};
