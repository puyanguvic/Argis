(() => {
  const toggle = document.querySelector(".menu-toggle");
  const overlay = document.querySelector("[data-overlay]");

  if (!toggle || !overlay) return;

  const setOpen = (isOpen) => {
    document.body.classList.toggle("nav-open", isOpen);
    toggle.setAttribute("aria-expanded", String(isOpen));
  };

  toggle.addEventListener("click", () => {
    const isOpen = !document.body.classList.contains("nav-open");
    setOpen(isOpen);
  });

  overlay.addEventListener("click", () => setOpen(false));
})();
