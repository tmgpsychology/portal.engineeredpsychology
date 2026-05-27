document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-password-toggle]");
  if (!button) {
    return;
  }

  const field = button.closest(".password-field");
  const input = field ? field.querySelector("[data-password-input]") : null;
  if (!input) {
    return;
  }

  const shouldShow = input.type === "password";
  input.type = shouldShow ? "text" : "password";
  button.textContent = shouldShow ? "Hide" : "Show";
  button.setAttribute("aria-label", shouldShow ? "Hide password" : "Show password");
});
