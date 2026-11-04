const notice = document.querySelector("#notice");

function tell(message, error = false) {
  notice.textContent = message;
  notice.className = error ? "error" : "";
  notice.hidden = false;
}

for (const form of document.querySelectorAll("form[data-action]")) {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = form.querySelector("button");
    button.disabled = true;
    try {
      let body = Object.fromEntries(new FormData(form));
      for (const input of form.querySelectorAll('input[type="number"]'))
        body[input.name] = Number(input.value);
      if (form.hasAttribute("data-document")) body = JSON.parse(body.document);
      const response = await fetch(form.dataset.action, {
        method: form.dataset.method ?? "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const result = await response.json();
      if (!response.ok)
        throw new Error(result.error ?? "Something went wrong.");
      if (form.hasAttribute("data-stay"))
        tell(`Delivered to ${result.destination}.`);
      else if (form.hasAttribute("data-document")) {
        tell(
          `Imported ${result.invoice.reference}.${result.review.warning ? ` ${result.review.warning}` : ""}`,
        );
      } else
        window.location.assign(result.redirect ?? window.location.pathname);
    } catch (error) {
      tell(error.message, true);
    } finally {
      button.disabled = false;
    }
  });
}

for (const button of document.querySelectorAll("[data-preview]")) {
  button.addEventListener("click", async () => {
    try {
      const response = await fetch(button.dataset.preview);
      const preview = await response.json();
      if (!response.ok) throw new Error(preview.error);
      const dialog = document.querySelector("#preview-dialog");
      dialog.querySelector(".preview-body").textContent =
        `${preview.reference}\n${preview.customer}\n${new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format(preview.amountCents / 100)}`;
      dialog.showModal();
    } catch (error) {
      tell(error.message, true);
    }
  });
}

document
  .querySelector("[data-close]")
  ?.addEventListener("click", () =>
    document.querySelector("#preview-dialog").close(),
  );
