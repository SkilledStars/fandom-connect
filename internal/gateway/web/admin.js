document.querySelectorAll("[data-campaign-search]").forEach((search) => {
  const account = search.closest(".account");
  if (!account) return;

  const rows = Array.from(account.querySelectorAll("[data-campaign-row]"));
  const count = account.querySelector("[data-campaign-count]");
  const noResults = account.querySelector("[data-campaign-no-results]");

  search.addEventListener("input", () => {
    const query = search.value.trim().toLocaleLowerCase();
    let visible = 0;

    rows.forEach((row) => {
      const matches =
        query === "" || row.textContent.toLocaleLowerCase().includes(query);
      row.hidden = !matches;
      if (matches) visible += 1;
    });

    if (count) {
      count.textContent = query
        ? `${visible} of ${rows.length} campaigns`
        : `${rows.length} campaigns`;
    }
    if (noResults) noResults.hidden = visible !== 0;
  });
});
