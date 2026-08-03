const elements = {
  form: document.getElementById("searchForm"),
  locationInput: document.getElementById("locationInput"),
  industryInput: document.getElementById("industryInput"),
  radiusInput: document.getElementById("radiusInput"),
  searchButton: document.getElementById("searchButton"),
  statusPill: document.getElementById("statusPill"),
  resultCount: document.getElementById("resultCount"),
  resultsNote: document.getElementById("resultsNote"),
  resultsList: document.getElementById("resultsList"),
};

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function setStatus(text, tone = "idle") {
  elements.statusPill.textContent = text;
  elements.statusPill.dataset.tone = tone;
}

function renderResults(payload) {
  const results = Array.isArray(payload.results) ? payload.results : [];
  elements.resultCount.textContent = `${results.length} wyników`;

  if (!results.length) {
    elements.resultsNote.textContent = "Brak trafień dla tej lokalizacji i sektora.";
    elements.resultsList.innerHTML = '<div class="empty">Brak wyników. Spróbuj innej lokalizacji, sektora albo większego promienia.</div>';
    return;
  }

  elements.resultsNote.textContent = `Znaleziono ${results.length} trafień.`;
  elements.resultsList.innerHTML = results
    .map((lead) => {
      const geo = lead.geo || {};
      const address = geo.address || "Brak adresu";
      const score = lead.total_score ?? 0;
      const category = geo.category || lead.priority || "brak kategorii";
      const url = lead.url || "#";
      return `
        <article class="result-card">
          <div class="result-top">
            <div>
              <h3>${escapeHtml(geo.name || lead.domain || "Bez nazwy")}</h3>
              <p>${escapeHtml(geo.city || "Brak miasta")}${geo.postcode ? `, ${escapeHtml(geo.postcode)}` : ""}</p>
            </div>
            <strong class="score">${escapeHtml(score)}</strong>
          </div>
          <div class="chips">
            <span>${escapeHtml(category)}</span>
            <span>${escapeHtml(address)}</span>
          </div>
          <a href="${escapeHtml(url)}" target="_blank" rel="noreferrer">Otwórz stronę</a>
        </article>
      `;
    })
    .join("");
}

function resetView() {
  elements.form.reset();
  elements.radiusInput.value = "10";
  elements.resultCount.textContent = "0 wyników";
  elements.resultsNote.textContent = "Wpisz lokalizację, sektor strategiczny i promień, potem kliknij Szukaj.";
  elements.resultsList.innerHTML = "";
  setStatus("Gotowe", "idle");
}

async function searchLeads(event) {
  event.preventDefault();
  const location = elements.locationInput.value.trim();
  const sector = elements.industryInput.value.trim();
  const radiusMiles = Number.parseFloat(elements.radiusInput.value) || 10;
  const params = new URLSearchParams();

  if (location) params.set("location", location);
  if (sector) params.set("sector", sector);
  params.set("radius_miles", String(radiusMiles));

  setStatus("Szukam...", "loading");
  elements.searchButton.disabled = true;

  try {
    const response = await fetch(`/api/search?${params.toString()}`);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const payload = await response.json();
    renderResults(payload);
    setStatus("Gotowe", payload.count ? "ready" : "idle");
  } catch (error) {
    console.error(error);
    elements.resultsNote.textContent = "Nie udało się pobrać wyników z backendu.";
    elements.resultsList.innerHTML = '<div class="empty">Błąd połączenia z backendem.</div>';
    setStatus("Błąd", "error");
  } finally {
    elements.searchButton.disabled = false;
  }
}

elements.form.addEventListener("submit", searchLeads);
resetView();