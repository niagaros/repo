// Waar hoort deze persoon na het inloggen terecht te komen?
//
// Tot nu toe eindigde iedereen op dezelfde plek: App.tsx haalde de
// dashboardgegevens op, zag dat er geen cloudaccount was, en toonde de wizard
// die vraagt om AWS te koppelen. Voor de beheerder die zich als eerste van een
// bedrijf aanmeldt klopt dat. Voor de twee groepen die hij daarna uitnodigt
// niet:
//
//   - Een uitgenodigd teamlid kwam in die wizard terecht, in een organisatie
//     die de trigger zojuist voor hem had aangemaakt, met het verzoek een
//     cloudaccount te koppelen dat zijn collega al had gekoppeld.
//   - Een auditor kreeg hetzelfde scherm. Dat is nog ongelukkiger: hij komt
//     van buiten, is uitgenodigd voor één opdracht, en kreeg als eerste indruk
//     het verzoek de infrastructuur van zijn eigen werkgever aan te sluiten.
//
// Gevonden op 15 oktober bij een volledige doorloop als nieuwe klant.
//
// De keuze wordt hier niet aan de gebruiker gevraagd. Dat zou een bewering van
// de voorkant zijn, en het hele ontwerp rust erop dat de achterkant vaststelt
// wat waar is. Het platform weet dit al: de uitnodiging staat op e-mailadres in
// team_invites, het engagement in engagement_auditors. Er valt dus niets te
// vragen, alleen op te zoeken.

function getApiBase(): string {
  return (window as any).__NIAGAROS_CONFIG__?.REACT_APP_API_BASE_URL || "";
}

/**
 * Issue #265, acceptatiecriterium 1. Idempotent: een no-op voor iedereen zonder
 * openstaande uitnodiging, en veilig om bij elke paginalading aan te roepen.
 *
 * Stond eerder alleen in useRequireAuth, dus alleen op de instellingenpagina's.
 * Wie na registratie op het eerste scherm belandde — precies de uitgenodigde —
 * kwam daar nooit, en zijn uitnodiging bleef openstaan.
 */
export async function acceptPendingInvite(token: string): Promise<void> {
  try {
    await fetch(`${getApiBase()}/team/accept-invite`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
  } catch {
    // Mag een pagina nooit tegenhouden.
  }
}

/**
 * Stuurt een auditor naar zijn portaal en meldt of dat is gebeurd.
 *
 * /auditor/scope is hier een schone scheidslijn: 200 betekent een lopend
 * engagement, en al het andere — geen engagement, afgelopen, vroegtijdig
 * gesloten — geeft 401. Dat oordeel komt van de achterkant; hier wordt alleen
 * op gerouteerd.
 */
export async function redirectAuditorToPortal(token: string): Promise<boolean> {
  // Zelf al op het portaal: niets doen, anders stuurt dit zichzelf rond.
  if (window.location.pathname.startsWith("/auditor")) return false;
  try {
    const resp = await fetch(`${getApiBase()}/auditor/scope`, {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    });
    if (!resp.ok) return false;
  } catch {
    return false;
  }
  window.location.href = "/auditor";
  return true;
}

/**
 * Hoort deze persoon de AWS-wizard te zien?
 *
 * Alleen als zijn organisatie nog geen cloudaccount heeft. Is stap 1 al
 * afgerond, dan is hij bij een bestaand team gekomen en hoeft hij niets te
 * koppelen — dan is het onboardingoverzicht de juiste plek, want daar ziet hij
 * waar zijn organisatie staat.
 *
 * Het voortgangseindpunt beantwoordt dat al, en het leest die toestand
 * server-side uit de database. Vandaar dat het hier wordt hergebruikt in plaats
 * van /team/cloud-accounts, dat alleen beheerders mogen opvragen.
 */
export async function organizationAlreadyHasInfrastructure(token: string): Promise<boolean> {
  try {
    const resp = await fetch(`${getApiBase()}/onboarding/progress`, {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    });
    if (!resp.ok) return false;
    const data = await resp.json();
    const stap = (data.steps || []).find((s: { step: string }) => s.step === "infrastructure");
    return Boolean(stap?.done);
  } catch {
    return false;
  }
}
