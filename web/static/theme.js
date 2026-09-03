/* Applique le thème stocké avant le premier rendu, pour éviter tout flash.
   Chargé de façon synchrone dans <head> : volontairement minuscule. */
(function () {
  try {
    var stored = localStorage.getItem("securepass-theme");
    if (stored === "light" || stored === "dark") {
      document.documentElement.setAttribute("data-theme", stored);
    }
  } catch (e) {
    /* localStorage indisponible (mode privé, cookies bloqués) : on garde
       la préférence système gérée en CSS. */
  }
})();
