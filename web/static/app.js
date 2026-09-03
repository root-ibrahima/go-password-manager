/* ==========================================================================
   SecurePass — améliorations progressives.

   Tout ce fichier est optionnel : sans JavaScript, les pages restent
   complètement utilisables (formulaires HTML natifs, navigation classique).
   Aucune dépendance externe, conforme à la CSP `script-src 'self'`.
   ========================================================================== */

(function () {
  "use strict";

  var THEME_KEY = "securepass-theme";
  var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---------------------------------------------------------------- utils */

  function $(selector, root) {
    return (root || document).querySelector(selector);
  }

  function $$(selector, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(selector));
  }

  /* Décale l'animation d'entrée de chaque élément d'une série. */
  function stagger(selector) {
    $$(selector).forEach(function (el, i) {
      el.style.setProperty("--i", i);
    });
  }

  /* ---------------------------------------------------------------- thème */

  function currentTheme() {
    var explicit = document.documentElement.getAttribute("data-theme");
    if (explicit) {
      return explicit;
    }
    return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }

  function initThemeToggle() {
    var toggle = $("[data-theme-toggle]");
    if (!toggle) {
      return;
    }

    function sync() {
      var theme = currentTheme();
      toggle.setAttribute("aria-pressed", theme === "light" ? "true" : "false");
      toggle.setAttribute(
        "aria-label",
        theme === "light" ? "Activer le thème sombre" : "Activer le thème clair"
      );
    }

    toggle.addEventListener("click", function () {
      var next = currentTheme() === "light" ? "dark" : "light";
      document.documentElement.setAttribute("data-theme", next);
      try {
        localStorage.setItem(THEME_KEY, next);
      } catch (e) {
        /* Préférence non persistée : sans gravité. */
      }
      sync();
    });

    sync();
  }

  /* ------------------------------------------------------------- toasts */

  function toast(message) {
    var stack = $(".toast-stack");
    if (!stack) {
      stack = document.createElement("div");
      stack.className = "toast-stack";
      stack.setAttribute("role", "status");
      stack.setAttribute("aria-live", "polite");
      document.body.appendChild(stack);
    }

    var el = document.createElement("div");
    el.className = "toast";

    var icon = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    icon.setAttribute("class", "icon");
    icon.setAttribute("viewBox", "0 0 24 24");
    var path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", "M20 6L9 17l-5-5");
    icon.appendChild(path);

    var text = document.createElement("span");
    text.textContent = message;

    el.appendChild(icon);
    el.appendChild(text);
    stack.appendChild(el);

    window.setTimeout(function () {
      el.classList.add("is-leaving");
      el.addEventListener("animationend", function () {
        el.remove();
      });
      if (reduceMotion) {
        el.remove();
      }
    }, 2200);
  }

  /* --------------------------------------------------- copie presse-papier */

  function copyText(value) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(value);
    }
    // Repli pour les contextes non sécurisés (http:// hors localhost).
    return new Promise(function (resolve, reject) {
      var area = document.createElement("textarea");
      area.value = value;
      area.setAttribute("readonly", "");
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      try {
        document.execCommand("copy") ? resolve() : reject(new Error("copy failed"));
      } catch (e) {
        reject(e);
      } finally {
        area.remove();
      }
    });
  }

  function initCopyButtons() {
    $$("[data-copy]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        copyText(btn.getAttribute("data-copy")).then(
          function () {
            btn.classList.add("is-done");
            toast(btn.getAttribute("data-copy-label") || "Copié");
            window.setTimeout(function () {
              btn.classList.remove("is-done");
            }, 1600);
          },
          function () {
            toast("Copie impossible");
          }
        );
      });
    });
  }

  /* ------------------------------------------------ génération sécurisée */

  var CHARSET =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";

  /* Même approche que le backend Go : crypto/rand côté serveur,
     crypto.getRandomValues ici, avec rejection sampling pour éliminer
     le biais modulo (on rejette les octets >= au plus grand multiple
     de la taille du charset tenant sur un octet). */
  function generatePassword(length) {
    var max = 256 - (256 % CHARSET.length);
    var out = "";
    var buf = new Uint8Array(1);

    while (out.length < length) {
      crypto.getRandomValues(buf);
      if (buf[0] < max) {
        out += CHARSET.charAt(buf[0] % CHARSET.length);
      }
    }
    return out;
  }

  /* --------------------------------------------------- force du mot de passe */

  /* Estimation par entropie : longueur × log2(taille de l'alphabet utilisé).
     Volontairement simple et explicable, plutôt qu'un score arbitraire. */
  function entropyBits(value) {
    if (!value) {
      return 0;
    }
    var pools = 0;
    if (/[a-z]/.test(value)) pools += 26;
    if (/[A-Z]/.test(value)) pools += 26;
    if (/[0-9]/.test(value)) pools += 10;
    if (/[^a-zA-Z0-9]/.test(value)) pools += 32;
    return value.length * (Math.log(pools || 1) / Math.log(2));
  }

  var LEVELS = [
    { min: 0, label: "Trop court", color: "var(--danger)", segments: 0 },
    { min: 28, label: "Faible", color: "var(--danger)", segments: 1 },
    { min: 48, label: "Correct", color: "var(--warn)", segments: 2 },
    { min: 68, label: "Solide", color: "var(--accent-2)", segments: 3 },
    { min: 90, label: "Excellent", color: "var(--accent)", segments: 4 }
  ];

  function levelFor(bits) {
    var found = LEVELS[0];
    LEVELS.forEach(function (level) {
      if (bits >= level.min) {
        found = level;
      }
    });
    return found;
  }

  function initStrengthMeter() {
    var input = $("[data-strength-for]");
    var meter = $("[data-strength]");
    if (!input || !meter) {
      return;
    }

    var segments = $$(".strength-seg", meter);
    var label = $(".strength-label", meter);

    function update() {
      var value = input.value;
      if (!value) {
        meter.classList.remove("is-visible");
        return;
      }

      var bits = entropyBits(value);
      var level = levelFor(bits);

      meter.classList.add("is-visible");
      meter.style.setProperty("--strength-color", level.color);
      label.textContent = level.label + " · " + Math.round(bits) + " bits d'entropie";

      segments.forEach(function (seg, i) {
        seg.classList.toggle("on", i < level.segments);
      });
    }

    input.addEventListener("input", update);
    update();
  }

  /* --------------------------------------- générateur & révélation du champ */

  /* Le champ visé est celui qui partage le même .input-wrap que le bouton,
     ce qui rend ces contrôles réutilisables sur n'importe quel formulaire. */
  function inputFor(btn) {
    var wrap = btn.closest(".input-wrap");
    return wrap ? $("input", wrap) : null;
  }

  function initPasswordTools() {
    $$("[data-reveal]").forEach(function (btn) {
      var input = inputFor(btn);
      if (!input) {
        return;
      }
      btn.hidden = false;
      btn.addEventListener("click", function () {
        var wasHidden = input.type === "password";
        input.type = wasHidden ? "text" : "password";
        btn.setAttribute("aria-pressed", wasHidden ? "true" : "false");
        btn.setAttribute(
          "aria-label",
          wasHidden ? "Masquer le mot de passe" : "Afficher le mot de passe"
        );
      });
    });

    $$("[data-generate]").forEach(function (btn) {
      var input = inputFor(btn);
      if (!input) {
        return;
      }
      btn.hidden = false;
      btn.addEventListener("click", function () {
        input.type = "text";
        input.value = generatePassword(20);
        input.dispatchEvent(new Event("input"));
        toast("Mot de passe généré");
      });
    });
  }

  /* ------------------------------------------------------------------ init */

  function init() {
    stagger(".entry");
    stagger(".spec");
    stagger(".field");
    initThemeToggle();
    initCopyButtons();
    initStrengthMeter();
    initPasswordTools();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
