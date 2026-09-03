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

  var CHAR_CLASSES = {
    lower: "abcdefghijklmnopqrstuvwxyz",
    upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    digits: "0123456789",
    symbols: "!@#$%^&*()-_=+[]{};:,.?"
  };

  /* Entier uniforme dans [0, max) par rejection sampling : on écarte la queue
     qui ne se divise pas exactement par max, pour éliminer le biais modulo.
     Même principe que le crypto/rand du backend Go. */
  function randomInt(max) {
    var limit = Math.floor(0x100000000 / max) * max;
    var buf = new Uint32Array(1);
    for (;;) {
      crypto.getRandomValues(buf);
      if (buf[0] < limit) {
        return buf[0] % max;
      }
    }
  }

  /* Mélange de Fisher-Yates alimenté par le même aléa cryptographique. */
  function shuffle(items) {
    for (var i = items.length - 1; i > 0; i--) {
      var j = randomInt(i + 1);
      var tmp = items[i];
      items[i] = items[j];
      items[j] = tmp;
    }
    return items;
  }

  /* Génère en garantissant au moins un caractère de chaque classe demandée :
     un tirage naïf dans l'union des classes peut ne produire aucun chiffre,
     et donc un mot de passe qui viole la politique affichée à l'utilisateur. */
  function generateFrom(sets, length) {
    if (!sets.length) {
      return "";
    }

    var chars = sets.map(function (set) {
      return set.charAt(randomInt(set.length));
    });

    var pool = sets.join("");
    while (chars.length < length) {
      chars.push(pool.charAt(randomInt(pool.length)));
    }

    // Si la longueur demandée est inférieure au nombre de classes, on tronque.
    return shuffle(chars).slice(0, length).join("");
  }

  function generatePassword(length) {
    return generateFrom(
      [CHAR_CLASSES.lower, CHAR_CLASSES.upper, CHAR_CLASSES.digits, CHAR_CLASSES.symbols],
      length
    );
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


  /* ------------------------------------------------------- générateur (page) */

  var HANDOFF_KEY = "securepass-pending-password";

  /* Affiche le mot de passe caractère par caractère, en distinguant lettres,
     chiffres et symboles : on repère d'un coup d'œil la composition réelle. */
  function renderPassword(container, value) {
    container.textContent = "";
    value.split("").forEach(function (ch) {
      var span = document.createElement("span");
      span.className = "pw-char";
      if (/[0-9]/.test(ch)) {
        span.classList.add("is-digit");
      } else if (/[^a-zA-Z0-9]/.test(ch)) {
        span.classList.add("is-symbol");
      }
      span.textContent = ch;
      container.appendChild(span);
    });
  }

  function initGenerator() {
    var display = $("[data-gen-output]");
    if (!display) {
      return;
    }

    var lengthInput = $("[data-gen-length]");
    var lengthLabel = $("[data-gen-length-value]");
    var meter = $("[data-gen-strength]");
    var segments = $$(".strength-seg", meter);
    var label = $(".strength-label", meter);
    var warning = $("[data-gen-warning]");
    var current = "";

    function selectedSets() {
      return $$("[data-gen-class]")
        .filter(function (box) {
          return box.checked;
        })
        .map(function (box) {
          return CHAR_CLASSES[box.getAttribute("data-gen-class")];
        });
    }

    function regenerate() {
      var sets = selectedSets();

      // Au moins une classe doit rester active, sinon rien n'est générable.
      if (!sets.length) {
        warning.hidden = false;
        display.textContent = "";
        current = "";
        return;
      }
      warning.hidden = true;

      current = generateFrom(sets, parseInt(lengthInput.value, 10));
      renderPassword(display, current);

      var bits = entropyBits(current);
      var level = levelFor(bits);
      meter.classList.add("is-visible");
      meter.style.setProperty("--strength-color", level.color);
      label.textContent = level.label + " · " + Math.round(bits) + " bits d'entropie";
      segments.forEach(function (seg, i) {
        seg.classList.toggle("on", i < level.segments);
      });
    }

    lengthInput.addEventListener("input", function () {
      lengthLabel.textContent = lengthInput.value;
      regenerate();
    });

    $$("[data-gen-class]").forEach(function (box) {
      box.addEventListener("change", regenerate);
    });

    var regenBtn = $("[data-gen-regenerate]");
    if (regenBtn) {
      regenBtn.addEventListener("click", regenerate);
    }

    var copyBtn = $("[data-gen-copy]");
    if (copyBtn) {
      copyBtn.addEventListener("click", function () {
        if (!current) {
          return;
        }
        copyText(current).then(
          function () {
            copyBtn.classList.add("is-done");
            toast("Mot de passe copié");
            window.setTimeout(function () {
              copyBtn.classList.remove("is-done");
            }, 1600);
          },
          function () {
            toast("Copie impossible");
          }
        );
      });
    }

    var useBtn = $("[data-gen-use]");
    if (useBtn) {
      useBtn.addEventListener("click", function () {
        if (!current) {
          return;
        }
        // Transmis via sessionStorage plutôt que par l'URL : un mot de passe
        // dans une query string finirait dans l'historique et les journaux.
        try {
          sessionStorage.setItem(HANDOFF_KEY, current);
          window.location.href = "/add-password";
        } catch (e) {
          toast("Stockage de session indisponible");
        }
      });
    }

    lengthLabel.textContent = lengthInput.value;
    regenerate();
  }

  /* Récupère un mot de passe généré sur la page dédiée, puis l'efface aussitôt
     du stockage de session pour ne pas le laisser traîner. */
  function initHandoff() {
    var input = $("[data-strength-for]");
    if (!input) {
      return;
    }

    var pending;
    try {
      pending = sessionStorage.getItem(HANDOFF_KEY);
      sessionStorage.removeItem(HANDOFF_KEY);
    } catch (e) {
      return;
    }

    if (pending) {
      input.type = "text";
      input.value = pending;
      input.dispatchEvent(new Event("input"));
      toast("Mot de passe généré inséré");
    }
  }


  /* --------------------------------------------- confirmation de suppression */

  /* Un premier clic « arme » le bouton, un second confirme. On évite ainsi la
     boîte confirm() native, bloquante et non stylable, tout en gardant un
     garde-fou sur une action irréversible. */
  function initDeleteConfirm() {
    $$("form[data-confirm]").forEach(function (form) {
      var btn = $("button[type=submit]", form);
      if (!btn) {
        return;
      }

      var armed = false;
      var timer;

      function disarm() {
        armed = false;
        btn.classList.remove("is-armed");
        btn.setAttribute("aria-label", btn.getAttribute("data-label-idle"));
      }

      btn.setAttribute("data-label-idle", btn.getAttribute("aria-label") || "Supprimer");

      form.addEventListener("submit", function (event) {
        if (armed) {
          return; // second clic : on laisse partir la requête
        }
        event.preventDefault();
        armed = true;
        btn.classList.add("is-armed");
        btn.setAttribute("aria-label", "Cliquez à nouveau pour confirmer la suppression");
        toast(form.getAttribute("data-confirm") + " Cliquez à nouveau.");

        window.clearTimeout(timer);
        timer = window.setTimeout(disarm, 4000);
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
    initGenerator();
    initHandoff();
    initDeleteConfirm();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
