// grund's only script: small enhancements over pages that work without it.
// Copy buttons, a sort select that applies itself, the app filter as you
// type, menus that close on Escape or a click elsewhere, the − and + of a
// number, and a choice that fills in a name.
(function () {
  "use strict";
  document.documentElement.classList.add("has-js");

  function ready(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn);
    } else {
      fn();
    }
  }

  ready(function () {
    if (navigator.clipboard) {
      document.querySelectorAll("button[data-copy]").forEach(function (button) {
        button.hidden = false;
        var label = button.getAttribute("aria-label");
        button.addEventListener("click", function () {
          navigator.clipboard.writeText(button.dataset.copy).then(function () {
            button.classList.add("is-done");
            button.setAttribute("aria-label", "Copied");
            setTimeout(function () {
              button.classList.remove("is-done");
              button.setAttribute("aria-label", label);
            }, 1500);
          });
        });
      });
    }

    document.querySelectorAll("select[data-autosubmit]").forEach(function (select) {
      select.addEventListener("change", function () {
        select.form.submit();
      });
    });

    var filter = document.querySelector("input[data-filter]");
    var list = document.querySelector("[data-filterable]");
    if (filter && list) {
      var items = Array.prototype.slice.call(list.querySelectorAll("[data-name]"));
      var none = document.querySelector("[data-filter-empty]");
      filter.addEventListener("input", function () {
        var query = filter.value.trim().toLowerCase();
        var shown = 0;
        items.forEach(function (item) {
          var match = !query ||
            item.dataset.name.indexOf(query) !== -1 ||
            (item.dataset.image || "").toLowerCase().indexOf(query) !== -1;
          item.hidden = !match;
          if (match) shown++;
        });
        if (none) none.hidden = shown !== 0;
      });
    }

    document.querySelectorAll("button[data-step]").forEach(function (button) {
      var input = document.getElementById(button.dataset["for"]);
      if (!input) return;
      button.hidden = false;
      button.addEventListener("click", function () {
        var min = Number(input.min || 1);
        var max = Number(input.max || 99);
        var value = parseInt(input.value, 10);
        if (isNaN(value)) value = min;
        input.value = String(Math.min(max, Math.max(min, value + Number(button.dataset.step))));
        input.dispatchEvent(new Event("input", { bubbles: true }));
      });
    });

    document.querySelectorAll("input[data-fill]").forEach(function (choice) {
      var target = document.getElementById(choice.dataset.fill);
      if (!target) return;
      if (choice.checked && target.value === choice.value) target.dataset.filled = choice.value;
      choice.addEventListener("change", function () {
        if (!choice.checked) return;
        if (target.value === "" || target.value === target.dataset.filled) {
          target.value = choice.value;
          target.dataset.filled = choice.value;
        }
      });
    });

    var menus = Array.prototype.slice.call(document.querySelectorAll("details.menu"));
    document.addEventListener("click", function (event) {
      menus.forEach(function (menu) {
        if (menu.open && !menu.contains(event.target)) menu.open = false;
      });
    });
    document.addEventListener("keydown", function (event) {
      if (event.key !== "Escape") return;
      menus.forEach(function (menu) {
        if (menu.open) {
          menu.open = false;
          menu.querySelector("summary").focus();
        }
      });
    });
  });
})();
