// grund's only script: small enhancements over pages that work without it.
// Copy buttons, a sort select that applies itself, the app filter as you
// type, menus that close on Escape or a click elsewhere, the − and + of a
// number, a choice that fills in a name, and rows of names and values that
// grow and shrink.
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
          var text = button.querySelector("[data-copy-label]");
          navigator.clipboard.writeText(button.dataset.copy).then(function () {
            button.classList.add("is-done");
            if (text) text.textContent = "Copied";
            else button.setAttribute("aria-label", "Copied");
            setTimeout(function () {
              button.classList.remove("is-done");
              if (text) text.textContent = "Copy";
              else button.setAttribute("aria-label", label);
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

    document.querySelectorAll("[data-pairs]").forEach(function (pairs) {
      var add = pairs.parentElement.querySelector(".pairs-add");
      function number() {
        Array.prototype.forEach.call(pairs.children, function (row, i) {
          row.querySelectorAll("[aria-label]").forEach(function (control) {
            control.setAttribute("aria-label", control.getAttribute("aria-label").replace(/\d+$/, String(i + 1)));
          });
        });
      }
      function wire(row) {
        var remove = row.querySelector("[data-remove-pair]");
        remove.hidden = false;
        remove.addEventListener("click", function () {
          var next = row.nextElementSibling || row.previousElementSibling;
          if (pairs.children.length > 1) {
            row.remove();
          } else {
            row.querySelectorAll("input").forEach(function (input) { input.value = ""; });
          }
          number();
          if (next) next.querySelector("input").focus();
        });
      }
      Array.prototype.forEach.call(pairs.children, wire);
      if (!add) return;
      add.hidden = false;
      add.addEventListener("click", function () {
        var last = pairs.lastElementChild;
        var row = last.cloneNode(true);
        row.querySelectorAll("input").forEach(function (input) {
          input.value = "";
          input.removeAttribute("aria-invalid");
        });
        pairs.appendChild(row);
        wire(row);
        number();
        row.querySelector("input").focus();
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
