// grund's only script: small enhancements over pages that work without it.
// Copy buttons, a sort select that applies itself, the app filter as you
// type, tabs that filter a list in place, menus that close on Escape or a click elsewhere, the − and + of a
// number, a choice that fills in a name, rows of names and values that
// grow and shrink, chips filtered as you type, sliders kept in step with
// their numbers, presets that fill them, and the setting a link points
// at, opened.
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
    if (list) {
      var items = Array.prototype.slice.call(list.querySelectorAll("[data-name]"));
      var empties = Array.prototype.slice.call(document.querySelectorAll("[data-filter-empty]"));
      var tabs = Array.prototype.slice.call(document.querySelectorAll("a[data-tab]")).filter(function (link) {
        return link.pathname === location.pathname;
      });
      var current = tabs.filter(function (link) { return link.classList.contains("is-active"); })[0];
      var tab = current ? current.dataset.tab : "";
      var apply = function () {
        var query = filter ? filter.value.trim().toLowerCase() : "";
        var shown = 0;
        items.forEach(function (item) {
          var match = (!query ||
            item.dataset.name.indexOf(query) !== -1 ||
            (item.dataset.image || "").toLowerCase().indexOf(query) !== -1) &&
            (!tab || item.dataset.tab === tab);
          item.hidden = !match;
          if (match) shown++;
        });
        var why = query ? "match" : "tab";
        empties.forEach(function (empty) {
          empty.hidden = shown !== 0 || (empty.dataset.filterEmpty || "match") !== why;
        });
      };
      if (filter) filter.addEventListener("input", apply);
      tabs.forEach(function (link) {
        link.addEventListener("click", function (event) {
          event.preventDefault();
          tab = link.dataset.tab;
          tabs.forEach(function (other) {
            var on = other === link;
            other.classList.toggle("is-active", on);
            if (on) other.setAttribute("aria-current", "page");
            else other.removeAttribute("aria-current");
          });
          if (filter) {
            var kept = filter.form.querySelector("input[name=tab]");
            if (!kept && tab) {
              kept = document.createElement("input");
              kept.type = "hidden";
              kept.name = "tab";
              filter.form.appendChild(kept);
            }
            if (kept) kept.value = tab;
            if (kept && !tab) kept.remove();
          }
          var url = new URL(link.href);
          if (filter && filter.value.trim()) url.searchParams.set("q", filter.value.trim());
          else url.searchParams.delete("q");
          history.replaceState(null, "", url.pathname + url.search);
          apply();
        });
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

    document.querySelectorAll("input[data-chip-search]").forEach(function (search) {
      var chips = Array.prototype.slice.call(search.parentElement.querySelectorAll(".chip"));
      if (chips.length < 8) return;
      search.hidden = false;
      search.addEventListener("keydown", function (event) {
        if (event.key === "Enter") event.preventDefault();
      });
      search.addEventListener("input", function () {
        var query = search.value.trim().toLowerCase();
        chips.forEach(function (chip) {
          var input = chip.querySelector("input");
          chip.hidden = !!query && !input.checked && chip.textContent.toLowerCase().indexOf(query) === -1;
        });
      });
    });

    document.querySelectorAll("[data-range]").forEach(function (slider) {
      var input = document.getElementById(slider.dataset.range);
      var range = slider.querySelector("input");
      var ticks = slider.querySelectorAll(".range-ticks span");
      var steps = range.dataset.steps.split(" ").map(Number);
      if (!input) return;
      slider.hidden = false;
      function nearest() {
        var value = Number(input.value);
        var best = 0;
        steps.forEach(function (step, i) {
          if (Math.abs(step - value) < Math.abs(steps[best] - value)) best = i;
        });
        return best;
      }
      function mark() {
        range.style.setProperty("--fill", (100 * Number(range.value) / Math.max(1, steps.length - 1)) + "%");
        var at = Number(input.value) === steps[range.value] ? Number(range.value) : -1;
        ticks.forEach(function (tick, i) { tick.classList.toggle("is-on", i === at); });
      }
      function follow() {
        range.value = String(nearest());
        mark();
      }
      follow();
      input.addEventListener("input", follow);
      range.addEventListener("input", function () {
        input.value = String(steps[range.value]);
        mark();
        input.dispatchEvent(new Event("change", { bubbles: true }));
      });
    });

    document.querySelectorAll("fieldset").forEach(function (group) {
      var options = Array.prototype.slice.call(group.querySelectorAll("input[data-sets]"));
      if (!options.length) return;
      function sets(option) {
        return option.dataset.sets.split(" ").filter(Boolean).map(function (pair) {
          var at = pair.indexOf("=");
          return { field: document.getElementById(pair.slice(0, at)), value: pair.slice(at + 1) };
        }).filter(function (set) { return set.field; });
      }
      var fields = [];
      options.forEach(function (option) {
        sets(option).forEach(function (set) {
          if (fields.indexOf(set.field) === -1) fields.push(set.field);
        });
        option.addEventListener("change", function () {
          if (!option.checked) return;
          sets(option).forEach(function (set) {
            set.field.value = set.value;
            set.field.dispatchEvent(new Event("input", { bubbles: true }));
          });
        });
      });
      function choose() {
        var match = options.filter(function (option) {
          var all = sets(option);
          return all.length && all.every(function (set) { return Number(set.field.value) === Number(set.value); });
        })[0] || options.filter(function (option) { return !option.dataset.sets; })[0];
        if (match) match.checked = true;
      }
      fields.forEach(function (field) {
        field.addEventListener("input", function (event) {
          if (event.isTrusted) choose();
        });
        field.addEventListener("change", choose);
      });
    });

    function openTarget() {
      var target = location.hash && document.getElementById(decodeURIComponent(location.hash.slice(1)));
      if (target && target.tagName === "DETAILS") target.open = true;
    }
    openTarget();
    window.addEventListener("hashchange", openTarget);

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
