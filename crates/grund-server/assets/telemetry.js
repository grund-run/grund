// grundTelemetry.mount(root, signal): the caller aborts the signal when sedx
// swaps the page, which stops polling and destroys the charts.
(function () {
  "use strict";

  var RANGES = {
    "": { metrics: "hour", seconds: 900, live: true },
    "15m": { metrics: "hour", seconds: 900 },
    "1h": { metrics: "hour", seconds: 3600 },
    "6h": { metrics: "day", seconds: 21600 },
    "24h": { metrics: "day", seconds: 86400 },
    "7d": { metrics: "week", seconds: 604800 },
  };
  var MIB = 1048576;

  function token(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function alpha(hex, opacity) {
    var n = parseInt(hex.slice(1), 16);
    return "rgba(" + (n >> 16) + "," + ((n >> 8) & 255) + "," + (n & 255) + "," + opacity + ")";
  }

  function seconds(at) {
    return at ? Date.parse(at) / 1000 : NaN;
  }

  function clock(at, withSeconds) {
    var text = new Date(at * 1000).toISOString();
    return withSeconds ? text.slice(11, 19) : text.slice(11, 16);
  }

  function day(at) {
    return new Date(at * 1000).toISOString().slice(5, 10).replace("-", "/");
  }

  function call(method, body, signal) {
    return fetch("/grund.app.v1.AppTelemetryService/" + method, {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json", "connect-protocol-version": "1" },
      body: JSON.stringify(body),
      signal: signal,
    }).then(function (response) {
      if (!response.ok) throw new Error(method + " " + response.status);
      return response.json();
    });
  }

  function axes(span) {
    var grid = { stroke: token("--chart-grid"), width: 1 };
    var font = "12px Inter, sans-serif";
    return [
      {
        stroke: token("--muted"), grid: grid, ticks: { show: false }, font: font, size: 30,
        space: span > 172800 ? 90 : 60,
        values: function (u, ticks) {
          return ticks.map(function (at) { return span > 172800 && at % 86400 === 0 ? day(at) : clock(at); });
        },
      },
      { stroke: token("--muted"), grid: grid, ticks: { show: false }, font: font, size: 52, gap: 6 },
    ];
  }

  function row(label, value, key) {
    var line = document.createElement("div");
    var name = document.createElement("span");
    if (key) {
      var swatch = document.createElement("i");
      swatch.className = "chart-swatch " + key;
      name.append(swatch);
    }
    name.append(label);
    var amount = document.createElement("strong");
    amount.textContent = value;
    line.append(name, amount);
    return line;
  }

  function tooltip(box, rows) {
    var tip = document.createElement("div");
    tip.className = "chart-tip";
    tip.hidden = true;
    box.append(tip);
    return {
      hooks: {
        setCursor: function (u) {
          var index = u.cursor.idx;
          if (index == null || u.cursor.left < 0) {
            tip.hidden = true;
            return;
          }
          tip.replaceChildren.apply(tip, rows(index));
          tip.hidden = false;
          var x = u.cursor.left + u.over.offsetLeft;
          var left = x + 12 + tip.offsetWidth > box.clientWidth ? x - 12 - tip.offsetWidth : x + 12;
          tip.style.left = Math.max(0, left) + "px";
          tip.style.top = u.over.offsetTop + "px";
        },
      },
    };
  }

  function bands(gaps) {
    return {
      hooks: {
        drawClear: function (u) {
          var ctx = u.ctx;
          ctx.save();
          gaps().forEach(function (gap) {
            var from = Math.max(u.valToPos(gap.since, "x", true), u.bbox.left);
            var to = Math.min(u.valToPos(gap.until, "x", true), u.bbox.left + u.bbox.width);
            if (to <= from) return;
            ctx.fillStyle = alpha(token(gap.offline ? "--orange" : "--muted"), 0.16);
            ctx.fillRect(from, u.bbox.top, to - from, u.bbox.height);
          });
          ctx.restore();
        },
      },
    };
  }

  function gapAt(gaps, at) {
    var found = gaps.filter(function (gap) { return at >= gap.since && at < gap.until; })[0];
    if (!found) return null;
    return row(found.offline ? "Machine offline" : "Coverage unknown", "");
  }

  function gapList(response) {
    return (response.gaps || []).map(function (gap) {
      return { since: seconds(gap.since), until: seconds(gap.until), offline: gap.reason === "machine_offline" };
    });
  }

  function keys(card, entries) {
    var list = card.querySelector("[data-chart-keys]");
    list.replaceChildren.apply(list, entries.map(function (entry) {
      var item = document.createElement("li");
      var swatch = document.createElement("i");
      swatch.className = "chart-swatch " + entry.key;
      item.append(swatch, entry.label);
      return item;
    }));
  }

  function chart(box, options, data, signal) {
    var plot = new uPlot(Object.assign({
      width: box.clientWidth,
      height: options.height,
      legend: { show: false },
      tzDate: function (at) { return uPlot.tzDate(new Date(at * 1000), "Etc/UTC"); },
    }, options), data, box);
    var resize = new ResizeObserver(function () { plot.setSize({ width: box.clientWidth, height: options.height }); });
    resize.observe(box);
    signal.addEventListener("abort", function () { resize.disconnect(); plot.destroy(); }, { once: true });
    return plot;
  }

  function poller(root, signal, every, run) {
    var status = root.querySelector("[data-telemetry-status]");
    var timer = null;
    var failures = 0;
    function tick() {
      timer = null;
      if (signal.aborted) return;
      if (document.visibilityState !== "visible") return;
      run().then(function (next) {
        failures = 0;
        status.textContent = "";
        schedule(next || every);
      }, function (error) {
        if (signal.aborted) return;
        failures += 1;
        status.textContent = failures > 1 ? "Reconnecting" : "";
        schedule(Math.max(every || 0, 10000));
        if (failures === 1) console.debug(error);
      });
    }
    function schedule(delay) {
      if (signal.aborted || !delay) return;
      clearTimeout(timer);
      timer = setTimeout(tick, delay);
    }
    document.addEventListener("visibilitychange", function () {
      if (document.visibilityState === "visible" && timer === null && every) tick();
    }, { signal: signal });
    signal.addEventListener("abort", function () { clearTimeout(timer); }, { once: true });
    tick();
  }

  var PALETTE = ["--accent", "--violet", "--blue", "--ok"];

  function metrics(root, signal) {
    var range = RANGES[root.dataset.telemetryRange || ""] || RANGES[""];
    var request = {
      organisation: root.dataset.telemetryOrganisation,
      name: root.dataset.telemetryName,
      range: range.metrics,
      instance: root.dataset.telemetryInstance || "",
    };
    var cards = {
      cpu: { box: root.querySelector('[data-chart="cpu"]'), unit: "m", scale: 1, digits: 0 },
      memory: { box: root.querySelector('[data-chart="memory"]'), unit: "MiB", scale: MIB, digits: 1 },
    };
    var gaps = [];
    var plots = {};
    var shape = "";

    function assemble(response) {
      var bucket = response.bucketSeconds || 10;
      var until = seconds(response.until);
      var first = Math.floor((until - range.seconds) / bucket) * bucket;
      var xs = [];
      for (var at = first; at <= until; at += bucket) xs.push(at);
      var instances = {};
      var order = [];
      function series(instance) {
        if (!instances[instance]) {
          instances[instance] = { cpu: xs.map(nil), memory: xs.map(nil), max: xs.map(nil) };
          order.push(instance);
        }
        return instances[instance];
      }
      var reserved = { cpu: xs.map(nil), memory: xs.map(nil) };
      (response.points || []).forEach(function (point) {
        if (!point.samples) return;
        var index = Math.round((seconds(point.at) - first) / bucket);
        if (index < 0 || index >= xs.length) return;
        var into = series(point.instance);
        into.cpu[index] = number(point.cpuMillis);
        into.memory[index] = scaled(point.memoryBytes);
        into.max[index] = scaled(point.memoryMaxBytes);
        reserved.cpu[index] = Math.max(reserved.cpu[index] || 0, Number(point.reservedCpuMillis || 0)) || null;
        reserved.memory[index] = Math.max(reserved.memory[index] || 0, Number(point.reservedMemoryBytes || 0) / MIB) || null;
      });
      order.sort();
      return { xs: xs, order: order, instances: instances, reserved: reserved };
    }
    function nil() { return null; }
    function number(value) { return value == null ? null : Number(value); }
    function scaled(value) { return value == null ? null : Number(value) / MIB; }

    function latest(values) {
      for (var index = values.length - 1; index >= 0; index--) if (values[index] != null) return values[index];
      return null;
    }

    function format(card, value) {
      return value == null ? "no data" : value.toFixed(card.digits) + " " + card.unit;
    }

    function describe(model, name) {
      var single = model.order.length === 1;
      var lines = [];
      model.order.forEach(function (instance, index) {
        var color = token(PALETTE[index % PALETTE.length]);
        var label = model.order.length > 1 ? instance.slice(-4) : "Used";
        lines.push({
          label: label, key: "swatch-" + (index % PALETTE.length),
          values: model.instances[instance][name === "cpu" ? "cpu" : "memory"],
          series: { stroke: color, width: 1.5, fill: alpha(color, single ? 0.14 : 0.06), points: { show: false }, spanGaps: false },
        });
        if (name === "memory" && single) {
          lines.push({
            label: "Maximum", key: "swatch-max", values: model.instances[instance].max,
            series: { stroke: token("--blue"), width: 1.25, dash: [2, 3], points: { show: false }, spanGaps: false },
          });
        }
      });
      lines.push({
        label: "Reserved", key: "swatch-reserved", values: model.reserved[name],
        series: { stroke: token("--orange"), width: 1.25, dash: [6, 4], points: { show: false }, spanGaps: false },
      });
      return lines;
    }

    function draw(response) {
      gaps = gapList(response);
      var model = assemble(response);
      var nextShape = model.order.join(",") + "|" + model.xs.length;
      ["cpu", "memory"].forEach(function (name) {
        var card = cards[name];
        var container = card.box.closest(".chart-card");
        var lines = describe(model, name);
        var data = [model.xs].concat(lines.map(function (line) { return line.values; }));
        if (!model.order.length) {
          if (plots[name]) { plots[name].destroy(); plots[name] = null; }
          var empty = document.createElement("p");
          empty.className = "chart-empty";
          empty.textContent = "No measurements in this range.";
          card.box.replaceChildren(empty);
          keys(container, []);
          container.querySelector("[data-chart-now]").textContent = "";
          return;
        }
        keys(container, lines);
        var now = container.querySelector("[data-chart-now]");
        if (model.order.length === 1) {
          var reserved = latest(model.reserved[name]);
          now.textContent = format(card, latest(lines[0].values)) + (reserved ? " of " + format(card, reserved) + " reserved" : "");
        } else {
          now.textContent = model.order.length + " instances";
        }
        if (plots[name] && nextShape === shape) {
          plots[name].setData(data, false);
          plots[name].redraw();
          return;
        }
        if (plots[name]) plots[name].destroy();
        card.box.replaceChildren();
        plots[name] = chart(card.box, {
          height: 220,
          padding: [8, 20, 0, 0],
          cursor: { sync: { key: "grund-metrics-" + request.name }, y: false, points: { size: 6 }, drag: { x: true, y: false } },
          scales: {
            x: { time: true, range: function () { return [model.xs[0], model.xs[model.xs.length - 1]]; } },
            y: { range: function (u, min, max) { return [0, max > 0 ? max * 1.15 : 1]; } },
          },
          axes: axes(range.seconds),
          series: [{}].concat(lines.map(function (line) { return Object.assign({ label: line.label }, line.series); })),
          plugins: [
            bands(function () { return gaps; }),
            tooltip(card.box, function (index) {
              var u = plots[name];
              var head = document.createElement("div");
              head.className = "chart-tip-head";
              head.textContent = (range.seconds > 86400 ? day(u.data[0][index]) + " " : "") + clock(u.data[0][index], true) + " UTC";
              var out = [head];
              lines.forEach(function (line, n) { out.push(row(line.label, format(card, u.data[n + 1][index]), line.key)); });
              var gap = gapAt(gaps, u.data[0][index]);
              if (gap) out.push(gap);
              return out;
            }),
          ],
        }, data, signal);
      });
      shape = nextShape;
    }

    poller(root, signal, range.live ? 10000 : 0, function () {
      return call("GetAppMetrics", request, signal).then(draw);
    });
  }

  window.grundTelemetry = {
    mount: function (root, signal) {
      if (root.dataset.telemetry === "metrics") metrics(root, signal);
    },
  };
})();
