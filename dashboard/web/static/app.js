/* Cloud Cost Guardian dashboard charts (task #26).
 * Data comes only from the same-origin JSON endpoints; text from the data (owner, project, service names)
 * is drawn on canvas by Chart.js or written with textContent, never as HTML.
 */
(function () {
  "use strict";

  var cfg = JSON.parse(document.getElementById("page-config").textContent);
  var css = getComputedStyle(document.documentElement);
  function cssVar(name) { return css.getPropertyValue(name).trim(); }
  var SERIES = [1, 2, 3, 4, 5, 6].map(function (i) { return cssVar("--series-" + i); });
  var OTHER = cssVar("--series-other");
  var charts = {};
  var serviceSlots = {};          // service name -> colour slot, stable for the page's life
  var nextServiceSlot = 0;

  if (typeof Chart === "undefined") { return; }
  Chart.defaults.color = cssVar("--text-secondary");
  Chart.defaults.borderColor = cssVar("--grid");
  Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
  Chart.defaults.font.size = 12;
  Chart.defaults.maintainAspectRatio = false;
  Chart.defaults.animation = false;
  Chart.defaults.plugins.legend.labels.boxWidth = 12;
  Chart.defaults.plugins.legend.labels.boxHeight = 12;

  // ------------------------------------------------------------------ helpers

  function usd(v, places) {
    if (v === null || v === undefined) { return "—"; }
    return "$" + Number(v).toFixed(places === undefined ? 2 : places);
  }

  var hatchCache = {};
  function hatch(color) {
    if (hatchCache[color]) { return hatchCache[color]; }
    var c = document.createElement("canvas");
    c.width = 8; c.height = 8;
    var g = c.getContext("2d");
    g.globalAlpha = 0.3; g.fillStyle = color; g.fillRect(0, 0, 8, 8);
    g.globalAlpha = 1; g.strokeStyle = color; g.lineWidth = 2;
    g.beginPath(); g.moveTo(-2, 10); g.lineTo(10, -2); g.moveTo(6, 10); g.lineTo(10, 6); g.moveTo(-2, 2); g.lineTo(2, -2);
    g.stroke();
    hatchCache[color] = g.createPattern(c, "repeat");
    return hatchCache[color];
  }

  function fig(name) { return document.querySelector('figure[data-chart="' + name + '"]'); }

  function renderTable(name, headers, rows) {
    var slot = fig(name).querySelector(".table-slot");
    slot.textContent = "";
    if (!rows.length) { return; }
    var table = document.createElement("table");
    var tr = document.createElement("tr");
    headers.forEach(function (h) { var th = document.createElement("th"); th.textContent = h; tr.appendChild(th); });
    var thead = document.createElement("thead"); thead.appendChild(tr); table.appendChild(thead);
    var tbody = document.createElement("tbody");
    rows.forEach(function (r) {
      var row = document.createElement("tr");
      r.forEach(function (cell) { var td = document.createElement("td"); td.textContent = cell; row.appendChild(td); });
      tbody.appendChild(row);
    });
    table.appendChild(tbody);
    slot.appendChild(table);
  }

  function showEmpty(name, message) {
    var f = fig(name);
    if (charts[name]) { charts[name].destroy(); delete charts[name]; }
    f.querySelector(".canvas-box").hidden = true;
    var p = f.querySelector(".empty"); p.textContent = message; p.hidden = false;
    renderTable(name, [], []);
  }

  function draw(name, config) {
    var f = fig(name);
    f.querySelector(".canvas-box").hidden = false;
    f.querySelector(".empty").hidden = true;
    if (charts[name]) { charts[name].destroy(); }
    charts[name] = new Chart(f.querySelector("canvas"), config);
  }

  function getJSON(url) {
    return fetch(url, { credentials: "same-origin", headers: { "Accept": "application/json" } })
      .then(function (r) { if (!r.ok) { throw new Error(url + " -> " + r.status); } return r.json(); });
  }

  function yMoney(places) {
    return { beginAtZero: true, ticks: { callback: function (v) { return usd(v, places); } } };
  }

  // A line series whose segments touching a sample day are dashed and whose sample points are diamonds.
  function lineDataset(label, color, values, samples) {
    return {
      label: label, data: values, borderColor: color, backgroundColor: color, borderWidth: 2,
      spanGaps: false, tension: 0,
      pointRadius: values.map(function (v, i) { return v === null ? 0 : (samples[i] ? 4 : 2.5); }),
      pointStyle: samples.map(function (s) { return s ? "rectRot" : "circle"; }),
      segment: { borderDash: function (ctx) { return samples[ctx.p0DataIndex] || samples[ctx.p1DataIndex] ? [6, 4] : undefined; } }
    };
  }

  function sampleSuffix(samples) {
    return function (item) { return samples[item.dataIndex] ? " (sample)" : ""; };
  }

  // ------------------------------------------------------------------ summaries

  function drawTrends(data) {
    var s = data.series;
    var labels = s.map(function (p) { return p.day; });
    var samples = s.map(function (p) { return p.sample; });
    var present = s.filter(function (p) { return p.present; });
    document.getElementById("trend-sample").hidden = !data.sampleInRange;

    if (!present.length) {
      showEmpty("waste", "No daily summaries in the last " + data.days + " days yet.");
      showEmpty("savings", "No daily summaries in the last " + data.days + " days yet.");
    } else {
      var suffix = sampleSuffix(samples);
      draw("waste", {
        type: "line",
        data: { labels: labels, datasets: [lineDataset("Waste", SERIES[0], s.map(function (p) { return p.totalMonthlyWaste; }), samples)] },
        options: { scales: { y: yMoney(2) }, plugins: { legend: { display: false },
          tooltip: { callbacks: { label: function (i) { return "Waste " + usd(i.raw) + "/month"; }, afterLabel: suffix } } } }
      });
      draw("savings", {
        type: "line",
        data: { labels: labels, datasets: [
          lineDataset("Realized", SERIES[0], s.map(function (p) { return p.realizedMonthlySavings; }), samples),
          lineDataset("Potential", SERIES[1], s.map(function (p) { return p.potentialMonthlySavings; }), samples)
        ] },
        options: { interaction: { mode: "index", intersect: false }, scales: { y: yMoney(2) },
          plugins: { tooltip: { callbacks: { label: function (i) { return i.dataset.label + " " + usd(i.raw) + "/month"; }, footer: function (items) { return items.length && samples[items[0].dataIndex] ? "sample (demo seed)" : ""; } } } } }
      });
      var rows = present.map(function (p) {
        return [p.day + (p.sample ? " (sample)" : ""), usd(p.totalMonthlyWaste), usd(p.realizedMonthlySavings), usd(p.potentialMonthlySavings), String(p.openFindings)];
      });
      renderTable("waste", ["Day", "Waste", "Realized", "Potential", "Active findings"], rows);
      renderTable("savings", ["Day", "Waste", "Realized", "Potential", "Active findings"], rows);
    }
    drawBreakdowns(data.latest);
  }

  function barBreakdown(name, items, isSample, money, emptyText) {
    if (!items || !items.length) { showEmpty(name, emptyText); return; }
    var color = isSample ? hatch(SERIES[0]) : SERIES[0];
    draw(name, {
      type: "bar",
      data: { labels: items.map(function (i) { return i.label; }),
        datasets: [{ data: items.map(function (i) { return i.value; }), backgroundColor: color, borderColor: SERIES[0],
          borderWidth: isSample ? 1 : 0, borderRadius: 4, borderSkipped: "start", maxBarThickness: 22 }] },
      options: { indexAxis: "y", scales: { x: money ? yMoney(2) : { beginAtZero: true, ticks: { precision: 0 } } },
        plugins: { legend: { display: false }, tooltip: { callbacks: {
          label: function (i) { return money ? usd(i.raw) + "/month" : i.raw + " active"; },
          afterLabel: function () { return isSample ? "sample (demo seed)" : ""; } } } } }
    });
    renderTable(name, ["", money ? "USD/month" : "Count"], items.map(function (i) { return [i.label, money ? usd(i.value) : String(i.value)]; }));
  }

  function drawBreakdowns(latest) {
    var label = document.getElementById("break-day");
    if (!latest) {
      label.textContent = "";
      ["byRegion", "byOwner", "byProject", "byType"].forEach(function (n) { showEmpty(n, "No daily summary yet."); });
      return;
    }
    label.textContent = "summary of " + latest.day + (latest.sample ? " — sample (demo seed), not real" : "");
    barBreakdown("byRegion", latest.wasteByRegion, latest.sample, true, "No waste by region.");
    barBreakdown("byOwner", latest.wasteByOwner, latest.sample, true, "No waste by owner.");
    barBreakdown("byProject", latest.wasteByProject, latest.sample, true, "No waste by project.");
    barBreakdown("byType", latest.countsByType, latest.sample, false, "No active findings.");
  }

  // ------------------------------------------------------------------ bill

  function serviceColor(name) {
    if (name === "other") { return OTHER; }
    if (!(name in serviceSlots)) { serviceSlots[name] = nextServiceSlot % SERIES.length; nextServiceSlot += 1; }
    return SERIES[serviceSlots[name]];
  }

  function drawBill(bill) {
    var labels = bill.days;
    var est = {};
    bill.estimatedDays.forEach(function (d) { est[d] = true; });
    if (!bill.hasData) {
      ["billTotal", "billServices", "billProjects"].forEach(function (n) { showEmpty(n, "No bill history for these days yet (the daily-cost Lambda fills it)."); });
      return;
    }
    var estNote = function (items) { return items.length && est[labels[items[0].dataIndex]] ? "estimated (Cost Explorer may revise it)" : ""; };
    draw("billTotal", {
      type: "line",
      data: { labels: labels, datasets: [{ label: "Total", data: bill.total, borderColor: SERIES[0], backgroundColor: SERIES[0],
        borderWidth: 2, pointRadius: 2, spanGaps: false, tension: 0 }] },
      options: { scales: { y: yMoney(2) }, plugins: { legend: { display: false },
        tooltip: { callbacks: { label: function (i) { return "Total " + usd(i.raw, 4) + "/day"; }, footer: estNote } } } }
    });
    renderTable("billTotal", ["Day", "Total USD/day"], labels.map(function (d, i) {
      return [d + (est[d] ? " (estimated)" : ""), bill.total[i] === null ? "no data" : usd(bill.total[i], 4)];
    }));

    if (!bill.services.length) {
      showEmpty("billServices", "No service spend in this range.");
    } else {
      draw("billServices", {
        type: "bar",
        data: { labels: labels, datasets: bill.services.map(function (svc) {
          return { label: svc.name, data: svc.amounts, backgroundColor: serviceColor(svc.name), borderColor: cssVar("--surface-1"),
            borderWidth: { top: 1 }, stack: "s" };
        }) },
        options: { interaction: { mode: "index", intersect: false },
          scales: { x: { stacked: true }, y: Object.assign(yMoney(2), { stacked: true }) },
          plugins: { tooltip: { callbacks: { label: function (i) { return i.dataset.label + " " + usd(i.raw, 4); }, footer: estNote } } } }
      });
      renderTable("billServices", ["Service", "Sum USD"], bill.services.map(function (svc) { return [svc.name, usd(svc.total, 4)]; }));
    }

    if (!bill.projects.length) {
      showEmpty("billProjects", "No project spend in this range.");
    } else {
      draw("billProjects", {
        type: "bar",
        data: { labels: bill.projects.map(function (p) { return p.name; }),
          datasets: [{ data: bill.projects.map(function (p) { return p.total; }), backgroundColor: SERIES[0], borderRadius: 4,
            borderSkipped: "start", maxBarThickness: 22 }] },
        options: { indexAxis: "y", scales: { x: yMoney(2) }, plugins: { legend: { display: false },
          tooltip: { callbacks: { label: function (i) { return usd(i.raw, 4) + " over " + labels.length + " days"; } } } } }
      });
      renderTable("billProjects", ["Project", "Sum USD"], bill.projects.map(function (p) { return [p.name, usd(p.total, 4)]; }));
    }
  }

  // ------------------------------------------------------------------ activity

  function drawActivity(data) {
    var w = data.weeks;
    var anySample = w.some(function (x) { return x.sample; });
    document.getElementById("activity-sample").hidden = !anySample;
    var total = w.reduce(function (n, x) { return n + x.findingsOpened + x.warningsSent + x.actionsTaken; }, 0);
    if (!total) { showEmpty("activity", "No activity in the last " + w.length + " weeks."); return; }
    function fill(color) { return w.map(function (x) { return x.sample ? hatch(color) : color; }); }
    function ds(label, key, color, stack) {
      return { label: label, data: w.map(function (x) { return x[key]; }), backgroundColor: fill(color), borderColor: color,
        borderWidth: w.map(function (x) { return x.sample ? 1 : 0; }), stack: stack, maxBarThickness: 18 };
    }
    var real = ds("Actions taken (real)", "actionsTaken", SERIES[2], "actions");
    real.data = w.map(function (x) { return x.actionsTaken - x.actionsTakenDryRun; });
    draw("activity", {
      type: "bar",
      data: { labels: w.map(function (x) { return x.week; }), datasets: [
        ds("Findings opened", "findingsOpened", SERIES[0], "opened"),
        ds("Warnings sent", "warningsSent", SERIES[1], "warnings"),
        real,
        ds("Actions taken (dry-run)", "actionsTakenDryRun", SERIES[3], "actions")
      ] },
      options: { interaction: { mode: "index", intersect: false },
        scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } },
        plugins: { tooltip: { callbacks: { title: function (items) { var x = w[items[0].dataIndex]; return x.week + " (" + x.start + " to " + x.end + ")"; },
          footer: function (items) { var x = w[items[0].dataIndex]; return x.sample ? x.sampleDays + " day(s) with sample data (demo seed)" : ""; } } } } }
    });
    renderTable("activity", ["Week", "Findings opened", "Warnings sent", "Actions taken", "of which dry-run", "Sample days"],
      w.map(function (x) { return [x.week, String(x.findingsOpened), String(x.warningsSent), String(x.actionsTaken), String(x.actionsTakenDryRun), String(x.sampleDays)]; }));
  }

  // ------------------------------------------------------------------ wiring

  function fail(names) {
    return function () { names.forEach(function (n) { showEmpty(n, "Data temporarily unavailable."); }); };
  }

  function loadRange(days) {
    document.querySelectorAll(".switch button").forEach(function (b) {
      b.setAttribute("aria-pressed", String(Number(b.getAttribute("data-days")) === days));
    });
    getJSON("/api/summaries?days=" + days).then(drawTrends, fail(["waste", "savings", "byRegion", "byOwner", "byProject", "byType"]));
    getJSON("/api/bill?days=" + days).then(drawBill, fail(["billTotal", "billServices", "billProjects"]));
  }

  document.querySelectorAll(".switch button").forEach(function (b) {
    b.addEventListener("click", function () { loadRange(Number(b.getAttribute("data-days"))); });
  });
  loadRange(cfg.defaultDays);
  getJSON("/api/activity?weeks=" + cfg.weeks).then(drawActivity, fail(["activity"]));
})();
