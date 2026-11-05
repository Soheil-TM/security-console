/* Stage-based scan progress and elapsed. Keep in sync with
 * security_console/execution_math.py. Host Node tests are not required. */
(function (root) {
  function parseStamp(value) {
    var raw = String(value || "").trim();
    if (!raw) return null;
    var text = raw;
    if (text.slice(-4) === " UTC") {
      text = text.slice(0, -4).trim().replace(" ", "T") + "Z";
    } else if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}/.test(text) && !/[zZ]|[+-]\d{2}:?\d{2}$/.test(text)) {
      text = text.replace(" ", "T") + "Z";
    }
    var ms = Date.parse(text);
    return Number.isFinite(ms) ? ms : null;
  }

  function okTools(scan) {
    var found = {};
    var rows = (scan && scan.tool_results) || [];
    for (var i = 0; i < rows.length; i++) {
      var row = rows[i];
      if (!row || !row.tool) continue;
      if (String(row.status || "").toLowerCase() === "ok") {
        found[String(row.tool).toLowerCase()] = true;
      }
    }
    return found;
  }

  function scanProgress(scan) {
    if (!scan || typeof scan !== "object") {
      return { percent: 0, ok: 0, total: 0, complete_success: false, label: "queued" };
    }
    var tools = (scan.tools || [])
      .map(function (t) { return String(t || "").trim().toLowerCase(); })
      .filter(Boolean);
    var total = tools.length;
    var oks = okTools(scan);
    var ok = 0;
    for (var i = 0; i < tools.length; i++) {
      if (oks[tools[i]]) ok += 1;
    }
    var status = String(scan.status || "").trim().toLowerCase();
    var percent = total === 0 ? 0 : Math.floor((ok * 100) / total);
    var completeSuccess = status === "done" && total > 0 && ok === total;
    if (status === "failed") {
      percent = Math.min(percent, 99);
      completeSuccess = false;
    } else if (status === "done" && completeSuccess) {
      percent = 100;
    } else if (status === "done") {
      percent = ok < total ? Math.min(percent, 99) : percent;
      completeSuccess = false;
    }
    var label = "unknown";
    if (status === "queued") label = "queued";
    else if (status === "running") label = "running";
    else if (status === "failed") label = "failed";
    else if (completeSuccess) label = "completed";
    else if (status === "done") label = "done_partial";
    else label = status || "unknown";
    return {
      percent: percent,
      ok: ok,
      total: total,
      complete_success: completeSuccess,
      label: label
    };
  }

  function formatDuration(seconds) {
    if (!(seconds >= 0) || seconds !== seconds) seconds = 0;
    var whole = Math.floor(seconds);
    var hours = Math.floor(whole / 3600);
    var rem = whole % 3600;
    var minutes = Math.floor(rem / 60);
    var secs = rem % 60;
    function pad(n) { return String(n).padStart(2, "0"); }
    if (hours) return pad(hours) + ":" + pad(minutes) + ":" + pad(secs);
    return pad(minutes) + ":" + pad(secs);
  }

  function scanElapsed(scan, nowMs) {
    if (!scan || typeof scan !== "object") {
      return { kind: "waiting", seconds: 0, text: "" };
    }
    var startMs = parseStamp(scan.started_at);
    if (startMs === null) {
      return { kind: "waiting", seconds: 0, text: "" };
    }
    var endMs = parseStamp(scan.finished_at);
    var frozen = endMs !== null;
    if (!frozen) endMs = typeof nowMs === "number" ? nowMs : Date.now();
    var seconds = Math.max(0, (endMs - startMs) / 1000);
    return {
      kind: frozen ? "frozen" : "running",
      seconds: seconds,
      text: formatDuration(seconds)
    };
  }

  root.ExecutionMath = {
    scanProgress: scanProgress,
    scanElapsed: scanElapsed,
    formatDuration: formatDuration
  };
})(typeof window !== "undefined" ? window : globalThis);
