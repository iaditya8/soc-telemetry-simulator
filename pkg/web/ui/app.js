// SOC Telemetry Simulator Web Console Frontend
document.addEventListener("DOMContentLoaded", () => {
  const statusDot = document.getElementById("status-dot");
  const runStatus = document.getElementById("run-status");
  const uptimeDisplay = document.getElementById("uptime-display");
  const btnStart = document.getElementById("btn-start");
  const btnStop = document.getElementById("btn-stop");
  const btnPreflight = document.getElementById("btn-preflight");
  const preflightBox = document.getElementById("preflight-result");
  const fleetCount = document.getElementById("fleet-count");

  // Poll status every 2 seconds
  async function pollStatus() {
    try {
      const res = await fetch("/api/health");
      if (res.ok) {
        const data = await res.json();
        runStatus.innerText = data.run_state;
        uptimeDisplay.innerText = "Uptime: " + data.uptime_sec + "s";
        if (data.run_state === "RUNNING") {
          statusDot.className = "status-indicator running";
          btnStart.disabled = true;
          btnStop.disabled = false;
        } else {
          statusDot.className = "status-indicator";
          btnStart.disabled = false;
          btnStop.disabled = true;
        }
      }
    } catch (e) {
      console.error("Health poll error:", e);
    }
  }

  // Preflight test
  btnPreflight.addEventListener("click", async () => {
    preflightBox.className = "preflight-box";
    preflightBox.innerText = "Testing connectivity...";
    const destType = document.getElementById("dest-type").value;
    const destAddr = document.getElementById("dest-addr").value;

    try {
      const res = await fetch("/api/preflight", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: destType, address: destAddr, timeout_ms: 2000 })
      });
      const data = await res.json();
      if (data.success) {
        preflightBox.className = "preflight-box success";
        preflightBox.innerText = `✓ Reachable: ${destAddr} (${data.latency_ms.toFixed(1)} ms)`;
      } else {
        preflightBox.className = "preflight-box error";
        preflightBox.innerText = `✗ Unreachable: ${data.error || "Connection failed"}`;
      }
    } catch (e) {
      preflightBox.className = "preflight-box error";
      preflightBox.innerText = "Error: " + e.message;
    }
  });

  // Start run
  btnStart.addEventListener("click", async () => {
    const eps = parseInt(document.getElementById("target-eps").value, 10);
    const duration = parseInt(document.getElementById("duration-sec").value, 10);
    const destType = document.getElementById("dest-type").value;
    const destAddr = document.getElementById("dest-addr").value;

    try {
      const res = await fetch("/api/run/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          generator: { target_eps: eps, duration_seconds: duration },
          destination: { type: destType, address: destAddr }
        })
      });
      if (res.ok) {
        pollStatus();
      } else {
        const err = await res.json();
        alert("Failed to start run: " + (err.error || "Unknown error"));
      }
    } catch (e) {
      alert("Error starting run: " + e.message);
    }
  });

  // Stop run
  btnStop.addEventListener("click", async () => {
    try {
      const res = await fetch("/api/run/stop", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ force: false })
      });
      if (res.ok) {
        pollStatus();
      }
    } catch (e) {
      alert("Error stopping run: " + e.message);
    }
  });

  // Load fleet count
  async function loadFleet() {
    try {
      const res = await fetch("/api/fleet?limit=1");
      if (res.ok) {
        const data = await res.json();
        fleetCount.innerText = data.total || 0;
      }
    } catch (e) {
      console.error("Fleet fetch error:", e);
    }
  }

  loadFleet();
  pollStatus();
  setInterval(pollStatus, 2000);
});
