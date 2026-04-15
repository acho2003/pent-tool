// background.js — MV3 Service Worker for Xalgorix extension.
// Maintains a WebSocket connection back to the Go agent on localhost:38401.
// Routes commands to content scripts and returns results.
//
// Architecture:
//   Go Agent <--WS--> background.js <--chrome.tabs.sendMessage--> content.js
//
// Keepalive: MV3 service workers are killed after 5min idle.
//            We use periodic chrome.alarms + self-pings to stay alive.

"use strict";

// ── Configuration ─────────────────────────────────────────────────────
const WS_URL = "ws://127.0.0.1:38401/ext";
const RECONNECT_BASE_MS = 500;
const RECONNECT_MAX_MS = 10000;
const KEEPALIVE_INTERVAL_MS = 20000; // 20s — well under MV3 5min limit

// ── State ─────────────────────────────────────────────────────────────
let ws = null;
let reconnectAttempts = 0;
let reconnectTimer = null;
let pendingCallbacks = new Map(); // requestId → { resolve, timer }

// ── WebSocket Connection ──────────────────────────────────────────────

function connect() {
  if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
    return;
  }

  try {
    ws = new WebSocket(WS_URL);
  } catch (e) {
    console.warn("[xalgorix-bg] WebSocket constructor failed:", e.message);
    scheduleReconnect();
    return;
  }

  ws.onopen = () => {
    console.log("[xalgorix-bg] Connected to agent");
    reconnectAttempts = 0;

    // Announce ourselves with extension capabilities
    wsSend({
      type: "ext_hello",
      version: chrome.runtime.getManifest().version,
      capabilities: ["discover", "interact", "get_cookies", "set_cookies", "intercept"],
    });
  };

  ws.onmessage = (event) => {
    let msg;
    try {
      msg = JSON.parse(event.data);
    } catch (e) {
      console.error("[xalgorix-bg] Invalid JSON from agent:", event.data);
      return;
    }

    // Response to a pending request from us
    if (msg.requestId && pendingCallbacks.has(msg.requestId)) {
      const cb = pendingCallbacks.get(msg.requestId);
      clearTimeout(cb.timer);
      pendingCallbacks.delete(msg.requestId);
      // Callbacks are handled inline — no need to resolve, already sent to content
      return;
    }

    // Command from Go agent
    handleAgentCommand(msg);
  };

  ws.onerror = (event) => {
    console.warn("[xalgorix-bg] WebSocket error");
  };

  ws.onclose = (event) => {
    console.log(`[xalgorix-bg] Disconnected (code=${event.code})`);
    ws = null;
    scheduleReconnect();
  };
}

function scheduleReconnect() {
  if (reconnectTimer) return;
  const delay = Math.min(RECONNECT_BASE_MS * Math.pow(2, reconnectAttempts), RECONNECT_MAX_MS);
  reconnectAttempts++;
  console.log(`[xalgorix-bg] Reconnecting in ${delay}ms (attempt ${reconnectAttempts})`);
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connect();
  }, delay);
}

function wsSend(data) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(data));
    return true;
  }
  return false;
}

// ── Command Handler ───────────────────────────────────────────────────

async function handleAgentCommand(msg) {
  const { requestId, command, args } = msg;
  if (!requestId || !command) {
    console.warn("[xalgorix-bg] Invalid command (missing requestId/command):", msg);
    return;
  }

  try {
    let result;

    switch (command) {
      case "discover":
      case "interact":
      case "get_state":
      case "type_text":
      case "select_option":
      case "wait_element":
      case "hover_probe":
        result = await forwardToContent(command, args || {});
        break;

      case "get_cookies":
        result = await handleGetCookies(args || {});
        break;

      case "set_cookies":
        result = await handleSetCookies(args || {});
        break;

      case "get_tabs":
        result = await handleGetTabs();
        break;

      case "ping":
        result = { pong: true, timestamp: Date.now() };
        break;

      default:
        result = { error: `Unknown command: ${command}` };
    }

    wsSend({ requestId, result });
  } catch (e) {
    wsSend({ requestId, result: { error: e.message || String(e) } });
  }
}

// ── Content Script Forwarding ─────────────────────────────────────────

async function forwardToContent(command, args) {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tabs.length) {
    throw new Error("No active tab");
  }
  const tabId = tabs[0].id;

  return new Promise((resolve, reject) => {
    const timeoutId = setTimeout(() => {
      reject(new Error(`Content script timeout for ${command} (15s)`));
    }, 15000);

    chrome.tabs.sendMessage(tabId, { command, args }, (response) => {
      clearTimeout(timeoutId);
      if (chrome.runtime.lastError) {
        // Content script not injected yet — inject it first then retry
        injectContentScript(tabId)
          .then(() => {
            return new Promise((res2, rej2) => {
              const t2 = setTimeout(() => rej2(new Error("Retry timeout")), 10000);
              chrome.tabs.sendMessage(tabId, { command, args }, (r2) => {
                clearTimeout(t2);
                if (chrome.runtime.lastError) {
                  rej2(new Error(chrome.runtime.lastError.message));
                } else {
                  res2(r2);
                }
              });
            });
          })
          .then(resolve)
          .catch(reject);
      } else {
        resolve(response);
      }
    });
  });
}

async function injectContentScript(tabId) {
  await chrome.scripting.executeScript({
    target: { tabId },
    files: ["content.js"],
  });
}

// ── Cookie Management ─────────────────────────────────────────────────

async function handleGetCookies(args) {
  const details = {};
  if (args.url) details.url = args.url;
  if (args.domain) details.domain = args.domain;
  if (args.name) details.name = args.name;

  const cookies = await chrome.cookies.getAll(details);
  return {
    cookies: cookies.map((c) => ({
      name: c.name,
      value: c.value,
      domain: c.domain,
      path: c.path,
      secure: c.secure,
      httpOnly: c.httpOnly,
      sameSite: c.sameSite,
      expirationDate: c.expirationDate,
    })),
    count: cookies.length,
  };
}

async function handleSetCookies(args) {
  if (!args.cookies || !Array.isArray(args.cookies)) {
    throw new Error("cookies array required");
  }

  const results = [];
  for (const cookie of args.cookies) {
    try {
      const details = {
        url: cookie.url,
        name: cookie.name,
        value: cookie.value,
      };
      if (cookie.domain) details.domain = cookie.domain;
      if (cookie.path) details.path = cookie.path;
      if (cookie.secure !== undefined) details.secure = cookie.secure;
      if (cookie.httpOnly !== undefined) details.httpOnly = cookie.httpOnly;
      if (cookie.sameSite) details.sameSite = cookie.sameSite;
      if (cookie.expirationDate) details.expirationDate = cookie.expirationDate;

      await chrome.cookies.set(details);
      results.push({ name: cookie.name, success: true });
    } catch (e) {
      results.push({ name: cookie.name, success: false, error: e.message });
    }
  }
  return { results };
}

// ── Tab Management ────────────────────────────────────────────────────

async function handleGetTabs() {
  const tabs = await chrome.tabs.query({});
  return {
    tabs: tabs.map((t) => ({
      id: t.id,
      url: t.url,
      title: t.title,
      active: t.active,
      windowId: t.windowId,
    })),
  };
}

// ── Keepalive (MV3 anti-termination) ──────────────────────────────────

// Use chrome.alarms for reliable keepalive (survives service worker suspension)
chrome.alarms.create("xalgorix-keepalive", { periodInMinutes: 0.3 }); // ~18s

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "xalgorix-keepalive") {
    // Ping to keep WS alive and prevent MV3 termination
    if (ws && ws.readyState === WebSocket.OPEN) {
      wsSend({ type: "keepalive", timestamp: Date.now() });
    } else {
      connect(); // Reconnect if disconnected
    }
  }
});

// ── Lifecycle ─────────────────────────────────────────────────────────

// Connect on install/update
chrome.runtime.onInstalled.addListener(() => {
  console.log("[xalgorix-bg] Extension installed/updated");
  connect();
});

// Connect on service worker startup
connect();
