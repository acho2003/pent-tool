// content.js — Xalgorix Page Agent content script.
// Injected into every page. Bundles discovery + controller capabilities.
// Responds to commands from background.js via chrome.runtime.onMessage.
//
// This is the in-page counterpart that does NOT use CDP — it runs as a
// proper extension content script with isTrusted event dispatching
// support and document_start timing capability.
//
// NOTE: For physical interactions (click, type, scroll), the Go agent
// uses Rod's CDP Input domain which produces isTrusted:true events.
// This content script is used for DISCOVERY and STATE INSPECTION only.
// The interact commands here are a FALLBACK for cases where CDP input
// cannot target the element (e.g., shadow DOM, cross-origin iframes).

"use strict";

(() => {
  // Guard against double-injection
  if (window.__xalgorix_content_loaded) return;
  window.__xalgorix_content_loaded = true;

  // ── ID Counter ────────────────────────────────────────────────────────
  let xpaCounter = 1;

  function assignId(el) {
    if (!el.getAttribute("data-xpa-id")) {
      el.setAttribute("data-xpa-id", "xpa" + xpaCounter++);
    }
    return el.getAttribute("data-xpa-id");
  }

  // ── Discovery Engine ──────────────────────────────────────────────────

  function discoverPage() {
    xpaCounter = 1; // Reset for consistent IDs across re-scans
    // Remove old IDs
    document.querySelectorAll("[data-xpa-id]").forEach((el) => {
      el.removeAttribute("data-xpa-id");
    });

    const result = {
      url: window.location.href,
      title: document.title,
      menus: [],
      dropdowns: [],
      tabs: [],
      accordions: [],
      modals: [],
      forms: [],
      other: [],
      counts: {},
    };

    // Discover navigation menus
    document
      .querySelectorAll('nav, [role="navigation"], [role="menubar"], .navbar, .nav-menu, .sidebar-nav, .main-nav')
      .forEach((nav) => {
        const id = assignId(nav);
        const children = [];
        nav.querySelectorAll("a, button, [role=\"menuitem\"]").forEach((item) => {
          const childId = assignId(item);
          const label = (item.textContent || "").trim().replace(/\s+/g, " ").substring(0, 80);
          if (!label) return;
          children.push({
            id: childId,
            tag: item.tagName.toLowerCase(),
            type: item.getAttribute("role") || item.tagName.toLowerCase(),
            label,
            href: item.href || "",
            visible: isVisible(item),
            disabled: item.disabled || item.getAttribute("aria-disabled") === "true",
          });
        });
        result.menus.push({
          id,
          tag: nav.tagName.toLowerCase(),
          type: "navigation",
          label: nav.getAttribute("aria-label") || (nav.textContent || "").trim().substring(0, 40),
          visible: isVisible(nav),
          children,
        });
      });

    // Discover dropdowns
    document
      .querySelectorAll(
        '[aria-haspopup], [data-toggle="dropdown"], [data-bs-toggle="dropdown"], ' +
          '.dropdown, .dropdown-toggle, select, [role="listbox"], [role="combobox"]'
      )
      .forEach((el) => {
        const id = assignId(el);
        const label = (el.textContent || "").trim().replace(/\s+/g, " ").substring(0, 80);
        const entry = {
          id,
          tag: el.tagName.toLowerCase(),
          type: el.getAttribute("role") || "dropdown",
          label,
          visible: isVisible(el),
          disabled: el.disabled || false,
          expanded: el.getAttribute("aria-expanded"),
          hasPopup: el.getAttribute("aria-haspopup") || "",
        };

        // Find associated panel
        const controls = el.getAttribute("aria-controls");
        if (controls) {
          const panel = document.getElementById(controls);
          if (panel) {
            entry.panel = {
              id: assignId(panel),
              tag: panel.tagName.toLowerCase(),
              visible: isVisible(panel),
              label: (panel.textContent || "").trim().substring(0, 60),
            };
          }
        }

        // For <select>, enumerate options
        if (el.tagName === "SELECT") {
          entry.options = Array.from(el.options).map((opt) => ({
            value: opt.value,
            text: opt.text.trim(),
            selected: opt.selected,
          }));
        }

        result.dropdowns.push(entry);
      });

    // Discover tabs
    document
      .querySelectorAll('[role="tablist"], .nav-tabs, .tab-list, .tabs')
      .forEach((tablist) => {
        const id = assignId(tablist);
        const tabs = [];
        tablist
          .querySelectorAll('[role="tab"], .nav-link, .tab')
          .forEach((tab) => {
            const tabId = assignId(tab);
            tabs.push({
              id: tabId,
              tag: tab.tagName.toLowerCase(),
              type: "tab",
              label: (tab.textContent || "").trim().substring(0, 60),
              visible: isVisible(tab),
              selected: tab.getAttribute("aria-selected") === "true" || tab.classList.contains("active"),
            });
          });
        result.tabs.push({
          id,
          tag: tablist.tagName.toLowerCase(),
          type: "tablist",
          label: tablist.getAttribute("aria-label") || "",
          children: tabs,
        });
      });

    // Discover accordions
    document
      .querySelectorAll('details, [role="region"][aria-labelledby], .accordion, .accordion-item, .collapse-trigger')
      .forEach((el) => {
        const id = assignId(el);
        let expanded = false;
        if (el.tagName === "DETAILS") expanded = el.open;
        else if (el.getAttribute("aria-expanded")) expanded = el.getAttribute("aria-expanded") === "true";
        result.accordions.push({
          id,
          tag: el.tagName.toLowerCase(),
          type: "accordion",
          label: (el.querySelector("summary, .accordion-header, [aria-expanded]")?.textContent || "").trim().substring(0, 80),
          visible: isVisible(el),
          expanded,
        });
      });

    // Discover modals/dialogs
    document
      .querySelectorAll('[role="dialog"], [role="alertdialog"], dialog, .modal, .overlay, [aria-modal="true"]')
      .forEach((el) => {
        const id = assignId(el);
        result.modals.push({
          id,
          tag: el.tagName.toLowerCase(),
          type: el.getAttribute("role") || "dialog",
          label: el.getAttribute("aria-label") || el.querySelector("h1,h2,h3,.modal-title")?.textContent?.trim().substring(0, 60) || "",
          visible: isVisible(el),
          open: el.open !== undefined ? el.open : isVisible(el),
        });
      });

    // Discover forms
    document.querySelectorAll("form").forEach((form) => {
      const id = assignId(form);
      const fields = [];
      form.querySelectorAll("input, select, textarea, button[type=\"submit\"], [role=\"button\"]").forEach((field) => {
        const fieldId = assignId(field);
        fields.push({
          id: fieldId,
          tag: field.tagName.toLowerCase(),
          type: field.type || field.getAttribute("role") || "field",
          name: field.name || "",
          label: findLabel(field),
          visible: isVisible(field),
          disabled: field.disabled || false,
          value: field.type === "password" ? "***" : (field.value || "").substring(0, 40),
        });
      });
      result.forms.push({
        id,
        tag: "form",
        type: "form",
        label: form.getAttribute("aria-label") || form.getAttribute("name") || "",
        action: form.action || "",
        method: form.method || "GET",
        visible: isVisible(form),
        children: fields,
      });
    });

    // Discover other interactive elements (buttons, links not in menus)
    document
      .querySelectorAll(
        'button:not([data-xpa-id]), a[href]:not([data-xpa-id]), ' +
          '[role="button"]:not([data-xpa-id]), [onclick]:not([data-xpa-id]), ' +
          '[tabindex="0"]:not([data-xpa-id])'
      )
      .forEach((el) => {
        // Skip if already captured in another section
        if (el.closest("nav, form, [role=\"tablist\"], .accordion")) return;
        const id = assignId(el);
        const label = (el.textContent || "").trim().replace(/\s+/g, " ").substring(0, 80);
        if (!label) return;
        result.other.push({
          id,
          tag: el.tagName.toLowerCase(),
          type: el.getAttribute("role") || el.tagName.toLowerCase(),
          label,
          href: el.href || "",
          visible: isVisible(el),
          disabled: el.disabled || el.getAttribute("aria-disabled") === "true",
        });
      });

    // Counts summary
    result.counts = {
      menus: result.menus.length,
      dropdowns: result.dropdowns.length,
      tabs: result.tabs.length,
      accordions: result.accordions.length,
      modals: result.modals.length,
      forms: result.forms.length,
      other: result.other.length,
      totalInteractive: xpaCounter - 1,
    };

    return result;
  }

  // ── Interaction Fallback Engine ────────────────────────────────────────
  // NOTE: These produce isTrusted:false events. They are a FALLBACK.
  // The Go agent should prefer Rod's CDP Input domain for physical clicks.

  function findElement(id) {
    const el = document.querySelector(`[data-xpa-id="${id}"]`);
    if (!el) throw new Error(`Element not found: ${id}`);
    return el;
  }

  function interactElement(id, action) {
    const el = findElement(id);
    el.scrollIntoView({ behavior: "instant", block: "center", inline: "center" });

    // Check interactability
    const rect = el.getBoundingClientRect();
    if (rect.width === 0 && rect.height === 0) {
      return { success: false, error: `Element ${id} has zero size` };
    }
    const style = window.getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden") {
      return { success: false, error: `Element ${id} is hidden` };
    }

    const cx = rect.left + rect.width / 2;
    const cy = rect.top + rect.height / 2;

    switch (action) {
      case "click":
        // Full W3C event sequence (synthetic — isTrusted:false)
        dispatchPointer(el, "pointerover", cx, cy);
        dispatchPointer(el, "pointerenter", cx, cy, { bubbles: false });
        dispatchMouse(el, "mouseover", cx, cy);
        dispatchMouse(el, "mouseenter", cx, cy, { bubbles: false });
        dispatchPointer(el, "pointerdown", cx, cy);
        dispatchMouse(el, "mousedown", cx, cy);
        el.focus({ preventScroll: true });
        dispatchPointer(el, "pointerup", cx, cy);
        dispatchMouse(el, "mouseup", cx, cy);
        el.click(); // Uses HTMLElement.click() which triggers activation behavior
        break;

      case "hover":
        dispatchPointer(el, "pointerenter", cx, cy, { bubbles: false });
        dispatchPointer(el, "pointerover", cx, cy);
        dispatchMouse(el, "mouseenter", cx, cy, { bubbles: false });
        dispatchMouse(el, "mouseover", cx, cy);
        break;

      case "rightClick":
        dispatchPointer(el, "pointerdown", cx, cy, { button: 2 });
        dispatchMouse(el, "mousedown", cx, cy, { button: 2 });
        dispatchPointer(el, "pointerup", cx, cy, { button: 2 });
        dispatchMouse(el, "mouseup", cx, cy, { button: 2 });
        dispatchMouse(el, "contextmenu", cx, cy, { button: 2 });
        break;

      case "focus":
        el.focus({ preventScroll: true });
        break;

      case "blur":
        el.blur();
        break;

      default:
        return { success: false, error: `Unknown action: ${action}` };
    }

    return {
      success: true,
      action,
      elementId: id,
      tag: el.tagName.toLowerCase(),
      label: (el.textContent || "").trim().substring(0, 60),
      url: window.location.href,
    };
  }

  function getElementState(id) {
    const el = findElement(id);
    const rect = el.getBoundingClientRect();
    const style = window.getComputedStyle(el);

    return {
      id,
      tag: el.tagName.toLowerCase(),
      visible: style.display !== "none" && style.visibility !== "hidden" && parseFloat(style.opacity) > 0.05,
      disabled: el.disabled || el.getAttribute("aria-disabled") === "true",
      expanded: el.getAttribute("aria-expanded"),
      selected: el.getAttribute("aria-selected"),
      checked: el.checked !== undefined ? el.checked : null,
      value: el.value || null,
      href: el.href || null,
      role: el.getAttribute("role") || null,
      rect: { x: Math.round(rect.x), y: Math.round(rect.y), width: Math.round(rect.width), height: Math.round(rect.height) },
    };
  }

  function typeText(id, text, clear) {
    const el = findElement(id);
    el.scrollIntoView({ behavior: "instant", block: "center" });
    el.focus();

    if (clear) {
      el.value = "";
      el.dispatchEvent(new Event("input", { bubbles: true }));
    }

    // Set value directly and fire events
    if ("value" in el) {
      el.value = text;
      el.dispatchEvent(new InputEvent("input", { data: text, inputType: "insertText", bubbles: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
    }

    return { success: true, elementId: id, typed: text.length + " chars" };
  }

  function selectOption(id, value) {
    const el = findElement(id);

    if (el.tagName === "SELECT") {
      for (const opt of el.options) {
        if (opt.value === value || opt.text.trim().toLowerCase().includes(value.toLowerCase())) {
          el.value = opt.value;
          el.dispatchEvent(new Event("change", { bubbles: true }));
          return { success: true, elementId: id, selected: opt.value };
        }
      }
      return { success: false, error: `Option "${value}" not found in select` };
    }

    // Custom dropdown — try clicking matching option
    const options = el.querySelectorAll("li, a, button, [role='option'], [data-value]");
    for (const opt of options) {
      if (
        opt.getAttribute("data-value") === value ||
        opt.getAttribute("value") === value ||
        (opt.textContent || "").trim().toLowerCase().includes(value.toLowerCase())
      ) {
        opt.click();
        return { success: true, elementId: id, selected: value };
      }
    }
    return { success: false, error: `Option "${value}" not found` };
  }

  function waitForElement(selector, timeoutMs) {
    timeoutMs = timeoutMs || 10000;
    return new Promise((resolve) => {
      const existing = document.querySelector(selector);
      if (existing) {
        const id = assignId(existing);
        resolve({ success: true, id, selector });
        return;
      }

      const observer = new MutationObserver(() => {
        const found = document.querySelector(selector);
        if (found) {
          observer.disconnect();
          clearTimeout(timeout);
          const id = assignId(found);
          resolve({ success: true, id, selector });
        }
      });
      observer.observe(document.body, { childList: true, subtree: true, attributes: true });

      const timeout = setTimeout(() => {
        observer.disconnect();
        resolve({ success: false, error: `Timeout waiting for: ${selector}` });
      }, timeoutMs);
    });
  }

  function hoverAndProbe(id) {
    const result = interactElement(id, "hover");
    if (!result.success) return result;

    // Scan for newly visible menus
    const newMenus = [];
    document
      .querySelectorAll('[role="menu"], ul.dropdown-menu, .submenu, [role="listbox"]')
      .forEach((el) => {
        const style = window.getComputedStyle(el);
        if (style.display !== "none" && style.visibility !== "hidden") {
          const items = [];
          el.querySelectorAll("a, button, li, [role=\"menuitem\"]").forEach((item) => {
            const label = (item.textContent || "").trim().substring(0, 60);
            if (!label) return;
            items.push({ id: assignId(item), label, tag: item.tagName.toLowerCase() });
          });
          if (items.length > 0) {
            newMenus.push({ tag: el.tagName.toLowerCase(), items });
          }
        }
      });

    result.discoveredMenus = newMenus;
    return result;
  }

  // ── Event Helpers ─────────────────────────────────────────────────────

  function dispatchPointer(el, type, x, y, overrides) {
    el.dispatchEvent(
      new PointerEvent(type, {
        bubbles: true,
        cancelable: true,
        view: window,
        clientX: x,
        clientY: y,
        pointerId: 1,
        pointerType: "mouse",
        ...overrides,
      })
    );
  }

  function dispatchMouse(el, type, x, y, overrides) {
    el.dispatchEvent(
      new MouseEvent(type, {
        bubbles: true,
        cancelable: true,
        view: window,
        clientX: x,
        clientY: y,
        button: 0,
        ...overrides,
      })
    );
  }

  // ── Utility ───────────────────────────────────────────────────────────

  function isVisible(el) {
    const style = window.getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    return (
      style.display !== "none" &&
      style.visibility !== "hidden" &&
      parseFloat(style.opacity) > 0.05 &&
      (rect.width > 0 || rect.height > 0)
    );
  }

  function findLabel(field) {
    // 1. Explicit <label for>
    if (field.id) {
      const label = document.querySelector(`label[for="${field.id}"]`);
      if (label) return label.textContent.trim().substring(0, 60);
    }
    // 2. Wrap <label>
    const parentLabel = field.closest("label");
    if (parentLabel) return parentLabel.textContent.trim().substring(0, 60);
    // 3. aria-label
    if (field.getAttribute("aria-label")) return field.getAttribute("aria-label");
    // 4. placeholder  
    if (field.placeholder) return field.placeholder;
    // 5. name as last resort
    return field.name || "";
  }

  // ── Message Listener ──────────────────────────────────────────────────

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    const { command, args } = msg;

    try {
      switch (command) {
        case "discover": {
          const result = discoverPage();
          sendResponse(result);
          break;
        }
        case "interact": {
          const result = interactElement(args.id, args.action || "click");
          sendResponse(result);
          break;
        }
        case "get_state": {
          const result = getElementState(args.id);
          sendResponse(result);
          break;
        }
        case "type_text": {
          const result = typeText(args.id, args.text, args.clear);
          sendResponse(result);
          break;
        }
        case "select_option": {
          const result = selectOption(args.id, args.value);
          sendResponse(result);
          break;
        }
        case "wait_element": {
          // Async — must return true to keep sendResponse alive
          waitForElement(args.selector, args.timeout).then(sendResponse);
          return true;
        }
        case "hover_probe": {
          const result = hoverAndProbe(args.id);
          sendResponse(result);
          break;
        }
        default:
          sendResponse({ error: `Unknown command: ${command}` });
      }
    } catch (e) {
      sendResponse({ error: e.message || String(e) });
    }

    return false; // Synchronous response (except wait_element)
  });

  console.log("[xalgorix-content] Page agent loaded on", window.location.href);
})();
