// controller.js — In-page element interaction engine for Xalgorix
// Injected via CDP.  Provides precise control over individual UI elements
// using correct event dispatching order (inspiration: page-agent's ai-motion).
//
// All functions are namespaced with xpa_ prefix to avoid collisions.
// Called from Go via page.Eval() with function name and arguments.

(() => {
  "use strict";

  // ── Helpers ──────────────────────────────────────────────────────────

  /** Find element by xpa id. */
  function _find(id) {
    const el = document.querySelector(`[data-xpa-id="${id}"]`);
    if (!el) throw new Error(`Element not found: ${id}`);
    return el;
  }

  /** Dispatch a MouseEvent with correct bubbling/cancelable flags. */
  function _mouseEvent(el, type, opts) {
    const rect = el.getBoundingClientRect();
    const x = rect.left + rect.width / 2;
    const y = rect.top + rect.height / 2;
    const event = new MouseEvent(type, {
      bubbles: true,
      cancelable: true,
      view: window,
      clientX: x,
      clientY: y,
      ...opts,
    });
    el.dispatchEvent(event);
  }

  /** Dispatch a PointerEvent. */
  function _pointerEvent(el, type, opts) {
    const rect = el.getBoundingClientRect();
    const x = rect.left + rect.width / 2;
    const y = rect.top + rect.height / 2;
    const event = new PointerEvent(type, {
      bubbles: true,
      cancelable: true,
      view: window,
      clientX: x,
      clientY: y,
      pointerId: 1,
      pointerType: "mouse",
      ...opts,
    });
    el.dispatchEvent(event);
  }

  /** Scroll element into view and wait for it to be in viewport. */
  function _scrollIntoView(el) {
    el.scrollIntoView({ behavior: "instant", block: "center", inline: "center" });
  }

  /** Check if element is interactive (visible, enabled, not covered). */
  function _isInteractive(el) {
    const rect = el.getBoundingClientRect();
    if (rect.width === 0 && rect.height === 0) return { ok: false, reason: "zero-size" };
    const style = window.getComputedStyle(el);
    if (style.display === "none") return { ok: false, reason: "display:none" };
    if (style.visibility === "hidden") return { ok: false, reason: "visibility:hidden" };
    if (style.pointerEvents === "none") return { ok: false, reason: "pointer-events:none" };
    if (el.disabled) return { ok: false, reason: "disabled" };
    // Check if covered by another element
    const cx = rect.left + rect.width / 2;
    const cy = rect.top + rect.height / 2;
    const topEl = document.elementFromPoint(cx, cy);
    if (topEl && topEl !== el && !el.contains(topEl) && !topEl.contains(el)) {
      return { ok: false, reason: `covered by <${topEl.tagName.toLowerCase()}>` };
    }
    return { ok: true };
  }

  /** Wait for DOM to stabilize (no new mutations for `ms` milliseconds). */
  function _waitStable(ms) {
    return new Promise((resolve) => {
      let timeout = setTimeout(resolve, ms);
      const observer = new MutationObserver(() => {
        clearTimeout(timeout);
        timeout = setTimeout(() => {
          observer.disconnect();
          resolve();
        }, ms);
      });
      observer.observe(document.body, {
        childList: true,
        subtree: true,
        attributes: true,
      });
      // Hard cap at 5s
      setTimeout(() => {
        observer.disconnect();
        resolve();
      }, 5000);
    });
  }

  /** Detect what changed after an action. */
  function _detectChanges(beforeSnapshot) {
    const changes = [];
    // Check for new visible elements
    document.querySelectorAll('[role="menu"], [role="listbox"], [role="dialog"], dialog[open], .dropdown-menu.show, .collapse.show')
      .forEach((el) => {
        const id = el.getAttribute("data-xpa-id");
        if (!beforeSnapshot.has(id || el.outerHTML.substring(0, 50))) {
          changes.push({
            type: "appeared",
            tag: el.tagName.toLowerCase(),
            role: el.getAttribute("role") || "",
            text: (el.textContent || "").trim().substring(0, 60),
          });
        }
      });
    return changes;
  }

  /** Snapshot currently visible dynamic elements for change detection. */
  function _snapshotDynamic() {
    const snapshot = new Set();
    document.querySelectorAll('[role="menu"], [role="listbox"], [role="dialog"], dialog[open], .dropdown-menu.show, .collapse.show')
      .forEach((el) => {
        snapshot.add(el.getAttribute("data-xpa-id") || el.outerHTML.substring(0, 50));
      });
    return snapshot;
  }

  // ── Public API ───────────────────────────────────────────────────────

  /**
   * Interact with an element by xpa-id.
   * Actions: click, hover, rightClick, doubleClick, focus, blur, toggle
   */
  window.xpa_interact = async function (id, action) {
    const el = _find(id);
    _scrollIntoView(el);

    const check = _isInteractive(el);
    if (!check.ok) {
      return JSON.stringify({
        success: false,
        error: `Element ${id} is not interactive: ${check.reason}`,
      });
    }

    const before = _snapshotDynamic();

    switch (action) {
      case "click":
        _pointerEvent(el, "pointerdown");
        _mouseEvent(el, "mousedown");
        _pointerEvent(el, "pointerup");
        _mouseEvent(el, "mouseup");
        _mouseEvent(el, "click");
        break;

      case "hover":
        _pointerEvent(el, "pointerenter");
        _mouseEvent(el, "mouseenter");
        _pointerEvent(el, "pointerover");
        _mouseEvent(el, "mouseover");
        break;

      case "rightClick":
        _pointerEvent(el, "pointerdown", { button: 2 });
        _mouseEvent(el, "mousedown", { button: 2 });
        _pointerEvent(el, "pointerup", { button: 2 });
        _mouseEvent(el, "mouseup", { button: 2 });
        _mouseEvent(el, "contextmenu", { button: 2 });
        break;

      case "doubleClick":
        _mouseEvent(el, "click");
        _mouseEvent(el, "click");
        _mouseEvent(el, "dblclick");
        break;

      case "focus":
        el.focus();
        el.dispatchEvent(new FocusEvent("focus", { bubbles: true }));
        el.dispatchEvent(new FocusEvent("focusin", { bubbles: true }));
        break;

      case "blur":
        el.blur();
        el.dispatchEvent(new FocusEvent("blur", { bubbles: true }));
        el.dispatchEvent(new FocusEvent("focusout", { bubbles: true }));
        break;

      case "toggle":
        // Toggle aria-expanded or open attribute
        if (el.hasAttribute("aria-expanded")) {
          const current = el.getAttribute("aria-expanded") === "true";
          el.setAttribute("aria-expanded", String(!current));
          _mouseEvent(el, "click");
        } else if (el.tagName === "DETAILS") {
          el.open = !el.open;
        } else {
          _mouseEvent(el, "click");
        }
        break;

      default:
        return JSON.stringify({
          success: false,
          error: `Unknown action: ${action}`,
        });
    }

    // Wait for DOM to stabilize after interaction
    await _waitStable(300);

    const changes = _detectChanges(before);
    const newState = {};
    if (el.getAttribute("aria-expanded") !== null) {
      newState.expanded = el.getAttribute("aria-expanded") === "true";
    }

    return JSON.stringify({
      success: true,
      action,
      elementId: id,
      tag: el.tagName.toLowerCase(),
      label: (el.textContent || "").trim().substring(0, 60),
      newState,
      domChanges: changes,
      url: window.location.href,
    });
  };

  /**
   * Type text into an element.
   * Options: { clear: true } to clear before typing.
   */
  window.xpa_type = function (id, text, clear) {
    const el = _find(id);
    _scrollIntoView(el);
    el.focus();

    if (clear) {
      el.value = "";
      el.dispatchEvent(new Event("input", { bubbles: true }));
    }

    // Type character by character for realistic input
    for (const char of text) {
      el.dispatchEvent(new KeyboardEvent("keydown", { key: char, bubbles: true }));
      el.dispatchEvent(new KeyboardEvent("keypress", { key: char, bubbles: true }));
      el.value += char;
      el.dispatchEvent(new InputEvent("input", { data: char, inputType: "insertText", bubbles: true }));
      el.dispatchEvent(new KeyboardEvent("keyup", { key: char, bubbles: true }));
    }

    el.dispatchEvent(new Event("change", { bubbles: true }));

    return JSON.stringify({
      success: true,
      elementId: id,
      typed: text.length + " chars",
    });
  };

  /**
   * Select a dropdown option by value or visible text.
   */
  window.xpa_select = function (id, value) {
    const el = _find(id);

    if (el.tagName.toLowerCase() !== "select") {
      // Try clicking the option inside a custom dropdown
      const option = el.querySelector(
        `[data-value="${value}"], [value="${value}"]`
      );
      if (option) {
        option.click();
        return JSON.stringify({ success: true, elementId: id, selected: value });
      }
      // Try by text
      const allOptions = el.querySelectorAll("li, a, button, [role='option']");
      for (const opt of allOptions) {
        if ((opt.textContent || "").trim().toLowerCase().includes(value.toLowerCase())) {
          opt.click();
          return JSON.stringify({ success: true, elementId: id, selected: value });
        }
      }
      return JSON.stringify({ success: false, error: "Option not found in custom dropdown" });
    }

    // Native <select>
    for (const opt of el.options) {
      if (opt.value === value || opt.text.trim().toLowerCase().includes(value.toLowerCase())) {
        el.value = opt.value;
        el.dispatchEvent(new Event("change", { bubbles: true }));
        return JSON.stringify({ success: true, elementId: id, selected: opt.value });
      }
    }

    return JSON.stringify({ success: false, error: `Option "${value}" not found` });
  };

  /**
   * Get element state: computed styles, aria attrs, visibility, position.
   */
  window.xpa_getState = function (id) {
    const el = _find(id);
    const rect = el.getBoundingClientRect();
    const style = window.getComputedStyle(el);

    return JSON.stringify({
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
      classes: el.className ? el.className.substring(0, 200) : "",
      rect: {
        x: Math.round(rect.x),
        y: Math.round(rect.y),
        width: Math.round(rect.width),
        height: Math.round(rect.height),
      },
      display: style.display,
      position: style.position,
      zIndex: style.zIndex,
      overflow: style.overflow,
    });
  };

  /**
   * Wait for an element matching the selector to appear.
   * Returns its data-xpa-id when found or error on timeout.
   */
  window.xpa_waitFor = function (selector, timeoutMs) {
    timeoutMs = timeoutMs || 10000;

    return new Promise((resolve) => {
      // Check immediately
      const existing = document.querySelector(selector);
      if (existing) {
        const id = existing.getAttribute("data-xpa-id") || (() => {
          const newId = "xpa_w" + Date.now();
          existing.setAttribute("data-xpa-id", newId);
          return newId;
        })();
        resolve(JSON.stringify({ success: true, id, selector }));
        return;
      }

      const observer = new MutationObserver(() => {
        const found = document.querySelector(selector);
        if (found) {
          observer.disconnect();
          clearTimeout(timeout);
          const id = found.getAttribute("data-xpa-id") || (() => {
            const newId = "xpa_w" + Date.now();
            found.setAttribute("data-xpa-id", newId);
            return newId;
          })();
          resolve(JSON.stringify({ success: true, id, selector }));
        }
      });

      observer.observe(document.body, { childList: true, subtree: true, attributes: true });

      const timeout = setTimeout(() => {
        observer.disconnect();
        resolve(JSON.stringify({ success: false, error: `Timeout waiting for: ${selector}` }));
      }, timeoutMs);
    });
  };

  /**
   * Scroll an element into the center of the viewport.
   */
  window.xpa_scrollIntoView = function (id) {
    const el = _find(id);
    _scrollIntoView(el);
    return JSON.stringify({ success: true, id });
  };

  return "xpa_controller_loaded";
})();
