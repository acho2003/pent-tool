// discovery.js — In-page menu/UI discovery agent for Xalgorix
// Injected via CDP into target pages.  Performs multi-phase analysis
// to enumerate menus, dropdowns, tabs, accordions, modals, and other
// interactive UI widgets that the pentesting agent may need to navigate.
//
// Returns a JSON-serializable object with the full UI element hierarchy.

(() => {
  "use strict";

  // ── helpers ──────────────────────────────────────────────────────────
  let _idCounter = 1;

  /** Assign a stable `data-xpa-id` to an element and return the id. */
  function tagElement(el) {
    if (el.getAttribute("data-xpa-id")) return el.getAttribute("data-xpa-id");
    const id = "xpa" + _idCounter++;
    el.setAttribute("data-xpa-id", id);
    return id;
  }

  /** Check if an element is truly visible. */
  function isVisible(el) {
    if (!el || !el.getBoundingClientRect) return false;
    const rect = el.getBoundingClientRect();
    if (rect.width === 0 && rect.height === 0) return false;
    const style = window.getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden") return false;
    if (parseFloat(style.opacity) < 0.05) return false;
    return true;
  }

  /** Get a human-readable label for an element. */
  function getLabel(el) {
    const candidates = [
      el.getAttribute("aria-label"),
      el.getAttribute("title"),
      el.getAttribute("alt"),
      el.textContent,
    ];
    for (const c of candidates) {
      if (c && c.trim().length > 0 && c.trim().length < 120) {
        return c.trim().replace(/\s+/g, " ").substring(0, 80);
      }
    }
    return "";
  }

  /** Build a descriptor object for a single element. */
  function describe(el, type, extras) {
    const id = tagElement(el);
    const tag = el.tagName.toLowerCase();
    const label = getLabel(el);
    const visible = isVisible(el);
    const disabled = el.disabled || el.getAttribute("aria-disabled") === "true";
    const expanded = el.getAttribute("aria-expanded");
    const hasPopup = el.getAttribute("aria-haspopup");
    const controls = el.getAttribute("aria-controls");
    const role = el.getAttribute("role") || "";

    const desc = {
      id,
      tag,
      type,
      label,
      visible,
      disabled,
      role,
    };

    if (expanded !== null) desc.expanded = expanded === "true";
    if (hasPopup) desc.hasPopup = hasPopup;
    if (controls) desc.controls = controls;
    if (el.name) desc.name = el.name;
    if (el.href) desc.href = el.href;
    if (extras) Object.assign(desc, extras);

    return desc;
  }

  // ── Phase 1: Static Analysis ─────────────────────────────────────────

  const menus = [];
  const dropdowns = [];
  const tabs = [];
  const accordions = [];
  const modals = [];
  const forms = [];
  const other = [];

  // 1a. Navigation menus
  document.querySelectorAll(
    'nav, [role="navigation"], [role="menubar"], [role="menu"]'
  ).forEach((el) => {
    const items = [];
    el.querySelectorAll(
      'a, button, [role="menuitem"], [role="menuitemcheckbox"], [role="menuitemradio"]'
    ).forEach((item) => {
      if (item.closest('nav, [role="navigation"], [role="menubar"], [role="menu"]') === el) {
        items.push(describe(item, "menu_item"));
      }
    });
    menus.push({
      ...describe(el, "navigation"),
      children: items,
    });
  });

  // 1b. Dropdowns — elements with aria-haspopup or aria-expanded
  document.querySelectorAll(
    '[aria-haspopup], [aria-expanded], [data-toggle="dropdown"], [data-bs-toggle="dropdown"]'
  ).forEach((el) => {
    // Skip if already captured as part of a menu
    if (el.closest('nav, [role="navigation"]')) return;
    const controlsId = el.getAttribute("aria-controls");
    let panel = null;
    if (controlsId) {
      const target = document.getElementById(controlsId);
      if (target) {
        const panelItems = [];
        target.querySelectorAll("a, button, li, [role=\"option\"]").forEach((item) => {
          panelItems.push(describe(item, "dropdown_item"));
        });
        panel = { ...describe(target, "dropdown_panel"), children: panelItems };
      }
    }
    const dd = describe(el, "dropdown_trigger");
    if (panel) dd.panel = panel;
    dropdowns.push(dd);
  });

  // 1c. Tab components
  document.querySelectorAll('[role="tablist"]').forEach((el) => {
    const tabItems = [];
    el.querySelectorAll('[role="tab"]').forEach((tab) => {
      const selected = tab.getAttribute("aria-selected") === "true";
      const controls = tab.getAttribute("aria-controls");
      tabItems.push(
        describe(tab, "tab", { selected, controls })
      );
    });
    tabs.push({
      ...describe(el, "tablist"),
      children: tabItems,
    });
  });

  // 1d. Accordions — details/summary and aria patterns
  document.querySelectorAll("details").forEach((el) => {
    const summary = el.querySelector("summary");
    accordions.push(
      describe(el, "accordion", {
        open: el.open,
        summaryLabel: summary ? getLabel(summary) : "",
        summaryId: summary ? tagElement(summary) : null,
      })
    );
  });

  // Also find custom accordions (Bootstrap/Material)
  document.querySelectorAll(
    '[data-toggle="collapse"], [data-bs-toggle="collapse"], [aria-expanded][aria-controls]'
  ).forEach((el) => {
    // Skip if already in dropdowns
    if (el.getAttribute("aria-haspopup")) return;
    if (el.closest("details")) return;
    const controlsId = el.getAttribute("aria-controls") ||
      el.getAttribute("data-target") ||
      el.getAttribute("data-bs-target");
    accordions.push(
      describe(el, "accordion_trigger", {
        expanded: el.getAttribute("aria-expanded") === "true",
        controls: controlsId ? controlsId.replace("#", "") : null,
      })
    );
  });

  // 1e. Modals and dialog triggers
  document.querySelectorAll(
    '[data-toggle="modal"], [data-bs-toggle="modal"], [role="dialog"], dialog'
  ).forEach((el) => {
    modals.push(describe(el, el.tagName === "DIALOG" ? "dialog" : "modal_trigger"));
  });

  // 1f. Forms
  document.querySelectorAll("form").forEach((el) => {
    const fields = [];
    el.querySelectorAll("input, select, textarea, button").forEach((field) => {
      fields.push(describe(field, "form_field", {
        inputType: field.type || null,
        value: field.type === "password" ? "***" : (field.value || "").substring(0, 40),
        placeholder: field.placeholder || null,
        required: field.required || false,
      }));
    });
    forms.push({
      ...describe(el, "form", {
        action: el.action || null,
        method: el.method || "GET",
      }),
      children: fields,
    });
  });

  // ── Phase 2: Heuristic Detection ─────────────────────────────────────

  // Find elements that likely contain hidden submenus (have hidden children)
  document.querySelectorAll("li, div, span").forEach((el) => {
    if (el.getAttribute("data-xpa-id")) return; // Already captured
    const hiddenChild = el.querySelector(
      'ul, ol, div, [role="menu"], [role="listbox"]'
    );
    if (!hiddenChild) return;
    if (!isVisible(hiddenChild) && isVisible(el)) {
      // This element has a hidden child — likely a hover-reveal menu
      const trigger = el.querySelector("a, button, span");
      if (trigger && getLabel(trigger)) {
        const childItems = [];
        hiddenChild.querySelectorAll("a, button, li").forEach((item) => {
          if (getLabel(item)) {
            childItems.push(describe(item, "submenu_item"));
          }
        });
        if (childItems.length > 0) {
          other.push({
            ...describe(trigger, "hover_menu_trigger"),
            hiddenPanel: describe(hiddenChild, "hidden_submenu"),
            children: childItems,
          });
        }
      }
    }
  });

  // Find select elements not in forms
  document.querySelectorAll("select").forEach((el) => {
    if (el.closest("form")) return;
    const options = [];
    el.querySelectorAll("option").forEach((opt) => {
      options.push({
        value: opt.value,
        label: opt.textContent.trim().substring(0, 60),
        selected: opt.selected,
      });
    });
    dropdowns.push(
      describe(el, "standalone_select", { options })
    );
  });

  // ── Phase 3: Summary ─────────────────────────────────────────────────

  const result = {
    url: window.location.href,
    title: document.title,
    timestamp: new Date().toISOString(),
    counts: {
      menus: menus.length,
      dropdowns: dropdowns.length,
      tabs: tabs.length,
      accordions: accordions.length,
      modals: modals.length,
      forms: forms.length,
      other: other.length,
    },
    menus,
    dropdowns,
    tabs,
    accordions,
    modals,
    forms,
    other,
  };

  return JSON.stringify(result);
})();
