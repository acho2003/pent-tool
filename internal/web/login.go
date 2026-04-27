package web

// loginPageHTML is the cyberpunk-styled login page served when auth is required
const loginPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Xalgorix — Access Terminal</title>
<style>
  /* Self-hosted typography stack — no third-party requests, works air-gapped */
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:ui-monospace,SFMono-Regular,'JetBrains Mono',Consolas,Menlo,monospace;background:#0a0a0f;color:#e0e0e0;display:flex;align-items:center;justify-content:center;min-height:100vh;overflow:hidden}
  body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(0,255,136,.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,255,136,.03) 1px,transparent 1px);background-size:50px 50px;pointer-events:none}
  body::after{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.15) 2px,rgba(0,0,0,.15) 4px);pointer-events:none;opacity:.4;z-index:9999}
  .card{background:rgba(18,18,26,.95);border:1px solid rgba(0,255,136,.25);padding:40px;width:100%;max-width:400px;position:relative;clip-path:polygon(0 12px,12px 0,calc(100% - 12px) 0,100% 12px,100% calc(100% - 12px),calc(100% - 12px) 100%,12px 100%,0 calc(100% - 12px));box-shadow:0 0 30px rgba(0,255,136,.08)}
  .card::before,.card::after{content:'';position:absolute;width:20px;height:20px;border:1px solid #ff00ff}
  .card::before{top:-1px;left:-1px;border-right:none;border-bottom:none}
  .card::after{bottom:-1px;right:-1px;border-left:none;border-top:none}
  .logo{text-align:center;margin-bottom:32px}
  .logo h1{font-family:ui-sans-serif,system-ui,'Segoe UI',Helvetica,Arial,sans-serif;font-size:28px;font-weight:900;letter-spacing:.15em;text-transform:uppercase;color:#00ff88;text-shadow:0 0 20px rgba(0,255,136,.4),-1px 0 #ff00ff,1px 0 #00d4ff}
  .logo p{color:#6b7280;font-size:10px;margin-top:8px;letter-spacing:.2em;text-transform:uppercase}
  .group{margin-bottom:20px}
  label{display:block;font-size:10px;font-weight:600;color:#6b7280;margin-bottom:6px;letter-spacing:.15em;text-transform:uppercase}
  label::before{content:'> ';color:#00ff88}
  input{width:100%;padding:12px 16px;padding-left:24px;background:rgba(10,10,15,.9);border:1px solid #2a2a3a;color:#00ff88;font-family:ui-monospace,SFMono-Regular,'JetBrains Mono',Consolas,Menlo,monospace;font-size:14px;outline:none;transition:all .2s;letter-spacing:.03em;clip-path:polygon(0 4px,4px 0,calc(100% - 4px) 0,100% 4px,100% calc(100% - 4px),calc(100% - 4px) 100%,4px 100%,0 calc(100% - 4px))}
  input:focus{border-color:#00ff88;box-shadow:0 0 5px #00ff88,0 0 15px rgba(0,255,136,.3)}
  input::placeholder{color:#4a4a5a}
  button{width:100%;padding:14px;background:#00ff88;color:#0a0a0f;border:none;font-family:ui-sans-serif,system-ui,'Segoe UI',Helvetica,Arial,sans-serif;font-size:13px;font-weight:700;cursor:pointer;transition:all .15s;text-transform:uppercase;letter-spacing:.15em;clip-path:polygon(0 4px,4px 0,calc(100% - 4px) 0,100% 4px,100% calc(100% - 4px),calc(100% - 4px) 100%,4px 100%,0 calc(100% - 4px))}
  button:hover{filter:brightness(1.1);box-shadow:0 0 10px #00ff88,0 0 30px rgba(0,255,136,.4)}
  button:active{transform:scale(.98)}
  button:disabled{opacity:.4;cursor:not-allowed}
  .error{color:#ff3366;font-size:11px;text-align:center;margin-top:16px;min-height:20px;letter-spacing:.05em}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <h1>XALGORIX</h1>
    <p>Access Terminal</p>
  </div>
  <form id="f">
    <div class="group"><label for="u">Username</label><input type="text" id="u" autocomplete="username" autofocus required></div>
    <div class="group"><label for="p">Password</label><input type="password" id="p" autocomplete="current-password" required></div>
    <button type="submit" id="b">Authenticate</button>
    <div class="error" id="e"></div>
  </form>
</div>
<script>
document.getElementById('f').addEventListener('submit',async e=>{e.preventDefault();const b=document.getElementById('b'),err=document.getElementById('e');b.disabled=true;b.textContent='CONNECTING...';err.textContent='';try{const r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})});const d=await r.json();if(r.ok){window.location.href='/'}else{err.textContent=d.error||'ACCESS DENIED'}}catch(x){err.textContent='CONNECTION ERROR'}b.disabled=false;b.textContent='AUTHENTICATE'});
</script>
</body>
</html>`
