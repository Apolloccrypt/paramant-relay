#!/usr/bin/env bash
# Deploy de paramant signup/login fix op productie, drift-veilig (past de
# transformatie toe op de ECHT gedeployde bestanden). Met backup, verificatie
# en auto-rollback. Draait vanaf de NUC; hopt read/write naar paramant-server.
set -uo pipefail
export SSH_AUTH_SOCK=/run/user/$(id -u)/keyring/ssh
H=paramant-server
LOG=/tmp/paramant-signup-fix.log
run() { ssh -o BatchMode=yes "$H" "$@"; }
say() { echo "[$(date +%H:%M:%S)] $*"; }

say "=== paramant signup-fix deploy start ==="

# 0. Verstuur de extractor naar prod
run 'cat > /tmp/extract.py' <<'PYEOF'
import re, sys, os
jobs = {
  "frontend/auth/login.html": "auth-login",
  "frontend/auth/setup.html": "auth-setup",
  "frontend/auth/request-reset.html": "auth-request-reset",
  "frontend/auth/reset-confirm.html": "auth-reset-confirm",
  "frontend/auth/backup.html": "auth-backup",
  "frontend/billing/checkout.html": "billing-checkout",
}
changed = 0
for path, name in jobs.items():
    if not os.path.exists(path):
        print(f"SKIP ontbreekt: {path}"); continue
    src = open(path, encoding="utf-8").read()
    m = re.search(r'[ \t]*<script>\n(.*?)\n[ \t]*</script>', src, re.DOTALL)
    if not m:
        print(f"AL-OK geen kaal <script>: {path}"); continue
    body = m.group(1)
    jsfile = f"frontend/js/{name}.js"
    open(jsfile, "w", encoding="utf-8").write(body.rstrip() + "\n")
    src2 = src[:m.start()] + f'<script src="/js/{name}.js?v=1"></script>' + src[m.end():]
    open(path, "w", encoding="utf-8").write(src2)
    left = len(re.findall(r'<script>\s*\n', src2))
    print(f"OK {path} -> {jsfile} ({len(body.splitlines())} regels) rest-kaal={left}")
    changed += 1
print(f"TOTAAL geexternaliseerd: {changed}")
PYEOF

# 1. Backup
TS=$(run 'date +%Y%m%d-%H%M%S')
BK="/opt/paramant-relay/backups/signup-fix-$TS"
say "backup -> $BK"
run "mkdir -p $BK/frontend/auth $BK/frontend/js $BK/frontend/billing $BK/nginx
     cd /opt/paramant-relay
     cp -a frontend/auth/*.html $BK/frontend/auth/ 2>/dev/null
     cp -a frontend/billing/checkout.html $BK/frontend/billing/ 2>/dev/null
     cp -a frontend/js $BK/frontend/js.orig 2>/dev/null
     cp -a /etc/nginx/sites-enabled/paramant.conf $BK/nginx/paramant.conf 2>/dev/null
     echo backup-klaar"

# 2. BLOKKER A - externaliseer op de gedeployde bestanden
say "BLOKKER A: externaliseren"
run "cd /opt/paramant-relay && python3 /tmp/extract.py"

# 3. BLOKKER B - nginx real_ip fix
say "BLOKKER B: nginx real_ip"
run "sed -i 's/^\(\s*\)real_ip_header CF-Connecting-IP;/\1real_ip_header X-Forwarded-For;\n\1real_ip_recursive on;/' /etc/nginx/sites-enabled/paramant.conf
     grep -n 'real_ip_header' /etc/nginx/sites-enabled/paramant.conf"

# 4. nginx test + reload
if run 'nginx -t 2>&1'; then
  run 'systemctl reload nginx && echo nginx-reloaded'
else
  say "!! nginx -t FAALT - rollback nginx"
  run "cp -a $BK/nginx/paramant.conf /etc/nginx/sites-enabled/paramant.conf && systemctl reload nginx"
fi

# 5. Redis: flush de vastgelopen 127.0.0.1 emmers
say "redis flush 127.0.0.1 emmers"
run 'docker exec paramant-relay-admin node -e "const {createClient}=require(\"redis\");(async()=>{const c=createClient({url:process.env.REDIS_URL});await c.connect();let n=0;for(const p of [\"paramant:signup:ratelimit:ip:*\",\"captcha:ip:*\",\"paramant:*ratelimit*127.0.0.1*\"]){const ks=await c.keys(p);for(const k of ks){await c.del(k);n++}}console.log(\"gedelete keys:\",n);await c.quit()})().catch(e=>console.log(\"redis-err\",e.message))"'

# 6. Verificatie (extern, echt)
say "=== verificatie ==="
FAIL=0
for u in /auth/login /auth/setup /js/auth-login.js /js/auth-setup.js; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "https://paramant.app$u")
  say "  $code  $u"
  [ "$code" = "200" ] || FAIL=1
done
BARE=$(curl -s https://paramant.app/auth/login | grep -cE '<script>[[:space:]]*$')
say "  kale <script> op /auth/login: $BARE (moet 0)"
[ "$BARE" = "0" ] || FAIL=1

if [ "$FAIL" = "1" ]; then
  say "!! VERIFICATIE GEFAALD - ROLLBACK frontend"
  run "cd /opt/paramant-relay && cp -a $BK/frontend/auth/*.html frontend/auth/ && cp -a $BK/frontend/billing/checkout.html frontend/billing/ 2>/dev/null; echo frontend-teruggezet"
  say "rollback klaar. Backup: $BK"
else
  say "=== KLAAR: signup/login hersteld. Backup: $BK ==="
fi
