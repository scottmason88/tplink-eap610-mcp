#!/usr/bin/env python3
"""Configure only a separately provisioned EAP610 tunnel. Never reuse another device's tunnel ID."""
import argparse, json, pathlib, re, subprocess, urllib.request

root=pathlib.Path.home()/'.config/eap610-mcp'
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--tunnel-id',required=True)
args=p.parse_args()
if not re.fullmatch(r'tunnel_[a-f0-9]{16,64}',args.tunnel_id):p.error('Invalid tunnel identifier')
# Refuse any tunnel ID currently assigned to another installed service.
for unit in (pathlib.Path.home()/'.config/systemd/user').glob('openai-*-tunnel.service'):
    if unit.name!='openai-eap610-tunnel.service' and args.tunnel_id in unit.read_text():
        p.error('This tunnel belongs to another service. Create a dedicated EAP610 tunnel.')
token=(root/'mcp-token').read_text().strip()
q=urllib.request.Request('http://127.0.0.1:8770/mcp',json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}}).encode(),
    {'Content-Type':'application/json','Accept':'application/json, text/event-stream','Authorization':'Bearer '+token})
with urllib.request.urlopen(q,timeout=10) as r:n=[t['name'] for t in json.load(r)['result']['tools']]
if len(n)!=11 or any(not x.startswith('eap_') for x in n):raise RuntimeError('Endpoint is not the dedicated EAP MCP')
path=root/'tunnel-id.env'
with path.open('w') as f:f.write('EAP610_TUNNEL_ID='+args.tunnel_id+'\n')
path.chmod(0o600)
subprocess.run(['systemctl','--user','enable','--now','openai-eap610-tunnel.service'],check=True)
print('Dedicated EAP610 tunnel configured. Check readiness before connecting the new EAP610 app.')
