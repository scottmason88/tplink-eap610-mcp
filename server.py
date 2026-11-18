#!/usr/bin/env python3
"""Guarded direct EAP610 MCP, firmware 1.6.30. No controller or Docker."""
from __future__ import annotations
import argparse, copy, fcntl, hashlib, hmac, json, os, pathlib, re, secrets, sys, tempfile, threading, time
from contextlib import contextmanager
from ap import AP, APError, ROOT, FIRMWARE
from eap_tools import SSIDChange, RadioChange, VLANChange, register

TTL=300
LOCK=threading.RLock()
SECRET_FIELDS={'psk_key','wpa_key','acct_key','password','passwordSHA256','salt','getCommunity','setCommunity'}

def private_write(path, value):
    path=pathlib.Path(path);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    os.chmod(path.parent,0o700)
    fd,tmp=tempfile.mkstemp(dir=path.parent)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb') as f:
            f.write(value if isinstance(value,bytes) else json.dumps(value,sort_keys=True).encode());f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def clean(d):
    if isinstance(d,dict):return {k:('[redacted]' if k in SECRET_FIELDS or k.startswith('wep_key') else clean(v)) for k,v in d.items()}
    if isinstance(d,list):return [clean(x) for x in d]
    return d

def canonical(s):
    # Only persistent config belongs in a drift digest, not uptime/CPU/counters.
    return {k:s[k] for k in ('radios','ssids','vlans','led')}

def digest(s):return hashlib.sha256(json.dumps(s,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def diff(a,b,p=''):
    if a==b:return []
    if isinstance(a,dict) and isinstance(b,dict):
        out=[]
        for k in sorted(set(a)|set(b)):
            if k in SECRET_FIELDS and a.get(k)!=b.get(k):raise APError('Unexpected credential change detected')
            out+=diff(a.get(k),b.get(k),p+'/'+str(k))
        return out
    if isinstance(a,list) and isinstance(b,list) and len(a)==len(b):
        return [v for i,(x,y) in enumerate(zip(a,b)) for v in diff(x,y,p+'/'+str(i))]
    return [{'field':p,'before':clean(a),'after':clean(b)}]

def valid_id(cid):
    if not re.fullmatch(r'[a-f0-9]{32}',cid):raise APError('Invalid change ID')
    return cid

@contextmanager
def exclusive():
    ROOT.mkdir(mode=0o700,exist_ok=True)
    with LOCK:
        fd=os.open(ROOT/'operation.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX);yield
        finally:os.close(fd)

def audit(event, **fields):
    path=ROOT/'audit.jsonl';prev='0'*64
    if path.exists():
        with path.open('rb') as f:
            lines=f.readlines()
            if lines:prev=json.loads(lines[-1])['record_hash']
    row={'at':time.time(),'event':event,'previous':prev,**fields}
    row['record_hash']=digest(row)
    fd=os.open(path,os.O_CREAT|os.O_APPEND|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a') as f:f.write(json.dumps(row,sort_keys=True)+'\n');f.flush();os.fsync(f.fileno())

class Backend:
    def __init__(self, ap=None):self.ap=ap or AP()

    def call(self,operation,args):
        allowed={'inventory','wireless','clients','capabilities','backup','preview_led','preview_ssid','preview_radio','preview_vlan','apply','preview_rollback'}
        if operation not in allowed:raise APError('Unknown operation')
        with exclusive():
            try:
                result=getattr(self,operation)(**args)
                audit('tool_ok',operation=operation)
                return result
            except Exception as e:
                audit('tool_failed',operation=operation,error_type=type(e).__name__)
                if isinstance(e,(APError,ValueError)):raise
                raise APError('Operation failed: '+type(e).__name__) from None

    def inventory(self):
        self.ap.ensure();return {'identity':self.ap.identity(),'management':'standalone HTTPS','writes_locked_by_default':True}

    def wireless(self):
        s=self.ap.snapshot();return clean({k:s[k] for k in ('radios','ssids','vlans','led')})

    def clients(self):return {'clients':clean(self.ap.clients())}

    def capabilities(self):
        verified={}
        p=ROOT/'verified.json'
        if p.exists():verified=json.loads(p.read_text())
        return {'adapter_firmware':FIRMWARE,'ip':(json.loads((ROOT/'device.json').read_text()).get('host') if (ROOT/'device.json').exists() else None),'mac':(json.loads((ROOT/'device.json').read_text()).get('mac') if (ROOT/'device.json').exists() else None),
                'read_live_verified':['identity','health','radios','ssids','clients','vlans','led'],
                'write_request_schemas_inspected':['led','ssid rename/broadcast','radio channel/power','SSID VLAN assignment'],
                'write_live_verified':verified,
                'not_exposed':['arbitrary HTTP','shell','credentials','management IP/VLAN','adoption','reset','firmware update','reboot','restore upload','SSID create/delete','security/password changes'],
                'preview_ttl_seconds':TTL,'approval':'Separate operator approval bound to change ID + plan hash; no MCP approval/unlock tool',
                'wireless_changes':'Additionally require one-use local interactive unlock; not live-tested without approval',
                'vlan_allowlist':[0,30,40],
                'rollback':'Preview inverse of applied change; approve separately. If AP becomes unreachable, stop and use local web restore of saved binary; never reset automatically.',
                'scope_limit':'The host account running this service is trusted. Local Unix account/root access can modify approval files. Audit is hash-chained, not externally tamper-proof.'}

    def _backup(self,snapshot=None):
        s=snapshot or self.ap.snapshot();blob=self.ap.backup()
        bid=time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'-'+secrets.token_hex(4)
        folder=ROOT/'backups'/bid
        private_write(folder/'config.bin',blob);private_write(folder/'snapshot.json',s)
        meta={'backup_id':bid,'bytes':len(blob),'sha256':hashlib.sha256(blob).hexdigest(),
              'restore_method':'Manual standalone web restore; automatic restore intentionally not exposed',
              'encryption':'Export uses existing AP backup state; no backup-encryption settings changed'}
        private_write(folder/'metadata.json',meta);audit('backup_saved',backup_id=bid,sha256=meta['sha256'])
        return meta

    def backup(self):return self._backup()

    def _proposal(self,kind,before,after,target,rollback_of=None):
        changes=diff(canonical(before),canonical(after))
        if not changes:raise APError('No change requested')
        cid=secrets.token_hex(16)
        p={'id':cid,'created':time.time(),'expires':time.time()+TTL,'kind':kind,'target':target,
           'before':before,'after':after,'before_hash':digest(canonical(before)),
           'after_hash':digest(canonical(after)),'disruptive':kind!='led','rollback_of':rollback_of,
           'status':'pending'}
        p['plan_hash']=digest(p)
        private_write(ROOT/'changes'/(cid+'.json'),p)
        audit('preview',change_id=cid,kind=kind,plan_hash=p['plan_hash'])
        return {'change_id':cid,'plan_hash':p['plan_hash'],'expires_at_unix':p['expires'],
                'changes':changes,'disruptive':p['disruptive'],
                'requires':'Explicit human approval recorded separately on Pi'+(' AND one-use local interactive unlock' if p['disruptive'] else ''),
                'apply_confirmation':'APPLY '+cid,'live_write_tested':kind in self.capabilities()['write_live_verified']}

    def preview_led(self,enabled):
        if type(enabled) is not bool:raise APError('enabled must be boolean')
        b=self.ap.snapshot();a=copy.deepcopy(b);a['led']['enable']='on' if enabled else 'off'
        return self._proposal('led',b,a,{})

    def preview_ssid(self,change):
        c=SSIDChange.model_validate(change)
        if c.name is not None and (len(c.name.encode())>32 or any(ord(x)<32 for x in c.name)):
            raise APError('SSID must be 1-32 UTF-8 bytes without control characters')
        b=self.ap.snapshot();a=copy.deepcopy(b)
        if c.index>=len(a['ssids'][c.band]):raise APError('SSID index does not exist')
        row=a['ssids'][c.band][c.index]
        if row.get('owe_ssid'):raise APError('OWE companion SSIDs are not supported')
        if c.name is not None:
            if any(x['ssidname']==c.name for i,x in enumerate(a['ssids'][c.band]) if i!=c.index):raise APError('SSID name already exists')
            old=row['ssidname'];row['ssidname']=c.name
            for v in a['vlans']:
                if v['band']==c.band and v['ssidname']==old:v['ssidname']=c.name
        if c.broadcast is not None:row['ssidbcast']=1 if c.broadcast else 0
        # Refuse a complete-record update if the firmware masks a protected key.
        for key in SECRET_FIELDS:
            if key in row and isinstance(row[key],str) and '*' in row[key]:
                raise APError('Firmware masks credentials; SSID updates disabled to preserve passwords')
        return self._proposal('ssid',b,a,{'band':c.band,'index':c.index})

    def preview_radio(self,change):
        c=RadioChange.model_validate(change);b=self.ap.snapshot();a=copy.deepcopy(b);row=a['radios'][c.band]
        if c.channel is not None:
            frequency=0 if c.channel==0 else (2407+5*c.channel if c.band==0 else 5000+5*c.channel)
            if frequency and frequency not in row['channelRange']:raise APError('Channel outside device-reported allowed frequencies')
            row['frequency']=frequency
        if c.power_dbm is not None:
            if c.power_dbm<int(row['minPower']):raise APError('Power below device minimum')
            row['txpower']=c.power_dbm
        return self._proposal('radio',b,a,{'band':c.band})

    def preview_vlan(self,change):
        c=VLANChange.model_validate(change);b=self.ap.snapshot();a=copy.deepcopy(b)
        rows=[x for x in a['vlans'] if x['band']==c.band and x['ssidname']==c.ssid]
        if len(rows)!=1:raise APError('SSID must uniquely match an existing VLAN row')
        rows[0]['vlan']=0 if c.vlan==0 else 1;rows[0]['vlan_id']=c.vlan
        # SSID table mirrors VLAN assignment; preserve all other fields.
        ssids=[x for x in a['ssids'][c.band] if x['ssidname']==c.ssid]
        if len(ssids)!=1:raise APError('SSID table mismatch')
        ssids[0]['vlanid']=c.vlan
        return self._proposal('vlan',b,a,{'band':c.band,'ssid':c.ssid})

    def _load(self,cid):
        valid_id(cid);p=json.loads((ROOT/'changes'/(cid+'.json')).read_text())
        # Pending plans are immutable and fully bound by their hash.
        original={k:v for k,v in p.items() if k not in ('plan_hash','backup','finished','error_type')}
        original['status']='pending'
        if not hmac.compare_digest(digest(original),p['plan_hash']):raise APError('Plan integrity check failed')
        return p

    def apply(self,change_id,confirmation):
        p=self._load(change_id)
        if confirmation!='APPLY '+change_id:raise APError('Exact apply confirmation required')
        if p['status']!='pending' or time.time()>p['expires']:raise APError('Change expired or already consumed')
        approval=ROOT/'approvals'/(change_id+'.json')
        if not approval.exists():raise APError('Separate local human approval missing')
        record=json.loads(approval.read_text())
        if record.get('plan_hash')!=p['plan_hash'] or record.get('expires',0)<time.time():raise APError('Approval expired or mismatched')
        unlock=ROOT/'unlocks'/(change_id+'.json')
        if p['disruptive']:
            if not unlock.exists():raise APError('Local interactive unlock required')
            u=json.loads(unlock.read_text())
            if u.get('plan_hash')!=p['plan_hash'] or u.get('expires',0)<time.time():raise APError('Local unlock expired or mismatched')
        current=self.ap.snapshot()
        if digest(canonical(current))!=p['before_hash']:raise APError('AP configuration drifted; make a new preview')
        p['backup']=self._backup(current)
        # Consume before first network write. An uncertain response is never retried.
        approval.unlink();unlock.unlink(missing_ok=True);p['status']='applying'
        private_write(ROOT/'changes'/(change_id+'.json'),p)
        audit('write_started',change_id=change_id,kind=p['kind'],plan_hash=p['plan_hash'],backup_id=p['backup']['backup_id'])
        try:
            self.ap.write(p['kind'],p['before'],p['after'],p['target'])
            after=self.ap.snapshot()
            if digest(canonical(after))!=p['after_hash']:raise APError('Read-back differs from exact expected configuration; inspect before further writes')
            p['status']='verified'
            vpath=ROOT/'verified.json';verified=json.loads(vpath.read_text()) if vpath.exists() else {}
            verified[p['kind']]={'at':time.time(),'change_id':change_id,'firmware':FIRMWARE}
            private_write(vpath,verified)
        except Exception as e:
            p['status']='uncertain';p['error_type']=type(e).__name__
            audit('write_uncertain',change_id=change_id,error_type=type(e).__name__)
            raise APError('Write outcome uncertain. Do not retry. Inspect state; private pre-change backup and inverse preview are available.') from None
        finally:
            p['finished']=time.time();private_write(ROOT/'changes'/(change_id+'.json'),p)
        audit('write_verified',change_id=change_id,kind=p['kind'])
        return {'change_id':change_id,'status':p['status'],'backup':p['backup'],'verified_configuration_hash':p['after_hash']}

    def preview_rollback(self,change_id):
        p=self._load(change_id)
        if p['status'] not in ('verified','uncertain'):raise APError('Only completed/uncertain writes can be considered for rollback')
        current=self.ap.snapshot()
        if digest(canonical(current))!=p['after_hash']:raise APError('Current state does not match expected post-change state; manual recovery review required')
        return self._proposal(p['kind'],current,p['before'],p['target'],rollback_of=change_id)

class Auth:
    def __init__(self,app):self.app=app
    async def __call__(self,scope,receive,send):
        if scope['type']=='http':
            headers=dict(scope['headers']);want=('Bearer '+(ROOT/'mcp-token').read_text().strip()).encode()
            if not hmac.compare_digest(headers.get(b'authorization',b''),want):
                await send({'type':'http.response.start','status':401,'headers':[(b'content-type',b'text/plain')]})
                await send({'type':'http.response.body','body':b'Unauthorized'});return
        await self.app(scope,receive,send)

def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group()
    group.add_argument('--approve',metavar='CHANGE_ID')
    group.add_argument('--unlock',metavar='CHANGE_ID')
    group.add_argument('--inspect',metavar='CHANGE_ID')
    group.add_argument('--self-test',action='store_true')
    parser.add_argument('--approval-reference',default='')
    args=parser.parse_args();b=Backend()
    if args.self_test:
        with exclusive():
            s=b.ap.snapshot();s2=b.ap.snapshot()
            print(json.dumps({'identity':s['identity'],'drift_digest_stable':digest(canonical(s))==digest(canonical(s2)),
                              'ssid_counts':[len(x) for x in s['ssids']],'vlan_ids':sorted(set(x['vlan_id'] for x in s['vlans'])),'backup':b._backup(s)},indent=2));return
    cid=args.approve or args.unlock or args.inspect
    if cid:
        with exclusive():
            p=b._load(cid)
            print(json.dumps({'change_id':cid,'plan_hash':p['plan_hash'],'changes':diff(canonical(p['before']),canonical(p['after'])),'expires':p['expires'],'status':p['status']},indent=2))
            if args.inspect:return
            if p['status']!='pending' or p['expires']<time.time():raise APError('Pending preview has expired')
            if args.approve:
                if not args.approval_reference.strip():raise APError('Provide a reference to the explicit human approval; never infer approval')
                private_write(ROOT/'approvals'/(cid+'.json'),{'plan_hash':p['plan_hash'],'expires':p['expires'],'reference':args.approval_reference})
                audit('operator_approval',change_id=cid,plan_hash=p['plan_hash'])
            if args.unlock:
                if not sys.stdin.isatty():raise APError('Unlock requires a local interactive terminal')
                if input('Type UNLOCK EAP610 '+cid+': ').strip()!='UNLOCK EAP610 '+cid:raise APError('Unlock refused')
                private_write(ROOT/'unlocks'/(cid+'.json'),{'plan_hash':p['plan_hash'],'expires':min(p['expires'],time.time()+180)})
                audit('operator_unlock',change_id=cid,plan_hash=p['plan_hash'])
            return
    from mcp.server.fastmcp import FastMCP
    import uvicorn
    mcp=FastMCP('EAP610 standalone guarded management',host='127.0.0.1',port=8770,stateless_http=True,json_response=True)
    register(mcp,b)
    uvicorn.run(Auth(mcp.streamable_http_app()),host='127.0.0.1',port=8770,log_level='warning')

if __name__=='__main__':main()
