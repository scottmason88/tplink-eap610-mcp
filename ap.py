"""Firmware-specific EAP610 standalone transport. No arbitrary endpoint MCP tool."""
from __future__ import annotations
import hashlib, http.client, json, pathlib, ssl, time, urllib.parse

ROOT = pathlib.Path.home() / '.config/eap610-mcp'
FIRMWARE = '1.6.30 Build 20260728 Rel. 08167(5553)'

class APError(RuntimeError): pass

class AP:
    def __init__(self):
        self.config = json.loads((ROOT/'device.json').read_text())
        self.cookie = ''
        self.login_blocked = False

    def _request(self, path, data=None, method='POST', binary=False):
        # A self-signed certificate is authenticated by its exact SHA256 pin BEFORE
        # any HTTP headers, cookies or credentials are sent. Never follow redirects.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        h = http.client.HTTPSConnection(self.config['host'], context=ctx, timeout=15)
        try:
            h.connect()
            pin = hashlib.sha256(h.sock.getpeercert(binary_form=True)).hexdigest()
            if pin != self.config['tls_sha256']:
                raise APError('AP certificate fingerprint changed; operator verification required')
            enc = urllib.parse.urlencode(data or {}, doseq=True)
            if method == 'GET' and enc: path += '?' + enc
            origin = 'https://' + self.config['host']
            h.request(method, path, enc if method=='POST' else None,
                      {'Cookie':self.cookie, 'Referer':origin+'/', 'Origin':origin,
                       'X-Requested-With':'XMLHttpRequest',
                       'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8'})
            r = h.getresponse()
            body = r.read(5_000_001)
            if r.status != 200 or len(body)>5_000_000:
                raise APError('Unexpected AP HTTP response')
            cookies = r.getheader('Set-Cookie')
            if cookies: self.cookie = cookies.split(';')[0]
            if binary:
                ct = (r.getheader('Content-Type') or '').lower()
                cd = r.getheader('Content-Disposition') or ''
                if len(body)<256 or body.lstrip().startswith((b'<',b'{')) or 'attachment' not in cd.lower():
                    raise APError('AP did not return a configuration attachment')
                return body
            return body
        except APError: raise
        except Exception as e:
            # Do not include response bodies, cookies, credentials or input data.
            raise APError('AP transport failed: '+type(e).__name__) from None
        finally: h.close()

    def _json(self, path, data=None, method='POST'):
        b = self._request(path, data, method)
        try: d = json.loads(b)
        except Exception: raise APError('AP session unavailable or non-JSON response') from None
        if not isinstance(d,dict) or d.get('success') is not True or d.get('timeout') in (True,'true'):
            raise APError('AP rejected operation or session expired')
        if d.get('errCode',0) not in (0,'0') or d.get('error',0) not in (0,'0'):
            raise APError('AP reported an operation error')
        return d.get('data')

    def login(self):
        if self.login_blocked: raise APError('Login attempt failed; operator must resolve credentials and restart service')
        cred = json.loads((ROOT/'credentials.json').read_text())
        self._request('/',{'username':cred['username'],
                          'password':hashlib.md5(cred['password'].encode()).hexdigest().upper()})
        try: self.identity()
        except Exception:
            self.login_blocked = True
            raise APError('Login or identity verification failed; no automatic retries') from None

    def identity(self):
        d = self._json('/data/status.device.json', {'operation':'read'}, 'GET')
        if d.get('mac','').replace('-',':').lower()!=self.config['mac'] or d.get('deviceModel')!='EAP610' or d.get('hardwareVersion')!=self.config['hardware']:
            raise APError('AP identity mismatch')
        if d.get('firmwareVersion') != FIRMWARE:
            raise APError('Untested AP firmware; adapter review required')
        return d

    def ensure(self):
        if not self.cookie: self.login()
        else:
            try: self.identity()
            except APError as e:
                if 'session' not in str(e).lower(): raise
                self.cookie=''; self.login()

    def snapshot(self):
        self.ensure()
        return {'identity':self.identity(),
                'radios':[self._json('/data/wireless.basic.json',{'operation':'read','radioID':i}) for i in (0,1)],
                'ssids':[self._json('/data/wireless.ssids.json',{'operation':'load','radioID':i}) for i in (0,1)],
                'vlans':self._json('/data/wireless.vlan.json',{'operation':'load'}),
                'led':self._json('/data/ledctrl.json',{'operation':'read'})}

    def clients(self):
        self.ensure()
        return self._json('/data/status.client.user.json',{'operation':'load'},'GET')

    def wireless_status(self):
        self.ensure()
        return self._json('/data/status.wireless.ssid.json',{'operation':'load'},'GET')

    def backup(self):
        self.ensure()
        return self._request('/data/configBackup.json',{'operation':'backup'},'GET',binary=True)

    def write(self, kind, before, after, target):
        # Only these three firmware request shapes are reachable from apply.
        if kind=='led':
            return self._json('/data/ledctrl.json',{'operation':'write','enable':after['led']['enable']})
        if kind=='radio':
            d=after['radios'][target['band']]
            payload={'operation':'write','radioID':target['band'],'wireless_mode':d['wirelessmode'],
                     'chan_width':d['chwidth'],'frequency':d['frequency'],'txpower':d['txpower'],
                     'channelRange':','.join(map(str,d['channelRange'])),'is_apmode':1}
            return self._json('/data/wireless.basic.json',payload)
        if kind=='ssid':
            band,index=target['band'],target['index']
            old=before['ssids'][band][index].copy();new=after['ssids'][band][index].copy()
            key=old['key'];new.pop('key',None)
            return self._json('/data/wireless.ssids.json',{'operation':'update','radioID':band,
                              'index':index,'key':key,'old':json.dumps(old,separators=(',',':')),
                              'new':json.dumps(new,separators=(',',':'))})
        if kind=='vlan':
            rows=after['vlans']; p={'operation':'save'}
            for key,field in [('ssidName','ssidname'),('band','band'),('vlan','vlan'),('vlan_id','vlan_id')]:
                p[key]='\n'.join(str(x[field]) for x in rows)
            p['ml']='\n'.join(str(x.get('ml',0)) for x in rows)
            return self._json('/data/wireless.vlan.json',p)
        raise APError('Operation not allowlisted')
