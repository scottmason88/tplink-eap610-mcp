import copy,json,pathlib,tempfile,time,unittest
from unittest.mock import patch,MagicMock
import server
from ap import AP,APError
from eap_tools import SSIDChange, RadioChange, VLANChange

def snapshot():
    radio={'status':'on','wirelessmode':13,'chwidth':4,'frequency':0,'txpower':25,'radioID':0,'minPower':4,'regionCode':841,'channelRange':[2412,2437,2462]}
    ssid={'ssidname':'Main','ssidbcast':1,'vlanid':0,'key':'0','securityMode':3,'psk_key':'preserved-secret'}
    return {'identity':{'mac':'AA-BB-CC-DD-EE-FF'},'radios':[radio,{**radio,'radioID':1,'channelRange':[5180,5200]}],
            'ssids':[[ssid],[copy.deepcopy(ssid)]],'vlans':[{'ssidname':'Main','band':0,'vlan':0,'vlan_id':0},{'ssidname':'Main','band':1,'vlan':0,'vlan_id':0}],
            'led':{'enable':'off'}}

class FakeAP:
    def __init__(self):self.state=snapshot();self.writes=0
    def snapshot(self):return copy.deepcopy(self.state)
    def backup(self):return b'configuration-backup'*100
    def write(self,kind,before,after,target):self.writes+=1;self.state=copy.deepcopy(after)

class Safety(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name)
        self.patch=patch.object(server,'ROOT',self.root);self.patch.start();self.ap=FakeAP();self.b=server.Backend(self.ap)
    def tearDown(self):self.patch.stop();self.tmp.cleanup()
    def approve(self,p,unlock=False):
        q=self.b._load(p['change_id']);r={'plan_hash':q['plan_hash'],'expires':q['expires']}
        server.private_write(self.root/'approvals'/(q['id']+'.json'),r)
        if unlock:server.private_write(self.root/'unlocks'/(q['id']+'.json'),r)
    def apply(self,p):return self.b.apply(p['change_id'],p['apply_confirmation'])
    def test_no_self_approval_or_unlock(self):
        p=self.b.preview_led(True)
        with self.assertRaisesRegex(APError,'approval missing'):self.apply(p)
        self.assertEqual(self.ap.writes,0)
        with self.assertRaises(APError):self.b.call('approve',{})
    def test_wireless_requires_unlock(self):
        p=self.b.preview_radio({'band':0,'channel':1});self.approve(p)
        with self.assertRaisesRegex(APError,'unlock required'):self.apply(p)
        self.assertEqual(self.ap.writes,0)
    def test_exact_apply_and_rollback(self):
        p=self.b.preview_led(True);self.approve(p);self.assertEqual(self.apply(p)['status'],'verified')
        with self.assertRaises(APError):self.apply(p)
        r=self.b.preview_rollback(p['change_id']);self.approve(r);self.apply(r)
        self.assertEqual(self.ap.state['led']['enable'],'off');self.assertEqual(self.ap.writes,2)
    def test_drift_and_expiry_rejected(self):
        p=self.b.preview_led(True);self.approve(p);self.ap.state['radios'][0]['txpower']=20
        with self.assertRaisesRegex(APError,'drifted'):self.apply(p)
        self.assertEqual(self.ap.writes,0)
        with patch.object(server.time,'time',return_value=time.time()+400):
            with self.assertRaisesRegex(APError,'expired'):self.apply(p)
    def test_backup_failure_blocks_write(self):
        p=self.b.preview_led(True);self.approve(p)
        with patch.object(self.ap,'backup',side_effect=APError('Backup failed')):
            with self.assertRaises(APError):self.apply(p)
        self.assertEqual(self.ap.writes,0)
    def test_uncertain_write_never_retried(self):
        p=self.b.preview_led(True);self.approve(p)
        with patch.object(self.ap,'write',side_effect=APError('Disconnected')) as w:
            with self.assertRaisesRegex(APError,'uncertain'):self.apply(p)
            with self.assertRaisesRegex(APError,'consumed'):self.apply(p)
            self.assertEqual(w.call_count,1)
    def test_typed_allowlist_and_redaction(self):
        for cls,data in [(SSIDChange,{'band':0,'index':0,'password':'bad'}),(VLANChange,{'band':0,'ssid':'Main','vlan':99}),(RadioChange,{'band':0,'channel':'1'})]:
            with self.assertRaises(ValueError):cls.model_validate(data)
        with self.assertRaises(APError):self.b.preview_radio({'band':0,'channel':36})
        p=self.b.preview_ssid({'band':0,'index':0,'name':'New'})
        self.assertNotIn('preserved-secret',json.dumps(p))
        q=self.b._load(p['change_id']);self.assertEqual(q['after']['ssids'][0][0]['psk_key'],'preserved-secret')
        self.assertEqual(server.clean(snapshot())['ssids'][0][0]['psk_key'],'[redacted]')
    def test_certificate_rejected_before_credentials_sent(self):
        ap=object.__new__(AP);ap.config={'host':'192.0.2.3','tls_sha256':'0'*64};ap.cookie='private-cookie'
        h=MagicMock();h.sock.getpeercert.return_value=b'wrong-certificate'
        with patch('ap.http.client.HTTPSConnection',return_value=h):
            with self.assertRaisesRegex(APError,'fingerprint'):ap._request('/',{'password':'secret'})
        h.request.assert_not_called()

if __name__=='__main__':unittest.main()
