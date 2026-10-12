import base64,copy,io,json,secrets,unittest
from contextlib import contextmanager
from datetime import datetime,timezone,timedelta
from unittest.mock import patch
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from . import narrative
b64=lambda x:base64.b64encode(x).decode()
class Codec:
    """Offline crypto boundary: exact native v1 AAD, no AWS/hardware claim."""
    def __init__(self):self.keys={};self.calls=[]
    def call(self,method,p):
        self.calls.append((method,p.copy()));record=p['record']
        if method=='generate':
            key=secrets.token_bytes(32);wrapped='enc:kms:recipient:v1:'+b64(secrets.token_bytes(32));self.keys[wrapped]=(key,record);return {'handle':wrapped,'wrappedKey':wrapped}
        if method=='bootstrap':
            key,bound=self.keys[p['wrappedKey']]
            if bound!=record:raise ValueError('scope')
            return {'handle':p['wrappedKey']}
        key,bound=self.keys[p['handle']]
        if bound!=record:raise ValueError('scope')
        raw=record.encode();aad=b'VERA-KEY-HANDLE-v1'+bytes([2])+len(raw).to_bytes(2,'big')+raw
        if method=='encrypt':
            iv=secrets.token_bytes(12);data=AESGCM(key).encrypt(iv,base64.b64decode(p['plaintext']),aad)
            return {'iv':b64(iv),'tag':b64(data[-16:]),'ciphertext':b64(data[:-16])}
        data=AESGCM(key).decrypt(base64.b64decode(p['iv']),base64.b64decode(p['ciphertext'])+base64.b64decode(p['tag']),aad)
        return {'plaintext':b64(data)}
class Tests(unittest.TestCase):
    def setUp(self):
        self.codec=Codec();self.sessions=0
        @contextmanager
        def channel(*args):self.sessions+=1;yield self.codec,{}
        self.patch=patch.object(narrative,'recipient_channel',channel);self.patch.start();self.addCleanup(self.patch.stop)
        self.r={'operation':'encrypt','trackingId':'VRA-1234567890ABCDEF','value':'Explicit offline narrative — preservation','port':15003,'keyArn':'arn:aws:kms:us-east-2:000000000000:key/12345678-1234-1234-1234-123456789012','pcrs':{str(i):str(i+1)*96 for i in range(3)},'credentials':{'accessKeyId':'test','secretAccessKey':'test','sessionToken':'test','expiration':(datetime.now(timezone.utc)+timedelta(minutes=10)).isoformat()}}
    def test_real_codec_roundtrip_new_session_bound_scope_no_handle(self):
        sealed=narrative.perform(self.r);self.assertNotIn(self.r['value'],json.dumps(sealed));self.assertEqual(set(sealed),{'format','trackingId','purpose','key','iv','tag','data'})
        value=narrative.perform({**self.r,'operation':'decrypt','value':sealed});self.assertEqual(value,self.r['value']);self.assertEqual(self.sessions,2)
        calls=self.codec.calls;self.assertEqual([m for m,_ in calls],['generate','encrypt','bootstrap','decrypt'])
        self.assertEqual(calls[0][1]['context'],{'purpose':'narrative','record':'report:VRA-1234567890ABCDEF:narrative:recipient:v1'})
    def test_tampering_fails_gcm_without_plaintext(self):
        sealed=narrative.perform(self.r);sealed['tag']=b64(bytes(16))
        with self.assertRaises(Exception):narrative.perform({**self.r,'operation':'decrypt','value':sealed})
    def test_cross_report_rebinding_fails(self):
        sealed=narrative.perform(self.r);sealed['trackingId']='VRA-AAAAAAAAAAAAAAAA'
        with self.assertRaises(ValueError):narrative.perform({**self.r,'trackingId':sealed['trackingId'],'operation':'decrypt','value':sealed})
    def test_unknown_profile_legacy_extra_and_wrong_purpose_fail_before_channel(self):
        sealed=narrative.perform(self.r)
        for delta in [{'format':'legacy'},{'purpose':'evidence'},{'salt':'unexpected'},{'key':'enc:kms:v2:YWJj'},{'trackingId':'VRA-AAAAAAAAAAAAAAAA'}]:
            before=self.sessions
            with self.assertRaises(ValueError):narrative.perform({**self.r,'operation':'decrypt','value':{**sealed,**delta}})
            self.assertEqual(self.sessions,before)
    def test_invalid_configuration_never_calls_channel(self):
        for delta in [{'trackingId':'internal'},{'port':0},{'pcrs':{'0':'0'*96,'1':'1'*96,'2':'2'*96}},{'credentials':{**self.r['credentials'],'expiration':'2000-01-01T00:00:00Z'}}]:
            with self.assertRaises(ValueError):narrative.perform({**self.r,**delta})
        self.assertEqual(self.sessions,0)
    def test_private_pipe_roundtrip_at_limit_avoids_json_escape_expansion(self):
        value='\x00'*narrative.MAX
        def invoke(request):
            stdin=io.TextIOWrapper(io.BytesIO(json.dumps(request).encode()))
            stdout=io.StringIO()
            with patch.object(narrative.sys,'stdin',stdin),patch.object(narrative.sys,'stdout',stdout):
                self.assertEqual(narrative.main(),0)
            raw=stdout.getvalue();self.assertLess(len(raw.encode()),12*1024*1024)
            return json.loads(raw)['value']
        sealed=invoke({**self.r,'value':b64(value.encode())})
        restored=invoke({**self.r,'operation':'decrypt','value':sealed})
        self.assertEqual(base64.b64decode(restored).decode(),value)

    def test_provider_failure_not_retried(self):
        self.codec.call=unittest.mock.Mock(side_effect=ValueError('sensitive-provider-error'))
        with self.assertRaises(ValueError):narrative.perform(self.r)
        self.assertEqual(self.codec.call.call_count,1)
if __name__=='__main__':unittest.main()
