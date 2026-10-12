"""Recipient-owned narrative operations on a single independently verified TLS channel."""
import base64, json, re, sys
from datetime import datetime, timezone
from .recipient_client import recipient_channel, binary
from .verify_identity import ROOT_PATH, unique_object
MAX=8*1024*1024
FAILURE='Narrative unavailable'
def exact(v,keys):
    if not isinstance(v,dict) or set(v)!=set(keys):raise ValueError(FAILURE)
    return v
def envelope(value,tracking):
    v=exact(value,['format','trackingId','purpose','key','iv','tag','data'])
    if v['format']!='recipient-narrative:v1' or v['trackingId']!=tracking or v['purpose']!='narrative':raise ValueError(FAILURE)
    prefix='enc:kms:recipient:v1:'
    if not isinstance(v['key'],str) or not v['key'].startswith(prefix) or not binary(v['key'][len(prefix):],6144):raise ValueError(FAILURE)
    binary(v['iv'],12,True);binary(v['tag'],16,True);binary(v['data'],MAX)
    return dict(v)
def perform(request):
    exact(request,['operation','trackingId','value','port','keyArn','pcrs','credentials'])
    tracking=request['trackingId'];operation=request['operation']
    if not isinstance(tracking,str) or not re.fullmatch(r'VRA-[A-F0-9]{16}',tracking) or operation not in ['encrypt','decrypt']:raise ValueError(FAILURE)
    if type(request['port']) is not int or not 1<=request['port']<=65535 or not re.fullmatch(r'arn:aws:kms:us-east-2:000000000000:key/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',request['keyArn']):raise ValueError(FAILURE)
    pins=exact(request['pcrs'],['0','1','2']);expected={}
    for k,v in pins.items():
        if not isinstance(v,str) or not re.fullmatch(r'[a-fA-F0-9]{96}',v) or not any(bytes.fromhex(v)):raise ValueError(FAILURE)
        expected[int(k)]=bytes.fromhex(v)
    creds=exact(request['credentials'],['accessKeyId','secretAccessKey','sessionToken','expiration'])
    if any(not isinstance(v,str) or not 0<len(v)<=8192 for v in creds.values()):raise ValueError(FAILURE)
    expiry=datetime.fromisoformat(creds['expiration'].replace('Z','+00:00'))
    if expiry.tzinfo is None or expiry<=datetime.now(timezone.utc):raise ValueError(FAILURE)
    if operation=='encrypt':
        if not isinstance(request['value'],str) or not 0<len(request['value'].encode('utf8'))<=MAX:raise ValueError(FAILURE)
    else:envelope(request['value'],tracking)
    # Version/profile are part of both KMS context and native payload AAD scope.
    record='report:'+tracking+':narrative:recipient:v1'
    scope={'purpose':'narrative','record':record}
    context={'purpose':'narrative','record':record}
    with recipient_channel(request['port'],expected,ROOT_PATH.read_bytes(),creds) as (client,_):
        if operation=='encrypt':
            generated=client.call('generate',{**scope,'keyArn':request['keyArn'],'context':context})
            result=client.call('encrypt',{**scope,'handle':generated['handle'],'plaintext':base64.b64encode(request['value'].encode('utf8')).decode('ascii')})
            return envelope({'format':'recipient-narrative:v1','trackingId':tracking,'purpose':'narrative','key':generated['wrappedKey'],'iv':result['iv'],'tag':result['tag'],'data':result['ciphertext']},tracking)
        stored=request['value']
        handle=client.call('bootstrap',{**scope,'keyArn':request['keyArn'],'wrappedKey':stored['key'],'context':context})['handle']
        result=client.call('decrypt',{**scope,'handle':handle,'iv':stored['iv'],'tag':stored['tag'],'ciphertext':stored['data']})
        plaintext=bytearray(binary(result['plaintext'],MAX))
        try:return plaintext.decode('utf8',errors='strict')
        finally:plaintext[:]=bytes(len(plaintext))
def main():
    try:
        raw=sys.stdin.buffer.read(12*1024*1024+1)
        if len(raw)>12*1024*1024:raise ValueError(FAILURE)
        request=json.loads(raw,object_pairs_hook=unique_object)
        if request['operation']=='encrypt':
            plaintext=bytearray(binary(request['value'],MAX))
            try:request['value']=plaintext.decode('utf8',errors='strict')
            finally:plaintext[:]=bytes(len(plaintext))
        result=perform(request)
        if request['operation']=='decrypt':result=base64.b64encode(result.encode('utf8')).decode('ascii')
        sys.stdout.write(json.dumps({'value':result},ensure_ascii=False,separators=(',',':'),allow_nan=False));return 0
    except Exception:
        sys.stdout.write('{"error":"Narrative unavailable"}');return 1
if __name__=='__main__':raise SystemExit(main())
