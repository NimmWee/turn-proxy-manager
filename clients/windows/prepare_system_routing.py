"""Compile pinned public routing data. Never run downloaded programs/scripts."""
from pathlib import Path
import hashlib, io, json, sys, tarfile, urllib.request, zipfile
from routing_geoip import compile_geoip

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
lock=json.loads((HERE/'routing-data.lock.json').read_text())
if sys.argv[1:] == ['--check']:
    for name, expected in lock['compiled'].items():
        path=HERE/'engine/routingdata'/name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
            raise SystemExit('Compiled routing data checksum mismatch: '+name)
    print('Pinned routing catalog/licenses/source archive verified; no network changes.')
    raise SystemExit(0)
if sys.argv[1:]:raise SystemExit('Usage: prepare_system_routing.py [--check]')
cache=ROOT/'.references/system-routing-assets'
cache.mkdir(parents=True,exist_ok=True)
def source(name):
    item=lock['sources'][name];path=cache/item['cacheFile']
    request=urllib.request.Request(item['url'],headers={'User-Agent':'FreeTurnManager-routing-build/0.20'})
    data=path.read_bytes() if path.exists() else urllib.request.urlopen(request,timeout=40).read(32*1024*1024+1)
    if len(data)>32*1024*1024 or hashlib.sha256(data).hexdigest()!=item['sha256']:raise SystemExit('Routing source checksum mismatch: '+name)
    if not path.exists():path.write_bytes(data)
    return data

data=source('v2fly');files={}
with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
    for member in archive:
        if not member.isfile():continue
        relative='/'.join(member.name.split('/')[1:])
        if '..' in relative.split('/') or relative.startswith('/') or '\\' in relative:raise SystemExit('Unsafe source path')
        if relative.startswith('data/') or relative=='LICENSE':files[relative]=archive.extractfile(member).read()
used={'LICENSE':files['LICENSE']}

def compile_list(root):
    result={kind:set() for kind in ('suffix','exact','regex','keyword')}
    def visit(name,filters=(),chain=()):
        if name in chain or len(chain)>32:raise SystemExit('Routing include cycle')
        path='data/'+name
        if path not in files:raise SystemExit('Unknown routing list: '+name)
        used[path]=files[path]
        for line in files[path].decode().splitlines():
            tokens=line.split('#',1)[0].strip().split()
            if not tokens:continue
            entry=tokens[0];attrs=set(tokens[1:])
            if entry.startswith('include:'):
                visit(entry[8:],filters+tuple(tokens[1:]),chain+(name,));continue
            if any(tag not in attrs for tag in filters):continue
            kind,value=entry.split(':',1) if ':' in entry else ('domain',entry)
            mapping={'domain':'suffix','full':'exact','regexp':'regex','keyword':'keyword'}
            if kind not in mapping:raise SystemExit('Unknown routing entry type')
            if kind in ('domain','full'):value=value.encode('idna').decode('ascii').lower().rstrip('.')
            result[mapping[kind]].add(value)
    visit(root)
    return {k:sorted(v) for k,v in result.items()}

ru=compile_list('category-ru');youtube=compile_list('youtube');push=compile_list('googlefcm');connectivity=compile_list('connectivity-check')
ru['suffix']=sorted(set(ru['suffix'])|{'ru','su','xn--p1ai'})
# Apple documents *.push.apple.com for APNs. Keep the addition narrowly scoped.
push['suffix']=sorted(set(push['suffix'])|{'push.apple.com','courier-push-apple.com.akadns.net'})
ipdata=source('dbipCountry');iplicense=source('geoIPLicense')
prefixes=compile_geoip(ipdata,lock['sources']['dbipCountry'])
geoip={**lock['geoIP'],'sourceSHA256':lock['sources']['dbipCountry']['sha256'],'ipv4Prefixes':len(prefixes)}
document={'v':1,'ru':ru,'youtube':youtube,'push':push,'connectivity':connectivity,'ruPrefixes':prefixes,'sources':{k:v['sha256'] for k,v in lock['sources'].items()},'countryAddressMeaning':'IP geolocation estimate, not precise physical location','geoIP':geoip}
contents=(json.dumps(document,ensure_ascii=True,separators=(',',':'))+'\n').encode()
attribution=f"IP Geolocation by DB-IP — https://db-ip.com/\nDB-IP Lite {geoip['release']} — CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/\nModified by FreeTurn Manager: selected RU IPv4 ranges, converted/merged into CIDR prefixes; IPv6 omitted.\nSource: {lock['sources']['dbipCountry']['url']}\nSource SHA256: {geoip['sourceSHA256']}\nGeolocation is approximate; coverage and accuracy are limited. No warranty of physical location.\n"
license_text='V2Fly domain-list-community — MIT\n'+files['LICENSE'].decode()+'\n'+attribution+'\n'+iplicense.decode()+'\nApple APNs host reference: https://support.apple.com/en-us/101555\n'
archive_bytes=io.BytesIO()
with zipfile.ZipFile(archive_bytes,'w',zipfile.ZIP_DEFLATED) as bundle:
    sources={**{'v2fly/'+name:value for name,value in used.items()},'db-ip/dbip-country-lite-'+geoip['release']+'.csv.gz':ipdata,'db-ip/CC-BY-4.0.txt':iplicense,'db-ip/ATTRIBUTION.txt':attribution.encode()}
    for name,payload in sorted(sources.items()):
        info=zipfile.ZipInfo(name,(2026,11,17,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;bundle.writestr(info,payload)
output=HERE/'engine/routingdata';output.mkdir(parents=True,exist_ok=True)
# Validate and assemble every input before replacing any compiled output.
for name,payload in {'catalog.json':contents,'LICENSES.txt':license_text.encode('utf-8'),'sources.zip':archive_bytes.getvalue()}.items():
    temporary=output/(name+'.tmp');temporary.write_bytes(payload);temporary.replace(output/name)
print(json.dumps({'ruSuffix':len(ru['suffix']),'ruExact':len(ru['exact']),'ruRegex':len(ru['regex']),'ruPrefixes':len(prefixes),'sourceFiles':len(used)+3,'catalogSHA256':hashlib.sha256(contents).hexdigest()}))
