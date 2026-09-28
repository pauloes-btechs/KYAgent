"""Parse the OFAC SDN XML into a compact JSON snapshot and inject it into the console page."""
import re, sys, json, xml.etree.ElementTree as ET
src, tpl, out = sys.argv[1], sys.argv[2], sys.argv[3]
tree = ET.parse(src); root = tree.getroot()
for el in root.iter():
    if isinstance(el.tag, str) and '}' in el.tag: el.tag = el.tag.split('}', 1)[1]
pub = root.find('publshInformation')
date = (pub.findtext('Publish_Date') or '').strip() if pub is not None else ''
TYPES = {'Entity': 'E', 'Individual': 'I', 'Vessel': 'V', 'Aircraft': 'A'}
entries, wallets = [], {}
HEX = re.compile(r'^0x[0-9a-fA-F]{40}$')
def norm_addr(a):
    a = a.strip()
    if HEX.match(a) or a.lower().startswith(('bc1', 'ltc1', 'tb1')): return a.lower()
    return a
for e in root.findall('sdnEntry'):
    uid = int(e.findtext('uid'))
    fn = (e.findtext('firstName') or '').strip(); ln = (e.findtext('lastName') or '').strip()
    name = (fn + ' ' + ln).strip() if fn else ln
    t = TYPES.get((e.findtext('sdnType') or '').strip(), 'E')
    progs = [p.text.strip() for p in e.findall('programList/program') if p.text]
    akas = []
    for a in e.findall('akaList/aka'):
        afn = (a.findtext('firstName') or '').strip(); aln = (a.findtext('lastName') or '').strip()
        n = (afn + ' ' + aln).strip() if afn else aln
        if n and n != name and n not in akas: akas.append(n)
    idx = len(entries)
    entries.append([uid, name, t, ' '.join(progs), akas])
    for i in e.findall('idList/id'):
        it = (i.findtext('idType') or '').strip()
        if it.startswith('Digital Currency Address'):
            asset = it.split('-')[-1].strip()
            addr = (i.findtext('idNumber') or '').strip()
            if addr: wallets.setdefault(norm_addr(addr), [idx, asset])
data = {'publishDate': date, 'entryCount': len(entries), 'walletCount': len(wallets), 'entries': entries, 'wallets': wallets}
blob = json.dumps(data, separators=(',', ':'), ensure_ascii=False).replace('</', '<\\/')
page = open(tpl, encoding='utf-8').read().replace('/*__SDN_DATA__*/null', blob)
open(out, 'w', encoding='utf-8').write(page)
assets = {}
for a, (i, asset) in wallets.items(): assets[asset] = assets.get(asset, 0) + 1
print(json.dumps({'publishDate': date, 'entries': len(entries), 'wallets': len(wallets), 'assets': assets, 'bytes': len(blob)}))
