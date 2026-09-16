#!/usr/bin/env python3
import asyncio, base64, hashlib, json, os, re, socket, subprocess, tempfile, time, urllib.parse, urllib.request
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

UA = 'romlik-speed-selector/1.0'
PROTOS = ('vless://','vmess://','trojan://','ss://')
TEST_URL = os.environ.get('SPEED_TEST_URL','https://speed.cloudflare.com/__down?bytes=3000000')
TOP_N = int(os.environ.get('TOP_N','20'))
TCP_KEEP = int(os.environ.get('TCP_KEEP','250'))
XRAY_TEST_KEEP = int(os.environ.get('XRAY_TEST_KEEP','80'))
CONCURRENCY = int(os.environ.get('CONCURRENCY','150'))

@dataclass
class Node:
    uri: str
    protocol: str
    host: str
    port: int
    source: str
    pool: str
    remark: str=''
    tcp_ms: Optional[float]=None
    latency_ms: Optional[float]=None
    mbps: Optional[float]=None
    score: Optional[float]=None
    ok: bool=False
    error: str=''

    def key(self):
        raw = self.uri.split('#',1)[0]
        return hashlib.sha256(raw.encode()).hexdigest()


def b64decode(s:str)->str:
    s=s.strip().replace('\n','').replace('\r','')
    s += '='*((4-len(s)%4)%4)
    for fn in (base64.urlsafe_b64decode, base64.b64decode):
        try: return fn(s).decode('utf-8','ignore')
        except Exception: pass
    return ''


def parse_uri(uri, source, pool):
    uri=uri.strip()
    try:
        if uri.startswith('vmess://'):
            d=json.loads(b64decode(uri[8:].split('#')[0]))
            return Node(uri,'vmess',str(d.get('add','')),int(d.get('port',0)),source,pool,str(d.get('ps','')))
        p=urllib.parse.urlparse(uri)
        if p.scheme in ('vless','trojan') and p.hostname and p.port:
            return Node(uri,p.scheme,p.hostname,p.port,source,pool,urllib.parse.unquote(p.fragment or ''))
        if p.scheme=='ss':
            if p.hostname and p.port:
                return Node(uri,'ss',p.hostname,p.port,source,pool,urllib.parse.unquote(p.fragment or ''))
            raw=uri[5:].split('#')[0]
            dec=b64decode(raw)
            if '@' in dec:
                hp=dec.rsplit('@',1)[1]
                h,po=hp.rsplit(':',1)
                return Node(uri,'ss',h,int(po),source,pool)
    except Exception:
        return None
    return None


def extract(text, source, pool):
    if not any(x in text for x in PROTOS):
        d=b64decode(text)
        if any(x in d for x in PROTOS): text=d
    out=[]
    for line in re.split(r'[\r\n]+',text):
        line=line.strip()
        if not line: continue
        n=parse_uri(line,source,pool)
        if n and n.host and n.port: out.append(n)
    return out


def fetch(url, timeout=25):
    req=urllib.request.Request(url,headers={'User-Agent':UA})
    with urllib.request.urlopen(req,timeout=timeout) as r:
        return r.read().decode('utf-8','ignore')


def load_sources():
    cfg=json.loads(Path('sources.json').read_text())
    nodes=[]
    for pool in ('normal','whitelist'):
        for src in cfg.get(pool,[]): 
            try:
                txt=fetch(src['url'])
                got=extract(txt,src['name'],pool)
                print(f"source {src['name']}: {len(got)}")
                nodes.extend(got)
            except Exception as e:
                print(f"source {src['name']} failed: {e}")
    ded={}
    for n in nodes: ded.setdefault(n.key(),n)
    return list(ded.values())


async def tcp_probe(n, sem):
    async with sem:
        st=time.perf_counter()
        try:
            r,w=await asyncio.wait_for(asyncio.open_connection(n.host,n.port),2.2)
            n.tcp_ms=(time.perf_counter()-st)*1000
            w.close()
            try: await w.wait_closed()
            except Exception: pass
            return True
        except Exception as e:
            n.error=f'tcp:{type(e).__name__}'
            return False


def qdict(uri):
    p=urllib.parse.urlparse(uri)
    return p, {k:(v[0] if v else '') for k,v in urllib.parse.parse_qs(p.query.replace('&amp;','&')).items()}


def stream_settings(q):
    net=q.get('type','tcp') or 'tcp'
    sec=q.get('security','none') or 'none'
    s={'network':net,'security':sec}
    if sec=='tls':
        s['tlsSettings']={'serverName':q.get('sni') or q.get('serverName') or '', 'allowInsecure': True}
    elif sec=='reality':
        s['realitySettings']={'serverName':q.get('sni',''),'fingerprint':q.get('fp','chrome'),'publicKey':q.get('pbk',''),'shortId':q.get('sid',''),'spiderX':q.get('spx','') or '/'}
    if net=='ws':
        s['wsSettings']={'path':q.get('path','/'),'headers':{'Host':q.get('host','')}}
    elif net=='grpc':
        s['grpcSettings']={'serviceName':q.get('serviceName') or q.get('service') or ''}
    return s


def outbound(n):
    if n.protocol in ('vless','trojan'):
        p,q=qdict(n.uri)
        if n.protocol=='vless':
            user={'id':urllib.parse.unquote(p.username or ''),'encryption':q.get('encryption','none') or 'none'}
            if q.get('flow'): user['flow']=q['flow']
            settings={'vnext':[{'address':p.hostname,'port':p.port,'users':[user]}]}
        else:
            settings={'servers':[{'address':p.hostname,'port':p.port,'password':urllib.parse.unquote(p.username or '')}]}
        return {'protocol':n.protocol,'settings':settings,'streamSettings':stream_settings(q)}
    if n.protocol=='vmess':
        d=json.loads(b64decode(n.uri[8:].split('#')[0]))
        user={'id':str(d.get('id','')),'alterId':int(d.get('aid',0) or 0),'security':d.get('scy','auto') or 'auto'}
        q={'type':d.get('net','tcp'),'security':d.get('tls','none'),'sni':d.get('sni',''),'host':d.get('host',''),'path':d.get('path','/')}
        return {'protocol':'vmess','settings':{'vnext':[{'address':str(d.get('add','')),'port':int(d.get('port',0)),'users':[user]}]},'streamSettings':stream_settings(q)}
    if n.protocol=='ss':
        p=urllib.parse.urlparse(n.uri)
        if p.hostname and p.port and p.username:
            user=urllib.parse.unquote(p.username)
            try:
                dec=b64decode(user)
                if ':' in dec: user=dec
            except Exception:
                pass
            method,password=user.split(':',1)
            return {'protocol':'shadowsocks','settings':{'servers':[{'address':p.hostname,'port':p.port,'method':method,'password':password}]}}
    raise ValueError('unsupported')


def test_with_xray(n, idx):
    port=20000 + (idx % 20000)
    cfg={'log':{'loglevel':'warning'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'socks','settings':{'udp':False}}], 'outbounds':[outbound(n)]}
    with tempfile.TemporaryDirectory() as td:
        fp=Path(td)/'x.json'; fp.write_text(json.dumps(cfg))
        proc=subprocess.Popen(['xray','run','-c',str(fp)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            time.sleep(.18)
            cmd=['curl','-L','--silent','--show-error','--fail','--max-time','9','--connect-timeout','4','--socks5-hostname',f'127.0.0.1:{port}','-o',os.devnull,'-w','%{time_starttransfer} %{speed_download}',TEST_URL]
            cp=subprocess.run(cmd,capture_output=True,text=True,timeout=11)
            if cp.returncode!=0: raise RuntimeError(cp.stderr.strip()[:120])
            ttfb,spd=cp.stdout.strip().split()[:2]
            n.latency_ms=float(ttfb)*1000
            n.mbps=float(spd)*8/1_000_000
            n.score=round(n.mbps*1000/(n.latency_ms+80),3)
            n.ok=n.mbps>0
            return n.ok
        except Exception as e:
            n.error=f'xray:{type(e).__name__}'
            return False
        finally:
            proc.terminate()
            try: proc.wait(timeout=1)
            except Exception: proc.kill()


def decorate(n, rank):
    p=urllib.parse.urlsplit(n.uri)
    label=f"#{rank:02d} {n.pool} | {n.mbps:.1f}Mbps | {n.latency_ms:.0f}ms | {n.source}"
    return urllib.parse.urlunsplit((p.scheme,p.netloc,p.path,p.query,urllib.parse.quote(label,safe=' |:.#'))) if p.scheme!='vmess' else n.uri


def save(nodes):
    Path('out').mkdir(exist_ok=True)
    for pool in ('normal','whitelist'):
        arr=[n for n in nodes if n.ok and n.pool==pool]
        arr.sort(key=lambda x:(x.score or 0,x.mbps or 0,-(x.latency_ms or 9999)),reverse=True)
        arr=arr[:TOP_N]
        uris=[decorate(n,i+1) for i,n in enumerate(arr)]
        Path(f'out/{pool}.txt').write_text('\n'.join(uris)+'\n')
        Path(f'out/{pool}.b64').write_text(base64.b64encode(('\n'.join(uris)+'\n').encode()).decode())
        Path(f'out/{pool}.json').write_text(json.dumps([asdict(n) for n in arr],ensure_ascii=False,indent=2))
    all_ok=[n for n in nodes if n.ok]
    all_ok.sort(key=lambda x:(x.score or 0,x.mbps or 0),reverse=True)
    Path('out/status.json').write_text(json.dumps({'updated_at':int(time.time()),'tested':len(nodes),'working':len(all_ok),'top':[asdict(n) for n in all_ok[:30]]},ensure_ascii=False,indent=2))


async def main():
    nodes=load_sources()
    print('unique',len(nodes))
    sem=asyncio.Semaphore(CONCURRENCY)
    good=[]
    tasks=[asyncio.create_task(tcp_probe(n,sem)) for n in nodes]
    rs=await asyncio.gather(*tasks)
    for n,ok in zip(nodes,rs):
        if ok: good.append(n)
    good.sort(key=lambda n:n.tcp_ms or 999999)
    cand=[]
    for pool in ('normal','whitelist'):
        cand += [n for n in good if n.pool==pool][:TCP_KEEP]
    print('tcp candidates',len(cand))
    tested=[]
    for pool in ('normal','whitelist'):
        subset=[n for n in cand if n.pool==pool][:XRAY_TEST_KEEP]
        for i in range(0,len(subset),8):
            batch=subset[i:i+8]
            await asyncio.gather(*[asyncio.to_thread(test_with_xray,n,i+j+(0 if pool=='normal' else 1000)) for j,n in enumerate(batch)])
            tested.extend(batch)
            print(pool, i+len(batch),'/',len(subset),'working',sum(1 for n in tested if n.ok and n.pool==pool))
    save(tested)

if __name__=='__main__':
    asyncio.run(main())
