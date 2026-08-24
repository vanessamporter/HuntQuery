'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const NQT=require('../translator-core.js');

function tx(input,target){const r=NQT.translate(input,[target]);assert.equal(r.parsed.errors.length,0,`unexpected errors: ${r.parsed.errors}`);return r.outputs[target];}

test('validates empty input',()=>{assert.match(NQT.parse('   ').errors[0],/Enter a network hunting request/);});
test('rejects oversized input with actionable length guidance',()=>{const e=NQT.parse('a'.repeat(NQT.MAX_INPUT+1)).errors[0];assert.match(e,/4097 characters long/);assert.match(e,/maximum is 4096/);assert.match(e,/shorten it by 1 character/);});
test('rejects control characters',()=>{assert.match(NQT.parse('dns\u0000 traffic').errors[0],/control characters/i);});
test('rejects invalid IPv4 with octet guidance',()=>{const e=NQT.parse('traffic from 999.1.1.1').errors[0];assert.match(e,/Invalid IPv4/);assert.match(e,/between 0 and 255/);assert.match(e,/found 999/);});
test('rejects invalid CIDR with prefix guidance',()=>{const e=NQT.parse('traffic from 10.0.0.0/99').errors[0];assert.match(e,/Invalid CIDR prefix/);assert.match(e,/between \/0 and \/32/);});
test('rejects invalid port with valid range',()=>{const e=NQT.parse('show traffic to port 70000').errors[0];assert.match(e,/Invalid port: 70000/);assert.match(e,/0 through 65535/);});
test('rejects invalid HTTP status with valid range',()=>{const e=NQT.parse('show http status 999').errors[0];assert.match(e,/Invalid HTTP status code: 999/);assert.match(e,/between 100 and 599/);});


test('empty input suggests a concrete example',()=>{assert.match(NQT.parse('   ').errors[0],/Example: show DNS traffic from 10\.0\.0\.5/);});
test('control character error tells user how to recover',()=>{assert.match(NQT.parse('dns\u0000 traffic').errors[0],/Remove them and try again/);});
test('no-recognized-fields error suggests supported concepts',()=>{const e=NQT.parse('find suspicious stuff').errors.join(' ');assert.match(e,/could not recognize enough/i);assert.match(e,/DNS, TLS, or SMB/);});

test('Arkime source IP and destination port',()=>{const out=tx('show traffic from 192.168.1.25 to port 443','arkime');assert.match(out,/ip\.src == 192\.168\.1\.25/);assert.match(out,/port\.dst == 443/);});
test('Malcolm DQL DNS search',()=>{const out=tx('find DNS queries containing microsoft from 10.20.0.5','dql');assert.match(out,/source\.ip:10\.20\.0\.5/);assert.match(out,/dns\.host:\*microsoft\*/);});
test('Malcolm Lucene uses uppercase AND',()=>{const out=tx('show dns traffic from 10.0.0.5 to 8.8.8.8','lucene');assert.match(out,/ AND /);});
test('Wireshark display filter',()=>{const out=tx('show traffic from 10.0.0.5 to port 53','wireshark');assert.match(out,/ip\.src == 10\.0\.0\.5/);assert.match(out,/tcp\.dstport == 53/);assert.match(out,/udp\.dstport == 53/);});
test('Splunk transport protocol mapping',()=>{assert.match(tx('show tcp traffic from 10.0.0.5','splunk'),/transport=tcp/);});
test('Splunk application protocol is clearly app field placeholder',()=>{assert.match(tx('show dns traffic from 10.0.0.5','splunk'),/app=dns/);});
test('Security Onion basic ECS query',()=>{const out=tx('show dns traffic from 10.0.0.5','securityonion');assert.match(out,/source\.ip:10\.0\.0\.5/);assert.match(out,/network\.protocol:dns/);});
test('Zeek chooses dns.log',()=>{assert.match(tx('show dns traffic from 10.0.0.5','zeek'),/dns\.log$/);});
test('Suricata uses eve.json',()=>{assert.match(tx('show Suricata alerts from 10.0.0.5','suricata'),/eve\.json$/);});
test('time phrase is separated from query',()=>{const r=NQT.translate('show dns traffic from 10.0.0.5 in the last 24 hours',['arkime']);assert.equal(r.parsed.time.label,'Last 24 hours');assert.doesNotMatch(r.outputs.arkime,/24/);});
test('CIDR is retained where natively supported',()=>{assert.match(tx('show traffic from 10.20.0.0/16','arkime'),/10\.20\.0\.0\/16/);assert.match(tx('show traffic from 10.20.0.0/16','wireshark'),/10\.20\.0\.0\/16/);});
test('CIDR is omitted with warning in Zeek jq',()=>{const r=NQT.translate('show traffic from 10.20.0.0/16',['zeek']);assert.doesNotMatch(r.outputs.zeek,/10\.20\.0\.0\/16/);assert.ok(NQT.warningsFor(r.parsed,'zeek').some(x=>/CIDR matching is omitted/.test(x)));});
test('CIDR is omitted with warning in Suricata jq',()=>{const r=NQT.translate('show traffic from 10.20.0.0/16',['suricata']);assert.doesNotMatch(r.outputs.suricata,/10\.20\.0\.0\/16/);assert.ok(NQT.warningsFor(r.parsed,'suricata').some(x=>/CIDR matching is omitted/.test(x)));});

test('shellQuote prevents single-quote shell breakout',()=>{const payload="x'; touch /tmp/pwn; echo '";const quoted=NQT.shellQuote(payload);assert.ok(quoted.startsWith("'"));assert.ok(quoted.endsWith("'"));assert.match(quoted,/'"'"'/);});
test('Suricata jq compiler shell-quotes malicious signature content',()=>{const parsed={conds:[{field:'alert_signature',op:'contains',value:"x'; touch /tmp/pwn; #"}],warnings:[],errors:[],notes:[],time:null};const out=NQT.compile(parsed,'suricata');assert.match(out,/'"'"'/);assert.doesNotMatch(out,/jq -c 'select\([^\n]*x'; touch/);});

test('multi-target translation returns each selected target',()=>{const r=NQT.translate('show dns traffic from 10.0.0.5',['arkime','dql','wireshark']);assert.deepEqual(Object.keys(r.outputs),['arkime','dql','wireshark']);assert.ok(r.outputs.arkime&&r.outputs.dql&&r.outputs.wireshark);});

test('browser UI source does not use dangerous innerHTML/eval/new Function',()=>{const root=path.resolve(__dirname,'..');const app=fs.readFileSync(path.join(root,'app.js'),'utf8');const html=fs.readFileSync(path.join(root,'index.html'),'utf8');assert.doesNotMatch(app,/\.innerHTML\s*=/);assert.doesNotMatch(app,/\beval\s*\(/);assert.doesNotMatch(app,/new\s+Function\s*\(/);assert.match(html,/Content-Security-Policy/);assert.match(html,/connect-src 'none'/);});
test('UI has multi-select target dropdown and copy-all control',()=>{const root=path.resolve(__dirname,'..');const app=fs.readFileSync(path.join(root,'app.js'),'utf8');const html=fs.readFileSync(path.join(root,'index.html'),'utf8');assert.match(app,/type='checkbox'/);assert.match(html,/id="targetTrigger"/);assert.match(html,/id="targetMenu"/);assert.match(html,/aria-expanded="false"/);assert.match(html,/id="selectAll"/);assert.match(html,/id="copyAll"/);});

test('UI has clickable examples and quick-clear control', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
  const app = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');
  assert.match(html, /id="examples"/);
  assert.match(html, /id="clearInline"/);
  assert.match(app, /\.examples button/);
  assert.match(app, /updateClearButton/);
});

test('example clicks populate input without auto-running translation', () => {
  const app = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');
  const exampleHandler = app.match(/document\.querySelectorAll\('\.examples button'\)[\s\S]*?updateClearButton\(\);/);
  assert.ok(exampleHandler, 'example click handler should exist');
  assert.doesNotMatch(exampleHandler[0], /run\(\)/);
});

test('UI no-target error tells the user where to fix the selection',()=>{
  const app=fs.readFileSync(path.join(__dirname,'..','app.js'),'utf8');
  assert.match(app,/Open the Output targets dropdown and choose at least one tool/);
});



test('plain hostname is recognized as a DNS hostname',()=>{
  const r=NQT.translate('hostname is server.example.com',['arkime','dql','wireshark']);
  assert.equal(r.parsed.errors.length,0);
  assert.ok(r.parsed.conds.some(c=>c.field==='dns_host'&&c.value==='server.example.com'));
  assert.match(r.outputs.arkime,/host\.dns == server\.example\.com/);
  assert.match(r.outputs.dql,/dns\.host:server\.example\.com/);
  assert.match(r.outputs.wireshark,/dns\.qry\.name == "server\.example\.com"/);
});

test('hostname without the word is is recognized',()=>{
  const r=NQT.parse('show hostname server.example.com');
  assert.equal(r.errors.length,0);
  assert.ok(r.conds.some(c=>c.field==='dns_host'&&c.value==='server.example.com'));
});

test('hostname contains creates a wildcard hostname condition',()=>{
  const r=NQT.parse('hostname contains microsoft');
  const c=r.conds.find(c=>c.field==='dns_host');
  assert.ok(c);
  assert.equal(c.value,'*microsoft*');
  assert.equal(c.wildcard,true);
});

test('Enter translates while Shift+Enter remains available for a newline',()=>{
  const app=fs.readFileSync(path.join(__dirname,'..','app.js'),'utf8');
  assert.match(app,/e\.key==='Enter'\|\|e\.code==='NumpadEnter'/);
  assert.match(app,/e\.preventDefault\(\)/);
  assert.match(app,/submitTranslation\(\)/);
  const html=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');
  assert.match(html,/Enter to translate/);
  assert.match(html,/Shift\+Enter for a new line/);
  assert.match(html,/id="translationForm"/);
  assert.match(html,/id="translate" type="submit"/);
});

test('translation form submission is guarded and displays unexpected errors',()=>{
  const app=fs.readFileSync(path.join(__dirname,'..','app.js'),'utf8');
  assert.match(app,/translationForm.*addEventListener\('submit'/);
  assert.match(app,/try\{run\(\);\}/);
  assert.match(app,/Translation could not be completed because of an unexpected error/);
});

test('Arkime syntax can be translated to Malcolm DQL',()=>{
  const r=NQT.translate('ip.src == 10.0.0.5 && port.dst == 443',['dql']);
  assert.equal(r.parsed.errors.length,0);
  assert.equal(r.parsed.sourceTarget,'arkime');
  assert.match(r.outputs.dql,/source\.ip:10\.0\.0\.5/);
  assert.match(r.outputs.dql,/destination\.port:443/);
});

test('Malcolm DQL syntax can be translated to Arkime',()=>{
  const r=NQT.translate('source.ip:10.0.0.5 and destination.port:443 and protocol:dns',['arkime']);
  assert.equal(r.parsed.errors.length,0);
  assert.equal(r.parsed.sourceTarget,'dql');
  assert.match(r.outputs.arkime,/ip\.src == 10\.0\.0\.5/);
  assert.match(r.outputs.arkime,/port\.dst == 443/);
  assert.match(r.outputs.arkime,/protocols == dns/);
});

test('Malcolm Lucene syntax is auto-detected and translated',()=>{
  const r=NQT.translate('source.ip:10.0.0.5 AND destination.port:443 AND protocol:dns',['wireshark']);
  assert.equal(r.parsed.sourceTarget,'lucene');
  assert.match(r.outputs.wireshark,/ip\.src == 10\.0\.0\.5/);
  assert.match(r.outputs.wireshark,/tcp\.dstport == 443/);
  assert.match(r.outputs.wireshark,/dns/);
});

test('Splunk syntax can be translated to Arkime',()=>{
  const r=NQT.translate('src=10.0.0.5 AND dest_port=443 AND app=dns',['arkime']);
  assert.equal(r.parsed.errors.length,0);
  assert.equal(r.parsed.sourceTarget,'splunk');
  assert.match(r.outputs.arkime,/ip\.src == 10\.0\.0\.5/);
  assert.match(r.outputs.arkime,/port\.dst == 443/);
  assert.match(r.outputs.arkime,/protocols == dns/);
});

test('Wireshark syntax can be translated to Splunk',()=>{
  const r=NQT.translate('ip.src == 10.0.0.5 && (tcp.dstport == 53 || udp.dstport == 53) && dns',['splunk']);
  assert.equal(r.parsed.errors.length,0);
  assert.equal(r.parsed.sourceTarget,'wireshark');
  assert.match(r.outputs.splunk,/src=10\.0\.0\.5/);
  assert.match(r.outputs.splunk,/dest_port=53/);
  assert.match(r.outputs.splunk,/app=dns/);
});

test('Security Onion syntax can be translated to Arkime',()=>{
  const r=NQT.translate('source.ip:10.0.0.5 AND network.protocol:dns',['arkime']);
  assert.equal(r.parsed.errors.length,0);
  assert.equal(r.parsed.sourceTarget,'securityonion');
  assert.match(r.outputs.arkime,/ip\.src == 10\.0\.0\.5/);
  assert.match(r.outputs.arkime,/protocols == dns/);
});

test('supported Zeek jq syntax can be translated to Wireshark',()=>{
  const r=NQT.translate('jq -c \'select(.["id.orig_h"] == "10.0.0.5" and .query == "example.com")\' dns.log',['wireshark']);
  assert.equal(r.parsed.errors.length,0);
  assert.equal(r.parsed.sourceTarget,'zeek');
  assert.match(r.outputs.wireshark,/ip\.src == 10\.0\.0\.5/);
  assert.match(r.outputs.wireshark,/dns\.qry\.name == "example\.com"/);
});

test('supported Suricata jq syntax can be translated to Security Onion',()=>{
  const r=NQT.translate('jq -c \'select(.src_ip == "10.0.0.5" and .dest_port == 443 and .event_type == "alert")\' eve.json',['securityonion']);
  assert.equal(r.parsed.errors.length,0);
  assert.equal(r.parsed.sourceTarget,'suricata');
  assert.match(r.outputs.securityonion,/source\.ip:10\.0\.0\.5/);
  assert.match(r.outputs.securityonion,/destination\.port:443/);
  assert.match(r.outputs.securityonion,/event\.module:suricata/);
});

test('UI concisely explains plain-language and query-to-query input',()=>{
  const root=path.resolve(__dirname,'..');
  const html=fs.readFileSync(path.join(root,'index.html'),'utf8');
  const app=fs.readFileSync(path.join(root,'app.js'),'utf8');
  assert.match(html,/plain language or paste supported query syntax/i);
  assert.match(html,/auto-detects/i);
  assert.match(html,/query-to-query/);
  assert.match(app,/Detected input:/);
});

test('generated syntax from every target can be auto-detected and translated back',()=>{
  const targets=Object.keys(NQT.TARGETS);
  const base='show dns traffic from 10.0.0.5 to port 53';
  for(const source of targets){
    const generated=NQT.translate(base,[source]).outputs[source];
    const r=NQT.translate(generated,['arkime']);
    assert.equal(r.parsed.errors.length,0,`${source} should not error when pasted back in`);
    assert.equal(r.parsed.sourceTarget,source,`${source} should be auto-detected`);
    assert.match(r.outputs.arkime,/ip\.src == 10\.0\.0\.5/);
    assert.match(r.outputs.arkime,/port\.dst == 53/);
    assert.match(r.outputs.arkime,/protocols == dns/);
  }
});

test('fully unrecognized plain language fails safely with an actionable error',()=>{
  const r=NQT.translate('do something suspiciously weird with the network',['arkime']);
  assert.ok(r.parsed.errors.length>0);
  assert.match(r.parsed.errors[0],/could not recognize enough/i);
  assert.match(r.parsed.errors[0],/hostname\/domain/i);
  assert.equal(r.outputs.arkime,'');
});

test('partially recognized input reports unused wording without discarding recognized fields',()=>{
  const r=NQT.translate('show dns traffic from 10.0.0.5 suspiciously',['arkime']);
  assert.equal(r.parsed.errors.length,0);
  assert.match(r.outputs.arkime,/ip\.src == 10\.0\.0\.5/);
  assert.ok(r.parsed.unrecognizedTerms.includes('suspiciously'));
  assert.ok(NQT.warningsFor(r.parsed,'arkime').some(x=>/Some wording was not interpreted/i));
});

test('syntax-looking input that cannot be parsed gets a syntax-specific error',()=>{
  const r=NQT.translate('ip.src ==',['wireshark']);
  assert.equal(r.parsed.sourceTarget,'arkime');
  assert.ok(r.parsed.errors.length>0);
  assert.match(r.parsed.errors[0],/looks like Arkime syntax/i);
  assert.match(r.parsed.errors[0],/could not parse any supported fields/i);
});

test('interpretation UI labels recognized and not recognized content',()=>{
  const app=fs.readFileSync(path.join(__dirname,'..','app.js'),'utf8');
  assert.match(app,/Recognized:/);
  assert.match(app,/Not recognized:/);
  assert.match(app,/unrecognizedTerms/);
});
