(function(root, factory){
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.NQT = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function(){
  'use strict';

  const TARGETS = {
    arkime:'Arkime', dql:'Malcolm DQL', lucene:'Malcolm Lucene', splunk:'Splunk SPL (CIM-style)',
    wireshark:'Wireshark Display Filter', zeek:'Zeek Logs (jq)', suricata:'Suricata EVE (jq)', securityonion:'Security Onion Hunt / OQL'
  };
  const FIELD_MAP = {
    source_ip:{arkime:'ip.src',dql:'source.ip',lucene:'source.ip',splunk:'src',wireshark:'ip.src',label:'source IP'},
    destination_ip:{arkime:'ip.dst',dql:'destination.ip',lucene:'destination.ip',splunk:'dest',wireshark:'ip.dst',label:'destination IP'},
    any_ip:{arkime:'ip',dql:null,lucene:null,splunk:null,wireshark:'ip.addr',label:'either-side IP'},
    source_port:{arkime:'port.src',dql:'source.port',lucene:'source.port',splunk:'src_port',wireshark:null,label:'source port'},
    destination_port:{arkime:'port.dst',dql:'destination.port',lucene:'destination.port',splunk:'dest_port',wireshark:null,label:'destination port'},
    any_port:{arkime:'port',dql:null,lucene:null,splunk:null,wireshark:null,label:'either-side port'},
    dns_host:{arkime:'host.dns',dql:'dns.host',lucene:'dns.host',splunk:'query',wireshark:'dns.qry.name',label:'DNS hostname'},
    http_host:{arkime:'host.http',dql:'zeek.http.host',lucene:'zeek.http.host',splunk:'http_host',wireshark:'http.host',label:'HTTP host'},
    http_status:{arkime:'http.statuscode',dql:'http.statuscode',lucene:'http.statuscode',splunk:'status',wireshark:'http.response.code',label:'HTTP status'},
    protocol:{arkime:'protocols',dql:'protocol',lucene:'protocol',splunk:'transport',wireshark:null,label:'protocol'},
    dataset:{arkime:'event.dataset',dql:'event.dataset',lucene:'event.dataset',splunk:'event_dataset',wireshark:null,label:'event dataset'}
  };
  const PROTOCOLS=['dns','http','https','tls','ssl','ssh','smb','smb2','ftp','smtp','imap','pop3','rdp','ntp','dhcp','quic','icmp','tcp','udp'];
  const COUNTRY_NAMES={russia:'RU',china:'CN',iran:'IR','north korea':'KP',ukraine:'UA',germany:'DE',france:'FR',canada:'CA',mexico:'MX',japan:'JP',india:'IN','united states':'US',usa:'US'};
  const MAX_INPUT=4096;

  function validateInput(input){
    if(typeof input!=='string') return {ok:false,error:'Input must be plain text. Enter a network hunting request and try again.'};
    const s=input.trim();
    if(!s) return {ok:false,error:'Enter a network hunting request before translating. Example: show DNS traffic from 10.0.0.5.'};
    if(input.length>MAX_INPUT) return {ok:false,error:`Input is ${input.length} characters long. The maximum is ${MAX_INPUT}; shorten it by ${input.length-MAX_INPUT} character${input.length-MAX_INPUT===1?'':'s'} and try again.`};
    if(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(input)) return {ok:false,error:'Input contains non-printing control characters. Remove them and try again.'};
    return {ok:true,value:s};
  }
  function explainInvalidIPorCIDR(v){
    const parts=String(v).split('/');
    if(parts.length>2)return `Invalid IPv4/CIDR value: ${v}. Use an address like 192.168.1.10 or a CIDR like 10.0.0.0/8.`;
    const ip=parts[0],prefix=parts[1],oct=ip.split('.');
    if(oct.length!==4||oct.some(x=>!/^\d{1,3}$/.test(x)))return `Invalid IPv4 address: ${v}. IPv4 addresses must contain four numeric octets, for example 192.168.1.10.`;
    const badOctet=oct.find(x=>+x>255);
    if(badOctet!==undefined)return `Invalid IPv4 address: ${v}. Each octet must be between 0 and 255; found ${badOctet}.`;
    if(prefix!==undefined&&(!/^\d{1,2}$/.test(prefix)||+prefix>32))return `Invalid CIDR prefix in ${v}. IPv4 CIDR prefixes must be between /0 and /32.`;
    return null;
  }
  function validIPorCIDR(v){return explainInvalidIPorCIDR(v)===null;}
  function q(v){return /[\s:\/]/.test(String(v))?`"${String(v).replace(/"/g,'\\"')}"`:String(v);}
  function extractTime(s){
    const patterns=[[/\b(?:in |over |during )?the last\s+(\d+)\s*(minute|minutes|hour|hours|day|days|week|weeks)\b/i,m=>`Last ${m[1]} ${m[2]}`],[/\bpast\s+(\d+)\s*(minute|minutes|hour|hours|day|days|week|weeks)\b/i,m=>`Last ${m[1]} ${m[2]}`],[/\byesterday\b/i,()=>`Yesterday`],[/\btoday\b/i,()=>`Today`]];
    for(const [re,fn] of patterns){const m=s.match(re);if(m)return {label:fn(m),span:m[0]};} return null;
  }
  function extractIPs(s){
    const re=/(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?(?![\w.])/g;
    return [...s.matchAll(re)].map(m=>({value:m[0],index:m.index})).filter(x=>validIPorCIDR(x.value));
  }
  function invalidIPLikeTokens(s){
    const re=/(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,3})?(?![\w.])/g;
    return [...s.matchAll(re)].map(m=>m[0]).filter(v=>!validIPorCIDR(v));
  }
  function directionFor(s,index){
    const before=s.slice(Math.max(0,index-38),index).toLowerCase();
    if(/(?:from|source|src)\s*$/.test(before))return 'source';
    if(/(?:to|destination|dest|dst)\s*$/.test(before))return 'destination'; return 'any';
  }
  function parsePorts(s){
    const out=[];
    const re=/\b(?:port|ports|destination port|destination ports|dest port|dst port|source port|source ports|src port)\s*(?:is|are|=|:)?\s*([0-9]{1,5}(?:\s*(?:,|or|and)\s*[0-9]{1,5})*)/gi;
    let m; while((m=re.exec(s))){
      const prefix=m[0].slice(0,m[0].indexOf(m[1])).toLowerCase();
      const dir=/source|src/.test(prefix)?'source':/destination|dest|dst/.test(prefix)?'destination':/\bto\s+port/.test(s.slice(Math.max(0,m.index-5),m.index+m[0].length).toLowerCase())?'destination':'any';
      const nums=m[1].split(/\s*(?:,|or|and)\s*/).map(Number); const vals=nums.filter(x=>x>=0&&x<=65535);
      if(vals.length)out.push({dir,values:vals});
    }
    const toPort=/\bto\s+port\s+(\d{1,5})\b/i.exec(s); if(toPort&&+toPort[1]<=65535&&!out.some(p=>p.values.includes(+toPort[1])))out.push({dir:'destination',values:[+toPort[1]]});
    return out;
  }
  function invalidPorts(s){
    const vals=[...s.matchAll(/\b(?:port|ports)\s*(?:is|are|=|:)?\s*(\d{1,6})\b/gi)].map(m=>+m[1]);
    return vals.filter(v=>v>65535);
  }
  function parseCountries(s){
    const found=[]; const upper=[...s.matchAll(/\b(?:country|countries)\s+(?:is|are|in|to)?\s*([A-Z]{2}(?:\s*(?:,|or|and)\s*[A-Z]{2})*)/g)];
    upper.forEach(m=>found.push(...m[1].split(/\s*(?:,|or|and)\s*/))); const lower=s.toLowerCase();
    for(const [name,code] of Object.entries(COUNTRY_NAMES))if(lower.includes(name))found.push(code); return [...new Set(found)];
  }

  function stripValue(v){
    let x=String(v).trim();
    while(x.startsWith('(')&&x.endsWith(')'))x=x.slice(1,-1).trim();
    if((x.startsWith('"')&&x.endsWith('"'))||(x.startsWith("'")&&x.endsWith("'")))x=x.slice(1,-1);
    return x.replace(/\\"/g,'"');
  }
  function parseListValue(v){
    let x=String(v).trim();
    if(x.startsWith('[')&&x.endsWith(']'))x=x.slice(1,-1);
    if(x.startsWith('(')&&x.endsWith(')'))x=x.slice(1,-1);
    return x.split(/\s*(?:,|\bOR\b|\bor\b)\s*/).map(stripValue).filter(Boolean);
  }
  function addCond(conds,c){
    if(!c||c.value===undefined||c.value===null)return;
    if(c.field==='country'){
      const vals=Array.isArray(c.value)?c.value:[c.value];
      const existing=conds.find(x=>x.field==='country');
      if(existing){existing.value=[...new Set(existing.value.concat(vals))];return;}
      conds.push({field:'country',op:'in',value:[...new Set(vals)]});return;
    }
    if(['source_port','destination_port','any_port'].includes(c.field)){
      const vals=(Array.isArray(c.value)?c.value:[c.value]).map(Number).filter(Number.isFinite);
      const existing=conds.find(x=>x.field===c.field&&x.op==='in');
      if(existing){existing.value=[...new Set(existing.value.concat(vals))];return;}
      conds.push({field:c.field,op:'in',value:[...new Set(vals)]});return;
    }
    if(conds.some(x=>x.field===c.field&&x.op===c.op&&String(x.value)===String(c.value)&&!!x.wildcard===!!c.wildcard))return;
    conds.push(c);
  }
  function detectSyntax(s){
    if(/^\s*jq\s+-c\b/i.test(s)&&/\beve\.json\b/i.test(s))return 'suricata';
    if(/^\s*jq\s+-c\b/i.test(s)&&/\b(?:conn|dns|http|ssl|files|notice|weird)\.log\b/i.test(s))return 'zeek';
    if(/\b(?:tcp|udp)\.(?:srcport|dstport|port)\s*==|\bdns\.qry\.name\s*(?:==|contains)|\bhttp\.response\.code\s*==/i.test(s))return 'wireshark';
    if(/\b(?:ip\.src|ip\.dst|port\.src|port\.dst|host\.dns|host\.http|http\.statuscode|protocols)\s*==/i.test(s))return 'arkime';
    if(/\b(?:src|dest|src_port|dest_port|transport|app|query|http_host|status|event_dataset)\s*=/i.test(s))return 'splunk';
    if(/\b(?:network\.protocol|dns\.question\.name|http\.response\.status_code|event\.module|event\.kind|rule\.name)\s*:/i.test(s))return 'securityonion';
    if(/\b(?:source\.ip|destination\.ip|source\.port|destination\.port|dns\.host|event\.dataset|protocol)\s*:/i.test(s)){
      if(/\bAND\b|\bOR\b/.test(s)||/_exists_:/i.test(s))return 'lucene';
      return 'dql';
    }
    return null;
  }
  function parseArkimeSyntax(s){
    const conds=[];
    const fmap={'ip.src':'source_ip','ip.dst':'destination_ip','ip':'any_ip','port.src':'source_port','port.dst':'destination_port','port':'any_port','host.dns':'dns_host','host.http':'http_host','http.statuscode':'http_status','protocols':'protocol','event.dataset':'dataset'};
    const re=/\b(ip\.src|ip\.dst|ip|port\.src|port\.dst|port|host\.dns|host\.http|http\.statuscode|protocols|event\.dataset|country)\s*==\s*(EXISTS!|\[[^\]]*\]|"[^"]*"|'[^']*'|[^\s()&|]+)/gi;
    let m;while((m=re.exec(s))){const f=m[1].toLowerCase(),raw=m[2];if(f==='country'){addCond(conds,{field:'country',op:'in',value:parseListValue(raw)});continue;}const field=fmap[f];if(!field)continue;if(/^EXISTS!$/i.test(raw)){addCond(conds,{field,op:'exists'});continue;}if(['source_port','destination_port','any_port'].includes(field)){addCond(conds,{field,op:'in',value:parseListValue(raw).map(Number)});continue;}let v=stripValue(raw);if(field==='http_status')v=Number(v);addCond(conds,{field,op:'eq',value:v,wildcard:field==='dns_host'&&v.includes('*')});}
    return conds;
  }
  function spansContain(spans,index){return spans.some(([a,b])=>index>=a&&index<b);}
  function tokenAfterColonPattern(){return '(\\([^()]+\\)|"[^"]*"|[^\\s()]+)';}
  function parseOpenSearchSyntax(s,source){
    const conds=[],skip=[];
    const tok=tokenAfterColonPattern();
    const anyIp=new RegExp(`\\(?\\s*source\\.ip\\s*:\\s*(${tok})\\s+(?:OR|or)\\s+destination\\.ip\\s*:\\s*(${tok})\\s*\\)?`,'gi');
    let m;while((m=anyIp.exec(s))){const a=stripValue(m[1]),b=stripValue(m[3]);if(a===b){addCond(conds,{field:'any_ip',op:'eq',value:a});skip.push([m.index,m.index+m[0].length]);}}
    const anyPort=/\(?\s*source\.port\s*:\s*(\([^()]+\)|\d+)\s+(?:OR|or)\s+destination\.port\s*:\s*(\([^()]+\)|\d+)\s*\)?/gi;
    while((m=anyPort.exec(s))){const a=parseListValue(m[1]),b=parseListValue(m[2]);if(a.join('|')===b.join('|')){addCond(conds,{field:'any_port',op:'in',value:a.map(Number)});skip.push([m.index,m.index+m[0].length]);}}
    const exists=/_exists_\s*:\s*(event\.dataset)/gi;while((m=exists.exec(s)))addCond(conds,{field:'dataset',op:'exists'});
    const fmap={'source.ip':'source_ip','destination.ip':'destination_ip','source.port':'source_port','destination.port':'destination_port','dns.host':'dns_host','protocol':'protocol','event.dataset':'dataset','dns.question.name':'dns_host','network.protocol':'protocol','http.response.status_code':'http_status'};
    const fieldRe=new RegExp(`\\b(source\\.ip|destination\\.ip|source\\.port|destination\\.port|dns\\.host|protocol|event\\.dataset|dns\\.question\\.name|network\\.protocol|http\\.response\\.status_code)\\s*:\\s*(${tok})`,'gi');
    while((m=fieldRe.exec(s))){if(spansContain(skip,m.index))continue;const key=m[1].toLowerCase(),field=fmap[key],raw=m[2];if(['source_port','destination_port'].includes(field)){addCond(conds,{field,op:'in',value:parseListValue(raw).map(Number)});continue;}if(field==='http_status'){addCond(conds,{field,op:'eq',value:Number(stripValue(raw))});continue;}if(field==='dataset'&&/^\*$/.test(stripValue(raw))){addCond(conds,{field,op:'exists'});continue;}const v=stripValue(raw);addCond(conds,{field,op:'eq',value:v,wildcard:field==='dns_host'&&v.includes('*')});}
    const countries=[...s.matchAll(/(?:source\.geo\.country_(?:code2|iso_code)|destination\.geo\.country_(?:code2|iso_code)|dns\.GEO)\s*:\s*([A-Z]{2})/g)].map(x=>x[1]);if(countries.length)addCond(conds,{field:'country',op:'in',value:countries});
    if(source==='securityonion'&&/event\.module\s*:\s*suricata/i.test(s)&&/event\.kind\s*:\s*alert/i.test(s))addCond(conds,{field:'suricata_alert',op:'eq',value:'alert'});
    const rn=/rule\.name\s*:\s*\*([^*]+)\*/i.exec(s);if(rn)addCond(conds,{field:'alert_signature',op:'contains',value:rn[1].replace(/\?/g,' ')});
    return conds;
  }
  function parseSplunkSyntax(s){
    const conds=[],skip=[];let m;
    const anyIp=/\(?\s*src\s*=\s*("[^"]*"|[^\s()]+)\s+OR\s+dest\s*=\s*("[^"]*"|[^\s()]+)\s*\)?/gi;
    while((m=anyIp.exec(s))){const a=stripValue(m[1]),b=stripValue(m[2]);if(a===b){addCond(conds,{field:'any_ip',op:'eq',value:a});skip.push([m.index,m.index+m[0].length]);}}
    const anyPort=/\(?\s*src_port\s*=\s*(\d+)\s+OR\s+dest_port\s*=\s*(\d+)\s*\)?/gi;
    while((m=anyPort.exec(s))){if(m[1]===m[2]){addCond(conds,{field:'any_port',op:'in',value:[Number(m[1])]});skip.push([m.index,m.index+m[0].length]);}}
    const fmap={src:'source_ip',dest:'destination_ip',src_port:'source_port',dest_port:'destination_port',query:'dns_host',http_host:'http_host',status:'http_status',transport:'protocol',app:'protocol',event_dataset:'dataset'};
    const re=/\b(src|dest|src_port|dest_port|query|http_host|status|transport|app|event_dataset)\s*=\s*("[^"]*"|[^\s()]+)/gi;
    while((m=re.exec(s))){if(spansContain(skip,m.index))continue;const field=fmap[m[1].toLowerCase()],v=stripValue(m[2]);if(['source_port','destination_port'].includes(field)){addCond(conds,{field,op:'in',value:[Number(v)]});continue;}if(field==='http_status'){addCond(conds,{field,op:'eq',value:Number(v)});continue;}if(field==='dataset'&&v==='*'){addCond(conds,{field,op:'exists'});continue;}addCond(conds,{field,op:'eq',value:v,wildcard:field==='dns_host'&&v.includes('*')});}
    const countries=[...s.matchAll(/\b(?:src_country|dest_country)\s*=\s*([A-Z]{2})/g)].map(x=>x[1]);if(countries.length)addCond(conds,{field:'country',op:'in',value:countries});
    return conds;
  }
  function parseWiresharkSyntax(s){
    const conds=[];let m;
    const ipRe=/\b(ip\.src|ip\.dst|ip\.addr)\s*==\s*([^\s()&|]+)/gi;while((m=ipRe.exec(s)))addCond(conds,{field:m[1].toLowerCase()==='ip.src'?'source_ip':m[1].toLowerCase()==='ip.dst'?'destination_ip':'any_ip',op:'eq',value:stripValue(m[2])});
    const portRe=/\b(tcp|udp)\.(srcport|dstport|port)\s*==\s*(\d+)/gi;while((m=portRe.exec(s)))addCond(conds,{field:m[2].toLowerCase()==='srcport'?'source_port':m[2].toLowerCase()==='dstport'?'destination_port':'any_port',op:'in',value:[Number(m[3])]});
    const dnsContains=/\bdns\.qry\.name\s+contains\s+"([^"]*)"/gi;while((m=dnsContains.exec(s)))addCond(conds,{field:'dns_host',op:'eq',value:`*${m[1]}*`,wildcard:true});
    const strRe=/\b(dns\.qry\.name|http\.host)\s*==\s*"([^"]*)"/gi;while((m=strRe.exec(s)))addCond(conds,{field:m[1].toLowerCase()==='dns.qry.name'?'dns_host':'http_host',op:'eq',value:m[2]});
    const status=/\bhttp\.response\.code\s*==\s*(\d{3})/i.exec(s);if(status)addCond(conds,{field:'http_status',op:'eq',value:Number(status[1])});
    for(const p of PROTOCOLS){const normalized=p==='https'?'tls':p;if(new RegExp(`(?:^|[(&|!\\s])${p}(?=$|[)&|\\s])`,'i').test(s))addCond(conds,{field:'protocol',op:'eq',value:normalized});}
    return conds;
  }
  function unescapeJqString(v){try{return JSON.parse(`"${String(v).replace(/"/g,'\\"')}"`);}catch{return String(v);}}
  function parseZeekSyntax(s){
    const conds=[],skip=[];let m;
    const anyIp=/\.\["id\.orig_h"\]\s*==\s*"([^"]+)"\s+or\s+\.\["id\.resp_h"\]\s*==\s*"([^"]+)"/gi;
    while((m=anyIp.exec(s))){if(m[1]===m[2]){addCond(conds,{field:'any_ip',op:'eq',value:m[1]});skip.push([m.index,m.index+m[0].length]);}}
    const fieldRe=/\.\["id\.(orig_h|resp_h|orig_p|resp_p)"\]\s*==\s*("[^"]+"|\d+)/gi;while((m=fieldRe.exec(s))){if(spansContain(skip,m.index))continue;const key=m[1],v=stripValue(m[2]);addCond(conds,{field:key==='orig_h'?'source_ip':key==='resp_h'?'destination_ip':key==='orig_p'?'source_port':'destination_port',op:key.endsWith('_p')?'in':'eq',value:key.endsWith('_p')?[Number(v)]:v});}
    const qeq=/\.query\s*==\s*"([^"]+)"/i.exec(s);if(qeq)addCond(conds,{field:'dns_host',op:'eq',value:qeq[1]});
    const qcontains=/\.query[^\n]*contains\("([^"]+)"\)/i.exec(s);if(qcontains)addCond(conds,{field:'dns_host',op:'eq',value:`*${qcontains[1]}*`,wildcard:true});
    const heq=/\.host\s*==\s*"([^"]+)"/i.exec(s);if(heq)addCond(conds,{field:'http_host',op:'eq',value:heq[1]});
    const status=/\.status_code\s*==\s*(\d{3})/i.exec(s);if(status)addCond(conds,{field:'http_status',op:'eq',value:Number(status[1])});
    const proto=/\.proto\s*==\s*"([^"]+)"/i.exec(s);if(proto)addCond(conds,{field:'protocol',op:'eq',value:proto[1]});
    const svc=/\.service\s*==\s*"([^"]+)"/i.exec(s);if(svc)addCond(conds,{field:'protocol',op:'eq',value:svc[1]==='ssl'?'tls':svc[1]});
    if(/\bdns\.log\b/i.test(s))addCond(conds,{field:'protocol',op:'eq',value:'dns'});else if(/\bhttp\.log\b/i.test(s))addCond(conds,{field:'protocol',op:'eq',value:'http'});else if(/\bssl\.log\b/i.test(s))addCond(conds,{field:'protocol',op:'eq',value:'tls'});
    return conds;
  }
  function parseSuricataSyntax(s){
    const conds=[],skip=[];let m;
    const anyIp=/\.src_ip\s*==\s*"([^"]+)"\s+or\s+\.dest_ip\s*==\s*"([^"]+)"/gi;while((m=anyIp.exec(s))){if(m[1]===m[2]){addCond(conds,{field:'any_ip',op:'eq',value:m[1]});skip.push([m.index,m.index+m[0].length]);}}
    const ipRe=/\.(src_ip|dest_ip)\s*==\s*"([^"]+)"/gi;while((m=ipRe.exec(s))){if(spansContain(skip,m.index))continue;addCond(conds,{field:m[1]==='src_ip'?'source_ip':'destination_ip',op:'eq',value:m[2]});}
    const portRe=/\.(src_port|dest_port)\s*==\s*(\d+)/gi;while((m=portRe.exec(s)))addCond(conds,{field:m[1]==='src_port'?'source_port':'destination_port',op:'in',value:[Number(m[2])]});
    if(/\.event_type\s*==\s*"alert"/i.test(s))addCond(conds,{field:'suricata_alert',op:'eq',value:'alert'});
    const sig=/\.alert\.signature[^\n]*contains\("([^"]+)"\)/i.exec(s);if(sig)addCond(conds,{field:'alert_signature',op:'contains',value:sig[1]});
    const app=/\.app_proto\s*==\s*"([^"]+)"/i.exec(s);if(app)addCond(conds,{field:'protocol',op:'eq',value:app[1]});
    const proto=/ascii_downcase\)\s*==\s*"([^"]+)"/i.exec(s);if(proto)addCond(conds,{field:'protocol',op:'eq',value:proto[1]});
    if(/\.event_type\s*==\s*"tls"|\.app_proto\s*==\s*"tls"/i.test(s))addCond(conds,{field:'protocol',op:'eq',value:'tls'});
    const dnsEq=/\.dns\.(?:rrname|queries\[0\]\.rrname)[^\n]*==\s*"([^"]+)"/i.exec(s);if(dnsEq)addCond(conds,{field:'dns_host',op:'eq',value:dnsEq[1]});
    const dnsContains=/\.dns\.[^\n]*contains\("([^"]+)"\)/i.exec(s);if(dnsContains)addCond(conds,{field:'dns_host',op:'eq',value:`*${dnsContains[1]}*`,wildcard:true});
    const host=/\.http\.hostname\s*==\s*"([^"]+)"/i.exec(s);if(host)addCond(conds,{field:'http_host',op:'eq',value:host[1]});
    const status=/\.http\.status[^\n]*==\s*(\d{3})/i.exec(s);if(status)addCond(conds,{field:'http_status',op:'eq',value:Number(status[1])});
    return conds;
  }
  function parseKnownSyntax(s,source){
    let conds=[];
    if(source==='arkime')conds=parseArkimeSyntax(s);
    else if(source==='dql'||source==='lucene'||source==='securityonion')conds=parseOpenSearchSyntax(s,source);
    else if(source==='splunk')conds=parseSplunkSyntax(s);
    else if(source==='wireshark')conds=parseWiresharkSyntax(s);
    else if(source==='zeek')conds=parseZeekSyntax(s);
    else if(source==='suricata')conds=parseSuricataSyntax(s);
    if(!conds.length)return null;
    return {conds,time:null,warnings:[`Detected ${TARGETS[source]} syntax. HuntQuery translated recognized fields into the selected target format${source==='zeek'||source==='suricata'?' from the supported jq form':''}.`],notes:[],errors:[],sourceTarget:source};
  }

  function findUnrecognizedTerms(s,conds,time){
    let residue=String(s).toLowerCase();
    const values=[];
    for(const c of conds||[]){
      if(Array.isArray(c.value))values.push(...c.value.map(String));
      else if(c.value!==undefined&&c.value!==null)values.push(String(c.value).replace(/^\*|\*$/g,''));
    }
    for(const v of values.sort((a,b)=>b.length-a.length)){
      if(!v)continue;
      residue=residue.split(v.toLowerCase()).join(' ');
    }
    if(time&&time.span)residue=residue.split(String(time.span).toLowerCase()).join(' ');
    residue=residue.replace(/(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?/g,' ');
    residue=residue.replace(/\b\d{1,5}\b/g,' ');
    const stop=new Set([
      'show','find','display','list','get','give','me','traffic','packet','packets','session','sessions','connection','connections','network','networking',
      'from','to','on','using','use','for','where','with','and','or','the','a','an','is','are','equals','equal','of','in','over','during','past','last',
      'contain','contains','containing','matching','match','matches','host','hostname','name','domain','dns','http','https','status','response','code','port','ports',
      'source','destination','src','dst','protocol','alert','alerts','suricata','zeek','dataset','country','minute','minutes','hour','hours','day','days','week','weeks',
      'today','yesterday','either','side','any','all','only','that','which','has','have','address','addresses','ip','ips','events','event','log','logs'
    ]);
    for(const p of PROTOCOLS)stop.add(p);
    for(const n of Object.keys(COUNTRY_NAMES))for(const t of n.split(/\s+/))stop.add(t);
    const terms=residue.replace(/[^a-z0-9_.-]+/g,' ').split(/\s+/).filter(Boolean).filter(t=>!stop.has(t));
    return [...new Set(terms)].slice(0,8);
  }

  function parse(input){
    const check=validateInput(input); if(!check.ok)return {conds:[],time:null,warnings:[],notes:[],errors:[check.error],sourceTarget:null,unrecognizedTerms:[]};
    const s=check.value;
    const sourceTarget=detectSyntax(s);
    if(sourceTarget){
      const syntaxParsed=parseKnownSyntax(s,sourceTarget);
      if(syntaxParsed){syntaxParsed.unrecognizedTerms=[];return syntaxParsed;}
      return {
        conds:[],time:null,warnings:[],notes:[],sourceTarget,unrecognizedTerms:[],
        errors:[`This looks like ${TARGETS[sourceTarget]} syntax, but HuntQuery could not parse any supported fields. Simplify the expression or paste a basic IP, port, protocol, hostname, HTTP status, country, alert, or dataset condition.`]
      };
    }
    const conds=[],warnings=[],notes=[],errors=[];
    invalidIPLikeTokens(s).forEach(v=>errors.push(explainInvalidIPorCIDR(v)||`Invalid IPv4/CIDR value: ${v}.`));
    invalidPorts(s).forEach(v=>errors.push(`Invalid port: ${v}. Valid TCP/UDP ports are 0 through 65535. Replace ${v} with a valid port and try again.`));
    const time=extractTime(s); extractIPs(s).forEach(ip=>{const dir=directionFor(s,ip.index);conds.push({field:dir==='source'?'source_ip':dir==='destination'?'destination_ip':'any_ip',op:'eq',value:ip.value});});
    parsePorts(s).forEach(p=>conds.push({field:p.dir==='source'?'source_port':p.dir==='destination'?'destination_port':'any_port',op:'in',value:p.values}));
    let protocol=null; for(const p of PROTOCOLS){if(new RegExp(`\\b${p}\\b`,'i').test(s)){protocol=p;break;}} if(protocol==='https')protocol='tls'; if(protocol)conds.push({field:'protocol',op:'eq',value:protocol});
    const dnsContain=/(?:dns (?:queries?|hosts?|names?).*?(?:contain(?:s|ing)?|matching)|(?:host\s*name|hostname|domain).*?(?:contain(?:s|ing)?|matching))\s+["']?([a-z0-9._*-]+)["']?/i.exec(s); if(dnsContain)conds.push({field:'dns_host',op:'eq',value:dnsContain[1].includes('*')?dnsContain[1]:`*${dnsContain[1]}*`,wildcard:true});
    const dnsExact=/(?:dns (?:host|hostname|domain)|host\s*name|hostname|domain)\s*(?:(?:is|=|equals?)\s*)?["']?([a-z0-9][a-z0-9._-]*)["']?/i.exec(s); if(dnsExact&&!conds.some(c=>c.field==='dns_host'))conds.push({field:'dns_host',op:'eq',value:dnsExact[1]});
    const httpStatus=/(?:http\s+)?(?:status|status code|response code)\s*(?:is|=|of)?\s*(\d{3})/i.exec(s); if(httpStatus){const n=+httpStatus[1];if(n>=100&&n<=599)conds.push({field:'http_status',op:'eq',value:n});else errors.push(`Invalid HTTP status code: ${n}. HTTP status codes must be between 100 and 599.`);}
    if(/\bevent\.dataset\s+(?:exists|is present)\b/i.test(s)||/\bdataset\s+exists\b/i.test(s))conds.push({field:'dataset',op:'exists'});
    const zeekType=/\bzeek\s+([a-z0-9_.-]+)\s+(?:events?|logs?)\b/i.exec(s); if(zeekType)conds.push({field:'dataset',op:'eq',value:zeekType[1]});
    if(/\b(?:suricata\s+)?alerts?\b/i.test(s))conds.push({field:'suricata_alert',op:'eq',value:'alert'});
    const sig=/(?:signature|alert name|rule name)\s+(?:contains|containing|is|=)?\s*["']?([^"']+?)["']?(?=$|\s+(?:from|to|on|in|with)\b)/i.exec(s); if(sig&&sig[1])conds.push({field:'alert_signature',op:'contains',value:sig[1].trim()});
    const countries=parseCountries(s); if(countries.length)conds.push({field:'country',op:'in',value:countries});
    if(/\bnot\b|\bexclude\b|\bwithout\b/i.test(s))warnings.push('Negation is only partially supported; review the generated expression carefully.');
    if(/\b(outbound|inbound|internal|external)\b/i.test(s))warnings.push('Direction terms such as internal/external/outbound require your local network ranges and are not inferred automatically.');
    const unrecognizedTerms=findUnrecognizedTerms(s,conds,time);
    if(!conds.length&&!errors.length){
      errors.push('HuntQuery could not recognize enough of this request to build a safe query. Try including an IP or CIDR, hostname/domain, port, protocol (such as DNS, TLS, or SMB), HTTP status, country, Suricata alert, or Zeek dataset. Example: show DNS traffic from 10.0.0.5 to port 53.');
    }else if(conds.length&&unrecognizedTerms.length){
      warnings.push(`Some wording was not interpreted and was not added to the query: ${unrecognizedTerms.join(', ')}. Review the recognized fields below.`);
    }
    return {conds,time,warnings,notes,errors,sourceTarget:null,unrecognizedTerms};
  }

  function arkimeCond(c){if(c.field==='country')return `country == [${c.value.join(',')}]`;const f=FIELD_MAP[c.field]?.arkime;if(!f)return null;if(c.op==='exists')return `${f} == EXISTS!`;if(c.op==='in')return c.value.length===1?`${f} == ${c.value[0]}`:`${f} == [${c.value.join(', ')}]`;const v=typeof c.value==='number'?c.value:(c.wildcard?`"${c.value}"`:c.value);return `${f} == ${v}`;}
  function osCond(c,target){const opOr=target==='dql'?' or ':' OR ';if(c.field==='any_ip')return `(source.ip:${q(c.value)}${opOr}destination.ip:${q(c.value)})`;if(c.field==='any_port'){const vv=c.value.length===1?String(c.value[0]):`(${c.value.join(opOr)})`;return `(source.port:${vv}${opOr}destination.port:${vv})`;}if(c.field==='country'){const vv=c.value.length===1?c.value[0]:`(${c.value.join(opOr)})`;return `(destination.geo.country_code2:${vv}${opOr}source.geo.country_code2:${vv}${opOr}dns.GEO:${vv})`;}const f=FIELD_MAP[c.field]?.[target];if(!f)return null;if(c.op==='exists')return target==='lucene'?`_exists_:${f}`:`${f}:*`;if(c.op==='in')return c.value.length===1?`${f}:${c.value[0]}`:`${f}:(${c.value.join(opOr)})`;if(c.wildcard)return `${f}:${c.value}`;return `${f}:${q(c.value)}`;}
  function splunkValue(v){const x=String(v);return /[\s*?()\[\]{}:=]/.test(x)?`"${x.replace(/"/g,'\\"')}"`:x;}
  function isTransportProtocol(v){return ['tcp','udp','icmp'].includes(String(v).toLowerCase());}
  function splunkCond(c){if(c.field==='any_ip')return `(src=${splunkValue(c.value)} OR dest=${splunkValue(c.value)})`;if(c.field==='any_port'){const one=v=>`(src_port=${v} OR dest_port=${v})`;return c.value.length===1?one(c.value[0]):`(${c.value.map(one).join(' OR ')})`;}if(c.field==='country')return `(${c.value.map(v=>`src_country=${splunkValue(v)} OR dest_country=${splunkValue(v)}`).join(' OR ')})`;if(c.field==='protocol'){const p=String(c.value).toLowerCase();return isTransportProtocol(p)?`transport=${splunkValue(p)}`:`app=${splunkValue(p)}`;}const f=FIELD_MAP[c.field]?.splunk;if(!f)return null;if(c.op==='exists')return `${f}=*`;if(c.op==='in')return c.value.length===1?`${f}=${c.value[0]}`:`(${c.value.map(v=>`${f}=${v}`).join(' OR ')})`;return `${f}=${splunkValue(c.value)}`;}
  function wsPortCond(dir,values){const fields=dir==='source'?['tcp.srcport','udp.srcport']:dir==='destination'?['tcp.dstport','udp.dstport']:['tcp.port','udp.port'];const each=v=>`(${fields.map(f=>`${f} == ${v}`).join(' || ')})`;return values.length===1?each(values[0]):`(${values.map(each).join(' || ')})`;}
  function wiresharkCond(c){if(c.field==='country'||c.field==='dataset')return null;if(c.field==='source_port')return wsPortCond('source',c.value);if(c.field==='destination_port')return wsPortCond('destination',c.value);if(c.field==='any_port')return wsPortCond('any',c.value);if(c.field==='protocol'){const proto=String(c.value).toLowerCase();return ({ssl:'tls',https:'tls',smb2:'smb2'})[proto]||proto;}const f=FIELD_MAP[c.field]?.wireshark;if(!f)return null;if(c.op==='exists')return f;if(c.field==='dns_host'&&c.wildcard){const raw=String(c.value).replace(/^\*|\*$/g,'');return `${f} contains "${raw.replace(/"/g,'\\"')}"`;}if(c.op==='in')return c.value.length===1?`${f} == ${c.value[0]}`:`(${c.value.map(v=>`${f} == ${v}`).join(' || ')})`;if(typeof c.value==='number')return `${f} == ${c.value}`;if(c.field==='dns_host'||c.field==='http_host')return `${f} == "${String(c.value).replace(/"/g,'\\"')}"`;return `${f} == ${c.value}`;}
  function jqString(v){return JSON.stringify(String(v));}
  function shellQuote(s){return `'${String(s).replace(/'/g, `'"'"'`)}'`;}
  function isCIDR(v){return String(v).includes('/');}
  function zeekField(c){return ({source_ip:'.["id.orig_h"]',destination_ip:'.["id.resp_h"]',source_port:'.["id.orig_p"]',destination_port:'.["id.resp_p"]',dns_host:'.query',http_host:'.host',http_status:'.status_code',dataset:null})[c.field]||null;}
  function zeekCompile(parsed){let logfile='conn.log';if(parsed.conds.some(c=>c.field==='dns_host'||(c.field==='protocol'&&c.value==='dns')))logfile='dns.log';else if(parsed.conds.some(c=>c.field==='http_host'||c.field==='http_status'||(c.field==='protocol'&&c.value==='http')))logfile='http.log';else if(parsed.conds.some(c=>c.field==='protocol'&&['tls','ssl'].includes(c.value)))logfile='ssl.log';const parts=[];for(const c of parsed.conds){if(['source_ip','destination_ip','any_ip'].includes(c.field)&&isCIDR(c.value))continue;if(c.field==='any_ip'){parts.push(`(.["id.orig_h"] == ${jqString(c.value)} or .["id.resp_h"] == ${jqString(c.value)})`);continue;}if(c.field==='any_port'){parts.push(`(${c.value.map(v=>`.["id.orig_p"] == ${v} or .["id.resp_p"] == ${v}`).join(' or ')})`);continue;}if(c.field==='dataset'){if(c.op==='eq'&&/^[a-z0-9_.-]+$/i.test(c.value))logfile=`${c.value}.log`;continue;}if(c.field==='country'||c.field==='suricata_alert'||c.field==='alert_signature')continue;if(c.field==='protocol'){const p=String(c.value).toLowerCase();if(logfile!=='conn.log')continue;if(isTransportProtocol(p))parts.push(`.proto == ${jqString(p)}`);else parts.push(`.service == ${jqString(p==='tls'||p==='ssl'?'ssl':p)}`);continue;}const f=zeekField(c);if(!f)continue;if(c.op==='exists'){parts.push(`${f} != null`);continue;}if(c.op==='in'){parts.push(`(${c.value.map(v=>`${f} == ${typeof v==='number'?v:jqString(v)}`).join(' or ')})`);continue;}if(c.wildcard||c.op==='contains'){const raw=String(c.value).replace(/^\*|\*$/g,'');parts.push(`(${f} // "" | contains(${jqString(raw)}))`);continue;}parts.push(`${f} == ${typeof c.value==='number'?c.value:jqString(c.value)}`);}const program=parts.length?`select(${parts.join(' and ')})`:'.';return `jq -c ${shellQuote(program)} ${logfile}`;}
  function suricataCompile(parsed){const parts=[];for(const c of parsed.conds){if(['source_ip','destination_ip','any_ip'].includes(c.field)&&isCIDR(c.value))continue;if(c.field==='source_ip'){parts.push(`.src_ip == ${jqString(c.value)}`);continue;}if(c.field==='destination_ip'){parts.push(`.dest_ip == ${jqString(c.value)}`);continue;}if(c.field==='any_ip'){parts.push(`(.src_ip == ${jqString(c.value)} or .dest_ip == ${jqString(c.value)})`);continue;}if(c.field==='source_port'){parts.push(`(${c.value.map(v=>`.src_port == ${v}`).join(' or ')})`);continue;}if(c.field==='destination_port'){parts.push(`(${c.value.map(v=>`.dest_port == ${v}`).join(' or ')})`);continue;}if(c.field==='any_port'){parts.push(`(${c.value.map(v=>`.src_port == ${v} or .dest_port == ${v}`).join(' or ')})`);continue;}if(c.field==='suricata_alert'){parts.push('.event_type == "alert"');continue;}if(c.field==='alert_signature'){parts.push(`(.alert.signature // "" | contains(${jqString(c.value)}))`);continue;}if(c.field==='protocol'){const p=String(c.value).toLowerCase();if(['tcp','udp','icmp'].includes(p))parts.push(`(.proto | ascii_downcase) == ${jqString(p)}`);else if(p==='tls'||p==='ssl')parts.push('(.event_type == "tls" or .app_proto == "tls")');else parts.push(`(.event_type == ${jqString(p)} or .app_proto == ${jqString(p)})`);continue;}if(c.field==='dns_host'){const raw=String(c.value).replace(/^\*|\*$/g,'');parts.push(c.wildcard?`((.dns.rrname // .dns.queries[0].rrname // "") | contains(${jqString(raw)}))`:`(.dns.rrname // .dns.queries[0].rrname) == ${jqString(c.value)}`);continue;}if(c.field==='http_host'){parts.push(`.http.hostname == ${jqString(c.value)}`);continue;}if(c.field==='http_status'){parts.push(`(.http.status | tonumber?) == ${c.value}`);continue;}if(c.field==='dataset'&&c.op==='eq'){parts.push(`.event_type == ${jqString(c.value)}`);continue;}}const program=parts.length?`select(${parts.join(' and ')})`:'.';return `jq -c ${shellQuote(program)} eve.json`;}
  function securityOnionCond(c){if(c.field==='any_ip')return `(source.ip:${q(c.value)} OR destination.ip:${q(c.value)})`;if(c.field==='any_port')return `(${c.value.map(v=>`source.port:${v} OR destination.port:${v}`).join(' OR ')})`;if(c.field==='source_ip')return `source.ip:${q(c.value)}`;if(c.field==='destination_ip')return `destination.ip:${q(c.value)}`;if(c.field==='source_port')return c.value.length===1?`source.port:${c.value[0]}`:`source.port:(${c.value.join(' OR ')})`;if(c.field==='destination_port')return c.value.length===1?`destination.port:${c.value[0]}`:`destination.port:(${c.value.join(' OR ')})`;if(c.field==='protocol')return `network.protocol:${q(c.value)}`;if(c.field==='dns_host')return `dns.question.name:${c.wildcard?c.value:q(c.value)}`;if(c.field==='http_status')return `http.response.status_code:${c.value}`;if(c.field==='dataset')return c.op==='exists'?'event.dataset:*':`event.dataset:${q(c.value)}`;if(c.field==='suricata_alert')return 'event.module:suricata AND event.kind:alert';if(c.field==='alert_signature'){const safe=String(c.value).replace(/([+\-!(){}\[\]^"~?:\\\/])/g,'\\$1').replace(/\s+/g,'?');return `rule.name:*${safe}*`;}if(c.field==='country')return `(${c.value.map(v=>`source.geo.country_iso_code:${v} OR destination.geo.country_iso_code:${v}`).join(' OR ')})`;return null;}
  function compile(parsed,target){if(!TARGETS[target])return '';if(parsed.errors&&parsed.errors.length)return '';let parts;if(target==='zeek')return zeekCompile(parsed);if(target==='suricata')return suricataCompile(parsed);if(target==='arkime')parts=parsed.conds.map(arkimeCond);else if(target==='dql'||target==='lucene')parts=parsed.conds.map(c=>osCond(c,target));else if(target==='splunk')parts=parsed.conds.map(splunkCond);else if(target==='wireshark')parts=parsed.conds.map(wiresharkCond);else parts=parsed.conds.map(securityOnionCond);parts=parts.filter(Boolean);const join=target==='arkime'?' && ':target==='dql'?' and ':target==='wireshark'?' && ':' AND ';return parts.map(p=>parts.length>1?`(${p})`:p).join(join);}
  function describe(c){if(c.field==='country')return `Country code matches ${c.value.join(' or ')}`;if(c.field==='suricata_alert')return 'Suricata alert events';if(c.field==='alert_signature')return `Alert signature contains ${c.value}`;const label=FIELD_MAP[c.field]?.label||c.field;if(c.op==='exists')return `${label} exists`;if(c.op==='in')return `${label} is ${c.value.join(' or ')}`;return `${label} ${c.wildcard?'contains/matches':'is'} ${c.value}`;}
  function warningsFor(parsed,target){const w=[...(parsed.warnings||[])];if(target==='splunk')w.push('Splunk output uses generic/CIM-style fields. Verify local field extractions or data models.');if(target==='wireshark'&&parsed.conds.some(c=>c.field==='country'||c.field==='dataset'))w.push('Country and event.dataset conditions are not emitted for Wireshark.');if(target==='zeek'){w.push('Zeek output is a shell-safe jq command against Zeek JSON logs.');if(parsed.conds.some(c=>['source_ip','destination_ip','any_ip'].includes(c.field)&&isCIDR(c.value)))w.push('CIDR matching is omitted in Zeek jq mode because plain jq does not perform subnet membership correctly without helper logic.');}if(target==='suricata'){w.push('Suricata output is a shell-safe jq filter for EVE JSON; exact fields can vary by version/configuration.');if(parsed.conds.some(c=>['source_ip','destination_ip','any_ip'].includes(c.field)&&isCIDR(c.value)))w.push('CIDR matching is omitted in Suricata jq mode because plain jq does not perform subnet membership correctly without helper logic.');}if(target==='securityonion')w.push('Security Onion output targets the SOC Hunt/Dashboards Lucene-style query bar.');return w;}
  function translate(input,targets){const parsed=parse(input);const list=Array.isArray(targets)?targets:[targets];const outputs={};for(const t of list){if(TARGETS[t])outputs[t]=compile(parsed,t);}return {parsed,outputs};}

  return {TARGETS,MAX_INPUT,validateInput,validIPorCIDR,explainInvalidIPorCIDR,detectSyntax,parseKnownSyntax,parse,compile,translate,describe,warningsFor,shellQuote};
});
