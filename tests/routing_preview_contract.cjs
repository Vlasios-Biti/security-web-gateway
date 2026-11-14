const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const {pac,cases}=JSON.parse(fs.readFileSync(0,'utf8'));
const numeric=ip=>ip.split('.').reduce((n,v)=>(n*256+Number(v))>>>0,0);
for(const [host,address,expected] of cases){
 const context={isPlainHostName:h=>!h.includes('.'),dnsDomainIs:(h,s)=>h.endsWith(s),dnsResolve:()=>address||null,isInNet:(ip,network,mask)=>(numeric(ip)&numeric(mask))===(numeric(network)&numeric(mask))};
 vm.createContext(context);vm.runInContext(pac,context);
 const actual=context.FindProxyForURL('https://'+host+'/',host);
 assert.equal(actual==='DIRECT'?'DIRECT':'PROXY',expected,host);
}
console.log('PAC diagnostic agrees with generated JavaScript: PASS');
