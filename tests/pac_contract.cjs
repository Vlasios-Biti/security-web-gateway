// Execute the generated PAC in a JavaScript VM with PAC host functions.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const {open, closed} = JSON.parse(fs.readFileSync(0, 'utf8'));
const ipNumber = ip => ip.split('.').reduce((n, x) => ((n << 8) | Number(x)) >>> 0, 0);
function load(code) {
  let resolutions = 0;
  const ctx = {
    isPlainHostName: h => !h.includes('.'),
    dnsDomainIs: (h, s) => h.endsWith(s),
    dnsResolve: h => { resolutions++; return h === 'ip-target.example' ? '198.51.100.42' : null; },
    isInNet: (ip, net, mask) => (ipNumber(ip) & ipNumber(mask)) === (ipNumber(net) & ipNumber(mask))
  };
  vm.createContext(ctx); vm.runInContext(code, ctx);
  return h => ctx.FindProxyForURL('https://' + h + '/', h);
}
const choose = load(open);
for (const h of ['portal.example.com', 'EXAMPLE.ORG.', 'assets.example.org', '10.20.0.1', '172.29.1.2', '192.168.4.3', 'intranet', '198.51.100.25', 'ip-target.example']) {
  assert.equal(choose(h), 'DIRECT', h);
}
for (const h of ['example.org.evil.test', 'notexample.org', '172.32.0.1', 'unlisted.example', 'portal.example.com.evil.test']) {
  assert.equal(choose(h), 'PROXY 192.0.2.10:3128; DIRECT', h);
}
const strict = load(closed);
assert.equal(strict('unlisted.example'), 'PROXY 192.0.2.10:3128');
assert.equal(strict('portal.example.com'), 'DIRECT');
console.log('PAC routing contract: PASS');
