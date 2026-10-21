'use strict';
// Fixed adapter. No caller JavaScript, browser executable, URL origin or CDP target.
const { chromium } = require('/opt/melissa-web-tools/node_modules/playwright');
const fs = require('node:fs');
const readline = require('node:readline');
const crypto = require('node:crypto');
const origin = 'http://127.0.0.1:37641';
const pages = new Map();
let browser, context;
let events = [];
let artifactSequence = 0;
function binary(kind, bytes) {
  const id = `a${++artifactSequence}`;
  fs.mkdirSync('.melissa-code10/artifacts',{recursive:true});
  fs.writeFileSync(`.melissa-code10/artifacts/${id}`,bytes,{flag:'wx'});
  return {id,kind,bytes:bytes.length,sha256:`sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`};
}
function target(path) {
  const u = new URL(path, origin);
  if (u.origin !== origin || !path.startsWith('/') || path.startsWith('//')) throw Error('origin denied');
  return u.href;
}
function record(event) { if (events.length >= 512) throw Error('event envelope exceeded'); events.push(event); }
async function pageFor(id) {
  if (!pages.has(id)) {
    if (pages.size >= 8) throw Error('page capacity exceeded');
    const p = await context.newPage();
    p.on('console', m => record({kind:'console',type:m.type(),text:m.text().slice(0,8192)}));
    p.on('pageerror', e => record({kind:'pageerror',message:String(e).slice(0,8192)}));
    p.on('requestfailed', r => record({kind:'requestfailed',url:r.url(),failure:r.failure()}));
    p.on('response', r => {if(r.status()>=400) record({kind:'http_error',url:r.url(),status:r.status()});});
    p.on('popup', async popup => {record({kind:'popup_blocked'}); await popup.close();});
    p.on('dialog', async dialog => {record({kind:'dialog_dismissed',type:dialog.type()}); await dialog.dismiss();});
    pages.set(id,p);
  }
  return pages.get(id);
}
async function main(op) {
  if (op.command === 'start') {
    // C03 is the outer hard isolation boundary; no host IPC/mount/network access.
    browser = await chromium.launch({headless:true,chromiumSandbox:false,args:['--disable-dev-shm-usage']});
    context = await browser.newContext({serviceWorkers:'block',acceptDownloads:false,viewport:{width:1280,height:800}});
    await context.route('**/*', async route => {
      const url = new URL(route.request().url());
      if (url.origin !== origin) { record({kind:'origin_denied',url:url.href}); return route.abort('blockedbyclient'); }
      return route.continue();
    });
    await context.routeWebSocket('**/*', socket => {record({kind:'websocket_denied',url:socket.url()});socket.close();});
    await context.tracing.start({screenshots:true,snapshots:true,sources:false});
    return {browser_version:browser.version(),playwright:require('/opt/melissa-web-tools/node_modules/playwright/package.json').version};
  }
  if (op.command === 'close') {
    const path='.melissa-code10/trace.zip';
    await context.tracing.stop({path});
    const bytes=fs.readFileSync(path);
    await browser.close();
    return bytes.length<=512*1024 ? {trace_hex:bytes.toString('hex'),events} : {binary_artifact:binary('trace',bytes),events};
  }
  const p=await pageFor(op.page);
  p.setDefaultTimeout(10000);
  let result={};
  switch(op.command) {
    case 'navigate': {
      const r=await p.goto(target(op.path),{waitUntil:'domcontentloaded'});
      result={status:r?.status(),url:p.url()};break;
    }
    case 'inspect':
      result={url:p.url(),title:await p.title(),aria:await p.locator('body').ariaSnapshot(),dom:await p.locator('body').innerHTML(),layout:await p.evaluate(()=>({width:innerWidth,height:innerHeight,scrollWidth:document.documentElement.scrollWidth,focus:document.activeElement?.getAttribute('id')}))};break;
    case 'fill':await p.locator(op.selector).fill(op.value);break;
    case 'click':await p.locator(op.selector).click();break;
    case 'press':await p.locator(op.selector).press(op.key);break;
    case 'wait':await p.locator(op.selector).waitFor({state:op.state,timeout:op.timeout_ms});break;
    case 'viewport':await p.setViewportSize({width:op.width,height:op.height});break;
    case 'screenshot': {
      const bytes=await p.screenshot({fullPage:true});
      result={content_type:'image/png',...(bytes.length<=512*1024?{png_hex:bytes.toString('hex')}:{binary_artifact:binary('png',bytes)}),viewport:p.viewportSize(),url:p.url()};break;
    }
    default:throw Error('unsupported fixed browser operation');
  }
  if (!['about:blank',origin].some(x=>p.url()===x||p.url().startsWith(origin+'/'))) throw Error('foreign navigation blocked');
  return {...result,events:events.splice(0)};
}
(async()=>{
  for await (const line of readline.createInterface({input:process.stdin,crlfDelay:Infinity})) {
    let op;
    try {op=JSON.parse(line);const body=await main(op);process.stdout.write(JSON.stringify({ok:true,body})+'\n');}
    catch(e){process.stdout.write(JSON.stringify({ok:false,error:{kind:'browser_error',message:String(e).slice(0,8192)}})+'\n');}
    if(op?.command==='close')break;
  }
})().catch(()=>{process.exitCode=1;});
