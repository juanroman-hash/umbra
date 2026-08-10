#!/usr/bin/env node
/* Umbra live dashboard — local, read-only, zero-dependency.
 * Streams a running engagement's agent progress, findings, artifacts, and live Burp activity
 * to a browser over SSE. Bind 127.0.0.1 only. Run: node .umbra/dashboard/server.js
 */
'use strict'
const http = require('http')
const fs = require('fs')
const path = require('path')
const os = require('os')

const PORT = +(process.env.UMBRA_DASH_PORT || 7878)
const HOST = '127.0.0.1'
const PROJECT_DIR = process.cwd()
const UMBRA_DIR = path.join(PROJECT_DIR, '.umbra')
const BURP_BASE = process.env.UMBRA_DASH_BURP || 'http://127.0.0.1:9876'

// ---------------- shared state broadcast to all SSE clients ----------------
const clients = new Set()
const scopeHosts = readScopeHosts()
const state = {
  run: null,            // { dir, id, startedAt }
  target: scopeHosts[0] || '',
  scopeHosts,
  agents: {},           // agentId -> { id, role, phase, status, started, ended }
  findings: [],         // { key, title, severity, target, status, evidence, reason }
  artifacts: [],        // { path, name, size, mtime }
  burp: { online: false, proxyCount: 0, proxyOther: 0, proxyRecent: [], collab: [], issues: [] },
}
// A proxy request is in-scope when its Host matches a scope entry (exact or a subdomain of it).
function inScopeHost(host) {
  if (!scopeHosts.length) return true // no scope known -> show everything
  host = (host || '').toLowerCase().split(':')[0]
  return scopeHosts.some(h => host === h || host.endsWith('.' + h))
}
function broadcast(type, data) {
  const line = `data: ${JSON.stringify({ type, data })}\n\n`
  for (const res of clients) { try { res.write(line) } catch (_) {} }
}
function snapshot() { return { type: 'snapshot', data: state } }

// ---------------- run discovery + journal tailing ----------------
function readScopeHosts() {
  try {
    const s = fs.readFileSync(path.join(UMBRA_DIR, 'scope.txt'), 'utf8')
    return s.split('\n').map(x => x.trim())
      .filter(x => x && !x.startsWith('#'))
      .map(x => x.replace(/^https?:\/\//, '').split('/')[0].split(':')[0].toLowerCase())
  } catch (_) { return [] }
}
function findLatestRun() {
  if (process.env.UMBRA_DASH_RUN) {
    const d = process.env.UMBRA_DASH_RUN
    return fs.existsSync(path.join(d, 'journal.jsonl')) ? d : null
  }
  const base = path.join(os.homedir(), '.claude', 'projects')
  let best = null, bestM = 0
  let projects = []
  try { projects = fs.readdirSync(base) } catch (_) { return null }
  for (const proj of projects) {
    let sessions = []
    try { sessions = fs.readdirSync(path.join(base, proj)) } catch (_) { continue }
    for (const sess of sessions) {
      const wfBase = path.join(base, proj, sess, 'subagents', 'workflows')
      let runs = []
      try { runs = fs.readdirSync(wfBase) } catch (_) { continue }
      for (const run of runs) {
        if (!run.startsWith('wf_')) continue
        const jp = path.join(wfBase, run, 'journal.jsonl')
        try {
          const m = fs.statSync(jp).mtimeMs
          if (m > bestM) { bestM = m; best = path.join(wfBase, run) }
        } catch (_) {}
      }
    }
  }
  return best
}

const journal = { dir: null, offset: 0 }
function switchRun(dir) {
  if (!dir || dir === journal.dir) return
  journal.dir = dir
  journal.offset = 0
  state.run = { dir, id: path.basename(dir), startedAt: Date.now() }
  state.agents = {}; state.findings = []
  roleCache.clear()
  broadcast('run', state.run)
}
function tailJournal() {
  if (!journal.dir) return
  const jp = path.join(journal.dir, 'journal.jsonl')
  let buf
  try {
    const fd = fs.openSync(jp, 'r')
    const size = fs.fstatSync(fd).size
    if (size <= journal.offset) { fs.closeSync(fd); return }
    const len = size - journal.offset
    buf = Buffer.alloc(len)
    fs.readSync(fd, buf, 0, len, journal.offset)
    fs.closeSync(fd)
    journal.offset = size
  } catch (_) { return }
  for (const line of buf.toString('utf8').split('\n')) {
    const s = line.trim(); if (!s) continue
    let ev; try { ev = JSON.parse(s) } catch (_) { continue }
    handleJournal(ev)
  }
}

// ---------------- role inference ----------------
const roleCache = new Map()
// Matched against ONLY the first ~200 chars of the prompt (the role intro, before the shared RULES
// body which contains keywords like "out-of-band"/"white-box"/"CVE" that would cause false matches).
const ROLE_RULES = [
  [/penetration tester working ONE subtask/i, 'solve', 'Exploit'],
  [/recon specialist/i, 'recon', 'Recon'],
  [/MEMORY WRITER/i, 'memory-write', 'Report'],
  [/long-term MEMORY specialist/i, 'memory', 'Recon'],
  [/adversarial FINDING VERIFIER/i, 'verify', 'Verify'],
  [/CVE-research specialist|SEARCHER/i, 'cve', 'Plan'],
  [/plan REFINER/i, 'refine', 'Refine'],
  [/SUBTASK GENERATOR/i, 'generate', 'Plan'],
  [/Initialize out-of-band|OOB interaction detection/i, 'oob-init', 'Recon'],
  [/Prepare white-box source/i, 'whitebox', 'Recon'],
  [/Write a concise final report/i, 'report', 'Report'],
]
function inferRoleFromPrompt(agentId) {
  if (roleCache.has(agentId)) return roleCache.get(agentId)
  const jp = path.join(journal.dir, `agent-${agentId}.jsonl`)
  let role = null
  try {
    const head = fs.readFileSync(jp, 'utf8').split('\n', 1)[0]
    const obj = JSON.parse(head)
    let content = typeof obj.message?.content === 'string' ? obj.message.content
      : Array.isArray(obj.message?.content) ? obj.message.content.map(c => c.text || '').join(' ') : ''
    content = content.slice(0, 200)
    for (const [re, r, ph] of ROLE_RULES) if (re.test(content)) { role = { role: r, phase: ph }; break }
  } catch (_) {}
  if (role) roleCache.set(agentId, role)
  return role
}
function inferRoleFromResult(result) {
  if (result && typeof result === 'object') {
    if ('appIdentity' in result) return { role: 'recon', phase: 'Recon' }
    if ('subtasks' in result) return { role: 'generate', phase: 'Plan' }
    if ('verified' in result) return { role: 'verify', phase: 'Verify' }
    if ('findings' in result) return { role: 'solve', phase: 'Exploit' }
    if ('backend' in result) return { role: 'oob-init', phase: 'Recon' }
    if ('path' in result && 'info' in result) return { role: 'whitebox', phase: 'Recon' }
  }
  const s = String(result || '')
  if (/Security Engagement|final report/i.test(s)) return { role: 'report', phase: 'Report' }
  if (/memory store|guide-/i.test(s)) return { role: 'memory', phase: 'Recon' }
  return { role: 'agent', phase: 'Exploit' }
}

function handleJournal(ev) {
  const id = ev.agentId; if (!id) return
  if (ev.type === 'started') {
    const r = inferRoleFromPrompt(id) || { role: 'pending', phase: 'Recon' }
    state.agents[id] = { id, role: r.role, phase: r.phase, status: 'running', started: Date.now(), ended: null }
    broadcast('agent', state.agents[id])
  } else if (ev.type === 'result') {
    let result = ev.result
    if (typeof result === 'string') { try { result = JSON.parse(result) } catch (_) {} }
    const a = state.agents[id] || { id, started: Date.now() }
    const r = (a.role && a.role !== 'pending') ? { role: a.role, phase: a.phase } : inferRoleFromResult(result)
    Object.assign(a, { role: r.role, phase: r.phase, status: 'done', ended: Date.now() })
    state.agents[id] = a
    broadcast('agent', a)
    ingestFindings(result)
  }
}

// ---------------- findings ----------------
function fkey(f) { return `${f.subtaskId || ''}|${(f.title || '').slice(0, 80)}` }
function ingestFindings(result) {
  if (!result || typeof result !== 'object') return
  if (Array.isArray(result.findings)) {
    for (const f of result.findings) {
      const key = fkey(f)
      let ex = state.findings.find(x => x.key === key)
      const rec = {
        key, title: f.title || '(untitled)', severity: (f.severity || 'info').toLowerCase(),
        target: f.target || '', status: (f.status === 'failed') ? 'FAILED' : 'CLAIMED',
        evidence: String(f.evidence || '').slice(0, 600), reason: '',
      }
      if (ex) Object.assign(ex, rec); else state.findings.push(rec)
    }
    broadcast('findings', state.findings)
  }
  if (Array.isArray(result.verified)) {
    for (const v of result.verified) {
      const t = (v.title || '').slice(0, 60)
      let ex = state.findings.find(x => x.title.includes(t) || t.includes(x.title.slice(0, 60)))
      if (!ex) {
        ex = { key: 'v|' + t, title: v.title || '(untitled)', severity: (v.severity || 'info').toLowerCase(),
               target: '', status: '', evidence: '', reason: '' }
        state.findings.push(ex)
      }
      ex.status = v.real ? 'CONFIRMED' : 'REJECTED'
      ex.reason = String(v.reason || '').slice(0, 400)
      if (v.severity) ex.severity = String(v.severity).toLowerCase()
    }
    broadcast('findings', state.findings)
  }
}

// ---------------- artifacts ----------------
function scanArtifacts() {
  const out = []
  const walk = (dir, depth) => {
    if (depth > 3) return
    let entries = []
    try { entries = fs.readdirSync(dir, { withFileTypes: true }) } catch (_) { return }
    for (const e of entries) {
      const p = path.join(dir, e.name)
      if (e.isDirectory()) {
        if (['src', 'memory', 'plugin-patches', 'dashboard', 'oob'].includes(e.name) && depth >= 1) {
          // list these dirs shallowly (skip huge src trees)
          if (e.name === 'src') { out.push(dirEntry(p)); continue }
        }
        walk(p, depth + 1)
      } else {
        if (/\.(md|json|txt|env|der)$/i.test(e.name)) out.push(fileEntry(p))
      }
    }
  }
  const fileEntry = (p) => { const st = fs.statSync(p); return { path: path.relative(PROJECT_DIR, p), name: path.basename(p), size: st.size, mtime: st.mtimeMs, dir: false } }
  const dirEntry = (p) => { const st = fs.statSync(p); return { path: path.relative(PROJECT_DIR, p), name: path.basename(p) + '/', size: 0, mtime: st.mtimeMs, dir: true } }
  walk(UMBRA_DIR, 0)
  out.sort((a, b) => b.mtime - a.mtime)
  state.artifacts = out.slice(0, 60)
  broadcast('artifacts', state.artifacts)
}

// ---------------- Burp MCP-over-SSE bridge ----------------
const burp = { post: null, id: 0, pending: new Map(), sseReq: null, ready: false }
function burpConnect() {
  try {
    const u = new URL(BURP_BASE)
    const req = http.get({ hostname: u.hostname, port: u.port, path: '/', headers: { Accept: 'text/event-stream' } }, (res) => {
      let buf = ''
      res.setEncoding('utf8')
      res.on('data', (chunk) => {
        buf += chunk
        let m
        while ((m = /\r?\n\r?\n/.exec(buf))) {           // SSE events are CRLF-separated in Burp
          const block = buf.slice(0, m.index); buf = buf.slice(m.index + m[0].length)
          let event = 'message', data = ''
          for (const ln of block.split(/\r?\n/)) {
            if (ln.startsWith('event:')) event = ln.slice(6).trim()
            else if (ln.startsWith('data:')) data += ln.slice(5).trim()
          }
          if (event === 'endpoint') { burp.post = new URL(data, BURP_BASE).href; burpHandshake() }
          else if (data) { try { burpOnMessage(JSON.parse(data)) } catch (_) {} }
        }
      })
      res.on('end', () => burpDown('sse ended')); res.on('error', (e) => burpDown(e))
    })
    req.on('error', (e) => burpDown(e))
    burp.sseReq = req
  } catch (e) { burpDown(e) }
}
function burpDown(why) {
  if (why) console.error('[burp] down:', why && why.message || why)
  burp.ready = false; burp.post = null
  state.burp.online = false; broadcast('burp', state.burp)
  setTimeout(burpConnect, 5000)
}
function burpRpc(method, params) {
  return new Promise((resolve, reject) => {
    if (!burp.post) return reject(new Error('no endpoint'))
    const id = ++burp.id
    const body = JSON.stringify({ jsonrpc: '2.0', id, method, params })
    const u = new URL(burp.post)
    const req = http.request({ hostname: u.hostname, port: u.port, path: u.pathname + u.search, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } }, (res) => { res.resume() })
    req.on('error', reject)
    burp.pending.set(id, { resolve, reject, t: setTimeout(() => { burp.pending.delete(id); reject(new Error('timeout')) }, 15000) })
    req.write(body); req.end()
  })
}
function burpOnMessage(msg) {
  if (msg.id && burp.pending.has(msg.id)) {
    const p = burp.pending.get(msg.id); burp.pending.delete(msg.id); clearTimeout(p.t)
    if (msg.error) p.reject(new Error(msg.error.message || 'rpc error')); else p.resolve(msg.result)
  }
}
async function burpHandshake() {
  try {
    await burpRpc('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'umbra-dashboard', version: '1' } })
    // notifications/initialized (no id, fire-and-forget)
    try {
      const u = new URL(burp.post)
      const body = JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })
      const r = http.request({ hostname: u.hostname, port: u.port, path: u.pathname + u.search, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } }, (res) => res.resume())
      r.on('error', () => {}); r.write(body); r.end()
    } catch (_) {}
    burp.ready = true; state.burp.online = true; broadcast('burp', state.burp)
    console.error('[burp] handshake ok — online')
  } catch (e) { burpDown(e) }
}
function textOf(result) { try { return (result.content || []).map(c => c.text || '').join('\n') } catch (_) { return '' } }
function parseJsonObjects(text) {
  const out = []; for (const ln of text.split('\n')) { const s = ln.trim(); if (s.startsWith('{')) { try { out.push(JSON.parse(s)) } catch (_) {} } } return out
}
let proxyOffset = 0
const collabSeen = new Set()
async function burpPoll() {
  if (!burp.ready) return
  try {
    // proxy: one page per poll from the cursor
    const r = await burpRpc('tools/call', { name: 'get_proxy_http_history', arguments: { count: 25, offset: proxyOffset } })
    const items = parseJsonObjects(textOf(r))
    for (const it of items) {
      const req = it.request || ''; const resp = it.response || ''
      const m = /^([A-Z]+)\s+(\S+)/.exec(req); const host = ((/\r?\nHost:\s*([^\r\n]+)/i.exec(req) || [])[1] || '').trim()
      if (!inScopeHost(host)) { state.burp.proxyOther++; continue }   // hide Chromium/off-scope noise
      const code = (/^HTTP\/\d(?:\.\d)?\s+(\d{3})/.exec(resp) || [])[1] || (resp.includes('<no response>') || !resp ? '—' : '?')
      const row = { method: m ? m[1] : '?', host, path: (m ? m[2] : '').split('?')[0], code }
      state.burp.proxyRecent.unshift(row)
      state.burp.proxyCount++
    }
    if (items.length) { proxyOffset += items.length; state.burp.proxyRecent = state.burp.proxyRecent.slice(0, 25) }
    // collaborator
    try {
      const c = await burpRpc('tools/call', { name: 'get_collaborator_interactions', arguments: {} })
      for (const it of parseJsonObjects(textOf(c))) {
        const k = `${it.id}|${it.timestamp}|${it.type}`
        if (collabSeen.has(k)) continue; collabSeen.add(k)
        state.burp.collab.unshift({ type: it.type, ip: it.clientIp || '', ts: it.timestamp || '' })
      }
      state.burp.collab = state.burp.collab.slice(0, 20)
    } catch (_) {}
    // scanner issues
    try {
      const s = await burpRpc('tools/call', { name: 'get_scanner_issues', arguments: {} })
      const issues = parseJsonObjects(textOf(s)).slice(0, 40)
      if (issues.length) state.burp.issues = issues.map(i => ({ name: i.name || i.issueName || '?', severity: i.severity || '', host: i.host || i.origin || '' }))
    } catch (_) {}
    broadcast('burp', state.burp)
  } catch (_) { /* transient */ }
}

// ---------------- HTTP server ----------------
const INDEX = path.join(__dirname, 'index.html')
const server = http.createServer((req, res) => {
  const u = new URL(req.url, `http://${HOST}:${PORT}`)
  if (u.pathname === '/') {
    fs.readFile(INDEX, (e, b) => { if (e) { res.writeHead(500); res.end('index missing') } else { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(b) } })
  } else if (u.pathname === '/events') {
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' })
    res.write(`data: ${JSON.stringify(snapshot())}\n\n`)
    clients.add(res)
    req.on('close', () => clients.delete(res))
  } else if (u.pathname === '/artifact') {
    const rel = u.searchParams.get('path') || ''
    const abs = path.resolve(PROJECT_DIR, rel)
    if (!abs.startsWith(UMBRA_DIR + path.sep) && abs !== UMBRA_DIR) { res.writeHead(403); res.end('forbidden'); return }
    fs.readFile(abs, (e, b) => { if (e) { res.writeHead(404); res.end('not found') } else { res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end(b) } })
  } else { res.writeHead(404); res.end('nope') }
})

// ---------------- boot ----------------
switchRun(findLatestRun())
scanArtifacts()
tailJournal()
burpConnect()
setInterval(() => { const r = findLatestRun(); if (r && r !== journal.dir) switchRun(r); tailJournal() }, 1000)
setInterval(scanArtifacts, 3000)
setInterval(burpPoll, 4000)
server.listen(PORT, HOST, () => {
  console.log(`\n  Umbra dashboard → http://${HOST}:${PORT}`)
  console.log(`  run: ${journal.dir ? path.basename(journal.dir) : '(none found yet)'}   target: ${state.target || '(none)'}\n`)
})
