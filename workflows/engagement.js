export const meta = {
  name: 'engagement',
  description: 'Autonomous pentest flow with two execution tracks. RECON reads prior memory, fingerprints and CLASSIFIES each in-scope target (web-app => agent-browser web track; IP/host/service => Kali Docker sandbox network track), and inventories components/versions. A CVE-ENRICHMENT stage turns detected versions into applicability-checked, RoE-classified exploit intel. A GENERATOR decomposes the objective into finding-based subtasks; a loop of parallel solvers → adversarial VERIFIER → REFINER runs until it goes dry, then a REPORT is written and an anonymized guide is persisted to memory. No target-specific knowledge is hardcoded.',
  phases: [
    { title: 'Recon',   detail: 'read memory + fingerprint + classify targets (web vs host/service) + inventory components' },
    { title: 'Plan',    detail: 'CVE-enrich detected versions, then generate finding-based subtasks' },
    { title: 'Exploit', detail: 'parallel solvers pick the right track (Kali sandbox for host/net, agent-browser for web)' },
    { title: 'Verify',  detail: 'adversarially confirm each claimed finding before trusting it' },
    { title: 'Refine',  detail: 'adapt the next round from what was found/failed' },
    { title: 'Report',  detail: 'summarize confirmed impact, then persist an anonymized memory guide' },
  ],
}

// ---------------- defensive args parsing ----------------
const A = typeof args === 'string'
  ? (() => { try { return JSON.parse(args) } catch { return {} } })()
  : (args && typeof args === 'object' ? args : {})
const target = A.target || A.objective || ''
const objective = A.objective || A.target || target
const scope = Array.isArray(A.scope) ? A.scope : (A.scope ? [A.scope] : [])
const maxRounds = Number.isFinite(+A.maxRounds) && +A.maxRounds > 0 ? +A.maxRounds : 4
const scopeLine = scope.length ? scope.join(', ') : 'NONE — refuse all network actions'

// Path to the disposable Kali sandbox (network/host track runs inside it) and the
// per-project memory store. These are embedded into subagent prompts and expanded by
// the shell when an agent runs Bash — the plugin runtime exports both variables, so the
// plugin works from any install location. Override via args ({ pluginRoot, projectDir })
// if you invoke the workflow outside the plugin runtime.
const PLUGIN_ROOT = (A.pluginRoot || A.root || '${CLAUDE_PLUGIN_ROOT}').replace(/\/+$/, '')
const PROJECT_DIR = (A.projectDir || A.cwd || '${CLAUDE_PROJECT_DIR}').replace(/\/+$/, '')
const SANDBOX = `${PLUGIN_ROOT}/scripts/sandbox.sh`
const MEM_DIR = `${PROJECT_DIR}/.umbra/memory`

// ---------------- bug-bounty profile (optional) ----------------
// Passed as A.bounty by commands/pentest-bounty.md. When present the engagement runs
// under bug-bounty Rules of Engagement: attribution header on all HTTP, banned aggressive
// tooling, a low request rate, tight scope + exclusions, and capped solver concurrency so
// the parallel fan-out can't blow a program's rate limit.
const bounty = (A.bounty && typeof A.bounty === 'object') ? A.bounty : null
const bHeader = (bounty && bounty.header) || 'X-Bug-Bounty'
const bHandle = (bounty && bounty.handle) || ''
const bRps = (bounty && Number.isFinite(+bounty.rps) && +bounty.rps > 0) ? +bounty.rps : 2
const bConc = (bounty && Number.isFinite(+bounty.concurrency) && +bounty.concurrency > 0) ? +bounty.concurrency : 2
const bBanned = (bounty && bounty.bannedTools) || ''
const bExclude = (bounty && bounty.exclude) || ''
const bRulesFile = (bounty && bounty.rulesFile) || `${PROJECT_DIR}/.umbra/rules.md`

const BOUNTY_ROE = !bounty ? '' :
  `\n\n=== BUG-BOUNTY RULES OF ENGAGEMENT (BINDING — overrides any speed/aggression guidance) ===\n` +
  `This is a LIVE third-party bug-bounty program. Your ONLY authorization is the program policy in ` +
  `${bRulesFile} plus the scope allowlist. Read ${bRulesFile} FIRST and treat every rule there as a hard constraint.\n` +
  `- SCOPE: touch only hosts explicitly in scope. Honor ALL exclusions` +
  `${bExclude ? ` (explicitly OUT of scope: ${bExclude})` : ''}. A redirect or link to an out-of-scope host is OUT OF ` +
  `BOUNDS — do not follow it. When unsure whether something is in scope, treat it as out of scope and stop.\n` +
  (bHandle
    ? `- ATTRIBUTION: put the header "${bHeader}: ${bHandle}" on EVERY HTTP request — curl -H "${bHeader}: ${bHandle}", ` +
      `agent-browser in-page fetch() headers, and any tool that accepts custom headers. If a tool cannot set it, say so ` +
      `rather than sending unattributed traffic.\n`
    : `- ATTRIBUTION: no researcher handle configured — set bounty.handle so all traffic is attributable before testing.\n`) +
  `- BANNED TOOLING (never run): brute-force (hydra/medusa/patator/ncrack), high-volume scanners (masscan, ` +
  `nmap -T5 / --min-rate), sqlmap above \`--level 1 --risk 1\`, and any DoS / stress / high-volume fuzzing` +
  `${bBanned ? `; also banned for this program: ${bBanned}` : ''}.\n` +
  `- RATE DISCIPLINE: stay under ~${bRps} request(s)/second per host. Use \`nmap -T2 --max-rate ${bRps}\`, insert ` +
  `delays, and never parallel-hammer a single host. Prefer targeted, manual-style requests over broad sweeps.\n` +
  `- WEB TRACK CAUTION: agent-browser runs host-side with NO egress firewall — you are the ONLY scope control there. ` +
  `Open in-scope hosts ONLY.\n` +
  `- NEVER AUTO-SUBMIT. Do not file, submit, or disclose anything to the program, platform, or vendor, and do not ` +
  `contact anyone. Your output is a written report for a HUMAN to review and submit. Unverified findings never leave ` +
  `this run. (Programs ban and de-rank autonomous tools that submit unreviewed volume — a human gate is mandatory.)\n` +
  `- Produce minimal, reproducible, NON-DESTRUCTIVE proofs suitable for a bug-bounty report.`

// ---------------- shared rules: TWO EXECUTION TRACKS ----------------
const RULES = BOUNTY_ROE +
  `AUTHORIZATION & SCOPE (binding): only test in-scope targets: ${scopeLine}. Never act out of scope.\n\n` +
  `TWO EXECUTION TRACKS — pick the right one per target/objective/service:\n` +
  `(a) NETWORK/HOST track (the general pentest track): run ALL host/service/network tooling INSIDE the ` +
  `disposable Kali Docker sandbox via:\n` +
  `    bash "${SANDBOX}" exec "<command>"\n` +
  `Use it for nmap (prefer TCP connect \`nmap -Pn -sT -sV\` — the sandbox drops caps so \`-sS\` raw sockets fail), ` +
  `service/version enumeration, gobuster/nikto/whatweb, sqlmap, hydra, netcat, exploitdb/searchsploit, metasploit ` +
  `if present, etc. This is how we pentest ANY host — not just web. First ensure it is up: bash "${SANDBOX}" up.\n` +
  `(b) WEB track: the stateful, host-side agent-browser CLI — ONLY for web-app / DOM / HTTP testing. Use an ` +
  `ISOLATED session per worker via \`--session <name>\`. Use \`eval '<js>'\` with in-page fetch() for same-origin ` +
  `authenticated API abuse (carries cookies/origin), and open/snapshot/click/fill for DOM/client-side behavior. ` +
  `Pass complex JS via a file: \`agent-browser --session <name> eval "$(cat f.js)"\`. agent-browser is NOT a ` +
  `general pentest tool — NEVER point it at a non-web host; use the Kali sandbox for that.\n\n` +
  `NOTE ON RAW HOST HTTP: this environment may run under context-mode (an external plugin) which can intercept or ` +
  `block raw Bash HTTP (curl / node fetch) on the host shell. umbra makes no guarantee either way. Regardless: ` +
  `run network tooling through the Kali sandbox and web/HTTP testing through agent-browser — do not rely on ad-hoc ` +
  `host-shell curl.`

// ---------------- schemas ----------------
const RECON_SCHEMA = {
  type: 'object',
  properties: {
    appIdentity: { type: 'string', description: 'what each target is + version, from fingerprinting' },
    targets: {
      type: 'array', description: 'each in-scope target classified by track',
      items: {
        type: 'object',
        properties: {
          target: { type: 'string' },
          track: { type: 'string', enum: ['web', 'host'], description: 'web => agent-browser; host => Kali sandbox' },
          services: { type: 'string', description: 'open ports/services or web routes/tech discovered' },
        },
        required: ['target', 'track'],
      },
    },
    surfaceNotes: { type: 'string', description: 'key attack surface discovered (routes, endpoints, ports, tech)' },
    components: {
      type: 'array',
      description: 'every software/framework/library/server component fingerprinted, with version if known, flagging end-of-life/unsupported/outdated ones',
      items: {
        type: 'object',
        properties: {
          name: { type: 'string' },
          version: { type: 'string' },
          eol: { type: 'boolean', description: 'end-of-life / unsupported / clearly outdated' },
          where: { type: 'string', description: 'where observed (server header, powered-by, JS bundle, service banner, TLS, etc.)' },
        },
        required: ['name'],
      },
    },
  },
  required: ['appIdentity', 'targets'],
}

// CVE-enrichment output (version -> CVE -> PoC, applicability + RoE-safety checked).
const CVE_SCHEMA = {
  type: 'object',
  properties: {
    components: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          name: { type: 'string' }, version: { type: 'string' }, eol: { type: 'boolean' },
          cves: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                id: { type: 'string' },
                cvss: { type: 'string' },
                summary: { type: 'string' },
                applicabilityConfirmed: { type: 'boolean', description: 'the detected version is actually within the affected range' },
                poc: {
                  type: 'object',
                  properties: { available: { type: 'boolean' }, ref: { type: 'string' }, kind: { type: 'string' } },
                },
                roeSafe: { type: 'boolean', description: 'true ONLY if a NON-DESTRUCTIVE proof exists; false = crash/DoS/memory-corruption class => research-only, do NOT run on a live host' },
                exploitability: { type: 'string' },
              },
              required: ['id'],
            },
          },
        },
        required: ['name'],
      },
    },
  },
  required: ['components'],
}

// Subtask-generator output.
const GEN_SCHEMA = {
  type: 'object',
  properties: {
    subtasks: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          title: { type: 'string' },
          goal: { type: 'string', description: 'what success looks like (a concrete finding to prove or refute)' },
          track: { type: 'string', enum: ['web', 'host'] },
          target: { type: 'string' },
          phase: { type: 'string', description: 'recon/enum/vuln/exploit/postex' },
        },
        required: ['id', 'title', 'goal', 'track', 'target'],
      },
    },
  },
  required: ['subtasks'],
}

// Solver output — captured, not discarded.
const SOLVE_SCHEMA = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          subtaskId: { type: 'string' },
          title: { type: 'string' },
          track: { type: 'string', enum: ['web', 'host'] },
          target: { type: 'string' },
          status: { type: 'string', enum: ['confirmed', 'attempted', 'failed'] },
          severity: { type: 'string' },
          evidence: { type: 'string', description: 'exact commands + trimmed output proving the result' },
        },
        required: ['title', 'status'],
      },
    },
    notes: { type: 'string', description: 'what worked, what failed, and why — feeds the refiner' },
  },
  required: ['findings'],
}

// Adversarial verifier output.
const VERIFY_SCHEMA = {
  type: 'object',
  properties: {
    verified: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          title: { type: 'string' },
          real: { type: 'boolean' },
          confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
          reason: { type: 'string' },
          severity: { type: 'string' },
        },
        required: ['title', 'real'],
      },
    },
  },
  required: ['verified'],
}

// Refiner output — adapts the next round.
const REFINE_SCHEMA = {
  type: 'object',
  properties: {
    done: { type: 'boolean', description: 'true if the objective is met or no productive avenue remains' },
    rationale: { type: 'string' },
    subtasks: {
      type: 'array', description: 'the adapted subtask set for the NEXT round',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          title: { type: 'string' },
          goal: { type: 'string' },
          track: { type: 'string', enum: ['web', 'host'] },
          target: { type: 'string' },
        },
        required: ['id', 'title', 'goal', 'track', 'target'],
      },
    },
  },
  required: ['done', 'subtasks'],
}

// ---------------- helpers ----------------
const clip = (s, n) => { const t = String(s == null ? '' : s); return t.length > n ? t.slice(0, n) + ' …[clipped]' : t }
const summarizeFindings = (fs) => (fs || []).map((f) =>
  `- [${f.status || '?'}${f.severity ? '/' + f.severity : ''}] ${f.title}${f.target ? ' @' + f.target : ''}${f.track ? ' (' + f.track + ')' : ''}` +
  (f.evidence ? ` — ${clip(f.evidence, 300)}` : '')).join('\n')
const summarizeCVEs = (d) => ((d && d.components) || []).map((c) => {
  const cves = (c.cves || []).map((v) =>
    `${v.id}${v.cvss ? '(' + v.cvss + ')' : ''}` +
    `${v.applicabilityConfirmed ? ' AFFECTED' : ' (applicability?)'}` +
    `${v.poc && v.poc.available ? ' PoC' : ''}` +
    `${v.roeSafe === false ? ' [UNSAFE:research-only]' : (v.roeSafe ? ' [RoE-safe]' : '')}`).join(', ')
  return `- ${c.name}${c.version ? ' ' + c.version : ''}${c.eol ? ' [EOL]' : ''}: ${cves || 'no notable CVEs'}`
}).join('\n')

// ==================== MEMORY: read prior notes at start ====================
phase('Recon')
const memoryBrief = await agent(
  `You are the long-term MEMORY specialist (read-only archivist). Before the engagement begins, retrieve any ` +
  `prior knowledge relevant to this objective so the team does not re-derive what is already known.\n\n` +
  `OBJECTIVE: ${objective}\nIN-SCOPE: ${scopeLine}\n\n` +
  `Do this with Bash:\n` +
  `1. mkdir -p "${MEM_DIR}"   (the store may not exist yet)\n` +
  `2. ls -1 "${MEM_DIR}" 2>/dev/null; then grep -rIl -i -E '<the specific tools/services/CVEs/app-names implied ` +
  `by the objective>' "${MEM_DIR}" 2>/dev/null and read the matching *.md notes (cat them).\n` +
  `Search with PRECISE terms (exact tool names, service versions, app names, CVEs), not vague words like "findings".\n\n` +
  `Return a concise historical-context brief: relevant techniques/findings/pitfalls with their source note filenames, ` +
  `or an explicit "no relevant prior memory" if the store is empty or nothing matches. Do NOT modify memory.`,
  { label: 'memory:read', phase: 'Recon', agentType: 'general-purpose' }
)
log('memory: ' + clip(memoryBrief, 160))

// ==================== RECON: fingerprint + classify + component inventory ====================
const recon = await agent(
  `You are an elite recon specialist. OBJECTIVE: ${objective}. Primary target: ${target}. ${RULES}\n\n` +
  `PRIOR MEMORY (may be empty — use it, don't repeat known work):\n${clip(memoryBrief, 1200)}\n\n` +
  `1. For EACH in-scope target, FINGERPRINT it and CLASSIFY its track:\n` +
  `   - web => a web application / HTTP service (URL, SPA, REST API): use the WEB track (agent-browser). Enumerate ` +
  `     SPA routes (parse client JS for hidden/gated routes), REST/API endpoints, and technologies/versions.\n` +
  `   - host => an IP/host exposing non-web services (SSH, SMB, DB, RPC, custom TCP, etc.): use the NETWORK/HOST ` +
  `     track (Kali sandbox). Run \`bash "${SANDBOX}" up\` then a TCP connect scan \`nmap -Pn -sT -sV\` and service ` +
  `     enumeration THROUGH the sandbox to map open ports/versions.\n` +
  `   A single target can need BOTH tracks (e.g. a host running a web app + SSH) — classify by the dominant surface ` +
  `   and note the secondary services in \`services\`.\n` +
  `2. IDENTIFY the application(s)/version(s) and map the attack surface into \`surfaceNotes\`.\n` +
  `3. COMPONENTS & VERSIONS: record EVERY software/framework/library/server component you fingerprint (server ` +
  `   headers, X-Powered-By, JS/asset bundles, service banners, TLS stack, CMS/plugins) with its version, and set ` +
  `   eol=true for any end-of-life / unsupported / clearly outdated one. A dedicated CVE-research stage consumes this ` +
  `   list, so be thorough and precise about versions.`,
  { label: 'recon', phase: 'Recon', agentType: 'general-purpose', schema: RECON_SCHEMA }
)
log('recon: ' + (recon && recon.appIdentity))
const targetsList = (recon && Array.isArray(recon.targets) ? recon.targets : [])
  .map((t) => `${t.target} [${t.track}]${t.services ? ' ' + t.services : ''}`).join('; ')
log('targets: ' + clip(targetsList, 200))

// ==================== CVE ENRICHMENT: version -> CVE -> PoC (searcher role) ====================
// Turn recon's detected components/versions into researched, applicability-checked, RoE-classified
// CVE intel that the generator/refiner convert into targeted (gated) exploit subtasks.
phase('Plan')
const components = (recon && Array.isArray(recon.components)) ? recon.components : []
let cveBrief = ''
if (components.length) {
  const cveData = await agent(
    `You are the SEARCHER / CVE-research specialist. Fingerprinted components (from recon):\n` +
    components.map((c) => `- ${c.name}${c.version ? ' ' + c.version : ''}${c.eol ? ' [flagged EOL/outdated]' : ''}${c.where ? ' (' + c.where + ')' : ''}`).join('\n') +
    `\n\nFor each component — PRIORITISING end-of-life / outdated ones — research known CVEs and public exploits:\n` +
    `- CVE WEB lookups run HOST-SIDE (agent-browser to NVD / vendor advisories / Exploit-DB / GitHub Security ` +
    `Advisories, or WebSearch) because the Kali sandbox egress is locked to the target only.\n` +
    `- Use the sandbox's LOCAL offline exploit database for PoC discovery: bash "${SANDBOX}" exec "searchsploit <product> <version>".\n\n` +
    `For each relevant CVE, report: id, CVSS, one-line summary, the affected version range and whether the DETECTED ` +
    `version is actually within it (applicabilityConfirmed), whether a public PoC/exploit exists (poc.available + ref + kind), ` +
    `and an exploitability note.\n\n` +
    `SAFETY / RULES OF ENGAGEMENT: ${RULES}\n` +
    `- STUDY the technique for every relevant CVE (understanding is always in-bounds). But set roeSafe=true ONLY when a ` +
    `NON-DESTRUCTIVE proof is possible (version confirmation, a benign marker, a bounded time-delay). Memory-corruption / ` +
    `crash-prone / DoS-class exploits are roeSafe=false — research-only, NEVER run them against a live host.\n` +
    `- Do NOT download and blindly execute untrusted PoC binaries; describe the technique so the pentester can ` +
    `reconstruct a minimal, safe test.`,
    { label: 'cve:enrich', phase: 'Plan', agentType: 'general-purpose', schema: CVE_SCHEMA }
  )
  cveBrief = summarizeCVEs(cveData)
  log('cve-enrichment:\n' + clip(cveBrief, 400))
}

// ==================== PLAN: decompose the objective into finding-based subtasks ====================
const gen = await agent(
  `You are the SUBTASK GENERATOR (planner). Decompose the objective into the SMALLEST ordered set of ` +
  `single-purpose, finding-based subtasks that proves or refutes concrete weaknesses on the in-scope targets. ` +
  `No busywork, no permission-seeking, at most 8 subtasks. ${RULES}\n\n` +
  `OBJECTIVE: ${objective}\n` +
  `CLASSIFIED TARGETS (set each subtask's \`track\` to match the target's surface):\n${targetsList || '(none reported)'}\n` +
  `RECON SURFACE NOTES: ${clip(recon && recon.surfaceNotes, 800)}\n` +
  `PRIOR MEMORY: ${clip(memoryBrief, 800)}\n` +
  `CVE INTEL (from the CVE-research stage). Turn each AFFECTED, [RoE-safe] CVE — especially on EOL/outdated ` +
  `components — into a targeted, NON-DESTRUCTIVE exploit subtask. For [UNSAFE:research-only] CVEs, add only a ` +
  `version-confirmation / analysis subtask, NEVER an exploit attempt:\n${clip(cveBrief || '(no components enriched)', 900)}\n\n` +
  `Roughly: ~10% setup, ~30% enumeration, ~30% evaluation/confirmation, ~30% focused exploitation. For WEB ` +
  `targets include browser-driven subtasks (DOM/XSS, authenticated API abuse via in-page fetch, IDOR/authz, ` +
  `injection reachable only through the rendered app). For HOST targets include sandbox-driven subtasks (service ` +
  `enum, version-based vuln analysis, targeted exploitation). Each subtask names its target and track.`,
  { label: 'generate', phase: 'Plan', agentType: 'general-purpose', schema: GEN_SCHEMA }
)
let subtasks = (gen && Array.isArray(gen.subtasks) ? gen.subtasks : [])
  .map((s, i) => ({ id: s.id || `st${i + 1}`, ...s }))
log(`generated ${subtasks.length} finding-based subtasks`)
if (bounty) {
  log(`BUG-BOUNTY MODE — attribution "${bHeader}: ${bHandle || '(unset!)'}", ~${bRps} req/s, ` +
    `concurrency ${bConc}, RoE from ${bRulesFile}${bExclude ? `, excluding ${bExclude}` : ''}`)
}

// ==================== LOOP: exploit -> verify -> refine, until dry ====================
const trustedFindings = []
let priorOutcomes = ''
for (let round = 1; round <= maxRounds; round++) {
  const active = subtasks.filter((s) => s && s.title)
  if (!active.length) { log('no remaining subtasks — stopping'); break }

  phase('Exploit')
  const solveOne = (st, i) => agent(
    `You are an elite penetration tester working ONE subtask to a clear conclusion. ${RULES}\n\n` +
    `SUBTASK [${st.id}] ${st.title}\nGOAL: ${st.goal || st.title}\nTARGET: ${st.target || target}\n` +
    `TRACK: ${st.track === 'host' ? 'NETWORK/HOST — run tooling through the Kali sandbox (nmap -Pn -sT -sV, ' +
      'service enum, sqlmap, searchsploit, etc.)' : 'WEB — drive agent-browser (session "solve_r' + round + '_' + i +
      '"): open/snapshot/click/fill for DOM, in-page fetch() for same-origin API abuse'}\n` +
    `Use session/isolation name "solve_r${round}_${i}" for any agent-browser work.\n\n` +
    (cveBrief ? `CVE INTEL for the fingerprinted stack (only attempt [RoE-safe] CVEs non-destructively; ` +
      `[UNSAFE:research-only] = confirm affected version but DO NOT run the exploit):\n${clip(cveBrief, 700)}\n\n` : '') +
    (priorOutcomes ? `WHAT PRIOR ROUNDS FOUND/FAILED (adapt — don't repeat dead ends):\n${clip(priorOutcomes, 1200)}\n\n` : '') +
    `Capture REPRODUCIBLE evidence (exact command + trimmed output). Be honest about negative results — ` +
    `"no vulnerability confirmed" is a valid finding. Do NOT overclaim: the verifier will try to refute every ` +
    `claim, and unproven claims are discarded. Return structured findings with subtaskId="${st.id}".`,
    { label: `solve:${st.id}`, phase: 'Exploit', agentType: 'general-purpose', schema: SOLVE_SCHEMA }
  )
  // Bug-bounty mode caps concurrency so the fan-out can't exceed the program's rate
  // limit: run solvers in fixed-size chunks instead of all at once. Normal mode fans
  // out fully (the workflow runtime still applies its own global concurrency cap).
  let results = []
  if (bounty) {
    for (let off = 0; off < active.length; off += bConc) {
      const chunk = active.slice(off, off + bConc)
      const r = await parallel(chunk.map((st, j) => () => solveOne(st, off + j)))
      results.push(...r)
    }
  } else {
    results = await parallel(active.map((st, i) => () => solveOne(st, i)))
  }
  const roundFindings = results.flatMap((r) => (r && r.findings) || [])
  const claimed = roundFindings.filter((f) => f && f.status !== 'failed')
  log(`round ${round}: ${roundFindings.length} findings (${claimed.length} claimed non-failed)`)

  // adversarial VERIFIER — confirm each claimed finding before it is trusted.
  phase('Verify')
  let verified = { verified: [] }
  if (claimed.length) {
    verified = await agent(
      `You are the adversarial FINDING VERIFIER (a skeptic). Default assumption: each claimed finding is NOT real ` +
      `until its evidence proves it. ${RULES}\n\n` +
      `For EACH claimed finding below: (1) check the captured evidence actually demonstrates the vulnerability ` +
      `(not a WAF banner, version-only inference, or a coincidental error page); (2) if cheap and in-scope, ` +
      `REPRODUCE it — network/host findings via \`bash "${SANDBOX}" exec "<cmd>"\`, web findings via agent-browser ` +
      `(session "verify_r${round}"). Mark real=false when uncertain — a discarded true finding is recoverable, a ` +
      `shipped false positive is not.\n\nCLAIMED FINDINGS:\n${summarizeFindings(claimed)}`,
      { label: `verify:r${round}`, phase: 'Verify', agentType: 'general-purpose', schema: VERIFY_SCHEMA }
    )
    const confirmed = (verified.verified || []).filter((v) => v && v.real)
    for (const v of confirmed) trustedFindings.push(v)
    log(`round ${round}: verifier confirmed ${confirmed.length}/${(verified.verified || []).length}`)
  }

  // REFINER edge — adapt the next round from what was found/failed.
  priorOutcomes = `Round ${round} claimed:\n${summarizeFindings(roundFindings)}\n` +
    `Verifier verdicts: ${(verified.verified || []).map((v) => `${v.title}=${v.real ? 'REAL' : 'refuted'}`).join('; ') || 'n/a'}\n` +
    results.map((r) => r && r.notes).filter(Boolean).join('\n')

  if (round < maxRounds) {
    phase('Refine')
    const refined = await agent(
      `You are the plan REFINER. Adapt the remaining engagement plan based on this round's results — add subtasks a ` +
      `result revealed the need for (a discovered service to enum, a confirmed injection point to exploit deeper), ` +
      `remove moot ones, sharpen goals, and reorder toward the highest-value path. After ~2 similar failures on an ` +
      `approach, PIVOT to a different tactic rather than repeating it. Converge on the objective; at most 8 subtasks; ` +
      `in-scope only; keep each subtask's track/target correct. ${RULES}\n\n` +
      `OBJECTIVE: ${objective}\n` +
      `THIS ROUND'S OUTCOMES:\n${clip(priorOutcomes, 1600)}\n\n` +
      `TRUSTED (verified) FINDINGS SO FAR:\n${summarizeFindings(trustedFindings) || '(none yet)'}\n\n` +
      (cveBrief ? `CVE INTEL (prioritise turning still-untested AFFECTED [RoE-safe] CVEs into next-round exploit ` +
        `subtasks; keep [UNSAFE:research-only] ones as analysis-only):\n${clip(cveBrief, 700)}\n\n` : '') +
      `Return the adapted subtask set for the NEXT round. Set done=true (empty subtasks) if the objective is met or ` +
      `no productive avenue remains.`,
      { label: `refine:r${round}`, phase: 'Refine', agentType: 'general-purpose', schema: REFINE_SCHEMA }
    )
    if (refined && refined.done) { log(`refiner: done — ${clip(refined.rationale, 160)}`); break }
    subtasks = (refined && Array.isArray(refined.subtasks) ? refined.subtasks : [])
      .map((s, i) => ({ id: s.id || `r${round + 1}_st${i + 1}`, ...s }))
    log(`round ${round}: refiner set ${subtasks.length} subtasks for next round`)
  }
}

// ==================== REPORT ====================
phase('Report')
const finalReport = await agent(
  `Write a concise final report for this engagement. OBJECTIVE: ${objective}. Targets (${recon && recon.appIdentity}): ` +
  `${targetsList}. Findings were adversarially verified before being trusted.\n\n` +
  `TRUSTED (VERIFIED) FINDINGS:\n${summarizeFindings(trustedFindings) || '(none confirmed)'}\n\n` +
  `Summarize the confirmed vulnerability classes and highest-impact findings (with evidence), note which subtasks ` +
  `produced nothing and why those avenues were hard, and give clear remediation. Be honest and specific — do not ` +
  `overclaim beyond what the verifier confirmed.`,
  { label: 'report', phase: 'Report', agentType: 'general-purpose' }
)

// ==================== MEMORY: write an anonymized guide back to the store ====================
await agent(
  `You are the MEMORY WRITER. Persist a reusable, ANONYMIZED guide note so future engagements benefit from what was ` +
  `learned here. Write with Bash:\n` +
  `1. mkdir -p "${MEM_DIR}"\n` +
  `2. Write a new markdown file at "${MEM_DIR}/guide-<short-slug>-<epoch>.md" (use \`date +%s\` for the epoch).\n\n` +
  `The note MUST be ANONYMIZED: NO real IPs, hostnames, URLs, credentials, tokens, or client-identifying names. ` +
  `Generalize to the app class / service type / technique (e.g. "a Rails/Passenger SPA behind a CDN", "SMB on an ` +
  `unpatched Windows host", "an outdated Elasticsearch node"). Capture: the app/service class, which track applied ` +
  `(web via agent-browser vs host via the Kali sandbox), the techniques that WORKED, the dead ends to avoid, and any ` +
  `reusable payloads/commands (with secrets redacted). Keep it short (a technique note, not a report).\n\n` +
  `APP/TARGETS: ${clip(recon && recon.appIdentity, 300)} — ${clip(targetsList, 300)}\n` +
  `FINAL REPORT TO DISTILL (anonymize before writing):\n${clip(finalReport, 2500)}\n\n` +
  `After writing, confirm the file path you created.`,
  { label: 'memory:write', phase: 'Report', agentType: 'general-purpose' }
)

return {
  appIdentity: recon && recon.appIdentity,
  targets: targetsList,
  trustedFindings: trustedFindings.length,
  report: finalReport,
}
