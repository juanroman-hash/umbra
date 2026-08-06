# Umbra — Architecture

Detailed diagrams of how Umbra runs an engagement. Umbra is an autonomous, multi-agent
penetration-testing plugin for Claude Code: a recon-first orchestration engine that fans
specialist agents across two execution tracks behind hard guardrails.

---

## 1. End-to-end engagement flow

The `workflows/engagement.js` engine. Everything is preceded by a hard authorization gate;
the core is an adaptive **exploit → verify → refine** loop that runs until it goes dry.

```mermaid
flowchart TD
    A([/pentest target]) --> G{Authorization gate}
    G -->|"no scope / no auth"| STOP([Refuse — establish scope + written authz first])
    G -->|"scope.txt + authz + sandbox up"| M[memorist: read prior guides from .umbra/memory]

    M --> R[recon: fingerprint + classify each target + inventory components/versions]
    R --> C[searcher: CVE enrichment - version to affected-CVE to PoC, RoE-classified]
    C --> P[generator: decompose objective into finding-based subtasks]

    P --> LOOP{{Round loop, up to maxRounds}}
    LOOP --> X[exploit: parallel solvers, one per subtask]
    X --> V[verifier: adversarially reproduce each claim]
    V --> RF{refiner: done?}
    RF -->|"more to test"| LOOP
    RF -->|"dry / objective met"| REP[reporter: verified findings only]

    REP --> W[memorist: write anonymized guide back to .umbra/memory]
    W --> OUT([Report + persisted memory])

    classDef gate fill:#3b0a0a,stroke:#e05252,color:#fff;
    classDef work fill:#1f2933,stroke:#7aa2c2,color:#fff;
    classDef done fill:#0a2e1a,stroke:#4caf7d,color:#fff;
    class G,STOP gate;
    class M,R,C,P,X,V,REP,W work;
    class OUT,LOOP,RF done;
```

Key properties:

- **Nothing is trusted until reproduced.** Every claimed finding is re-run by an adversarial
  verifier that defaults to "not real" and tries to refute it; unproven claims are discarded.
- **Findings are captured and fed forward.** Each round's results steer the refiner, which
  adapts the next round (add follow-ups, drop dead ends, pivot after repeated failure).
- **Memory closes the loop.** Prior guides are read at the start; an anonymized guide is
  written at the end.

---

## 2. Two execution tracks

Recon classifies each target; the pentester picks the track per subtask. `agent-browser`
is web-only; everything host/network goes through the Kali sandbox.

```mermaid
flowchart LR
    ST[Subtask + target] --> Q{Target / service type?}

    Q -->|"web app / HTTP / DOM"| WEB[WEB track: agent-browser CLI]
    Q -->|"host / service / network"| HOST[NETWORK track: Kali Docker sandbox]

    WEB --> W1["open / snapshot / click / fill (DOM)"]
    WEB --> W2["eval + in-page fetch (same-origin API abuse)"]

    HOST --> H1["nmap -Pn -sT -sV, service enum"]
    HOST --> H2["sqlmap / nikto / gobuster / whatweb"]
    HOST --> H3["searchsploit, hydra (RoE permitting)"]
    HOST --> H4["metasploit (opt-in)"]

    W1 & W2 & H1 & H2 & H3 & H4 --> EV[Structured finding + reproducible evidence]

    classDef web fill:#0a1f33,stroke:#5aa0e0,color:#fff;
    classDef host fill:#241a0a,stroke:#d0a24a,color:#fff;
    class WEB,W1,W2 web;
    class HOST,H1,H2,H3,H4 host;
```

---

## 3. Guardrails — defense in depth

Two **independent** controls enforce scope: a PreToolUse hook blocks the *command*, and the
sandbox's egress firewall blocks the *packet*. Either alone would suffice; together a mistake
has to defeat both.

```mermaid
flowchart TD
    CMD[Agent issues a Bash command] --> HOOK{{scope-gate.sh — PreToolUse hook}}

    HOOK --> NB{Known network binary?<br/>nmap/curl/hydra/ssh/...}
    NB -->|no network binary, no target| ALLOW1([ALLOW])
    NB -->|yes| TGT{Extract targets<br/>FQDN / IPv4 / IPv6 / bare host / URL}

    TGT -->|"-iL / -iR file-list"| DENY1([DENY — cannot scope-check a file])
    TGT -->|no resolvable target| DENY2([DENY — default-deny])
    TGT --> SC{All targets in .umbra/scope.txt<br/>or loopback?}
    SC -->|no| DENY3([DENY — out of scope])
    SC -->|yes| ALLOW2([ALLOW])

    ALLOW2 --> EXEC[Command runs]
    EXEC --> INSANDBOX{Runs inside Kali sandbox?}
    INSANDBOX -->|yes| FW{{iptables egress — seeded from scope.txt}}
    FW -->|"dst in scope"| NET([Packet leaves to target])
    FW -->|"dst out of scope"| DROP([DROP / REJECT])

    classDef deny fill:#3b0a0a,stroke:#e05252,color:#fff;
    classDef allow fill:#0a2e1a,stroke:#4caf7d,color:#fff;
    classDef gate fill:#1f2933,stroke:#7aa2c2,color:#fff;
    class DENY1,DENY2,DENY3,DROP deny;
    class ALLOW1,ALLOW2,NET allow;
    class HOOK,FW,NB,TGT,SC,INSANDBOX gate;
```

The sandbox itself is a disposable Kali container: own bridge network, `--cap-drop=ALL`,
`--security-opt no-new-privileges`, `--pids-limit`, `--memory`, and egress default-deny.

---

## 4. Agent roster

15 specialist roles. In the `engagement.js` workflow they run as `general-purpose` agents
with the role carried inline (the workflow engine can't spawn plugin agent types); as durable
`agents/*.md` they're available via the Task tool and after `/reload-plugins`.

```mermaid
graph TD
    ORCH[orchestrator<br/>central delegator]

    subgraph Planning
        GEN[generator<br/>decompose]
        REF[refiner<br/>adapt plan]
    end
    subgraph Workers
        PEN[pentester]
        COD[coder]
        INS[installer]
        SEA[searcher / CVE research]
    end
    subgraph Supervision
        VER[verifier<br/>refute claims]
        RFL[reflector<br/>tool-call barrier]
        ADV[adviser<br/>mentor]
        ENR[enricher<br/>context]
    end
    subgraph Memory
        MEM[memorist<br/>recall]
        SUM[summarizer<br/>compress]
    end
    subgraph Output
        REP[reporter]
        AST[assistant<br/>human steering]
    end

    ORCH --> GEN --> PEN
    ORCH --> PEN
    PEN -->|"needs a CVE/PoC"| SEA
    PEN -->|"needs tooling"| INS
    PEN -->|"needs exploit code"| COD
    PEN -->|"stuck"| ADV
    ADV --> ENR
    PEN --> VER
    ORCH --> MEM
    ORCH --> REF
    ORCH --> REP
    VER -.->|"prose not tool call"| RFL
```

---

## 5. CVE enrichment

Recon's component/version inventory drives a dedicated research stage. Web CVE lookups run
host-side (the sandbox egress is target-locked); `searchsploit` runs inside the sandbox.

```mermaid
flowchart TD
    RC[recon: components + versions, EOL flagged] --> S[searcher / CVE research]

    S --> WEB["host-side lookups: NVD, Exploit-DB, vendor advisories"]
    S --> SS["sandbox: searchsploit product version (offline DB)"]

    WEB & SS --> PER{Per CVE}
    PER --> APP{Detected version actually affected?}
    APP -->|no| DROP([drop — not applicable])
    APP -->|yes| SAFE{Non-destructive proof possible?}
    SAFE -->|"yes — version check / benign marker / time delay"| GATED[roeSafe = true → targeted exploit subtask]
    SAFE -->|"no — crash / DoS / memory-corruption"| RESEARCH[roeSafe = false → analysis-only subtask]

    GATED & RESEARCH --> GEN[fed into generator / refiner]

    classDef safe fill:#0a2e1a,stroke:#4caf7d,color:#fff;
    classDef unsafe fill:#3b2a0a,stroke:#d0a24a,color:#fff;
    class GATED safe;
    class RESEARCH,DROP unsafe;
```

**Never run untrusted PoC binaries blindly** — the searcher studies the technique so the
pentester reconstructs a minimal, safe test. EOL/outdated components are prioritized.

---

## 6. One round — sequence

```mermaid
sequenceDiagram
    participant O as Orchestrator (engagement.js)
    participant S as Solvers (parallel)
    participant T as Track (agent-browser / Kali sandbox)
    participant V as Verifier
    participant R as Refiner

    O->>S: dispatch N subtasks (with CVE intel + prior-round notes)
    par each subtask
        S->>T: run tooling (in-scope, RoE-gated)
        T-->>S: evidence (commands + output)
    end
    S-->>O: structured findings (confirmed / attempted / failed)
    O->>V: verify claimed findings
    V->>T: reproduce cheaply, try to refute
    T-->>V: reproduction result
    V-->>O: real / refuted per finding
    O->>R: this round's outcomes + trusted findings
    R-->>O: adapted subtasks (or done=true)
    Note over O: loop until dry, then report + persist memory
```

---

## 7. Structured-data handoff between stages

Stages don't pass prose — each agent returns a **schema-validated object** (`agent(..., { schema })`
forces the model to a structured tool call and re-prompts on mismatch), so every handoff is typed
and machine-checkable. This is what makes the loop deterministic to orchestrate. Schemas live at the
top of `workflows/engagement.js`.

```mermaid
flowchart LR
    MEM["memoryBrief<br/><i>(prose)</i>"] --> RECON
    RECON["recon<br/>RECON_SCHEMA"] -->|"targets[].track<br/>components[] + eol"| CVE["searcher<br/>CVE_SCHEMA"]
    RECON -->|"surfaceNotes<br/>appIdentity"| GEN
    CVE -->|"cves[]: applicabilityConfirmed<br/>+ roeSafe"| GEN["generator<br/>GEN_SCHEMA"]

    GEN -->|"subtasks[]: track, target, goal"| SOLVE["solvers ×N<br/>SOLVE_SCHEMA"]
    SOLVE -->|"findings[]: status<br/>confirmed / attempted / failed<br/>+ evidence"| VER["verifier<br/>VERIFY_SCHEMA"]
    VER -->|"verified[]: real = true/false"| TRUST[(trustedFindings)]
    VER -->|"verdicts + notes"| REFINE["refiner<br/>REFINE_SCHEMA"]

    REFINE -->|"done = false<br/>subtasks[] for next round"| SOLVE
    REFINE -->|"done = true"| REPORT["reporter<br/><i>(prose report)</i>"]
    TRUST --> REPORT
    REPORT --> WRITE["memory writer<br/>anonymized guide.md"]

    classDef schema fill:#1f2933,stroke:#7aa2c2,color:#fff;
    classDef prose fill:#241a0a,stroke:#d0a24a,color:#fff;
    classDef store fill:#0a2e1a,stroke:#4caf7d,color:#fff;
    class RECON,CVE,GEN,SOLVE,VER,REFINE schema;
    class MEM,REPORT,WRITE prose;
    class TRUST store;
```

Only two boundaries are deliberately free-form: the **memory brief** in (read prior guides) and the
**final report / persisted guide** out. Everything the loop reasons over in between is a validated
object, and only `verified[].real === true` findings ever reach `trustedFindings` — the single source
the report is written from.
