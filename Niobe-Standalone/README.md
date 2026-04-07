# Niobe

**Niobe** è una suite snella di Audit per attività di Digital Audit, technical intelligence, due diligence, con produzione di deliverable completi e auditabili.

- **Creatore**: Mattia C.
- **Azienda**: Tecnolife
- **Data**: aprile 2026
- **Licenza**: GPL-2.0 (vedi `LICENSE.md`)
- **Python**: >= 3.11 (Python 3.10 è in grace period, raggiunge EoS a fine ottobre 2026)

## SCOPO

Niobe ha la finalità di eseguire audit software in modo ripetibile, leggibile e difendibile. Il progetto privilegia una pipeline **smart**: pochi passaggi ma chiari, evidenze forensi firmate e robuste, scoring deterministico basato attualmente su un HLD e un layer LLM unico ma governato da gate logici stadiali stretti.

L'obiettivo operativo è produrre una Delivery finale adatta a contesti di audit, due diligence, procurement critico, governance tecnica e review executive, senza trasformare la pipeline in un sistema pesante od opaco: un layer di audit intelligence smart e snello.

## OPERATIVITÀ

Niobe:
- acquisisce il repository target e ne congela l'identità con digestione SHA-512 e manifest probatorio;
- esegue uno stack di analisi statiche, SAST, SBOM, secret scanning e OSS/compliance review;
- correla le evidenze e applica una revisione AI profonda sul codice core e custom dell'applicativo;
- produce deliverable finali in Word, PDF, Excel e JSON, con firme detached GPG e marche temporali blockchain;
- organizza la Delivery finale in modo coerente con use case cliente, control plane (beta) e modalità standalone.

## PIPELINE

La pipeline logica di Niobe è articolata nei seguenti gate:
1. **Normalizzazione**
2. **Clustering**
3. **Triage**
4. **Reporting**

Questi gate non servono a frammentare artificialmente il giudizio. Servono a separare in modo netto l'acquisizione delle evidenze, la correlazione dei finding, la revisione profonda del codice e la stesura finale dei deliverable.


## ESECUZIONE

Eseguire lo script/launcher dalla root del progetto con `./digital-audit`. Costruirà la build dell'immagine se necessario, poi alcune interazioni:
1. Provider LLM scelto (Anthropic Claude / OpenAI Codex)
2. Tipo di attività: Audit, Digital-Audit (default), Due Diligence, Check di SSDLC
3. Path del repository target
4. Nome del progetto e del cliente

Il software contiene il necessario di un friendly Linux CLI, con `--help` dettagliato.
Contiene una logica per intercettare e fare clean-up in caso di SIGTERM.

## FUNZIONALITÀ

- CLI funny and friendly `digital-audit` per installazione, login, esecuzione audit e packaging finale. Il launcher "./digital-audit" fa tutto. Un paio di interazioni con l'utente per conoscere il progetto da scansionare, il provider scelto, i nominativo del cliente. Fine. 
- Modalità standalone (operativa) e modalità control plane.(beta)
- Runner Linux containerizzato (secondo standard di container Security nel montaggio della pocket) per la raccolta deterministica delle evidenze.
- Supporto provider LLM host-side: Anthropic Claude Code (default: `claude-sonnet-4-6` con thinking) e OpenAI Codex CLI.
- Retry logic con backoff esponenziale (3 tentativi) su tutte le chiamate LLM, per entrambi i provider.
- Prompt LLM passato via stdin (non come argomento CLI xoxo) per sicurezza e compatibilità con repository grandi.
- Scoring HLD a 8 dimensioni con grade A-E e classificazione transazionale.
- Risk Register `.xlsx` e report finale `AI Technical Intelligence Review.docx/.pdf`.
- Grafici e diagrammi (topologia, heatmap rischi, distribuzione linguaggi) generati via matplotlib e inseriti nel DOCX/PDF.
- Evidence chain con `evidence-manifest.json` (incluso hashing SHA-512 per-file di ogni file del target), firme GPG detached e OTS.
- Supply chain review con SBOM CycloneDX, OWASP Dependency-Check, OSS artifact e compliance artifact.
- Frontend remoto per control plane e visibilità della delivery, passando per load balancer (beta)

## STRUCT

```
.
├── Python3/                      Moduli Python (audit, claude, reporting, scoring, provenance, ecc.)
│   ├── audit.py                  Orchestrazione pipeline (parallelizzazione tool, signal handler)
│   ├── claude.py                 Astrazione provider LLM (retry, thinking, stdin prompt)
│   ├── reporting.py              Rendering DOCX/PDF (matplotlib, rich text, barra blu)
│   ├── scoring.py                Scoring HLD a 8 dimensioni, grade A-E
│   ├── provenance.py             Manifest, firme GPG, OTS, hashing SHA-512 per-file
│   ├── risk_register.py          Registro dei rischi e artefatti HLD
│   ├── deep_review.py            Revisione profonda post-correlazione sul codice
│   └── ...                       (cli, detect, installer, metrics, models, parsers, ecc.)
├── LLMs/
│   └── prompts/                  Prompt per reporting, triage, deep review e compliance
├── templates/                    Template DOCX/Jinja2, HLD, engagement, fontconfig, fonts
│   ├── template.docx             Template grafico di riferimento per il report
│   ├── *.j2                      Template Jinja2 (markdown, HTML)
│   ├── fontconfig/               Alias font per Linux
│   ├── fonts/                    Font Aptos (inserire .ttf qui per Linux)
│   └── ...                       (engagement, risk register template, bootstrap, HLD)
├── Docker/
│   ├── Dockerfile                Immagine base
│   └── Dockerfile.audit          Runner Linux (Semgrep, ScanCode, Syft, Gitleaks, Dependency-Check)
├── ControlPlane_beta/            Frontend e docker-compose per control plane remoto (beta)
│   ├── web/                      app.js, index.html, styles.css
│   └── docker-compose.yml
├── scripts/
│   └── digital-audit             Launcher cross-distro (Debian/RHEL/macOS)
├── dependency-check-data/        Database NVD pre-scaricato, delta update a runtime
├── ops/ansible/                  Playbook di deployment e hardening
├── LICENSE.md                    GPL-2.0
├── pyproject.toml                Configurazione progetto Python
└── README.md
```

## OUTPUT (che non ti aspetti xoxo)

La directory di riferimento (ripulita in caso di nuovo scan, in automatico) è la temp-delivery nella root del progetto, anche la cli indicherà a fine del processo i path, in ogni caso.
Una run standalone produce tipicamente:
- `temp-delivery/Reports/` con gli artefatti tecnici dei tool;
- `temp-delivery/Delivery/` con i deliverable cliente finali;
- `temp-delivery/Delivery/signatures/` con le firme detached e le marche temporali;
- `temp-delivery/AI_DA.zip` e `temp-delivery/AI_DA.zip.asc` come pacchetto finale sigillato read-to-send al cliente.

I deliverable principali includono:
- `AI Technical Intelligence Review.docx`
- `AI Technical Intelligence Review.pdf`
- `Risk Register.xlsx`
- `sbom.cyclonedx.json`
- `Compliance Artifact.pdf`
- `OSS Provenance Report (Copyleft Risk).pdf`
- `evidence-manifest.json`

## VARIA

- Il runner di raccolta evidenze è Linux-first e containerizzato.
- La selezione del provider LLM è esplicita e autenticata prima della review.
- La raccolta evidenze resta separata dalla fase di ragionamento LLM.
- I tool di evidence collection vengono eseguiti in **parallelo** (configurabile via `NIOBE_TOOL_WORKERS`, default 4).
- Resilienza a interruzioni: signal handler `SIGINT/SIGTERM` che termina i container Docker attivi e pulisce i file temporanei.
- Se l'LLM fallisce dopo tutti i retry, la pipeline prosegue con i soli dati deterministici; il report può essere rigenerato con `finalize`.
- Il database NVD per OWASP Dependency-Check è pre-scaricato nel progetto (`dependency-check-data/`) e montato nel container a build-time. A ogni esecuzione, viene aggiornato con un delta update prima dello scan, garantendo dati di vulnerability sempre aggiornati senza download completi ripetuti.
- Se la versione di Python3 installata è inferiore alla 3.11, il launcher prova ad aggiornarla automaticamente.
- Il codice punta a rimanere snello: meno agenti, meno handoff.

## COMPATIBILITÀ

Lo script `digital-audit` supporta nativamente:
 ---------------------------------------------------
| Famiglia | Distribuzioni        | Package Manager |
|----------|----------------------|-----------------|
| Debian   | Debian, Ubuntu, Kali | APT, DNF, YUM,  |
| Red Hat  | RHEL, CentOS, Rocky, | BREW            |
| MacOS    | MacOS(silicon),Fedora|                 |
 ---------------------------------------------------
All'interno del container Docker l'ambiente è identico indipendentemente dalla distro host.

## NOTE

- `Niobe-Standalone` è il repo di lavoro/test per iterare rapidamente sulla pipeline.
- `Niobe` è il repo allineato alla soluzione principale da tenere coerente con gli stessi renderer, prompt e deliverable, che contiene anche la beta per control plane remoto
- Al momento, si è data preferenza a una versione tramite abbonamento con i provider LLM (e non a una soluzione LLM) per sensibilità di costi ma anche perché va inquadrato il quadro di business dove viene situata la soluzione.
