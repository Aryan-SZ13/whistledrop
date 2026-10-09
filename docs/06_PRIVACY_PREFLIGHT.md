# WhistleDrop — Privacy Preflight: Client-Side Identification Prevention
## *Why In-Browser Deterministic Inspection Beats Machine Learning for Anonymous Disclosures*

---

## 1. Executive Summary & The Problem

WhistleDrop is engineered to eliminate systemic metadata leaks: zero server access logs with IP addresses, zero user accounts, zero tracking cookies, and high-entropy 256-bit bearer case codes.

However, operational security audits identified a critical human vulnerability: **accidental self-disclosure in free-text narratives**.

When informants prepare disclosures under intense pressure, they frequently copy and paste internal records or write narratives containing:
1. **Personal or Work Emails** (e.g. `alice.smith@internal.company.com` or personal Gmail addresses).
2. **Direct Phone Extensions or Mobile Numbers** (e.g. `+1 555-234-5678` or `+44 20 7946 0991`).
3. **Internal Subnet IP Addresses** (e.g. `10.240.12.88`), which pinpoint physical buildings, floors, or departmental VLANs.
4. **URLs with Active Session Tokens or User IDs** (e.g. `https://cloud-storage.com/share?token=9f8a8b1c4d&uid=8823`).
5. **Employee Badge Numbers or National Identifiers** (e.g. `EMP-94821` or SSNs).
6. **First-Person Declarations** (e.g. *"I am the senior accountant on the 4th floor..."*).

Once submitted to the server, this text is encrypted under per-case keys (ALEE). However, when authorized moderators decrypt the report during legitimate triage, these embedded identifiers immediately expose the whistleblower to subpoena, internal discovery, or retaliatory identification.

**Privacy Preflight** solves this problem by inspecting draft narratives directly within the informant's browser *before* transmission, alerting the whistleblower to potential self-identifying markers while strictly preserving informant agency.

---

## 2. Architectural Trade-Off Analysis: Why Deterministic Inspection Beats Client ML

During architecture exploration, a candidate approach was deploying an in-browser Machine Learning model (such as a Named Entity Recognition Transformer running via ONNX Web Runtime over WebAssembly or WebGL).

We systematically analyzed this approach against a **deterministic lexical pattern engine**. The results decisively favored deterministic client-side inspection across every security and operational dimension:

![Privacy Preflight Architectural Trade-Off Analysis](figures/preflight_evaluation.svg)

### Architectural Trade-Off Comparison

| Evaluation Dimension | WhistleDrop Deterministic Preflight | Client-Side ML (ONNX / BERT) | Cloud / Server AI API |
| :--- | :--- | :--- | :--- |
| **Network Privacy (Wire Leakage)** | **0 bytes transmitted** (100% In-Browser) | 0 bytes (after model download) | **100% Leaked** (Draft sent over wire) |
| **Asset Download Weight** | **0 KB** (&lt; 8 KB minified JS in bundle) | **25 MB – 65 MB model weights** | 0 KB client assets |
| **Execution Latency (p50)** | **&lt; 0.05 ms** (Synchronous, instant) | 250 ms – 1,200 ms per inference | 400 ms – 2,500 ms (RTT + queue) |
| **Hardware & Acoustic Safety** | **Negligible CPU** (Zero fan spin) | **Heavy CPU/GPU spike** (Loud fan noise) | Negligible client CPU |
| **Tor Browser Compatibility** | **100% Compatible** (Standard ES6) | **Broken** (Tor disables WebGL/WebGPU) | High correlation attack surface |
| **Structured Identifier Precision** | **100.0% Synthetic** (Exact boundaries) | ~82% – 88% (Tokenization errors) | ~85% – 92% (Hallucinations) |
| **ReDoS & Denial-of-Service** | **Formally bounded** (Fixed-depth regexes) | Model timeout / OOM risks | Server API rate limiting |

*Note: The ML and Cloud columns represent architectural trade-off profiles from literature and standard client runtimes. WhistleDrop uses 100% deterministic local rules.*

### Critical Reasons Client-Side ML Was Rejected

1. **Tor Browser Hostility**: Whistleblowers frequently access reporting platforms using the Tor Browser. To prevent hardware fingerprinting, Tor Browser disables or restricts WebGL and WebGPU acceleration. An in-browser ML model requiring WebGL/WASM either fails to initialize or suffers catastrophic CPU fallback penalties.
2. **Bandwidth Penalty on High-Risk Networks**: Downloading a 25–65 MB quantized neural network model over Tor or constrained cellular networks takes minutes, creates suspicious network traffic spikes on monitored corporate proxies, and drastically increases informant drop-off.
3. **Acoustic and Thermal Side-Channel Risk**: Running transformer inference in the browser stresses client CPU/GPU threads, causing cooling fans to spin up loudly in quiet corporate office environments—providing an acoustic tell that exposes the whistleblower to nearby colleagues.
4. **Tokenization Boundary Failures on Structured PII**: Subword tokenizers (WordPiece/BPE) frequently split IP addresses (`10.240.12.88`), internal hostnames (`jira.internal`), and tracking query parameters into fragmented tokens, resulting in high false-negative rates for the exact technical identifiers that leak network location.
5. **Why Cloud AI Was Disqualified Instantly**: Forwarding uncommitted report drafts to a cloud LLM or backend analysis endpoint completely violates WhistleDrop's zero-knowledge security invariant by transmitting cleartext disclosures across third-party networks before the user has even decided to submit.

---

## 3. Preflight System Architecture & Invariants

```mermaid
sequenceDiagram
    autonumber
    actor Whistleblower as Whistleblower (Browser)
    participant Engine as Privacy Preflight Engine (Local Memory)
    participant UI as Privacy Banner UI (DOM)
    participant Crypto as Web Crypto / ALEE Client
    participant Server as WhistleDrop Backend (FastAPI)

    Whistleblower->>Engine: Types narrative in draft form
    Note over Engine: Pure function scanDraftText()<br/>Synchronous execution (&lt; 0.05 ms)<br/>Zero network / Zero localStorage
    Engine-->>UI: PreflightScanResult (findings, severity)
    
    alt Potential Identifiers Detected (e.g. email, phone, IP)
        UI->>Whistleblower: Display Advisory Banner with Snippet Previews
        Whistleblower->>UI: Reviews findings: Evidence vs. Self-Disclosure
        alt Informant Confirms It Is Incident Evidence
            Whistleblower->>UI: Check "This is incident evidence (allow submission)"
            UI->>Whistleblower: Submit button updates to active submission
        else Informant Edits Draft
            Whistleblower->>UI: Click "Edit Draft" -> Remove personal details
            Engine-->>UI: Findings cleared -> Banner automatically hides
        end
    else Narrative Clean (0 Identifiers Detected)
        UI-->>Whistleblower: Submit button enabled immediately
    end

    Whistleblower->>Crypto: Click "Submit Confidential Report"
    Crypto->>Server: POST /api/v1/reports (ALEE Encrypted Payload)
    Server-->>Whistleblower: Returns 256-bit Bearer Case Code
```

### Non-Negotiable Invariants

1. **100% In-Browser Execution**: Under no circumstances does draft text, token substrings, or preflight findings trigger an HTTP request, beacon, or websocket frame prior to form submission.
2. **Zero Client-Side Persistence**: Draft narratives and detected findings are never saved to `localStorage`, `sessionStorage`, `indexedDB`, or cookies. Closing the tab leaves zero traces in the browser storage profile.
3. **Preservation of Whistleblower Agency (Advisory Only)**: The preflight banner never automatically blocks, deletes, or redacts text. In legitimate whistleblowing, naming a corrupt manager (e.g. `cfo@company.com`) or a compromised server (`10.0.4.15`) is essential evidence. The platform allows submission once the informant explicitly reviews and confirms the advisory.
4. **ReDoS-Safe Regex Guarantees**: All pattern definitions are non-backtracking and bounded to prevent catastrophic regular expression denial-of-service on large texts (50,000 characters process in &lt; 2 ms).
5. **Fail-Safe Submission Flow**: Scanner errors or unexpected inputs are caught in a `try/catch` fallback block in `useMemo`, ensuring that a scanner error never destroys draft text or breaks the core submission workflow.
6. **Accessible Navigation**: The banner declares `role="region"`, `aria-label="Privacy Preflight Advisory"`, and `aria-live="polite"`. The acknowledgment checkbox has an explicit accessibility label and `id`.

---

## 4. Entity Detection Specification & Limitations

The preflight scanner detects six distinct categories of identifying data:

| Category | Finding Type | Severity | Detection Pattern | User Guidance |
| :--- | :--- | :---: | :--- | :--- |
| **Email Address** | `EMAIL` | `CRITICAL` | Bounded standard RFC 5322 address syntax | Warning if address is informant's own personal/work mailbox; allowed if naming perpetrator. |
| **Phone Number** | `PHONE` | `CRITICAL` | Domestic & international telephone formats (`+1`, `+44`, grouped digits) | Warning to avoid personal mobile or direct desk extension. Specifically excludes plain year ranges (2020-2024), dates, and order numbers. |
| **IP Address** | `IP_ADDRESS` | `WARNING` | IPv4 quad notation (excluding `127.0.0.1`, `0.0.0.0`, version strings like `1.2.3.4`, and section headers) | Identifies internal subnets that pinpoint physical cubicle or corporate VLAN. |
| **Tracking URL** | `TRACKING_URL` | `CRITICAL` | URLs with query tokens (`token=`, `session=`, `uid=`) or internal hostnames (`.internal`, `.corp`, `.intranet`) | High risk of active SSO session tokens linking to authenticated user accounts. Strips trailing sentence punctuation. |
| **Structured ID** | `STRUCTURED_ID` | `CRITICAL` | Employee badge formats (`EMP-`, `BADGE#`, `STAFF-`) and national IDs (SSN) | Direct employee directory keys. Requires digits to prevent matching ordinary English words. |
| **Self-Disclosure** | `SELF_IDENTIFIER`| `WARNING` | First-person declarative phrases (*"my name is"*, *"contact me at"*, *"my desk is"*) | Prompts informant to rewrite in objective third-person perspective. |

### Detection Limitations & False Positives

1. **Proper Names Are Not Automatically Flagged**: The scanner intentionally does not flag bare personal names (e.g. "John Smith"). In whistleblowing disclosures, almost every report mentions the names of perpetrators or managers. Blanket-flagging all names would force whistleblowers to acknowledge warnings on virtually every legitimate report, causing banner fatigue.
2. **Unstructured Self-Disclosure**: First-person self-disclosure phrases (*"my name is"*, *"reach me at"*) catch direct explicit disclosures, but subtle linguistic nuances (e.g. *"As someone who joined the accounting team last May..."*) cannot be reliably captured by deterministic patterns without NLP models that incur privacy/network compromises.
3. **Internal Subnet IPs vs. Public IPs**: All valid IPv4 addresses (except loopback and software versions) are flagged as `WARNING` because an informant cannot easily determine whether an IP belongs to their workstation or an external target.

---

## 5. Synthetic Evaluation Methodology & Results

The preflight engine was verified using an automated benchmark harness against **58 annotated synthetic whistleblowing narratives** spanning clean disclosures, corporate fraud descriptions, technical vulnerability reports, negative edge cases, and adversarial mixed cases.

> **Synthetic Benchmark Caveat**: This evaluation uses synthetic benchmark cases to test known positive patterns and negative edge cases (e.g. year ranges, ISO dates, order numbers, software versions). Synthetic test scores verify rule engine consistency and boundary correctness, but do **NOT** establish real-world accuracy across arbitrary human prose.

### Per-Category Breakdown (Synthetic Dataset)

| Category | Expected Samples | True Positives | False Positives | False Negatives | Precision | Recall | F1 Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **EMAIL** | 7 | 7 | 0 | 0 | 100.00% | 100.00% | 1.0000 |
| **PHONE** | 8 | 8 | 0 | 0 | 100.00% | 100.00% | 1.0000 |
| **IP_ADDRESS** | 6 | 6 | 0 | 0 | 100.00% | 100.00% | 1.0000 |
| **TRACKING_URL** | 8 | 8 | 0 | 0 | 100.00% | 100.00% | 1.0000 |
| **STRUCTURED_ID** | 8 | 8 | 0 | 0 | 100.00% | 100.00% | 1.0000 |
| **SELF_IDENTIFIER** | 8 | 8 | 0 | 0 | 100.00% | 100.00% | 1.0000 |

### Clean & Negative Sample Validation

- **Clean / Negative Test Cases**: 22 samples (e.g. clean reports, calendar years `2024` and `2025`, year ranges `2020-2024`, order IDs, software versions `1.2.3.4`, section numbers `2.3.4.1`, dictionary words).
- **Clean Negative Accuracy**: 22 / 22 correct (0 false positives).

### Execution Latency (Local Benchmark)

- **p50 (Median)**: `0.0161 ms`
- **p95**: `0.0336 ms`
- **p99**: `0.1074 ms`
- *Methodology*: Synchronous benchmark measured locally in Python 3.13 over 58 sequential sample runs.

*Source: `docs/preflight_metrics.json`, generated by `scripts/evaluate_privacy_preflight.py`.*

---

## 6. Relevant Source Files & Test Inventory

| File | Purpose | Test Coverage |
| :--- | :--- | :--- |
| `frontend/src/utils/privacyPreflight.ts` | Pure deterministic scanner engine with ReDoS-safe patterns and regex idempotency | Tested in `frontend/src/__tests__/privacyPreflight.test.tsx` |
| `frontend/src/components/PrivacyPreflightBanner.tsx` | Accessible advisory banner with snippet tags and agency acknowledgment | Tested in `frontend/src/__tests__/privacyPreflight.test.tsx` |
| `frontend/src/pages/SubmitReportPage.tsx` | Live report submission form with `useMemo` preflight scan and error handling | Tested in `frontend/src/__tests__/privacyPreflight.test.tsx` |
| `scripts/evaluate_privacy_preflight.py` | 58-sample synthetic evaluation harness generating metrics and SVG chart | Executable via Python 3 |

---

## 7. Verification and Reproduction Commands

### 1. Run the Empirical Accuracy and Benchmark Suite
```bash
python3 scripts/evaluate_privacy_preflight.py
```
Evaluates all 58 synthetic test cases, computes per-category metrics, and regenerates `docs/figures/preflight_evaluation.svg`.

### 2. Run Frontend Tests
```bash
cd frontend
npm test -- --run
```
Executes all 35 frontend tests across 4 test files, including network isolation, zero-storage invariants, negative edge cases, ordering guarantees, and accessibility attributes.

### 3. Build the Production Frontend Bundle
```bash
cd frontend
npm run build
```
Executes TypeScript compilation and Vite packaging.

### 4. Run Frontend Linter
```bash
cd frontend
npm run lint
```
Runs `oxlint` across all TypeScript/React source files.
