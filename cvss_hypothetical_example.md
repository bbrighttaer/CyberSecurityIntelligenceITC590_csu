
# CVSS v3.1 Hypothetical Vulnerability Scoring Example

## 🛠 Vulnerability Description
A SQL injection vulnerability exists in a public-facing login form of a web application. An unauthenticated attacker can exfiltrate the entire user database, including sensitive information such as passwords. No user interaction is required.

---

## 1. Base Metrics

| Metric                   | Value       | Score   | Justification |
|--------------------------|-------------|---------|----------------|
| **Attack Vector (AV)**   | Network     | 0.85    | Exploitable remotely via HTTP |
| **Attack Complexity (AC)** | Low       | 0.77    | No special conditions needed |
| **Privileges Required (PR)** | None    | 0.85    | No authentication required |
| **User Interaction (UI)** | None       | 0.85    | No user action required |
| **Scope (S)**            | Unchanged   | -       | Attack confined to single component |
| **Confidentiality (C)**  | High        | 0.56    | Full data disclosure |
| **Integrity (I)**        | Low         | 0.22    | Some modification of data possible |
| **Availability (A)**     | None        | 0.0     | No impact on availability |

### 🧮 Calculations

**Impact Subscore (ISC_base):**
```
ISC_base = 1 - (1 - C) * (1 - I) * (1 - A)
          = 1 - (1 - 0.56) * (1 - 0.22) * (1 - 0.0)
          = 1 - (0.44 * 0.78 * 1.0) = 1 - 0.3432 = 0.6568
```

**Impact Score:**
```
Scope = Unchanged → Impact = 6.42 * ISC_base
Impact = 6.42 * 0.6568 ≈ 4.21
```

**Exploitability Score:**
```
Exploitability = 8.22 * AV * AC * PR * UI
               = 8.22 * 0.85 * 0.77 * 0.85 * 0.85 ≈ 3.93
```

**Base Score:**
```
Base Score = ROUND_UP(Impact + Exploitability)
           = ROUND_UP(4.21 + 3.93) = ROUND_UP(8.14) = 8.2
```

➡️ **Base Score: 8.2 (High Severity)**

---

## 2. Temporal Metrics

| Metric                     | Value         | Multiplier |
|----------------------------|---------------|------------|
| **Exploit Code Maturity** | Functional    | 0.97       |
| **Remediation Level**     | Temporary Fix | 0.96       |
| **Report Confidence**     | Reasonable    | 0.96       |

**Temporal Score:**
```
Temporal Score = Base Score * E * RL * RC
               = 8.2 * 0.97 * 0.96 * 0.96 ≈ 7.2
```

➡️ **Temporal Score: 7.2 (High Severity)**

---

## 3. Environmental Metrics

Assume this system is used in a hospital where confidentiality is highly important.

| Metric                        | Value | Multiplier |
|-------------------------------|-------|------------|
| **Confidentiality Requirement** | High  | 1.5        |
| **Integrity Requirement**       | Medium | 1.0        |
| **Availability Requirement**    | Low   | 0.5        |

Modified Impact metrics:
```
C = 0.56 * 1.5 = 0.84
I = 0.22 * 1.0 = 0.22
A = 0.00 * 0.5 = 0.00
```

**Modified ISC_base:**
```
ISC_env = 1 - (1 - 0.84) * (1 - 0.22) * (1 - 0.0)
        = 1 - (0.16 * 0.78) = 1 - 0.1248 = 0.8752
```

**Modified Impact:**
```
Impact = 6.42 * 0.8752 ≈ 5.62
```

**Environmental Score:**
```
Environmental Score = ROUND_UP(Impact + Exploitability)
                    = ROUND_UP(5.62 + 3.93) = ROUND_UP(9.55) = 9.6
```

➡️ **Environmental Score: 9.6 (Critical Severity)**

---

## 📊 Summary

| Score Type          | Value | Severity |
|---------------------|--------|----------|
| **Base Score**      | 8.2    | High     |
| **Temporal Score**  | 7.2    | High     |
| **Environmental Score** | 9.6 | Critical |
