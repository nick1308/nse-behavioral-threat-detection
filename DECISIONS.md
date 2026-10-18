# Project Decisions & Rationale

Real-Time Behavioral Threat Detection for Trading Systems — IDP, Aug–Feb/Mar
Team: Ankit V, Tusya S, Vishal Basker · Guide: Dr. Karmel A

This document exists to answer the guide's feedback directly: what are we building, why, and on what basis. Every non-obvious decision below is backed by a specific reason and, where relevant, a citation.

---

## 1. End Goal (concrete, measurable)

By the end of the program, a working system that ingests simulated trading events in real time, flags account takeover, API abuse, and automated-trading behavior with an explainable 0–100 risk score, and demonstrably catches **≥80% of planted attacks (recall)** at a **false-positive rate under 10%** and **detection latency under 5 seconds**, measured against our own labeled synthetic dataset.

*(Targets are working numbers — revise once early benchmarking gives us real baselines. Having a number, even approximate, is what matters for review purposes.)*

---

## 2. Why behavioral detection at all, not just authentication

Credential validity and behavioral legitimacy are different questions. This is the entire premise of the User and Entity Behavior Analytics (UEBA) category, which exists specifically because rule-based and authentication-only security misses attacks that use valid, stolen, or abused credentials.

**Reference:** A 2024 review of insider-threat detection surveys the field and confirms the core mechanism we're using: a per-user/entity behavioral baseline, with alerts triggered by deviation from that baseline, is the standard formulation across the UEBA literature.
— *Insider Threat Detection Techniques: Review of User Behavior Analytics Approach* (2024)

**Implication for us:** we are not inventing this detection paradigm — we're applying it in an under-served context (Indian retail trading platforms) and being honest about that positioning, which is itself defensible as the actual contribution.

---

## 3. Detection is a means to the product outcome

Isolation Forest detects anomalies by measuring how easily a data point can be isolated by random partitioning. It is one signal in the current backend, not the project objective. The product objective is to surface actionable, explainable risk assessments in an analyst interface. Model comparisons are supporting validation only.

1. **No labeled fraud data required for training** — it's trained on (mostly) normal behavior and doesn't need a labeled fraud dataset we don't have.
2. It is a manageable first comparison for a student-scale prototype; actual cost is measured rather than assumed.
3. Its published method and implementation are documented, which supports a clear explanation in project reviews.

**Reference:** Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2008). *Isolation Forest*. Proceedings of the 8th IEEE International Conference on Data Mining (ICDM'08), 413–422. https://doi.org/10.1109/ICDM.2008.17
(Extended journal version: Liu, Ting, & Zhou (2012). *Isolation-Based Anomaly Detection*. ACM Transactions on Knowledge Discovery from Data, 6(1), 1–39.)

**Measured status:** in the seed-42 run, standalone Forest event recall was 3.5% with 5.2% FPR; it missed API abuse and automated trading. The current API includes its signal in a maximum-score ensemble. These metrics inform whether that signal improves the user-facing risk assessment; they do not define project completion. See `docs/EVALUATION_BASELINE.md`.

---

## 4. Why statistical/rolling baseline as a first layer, not just ML

Before the ML layer, we compute rolling per-account statistics (mean/std of actions-per-hour, order size, etc.) and flag deviation via z-score. This isn't a placeholder — it's a deliberate two-layer design:

- It gives us an **interpretable floor** — every ML result can be compared against "would a simple statistical rule have caught this," which is exactly the baseline-vs-ML comparison our evaluation slide promises.
- It's **cheap to compute in real time**, unlike retraining a model per-account.
- It **directly informs the risk-score explanation** — "300% above your typical order size" is a statistical statement, and it's the kind of human-readable evidence UEBA literature identifies as a common gap in black-box tools.

---

## 5. Why Autoencoder is deferred

We considered an autoencoder (reconstruction-error-based anomaly detection) as an alternative/addition to Isolation Forest. The literature is genuinely mixed on this, which is exactly why we're treating it as a comparison method rather than betting the core system on it:

**Reference (supportive):** Ding, L., Liu, L., Wang, Y., Shi, P., & Yu, J. (2024). *An AutoEncoder enhanced light gradient boosting machine method for credit card fraud detection*. PeerJ Computer Science, 10, e2323. https://doi.org/10.7717/peerj-cs.2323 — shows autoencoders can meaningfully improve fraud detection when combined with a downstream classifier, on real transaction data.

**Reference (cautionary):** A 2026 evaluation of autoencoder architectures for credit-card fraud detection found significant reconstruction-error overlap between normal and fraudulent classes, with precision dropping quickly as recall increases — i.e., autoencoders are not a free upgrade over simpler methods and need careful architecture/threshold tuning to beat baselines.
— *An Evaluation of Autoencoder Architectures for Fraud Detection in Credit Card Transactions* (IEEE Computer Society, 2026)

**Decision:** an autoencoder is optional future work, not part of the committed prototype. First run a fair held-out evaluation of the existing baseline and Forest. Adding another model before that would increase tuning effort without evidence it solves the observed weak Forest recall.

---

## 6. Why synthetic, ground-truth-labeled data — not scraped or real market data

Two independent reasons converge here:

1. **Legal/ethical:** we will not scrape NSE endpoints against terms of service, and we have no student budget for licensed real-time feeds.
2. **Methodological — this is the stronger reason:** we *need* labeled ground truth to compute precision/recall/F1 at all. Real production data doesn't come pre-labeled with "this was fraud." Generating our own synthetic accounts with planted, known attacks is standard practice in this exact research area.

**Reference:** the CERT Insider Threat Dataset — the most widely used benchmark in insider-threat/behavioral-anomaly research — is itself entirely synthetic, generated specifically because real labeled insider-threat data essentially doesn't exist to work with. Its creation methodology is documented in:
Glasser, J., & Lindauer, B. (2013). *Bridging the Gap: A Pragmatic Approach to Generating Insider Threat Data*. IEEE Security and Privacy Workshops.

**Implication for us:** we're not settling for synthetic data because we couldn't get real data — synthetic, labeled data is the methodologically correct choice for this kind of evaluation, and the most-cited work in the field does the same thing for the same reason. This is a good line to say directly to your guide if asked.

---

## 7. Technology stack — decided, with reasons

| Layer | Choice | Why |
|---|---|---|
| API framework | FastAPI | Pydantic request validation; currently exposes `/health` and `/score` |
| Dependency management | pip + requirements.txt | Simplest for a 3-person team; no extra tooling to install/sync |
| Event storage | In-memory process state; database not selected | Suitable for the current single-process feasibility prototype; persistence remains open |
| Caching | None | No measured need at current prototype scale |
| Detection — baseline | Rolling z-score per account | Interpretable statistical baseline; see §4 |
| Detection — ML | Isolation Forest comparison plus max-score ensemble | Forest standalone performance is weak in current benchmark; see §3 |
| Frontend | Local analyst dashboard served by FastAPI | HTML/CSS/JavaScript avoids a separate build toolchain for the demo; this is implemented, while a polished production console remains future work |
| Containerization | Docker files present; build unverified | Intended reproducibility; local engine was unavailable at last build attempt |

**Engineering principle:** keep the system a modular monolith while completing the usable product. PostgreSQL, Redis, Kafka, and WebSockets remain optional until persistence, scale, or push-update requirements justify them. The UI itself is not optional; it is a core missing deliverable.

---

## 8. Attack scenarios — concrete detection logic, not just names

| Attack | Concrete signal |
|---|---|
| Account takeover | New/unseen device **and** login outside the account's historical time window **and** order size far above historical max, within a short time span |
| API abuse | Request rate N× above the account's rolling baseline within a short window |
| Automated trading | Repeated order→cancel sequences with near-zero human-like timing variance |

---

## 9. Future scope (explicitly not core — see slide 13 of the deck)

- **Graph-based fraud-ring detection**: account graph with edges on shared device/IP/timing, community-detection to surface coordinated clusters. Pursued only after core milestones are met.
- **Adversarial evasion testing**: simulate an attacker slowly drifting behavior to evade the baseline ("boiling frog"); measure drift tolerance; harden with drift-rate limits.

---

## References

1. Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2008). Isolation Forest. *ICDM'08*, 413–422. https://doi.org/10.1109/ICDM.2008.17
2. Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2012). Isolation-Based Anomaly Detection. *ACM TKDD*, 6(1), 1–39.
3. Insider Threat Detection Techniques: Review of User Behavior Analytics Approach (2024).
4. Ding, L., Liu, L., Wang, Y., Shi, P., & Yu, J. (2024). An AutoEncoder enhanced light gradient boosting machine method for credit card fraud detection. *PeerJ Computer Science*, 10, e2323. https://doi.org/10.7717/peerj-cs.2323
5. An Evaluation of Autoencoder Architectures for Fraud Detection in Credit Card Transactions (2026).
6. Glasser, J., & Lindauer, B. (2013). Bridging the Gap: A Pragmatic Approach to Generating Insider Threat Data. *IEEE Security and Privacy Workshops*.
