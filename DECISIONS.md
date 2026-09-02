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

## 3. Why Isolation Forest as the ML anomaly method

Isolation Forest detects anomalies by measuring how easily a data point can be isolated by random partitioning — anomalies, being rare and different, require fewer partitions to isolate than normal points. Three properties make it the right first choice for us specifically:

1. **No labeled fraud data required for training** — it's trained on (mostly) normal behavior and doesn't need a labeled fraud dataset we don't have.
2. **Linear time complexity, low memory** — matters for a student-scale real-time pipeline; we can't afford an expensive model.
3. **Established, well-understood, and defensible in a review** — it's the most-cited unsupervised anomaly detection method in this space, meaning we can point to prior art when asked to justify it, rather than defending something exotic.

**Reference:** Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2008). *Isolation Forest*. Proceedings of the 8th IEEE International Conference on Data Mining (ICDM'08), 413–422. https://doi.org/10.1109/ICDM.2008.17
(Extended journal version: Liu, Ting, & Zhou (2012). *Isolation-Based Anomaly Detection*. ACM Transactions on Knowledge Discovery from Data, 6(1), 1–39.)

**Why not skip straight to deep learning:** the original paper's own comparison shows iForest matching or beating distance/density-based methods (SVM, LOF) on accuracy while being dramatically faster, since it avoids pairwise distance computation entirely — exactly the tradeoff a 3-person team on a real-time budget needs.

---

## 4. Why statistical/rolling baseline as a first layer, not just ML

Before the ML layer, we compute rolling per-account statistics (mean/std of actions-per-hour, order size, etc.) and flag deviation via z-score. This isn't a placeholder — it's a deliberate two-layer design:

- It gives us an **interpretable floor** — every ML result can be compared against "would a simple statistical rule have caught this," which is exactly the baseline-vs-ML comparison our evaluation slide promises.
- It's **cheap to compute in real time**, unlike retraining a model per-account.
- It **directly informs the risk-score explanation** — "300% above your typical order size" is a statistical statement, and it's the kind of human-readable evidence UEBA literature identifies as a common gap in black-box tools.

---

## 5. Why Autoencoder is future scope, not core — with evidence, not just a guess

We considered an autoencoder (reconstruction-error-based anomaly detection) as an alternative/addition to Isolation Forest. The literature is genuinely mixed on this, which is exactly why we're treating it as a comparison method rather than betting the core system on it:

**Reference (supportive):** Ding, L., Liu, L., Wang, Y., Shi, P., & Yu, J. (2024). *An AutoEncoder enhanced light gradient boosting machine method for credit card fraud detection*. PeerJ Computer Science, 10, e2323. https://doi.org/10.7717/peerj-cs.2323 — shows autoencoders can meaningfully improve fraud detection when combined with a downstream classifier, on real transaction data.

**Reference (cautionary):** A 2026 evaluation of autoencoder architectures for credit-card fraud detection found significant reconstruction-error overlap between normal and fraudulent classes, with precision dropping quickly as recall increases — i.e., autoencoders are not a free upgrade over simpler methods and need careful architecture/threshold tuning to beat baselines.
— *An Evaluation of Autoencoder Architectures for Fraud Detection in Credit Card Transactions* (IEEE Computer Society, 2026)

**Decision:** Isolation Forest is our core ML layer (cheaper, faster, sufficient literature support). Autoencoder is evaluated as a comparison method in the Jan evaluation phase — this is exactly what our "compare baseline vs. ML approach(es)" evaluation slide already promises, so it costs us nothing to keep it in scope as a second ML method rather than a competing core decision.

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
| API framework | FastAPI | Async, built-in request validation (Pydantic), native WebSocket support needed for the live dashboard |
| Dependency management | pip + requirements.txt | Simplest for a 3-person team; no extra tooling to install/sync |
| Event storage | PostgreSQL (+ TimescaleDB if benchmarks justify it) | Relational, well understood, time-series extension available if event volume needs it |
| Caching | Redis | Low-latency current-state lookups for the risk engine |
| Detection — baseline | Rolling z-score per account | Interpretable, no training data needed, sets a measurable floor (see §4) |
| Detection — ML | Isolation Forest (core), Autoencoder (comparison) | See §3 and §5 |
| Frontend | React + WebSockets | Matches the "real-time" claim; live alert feed |
| Containerization | Docker | Standard, reproducible for grading/demo |

**Engineering principle carried through all of the above:** start as a modular monolith; introduce streaming/queue infrastructure (e.g. Kafka) only where a load test actually shows it's needed, not preemptively. Every architecture choice is backed by a measurement, not an assumption — this is also directly defensible if a guide asks "why didn't you use X trendy technology."

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
