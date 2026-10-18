# Synthetic evaluation baseline

This report records fixed-input measurements for the current risk signals
(z-score, Isolation Forest, and their combined score). These are implementation measurements on this
synthetic generator, not literature results or claims that the project targets
are achieved on real trading data.

## Reproduce it

From the repository root, run:

```powershell
$env:PYTHONPATH = "src"
python -m threat_detection.evaluation
```

The runner fixes seed `42` and start time `2026-09-18T00:00:00+00:00`. With
the current defaults, it generates 20 accounts, 4 planted attack scenarios,
and 986 events.

## Metric definitions

- **Attack-scenario recall:** a planted scenario is detected when at least one
  of its labeled events receives a risk score at or above the threshold. The
  current generator plants at most one attack type per account, so the
  evaluation groups scenarios by `(account_id, attack_type)`.
- **Attack-event recall:** detected labeled attack events divided by all
  labeled attack events.
- **False-positive rate:** normal events at or above threshold divided by all
  normal events.
- **Per-attack-type recall:** scenario-level recall for each of the three
  planted attack types.
- **Latency:** time spent in feature extraction plus detector scoring for one
  event. It excludes event-source generation, API validation, network time,
  and response serialization.

Ground-truth fields are copied for evaluation bookkeeping and removed before
the event reaches the feature extractor. The default alert threshold is `50`.
Because Isolation Forest supplies a binary outlier decision rather than a
calibrated severity, an outlier maps to the minimum review score of `50`.

## Measured result

The current Isolation Forest signal is fit on a separate 900-event synthetic
stream generated with zero planted attack accounts (seed 7). Its alert cutoff
is calibrated to a 5% false-positive operating point on a second, separate
900-event normal-only stream (seed 8). Ground-truth fields are stripped before
both streams reach feature extraction; no labels select or weight training
samples. Evaluation uses the same seed 42 and start time as the baseline.
Event-kind indicators and successful login authentication-method indicators
are included in the rolling feature vector so the model can interpret sparse
order, cancellation, login, and API signals in context. Same-session successful
MFA is also retained as observable context for explanations; it does not erase
an unusual-behavior review alert.

| Measure | Z-score | Isolation Forest |
|---|---:|---:|
| Evaluation events | 986 | 986 |
| Attack-scenario recall | 100.0% (4 / 4) | 50.0% (2 / 4) |
| Attack-event recall | 88.4% (76 / 86) | 3.5% (3 / 86) |
| False-positive rate | 0.0% (0 / 900) | 4.4% (40 / 900) |
| Account takeover scenario recall | 100.0% (2 / 2) | 100.0% (2 / 2) |
| API abuse scenario recall | 100.0% (1 / 1) | 0.0% (0 / 1) |
| Automated trading scenario recall | 100.0% (1 / 1) | 0.0% (0 / 1) |
| Mean per-event feature-plus-detector latency | 0.014 ms | 20.756 ms |
| 95th percentile per-event feature-plus-detector latency | 0.033 ms | 25.261 ms |

The combined detector uses the larger of the z-score and Isolation Forest
scores. It retains the z-score attack-type guess and includes explanations from
each layer that raised a score. Its fixed-seed result was:

| Measure | Combined layers |
|---|---:|
| Attack-scenario recall | 100.0% (4 / 4) |
| Attack-event recall | 90.7% (78 / 86) |
| False-positive rate | 2.2% (20 / 900) |
| Recall by attack type | 100.0% for each type |
| Mean per-event feature-plus-detector latency | 20.658 ms |
| 95th percentile per-event feature-plus-detector latency | 27.004 ms |

The forest's validation cutoff targeted 5% FPR; the measured evaluation FPR
was 4.4%. Its recall is far below the 80% working target and misses API abuse
and automated trading in this run. This is evidence that the present feature
representation and model configuration are not ready to replace the
interpretable detector. Do not present the forest as an effective production
detector by itself. The combined detector cleared the working recall and FPR
targets in this fixed-seed run, but this run alone does not establish those
targets on independent data or unseen attack patterns. These figures measure
this generator's known signatures and are supporting validation of the product
risk logic, not a claim of general broker-ready effectiveness.

Five fixed evaluation seeds (42–46), with the same fixed fit and calibration
streams, produced combined results of 100% scenario recall and 90.7% event
recall on every seed. Per-seed combined FPR was 2.2%, 2.0%, 3.1%, 2.3%, and
2.8%; mean FPR was 2.5%. The standalone Forest had only 3.5% event recall in
the fixed seed-42 comparison. These seeds alter generator
profile choices, not planted attack mechanisms; treat this as a stability check
on one synthetic generator, not independent generalization evidence.

Latency values above are from a single current-environment run on 2026-10-18
and can vary across runs and machines. The five-seed check reports detection
metrics, not a latency distribution.

The z-score and combined metric tables above describe the current scoring
pipeline. These are synthetic-generator measurements; four planted scenarios
are too few to estimate general performance, and the generator encodes signals
the detector is designed to recognize. The latency measures only in-process
feature extraction and detector scoring. None of these figures establishes
production performance or validates the working targets against independent
data.

## Curated attack-variation checks

Run a second check with lower-amplitude or timing-varied attack recipes:

```powershell
$env:PYTHONPATH = "src"
python -m threat_detection.evaluation.variants
```

This runner fits and calibrates the same combined pipeline on normal-only
synthetic streams, then evaluates one curated variation per attack type after a
separate synthetic normal history. Evaluation labels are removed before
features and detectors. These are designed challenge cases, not independent
samples: they change magnitude or timing while retaining the same three
hand-selected behavior signals, and they do not represent real broker traffic.

| Curated variation | Events | Attack-event recall | Scenario recall | False-positive rate |
|---|---:|---:|---:|---:|
| Account takeover: 2× typical quantity, new device and unusual-hour login | 47 | 100.0% (2 / 2) | 100.0% (1 / 1) | 0.0% (0 / 45) |
| API abuse: 6 requests spaced 5 seconds apart | 51 | 100.0% (6 / 6) | 100.0% (1 / 1) | 0.0% (0 / 45) |
| Automated trading: 6 matched pairs with 243–257 ms cancel delays | 57 | 58.3% (7 / 12) | 100.0% (1 / 1) | 0.0% (0 / 45) |

The automated-trading variation exposes an event-level limitation: the
scenario is eventually flagged, but only 7 of its 12 events cross the
threshold. Its detector rule requires three completed matched order/cancel
pairs with low timing variance before alerting; the first two pairs and the
third order occur before enough evidence exists. The checks help identify
brittle magnitudes and timing assumptions; four total scenarios do not
establish expected broker performance.

The same runner includes a constructed benign unusual-login/MFA chain. It
relabels the takeover-shaped login/order events as normal and reports two
combined review alerts in 47 events (4.3% for this single constructed case).
This is a deliberate challenge case, not a representative false-positive-rate
estimate. It shows that MFA context should inform the analyst explanation but
does not automatically suppress behavior-based review. The feature extractor
associates the MFA flag only with a matching device and session within its
configured recent-login window. The Forest explanation lists observable
context separately from model attribution.

For attribution, the z-score layer alone had event recall of 50.0% for the
takeover variation, 83.3% for API abuse, and 58.3% for automated trading. The
combined pipeline's Forest signal moved one additional takeover and one
additional API event to the review floor; it did not improve event recall for
the cancellation-timing case. This separates the contribution of each signal
without treating this as an algorithm contest.

The market-time feature uses the NSE regular equity time window of 09:15–15:30
India Standard Time on weekdays. It does not load the exchange holiday
calendar, so it is a weekday time-window indicator rather than a live market
calendar check. [NSE market timings](https://www.nseindia.com/static/market-data/market-timings)
