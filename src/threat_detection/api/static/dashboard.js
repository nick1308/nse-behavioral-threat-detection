const elements = {
  rows: document.querySelector('#event-rows'),
  eventCount: document.querySelector('#event-count'),
  highCount: document.querySelector('#high-count'),
  mediumCount: document.querySelector('#medium-count'),
  accountCount: document.querySelector('#account-count'),
  shownCount: document.querySelector('#shown-count'),
  filter: document.querySelector('#risk-filter'),
  replayButton: document.querySelector('#replay-button'),
  refreshButton: document.querySelector('#refresh-button'),
  notice: document.querySelector('#notice'),
};

let scoredEvents = [];

function makeCell(className, text) {
  const cell = document.createElement('td');
  if (className) cell.className = className;
  cell.textContent = text;
  return cell;
}

function riskBand(score) {
  if (score >= 70) return 'high';
  if (score >= 50) return 'medium';
  return 'low';
}

function displayTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value || '—';
  return new Intl.DateTimeFormat(undefined, {
    month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit',
  }).format(date);
}

function eventRow(event) {
  const row = document.createElement('tr');

  const identity = document.createElement('td');
  const eventId = document.createElement('span');
  eventId.className = 'event-id';
  eventId.textContent = event.event_id;
  const accountId = document.createElement('span');
  accountId.className = 'account-id';
  accountId.textContent = event.account_id;
  identity.append(eventId, accountId);
  row.append(identity);

  const typeCell = document.createElement('td');
  const typePill = document.createElement('span');
  typePill.className = 'type-pill';
  typePill.textContent = event.event_type;
  typeCell.append(typePill);
  row.append(typeCell);

  const scoreCell = document.createElement('td');
  const scoreLayout = document.createElement('div');
  const band = riskBand(Number(event.risk_score) || 0);
  scoreLayout.className = 'score-cell';
  const score = document.createElement('span');
  score.className = `score-number ${band}`;
  score.textContent = String(Math.round(Number(event.risk_score) || 0));
  const track = document.createElement('span');
  track.className = 'score-track';
  const fill = document.createElement('span');
  fill.className = `score-fill ${band}`;
  fill.style.width = `${Math.max(0, Math.min(100, Number(event.risk_score) || 0))}%`;
  track.append(fill);
  scoreLayout.append(score, track);
  scoreCell.append(scoreLayout);
  row.append(scoreCell);

  const explanationCell = document.createElement('td');
  explanationCell.className = event.explanation ? 'reason' : 'reason no-reason';
  explanationCell.textContent = event.explanation || 'No risk signal crossed the alert threshold.';
  if (event.attack_type_guess) {
    const pattern = document.createElement('span');
    pattern.className = 'pattern-guess';
    pattern.textContent = `Possible pattern: ${event.attack_type_guess.replaceAll('_', ' ')} (detector guess)`;
    explanationCell.append(pattern);
  }
  if (event.layer_scores && typeof event.layer_scores === 'object') {
    const signalScores = document.createElement('span');
    signalScores.className = 'signal-scores';
    const behaviorScore = Number(event.layer_scores.zscore) || 0;
    const modelScore = Number(event.layer_scores.isolation_forest) || 0;
    signalScores.textContent = `Behavior signals ${Math.round(behaviorScore)} · ML anomaly signal ${Math.round(modelScore)}`;
    explanationCell.append(signalScores);
  }
  row.append(explanationCell);

  const timeCell = document.createElement('td');
  const timestamp = document.createElement('span');
  timestamp.className = 'timestamp';
  timestamp.textContent = displayTime(event.timestamp);
  timeCell.append(timestamp);
  row.append(timeCell);
  return row;
}

function render() {
  const selectedRisk = elements.filter.value;
  const visibleEvents = scoredEvents.filter((event) => {
    const score = Number(event.risk_score) || 0;
    if (selectedRisk === 'high') return score >= 70;
    if (selectedRisk === 'review') return score >= 50;
    if (selectedRisk === 'low') return score < 50;
    return true;
  });

  elements.eventCount.textContent = String(scoredEvents.length);
  elements.highCount.textContent = String(scoredEvents.filter((event) => event.risk_score >= 70).length);
  elements.mediumCount.textContent = String(scoredEvents.filter((event) => event.risk_score >= 50 && event.risk_score < 70).length);
  elements.accountCount.textContent = String(new Set(scoredEvents.map((event) => event.account_id)).size);
  elements.shownCount.textContent = `Showing ${visibleEvents.length} of ${scoredEvents.length} recent events`;
  elements.rows.replaceChildren();

  if (visibleEvents.length === 0) {
    const row = document.createElement('tr');
    const emptyCell = document.createElement('td');
    emptyCell.colSpan = 5;
    emptyCell.className = 'empty-state';
    emptyCell.textContent = scoredEvents.length
      ? 'No events match this risk filter.'
      : 'No events yet. Run the demo stream to see scored activity.';
    row.append(emptyCell);
    elements.rows.append(row);
    return;
  }
  elements.rows.append(...visibleEvents.map(eventRow));
}

function showNotice(message, isError = false) {
  elements.notice.textContent = message;
  elements.notice.classList.toggle('error', isError);
  elements.notice.hidden = false;
}

async function loadEvents({ quiet = false } = {}) {
  try {
    const response = await fetch('/events?limit=500', { headers: { Accept: 'application/json' } });
    if (!response.ok) throw new Error(`Could not load events (${response.status}).`);
    const data = await response.json();
    scoredEvents = Array.isArray(data.events) ? data.events : [];
    render();
  } catch (error) {
    if (!quiet) showNotice(error.message || 'Could not load recent events.', true);
  }
}

elements.replayButton.addEventListener('click', async () => {
  elements.replayButton.disabled = true;
  elements.replayButton.textContent = 'Replaying demo…';
  elements.notice.hidden = true;
  try {
    const response = await fetch('/demo/replay?seed=42', { method: 'POST' });
    if (!response.ok) throw new Error(`Demo replay failed (${response.status}).`);
    const result = await response.json();
    await loadEvents({ quiet: true });
    showNotice(`Replay complete: ${result.processed_events} synthetic events were scored; ${result.alert_count} reached the review threshold. Labels were not sent to the detector.`);
  } catch (error) {
    showNotice(error.message || 'The demo stream could not be replayed.', true);
  } finally {
    elements.replayButton.disabled = false;
    elements.replayButton.innerHTML = '<span aria-hidden="true">▶</span> Run demo stream';
  }
});

elements.refreshButton.addEventListener('click', () => loadEvents());
elements.filter.addEventListener('change', render);
loadEvents();
window.setInterval(() => loadEvents({ quiet: true }), 10000);
