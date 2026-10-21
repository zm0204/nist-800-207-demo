const $ = id => document.getElementById(id);
let sessionToken = '', scenarios = [], selected = 'salary', active = null, state = null, history = [], selectedRun = null;
const scenarioResults = new Map();
const checkLabels = {
  'authorized chain to salary': '合法服務鏈 → 薪資', 'authorized chain to profile': '合法服務鏈 → 個人資料',
  'query preserves allowed path': '查詢參數不改變授權路徑', 'wrong workload identity': '拒絕錯誤的服務身分',
  'probe cannot bypass frontend': 'probe 無法跳過 frontend', 'wrong method': '拒絕未授權的 HTTP 方法',
  'wrong path': '拒絕未授權的路徑', 'health route has no implicit grant': '健康檢查路徑沒有隱含權限',
  'forged identity headers': '偽造標頭無法取代服務身分', 'plaintext rejected by STRICT mTLS': 'STRICT mTLS 拒絕明文',
  'direct Pod IP attempt unsuccessful (routing/TLS/RBAC)': '直接連到 Pod IP 無法取得資源',
  'service remains reachable after direct-IP attempt': '直接 IP 測試後，合法路徑仍可用',
  'native policy revocation': '原生政策撤銷後拒絕', 'native policy restored': '原生政策恢復後成功',
  'client cannot forge gRPC PE inputs': '一般 client 無法直接呼叫 PE',
  'PE policy reload revokes without restart': 'PE 不重啟即可套用撤銷政策', 'PE policy restored': 'PE 政策恢復後成功',
  'mesh-authz outage fails closed': '授權服務停機時拒絕', 'mesh-authz restored': '授權服務恢復後成功',
  'pe outage fails closed': 'PE 停機時拒絕', 'pe restored': 'PE 恢復後成功',
  'context outage fails closed': 'audit 停機時拒絕', 'context restored': 'audit 恢復後成功'
};

function node(tag, text, className) {
  const el = document.createElement(tag);
  if (text !== undefined) el.textContent = text;
  if (className) el.className = className;
  return el;
}

async function api(path, options = {}) {
  const response = await fetch('/api/console/' + path, {cache: 'no-store', ...options});
  const body = await response.json();
  if (!response.ok) {
    const error = new Error(typeof body.detail === 'string' ? body.detail : '操作未完成，請稍後重試。');
    error.status = response.status; throw error;
  }
  return body;
}

function stamp(value, date = false) {
  if (!value) return '—';
  const time = typeof value === 'number' ? new Date(value * 1000) : new Date(value);
  return time.toLocaleString('zh-TW', {timeZone: 'Asia/Taipei', hour12: false,
    ...(date ? {month: '2-digit', day: '2-digit'} : {}), hour: '2-digit', minute: '2-digit', second: '2-digit'});
}

function nameOf(id) { return id === 'full-verify' ? '完整驗證' : scenarios.find(s => s.id === id)?.label || id; }
function shortIdentity(uri) { return uri?.split('/sa/').pop() || '—'; }
function statusText(status) { return status === 0 ? '連線遭拒' : String(status ?? '—'); }
function errorBanner(message = '') { $('page-error').textContent = message; $('page-error').hidden = !message; }

function renderScenarios() {
  $('scenarios').replaceChildren(...scenarios.map((s, i) => {
    const button = node('button', undefined, 'scenario-button');
    button.type = 'button'; button.setAttribute('aria-pressed', String(selected === s.id));
    button.disabled = Boolean(active);
    button.append(node('span', String(i + 1).padStart(2, '0'), 'scenario-index'), node('span', s.label, 'scenario-name'));
    const result = scenarioResults.get(s.id);
    button.append(node('span', result === undefined ? '—' : result ? 'PASS' : 'FAIL', 'scenario-status'));
    button.addEventListener('click', () => choose(s.id));
    return button;
  }));
}

function choose(id, preserveResult = false) {
  selected = id;
  const s = scenarios.find(s => s.id === id);
  if (!s) return;
  renderScenarios();
  $('scenario-title').textContent = s.label;
  $('scenario-description').textContent = s.detail;
  $('expectation').textContent = s.expected.includes(0) ? '預期連線遭拒 / 503' : '預期 ' + s.expected.join(' / ');
  $('request-method').textContent = s.method;
  $('request-url').textContent = `http://${s.target}:8000${s.path}`;
  $('caller-identity').textContent = s.caller;
  $('target-identity').textContent = s.target === 'frontend' ? `frontend → ${s.resource}` : s.target;
  $('route-source').textContent = s.caller;
  $('source-note').textContent = s.id === 'plaintext' ? '無 sidecar 的測試端' : '獨立 ServiceAccount';
  $('first-hop-label').textContent = s.id === 'plaintext' ? '明文' : 'mTLS';
  $('route-target').textContent = s.resource || s.target;
  $('route-frontend').hidden = s.target !== 'frontend';
  $('backend-link').hidden = s.target !== 'frontend';
  $('headers-detail').hidden = !Object.keys(s.headers).length;
  $('request-headers').textContent = JSON.stringify(s.headers, null, 2);
  if (!preserveResult) {
    selectedRun = null;
    $('route-caption').textContent = '目前選擇的路徑 · 尚未執行';
    $('response-placeholder').hidden = false; $('response-content').hidden = true;
    $('response-time').textContent = '';
  }
}

async function refreshStatus() {
  $('refresh-status').disabled = true;
  try {
    state = await api('status');
    const good = state.available;
    const ready = state.workloads.filter(w => w.desired > 0 && w.ready >= w.desired).length;
    $('connection').replaceChildren(node('i', '', `dot ${good ? 'good' : 'bad'}`),
      document.createTextNode(good ? `叢集已連線 · ${ready}/${state.workloads.length} 服務就緒` : '叢集無法連線'));
    $('environment-note').textContent = good ? `觀測時間 ${stamp(state.observed_at)}（台北） · ${state.context} / ${state.namespace}` : state.error;
    $('mtls-mode').textContent = good ? state.security.mtls : '未知';
    $('mtls-dot').className = `dot ${good && state.security.mtls === 'STRICT' ? 'good' : 'neutral'}`;
    $('default-deny').textContent = good ? state.security.default_deny ? '已套用' : '未找到' : '未知';
    $('pe-label').textContent = good ? state.security.external_authz ? 'CUSTOM 已套用' : '尚未啟用' : '無法讀取';
    $('workloads').replaceChildren(...state.workloads.map(w => {
      const tr = node('tr');
      tr.append(node('td', w.name), node('td', `${w.ready}/${w.desired}`, w.ready >= w.desired && w.desired > 0 ? 'table-status' : 'table-status failed'),
        node('td', w.sidecar ? '已注入' : w.name === 'plaintext' ? '刻意停用' : '未觀測到'), node('td', w.service_account || '—'));
      return tr;
    }));
    if (!good) { const tr = node('tr'); const td = node('td', '沒有可讀取的即時資料', 'empty-row'); td.colSpan = 4; tr.append(td); $('workloads').append(tr); }
    $('policy-json').textContent = good ? JSON.stringify(state.policies, null, 2) : '叢集無法連線';
  } catch (error) {
    const previous = state;
    state = {available:false, stale:true, observed_at:null, last_observed_at:previous?.observed_at || previous?.last_observed_at,
      context:'kind-zta-207a', namespace:'zta-207a', workloads:[], security:{}, policies:[]};
    $('connection').replaceChildren(node('i', '', 'dot bad'), document.createTextNode('控制程式無法連線'));
    $('environment-note').textContent = `無法讀取控制程式，先前資料已撤下。最後觀測時間 ${stamp(state.last_observed_at)}。`;
    $('mtls-mode').textContent = '未知'; $('mtls-dot').className = 'dot neutral';
    $('default-deny').textContent = '未知'; $('pe-label').textContent = '無法讀取';
    $('workloads').replaceChildren(); $('policy-json').textContent = '即時資料無法讀取。';
  } finally { $('refresh-status').disabled = false; }
}

function renderResult(job) {
  selectedRun = job;
  $('response-placeholder').hidden = true; $('response-content').hidden = false;
  $('response-time').textContent = stamp(job.started_at);
  $('full-checks').hidden = true; $('full-checks').replaceChildren(); $('response-body').textContent = '';
  if (job.state === 'error') {
    $('route-caption').textContent = `${nameOf(job.scenario)} · 未完成 · ${stamp(job.finished_at)}`;
    $('response-code').textContent = '—'; $('outcome-title').textContent = '操作未完成';
    $('outcome-description').textContent = job.error;
    $('outcome-badge').textContent = 'ERROR'; $('outcome-badge').className = 'outcome-badge failed';
    return;
  }
  const result = job.result;
  $('outcome-badge').textContent = result.passed ? 'PASS' : 'FAIL';
  $('outcome-badge').className = 'outcome-badge' + (result.passed ? '' : ' failed');
  if (job.scenario === 'full-verify') {
    $('route-caption').textContent = `完整驗證 · ${result.passed_count}/${result.total} · ${stamp(job.finished_at)}`;
    $('response-code').textContent = `${result.passed_count}/${result.total}`;
    $('outcome-title').textContent = result.passed ? '完整驗證通過' : '有檢查未通過';
    $('outcome-description').textContent = '服務存取、政策撤銷、停機拒絕與恢復';
    $('full-checks').hidden = false;
    $('full-checks').replaceChildren(...result.checks.map(c => {
      const row = node('div', undefined, 'check-row' + (c.passed ? '' : ' failed'));
      row.append(node('span', c.passed ? 'PASS' : 'FAIL'), node('span', checkLabels[c.name] || c.name), node('span', statusText(c.result?.status)));
      return row;
    }));
    return;
  }
  const response = result.response;
  $('response-code').textContent = response.status === 0 ? '斷線' : response.status;
  const denied = response.status === 0 || response.status === 403 || response.status === 503;
  $('outcome-title').textContent = result.passed ? denied ? '請求被拒絕，符合預期' : '已取得受保護資源' : '回應不符合預期';
  $('outcome-description').textContent = response.status === 0 ? '未取得 HTTP 回應；明文 client 無法完成連線。' :
    response.status === 403 ? '代理回傳 403；此回應本身不區分原生政策與外部授權的拒絕。' :
    response.status === 200 ? '這是叢集內實際呼叫的回應。' : '請查看回應內容與環境狀態。';
  $('response-time').textContent = `${stamp(job.started_at)} · ${result.elapsed_ms} ms`;
  $('response-body').textContent = response.data ? JSON.stringify(response.data, null, 2) : response.text || response.error || '';
  $('route-caption').textContent = `${nameOf(job.scenario)} · ${statusText(response.status)} · ${stamp(job.finished_at)}`;
}

function renderHistory() {
  $('history-count').textContent = history.length;
  if (!history.length) return;
  $('history').replaceChildren(...history.map(job => {
    const tr = node('tr'); tr.dataset.run = job.id;
    const result = job.result, request = result?.request;
    const running = job.state === 'running';
    tr.append(node('td', stamp(job.started_at)), node('td', nameOf(job.scenario)),
      node('td', request ? `${request.caller} → ${request.target}` : job.scenario === 'full-verify' ? '整個測試環境' : '—'),
      node('td', running ? '執行中' : result?.checks ? `${result.passed_count}/${result.total}` : statusText(result?.response?.status)),
      node('td', running ? '等待結果' : job.state === 'error' ? '未完成' : result?.passed ? 'PASS' : 'FAIL',
        'table-status' + (!running && !result?.passed ? ' failed' : '')));
    tr.tabIndex = 0;
    tr.setAttribute('aria-label', `${nameOf(job.scenario)}，${stamp(job.started_at)}，查看結果`);
    const inspect = () => { if (!running) { if (job.scenario !== 'full-verify') choose(job.scenario, true); renderResult(job); $('experiment').scrollIntoView({block: 'start'}); } };
    tr.addEventListener('click', inspect); tr.addEventListener('keydown', event => { if (event.key === 'Enter') inspect(); });
    return tr;
  }));
}

function busy(isBusy) {
  $('run-scenario').disabled = isBusy; $('full-verify').disabled = isBusy;
  $('run-scenario').classList.toggle('loading', isBusy);
  document.querySelectorAll('.scenario-button').forEach(button => { button.disabled = isBusy; });
}

async function start(name) {
  if (active) return;
  busy(true); errorBanner(); $('run-message').classList.remove('run-error');
  try {
    const job = await api('runs', {method: 'POST', headers: {'content-type': 'application/json', 'x-mesh-console': sessionToken}, body: JSON.stringify({scenario: name})});
    active = job.id;
    $('response-placeholder').hidden = false; $('response-content').hidden = true;
    $('response-placeholder').replaceChildren(node('span', '↳', 'empty-mark loading'), node('div', name === 'full-verify' ? '正在執行完整驗證，結果完成後顯示。' : '請求已送往叢集，等待實際回應。'));
    await watch(job.id);
  } catch (error) {
    errorBanner(error.message); active = null; busy(false);
    $('run-message').textContent = '操作未完成'; $('run-message').classList.add('run-error');
  }
}

async function watch(id) {
  const began = Date.now();
  let job;
  while (true) {
    try {
      const snapshot = await api('runs');
      history = snapshot.runs; renderHistory();
      job = history.find(j => j.id === id) || await api('runs/' + id);
    } catch (error) {
      if (error.status === 404) {
        active = null; busy(false);
        $('run-message').textContent = '找不到原操作，控制程式可能已重新啟動。';
        errorBanner('原操作的結果無法確認。請先更新環境狀態，再決定是否重新執行。');
        return;
      }
      $('run-message').textContent = '連線暫時中斷，正在繼續追蹤同一項操作…';
      await new Promise(resolve => setTimeout(resolve, 1500));
      continue;
    }
    $('run-message').textContent = `正在執行 · ${Math.floor((Date.now() - began) / 1000)} 秒`;
    if (job.state !== 'running') break;
    await new Promise(resolve => setTimeout(resolve, 700));
  }
  active = null; busy(Boolean(job.recovery_required));
  if (job.scenario !== 'full-verify') { scenarioResults.set(job.scenario, job.result?.passed === true); choose(job.scenario, true); }
  renderResult(job); renderScenarios();
  if (job.recovery_required) { busy(true); errorBanner(job.error); }
  $('run-message').textContent = job.state === 'error' ? '未完成，請查看結果' : '執行完成 · ' + stamp(job.finished_at);
  refreshStatus();
  if ($('audit-details').open) loadAudit();
}

async function loadCertificates() {
  $('load-certificates').disabled = true;
  $('certificate-list').replaceChildren(node('p', '正在讀取代理的有效公開憑證…'));
  try {
    const result = await api('certificates');
    $('certificate-list').replaceChildren(...result.certificates.map(c => {
      const item = node('div', undefined, 'certificate-item');
      item.append(node('strong', c.app), node('code', c.uri),
        node('small', `到期 ${stamp(c.not_after, true)} · 有效長度 ${c.lifetime_seconds} 秒`));
      return item;
    }));
  } catch (error) { $('certificate-list').replaceChildren(node('p', error.message, 'run-error')); }
  finally { $('load-certificates').disabled = false; }
}

async function loadAudit() {
  $('refresh-audit').disabled = true; $('audit-message').textContent = '正在讀取…';
  try {
    const result = await api('audit');
    $('audit-message').textContent = `觀測時間 ${stamp(result.observed_at)} · 最近 ${result.events.length} 筆服務決策`;
    $('audit-events').replaceChildren(...result.events.map(e => {
      const tr = node('tr');
      tr.append(node('td', stamp(e.timestamp)), node('td', `${shortIdentity(e.source)} → ${shortIdentity(e.destination)}`),
        node('td', `${e.method} ${e.path}`), node('td', e.decision, 'table-status' + (e.decision === 'ALLOW' ? '' : ' failed')),
        node('td', e.reason === 'workload_grant_matched' ? '符合 workload grant' : e.reason === 'no_workload_grant' ? '沒有對應的 grant' : e.reason || '—'));
      return tr;
    }));
  } catch (error) { $('audit-message').textContent = error.message; $('audit-events').replaceChildren(); }
  finally { $('refresh-audit').disabled = false; }
}

async function boot() {
  busy(true);
  try {
    const session = await api('session'); sessionToken = session.token; scenarios = session.scenarios;
    const initial = new URLSearchParams(location.search).get('scenario');
    choose(scenarios.some(s => s.id === initial) ? initial : 'salary');
    const snapshot = await api('runs'); history = snapshot.runs; renderHistory();
    for (const job of [...history].reverse()) if (job.state === 'done' && job.scenario !== 'full-verify') scenarioResults.set(job.scenario, job.result.passed);
    renderScenarios();
    if (snapshot.active) { active = snapshot.active; watch(snapshot.active).catch(error => { errorBanner(error.message); active = null; busy(false); }); }
    else if (snapshot.blocked) { busy(true); errorBanner('環境恢復未完成，後續操作已鎖定。請依部署說明檢查政策與 replicas。'); }
    else busy(false);
    refreshStatus();
  } catch (error) { errorBanner('無法初始化實驗台。' + error.message); }
}

$('run-scenario').addEventListener('click', () => start(selected));
$('refresh-status').addEventListener('click', refreshStatus);
$('load-certificates').addEventListener('click', loadCertificates);
$('refresh-audit').addEventListener('click', loadAudit);
$('audit-details').addEventListener('toggle', () => { if ($('audit-details').open) loadAudit(); });
$('full-verify').addEventListener('click', () => $('verify-dialog').showModal());
$('verify-dialog').addEventListener('close', () => { if ($('verify-dialog').returnValue === 'run') start('full-verify'); });
$('export-history').addEventListener('click', () => {
  const content = JSON.stringify({exported_at: new Date().toISOString(), environment: state, runs: history}, null, 2);
  const url = URL.createObjectURL(new Blob([content], {type: 'application/json'}));
  const link = node('a'); link.href = url; link.download = '207a-operations.json'; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
for (const link of document.querySelectorAll('.rail nav a')) link.addEventListener('click', () => {
  document.querySelectorAll('.rail nav a').forEach(a => a.classList.toggle('current', a === link));
});
boot();
