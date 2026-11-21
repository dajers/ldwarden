import { runGraph, toOutputJson, toMarkdown } from './engine.js';
import { nodeTitle } from './blocks.js';

export const CONFIG = {
  mode: 'auto',
  baseUrl: '/api',
  apiToken: '',
};

const TYPE_TO_BACKEND = {
  'logic.custom': 'logic.custom',
  'logic.regex': 'logic.regex',
  'logic.fork': 'logic.fork',
  'logic.join': 'logic.join',
  'source.repo': 'source.target',
  'scan.secret': 'scan.secrets',
  'ai.explain': 'ai.analyze',
  'logic.branch': 'logic.if',
  'control.gate': 'control.severity_gate',
  'notify.telegram': 'notify.telegram',
  'notify.webhook': 'notify.webhook',
};

const TYPE_FROM_BACKEND = Object.fromEntries(
  Object.entries(TYPE_TO_BACKEND).map(([front, back]) => [back, front]),
);

const CHANNEL_TO_BACKEND = {
  Telegram: 'telegram',
  'HTTP webhook': 'webhook',
};
const CHANNEL_FROM_BACKEND = {
  telegram: 'Telegram',
  webhook: 'HTTP webhook',
};

const FIELD_TO_BACKEND = {
  total: 'findings.total',
  critical: 'findings.CRITICAL',
  secret: 'findings.by_category.SECRET',
};
const FIELD_FROM_BACKEND = {
  'findings.total': 'total',
  'findings.CRITICAL': 'critical',
  'findings.by_category.SECRET': 'secret',
};

const OPERATOR_TO_BACKEND = { '>=': 'gte', '==': 'eq', '<=': 'lte', '>': 'gt' };

const REGEX_FIELD_TO_BACKEND = {
  path: 'findings.path',
  class: 'findings.class',
  message: 'findings.message',
  category: 'findings.category',
};
const REGEX_FIELD_FROM_BACKEND = Object.fromEntries(
  Object.entries(REGEX_FIELD_TO_BACKEND).map(([front, back]) => [back, front]),
);
const OPERATOR_FROM_BACKEND = { gte: '>=', eq: '==', lte: '<=', gt: '>' };

const CRON_TO_LABEL = {
  '0 14 * * *': 'Каждый день в 14:00',
  '0 * * * *': 'Каждый час',
  '0 9 * * 1': 'По понедельникам в 09:00',
};
const CRON_FROM_LABEL = Object.fromEntries(
  Object.entries(CRON_TO_LABEL).map(([cron, label]) => [label, cron]),
);

function scheduleFromCron(cron) {
  const parts = String(cron || '').trim().split(/\s+/);
  let runTime = '09:00';
  let weekday = '*';
  if (parts.length === 5 && /^\d+$/.test(parts[0]) && /^\d+$/.test(parts[1])) {
    runTime = `${String(parts[1]).padStart(2, '0')}:${String(parts[0]).padStart(2, '0')}`;
    if (/^\d+$/.test(parts[4])) {
      const value = Number(parts[4]);
      weekday = value === 0 ? '7' : String(Math.min(7, Math.max(1, value)));
    }
  }
  return { mode: 'weekly', runDate: '', runTime, weekday, cron: '' };
}

const FORMATS_TO_LABEL = {
  'json,md,sarif': 'JSON + Markdown + SARIF',
  'json,md': 'JSON + Markdown',
  'json': 'Только JSON',
  'md': 'Только Markdown',
};
const FORMATS_FROM_LABEL = {
  'JSON + Markdown + SARIF': ['md', 'json', 'sarif'],
  'JSON + Markdown': ['md', 'json'],
  'Только JSON': ['json'],
  'Только Markdown': ['md'],
};

const EVENT_TYPES = [
  'run.started',
  'node.started',
  'node.finished',
  'node.skipped',
  'node.failed',
  'finding',
  'run.finished',
  'run.cancelled',
  'run.failed',
];

let remoteAvailable = CONFIG.mode !== 'mock';

function authToken() {
  try {
    return localStorage.getItem('sakura.apiToken') || CONFIG.apiToken || '';
  } catch {
    return CONFIG.apiToken || '';
  }
}

function isNetworkError(error) {
  return error && !error.status && (error instanceof TypeError || error.name === 'TypeError');
}

async function request(path, options = {}) {
  const method = options.method || 'GET';
  const body = options.body;
  const headers = { ...(options.headers || {}) };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const token = authToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(`${CONFIG.baseUrl}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  if (!response.ok) {
    const message = (data && data.error && data.error.message) || `HTTP ${response.status}`;
    const details = data && data.error && data.error.details;
    const suffix =
      details && Array.isArray(details.errors) && details.errors.length
        ? `: ${details.errors.slice(0, 3).join('; ')}`
        : '';
    const error = new Error(message + suffix);
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
}

function normalizeTarget(value) {
  const target = String(value || '').trim();
  if (!target || target === 'training-project' || target === 'training-main/training-project') return '';
  return target;
}

function targetPayload(workflow) {
  const source = (workflow.nodes || []).find((node) => node.type === 'source.repo');
  const raw = String((source && source.params && source.params.target) || '').trim();
  if (!raw || raw === 'training-project' || raw === 'training-main/training-project') return null;
  if (/^https?:\/\//i.test(raw)) {
    const ref = String((source && source.params && source.params.branch) || '').trim();
    return { kind: 'git', url: raw, ...(ref && ref !== 'main' ? { ref } : {}) };
  }
  return { kind: 'path', path: raw };
}

function mapParamsToBackend(node) {
  const params = node.params || {};
  switch (node.type) {
    case 'trigger.webhook':
      return { secret: params.secret || '', description: params.description || '' };
    case 'trigger.schedule':
      return {
        mode: params.mode || 'weekly',
        run_date: params.runDate || '',
        run_time: params.runTime || '09:00',
        weekday: String(params.weekday || '*'),
        timezone: params.timezone || 'UTC',
        cron: params.cron || '',
      };
    case 'source.repo':
      return {
        path: /^https?:\/\//i.test(String(params.target || '')) ? '' : normalizeTarget(params.target),
        git_token: params.gitToken || '',
        git_username: params.gitUsername || 'x-access-token',
      };
    case 'scan.secret':
      return { min_severity: params.minSeverity || 'LOW' };
    case 'scan.sca':
      return { db_path: params.db && params.db !== 'vulnerabilities.json' ? params.db : '' };
    case 'scan.sast':
      return {};
    case 'logic.branch':
      return {
        field: FIELD_TO_BACKEND[params.field] || params.field || 'findings.CRITICAL',
        operator: OPERATOR_TO_BACKEND[params.operator] || params.operator || 'gte',
        value: String(params.value ?? '1'),
        case_sensitive: Boolean(params.caseSensitive),
      };
    case 'logic.custom':
      return { expr: params.expr || 'critical >= 1' };
    case 'logic.regex':
      return {
        field: REGEX_FIELD_TO_BACKEND[params.field] || 'findings.path',
        pattern: params.pattern || '',
        case_sensitive: false,
        negate: Boolean(params.negate),
      };
    case 'logic.fork':
    case 'logic.join':
      return {};
    case 'control.gate':
      return {
        threshold: params.threshold || 'HIGH',
        categories: ['SECRET', 'SAST', 'SCA'],
        blocking: params.blocking !== false,
      };
    case 'ai.explain':
      return {
        provider: params.provider || 'auto',
        max_findings: Number(params.maxFindings) || 2,
        threads: Number(params.threads) || 4,
        timeout: Number(params.timeout) || 180,
      };
    case 'notify.telegram':
      return {
        bot_token: params.botToken || '',
        chat_id: params.chatId || '',
        subject: params.subject || 'LDWarden: отчёт о проверке',
        attach_report: params.attachReport !== false,
        dry_run: Boolean(params.dryRun),
        fail_on_error: Boolean(params.failOnError),
      };
    case 'notify.webhook':
      return {
        url: params.url || 'local://inbox',
        method: params.method || 'POST',
        secret: params.hmacSecret || '',
        subject: params.subject || 'LDWarden: отчёт о проверке',
        attach_report: params.attachReport !== false,
        dry_run: Boolean(params.dryRun),
        fail_on_error: Boolean(params.failOnError),
      };
    case 'notify.send': {
      const channel = CHANNEL_TO_BACKEND[params.channel] || 'telegram';
      const base = {
        channel,
        subject: params.subject || 'LDWarden: отчёт о проверке',
        attach_report: params.attachReport !== false,
        dry_run: Boolean(params.dryRun),
        fail_on_error: Boolean(params.failOnError),
      };
      if (channel === 'telegram') {
        return { ...base, bot_token: params.token || '', chat_id: params.chatId || '' };
      }
      return { ...base, url: params.token || 'local://inbox', method: 'POST', secret: params.hmacSecret || '' };
    }
    case 'report.build':
      return { formats: FORMATS_FROM_LABEL[params.formats] || ['md', 'json'] };
    default:
      return {};
  }
}

function mapParamsFromBackend(node) {
  const params = node.params || {};
  switch (node.type) {
    case 'trigger.schedule':
      if (params.mode === 'weekly' || params.mode === 'once') {
        return {
          mode: params.mode,
          runDate: params.run_date || '',
          runTime: params.run_time || '09:00',
          weekday: String(params.weekday || '*'),
          timezone: params.timezone || 'UTC',
          cron: params.cron || '',
        };
      }
      return { ...scheduleFromCron(params.cron), timezone: params.timezone || 'UTC' };
    case 'trigger.webhook':
      return { secret: params.secret || '', description: params.description || '' };
    case 'source.target':
      return {
        target: params.path || 'training-project',
        branch: 'main',
        gitToken: params.git_token || '',
        gitUsername: params.git_username || 'x-access-token',
      };
    case 'scan.secrets':
      return { minSeverity: params.min_severity || 'LOW', mask: true };
    case 'scan.sca':
      return { db: params.db_path || 'vulnerabilities.json' };
    case 'scan.sast':
      return { lang: 'Kotlin' };
    case 'logic.if':
      return {
        field: params.field || 'findings.CRITICAL',
        operator: params.operator || 'gte',
        value: String(params.value ?? '1'),
        caseSensitive: Boolean(params.case_sensitive),
      };
    case 'logic.custom':
      return { expr: params.expr || '' };
    case 'logic.regex':
      return {
        field: REGEX_FIELD_FROM_BACKEND[params.field] || 'path',
        pattern: params.pattern || '',
        negate: Boolean(params.negate),
      };
    case 'logic.fork':
    case 'logic.join':
      return {};
    case 'control.severity_gate':
      return { threshold: params.threshold || 'HIGH', blocking: params.blocking !== false };
    case 'ai.analyze':
      return {
        provider: params.provider || 'auto',
        model:
          params.provider === 'openai' || params.provider === 'ollama'
            ? 'GigaChat · API'
            : 'Qwen2.5-Coder 7B · локально',
        tone: 'Для разработчика',
        maxFindings: params.max_findings || 2,
        threads: params.threads || 4,
        timeout: params.timeout || 180,
        ...(params.timeout === 45 && params.max_findings === 12 && params.threads === 4
          ? { maxFindings: 2, threads: 4, timeout: 180 }
          : {}),
      };
    case 'notify.telegram':
      return {
        botToken: params.bot_token || '',
        chatId: params.chat_id || '',
        subject: params.subject || 'LDWarden: отчёт о проверке',
        attachReport: params.attach_report !== false,
        dryRun: Boolean(params.dry_run),
        failOnError: Boolean(params.fail_on_error),
      };
    case 'notify.webhook':
      return {
        url: params.url || 'local://inbox',
        method: params.method || 'POST',
        hmacSecret: params.secret || '',
        subject: params.subject || 'LDWarden: отчёт о проверке',
        attachReport: params.attach_report !== false,
        dryRun: Boolean(params.dry_run),
        failOnError: Boolean(params.fail_on_error),
      };
    case 'notify.send': {
      const channel = CHANNEL_FROM_BACKEND[params.channel] || 'Telegram';
      let token = '';
      if (params.channel === 'webhook') token = params.url || '';
      else token = params.bot_token || '';
      return {
        channel,
        token,
        chatId: params.chat_id || params.to_addr || '',
        attachReport: params.attach_report !== false,
        dryRun: Boolean(params.dry_run),
        hmacSecret: params.secret || '',
      };
    }
    case 'report.build': {
      const formats = Array.isArray(params.formats) ? params.formats.slice().sort().join(',') : 'json,md';
      return { formats: FORMATS_TO_LABEL[formats] || 'JSON + Markdown' };
    }
    default:
      return {};
  }
}

function execPort(port) {
  return ['out', 'true', 'false', 'pass', 'fail', 'a', 'b', 'c'].includes(port);
}

export function toBackendGraph(workflow) {
  const nodes = (workflow.nodes || [])
    .filter((node) => TYPE_TO_BACKEND[node.type] || node.type.startsWith('trigger.') || ['scan.sca', 'scan.sast', 'notify.telegram', 'notify.webhook', 'notify.send', 'report.build'].includes(node.type))
    .map((node) => ({
      id: node.id,
      type: TYPE_TO_BACKEND[node.type] || node.type,
      position: { x: Number(node.x) || 0, y: Number(node.y) || 0 },
      data: {
        label: nodeTitle(node),
        params: mapParamsToBackend(node),
        ...(node.color ? { color: node.color } : {}),
      },
    }));
  const ids = new Set(nodes.map((node) => node.id));
  const edges = (workflow.edges || [])
    .filter(
      (edge) =>
        ids.has(edge.from.node) &&
        ids.has(edge.to.node) &&
        execPort(edge.from.port),
    )
    .map((edge) => ({
      id: edge.id,
      source: edge.from.node,
      sourceHandle: edge.from.port,
      target: edge.to.node,
      targetHandle: 'in',
    }));
  return { nodes, edges };
}

export function fromBackendWorkflow(row) {
  const graph = (row && row.graph) || { nodes: [], edges: [] };
  const nodes = [];
  for (const node of graph.nodes || []) {
    const params = node.data && node.data.params ? node.data.params : {};
    let frontType = TYPE_FROM_BACKEND[node.type] || node.type;
    if (node.type === 'notify.send') {
      frontType = params.channel === 'telegram' ? 'notify.telegram' : 'notify.webhook';
    }
    if (
      !frontType.startsWith('trigger.') &&
      !['source.repo', 'scan.secret', 'scan.sca', 'scan.sast', 'ai.explain', 'logic.branch', 'control.gate', 'logic.custom', 'logic.regex', 'logic.fork', 'logic.join', 'notify.telegram', 'notify.webhook', 'report.build'].includes(frontType)
    ) {
      continue;
    }
    const mapped = mapParamsFromBackend({ type: node.type === 'notify.send' ? frontType : node.type, params });
    const entry = {
      id: node.id,
      type: frontType,
      x: Number(node.position && node.position.x) || 0,
      y: Number(node.position && node.position.y) || 0,
      params: mapped,
    };
    if (node.data && typeof node.data.color === 'string' && node.data.color) entry.color = node.data.color;
    nodes.push(entry);
  }
  const ids = new Set(nodes.map((node) => node.id));
  const joinCounters = new Map();
  const edges = (graph.edges || [])
    .filter((edge) => ids.has(edge.source) && ids.has(edge.target))
    .map((edge) => {
      const target = nodes.find((node) => node.id === edge.target);
      let port = edge.targetHandle || 'in';
      // у «Собирателя» два входных пина: раскладываем связи по ним
      if (target && target.type === 'logic.join') {
        const count = joinCounters.get(target.id) || 0;
        port = count === 0 ? 'a' : 'b';
        joinCounters.set(target.id, count + 1);
      }
      return {
        id: edge.id,
        from: { node: edge.source, port: edge.sourceHandle || 'out' },
        to: { node: edge.target, port },
      };
    });
  return {
    id: row.id || 'wf-' + Date.now().toString(36),
    backendId: row.id || null,
    name: row.name || 'Сценарий',
    nodes,
    edges,
  };
}

function mapTitle(item) {
  return item.message || item.description || item.class || 'Находка';
}

function mapFinding(item, aiById = {}) {
  return {
    id: item.id || item.fingerprint,
    category: item.category,
    class: item.class,
    path: item.path,
    line: item.line,
    endLine: item.end_line || undefined,
    severity: item.severity,
    title: mapTitle(item),
    description: item.description || item.message || '',
    remediation: item.remediation || '',
    why: (aiById[item.id] && aiById[item.id].explanation) || '',
    snippet: item.evidence || '',
    group: item.group,
    artifact: item.artifact,
    version: item.version,
    advisoryId: item.advisory_id || (item.advisory_ids || [])[0] || '',
  };
}

function mapNotification(notification) {
  if (!notification) return null;
  return {
    channel: CHANNEL_FROM_BACKEND[notification.channel] || notification.channel || 'webhook',
    findings: 0,
    at: Date.now(),
    status: notification.status,
    target: notification.target,
    message: notification.message,
  };
}

async function buildResult(runId, workflow, liveFindings) {
  const run = await request(`/runs/${encodeURIComponent(runId)}?reports=1`);
  const findingsResponse = await request(`/runs/${encodeURIComponent(runId)}/findings?limit=2000`);
  const rawFindings = (findingsResponse && findingsResponse.items) || liveFindings || [];
  const ai = run.ai || null;
  const aiById = {};
  if (ai && Array.isArray(ai.findings)) {
    for (const item of ai.findings) aiById[item.finding_id] = item;
  }
  const findings = rawFindings.map((item) => mapFinding(item, aiById));
  findings.sort((a, b) => {
    const order = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    return (order[b.severity] || 0) - (order[a.severity] || 0);
  });
  const aiModel = ai ? [ai.provider, ai.model].filter(Boolean).join(' · ') : '—';
  const aiItems = ai
    ? findings
        .filter((finding) => aiById[finding.id])
        .map((finding) => ({
          id: finding.id,
          title: finding.title,
          why: aiById[finding.id].explanation || '',
        }))
    : [];
  let report = {
    formats: 'JSON + Markdown',
    json: '',
    markdown: '',
  };
  if (run.report_json || run.report_markdown) {
    report = {
      formats: 'JSON + Markdown',
      json: run.report_json ? JSON.stringify(run.report_json, null, 2) : '',
      markdown: run.report_markdown || '',
    };
  } else if (findings.length) {
    report = {
      formats: 'JSON + Markdown',
      json: JSON.stringify(toOutputJson(findings), null, 2),
      markdown: toMarkdown(findings, { target: targetNameFrom(workflow) }),
    };
  }
  const notified = mapNotification(run.summary && run.summary.notification);
  if (notified) notified.findings = findings.length;
  return {
    cancelled: run.status === 'cancelled',
    findings,
    ai: ai
      ? {
          summary: ai.summary || '',
          model: aiModel,
          provider: ai.provider || '',
          validation: ai.validation || {},
          items: aiItems,
        }
      : null,
    notified,
    report,
    duration: run.duration_ms || 0,
    summary: run.summary,
    runId,
  };
}

function targetNameFrom(workflow) {
  const source = (workflow.nodes || []).find((node) => node.type === 'source.repo');
  return (source && source.params && source.params.target) || 'training-project';
}

async function follow(runId, workflow, handlers, token) {
  return new Promise((resolve, reject) => {
    let finished = false;
    const liveFindings = [];
    const source = new EventSource(
      `${CONFIG.baseUrl}/runs/${encodeURIComponent(runId)}/stream?after=0`,
    );

    const close = () => {
      try {
        source.close();
      } catch {
        /* ignore */
      }
    };

    const finish = async (cancelled) => {
      if (finished) return;
      finished = true;
      close();
      try {
        const result = await buildResult(runId, workflow, liveFindings);
        result.cancelled = Boolean(cancelled || result.cancelled);
        handlers.onEvent && handlers.onEvent({ type: 'run.done', result });
        resolve(result);
      } catch (error) {
        reject(error);
      }
    };

    const fail = (message) => {
      if (finished) return;
      finished = true;
      close();
      handlers.onEvent && handlers.onEvent({ type: 'run.error', message });
      reject(new Error(message || 'Ошибка выполнения'));
    };

    const handle = (type, event) => {
      const info = event.payload || {};
      switch (type) {
        case 'run.started': {
          const total = (info.graph && info.graph.nodes && info.graph.nodes.length) || workflow.nodes.length;
          handlers.onEvent && handlers.onEvent({ type: 'run.started', total });
          break;
        }
        case 'node.started':
          handlers.onEvent && handlers.onEvent({ type: 'node.started', nodeId: event.node_id });
          break;
        case 'node.finished': {
          const status = info.status === 'success' ? 'done' : info.status === 'error' ? 'error' : info.status === 'skipped' ? 'skipped' : 'done';
          const chip = String(event.message || '').slice(0, 80);
          handlers.onEvent &&
            handlers.onEvent({
              type: 'node.done',
              nodeId: event.node_id,
              status,
              chip,
              output: info.preview || info.outputs || null,
            });
          const active = Array.isArray(info.active_handles) ? info.active_handles : ['out'];
          for (const edge of workflow.edges || []) {
            if (edge.from.node === event.node_id && active.includes(edge.from.port)) {
              handlers.onEvent && handlers.onEvent({ type: 'edge.active', edgeId: edge.id });
            }
          }
          break;
        }
        case 'node.skipped':
          handlers.onEvent &&
            handlers.onEvent({
              type: 'node.done',
              nodeId: event.node_id,
              status: 'skipped',
              chip: String(event.message || 'не выполнялся').slice(0, 80),
            });
          break;
        case 'node.failed':
          handlers.onEvent &&
            handlers.onEvent({
              type: 'node.done',
              nodeId: event.node_id,
              status: 'error',
              chip: String(event.message || 'ошибка').slice(0, 80),
            });
          break;
        case 'finding': {
          const finding = mapFinding(info);
          liveFindings.push(finding);
          handlers.onEvent && handlers.onEvent({ type: 'findings', items: [finding] });
          break;
        }
        case 'run.finished':
          finish(info.status === 'cancelled');
          break;
        case 'run.cancelled':
          finish(true);
          break;
        case 'run.failed':
          fail(event.message || 'Ошибка выполнения');
          break;
        default:
          break;
      }
    };

    for (const type of EVENT_TYPES) {
      source.addEventListener(type, (event) => {
        let payload;
        try {
          payload = JSON.parse(event.data);
        } catch {
          return;
        }
        handle(type, payload);
      });
    }
    source.onmessage = (event) => {
      let payload;
      try {
        payload = JSON.parse(event.data);
      } catch {
        return;
      }
      if (payload && payload.type) handle(payload.type, payload);
    };
    source.onerror = () => {
      if (finished) return;
      if (token && token.cancelled) {
        finished = true;
        close();
        resolve({ cancelled: true, findings: liveFindings, ai: null, notified: null, report: null, duration: 0 });
      }
    };

    if (token && token.cancelled) {
      cancel(token);
    }
  });
}

async function loadWorkflow() {
  if (!remoteAvailable) return null;
  try {
    const data = await request('/workflows?include_templates=1&limit=200');
    const rows = (data && data.items) || [];
    const withNodes = rows.filter((row) => row.graph && Array.isArray(row.graph.nodes) && row.graph.nodes.length);
    const row =
      withNodes.find((item) => !item.is_template && !item.published) ||
      withNodes.find((item) => item.id === 'tpl-full-audit') ||
      withNodes[0];
    if (!row) return null;
    return { workflow: fromBackendWorkflow(row), backendId: row.id };
  } catch (error) {
    if (CONFIG.mode === 'remote') throw error;
    return null;
  }
}

async function saveWorkflow(workflow) {
  if (!remoteAvailable || !workflow.nodes || !workflow.nodes.length) return null;
  const graph = toBackendGraph(workflow);
  const payload = {
    name: workflow.name || 'Сценарий',
    description: 'Сценарий ldwarden',
    graph,
  };
  try {
    let id = workflow.backendId || null;
    if (id && String(id).startsWith('tpl-')) {
      const clone = await request(`/templates/${encodeURIComponent(id)}/clone`, {
        method: 'POST',
        body: { name: payload.name },
      });
      id = clone.id;
      workflow.backendId = id;
    }
    if (id) {
      try {
        const row = await request(`/workflows/${encodeURIComponent(id)}`, {
          method: 'PUT',
          body: payload,
        });
        workflow.backendId = row.id;
        return { id: row.id };
      } catch (error) {
        if (error.status !== 404) throw error;
        workflow.backendId = null;
      }
    }
    const row = await request('/workflows', { method: 'POST', body: payload });
    workflow.backendId = row.id;
    return { id: row.id };
  } catch (error) {
    if (CONFIG.mode === 'auto' && isNetworkError(error)) {
      remoteAvailable = false;
      return null;
    }
    throw error;
  }
}

async function cancel(token) {
  if (!token || !token.runId || !remoteAvailable) return;
  try {
    await request(`/runs/${encodeURIComponent(token.runId)}/cancel`, { method: 'POST' });
  } catch {
    /* ignore */
  }
}

async function run(workflow, handlers = {}, token = { cancelled: false }) {
  if (!remoteAvailable) return runGraph(workflow, { ...handlers, token });
  try {
    const saved = await saveWorkflow(workflow);
    if (!saved || !saved.id) {
      if (CONFIG.mode === 'auto') return runGraph(workflow, { ...handlers, token });
      throw new Error('Не удалось сохранить сценарий на сервере');
    }
    const response = await request(`/workflows/${encodeURIComponent(saved.id)}/runs`, {
      method: 'POST',
      body: { wait: false, target: targetPayload(workflow) },
    });
    if (token) token.runId = response.id;
    return await follow(response.id, workflow, handlers, token);
  } catch (error) {
    if (CONFIG.mode === 'auto' && isNetworkError(error)) {
      remoteAvailable = false;
      return runGraph(workflow, { ...handlers, token });
    }
    throw error;
  }
}

async function telegramConnect(botToken = '') {
  return request('/telegram/connect', { method: 'POST', body: { bot_token: botToken } });
}

async function telegramChats(state) {
  return request(`/telegram/chats?state=${encodeURIComponent(state)}`);
}

async function telegramLink(state, chatId, workflowId) {
  return request('/telegram/link', {
    method: 'POST',
    body: {
      state,
      chat_id: String(chatId),
      workflow_id: workflowId || undefined,
    },
  });
}

async function libraryPresets(force = false) {
  return request(`/library${force ? '?refresh=1' : ''}`);
}

async function publishLibraryPreset(workflowId, payload = {}) {
  return request('/library/publish', {
    method: 'POST',
    body: { workflow_id: workflowId, ...payload },
  });
}

async function health() {
  if (!remoteAvailable) return null;
  try {
    return await request('/health');
  } catch {
    return null;
  }
}

export const api = {
  run,
  cancel,
  loadWorkflow,
  saveWorkflow,
  libraryPresets,
  publishLibraryPreset,
  health,
  telegramConnect,
  telegramChats,
  telegramLink,
  toBackendGraph,
  fromBackendWorkflow,
  get isRemote() {
    return remoteAvailable;
  },
};
