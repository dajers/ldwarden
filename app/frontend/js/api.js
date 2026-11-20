import { runGraph, toOutputJson, toMarkdown } from './engine.js';
import { nodeTitle } from './blocks.js';

export const CONFIG = {
  mode: 'auto',
  baseUrl: '/api',
  apiToken: '',
};

const TYPE_TO_BACKEND = {
  'source.repo': 'source.target',
  'scan.secret': 'scan.secrets',
  'ai.explain': 'ai.analyze',
  'logic.branch': 'logic.if',
  'control.gate': 'control.severity_gate',
};

const TYPE_FROM_BACKEND = Object.fromEntries(
  Object.entries(TYPE_TO_BACKEND).map(([front, back]) => [back, front]),
);

const CHANNEL_TO_BACKEND = {
  Telegram: 'telegram',
  'HTTP webhook': 'webhook',
  'E-mail': 'smtp',
};
const CHANNEL_FROM_BACKEND = {
  telegram: 'Telegram',
  webhook: 'HTTP webhook',
  smtp: 'E-mail',
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
const OPERATOR_FROM_BACKEND = { gte: '>=', eq: '==', lte: '<=', gt: '>' };

const CRON_TO_LABEL = {
  '0 14 * * *': 'Каждый день в 14:00',
  '0 * * * *': 'Каждый час',
  '0 9 * * 1': 'По понедельникам в 09:00',
};
const CRON_FROM_LABEL = Object.fromEntries(
  Object.entries(CRON_TO_LABEL).map(([cron, label]) => [label, cron]),
);

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
        cron: CRON_FROM_LABEL[params.cron] || String(params.cron || '0 14 * * *'),
        timezone: 'UTC',
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
    case 'control.gate':
      return {
        threshold: params.threshold || 'HIGH',
        categories: ['SECRET', 'SAST', 'SCA'],
        blocking: params.blocking !== false,
      };
    case 'ai.explain':
      return {
        provider: params.provider || 'auto',
        max_findings: Number(params.maxFindings) || 12,
        threads: Number(params.threads) || 4,
        timeout: Number(params.timeout) || 45,
      };
    case 'notify.send': {
      const channel = CHANNEL_TO_BACKEND[params.channel] || 'telegram';
      const base = {
        channel,
        attach_report: params.attachReport !== false,
        dry_run: Boolean(params.dryRun),
      };
      if (channel === 'telegram') {
        return { ...base, bot_token: params.token || '', chat_id: params.chatId || '' };
      }
      if (channel === 'webhook') {
        return { ...base, url: params.token || 'local://inbox', method: 'POST', secret: params.hmacSecret || '' };
      }
      return {
        ...base,
        password: params.token || '',
        to_addr: params.chatId || '',
      };
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
      return { cron: CRON_TO_LABEL[params.cron] || params.cron || 'Каждый день в 14:00' };
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
        maxFindings: params.max_findings || 12,
        threads: params.threads || 4,
        timeout: params.timeout || 45,
      };
    case 'notify.send': {
      const channel = CHANNEL_FROM_BACKEND[params.channel] || 'Telegram';
      let token = '';
      if (params.channel === 'webhook') token = params.url || '';
      else if (params.channel === 'smtp') token = params.password || '';
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
  return ['out', 'true', 'false', 'pass', 'fail'].includes(port);
}

export function toBackendGraph(workflow) {
  const nodes = (workflow.nodes || [])
    .filter((node) => TYPE_TO_BACKEND[node.type] || node.type.startsWith('trigger.') || ['scan.sca', 'scan.sast', 'notify.send', 'report.build'].includes(node.type))
    .map((node) => ({
      id: node.id,
      type: TYPE_TO_BACKEND[node.type] || node.type,
      position: { x: Number(node.x) || 0, y: Number(node.y) || 0 },
      data: {
        label: nodeTitle(node),
        params: mapParamsToBackend(node),
      },
    }));
  const ids = new Set(nodes.map((node) => node.id));
  const edges = (workflow.edges || [])
    .filter(
      (edge) =>
        ids.has(edge.from.node) &&
        ids.has(edge.to.node) &&
        execPort(edge.from.port) &&
        edge.to.port === 'in',
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
    const frontType = TYPE_FROM_BACKEND[node.type] || node.type;
    if (
      !frontType.startsWith('trigger.') &&
      !['source.repo', 'scan.secret', 'scan.sca', 'scan.sast', 'ai.explain', 'logic.branch', 'control.gate', 'notify.send', 'report.build'].includes(frontType)
    ) {
      continue;
    }
    const params = node.data && node.data.params ? node.data.params : {};
    const mapped = mapParamsFromBackend({ type: node.type, params });
    nodes.push({
      id: node.id,
      type: frontType,
      x: Number(node.position && node.position.x) || 0,
      y: Number(node.position && node.position.y) || 0,
      params: mapped,
    });
  }
  const ids = new Set(nodes.map((node) => node.id));
  const edges = (graph.edges || [])
    .filter((edge) => ids.has(edge.source) && ids.has(edge.target))
    .map((edge) => ({
      id: edge.id,
      from: { node: edge.source, port: edge.sourceHandle || 'out' },
      to: { node: edge.target, port: edge.targetHandle || 'in' },
    }));
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

async function telegramConnect() {
  return request('/telegram/connect', { method: 'POST' });
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
