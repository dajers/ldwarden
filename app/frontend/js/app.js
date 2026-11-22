




import {
  NODE_TYPES,
  CATEGORIES,
  CATEGORY_ORDER,
  PRESETS,
  EMPTY_WORKFLOW,
  NODE_W,
  nodeHeight,
  pinOffsetY,
  portIndex,
  SEVERITY_LABEL,
  SEVERITY_COLOR,
  nodeCat,
  nodeIcon,
  nodeSub,
  nodeTitle,
  clone,
  cloneNode,
  createNode,
} from './blocks.js';
import { api } from './api.js';
import { plural, summarize, toHtml, toMarkdown, toOutputJson } from './engine.js';
import { evaluateExpression } from './expression.js';





const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const NS = 'http://www.w3.org/2000/svg';
const LS_WORKFLOW = 'sakura.graph.v1';
const LS_HISTORY = 'sakura.history.v1';
const LS_PRESETS = 'sakura.presets.v1';

function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else if (key === 'dataset') Object.assign(node.dataset, value);
    else if (key === 'style') node.setAttribute('style', value);
    else if (key.startsWith('on') && typeof value === 'function') node.addEventListener(key.slice(2).toLowerCase(), value);
    else node.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat(3)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child.nodeType ? child : document.createTextNode(String(child)));
  }
  return node;
}

function svgIcon(name) {
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('class', 'icon');
  const use = document.createElementNS(NS, 'use');
  use.setAttribute('href', `#i-${name}`);
  svg.append(use);
  return svg;
}

function svgPath(d, cls) {
  const path = document.createElementNS(NS, 'path');
  path.setAttribute('d', d);
  path.setAttribute('class', cls);
  path.setAttribute('vector-effect', 'non-scaling-stroke');
  return path;
}

function toast(message, kind = 'info') {
  const node = h(
    'div',
    { class: `toast toast--${kind}`, role: 'status' },
    svgIcon(kind === 'ok' ? 'check' : kind === 'warn' ? 'alert' : 'sparkles'),
    h('span', { text: message }),
  );
  $('#toasts').append(node);
  setTimeout(() => {
    node.classList.add('is-out');
    setTimeout(() => node.remove(), 220);
  }, 2600);
}

function download(filename, text, mime) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 800);
}

async function copy(text, message = 'Скопировано') {
  try {
    await navigator.clipboard.writeText(text);
    toast(message, 'ok');
    return;
  } catch {

  }
  try {
    const area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.append(area);
    area.select();
    document.execCommand('copy');
    area.remove();
    toast(message, 'ok');
  } catch {
    toast('Браузер не разрешил копирование', 'warn');
  }
}

const clamp = (v, min, max) => Math.min(max, Math.max(min, v));
const snap = (v, step = 10) => Math.round(v / step) * step;






const THEME_KEY = 'sakura.theme';
const THEMES = ['sakura', 'mono', 'warden', 'github', 'github-dark'];
const THEME_ICONS = { sakura: 'i-theme-blossom', mono: 'i-theme-contrast', warden: 'i-shield', github: 'i-theme-branch', 'github-dark': 'i-theme-branch' };
let currentTheme = readTheme();

function readTheme() {
  try {
    const saved = localStorage.getItem(THEME_KEY);
    if (THEMES.includes(saved)) return saved;
  } catch {

  }
  return 'sakura';
}

function applyTheme(theme, { persist = true } = {}) {
  const next = THEMES.includes(theme) ? theme : 'sakura';
  currentTheme = next;
  document.documentElement.dataset.theme = next;
  if (persist) {
    try {
      localStorage.setItem(THEME_KEY, next);
    } catch {

    }
  }
  for (const option of $$('.theme-option')) option.classList.toggle('is-active', option.dataset.theme === next);
  const triggerIcon = $('#themeBtn use');
  if (triggerIcon) triggerIcon.setAttribute('href', `#${THEME_ICONS[next] || 'i-theme-contrast'}`);
}

function initThemeSwitch() {
  const button = $('#themeBtn');
  const menu = $('#themeMenu');
  const close = () => {
    menu.classList.remove('is-open');
    button.setAttribute('aria-expanded', 'false');
  };

  button.addEventListener('click', (event) => {
    event.stopPropagation();
    const open = menu.classList.toggle('is-open');
    button.setAttribute('aria-expanded', String(open));
  });

  for (const option of $$('.theme-option')) {
    option.addEventListener('click', (event) => {
      event.stopPropagation();
      applyTheme(option.dataset.theme);
      close();
    });
  }

  document.addEventListener('click', (event) => {
    if (!event.target.closest('#themeSwitch')) close();
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') close();
  });
}





let edgeMenuTarget = null;

function openEdgeData(edge) {
  const source = findNode(edge.from.node);
  const target = findNode(edge.to.node);
  const output = state.outputs[edge.from.node];
  const status = state.statuses[edge.from.node] || '';
  const kind = portKind(source, edge.from.port, 'out');
  const statusLabel = { done: 'выполнена', error: 'ошибка', running: 'выполняется', skipped: 'пропущена', pending: 'ожидает' }[status] || status || 'не выполнялась';
  const size = output ? new Blob([JSON.stringify(output)]).size : 0;
  const rows = [
    ['Нода-источник', nodeTitle(source)],
    ['Нода-приёмник', nodeTitle(target)],
    ['Порт', edge.from.port || 'out'],
    ['Тип связи', kind === 'data' ? 'данные' : 'выполнение'],
    ['Статус', statusLabel],
    ['Размер данных', size ? `${size} Б` : '—'],
  ];
  const preview = output ? JSON.stringify(output, null, 2) : 'Нода ещё не выполнялась — данных пока нет.';
  $('#modalTitle').textContent = 'Данные связи';
  $('#modalBody').replaceChildren(
    h('div', { class: 'run-detail__meta edge-data__meta' },
      ...rows.map(([label, value]) => h('div', {}, h('span', { text: label }), h('b', { text: String(value) })))),
    h('h3', { class: 'run-detail__subtitle', text: 'Что передаётся' }),
    h('pre', { class: 'node-editor__test edge-data__preview', text: preview.slice(0, 8000) }),
    h('div', { class: 'run-detail__actions' },
      (() => {
        const sourceButton = h('button', { class: 'btn btn--ghost btn--sm', type: 'button', text: 'Открыть источник' });
        sourceButton.addEventListener('click', () => { closeModal(); selectNode(source.id); });
        return sourceButton;
      })(),
      (() => {
        const targetButton = h('button', { class: 'btn btn--ghost btn--sm', type: 'button', text: 'Открыть приёмник' });
        targetButton.addEventListener('click', () => { closeModal(); selectNode(target.id); });
        return targetButton;
      })()),
  );
  $('#modal').hidden = false;
}

function openEdgeMenu(edge, x, y) {
  const menu = $('#edgeMenu');
  edgeMenuTarget = edge;
  menu.hidden = false;

  for (const swatch of $$('.edge-swatch[data-color]')) {
    const value = swatch.dataset.color;
    swatch.classList.toggle('is-active', value === 'theme' ? !edge.color : value === edge.color);
  }
  const custom = $('#edgeCustom');
  if (edge.color) custom.value = edge.color;

  const rect = menu.getBoundingClientRect();
  const pad = 10;
  let left = x + 12;
  let top = y + 12;
  if (left + rect.width > window.innerWidth - pad) left = x - rect.width - 12;
  if (top + rect.height > window.innerHeight - pad) top = y - rect.height - 12;
  menu.style.left = `${Math.max(pad, left)}px`;
  menu.style.top = `${Math.max(pad, top)}px`;
}

function closeEdgeMenu() {
  const menu = $('#edgeMenu');
  if (menu) menu.hidden = true;
  edgeMenuTarget = null;
}

function setEdgeColor(color) {
  if (!edgeMenuTarget) return;
  if (color) edgeMenuTarget.color = color;
  else delete edgeMenuTarget.color;
  saveWorkflow();
  renderWires();
}

function initEdgeMenu() {
  const menu = $('#edgeMenu');

  for (const swatch of $$('.edge-swatch[data-color]')) {
    swatch.addEventListener('click', (event) => {
      event.stopPropagation();
      if (!edgeMenuTarget) return;
      const value = swatch.dataset.color;
      setEdgeColor(value === 'theme' ? null : value);
      closeEdgeMenu();
    });
  }

  $('#edgeCustom').addEventListener('change', (event) => {
    if (!edgeMenuTarget) return;
    setEdgeColor(event.target.value);
  });

  $('#edgeDataBtn').addEventListener('click', (event) => {
    event.stopPropagation();
    if (!edgeMenuTarget) return;
    const edge = edgeMenuTarget;
    closeEdgeMenu();
    openEdgeData(edge);
  });

  $('#edgeReset').addEventListener('click', (event) => {
    event.stopPropagation();
    setEdgeColor(null);
    closeEdgeMenu();
  });

  $('#edgeDelete').addEventListener('click', (event) => {
    event.stopPropagation();
    if (!edgeMenuTarget) return;
    const id = edgeMenuTarget.id;
    closeEdgeMenu();
    deleteEdge(id);
  });

  menu.addEventListener('click', (event) => event.stopPropagation());

  document.addEventListener('click', () => closeEdgeMenu());
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') closeEdgeMenu();
  });
  window.addEventListener('blur', closeEdgeMenu);
}





const state = {
  workflow: loadWorkflow(),
  selectedNode: null,
  selectedNodes: [],
  selectedEdge: null,
  view: { x: 0, y: 0, z: 1 },
  statuses: {},
  chips: {},
  outputs: {},
  running: false,
  token: null,
  run: null,
  liveFindings: [],
  activeFindingId: null,
  tab: 'findings',
  history: loadHistory(),
  activePresetId: null,
  workspaceView: 'graph',
  presetQuery: '',
  libraryQuery: '',
  libraryData: null,
  libraryItems: [],
  libraryAt: 0,
  libraryLoading: false,
  libraryError: '',
  libraryFilter: 'all',
  schedulerEnabled: null,
  models: [],
  modelsLoaded: false,
  runs: [],
  schedules: [],
  runsTimer: null,
  runsLoading: false,
  customNodes: [],
  customCatalog: {},
  compositeEdit: null,
  ciWorkflows: null,
  ciWorkflowId: '',
  ciPlatform: 'github',
  ciSnippet: '',
  ciInfo: null,
  ciLoading: false,
  ciError: '',
  ciBaseUrl: '',
  ciTarget: '',
  generatorResult: null,
  generatorLoading: false,
  generatorError: '',
  undoStack: [],
  redoStack: [],
  historyCurrent: null,
  clipboard: null,
};

state.historyCurrent = clone(state.workflow);
let customPresets = loadCustomPresets();
let syncTimer = null;
let syncWarned = false;

function setSavePill(text, kind = 'quiet') {
  const pill = $('#savePill');
  if (!pill) return;
  pill.classList.toggle('pill--quiet', kind !== 'ok');
  pill.replaceChildren(svgIcon('save'), document.createTextNode(text));
}

function setAiPill(text) {
  const pill = $('#aiPill');
  if (!pill) return;
  pill.replaceChildren(h('span', { class: 'pill__dot' }), document.createTextNode(text));
}

async function hydrateRemote() {
  if (!api.isRemote) return;
  try {
    const health = await api.health();
    if (health && health.llm) {
      const provider = health.llm.provider || 'none';
      let label = { local: 'AI · локальная модель', fake: 'AI · тест', openai: 'AI · API', ollama: 'AI · Ollama', none: 'AI · fallback' }[provider] || `AI · ${provider}`;
      if (provider === 'local' && health.llm.ready === false) label = 'AI · fallback (нет llama-cpp)';
      setAiPill(label);
    }
    if (health && health.scheduler) {
      state.schedulerEnabled = Boolean(health.scheduler.enabled);
    }
    await loadCustomCatalog();
    await refreshCustomNodes();
    const catalog = await api.models();
    if (catalog) {
      state.models = Array.isArray(catalog.items) ? catalog.items : [];
      state.modelsLoaded = true;
      if (state.selectedNode && findNode(state.selectedNode)?.type === 'ai.explain') renderInspector();
    }
  } catch {

  }
  try {
    const remote = await api.loadWorkflow();
    if (remote && remote.workflow && remote.workflow.nodes.length) {
      state.workflow = remote.workflow;
      state.selectedNode = null;
      state.selectedNodes = [];
      state.selectedEdge = null;
      state.activePresetId = null;
      resetStatuses();
      resetHistory();
      renderAll();
      fitView();
      try {
        localStorage.setItem(LS_WORKFLOW, JSON.stringify(localSnapshot(state.workflow)));
      } catch {

      }
      setSavePill(remote.backendId && String(remote.backendId).startsWith('tpl-') ? 'Шаблон с сервера' : 'Синхронизировано', 'ok');
      toast('Сценарий загружен с сервера', 'ok');
    } else {
      setSavePill('Локальный черновик');
    }
  } catch (error) {
    setSavePill('Локальный черновик');
    if (error && error.status) toast(error.message, 'warn');
  }
}

async function syncRemote() {
  if (!api.isRemote || !state.workflow.nodes.length) return false;
  try {
    const saved = await api.saveWorkflow(state.workflow);
    if (saved && saved.id) {
      state.workflow.backendId = saved.id;
      setSavePill('Сохранено на сервере', 'ok');
      syncWarned = false;
      return true;
    }
  } catch (error) {
    setSavePill('Локальный черновик');
    if (!syncWarned) {
      syncWarned = true;
      toast(error && error.message ? error.message : 'Не удалось сохранить на сервере', 'warn');
    }
  }
  return false;
}

function migrateLegacyNotify(node) {
  if (!node || node.type !== 'notify.send') return node;
  const params = node.params || {};
  const channel = String(params.channel || '').toLowerCase();
  if (channel === 'telegram') {
    return { ...node, type: 'notify.telegram', params: {
      botToken: params.botToken || params.bot_token || params.token || '',
      chatId: params.chatId || params.chat_id || '',
      subject: params.subject || 'LDWarden: отчёт о проверке',
      attachReport: params.attachReport !== false,
      dryRun: Boolean(params.dryRun || params.dry_run),
      failOnError: Boolean(params.failOnError || params.fail_on_error),
    } };
  }
  return { ...node, type: 'notify.webhook', params: {
    url: params.url || params.token || 'local://inbox',
    method: params.method || 'POST',
    hmacSecret: params.hmacSecret || params.secret || '',
    subject: params.subject || 'LDWarden: отчёт о проверке',
    attachReport: params.attachReport !== false,
    dryRun: Boolean(params.dryRun || params.dry_run),
    failOnError: Boolean(params.failOnError || params.fail_on_error),
  } };
}

function normalizeGraph(raw) {
  const sourceNodes = Array.isArray(raw && raw.nodes) ? raw.nodes.map(migrateLegacyNotify) : [];
  const nodes = sourceNodes.filter((n) => n && NODE_TYPES[n.type]);
  const normalized = nodes.map((n) => {
    const def = NODE_TYPES[n.type];
    const params = {};
    for (const p of def.params) params[p.key] = n.params && p.key in n.params ? n.params[p.key] : p.def;
    if (n.type === 'trigger.schedule' && n.params && !n.params.mode && n.params.cron) {
      const legacy = String(n.params.cron);
      if (legacy === 'Каждый день в 14:00') {
        params.mode = 'weekly';
        params.weekday = '*';
        params.runTime = '14:00';
      } else if (legacy === 'По понедельникам в 09:00') {
        params.mode = 'weekly';
        params.weekday = '1';
        params.runTime = '09:00';
      } else if (legacy === 'Каждый час') {
        params.mode = 'weekly';
        params.weekday = '*';
        params.runTime = '09:00';
      } else {
        const fields = legacy.trim().split(/\s+/);
        if (fields.length === 5 && /^\d+$/.test(fields[0]) && /^\d+$/.test(fields[1])) {
          params.mode = 'weekly';
          params.runTime = `${String(fields[1]).padStart(2, '0')}:${String(fields[0]).padStart(2, '0')}`;
          params.weekday = /^\d$/.test(fields[4]) ? String(Number(fields[4]) === 0 ? 7 : Number(fields[4])) : '*';
        }
      }
      params.cron = '';
    }
    if (n.type === 'ai.explain' && ['Qwen2.5-Coder 7B · локально', 'Llama 3.1 8B · локально', 'GigaChat · API'].includes(params.model)) {
      params.model = 'auto';
    }
    if (n.type === 'ai.explain' && params.timeout === 45 && params.maxFindings === 12 && params.threads === 4) {
      params.timeout = 180;
      params.maxFindings = 2;
      params.threads = 4;
    }
    if (n.type === 'logic.branch') {
      const fields = { total: 'findings.total', critical: 'findings.CRITICAL', secret: 'findings.by_category.SECRET' };
      const operators = { '>=': 'gte', '==': 'eq', '<=': 'lte', '>': 'gt' };
      if (fields[params.field]) params.field = fields[params.field];
      if (n.params && operators[n.params.op]) params.operator = operators[n.params.op];
      params.value = String(params.value);
    }
    const node = {
      id: n.id || newIdent('n'),
      type: n.type,
      x: Number.isFinite(n.x) ? n.x : 120,
      y: Number.isFinite(n.y) ? n.y : 160,
      params,
    };
    if (typeof n.color === 'string' && n.color) node.color = n.color;
    return node;
  });
  const ids = new Set(normalized.map((n) => n.id));
  const edges = Array.isArray(raw && raw.edges)
    ? raw.edges.filter((e) => e && e.from && e.to && ids.has(e.from.node) && ids.has(e.to.node))
    : [];
  return {
    id: (raw && raw.id) || 'wf-' + Date.now().toString(36),
    backendId: (raw && raw.backendId) || null,
    name: (raw && raw.name) || 'Сценарий',
    nodes: normalized,
    edges,
  };
}

const newIdent = (prefix) => `${prefix}-${Date.now().toString(36)}-${Math.floor(Math.random() * 1e5).toString(36)}`;

function loadWorkflow() {
  try {
    const raw = localStorage.getItem(LS_WORKFLOW);
    if (!raw) return clone(EMPTY_WORKFLOW);
    const parsed = JSON.parse(raw);
    if (!parsed) return clone(EMPTY_WORKFLOW);
    return normalizeGraph(parsed);
  } catch {
    return clone(EMPTY_WORKFLOW);
  }
}

function localSnapshot(workflow) {
  const copy = clone(workflow);
  for (const node of copy.nodes || []) {
    if (node.type === 'source.repo' && node.params && node.params.gitToken) node.params.gitToken = '••••••';
    if (node.type === 'notify.telegram' && node.params && node.params.botToken) node.params.botToken = '••••••';
    if (node.type === 'notify.webhook' && node.params && node.params.hmacSecret) node.params.hmacSecret = '••••••';
    if (node.type === 'notify.send' && node.params) {
      if (node.params.token) node.params.token = '••••••';
      if (node.params.hmacSecret) node.params.hmacSecret = '••••••';
    }
    if (node.type === 'trigger.webhook' && node.params && node.params.secret) node.params.secret = '••••••';
  }
  return copy;
}

function updateActivePreset() {
  if (!state.activePresetId) return;
  const preset = customPresets.find((item) => item.id === state.activePresetId);
  if (!preset) return;
  const snapshot = localSnapshot(state.workflow);
  preset.workflow = {
    name: preset.name,
    nodes: clone(snapshot.nodes),
    edges: clone(snapshot.edges),
  };
  saveCustomPresets();
}

function resetHistory() {
  state.undoStack = [];
  state.redoStack = [];
  state.historyCurrent = clone(state.workflow);
}

function recordHistory() {
  const current = clone(state.workflow);
  if (!state.historyCurrent) {
    state.historyCurrent = current;
    return;
  }
  if (JSON.stringify(current) === JSON.stringify(state.historyCurrent)) return;
  state.undoStack.push(state.historyCurrent);
  state.undoStack = state.undoStack.slice(-50);
  state.redoStack = [];
  state.historyCurrent = current;
}

function undo() {
  if (!state.undoStack.length) return false;
  const previous = state.undoStack.pop();
  state.redoStack.push(clone(state.workflow));
  state.workflow = previous;
  state.historyCurrent = clone(previous);
  state.selectedNode = null;
  state.selectedNodes = [];
  state.selectedEdge = null;
  renderAll();
  renderInspector();
  saveWorkflow({ noHistory: true });
  toast('Действие отменено', 'ok');
  return true;
}

function redo() {
  if (!state.redoStack.length) return false;
  const next = state.redoStack.pop();
  state.undoStack.push(clone(state.workflow));
  state.workflow = next;
  state.historyCurrent = clone(next);
  state.selectedNode = null;
  state.selectedNodes = [];
  state.selectedEdge = null;
  renderAll();
  renderInspector();
  saveWorkflow({ noHistory: true });
  toast('Действие повторено', 'ok');
  return true;
}

function copySelectedNodes() {
  const ids = new Set(state.selectedNodes || []);
  if (state.selectedEdge) {
    const edge = state.workflow.edges.find((item) => item.id === state.selectedEdge);
    if (edge) {
      ids.add(edge.from.node);
      ids.add(edge.to.node);
    }
  }
  if (!ids.size) return false;
  const nodes = state.workflow.nodes.filter((node) => ids.has(node.id));
  const edges = state.workflow.edges.filter(
    (edge) => ids.has(edge.from.node) && ids.has(edge.to.node),
  );
  state.clipboard = { nodes: clone(nodes), edges: clone(edges) };
  toast(`Скопировано узлов: ${nodes.length}, связей: ${edges.length}`, 'ok');
  return true;
}

function pasteNodes() {
  if (!state.clipboard || !state.clipboard.nodes.length) return false;
  const idMap = new Map();
  const pasted = state.clipboard.nodes.map((node) => {
    const id = 'n-' + Math.random().toString(36).slice(2, 9);
    idMap.set(node.id, id);
    return { ...clone(node), id, x: (Number(node.x) || 0) + 40, y: (Number(node.y) || 0) + 40 };
  });
  const pastedEdges = state.clipboard.edges
    .filter((edge) => idMap.has(edge.from.node) && idMap.has(edge.to.node))
    .map((edge) => ({
      ...clone(edge),
      id: 'e-' + Math.random().toString(36).slice(2, 9),
      from: { ...edge.from, node: idMap.get(edge.from.node) },
      to: { ...edge.to, node: idMap.get(edge.to.node) },
    }));
  state.workflow.nodes.push(...pasted);
  state.workflow.edges.push(...pastedEdges);
  state.selectedNode = pasted[0] ? pasted[0].id : null;
  state.selectedNodes = pasted.map((node) => node.id);
  state.selectedEdge = null;
  renderAll();
  renderInspector();
  saveWorkflow();
  toast(`Вставлено узлов: ${pasted.length}, связей: ${pastedEdges.length}`, 'ok');
  return true;
}

function saveWorkflow(options = {}) {
  if (!options.noHistory) recordHistory();
  try {
    localStorage.setItem(LS_WORKFLOW, JSON.stringify(localSnapshot(state.workflow)));
  } catch {

  }
  updateActivePreset();
  if (state.compositeEdit) return;
  if (!api.isRemote || !state.workflow.nodes.length) return;
  setSavePill('Сохраняем…');
  clearTimeout(syncTimer);
  syncTimer = setTimeout(syncRemote, 650);
}

function loadHistory() {
  try {
    const parsed = JSON.parse(localStorage.getItem(LS_HISTORY) || '[]');
    return Array.isArray(parsed) ? parsed.slice(0, 10) : [];
  } catch {
    return [];
  }
}

function saveHistoryEntry(result) {
  const entry = {
    id: 'run-' + Date.now().toString(36),
    at: new Date().toISOString(),
    target: targetName(),
    nodes: state.workflow.nodes.length,
    findings: result.findings,
    ai: result.ai,
    report: result.report,
    notified: result.notified,
    duration: result.duration,
  };
  state.history.unshift(entry);
  state.history = state.history.slice(0, 10);
  try {
    localStorage.setItem(LS_HISTORY, JSON.stringify(state.history));
  } catch {

  }
}

function targetName() {
  const node = state.workflow.nodes.find((n) => n.type === 'source.repo');
  return (node && node.params.target) || 'training-project';
}

const findNode = (id) => state.workflow.nodes.find((n) => n.id === id) || null;





function pinPosition(node, portId, dir) {
  const index = Math.max(0, portIndex(node.type, portId, dir));
  return {
    x: dir === 'out' ? node.x + NODE_W : node.x,
    y: node.y + pinOffsetY(node.type, index),
  };
}

function portKind(node, portId, dir) {
  const def = NODE_TYPES[node.type];
  const list = dir === 'out' ? def.outputs : def.inputs;
  return (list.find((p) => p.id === portId) || {}).kind || 'exec';
}

function nearestLinkMagnet(clientX, clientY, current) {
  const viewport = $('#viewport').getBoundingClientRect();
  let best = null;
  for (const pinEl of $$('.pin')) {
    if (pinEl.dataset.node === current.node.id) continue;
    if (pinEl.dataset.kind !== current.kindPin) continue;
    if (pinEl.dataset.dir === current.dir) continue;
    const node = findNode(pinEl.dataset.node);
    if (!node) continue;
    const world = pinPosition(node, pinEl.dataset.port, pinEl.dataset.dir);
    const x = viewport.left + state.view.x + world.x * state.view.z;
    const y = viewport.top + state.view.y + world.y * state.view.z;
    const distance = Math.hypot(x - clientX, y - clientY);
    if (distance <= 46 && (!best || distance < best.distance)) {
      best = { node, port: pinEl.dataset.port, dir: pinEl.dataset.dir, el: pinEl, distance, x: world.x, y: world.y };
    }
  }
  return best;
}

function setLinkMagnet(target) {
  for (const pinEl of $$('.pin.is-magnet')) pinEl.classList.remove('is-magnet');
  if (target) target.el.classList.add('is-magnet');
}

function wireGeometry(from, to) {
  const dx = to.x - from.x;
  const out = dx < 0 ? Math.max(70, Math.abs(dx) * 0.5) : Math.max(22, Math.min(160, dx * 0.5));
  const c1 = { x: from.x + out, y: from.y };
  const c2 = { x: to.x - out, y: to.y };
  const d = `M ${from.x} ${from.y} C ${c1.x} ${c1.y}, ${c2.x} ${c2.y}, ${to.x} ${to.y}`;
  const angle = (Math.atan2(to.y - c2.y, to.x - c2.x) * 180) / Math.PI;
  return { d, angle };
}





function renderPalette() {
  const root = $('#palette');
  root.replaceChildren();

  for (const cat of CATEGORY_ORDER) {
    const entries = Object.entries(NODE_TYPES).filter(([, def]) => def.cat === cat);
    if (!entries.length) continue;

    const group = h('section', { class: 'palette__group' });
    group.append(h('h3', { class: 'palette__group-title' }, h('i', { style: `background:${CATEGORIES[cat].color}` }), CATEGORIES[cat].label));

    for (const [type, def] of entries) {
      const item = h(
        'div',
        { class: 'palette-item', role: 'button', tabindex: '0', dataset: { type } },
        h('span', { class: 'palette-item__icon' }, svgIcon(def.icon)),
        h(
          'span',
          { class: 'palette-item__text' },
          h('span', { class: 'palette-item__title', text: def.title }),
          h('span', { class: 'palette-item__sub', text: def.sub(defaultParams(def)) }),
        ),
      );
      item.style.setProperty('--cat', CATEGORIES[cat].color);
      item.style.setProperty('--tint', CATEGORIES[cat].tint);
      item.addEventListener('pointerdown', (event) => startPaletteDrag(event, type));
      item.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          addNodeAtCenter(type);
        }
      });
      group.append(item);
    }
    root.append(group);
  }
}

function defaultParams(def) {
  const params = {};
  for (const p of def.params) params[p.key] = p.def;
  return params;
}

function loadCustomPresets() {
  try {
    const parsed = JSON.parse(localStorage.getItem(LS_PRESETS) || '[]');
    return Array.isArray(parsed) ? parsed.filter((item) => item && item.name && item.workflow) : [];
  } catch {
    return [];
  }
}

function saveCustomPresets() {
  try {
    localStorage.setItem(LS_PRESETS, JSON.stringify(customPresets));
  } catch {

  }
}

function saveCurrentAsPreset() {
  if (!state.workflow.nodes.length) {
    toast('Сначала добавьте узлы в сценарий', 'warn');
    return;
  }
  const suggested = state.workflow.name && state.workflow.name !== 'Новый сценарий' ? state.workflow.name : 'Мой пресет';
  const name = window.prompt('Название пресета', suggested);
  if (!name || !name.trim()) return;
  const snapshot = localSnapshot(state.workflow);
  const preset = {
    id: 'custom-' + Date.now().toString(36),
    name: name.trim().slice(0, 60),
    workflow: {
      name: name.trim().slice(0, 60),
      nodes: clone(snapshot.nodes),
      edges: clone(snapshot.edges),
    },
  };
  customPresets = [...customPresets.filter((item) => item.name !== preset.name), preset].slice(-20);
  state.activePresetId = preset.id;
  saveCustomPresets();
  saveWorkflow();
  renderPresets();
  toast(`Пресет «${preset.name}» сохранён`, 'ok');
}

function deleteCustomPreset(id) {
  const preset = customPresets.find((item) => item.id === id);
  if (!preset) return;
  if (!window.confirm(`Удалить пресет «${preset.name}»?`)) return;
  customPresets = customPresets.filter((item) => item.id !== id);
  if (state.activePresetId === id) state.activePresetId = null;
  saveCustomPresets();
  renderPresets();
  toast(`Пресет «${preset.name}» удалён`, 'ok');
}

function presetBundle(presets) {
  return {
    format: 'ldwarden-presets/v1',
    exported_at: new Date().toISOString(),
    presets: presets.map((preset) => ({
      id: preset.id,
      name: preset.name,
      workflow: {
        name: preset.workflow.name,
        nodes: preset.workflow.nodes,
        edges: preset.workflow.edges,
      },
    })),
  };
}

function usedCustomTypes(workflow) {
  return [...new Set((workflow && workflow.nodes || []).map((node) => node.type).filter((type) => String(type).startsWith('custom-')))];
}

async function exportPreset(preset) {
  if (!preset || !preset.workflow) return;
  const types = usedCustomTypes(preset.workflow);
  download(
    `ldwarden-preset-${preset.name.replace(/[^a-zA-Z0-9._-]+/g, '-').slice(0, 50) || 'preset'}.json`,
    JSON.stringify(presetBundle([preset]), null, 2),
    'application/json',
  );
  for (const type of types) await downloadCustomNode(type);
  toast(
    types.length ? `Пресет и ${types.length} нод(ы) выгружены отдельными файлами` : `Пресет «${preset.name}» выгружен`,
    'ok',
  );
}

function pickNodeFiles() {
  return new Promise((resolve) => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json,application/json';
    input.multiple = true;
    input.addEventListener('change', () => resolve([...(input.files || [])]));
    input.click();
  });
}

function exportCustomPresets() {
  if (!customPresets.length) {
    toast('Сначала создайте свой пресет', 'warn');
    return;
  }
  download('ldwarden-presets.json', JSON.stringify(presetBundle(customPresets), null, 2), 'application/json');
  toast(`Выгружено пресетов: ${customPresets.length}`, 'ok');
}

function normalizeImportedPreset(raw) {
  if (!raw || typeof raw !== 'object' || !raw.name || !raw.workflow) return null;
  const nodes = Array.isArray(raw.workflow.nodes) ? raw.workflow.nodes : [];
  const edges = Array.isArray(raw.workflow.edges) ? raw.workflow.edges : [];
  if (!nodes.length) return null;
  return {
    id: String(raw.id || 'custom-' + Date.now().toString(36) + '-' + Math.floor(Math.random() * 1e5)),
    name: String(raw.name).trim().slice(0, 60) || 'Импортированный пресет',
    workflow: {
      name: String(raw.workflow.name || raw.name).trim().slice(0, 60) || 'Импортированный пресет',
      nodes: clone(nodes),
      edges: clone(edges),
    },
  };
}

async function importCustomPresets(file) {
  if (!file) return;
  try {
    const text = await file.text();
    const parsed = JSON.parse(text);
    const list = Array.isArray(parsed) ? parsed : parsed && Array.isArray(parsed.presets) ? parsed.presets : [parsed];
    const incoming = list.map(normalizeImportedPreset).filter(Boolean);
    if (!incoming.length) throw new Error('В файле нет валидных пресетов');
    const needed = new Set();
    for (const preset of incoming) for (const type of usedCustomTypes(preset.workflow)) needed.add(type);
    const missing = [...needed].filter((type) => !(state.customNodes || []).some((node) => node.id === type));
    if (missing.length) {
      toast(`В пресете ${missing.length} своих нод — выберите их .node.json файлы`, 'info');
      const files = await pickNodeFiles();
      for (const nodeFile of files) {
        try {
          await api.importCustomNode(JSON.parse(await nodeFile.text()));
        } catch (error) {
          toast(`Не удалось импортировать ${nodeFile.name}`, 'warn');
        }
      }
      if (files.length) {
        await loadCustomCatalog();
        await refreshCustomNodes();
      }
      const stillMissing = missing.filter((type) => !(state.customNodes || []).some((node) => node.id === type));
      if (stillMissing.length) toast(`Без нод: ${stillMissing.join(', ')}. Сценарий может не запуститься`, 'warn');
    }
    const byName = new Map(customPresets.map((preset) => [preset.name, preset]));
    for (const preset of incoming) byName.set(preset.name, preset);
    customPresets = [...byName.values()].slice(-50);
    saveCustomPresets();
    renderPresets();
    toast(`Импортировано пресетов: ${incoming.length}`, 'ok');
  } catch (error) {
    toast(error && error.message ? error.message : 'Не удалось импортировать пресеты', 'warn');
  }
}

function renderPresets() {
  const root = $('#presetsGrid');
  if (!root) return;
  const query = state.presetQuery.trim().toLowerCase();
  const builtin = PRESETS.map((preset) => ({ preset, builtin: true }));
  const custom = customPresets.map((preset) => ({ preset, builtin: false, source: preset.source || 'custom' }));
  const items = [...builtin, ...custom].filter(({ preset }) => {
    if (!query) return true;
    return `${preset.name} ${preset.description || ''}`.toLowerCase().includes(query);
  });
  root.replaceChildren();

  if (!items.length) {
    root.append(
      h('div', { class: 'workspace-empty' },
        h('h3', { text: query ? 'Ничего не найдено' : 'Пока нет пресетов' }),
        h('p', { text: query ? 'Попробуйте другой запрос.' : 'Создайте пресет из текущего сценария или импортируйте JSON.' })),
    );
    return;
  }

  for (const { preset, builtin: isBuiltin, source } of items) {
    const workflow = isBuiltin ? preset.build() : preset.workflow;
    const nodes = Array.isArray(workflow.nodes) ? workflow.nodes : [];
    const edges = Array.isArray(workflow.edges) ? workflow.edges : [];
    const active = !isBuiltin && state.activePresetId === preset.id;
    const badge = isBuiltin ? 'Встроенный' : source === 'library' ? 'Из библиотеки' : 'Мой';
    const card = h('article', { class: 'preset-card' + (active ? ' is-active' : '') },
      h('div', { class: 'preset-card__top' },
        h('span', { class: 'preset-card__badge', text: badge }),
        active ? h('span', { class: 'preset-card__active', text: 'активный' }) : null),
      h('h2', { class: 'preset-card__title', text: preset.name }),
      h('p', { class: 'preset-card__meta', text: `${nodes.length} ${plural(nodes.length, 'узел', 'узла', 'узлов')} · ${edges.length} ${plural(edges.length, 'связь', 'связи', 'связей')}` }),
    );
    const actions = h('div', { class: 'preset-card__actions' });
    const open = h('button', { class: 'btn btn--primary btn--sm', type: 'button', text: 'Открыть' });
    open.addEventListener('click', () => applyPreset(preset));
    actions.append(open);
    if (!isBuiltin) {
      const downloadPreset = h('button', { class: 'btn btn--ghost btn--sm', type: 'button', text: 'Скачать' });
      downloadPreset.addEventListener('click', () => exportPreset(preset));
      const remove = h('button', { class: 'icon-btn', type: 'button', title: 'Удалить пресет', 'aria-label': 'Удалить пресет' }, svgIcon('trash'));
      remove.addEventListener('click', () => deleteCustomPreset(preset.id));
      actions.append(downloadPreset, remove);
    }
    card.append(actions);
    root.append(card);
  }
}





const RUN_STATUS_META = {
  success: { label: 'Выполнен', tone: 'ok' },
  failed: { label: 'Ошибка', tone: 'bad' },
  running: { label: 'Выполняется', tone: 'run' },
  queued: { label: 'В очереди', tone: 'wait' },
  cancelled: { label: 'Отменён', tone: 'warn' },
};

function runStatusMeta(status) {
  return RUN_STATUS_META[status] || { label: status || 'Неизвестно', tone: 'wait' };
}

function triggerLabel(trigger) {
  return (
    { manual: 'Вручную', schedule: 'По расписанию', webhook: 'Webhook', ci: 'CI', api: 'API' }[trigger] ||
    trigger ||
    '—'
  );
}

function runWhen(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' });
}

function runDuration(ms) {
  if (ms === null || ms === undefined) return '—';
  if (ms < 1000) return `${ms} мс`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)} с`;
  return `${Math.floor(ms / 60000)} мин ${Math.round((ms % 60000) / 1000)} с`;
}

function scheduleLabel(item) {
  if (item.mode === 'once') return `Один раз · ${item.run_time || '—'}`;
  const day = item.weekday === '*' ? 'каждый день' : `день ${item.weekday}`;
  return `${day} · ${item.run_time || '—'}`;
}

function stopRunsPolling() {
  if (state.runsTimer) {
    clearInterval(state.runsTimer);
    state.runsTimer = null;
  }
}

function openRunsView() {
  stopRunsPolling();
  renderRunsPage();
  loadRuns(true);
  state.runsTimer = setInterval(() => loadRuns(false), 10000);
}

async function loadRuns(force = false) {
  if (state.runsLoading) return;
  state.runsLoading = true;
  try {
    const [runs, schedules] = await Promise.all([api.listRuns(50), api.listSchedules()]);
    state.runs = (runs && runs.items) || [];
    state.schedules = (schedules && schedules.items) || [];
    renderRunsPage();
  } catch (error) {
    if (force) toast('Не удалось загрузить процессы', 'warn');
    renderRunsPage(error);
  } finally {
    state.runsLoading = false;
  }
}

function renderRunsPage(error) {
  const runs = state.runs || [];
  const scheduled = state.schedules || [];
  const stats = $('#runsStats');
  stats.replaceChildren();
  const counts = { success: 0, failed: 0, running: 0 };
  for (const run of runs) {
    if (run.status === 'success') counts.success += 1;
    else if (run.status === 'failed') counts.failed += 1;
    else if (run.status === 'running') counts.running += 1;
  }
  for (const [label, value, tone] of [
    ['Всего запусков', runs.length, ''],
    ['Выполнено', counts.success, 'ok'],
    ['С ошибкой', counts.failed, 'bad'],
    ['Выполняется', counts.running, 'run'],
    ['Ожидают', scheduled.length, 'wait'],
  ]) {
    stats.append(
      h('div', { class: 'runs-stat' + (tone ? ` runs-stat--${tone}` : '') },
        h('span', { text: label }),
        h('b', { text: String(value) })),
    );
  }

  const scheduledRoot = $('#scheduledList');
  scheduledRoot.replaceChildren();
  $('#scheduledCount').textContent = scheduled.length ? String(scheduled.length) : '';
  if (!scheduled.length) {
    scheduledRoot.append(h('p', { class: 'runs-empty', text: 'Нет запланированных проверок. Добавьте ноду «По расписанию».' }));
  }
  for (const item of scheduled) scheduledRoot.append(renderScheduledRow(item));

  const runsRoot = $('#runsList');
  runsRoot.replaceChildren();
  $('#runsCount').textContent = runs.length ? `последние ${runs.length}` : '';
  if (error) {
    runsRoot.append(h('p', { class: 'runs-empty runs-empty--error', text: `Не удалось загрузить: ${error.message || error}` }));
  } else if (!runs.length) {
    runsRoot.append(h('p', { class: 'runs-empty', text: 'Запусков пока нет — запустите сценарий или дождитесь расписания.' }));
  }
  for (const run of runs) runsRoot.append(renderRunRow(run));
}

function renderScheduledRow(item) {
  const status = item.valid ? { label: 'Ожидает', tone: 'wait' } : { label: 'Не сработает', tone: 'bad' };
  const details = h('button', { class: 'btn btn--ghost btn--sm', type: 'button', text: 'Подробнее' });
  details.addEventListener('click', () => openScheduleDetails(item));
  const cancel = h('button', { class: 'btn btn--ghost btn--sm run-stop', type: 'button', text: 'Отменить' });
  cancel.addEventListener('click', async () => {
    if (!window.confirm('Отменить это расписание? Регулярные запуски больше не будут выполняться.')) return;
    cancel.disabled = true;
    try {
      await api.cancelSchedule(item.workflow_id, item.node_id);
      toast('Расписание отменено', 'ok');
      await loadRuns(true);
    } catch (error) {
      toast(error && error.message ? error.message : 'Не удалось отменить расписание', 'warn');
      cancel.disabled = false;
    }
  });
  return h('div', { class: 'run-row' },
    h('div', { class: 'run-row__main' },
      h('div', { class: 'run-row__title' },
        h('b', { text: item.workflow_name || item.workflow_id }),
        h('span', { class: `run-chip run-chip--${status.tone}`, text: status.label })),
      h('div', { class: 'run-row__meta', text: `${scheduleLabel(item)} · ${item.timezone} · ${item.valid ? `запуск ${runWhen(item.next_run)}` : 'проверьте дату/время'}` })),
    h('div', { class: 'run-row__actions' }, details, cancel));
}

function renderRunRow(run) {
  const status = runStatusMeta(run.status);
  const findings = (run.summary && run.summary.findings) || {};
  const total = findings.total !== undefined ? findings.total : run.findings_count || 0;
  const details = h('button', { class: 'btn btn--ghost btn--sm', type: 'button', text: 'Подробнее' });
  details.addEventListener('click', () => openRunDetails(run));
  const actions = [details];
  if (['running', 'queued', 'pending'].includes(run.status)) {
    const stop = h('button', { class: 'btn btn--ghost btn--sm run-stop', type: 'button', text: 'Остановить' });
    stop.addEventListener('click', async () => {
      stop.disabled = true;
      try {
        await api.cancelRun(run.id);
        toast('Запуск остановлен', 'ok');
        await loadRuns(true);
      } catch (error) {
        toast(error && error.message ? error.message : 'Не удалось остановить запуск', 'warn');
        stop.disabled = false;
      }
    });
    actions.push(stop);
  }
  return h('div', { class: 'run-row' },
    h('div', { class: 'run-row__main' },
      h('div', { class: 'run-row__title' },
        h('b', { text: run.workflow_name || 'Сценарий' }),
        h('span', { class: `run-chip run-chip--${status.tone}`, text: status.label })),
      h('div', { class: 'run-row__meta', text: `${triggerLabel(run.trigger)} · ${runWhen(run.created_at)} · ${runDuration(run.duration_ms)} · ${total} ${plural(total, 'находка', 'находки', 'находок')}` })),
    h('div', { class: 'run-row__actions' }, ...actions));
}

function openScheduleDetails(item) {
  $('#modalTitle').textContent = 'Запланированный процесс';
  const open = h('button', { class: 'btn btn--primary btn--sm', type: 'button', text: 'Открыть сценарий' });
  open.addEventListener('click', () => {
    closeModal();
    openWorkflowById(item.workflow_id);
  });
  $('#modalBody').replaceChildren(
    h('div', { class: 'run-detail__title' },
      h('b', { text: item.workflow_name || item.workflow_id }),
      h('span', { class: `run-chip run-chip--${item.valid ? 'wait' : 'bad'}`, text: item.valid ? 'Ожидает' : 'Не сработает' })),
    h('div', { class: 'run-detail__meta' },
      h('div', {}, h('span', { text: 'Следующий запуск' }), h('b', { text: item.valid ? runWhen(item.next_run) : 'не состоится' })),
      h('div', {}, h('span', { text: 'Режим' }), h('b', { text: scheduleLabel(item) })),
      h('div', {}, h('span', { text: 'Часовой пояс' }), h('b', { text: item.timezone })),
      h('div', {}, h('span', { text: 'Нода' }), h('b', { text: item.node_id || '—' }))),
    h('div', { class: 'run-detail__actions' }, open),
  );
  $('#modal').hidden = false;
}

function downloadRunFile(runId, format) {
  const themeQuery = format === 'html' ? `&theme=${encodeURIComponent(currentTheme)}` : '';
  fetch(`/api/runs/${encodeURIComponent(runId)}/report?format=${format}&download=1${themeQuery}`)
    .then((response) => {
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.blob();
    })
    .then((blob) => {
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `ldwarden-run-${runId}.${format}`;
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
      toast('Отчёт выгружен', 'ok');
    })
    .catch(() => toast('Не удалось выгрузить отчёт', 'warn'));
}

async function openRunDetails(run) {
  $('#modalTitle').textContent = 'Процесс';
  const root = $('#modalBody');
  root.replaceChildren(h('p', { class: 'field__hint', text: 'Загружаю процесс…' }));
  $('#modal').hidden = false;
  let detail;
  try {
    detail = await api.runDetail(run.id);
  } catch (error) {
    root.replaceChildren(h('p', { class: 'field__hint is-error', text: error.message || 'Не удалось загрузить процесс' }));
    return;
  }
  const status = runStatusMeta(detail.status);
  const summary = detail.summary || {};
  const findings = summary.findings || {};
  const bySev = findings.by_severity || {};
  const nodes = Object.entries(summary.nodes || {});
  const total = findings.total !== undefined ? findings.total : detail.findings_count || 0;

  const actions = h('div', { class: 'run-detail__actions' });
  if (detail.workflow_id) {
    const open = h('button', { class: 'btn btn--primary btn--sm', type: 'button', text: 'Открыть сценарий' });
    open.addEventListener('click', () => {
      closeModal();
      openWorkflowById(detail.workflow_id);
    });
    actions.append(open);
  }
  const json = h('button', { class: 'btn btn--ghost btn--sm', type: 'button', text: 'JSON' });
  json.addEventListener('click', () => download(`ldwarden-run-${detail.id}.json`, JSON.stringify(detail.report_json || detail, null, 2), 'application/json'));
  actions.append(json);
  for (const [format, label] of [['md', 'Отчёт .md'], ['html', 'Отчёт .html']]) {
    const button = h('button', { class: 'btn btn--ghost btn--sm', type: 'button', text: label });
    button.addEventListener('click', () => downloadRunFile(detail.id, format));
    actions.append(button);
  }

  const children = [
    h('div', { class: 'run-detail__head' },
      h('div', { class: 'run-detail__title' },
        h('b', { text: detail.workflow_name || 'Сценарий' }),
        h('span', { class: `run-chip run-chip--${status.tone}`, text: status.label })),
      h('p', { class: 'field__hint', text: `${triggerLabel(detail.trigger)} · ${runWhen(detail.created_at)} · ${runDuration(detail.duration_ms)}` })),
    h('div', { class: 'run-detail__stats' },
      ...[
        ['Всего', total],
        ['CRITICAL', bySev.CRITICAL || 0],
        ['HIGH', bySev.HIGH || 0],
        ['MEDIUM', bySev.MEDIUM || 0],
        ['LOW', bySev.LOW || 0],
      ].map(([label, value]) => h('div', { class: 'run-stat' }, h('span', { text: label }), h('b', { text: String(value) })))),
    h('div', { class: 'run-detail__meta' },
      h('div', {}, h('span', { text: 'Источник' }), h('b', { text: detail.source_label || (detail.target && detail.target.path) || '—' })),
      h('div', {}, h('span', { text: 'Начало' }), h('b', { text: runWhen(detail.started_at || detail.created_at) })),
      h('div', {}, h('span', { text: 'Длительность' }), h('b', { text: runDuration(detail.duration_ms) })),
      h('div', {}, h('span', { text: 'CI' }), h('b', { text: detail.ci_mode ? 'да' : 'нет' }))),
  ];
  if (detail.error) children.push(h('pre', { class: 'run-detail__error', text: detail.error }));
  if (detail.gate) {
    children.push(h('p', { class: 'field__hint', text: `Порог: ${detail.gate.passed ? 'пройден' : 'заблокирован'}` }));
  }
  if (nodes.length) {
    children.push(h('h3', { class: 'run-detail__subtitle', text: 'Узлы' }));
    for (const [id, node] of nodes) {
      const nodeStatus = runStatusMeta(node.status);
      children.push(h('div', { class: 'run-node' },
        h('span', { class: `run-chip run-chip--${nodeStatus.tone}`, text: nodeStatus.label }),
        h('b', { text: node.title || id }),
        h('span', { class: 'run-node__message', text: node.message || '' }),
        h('span', { class: 'run-node__time', text: runDuration(node.duration_ms) })));
    }
  }
  children.push(actions);
  root.replaceChildren(...children);

  try {
    const found = await api.runFindings(detail.id, 8);
    const items = (found && found.items) || [];
    if (items.length) {
      const box = h('div', { class: 'run-detail__findings' },
        h('h3', { class: 'run-detail__subtitle', text: `Находки (${items.length})` }));
      for (const finding of items) {
        const tone = String(finding.severity || '').toUpperCase() === 'CRITICAL' ? 'bad' : 'warn';
        box.append(h('div', { class: 'run-finding' },
          h('span', { class: `run-chip run-chip--${tone}`, text: finding.severity || '—' }),
          h('b', { text: finding.title || finding.class || finding.message || 'Находка' }),
          h('span', { class: 'run-finding__path', text: `${finding.path || ''}${finding.line ? ':' + finding.line : ''}` })));
      }
      root.append(box);
    }
  } catch {

  }
}

async function openWorkflowById(id) {
  try {
    const row = await api.workflowById(id);
    state.workflow = api.fromBackendWorkflow(row);
    state.selectedNode = null;
    state.selectedNodes = [];
    state.selectedEdge = null;
    state.activePresetId = null;
    resetStatuses();
    showWorkspace('graph');
    renderAll();
    fitView();
    setSavePill('Синхронизировано', 'ok');
    toast('Сценарий открыт', 'ok');
  } catch (error) {
    toast(error && error.message ? error.message : 'Не удалось открыть сценарий', 'warn');
  }
}





const CUSTOM_ICONS = ['box', 'shield', 'key', 'send', 'search', 'clock', 'package', 'link', 'play', 'gauge'];
const CUSTOM_PARAM_TYPES = {
  string: 'text',
  text: 'textarea',
  number: 'number',
  boolean: 'toggle',
  select: 'select',
  secret: 'secret',
  json: 'textarea',
  keyvalue: 'keyvalue',
};
const CUSTOM_BACKEND_TYPES = ['string', 'text', 'number', 'boolean', 'select', 'secret', 'json', 'keyvalue'];

function customSpecToType(spec) {
  const params = (spec.params || []).map((param) => ({
    key: param.name,
    label: param.label || param.name,
    type: CUSTOM_PARAM_TYPES[param.type] || 'text',
    def: param.default,
    hint: param.description || '',
    required: Boolean(param.required),
    options: param.options || [],
  }));
  const ports = (list, fallback) =>
    (Array.isArray(list) && list.length ? list : fallback).map((port) => ({
      id: port.id,
      kind: port.kind === 'data' ? 'data' : 'exec',
      label: port.label || port.id,
    }));
  const kind = spec.kind || (Array.isArray(spec.tags) ? spec.tags[1] : '') || 'http';
  return {
    cat: 'custom',
    icon: spec.icon || 'box',
    title: spec.title,
    sub: (values) =>
      `${kind === 'http' ? 'HTTP' : kind === 'ai' ? 'AI' : 'Композит'}` +
      (values && Object.keys(values).length ? ' · настроена' : ''),
    inputs: ports(spec.inputs, [{ id: 'in', kind: 'exec', label: 'Вход' }]),
    outputs: ports(spec.outputs, [{ id: 'out', kind: 'exec', label: 'Выход' }]),
    params,
  };
}

async function loadCustomCatalog() {
  try {
    const data = await api.nodeCatalog();
    for (const key of Object.keys(NODE_TYPES)) {
      if (key.startsWith('custom-')) delete NODE_TYPES[key];
    }
    for (const spec of (data && data.items) || []) {
      const tags = Array.isArray(spec.tags) ? spec.tags : [];
      if (spec.category === 'custom' && tags.includes('composite')) {
        NODE_TYPES[spec.type] = customSpecToType(spec);
      }
    }
    renderPalette();
  } catch {

  }
}

async function refreshCustomNodes() {
  try {
    const data = await api.customNodes();
    state.customNodes = ((data && data.items) || []).filter((item) => item.kind === 'composite');
  } catch {

  }
  return state.customNodes;
}

async function openNodesView() {
  renderNodesPage();
  await refreshCustomNodes();
  renderNodesPage();
}

function renderNodesPage() {
  const root = $('#customNodesGrid');
  if (!root) return;
  root.replaceChildren();
  const items = (state.customNodes || []).filter((item) => item.kind === 'composite');
  if (!items.length) {
    root.append(
      h('div', { class: 'custom-nodes-empty' },
        h('h2', { text: 'Пока нет композитных нод' }),
        h('p', { text: 'Выделите ноды на холсте и нажмите «Свернуть в ноду» в верхней панели.' })),
    );
    return;
  }
  for (const item of items) {
    const kindLabel = 'Композитная';
    const edit = h('button', { class: 'btn btn--ghost btn--sm', type: 'button', text: 'Изменить' });
    edit.addEventListener('click', () => openCompositeEditor(item.id));
    const use = h('button', { class: 'btn btn--ghost btn--sm', type: 'button', text: 'На холст' });
    use.addEventListener('click', () => {
      if (!NODE_TYPES[item.id]) NODE_TYPES[item.id] = customSpecToType({
        type: item.id, title: item.name, kind: item.kind, icon: item.icon,
        inputs: item.inputs, outputs: item.outputs, params: item.params,
      });
      showWorkspace('graph');
      addNodeAtCenter(item.id);
    });
    const exportBtn = h('button', { class: 'btn btn--ghost btn--sm', type: 'button', text: 'Экспорт' });
    exportBtn.addEventListener('click', () => downloadCustomNode(item.id));
    const publish = h('button', { class: 'btn btn--ghost btn--sm', type: 'button', text: 'В библиотеку' });
    publish.addEventListener('click', async () => {
      try {
        const result = await api.publishLibraryNode(item.id);
        toast(`Нода опубликована: ${result.path || item.name}`, 'ok');
        await loadLibrary(true);
        renderLibraryPage();
      } catch (error) {
        toast(error && error.message ? error.message : 'Не удалось опубликовать ноду', 'warn');
      }
    });
    const remove = h('button', { class: 'icon-btn', type: 'button', title: 'Удалить ноду', 'aria-label': 'Удалить ноду' }, svgIcon('trash'));
    remove.addEventListener('click', async () => {
      if (!window.confirm(`Удалить ноду «${item.name}»?`)) return;
      try {
        await api.deleteCustomNode(item.id);
        delete NODE_TYPES[item.id];
        await loadCustomCatalog();
        await openNodesView();
        toast('Нода удалена', 'ok');
      } catch (error) {
        toast(error && error.message ? error.message : 'Не удалось удалить ноду', 'warn');
      }
    });
    root.append(
      h('article', { class: 'custom-node-card' },
        h('div', { class: 'custom-node-card__top' },
          h('span', { class: 'custom-node-card__icon' }, svgIcon(item.icon || 'box')),
          h('div', { class: 'custom-node-card__title' },
            h('h2', { text: item.name }),
            h('p', { text: `${kindLabel} · v${item.version || 1}` }))),
        h('p', { class: 'custom-node-card__desc', text: item.description || 'Без описания' }),
        h('div', { class: 'custom-node-card__actions' }, edit, use, exportBtn, remove)),
    );
  }
}

function downloadCustomNode(nodeId) {
  fetch(`/api/custom-nodes/${encodeURIComponent(nodeId)}/export`)
    .then((response) => {
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.blob();
    })
    .then((blob) => {
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `${nodeId}.node.json`;
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1500);
    })
    .catch(() => toast('Не удалось экспортировать ноду', 'warn'));
}

function defaultCustomDraft() {
  return {
    name: '',
    kind: 'http',
    icon: 'box',
    color: '#8b5cf6',
    description: '',
    inputs: [{ id: 'in', label: 'Вход', kind: 'exec' }],
    outputs: [
      { id: 'out', label: 'Выход', kind: 'exec' },
      { id: 'response', label: 'Ответ', kind: 'data' },
    ],
    params: [],
    runtime: {
      method: 'GET',
      url: '',
      headers: {},
      body: '',
      timeout: 20,
      findings: {
        enabled: true,
        from: '',
        category: 'CUSTOM',
        default_severity: 'MEDIUM',
        map: { severity: 'severity', title: 'message', path: 'path', line: 'line', rule: 'rule' },
      },
    },
  };
}

function editorInput(value, onInput, placeholder, type) {
  const input = h('input', { class: 'input', type: type || 'text', placeholder: placeholder || '', value: value == null ? '' : String(value) });
  input.addEventListener('input', () => onInput(input.value));
  return input;
}

function editorSelect(value, options, onChange, labels) {
  const select = h('select', { class: 'select' });
  for (const option of options) {
    const optionEl = h('option', { value: option, text: (labels && labels[option]) || option });
    if (String(option) === String(value)) optionEl.selected = true;
    select.append(optionEl);
  }
  select.addEventListener('change', () => onChange(select.value));
  return select;
}

function editorCheck(label, checked, onChange) {
  const input = h('input', { type: 'checkbox' });
  input.checked = Boolean(checked);
  input.addEventListener('change', () => onChange(input.checked));
  return h('label', { class: 'toggle toggle--compact' }, input, h('span', { class: 'toggle__track' }), h('span', { text: label }));
}

function openCustomNodeEditor(definition) {
  const draft = definition ? JSON.parse(JSON.stringify(definition)) : defaultCustomDraft();
  if (!draft.runtime) draft.runtime = defaultCustomDraft().runtime;
  if (!draft.runtime.findings) draft.runtime.findings = defaultCustomDraft().runtime.findings;
  if (!Array.isArray(draft.params)) draft.params = [];
  if (!Array.isArray(draft.outputs)) draft.outputs = [{ id: 'out', label: 'Выход', kind: 'exec' }];
  $('#modalTitle').textContent = draft.id ? 'Редактирование ноды' : 'Новая нода';
  const root = $('#modalBody');
  root.replaceChildren();
  $('#modal').hidden = false;
  let testResult = null;
  let busy = false;

  const mount = () => {
    root.replaceChildren();
    const basics = h('div', { class: 'node-editor__grid' },
      h('div', { class: 'field' }, h('label', { class: 'field__label', text: 'Название' }), editorInput(draft.name, (value) => { draft.name = value; })),
      h('div', { class: 'field' }, h('label', { class: 'field__label', text: 'Тип' }),
        editorSelect(draft.kind, ['http', 'ai'], (value) => {
          draft.kind = value;
          if (value === 'ai' && !draft.runtime.prompt) {
            draft.runtime = { provider: 'auto', system: '', prompt: '', max_tokens: 512, temperature: 0.2, findings: draft.runtime.findings };
            draft.outputs = [{ id: 'out', label: 'Выход', kind: 'exec' }, { id: 'text', label: 'Текст', kind: 'data' }];
          }
          if (value === 'http' && !draft.runtime.url) {
            draft.runtime = { ...defaultCustomDraft().runtime, findings: draft.runtime.findings };
            draft.outputs = defaultCustomDraft().outputs;
          }
          mount();
        }, { http: 'HTTP-запрос', ai: 'AI-промпт' })),
      h('div', { class: 'field' }, h('label', { class: 'field__label', text: 'Иконка' }),
        editorSelect(draft.icon, CUSTOM_ICONS, (value) => { draft.icon = value; }, Object.fromEntries(CUSTOM_ICONS.map((name) => [name, name])))),
      h('div', { class: 'field' }, h('label', { class: 'field__label', text: 'Описание' }),
        (() => { const area = h('textarea', { class: 'input input--area', rows: '2' }); area.value = draft.description || ''; area.addEventListener('input', () => { draft.description = area.value; }); return area; })()),
    );

    const paramsSection = h('section', { class: 'node-editor__section' },
      h('h3', { text: 'Параметры' }),
      h('p', { class: 'field__hint', text: 'Поля, которые пользователь заполняет в инспекторе ноды.' }));
    const paramsBox = h('div', { class: 'params-editor' });
    const drawParams = () => {
      paramsBox.replaceChildren();
      draft.params.forEach((param, index) => {
        const row = h('div', { class: 'param-row' });
        const name = editorInput(param.name, (value) => { param.name = value; }, 'ключ');
        const label = editorInput(param.label, (value) => { param.label = value; }, 'подпись');
        const type = editorSelect(param.type || 'string', CUSTOM_BACKEND_TYPES, (value) => { param.type = value; if (value === 'secret') param.secret = true; });
        const def = editorInput(param.default, (value) => { param.default = value; }, 'по умолчанию');
        const secret = editorCheck('секрет', param.secret, (value) => { param.secret = value; });
        const required = editorCheck('обязательный', param.required, (value) => { param.required = value; });
        const remove = h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Удалить параметр' }, svgIcon('x'));
        remove.addEventListener('click', () => { draft.params.splice(index, 1); drawParams(); });
        row.append(name, label, type, def, secret, required, remove);
        paramsBox.append(row);
      });
      const add = h('button', { class: 'btn btn--ghost btn--sm', type: 'button', text: '+ параметр' });
      add.addEventListener('click', () => {
        draft.params.push({ name: `param${draft.params.length + 1}`, label: 'Параметр', type: 'string', default: '', required: false, secret: false, options: [] });
        drawParams();
      });
      paramsBox.append(add);
    };
    drawParams();
    paramsSection.append(paramsBox);

    const runtimeSection = h('section', { class: 'node-editor__section' }, h('h3', { text: draft.kind === 'http' ? 'HTTP-запрос' : 'AI-промпт' }));
    if (draft.kind === 'http') {
      const headersArea = h('textarea', { class: 'input input--area', rows: '2', placeholder: '{"Authorization": "Bearer …"}' });
      headersArea.value = JSON.stringify(draft.runtime.headers || {}, null, 2);
      headersArea.addEventListener('change', () => {
        try { draft.runtime.headers = JSON.parse(headersArea.value || '{}'); } catch {  }
      });
      const bodyArea = h('textarea', { class: 'input input--area', rows: '3', placeholder: '{"key": "{{params.key}}"}' });
      bodyArea.value = typeof draft.runtime.body === 'string' ? draft.runtime.body : JSON.stringify(draft.runtime.body || '', null, 2);
      bodyArea.addEventListener('input', () => { draft.runtime.body = bodyArea.value; });
      runtimeSection.append(
        h('div', { class: 'node-editor__grid' },
          h('div', { class: 'field' }, h('label', { class: 'field__label', text: 'Метод' }),
            editorSelect(draft.runtime.method || 'GET', ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'], (value) => { draft.runtime.method = value; })),
          h('div', { class: 'field' }, h('label', { class: 'field__label', text: 'Таймаут, сек' }),
            editorInput(draft.runtime.timeout || 20, (value) => { draft.runtime.timeout = Number(value) || 20; }, '20', 'number'))),
        h('div', { class: 'field' }, h('label', { class: 'field__label', text: 'URL' }),
          editorInput(draft.runtime.url, (value) => { draft.runtime.url = value; }, 'https://api.example.com/check')),
        h('div', { class: 'field' }, h('label', { class: 'field__label', text: 'Заголовки (JSON)' }), headersArea),
        h('div', { class: 'field' }, h('label', { class: 'field__label', text: 'Тело запроса' }), bodyArea),
      );
    } else {
      const systemArea = h('textarea', { class: 'input input--area', rows: '2' });
      systemArea.value = draft.runtime.system || '';
      systemArea.addEventListener('input', () => { draft.runtime.system = systemArea.value; });
      const promptArea = h('textarea', { class: 'input input--area', rows: '4' });
      promptArea.value = draft.runtime.prompt || '';
      promptArea.addEventListener('input', () => { draft.runtime.prompt = promptArea.value; });
      runtimeSection.append(
        h('div', { class: 'node-editor__grid' },
          h('div', { class: 'field' }, h('label', { class: 'field__label', text: 'Провайдер' }),
            editorSelect(draft.runtime.provider || 'auto', ['auto', 'local', 'openai', 'ollama'], (value) => { draft.runtime.provider = value; })),
          h('div', { class: 'field' }, h('label', { class: 'field__label', text: 'Макс. токенов' }),
            editorInput(draft.runtime.max_tokens || 512, (value) => { draft.runtime.max_tokens = Number(value) || 512; }, '512', 'number')),
          h('div', { class: 'field' }, h('label', { class: 'field__label', text: 'Температура' }),
            editorInput(draft.runtime.temperature ?? 0.2, (value) => { draft.runtime.temperature = Number(value) || 0; }, '0.2', 'number'))),
        h('div', { class: 'field' }, h('label', { class: 'field__label', text: 'Системная инструкция' }), systemArea),
        h('div', { class: 'field' }, h('label', { class: 'field__label', text: 'Промпт' }), promptArea),
      );
    }

    const findings = draft.runtime.findings;
    const findingsSection = h('section', { class: 'node-editor__section' }, h('h3', { text: 'Находки' }),
      h('p', { class: 'field__hint', text: 'Если ответ содержит находки, укажите путь и поля — они попадут в общий результат.' }));
    const fromInput = editorInput(findings.from, (value) => { findings.from = value; }, 'items или response.findings');
    const categorySelect = editorSelect(findings.category || 'CUSTOM', ['CUSTOM', 'SECRET', 'SCA', 'SAST'], (value) => { findings.category = value; });
    const severitySelect = editorSelect(findings.default_severity || 'MEDIUM', ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'], (value) => { findings.default_severity = value; });
    const mapInputs = {};
    for (const key of ['severity', 'title', 'path', 'line', 'rule']) {
      mapInputs[key] = editorInput((findings.map || {})[key] || '', (value) => { findings.map = { ...(findings.map || {}), [key]: value }; }, key);
    }
    findingsSection.append(
      h('div', { class: 'node-editor__grid' },
        h('div', { class: 'field' }, h('label', { class: 'field__label', text: 'Откуда (JSON-путь)' }), fromInput),
        h('div', { class: 'field' }, h('label', { class: 'field__label', text: 'Категория' }), categorySelect),
        h('div', { class: 'field' }, h('label', { class: 'field__label', text: 'Критичность по умолчанию' }), severitySelect)),
      h('div', { class: 'node-editor__grid' },
        ...['severity', 'title', 'path', 'line', 'rule'].map((key) =>
          h('div', { class: 'field' }, h('label', { class: 'field__label', text: `Поле «${key}»` }), mapInputs[key]))),
    );

    const testArea = h('textarea', { class: 'input input--area', rows: '2', placeholder: 'Параметры для теста (JSON)' });
    testArea.value = JSON.stringify(Object.fromEntries(draft.params.map((param) => [param.name, param.default ?? ''])), null, 2);
    const testOut = h('pre', { class: 'node-editor__test', text: testResult ? JSON.stringify(testResult, null, 2) : '' });
    const testButton = h('button', { class: 'btn btn--ghost btn--sm', type: 'button', text: 'Тестовый запуск' });
    testButton.addEventListener('click', async () => {
      if (busy) return;
      busy = true;
      testButton.disabled = true;
      try {
        const saved = await saveDraft();
        if (!saved) return;
        let params = {};
        try { params = JSON.parse(testArea.value || '{}'); } catch { params = {}; }
        testResult = await api.testCustomNode(saved.id, params);
        testOut.textContent = JSON.stringify(testResult, null, 2);
        testOut.classList.toggle('is-error', !testResult.ok);
      } catch (error) {
        testOut.textContent = error && error.message ? error.message : 'Ошибка теста';
        testOut.classList.add('is-error');
      } finally {
        busy = false;
        testButton.disabled = false;
      }
    });

    const saveButton = h('button', { class: 'btn btn--primary', type: 'button', text: 'Сохранить' });
    saveButton.addEventListener('click', async () => {
      if (busy) return;
      busy = true;
      saveButton.disabled = true;
      try {
        const saved = await saveDraft();
        if (saved) {
          closeModal();
          toast('Нода сохранена', 'ok');
        }
      } finally {
        busy = false;
        saveButton.disabled = false;
      }
    });
    const cancel = h('button', { class: 'btn btn--ghost', type: 'button', text: 'Отмена' });
    cancel.addEventListener('click', closeModal);

    root.append(
      basics, paramsSection, runtimeSection, findingsSection,
      h('section', { class: 'node-editor__section' }, h('h3', { text: 'Проверка' }), testArea,
        h('div', { class: 'run-detail__actions' }, testButton), testOut),
      h('div', { class: 'node-editor__footer' }, saveButton, cancel),
    );

    async function saveDraft() {
      if (!draft.name.trim()) {
        toast('Укажите название ноды', 'warn');
        return null;
      }
      const payload = {
        name: draft.name.trim(),
        kind: draft.kind,
        icon: draft.icon,
        color: draft.color,
        description: draft.description,
        inputs: draft.inputs,
        outputs: draft.outputs,
        params: draft.params.map((param) => ({
          name: param.name,
          label: param.label || param.name,
          type: param.type || 'string',
          default: param.default,
          required: Boolean(param.required),
          secret: Boolean(param.secret) || param.type === 'secret',
          options: Array.isArray(param.options) ? param.options : [],
        })),
        runtime: draft.runtime,
      };
      try {
        const saved = draft.id ? await api.updateCustomNode(draft.id, payload) : await api.createCustomNode(payload);
        draft.id = saved.id;
        draft.version = saved.version;
        await loadCustomCatalog();
        await openNodesView();
        return saved;
      } catch (error) {
        toast(error && error.message ? error.message : 'Не удалось сохранить ноду', 'warn');
        return null;
      }
    }
  };

  mount();
}

async function openNetworkRules() {
  let rules;
  try {
    rules = await api.networkRules();
  } catch (error) {
    toast(error && error.message ? error.message : 'Не удалось загрузить правила', 'warn');
    return;
  }
  const hosts = [...(rules.allow_hosts || [])];
  $('#modalTitle').textContent = 'Сетевые правила';
  const root = $('#modalBody');
  root.replaceChildren();
  const list = h('div', { class: 'hosts-list' });
  const draw = () => {
    list.replaceChildren();
    if (!hosts.length) {
      list.append(h('p', { class: 'field__hint', text: 'Список пуст — HTTP-ноды не смогут делать запросы.' }));
    }
    hosts.forEach((host, index) => {
      const remove = h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Удалить хост' }, svgIcon('trash'));
      remove.addEventListener('click', () => { hosts.splice(index, 1); draw(); });
      list.append(h('div', { class: 'host-row' }, h('code', { text: host }), remove));
    });
  };
  const input = h('input', { class: 'input', placeholder: 'api.example.com или *.example.com' });
  const add = h('button', { class: 'btn btn--ghost btn--sm', type: 'button', text: 'Добавить' });
  add.addEventListener('click', () => {
    const value = input.value.trim().toLowerCase();
    if (value && !hosts.includes(value)) hosts.push(value);
    input.value = '';
    draw();
  });
  const save = h('button', { class: 'btn btn--primary', type: 'button', text: 'Сохранить правила' });
  save.addEventListener('click', async () => {
    try {
      await api.saveNetworkRules({ ...rules, allow_hosts: hosts });
      closeModal();
      toast('Сетевые правила сохранены', 'ok');
    } catch (error) {
      toast(error && error.message ? error.message : 'Не удалось сохранить правила', 'warn');
    }
  });
  draw();
  root.append(
    h('p', { class: 'field__hint', text: 'HTTP-ноды могут обращаться только к этим хостам. Поддерживается *.example.com.' }),
    h('div', { class: 'hosts-add' }, input, add),
    list,
    h('div', { class: 'run-detail__actions' }, save),
  );
  $('#modal').hidden = false;
}





function updateCompositeButton() {
  const button = $('#compositeBtn');
  if (!button) return;
  button.disabled = (state.selectedNodes || []).length === 0;
}

function updateSaveButton() {
  const button = $('#savePresetBtn');
  if (!button) return;
  button.disabled = !state.workflow.nodes.length;
}

function openCompositeDialog() {
  if (!state.selectedNodes.length) {
    toast('Сначала выделите ноды, которые нужно свернуть', 'warn');
    return;
  }
  $('#modalTitle').textContent = 'Свернуть в ноду';
  const nameInput = h('input', { class: 'input', value: 'Моя композитная нода' });
  const iconSelect = editorSelect('box', CUSTOM_ICONS, () => {}, Object.fromEntries(CUSTOM_ICONS.map((name) => [name, name])));
  const descInput = h('textarea', { class: 'input input--area', rows: '2', placeholder: 'Что делает эта нода' });
  const create = h('button', { class: 'btn btn--primary', type: 'button', text: 'Создать ноду' });
  create.addEventListener('click', async () => {
    create.disabled = true;
    try {
      await collapseSelection(nameInput.value.trim() || 'Композитная нода', iconSelect.value, descInput.value.trim());
    } finally {
      create.disabled = false;
    }
  });
  const cancel = h('button', { class: 'btn btn--ghost', type: 'button', text: 'Отмена' });
  cancel.addEventListener('click', closeModal);
  $('#modalBody').replaceChildren(
    h('p', { class: 'field__hint', text: 'Выделенные ноды станут одной нодой. Границы станут её портами; внутренние параметры сохранятся.' }),
    h('div', { class: 'field' }, h('label', { class: 'field__label', text: 'Название' }), nameInput),
    h('div', { class: 'field' }, h('label', { class: 'field__label', text: 'Иконка' }), iconSelect),
    h('div', { class: 'field' }, h('label', { class: 'field__label', text: 'Описание' }), descInput),
    h('div', { class: 'run-detail__actions' }, create, cancel),
  );
  $('#modal').hidden = false;
}

async function collapseSelection(name, icon, description) {
  const selected = new Set(state.selectedNodes || []);
  const innerNodes = state.workflow.nodes.filter((node) => selected.has(node.id));
  if (!innerNodes.length) return;
  const innerEdges = state.workflow.edges.filter((edge) => selected.has(edge.from.node) && selected.has(edge.to.node));
  const incoming = state.workflow.edges.filter((edge) => !selected.has(edge.from.node) && selected.has(edge.to.node));
  const outgoing = state.workflow.edges.filter((edge) => selected.has(edge.from.node) && !selected.has(edge.to.node));
  const inputs = incoming.map((edge, index) => ({
    id: `in${index + 1}`,
    label: edge.to.port || 'in',
    kind: 'exec',
    inner: { node: edge.to.node, port: edge.to.port || 'in' },
  }));
  const outputs = outgoing.map((edge, index) => ({
    id: `out${index + 1}`,
    label: edge.from.port || 'out',
    kind: 'exec',
    inner: { node: edge.from.node, port: edge.from.port || 'out' },
  }));
  const backend = api.toBackendGraph({ nodes: innerNodes, edges: innerEdges });
  try {
    const definition = await api.createCustomNode({
      name,
      kind: 'composite',
      icon,
      description,
      inputs,
      outputs,
      runtime: { graph: backend },
    });
    state.customNodes = [definition, ...(state.customNodes || [])];
    const x = Math.round(innerNodes.reduce((sum, node) => sum + (Number(node.x) || 0), 0) / innerNodes.length);
    const y = Math.round(innerNodes.reduce((sum, node) => sum + (Number(node.y) || 0), 0) / innerNodes.length);
    const compositeNode = { id: 'n-' + Math.random().toString(36).slice(2, 9), type: definition.id, x, y, params: {} };
    const newNodes = state.workflow.nodes.filter((node) => !selected.has(node.id)).concat(compositeNode);
    const newEdges = state.workflow.edges.filter((edge) => !selected.has(edge.from.node) && !selected.has(edge.to.node));
    incoming.forEach((edge, index) => newEdges.push({ ...edge, to: { node: compositeNode.id, port: inputs[index].id } }));
    outgoing.forEach((edge, index) => newEdges.push({ ...edge, from: { node: compositeNode.id, port: outputs[index].id } }));
    state.workflow = { ...state.workflow, nodes: newNodes, edges: newEdges };
    await loadCustomCatalog();
    closeModal();
    renderAll();
    saveWorkflow();
    selectMany([compositeNode.id]);
    toast('Композитная нода создана', 'ok');
  } catch (error) {
    toast(error && error.message ? error.message : 'Не удалось создать композитную ноду', 'warn');
  }
}

async function openCompositeEditor(nodeType) {
  if (state.compositeEdit) {
    toast('Сначала сохраните или отмените текущее редактирование', 'warn');
    return;
  }
  try {
    const definition = await api.customNode(nodeType);
    if (definition.kind !== 'composite') return toast('Это не композитная нода', 'warn');
    state.compositeEdit = { definition, original: clone(state.workflow) };
    const inner = api.fromBackendWorkflow({ id: 'composite-edit', name: definition.name, graph: definition.runtime.graph || { nodes: [], edges: [] } });
    state.workflow = { ...inner, id: state.workflow.id };
    state.selectedNode = null;
    state.selectedNodes = [];
    state.selectedEdge = null;
    $('#compositeBannerTitle').textContent = `Редактирование: ${definition.name}`;
    $('#compositeBanner').hidden = false;
    showWorkspace('graph');
    renderAll();
    fitView();
  } catch (error) {
    toast(error && error.message ? error.message : 'Не удалось открыть композитную ноду', 'warn');
  }
}

async function saveCompositeEdit() {
  const context = state.compositeEdit;
  if (!context) return;
  const backend = api.toBackendGraph(state.workflow);
  try {
    await api.updateCustomNode(context.definition.id, {
      ...context.definition,
      runtime: { ...context.definition.runtime, graph: backend },
    });
    state.compositeEdit = null;
    state.workflow = context.original;
    $('#compositeBanner').hidden = true;
    await loadCustomCatalog();
    renderAll();
    saveWorkflow();
    toast('Композитная нода обновлена', 'ok');
  } catch (error) {
    toast(error && error.message ? error.message : 'Не удалось сохранить композитную ноду', 'warn');
  }
}

function cancelCompositeEdit() {
  if (!state.compositeEdit) return;
  state.workflow = state.compositeEdit.original;
  state.compositeEdit = null;
  $('#compositeBanner').hidden = true;
  renderAll();
}

function openCiView() {
  renderCiPage();
  if (!state.ciWorkflows || !state.ciWorkflows.length) loadCiView();
}

async function loadCiView(force = false) {
  if (state.ciLoading) return;
  state.ciLoading = true;
  state.ciError = '';
  renderCiPage();
  try {
    const data = await api.workflows();
    const all = (data && data.items) || [];
    const byName = new Map();
    for (const workflow of all) {
      const key = workflow.name || workflow.id;
      const previous = byName.get(key);
      if (!previous || String(workflow.updated_at || '') > String(previous.updated_at || '')) {
        byName.set(key, workflow);
      }
    }
    state.ciWorkflows = [...byName.values()];
    const current = all.find((item) => item.id === state.workflow.backendId);
    const preferred = state.ciWorkflowId && state.ciWorkflows.some((item) => item.id === state.ciWorkflowId)
      ? state.ciWorkflowId
      : current
        ? (byName.get(current.name) || {}).id || ''
        : (state.ciWorkflows.find((item) => !item.is_template) || state.ciWorkflows[0] || {}).id || '';
    state.ciWorkflowId = preferred;
    await generateCiSnippet();
  } catch (error) {
    state.ciError = error && error.message ? error.message : 'Не удалось загрузить workflows';
  } finally {
    state.ciLoading = false;
    renderCiPage();
  }
}

async function generateCiSnippet() {
  const select = $('#ciWorkflow');
  const workflowId = select ? select.value : state.ciWorkflowId;
  if (!workflowId) {
    state.ciError = 'Выберите workflow';
    renderCiPage();
    return;
  }
  state.ciWorkflowId = workflowId;
  state.ciBaseUrl = ($('#ciBaseUrl') && $('#ciBaseUrl').value.trim()) || state.ciBaseUrl || location.origin;
  const target = ($('#ciTarget') && $('#ciTarget').value.trim()) || '';
  state.ciLoading = true;
  state.ciError = '';
  renderCiPage();
  try {
    state.ciInfo = await api.ciSnippets({
      workflow_id: workflowId,
      base_url: state.ciBaseUrl,
      target,
    });
  } catch (error) {
    state.ciError = error && error.message ? error.message : 'Не удалось сгенерировать конфиг';
  } finally {
    state.ciLoading = false;
    renderCiPage();
  }
}

function renderCiPage() {
  const select = $('#ciWorkflow');
  if (!select) return;
  const selected = state.ciWorkflowId;
  select.replaceChildren();
  for (const workflow of state.ciWorkflows || []) {
    const option = h('option', { value: workflow.id, text: workflow.is_template ? `${workflow.name} · шаблон` : workflow.name });
    if (workflow.id === selected) option.selected = true;
    select.append(option);
  }
  if (!state.ciWorkflows || !state.ciWorkflows.length) {
    select.append(h('option', { value: '', text: 'Нет доступных workflows' }));
  }
  const base = $('#ciBaseUrl');
  if (base && !base.value) base.value = state.ciBaseUrl || location.origin;
  if (base && state.ciBaseUrl) base.value = state.ciBaseUrl;
  const target = $('#ciTarget');
  if (target && state.ciTarget) target.value = state.ciTarget;
  for (const button of $$('.ci-platform')) {
    button.classList.toggle('is-active', button.dataset.platform === state.ciPlatform);
  }
  const info = state.ciInfo;
  const snippet = info ? (state.ciPlatform === 'gitlab' ? info.gitlab_ci : info.github_actions) : '';
  state.ciSnippet = snippet || '';
  $('#ciSnippet').textContent = snippet || 'Выберите workflow и нажмите «Сгенерировать».';
  const status = $('#ciStatus');
  if (state.ciLoading) {
    status.textContent = 'Генерируем конфиг…';
  } else if (state.ciError) {
    status.textContent = state.ciError;
    status.classList.add('is-error');
  } else if (info) {
    status.classList.remove('is-error');
    status.textContent = `Workflow: ${info.workflow_id || state.ciWorkflowId} · CI-токен: ${info.ci_token_configured ? 'настроен' : 'не задан (добавьте LDWARDEN_CI_TOKEN)'}`;
  } else {
    status.textContent = 'Выберите workflow и нажмите «Сгенерировать».';
  }
  $('#ciCopyBtn').disabled = !snippet;
  $('#ciDownloadBtn').disabled = !snippet;
  $('#ciCheckBtn').disabled = !state.ciWorkflowId;
}

async function ciCheckWorkflow() {
  const workflowId = state.ciWorkflowId || ($('#ciWorkflow') && $('#ciWorkflow').value);
  if (!workflowId) return toast('Выберите workflow', 'warn');
  const target = ($('#ciTarget') && $('#ciTarget').value.trim()) || '';
  $('#ciCheckBtn').disabled = true;
  $('#ciStatus').textContent = 'Пробный запуск…';
  try {
    const run = await api.ciCheck(workflowId, target);
    const result = run.status === 'success' ? 'успешно' : run.status === 'failed' ? 'ошибка/gate' : run.status;
    $('#ciStatus').textContent = `Пробный запуск: ${result}${run.gate ? ` · gate ${run.gate.passed ? 'пройден' : 'не пройден'}` : ''}`;
    toast(`CI-проверка: ${result}`, run.status === 'success' ? 'ok' : 'warn');
  } catch (error) {
    $('#ciStatus').textContent = error && error.message ? error.message : 'Не удалось выполнить проверку';
    toast('Не удалось выполнить CI-проверку', 'warn');
  } finally {
    $('#ciCheckBtn').disabled = false;
  }
}

function renderGeneratorPage() {
  const resultRoot = $('#generatorResult');
  if (!resultRoot) return;
  const status = $('#generatorStatus');
  const button = $('#generatorRunBtn');
  if (button) button.disabled = state.generatorLoading;
  if (status) {
    status.classList.toggle('is-error', Boolean(state.generatorError));
    status.textContent = state.generatorLoading
      ? 'Генерируем… локальная модель может думать до двух минут.'
      : state.generatorError || 'AI соберёт AST, backend превратит его в граф.';
  }
  if (state.generatorLoading) {
    resultRoot.replaceChildren(h('div', { class: 'workspace-empty' }, h('p', { text: 'AI разбирает описание и собирает сценарий…' })));
    return;
  }
  const result = state.generatorResult;
  if (!result) {
    resultRoot.replaceChildren(h('div', { class: 'workspace-empty' },
      h('h3', { text: 'Здесь появится превью' }),
      h('p', { text: 'Опишите задачу, выберите пример или сгенерируйте сценарий с нуля.' })));
    return;
  }
  let workflow;
  try {
    workflow = api.fromBackendWorkflow({ id: 'generator-preview', name: result.name, graph: result.graph });
  } catch {
    workflow = { nodes: [], edges: [] };
  }
  const nodes = workflow.nodes || [];
  const warnings = result.warnings || [];
  const card = h('article', { class: 'generator-preview' },
    h('div', { class: 'generator-preview__head' },
      h('div', {},
        h('span', { class: 'workspace-page__kicker', text: result.provider === 'heuristic' ? 'Собрано эвристикой' : `AI · ${result.provider || 'LLM'}` }),
        h('h2', { text: result.name || 'Сгенерированный сценарий' }),
        h('p', { class: 'field__hint', text: result.description || `${nodes.length} узлов` }))),
    warnings.length ? h('div', { class: 'generator-warnings' }, ...warnings.map((warning) => h('p', { text: `⚠ ${warning}` }))) : null,
    h('div', { class: 'generator-node-list' }, ...nodes.map((node) => h('div', { class: 'generator-node' },
      h('span', { class: 'generator-node__icon' }, svgIcon(nodeIcon(node.type))),
      h('span', { class: 'generator-node__name', text: nodeTitle(node.type) }),
      h('span', { class: 'field__hint', text: node.type })))),
    h('div', { class: 'generator-preview__foot' },
      h('span', { class: 'field__hint', text: `${nodes.length} ${plural(nodes.length, 'узел', 'узла', 'узлов')} · ${(workflow.edges || []).length} связей` }),
      h('button', { class: 'btn btn--primary', id: 'generatorOpenBtn', type: 'button', text: 'Открыть в конструкторе' })),
  );
  resultRoot.replaceChildren(card);
  $('#generatorOpenBtn').addEventListener('click', openGeneratedWorkflow);
}

async function runGenerator() {
  const prompt = ($('#generatorPrompt') && $('#generatorPrompt').value.trim()) || '';
  if (!prompt) {
    toast('Опишите задачу текстом', 'warn');
    return;
  }
  const source = ($('#generatorSource') && $('#generatorSource').value.trim()) || '';
  state.generatorLoading = true;
  state.generatorError = '';
  state.generatorResult = null;
  renderGeneratorPage();
  try {
    state.generatorResult = await api.generateWorkflow(prompt, source, false);
  } catch (error) {
    state.generatorError = error && error.message ? error.message : 'Не удалось сгенерировать сценарий';
  } finally {
    state.generatorLoading = false;
    renderGeneratorPage();
    if (state.generatorResult) toast('Сценарий сгенерирован', 'ok');
  }
}

function openGeneratedWorkflow() {
  if (!state.generatorResult) return;
  try {
    const workflow = api.fromBackendWorkflow({
      id: 'wf-' + Date.now().toString(36),
      name: state.generatorResult.name || 'Сгенерированный сценарий',
      graph: state.generatorResult.graph,
    });
    if (!workflow.nodes.length) throw new Error('В сгенерированном графе нет узлов');
    workflow.backendId = null;
    state.workflow = workflow;
    state.selectedNode = null;
    state.selectedNodes = [];
    state.selectedEdge = null;
    state.activePresetId = null;
    showWorkspace('graph');
    renderAll();
    fitView();
    saveWorkflow();
    toast('Сценарий открыт в конструкторе', 'ok');
  } catch (error) {
    toast(error && error.message ? error.message : 'Не удалось открыть сценарий', 'warn');
  }
}

function showWorkspace(view) {
  state.workspaceView = view;
  const isGraph = view === 'graph';
  const isGenerator = view === 'generator';
  const isPresets = view === 'presets';
  const isLibrary = view === 'library';
  const isRuns = view === 'runs';
  const isNodes = view === 'nodes';
  const isCi = view === 'ci';
  $('#graphLayout').hidden = !isGraph;
  $('#generatorView').hidden = !isGenerator;
  $('#presetsView').hidden = !isPresets;
  $('#libraryView').hidden = !isLibrary;
  $('#runsView').hidden = !isRuns;
  $('#nodesView').hidden = !isNodes;
  $('#ciView').hidden = !isCi;
  for (const tab of $$('#workspaceTabs .workspace-tab')) {
    tab.classList.toggle('is-active', tab.dataset.workspace === view);
  }
  if (isGenerator) renderGeneratorPage();
  if (isPresets) renderPresets();
  if (isLibrary) openLibraryView();
  if (isRuns) openRunsView();
  else stopRunsPolling();
  if (isNodes) openNodesView();
  if (isCi) openCiView();
  if (!isGraph) clearSelection();
}

function applyPreset(preset) {
  state.activePresetId = null;
  if (preset.workflow) {
    state.workflow = normalizeGraph({
      id: 'wf-' + Date.now().toString(36),
      backendId: null,
      name: preset.name,
      nodes: clone(preset.workflow.nodes),
      edges: clone(preset.workflow.edges),
    });
  } else {
    state.workflow = { id: 'wf-' + Date.now().toString(36), name: preset.name, ...preset.build() };
  }
  state.selectedNode = null;
  state.selectedNodes = [];
  state.selectedEdge = null;
  resetStatuses();
  renderAll();
  fitView();
  saveWorkflow();
  state.activePresetId = preset.workflow ? preset.id : null;
  showWorkspace('graph');
  toast(`Пресет «${preset.name}» загружен`, 'ok');
}

function resetStatuses() {
  state.statuses = {};
  state.chips = {};
  state.outputs = {};
}





function isScheduleOnlyWorkflow() {
  const triggers = state.workflow.nodes.filter((node) => node.type.startsWith('trigger.'));
  return triggers.length > 0 && triggers.every((node) => node.type === 'trigger.schedule');
}

function renderAll() {
  renderNodes();
  renderWires();
  updateEmpty();
  $('#footStats').textContent = `${state.workflow.nodes.length} ${plural(state.workflow.nodes.length, 'узел', 'узла', 'узлов')} · ${state.workflow.edges.length} ${plural(state.workflow.edges.length, 'связь', 'связи', 'связей')}`;
  const runLabel = $('#runLabel');
  if (runLabel && !state.running) runLabel.textContent = isScheduleOnlyWorkflow() ? 'В очередь' : 'Запустить';
  updateSaveButton();
}

function updateEmpty() {
  $('#empty').classList.toggle('is-hidden', state.workflow.nodes.length > 0);
}

function renderNodes() {
  const root = $('#nodes');
  root.replaceChildren(...state.workflow.nodes.map(renderNode));
}

function renderNode(node) {
  const def = NODE_TYPES[node.type];
  const height = nodeHeight(node.type);
  const status = state.statuses[node.id];
  const chip = state.chips[node.id] || '';

  const classes = ['node'];
  if (state.selectedNodes.includes(node.id)) classes.push('is-selected');
  if (state.selectedNodes.length > 1 && state.selectedNodes.includes(node.id)) classes.push('is-multi-selected');
  if (status) classes.push('is-' + status);

  const el = h('div', {
    class: classes.join(' '),
    tabindex: '0',
    dataset: { id: node.id, type: node.type, cat: def.cat },
    style: `left:${node.x}px;top:${node.y}px;height:${height}px`,
  });
  if (node.color) el.style.setProperty('--cat', node.color);

  const remove = h('button', { class: 'node__remove', type: 'button', 'aria-label': 'Удалить узел' }, svgIcon('x'));
  remove.addEventListener('pointerdown', (event) => event.stopPropagation());
  remove.addEventListener('click', (event) => {
    event.stopPropagation();
    deleteNode(node.id);
  });

  const head = h(
    'div',
    { class: 'node__head' },
    h('span', { class: 'node__icon' }, svgIcon(def.icon)),
    h('span', { class: 'node__title', text: def.title, title: def.title }),
    h('span', { class: 'node__state' }),
    remove,
  );

  const body = h('div', { class: 'node__body' });
  for (let i = 0; i < Math.max(def.inputs.length, def.outputs.length, 1); i += 1) {
    body.append(h('div', { class: 'node__row' }));
  }
  body.append(h('div', { class: 'node__meta', text: nodeSub(node) }));
  body.append(h('div', { class: 'node__chip' + (chip ? ' is-visible' : ''), text: chip, title: chip || '' }));

  el.append(head, body);

  for (const [index, pin] of def.inputs.entries()) {
    el.append(renderPin(node, pin, 'in', pinOffsetY(node.type, index)));
  }
  for (const [index, pin] of def.outputs.entries()) {
    el.append(renderPin(node, pin, 'out', pinOffsetY(node.type, index)));
  }

  el.addEventListener('pointerdown', (event) => {
    if (event.button === 2) return;
    if (event.target.closest('.pin, .node__remove')) return;
    if (event.button !== 0) return;
    event.stopPropagation();
    const additive = event.shiftKey || event.ctrlKey || event.metaKey;
    if (additive) {
      selectNode(node.id, true);
      if (state.selectedNodes.includes(node.id)) startNodeDrag(event, node);
      return;
    }
    if (!state.selectedNodes.includes(node.id)) selectNode(node.id);
    startNodeDrag(event, node);
  });
  el.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') selectNode(node.id);
  });

  return el;
}

function renderPin(node, pin, dir, top) {
  const el = h(
    'span',
    {
      class: `pin pin--${dir} pin--${pin.kind}`,
      dataset: { node: node.id, port: pin.id, kind: pin.kind, dir },
      style: `top:${top}px`,
      title: pin.label,
    },
    h('i', { class: 'pin__dot' }),
    h('em', { class: 'pin__label', text: pin.label }),
  );
  el.addEventListener('pointerdown', (event) => startLink(event, node, pin, dir));
  return el;
}

function dataWireSummary(edge, output) {
  if (!output || typeof output !== 'object') return '';
  const port = edge.from.port;
  const count = output.count ?? output.files ?? output.findings
    ?? (Array.isArray(output.items) ? output.items.length : null);
  if (port === 'files' && count != null) {
    return `${count} ${plural(count, 'файл', 'файла', 'файлов')}`;
  }
  if (port === 'findings' && count != null) {
    return `${count} ${plural(count, 'находка', 'находки', 'находок')}`;
  }
  if (port === 'payload') {
    if (output.formats) return output.formats.join(' · ');
    if (output.status) return output.status;
    return 'payload';
  }
  if (output.formats) return output.formats.join(' · ');
  if (output.overall_risk) return output.overall_risk;
  if (output.summary) return 'AI-сводка';
  if (count != null) return `${count} ${plural(count, 'запись', 'записи', 'записей')}`;
  return '';
}

function renderWires() {
  const group = $('#wiresGroup');
  const frag = document.createDocumentFragment();

  for (const edge of state.workflow.edges) {
    const from = findNode(edge.from.node);
    const to = findNode(edge.to.node);
    if (!from || !to) continue;

    const kind = portKind(from, edge.from.port, 'out');
    const start = pinPosition(from, edge.from.port, 'out');
    const end = pinPosition(to, edge.to.port, 'in');
    const { d, angle } = wireGeometry(start, end);

    const g = document.createElementNS(NS, 'g');
    g.setAttribute('class', `wire wire--${kind}${state.selectedEdge === edge.id ? ' is-selected' : ''}`);
    g.dataset.id = edge.id;

    const hit = svgPath(d, 'wire__hit');
    const casing = svgPath(d, 'wire__casing');
    const line = svgPath(d, 'wire__line');
    const arrow = svgPath('M -8 -4.2 L 0 0 L -8 4.2 Z', 'wire__arrow');
    arrow.setAttribute('transform', `translate(${end.x} ${end.y}) rotate(${angle})`);

    if (edge.color) {
      line.style.stroke = edge.color;
      arrow.style.fill = edge.color;
    }

    hit.addEventListener('pointerdown', (event) => {
      if (event.button === 0) event.stopPropagation();
    });
    hit.addEventListener('click', (event) => {
      event.stopPropagation();
      selectEdge(edge.id);
      openEdgeMenu(edge, event.clientX, event.clientY);
    });

    g.append(hit, casing, line, arrow);

    const output = state.outputs[from.id];
    if (kind === 'data') {
      const summary = dataWireSummary(edge, output);
      if (summary) {
        const label = document.createElementNS(NS, 'text');
        label.setAttribute('class', 'wire__data-label');
        label.setAttribute('x', String((start.x + end.x) / 2));
        label.setAttribute('y', String((start.y + end.y) / 2 - 7));
        label.setAttribute('text-anchor', 'middle');
        label.textContent = summary;
        g.append(label);
      }
    }
    const title = document.createElementNS(NS, 'title');
    title.textContent = output
      ? `${state.statuses[from.id] || 'нет статуса'} · ${JSON.stringify(output, null, 2).slice(0, 2500)}`
      : 'Данные по этой связи ещё не сформированы';
    g.append(title);

    frag.append(g);
  }

  group.replaceChildren(frag);
}

function updateNodeElement(id) {
  const el = $(`.node[data-id="${id}"]`);
  if (!el) return;
  const status = state.statuses[id];
  el.classList.remove('is-running', 'is-done', 'is-skipped', 'is-error', 'is-pending');
  if (status) el.classList.add('is-' + status);

  const chip = el.querySelector('.node__chip');
  if (chip) {
    chip.textContent = state.chips[id] || '';
    chip.classList.toggle('is-visible', Boolean(state.chips[id]));
  }
}





function syncSelection() {
  for (const el of $$('.node')) {
    const selected = state.selectedNodes.includes(el.dataset.id);
    el.classList.toggle('is-selected', selected);
    el.classList.toggle('is-multi-selected', selected && state.selectedNodes.length > 1);
  }
  updateCompositeButton();
}

function selectNode(id, additive = false) {
  if (additive) {
    const next = new Set(state.selectedNodes);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    state.selectedNodes = [...next];
  } else {
    state.selectedNodes = [id];
  }
  state.selectedNode = state.selectedNodes.includes(id)
    ? id
    : state.selectedNodes[state.selectedNodes.length - 1] || null;
  state.selectedEdge = null;
  for (const g of $$('.wire')) g.classList.remove('is-selected');
  syncSelection();
  renderWires();
  renderInspector();
}

function selectMany(ids) {
  state.selectedNodes = [...new Set(ids)];
  state.selectedNode = state.selectedNodes[0] || null;
  state.selectedEdge = null;
  for (const g of $$('.wire')) g.classList.remove('is-selected');
  syncSelection();
  renderWires();
  renderInspector();
}

function selectEdge(id) {
  state.selectedEdge = id;
  state.selectedNode = null;
  state.selectedNodes = [];
  closeInspector();
  for (const el of $$('.node')) el.classList.remove('is-selected', 'is-multi-selected');
  updateCompositeButton();
  for (const g of $$('.wire')) g.classList.toggle('is-selected', g.dataset.id === id);
}

function clearSelection() {
  state.selectedNode = null;
  state.selectedNodes = [];
  state.selectedEdge = null;
  for (const el of $$('.node')) el.classList.remove('is-selected', 'is-multi-selected');
  for (const g of $$('.wire')) g.classList.remove('is-selected');
  renderInspector();
}





function closeInspector() {
  $('#inspector').classList.remove('is-open');
}

function inspectorHead(kicker, title, iconName) {
  const close = h('button', { class: 'icon-btn inspector__close', type: 'button', 'aria-label': 'Закрыть панель' }, svgIcon('x'));
  close.addEventListener('click', () => {
    closeInspector();
    clearSelection();
  });
  return h(
    'div',
    { class: 'inspector__head' },
    h('span', { class: 'inspector__kicker', text: kicker }),
    h('h3', { class: 'inspector__title' }, iconName ? svgIcon(iconName) : null, h('span', { text: title }), close),
  );
}

let telegramPoll = null;

function stopTelegramPoll() {
  if (telegramPoll && telegramPoll.timer) clearTimeout(telegramPoll.timer);
  telegramPoll = null;
}

function openTelegramModal(node) {
  stopTelegramPoll();
  const title = $('#modalTitle');
  const body = $('#modalBody');
  title.textContent = 'Подключение Telegram';
  body.replaceChildren();

  const steps = h(
    'ol',
    { class: 'tg-steps' },
    h('li', {}, 'Откройте ', h('a', { href: 'https://t.me/BotFather', target: '_blank', rel: 'noopener', text: '@BotFather' }), ' и создайте бота командой /newbot — или возьмите готового.'),
    h('li', { text: 'Вставьте токен: он сохранится в ноде в зашифрованном виде.' }),
    h('li', { text: 'Нажмите «Подключить», откройте бота и отправьте /start — Chat ID подставится сам.' }),
  );

  const tokenInput = h('input', {
    class: 'input',
    id: 'tgToken',
    type: 'password',
    autocomplete: 'off',
    spellcheck: 'false',
    placeholder: '123456789:AA...',
    value: String(node.params.botToken || ''),
  });
  const tokenField = h('div', { class: 'field' }, h('label', { class: 'field__label', text: 'Токен бота' }), tokenInput);

  const connectButton = h('button', { class: 'btn btn--primary btn--sm', type: 'button' }, svgIcon('send'), h('span', { text: 'Подключить' }));
  const openLink = h('a', { class: 'btn btn--ghost btn--sm', target: '_blank', rel: 'noopener' }, h('span', { text: 'Открыть бота' }));
  openLink.hidden = true;
  const actions = h('div', { class: 'tg-actions' }, connectButton, openLink);

  const status = h('p', {
    class: 'field__hint tg-status',
    text: node.params.chatId ? `Сейчас подключён чат: ${node.params.chatId}` : '',
  });
  const chats = h('div', { class: 'tg-chats' });

  body.append(steps, tokenField, actions, status, chats);
  $('#modal').hidden = false;

  const selectChat = async (session, chat) => {
    stopTelegramPoll();
    const value = String(chat.chat_id);
    node.params.botToken = tokenInput.value.trim();
    node.params.chatId = value;
    saveWorkflow();
    renderInspector();
    try {
      const saved = await api.saveWorkflow(state.workflow);
      if (saved && saved.id) await api.telegramLink(session.state, value, saved.id);
    } catch {

    }
    closeModal();
    toast(`Telegram подключён: ${chat.title || value}`, 'ok');
  };

  const startPolling = (session) => {
    const started = Date.now();
    const poll = { timer: null, state: session.state };
    telegramPoll = poll;
    const tick = async () => {
      if (telegramPoll !== poll) return;
      if (Date.now() - started > 90000) {
        status.textContent = 'Не дождались Start в Telegram. Нажмите «Подключить» ещё раз.';
        status.classList.add('is-error');
        stopTelegramPoll();
        return;
      }
      try {
        const result = await api.telegramChats(session.state);
        const items = result.items || [];
        if (items.length === 1) {
          await selectChat(session, items[0]);
          return;
        }
        if (items.length > 1) {
          chats.replaceChildren(
            h('p', { class: 'field__label', text: 'Выберите чат:' }),
            ...items.map((chat) => {
              const button = h('button', { class: 'btn btn--ghost btn--sm', type: 'button', text: chat.title || String(chat.chat_id) });
              button.addEventListener('click', () => selectChat(session, chat));
              return button;
            }),
          );
          status.textContent = 'Найдено несколько чатов — выберите нужный.';
          stopTelegramPoll();
          return;
        }
        status.textContent = 'Ждём Start в Telegram…';
        poll.timer = setTimeout(tick, 2000);
      } catch (error) {
        status.textContent = error && error.message ? error.message : 'Ошибка подключения';
        status.classList.add('is-error');
        stopTelegramPoll();
      }
    };
    tick();
  };

  connectButton.addEventListener('click', async () => {
    const value = tokenInput.value.trim();
    status.classList.remove('is-error');
    chats.replaceChildren();
    if (!value) {
      status.textContent = 'Вставьте токен бота от @BotFather';
      status.classList.add('is-error');
      tokenInput.focus();
      return;
    }
    connectButton.disabled = true;
    status.textContent = 'Проверяю токен…';
    try {
      const session = await api.telegramConnect(value);
      openLink.href = session.connect_url;
      openLink.hidden = false;
      node.params.botToken = value;
      saveWorkflow();
      try {
        openLink.click();
      } catch {

      }
      toast('В Telegram нажмите Start — ждём подключение…', 'info');
      startPolling(session);
    } catch (error) {
      status.textContent = error && error.message ? error.message : 'Не удалось подключить Telegram';
      status.classList.add('is-error');
    } finally {
      connectButton.disabled = false;
    }
  });
}

function renderScheduleCheck(node) {
  const wrap = h('div', { class: 'field' });
  const button = h('button', { class: 'btn btn--ghost btn--sm', type: 'button', text: 'Когда сработает?' });
  const hint = h('p', { class: 'field__hint schedule-check', text: '' });
  button.addEventListener('click', async () => {
    hint.classList.remove('is-ok', 'is-error');
    hint.textContent = 'Считаю…';
    try {
      const result = await api.schedulePreview({
        mode: node.params.mode || 'weekly',
        run_date: node.params.runDate || '',
        run_time: node.params.runTime || '09:00',
        weekday: String(node.params.weekday || '*'),
        timezone: node.params.timezone || 'Europe/Moscow',
        cron: node.params.cron || '',
      });
      hint.classList.add(result.ok ? 'is-ok' : 'is-error');
      hint.textContent = result.ok
        ? `Следующий запуск: ${result.human} (${result.timezone})`
        : result.error;
    } catch (error) {
      hint.classList.add('is-error');
      hint.textContent = error && error.message ? error.message : 'Не удалось проверить расписание';
    }
  });
  wrap.append(
    button,
    hint,
    h('p', { class: 'field__hint', text: 'Планировщик проверяет расписание каждые 30 секунд (пока сервер запущен).' }),
  );
  return wrap;
}

async function openPathPicker(node) {
  const title = $('#modalTitle');
  const body = $('#modalBody');
  title.textContent = 'Выбрать папку';
  let data = null;
  let busy = false;
  const pathInput = h('input', { class: 'input', type: 'text', value: node.params.target || '' });
  const list = h('div', { class: 'path-picker__list' });
  const status = h('p', { class: 'field__hint', text: 'Загрузка…' });
  const up = h('button', { class: 'btn btn--ghost btn--sm', type: 'button', text: 'Вверх' });
  const go = h('button', { class: 'btn btn--ghost btn--sm', type: 'button', text: 'Перейти' });
  const choose = h('button', { class: 'btn btn--primary btn--sm', type: 'button', text: 'Выбрать эту папку' });
  const close = h('button', { class: 'btn btn--ghost', type: 'button', text: 'Отмена' });
  close.addEventListener('click', closeModal);

  const draw = () => {
    list.replaceChildren();
    if (!data) return;
    pathInput.value = data.path;
    up.disabled = !data.parent;
    status.textContent = data.entries.length ? `Папок: ${data.entries.length}` : 'Вложенных папок нет';
    for (const entry of data.entries) {
      const item = h('button', { class: 'path-picker__item', type: 'button' },
        h('span', { class: 'path-picker__icon' }, svgIcon('folder')),
        h('span', { text: entry.name }));
      item.addEventListener('click', () => load(entry.path));
      list.append(item);
    }
    if (!data.entries.length) {
      list.append(h('p', { class: 'field__hint', text: 'В этой папке нет подкаталогов.' }));
    }
  };

  const load = async (path) => {
    if (busy) return;
    busy = true;
    status.textContent = 'Загрузка…';
    try {
      data = await api.browsePath(path);
      draw();
    } catch (error) {
      status.textContent = error && error.message ? error.message : 'Не удалось открыть папку';
    } finally {
      busy = false;
    }
  };

  up.addEventListener('click', () => { if (data && data.parent) load(data.parent); });
  go.addEventListener('click', () => load(pathInput.value.trim()));
  pathInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') load(pathInput.value.trim());
  });
  choose.addEventListener('click', () => {
    if (!data) return;
    node.params.target = data.path;
    node.params.sourceId = '';
    node.params.sourceName = '';
    saveWorkflow();
    closeModal();
    renderAll();
    renderInspector();
    toast(`Источник: ${data.path}`, 'ok');
  });

  body.replaceChildren(
    h('p', { class: 'field__hint', text: 'Выберите папку на сервере. Абсолютный путь можно ввести вручную.' }),
    h('div', { class: 'field' }, h('span', { class: 'field__label', text: 'Текущий путь' }), pathInput),
    h('div', { class: 'run-detail__actions' }, go, up),
    list,
    status,
    h('div', { class: 'run-detail__actions' }, choose, close),
  );
  $('#modal').hidden = false;
  await load(node.params.sourceId ? '' : (node.params.target || ''));
}

function renderInspector() {
  const root = $('#inspector');
  const visible = Boolean(state.selectedNode);
  root.classList.toggle('is-open', visible);
  root.replaceChildren();
  if (!visible) return;

  const node = state.selectedNode ? findNode(state.selectedNode) : null;
  if (!node) {
    root.append(
      h('div', { class: 'inspector__empty' }, svgIcon('grip'), h('p', { text: 'Выберите узел или провод на холсте, чтобы настроить сценарий.' })),
    );
    return;
  }

  const def = NODE_TYPES[node.type];
  root.style.setProperty('--cat', node.color || CATEGORIES[def.cat].color);

  root.append(inspectorHead(CATEGORIES[def.cat].label, def.title, def.icon));

  const body = h('div', { class: 'inspector__body' });
  for (const param of def.params) {
    if (param.hidden) continue;
    if (param.dependsOn && String(node.params[param.dependsOn.key] ?? '') !== String(param.dependsOn.value)) continue;
    body.append(renderField(node, param));
  }
  if (node.type === 'logic.custom') body.append(h('p', { class: 'field__hint expr-hint', id: 'exprHint' }));
  if (node.type === 'trigger.schedule' && state.schedulerEnabled === false) {
    body.append(h('p', { class: 'field__hint' }, 'Планировщик выключен на сервере: задайте LDWARDEN_ENABLE_SCHEDULER=true в .env.'));
  }
  body.append(renderNodeColor(node));
  if (api.isRemote && String(node.type || '').startsWith('custom-')) {
    const edit = h('button', { class: 'btn btn--ghost btn--sm', type: 'button', text: 'Редактировать ноду' });
    edit.addEventListener('click', async () => {
      try {
        openCustomNodeEditor(await api.customNode(node.type));
      } catch (error) {
        toast(error && error.message ? error.message : 'Не удалось открыть ноду', 'warn');
      }
    });
    body.append(h('div', { class: 'field' }, edit));
    const definition = (state.customNodes || []).find((item) => item.id === node.type);
    if (definition && definition.kind === 'composite') {
      const openCanvas = h('button', { class: 'btn btn--ghost btn--sm', type: 'button', text: 'Открыть композитный холст' });
      openCanvas.addEventListener('click', () => openCompositeEditor(node.type));
      body.append(h('div', { class: 'field' }, openCanvas));
    }
  }
  if (api.isRemote && node.type === 'trigger.schedule') {
    body.append(renderScheduleCheck(node));
  }
  if (api.isRemote && node.type === 'notify.telegram') {
    const connect = h('button', { class: 'btn btn--ghost btn--sm', type: 'button' }, svgIcon('send'), h('span', { text: 'Подключить Telegram' }));
    connect.addEventListener('click', () => openTelegramModal(node));
    body.append(
      h('div', { class: 'field' },
        connect,
        h('p', { class: 'field__hint', text: 'Токен — у @BotFather. Откроется бот: нажмите Start, Chat ID подставится сам.' })),
    );
  }
  if (node.type === 'source.repo') {
    const fileInput = h('input', { type: 'file', accept: '.zip,application/zip', hidden: true });
    const upload = h('button', { class: 'btn btn--ghost btn--sm', type: 'button' }, svgIcon('box'), h('span', { text: 'Загрузить ZIP' }));
    upload.addEventListener('click', () => fileInput.click());
    const sourceHint = h('p', {
      class: 'field__hint',
      text: node.params.sourceId
        ? `ZIP-источник: ${node.params.sourceName || node.params.sourceId}`
        : 'ZIP распакуется на сервере; путь или ссылка в поле «Путь или ссылка» не нужны.',
    });
    const reset = h('button', { class: 'btn btn--ghost btn--sm', type: 'button', text: 'Сбросить ZIP' });
    reset.hidden = !node.params.sourceId;
    reset.addEventListener('click', () => {
      node.params.sourceId = '';
      node.params.sourceName = '';
      saveWorkflow();
      renderInspector();
      toast('ZIP-источник отвязан', 'ok');
    });
    const browse = h('button', { class: 'btn btn--ghost btn--sm', type: 'button', text: 'Выбрать папку' });
    browse.addEventListener('click', () => openPathPicker(node));
    fileInput.addEventListener('change', async () => {
      const file = fileInput.files && fileInput.files[0];
      fileInput.value = '';
      if (!file) return;
      upload.disabled = true;
      try {
        const uploaded = await api.uploadSource(file, file.name);
        node.params.sourceId = uploaded.id;
        node.params.sourceName = uploaded.name || file.name;
        node.params.target = '';
        saveWorkflow();
        renderAll();
        renderInspector();
        toast(`ZIP загружен: ${node.params.sourceName}`, 'ok');
      } catch (error) {
        toast(error && error.message ? error.message : 'Не удалось загрузить ZIP', 'warn');
      } finally {
        upload.disabled = false;
      }
    });
    body.append(
      h('div', { class: 'field' },
        h('span', { class: 'field__label', text: 'Источник' }),
        h('div', { class: 'run-detail__actions' }, upload, browse, reset, fileInput),
        sourceHint),
    );
  }
  const output = state.outputs[node.id];
  body.append(
    h('div', { class: 'field' },
      h('span', { class: 'field__label', text: 'Результат узла' }),
      h('div', { class: 'inspector__preview', text: output ? JSON.stringify(output, null, 2) : 'Узел ещё не выполнялся' }),
    ),
  );
  root.append(body);
  if (node.type === 'logic.custom') updateExprHint(node);

  const duplicate = h('button', { class: 'btn btn--ghost btn--sm', type: 'button' }, svgIcon('copy'), h('span', { text: 'Дублировать' }));
  duplicate.addEventListener('click', () => {
    const copyNode = cloneNode(node);
    state.workflow.nodes.push(copyNode);
    state.selectedNode = copyNode.id;
    state.selectedNodes = [copyNode.id];
    renderAll();
    renderInspector();
    saveWorkflow();
  });

  const remove = h('button', { class: 'btn btn--ghost btn--sm', type: 'button' }, svgIcon('trash'), h('span', { text: 'Удалить' }));
  remove.addEventListener('click', () => deleteNode(node.id));

  root.append(h('div', { class: 'inspector__foot' }, duplicate, remove));
}

function renderField(node, param) {
  const value = node.params[param.key];
  const wrap = h('div', { class: 'field' });

  if (param.type === 'toggle') {
    const input = h('input', { type: 'checkbox' });
    input.checked = Boolean(value);
    input.addEventListener('change', () => setParam(node, param.key, input.checked));
    wrap.append(h('label', { class: 'toggle' }, input, h('span', { class: 'toggle__track' }), h('span', { text: param.label })));
    if (param.hint) wrap.append(h('p', { class: 'field__hint', text: param.hint }));
    return wrap;
  }

  wrap.append(h('label', { class: 'field__label', text: param.label }));

  if (param.type === 'expression') {
    const area = h('textarea', { class: 'input input--area', rows: '2', spellcheck: 'false' });
    area.value = value ?? '';
    area.addEventListener('input', () => {
      setParam(node, param.key, area.value);
      updateExprHint(node);
    });
    wrap.append(area);
    if (param.hint) wrap.append(h('p', { class: 'field__hint', text: param.hint }));
    return wrap;
  }

  if (param.type === 'time') {
    const raw = String(value || '09:00').trim();
    const match = raw.match(/^(\d{1,2}):(\d{2})$/);
    const hourValue = match ? Math.min(23, Number(match[1])) : 9;
    const minuteValue = match ? Math.min(59, Number(match[2])) : 0;
    const row = h('div', { class: 'time-control' });
    const hours = h('select', { class: 'select', 'aria-label': 'Часы' });
    for (let index = 0; index < 24; index += 1) {
      const text = String(index).padStart(2, '0');
      const option = h('option', { value: text, text });
      if (index === hourValue) option.selected = true;
      hours.append(option);
    }
    const minutes = h('select', { class: 'select', 'aria-label': 'Минуты' });
    for (let index = 0; index < 60; index += 1) {
      const text = String(index).padStart(2, '0');
      const option = h('option', { value: text, text });
      if (index === minuteValue) option.selected = true;
      minutes.append(option);
    }
    const sync = () => setParam(node, param.key, `${hours.value}:${minutes.value}`);
    hours.addEventListener('change', sync);
    minutes.addEventListener('change', sync);
    row.append(hours, h('span', { text: ':' }), minutes);
    wrap.append(row);
    if (param.hint) wrap.append(h('p', { class: 'field__hint', text: param.hint }));
    return wrap;
  }

  if (param.type === 'select') {
    const select = h('select', { class: 'select' });
    let options = [...(param.options || [])];
    let labels = { ...(param.labels || {}) };
    if (param.dynamicOptions === 'models') {
      const models = state.models || [];
      options = ['auto', ...models.map((model) => model.id)];
      labels = { auto: 'auto (из .env)', ...Object.fromEntries(models.map((model) => [model.id, model.name || model.filename || model.id])) };
    }
    if (value && !options.includes(String(value))) options.push(String(value));
    for (const option of options) {
      const label = labels[option] ? labels[option] : option;
      const optionEl = h('option', { value: option, text: label });
      if (String(option) === String(value)) optionEl.selected = true;
      select.append(optionEl);
    }
    select.addEventListener('change', () => {
      setParam(node, param.key, select.value);
      if (node.type === 'trigger.schedule') renderInspector();
    });
    wrap.append(select);
    if (param.dynamicOptions === 'models' && state.modelsLoaded && !state.models.length) {
      wrap.append(h('p', { class: 'field__hint', text: 'В папке llms нет .gguf-файлов.' }));
    }
  } else {
    const input = h('input', {
      class: 'input',
      type: param.type === 'number' ? 'number' : param.type === 'secret' ? 'password' : param.type === 'date' ? 'date' : param.type === 'time' ? 'time' : 'text',
      value: value ?? '',
      autocomplete: 'off',
      spellcheck: 'false',
    });
    input.addEventListener('input', () => setParam(node, param.key, param.type === 'number' ? Number(input.value) : input.value));
    wrap.append(input);
  }

  if (param.hint) wrap.append(h('p', { class: 'field__hint', text: param.hint }));
  return wrap;
}

function renderNodeColor(node) {
  const def = NODE_TYPES[node.type];
  const wrap = h('div', { class: 'field' });
  wrap.append(h('span', { class: 'field__label', text: 'Цвет узла' }));

  const row = h('div', { class: 'color-row' });
  const options = [
    { value: null, title: 'Как в теме', color: CATEGORIES[def.cat].color },
    { value: '#e05252', title: 'Красный' },
    { value: '#e0913c', title: 'Оранжевый' },
    { value: '#4fa870', title: 'Зелёный' },
    { value: '#3b82f6', title: 'Синий' },
    { value: '#a855f7', title: 'Фиолетовый' },
  ];

  for (const option of options) {
    const swatch = h('button', {
      class: 'color-swatch' + (option.value === null ? ' color-swatch--theme' : ''),
      type: 'button',
      title: option.title,
      'aria-label': option.title,
    });
    swatch.style.setProperty('--sw', option.color || option.value);
    swatch.classList.toggle('is-active', (node.color || null) === option.value);
    swatch.addEventListener('click', () => setNodeColor(node, option.value));
    row.append(swatch);
  }

  const custom = h('label', { class: 'color-swatch color-swatch--custom', title: 'Свой цвет' });
  const input = h('input', { type: 'color', value: node.color || '#d9738f' });
  input.addEventListener('change', () => setNodeColor(node, input.value));
  custom.append(input);
  row.append(custom);

  wrap.append(row);
  return wrap;
}

function setNodeColor(node, color) {
  if (color) node.color = color;
  else delete node.color;
  saveWorkflow();

  const el = $(`.node[data-id="${node.id}"]`);
  if (el) {
    if (node.color) el.style.setProperty('--cat', node.color);
    else el.style.removeProperty('--cat');
  }
  renderInspector();
}

function updateExprHint(node) {
  const hint = $('#exprHint');
  if (!hint) return;
  const findings = state.run ? state.run.findings : [];
  const result = evaluateExpression(node.params.expr, findings, targetName());
  hint.classList.toggle('is-error', !result.ok);
  if (!result.ok) {
    hint.textContent = `Ошибка: ${result.error}`;
  } else if (state.run) {
    hint.textContent = `На последнем прогоне: ${result.value ? 'истина' : 'ложь'}`;
  } else {
    hint.textContent = 'Синтаксис в порядке — условие проверится при запуске';
  }
}

function setParam(node, key, value) {
  node.params[key] = value;
  const meta = $(`.node[data-id="${node.id}"] .node__meta`);
  if (meta) meta.textContent = nodeSub(node);
  saveWorkflow();
}





function deleteNode(id) {
  state.workflow.nodes = state.workflow.nodes.filter((n) => n.id !== id);
  state.workflow.edges = state.workflow.edges.filter((e) => e.from.node !== id && e.to.node !== id);
  state.selectedNodes = state.selectedNodes.filter((selected) => selected !== id);
  if (state.selectedNode === id) state.selectedNode = state.selectedNodes[0] || null;
  renderAll();
  renderInspector();
  saveWorkflow();
}

function deleteSelectedNodes() {
  const ids = new Set(state.selectedNodes);
  if (!ids.size) return;
  state.workflow.nodes = state.workflow.nodes.filter((node) => !ids.has(node.id));
  state.workflow.edges = state.workflow.edges.filter(
    (edge) => !ids.has(edge.from.node) && !ids.has(edge.to.node),
  );
  state.selectedNodes = [];
  state.selectedNode = null;
  state.selectedEdge = null;
  renderAll();
  renderInspector();
  saveWorkflow();
}

function deleteEdge(id) {
  state.workflow.edges = state.workflow.edges.filter((e) => e.id !== id);
  state.selectedEdge = null;
  renderWires();
  renderInspector();
  saveWorkflow();
}

function addNode(type, x, y) {
  const node = createNode(type, snap(x - NODE_W / 2), snap(y - 60));
  state.workflow.nodes.push(node);
  state.selectedNode = node.id;
  state.selectedNodes = [node.id];
  state.selectedEdge = null;
  renderAll();
  renderInspector();
  saveWorkflow();
  return node;
}

function addNodeAtCenter(type) {
  const rect = $('#viewport').getBoundingClientRect();
  const world = screenToWorld(rect.left + rect.width / 2, rect.top + rect.height / 2);
  addNode(type, world.x, world.y);
}

function connectPins(fromNode, fromPort, toNode, toPort) {
  const fromKind = portKind(fromNode, fromPort, 'out');
  const toKind = portKind(toNode, toPort, 'in');
  if (fromKind !== toKind) return false;
  if (fromNode.id === toNode.id) return false;

  const exists = state.workflow.edges.some(
    (e) => e.from.node === fromNode.id && e.from.port === fromPort && e.to.node === toNode.id && e.to.port === toPort,
  );
  if (exists) return false;

  if (fromKind === 'data') {
    state.workflow.edges = state.workflow.edges.filter((e) => !(e.to.node === toNode.id && e.to.port === toPort));
  }

  state.workflow.edges.push({ id: newIdent('e'), from: { node: fromNode.id, port: fromPort }, to: { node: toNode.id, port: toPort } });
  return true;
}





function applyView() {
  const { x, y, z } = state.view;
  $('#world').style.transform = `translate(${x}px, ${y}px) scale(${z})`;
  $('#viewport').style.backgroundSize = `${24 * z}px ${24 * z}px`;
  $('#viewport').style.backgroundPosition = `${x}px ${y}px`;
  $('#zoomLabel').textContent = `${Math.round(z * 100)}%`;
}

function screenToWorld(clientX, clientY) {
  const rect = $('#viewport').getBoundingClientRect();
  return {
    x: (clientX - rect.left - state.view.x) / state.view.z,
    y: (clientY - rect.top - state.view.y) / state.view.z,
  };
}

function zoomAt(clientX, clientY, factor) {
  const rect = $('#viewport').getBoundingClientRect();
  const px = clientX - rect.left;
  const py = clientY - rect.top;
  const next = clamp(state.view.z * factor, 0.35, 1.8);
  if (next === state.view.z) return;
  const world = { x: (px - state.view.x) / state.view.z, y: (py - state.view.y) / state.view.z };
  state.view.z = next;
  state.view.x = px - world.x * next;
  state.view.y = py - world.y * next;
  applyView();
}

function fitView() {
  const nodes = state.workflow.nodes;
  if (!nodes.length) {
    state.view = { x: 0, y: 0, z: 1 };
    applyView();
    return;
  }
  const rect = $('#viewport').getBoundingClientRect();
  const pad = 56;
  const minX = Math.min(...nodes.map((n) => n.x));
  const minY = Math.min(...nodes.map((n) => n.y));
  const maxX = Math.max(...nodes.map((n) => n.x + NODE_W));
  const maxY = Math.max(...nodes.map((n) => n.y + nodeHeight(n.type)));
  const w = Math.max(1, maxX - minX);
  const hgt = Math.max(1, maxY - minY);
  const z = clamp(Math.min((rect.width - pad * 2) / w, (rect.height - pad * 2) / hgt, 1.15), 0.4, 1.2);
  state.view.z = z;
  state.view.x = (rect.width - w * z) / 2 - minX * z;
  state.view.y = (rect.height - hgt * z) / 2 - minY * z;
  applyView();
}





let interaction = null;

function startNodeDrag(event, node) {
  if (event.button !== 0) return;
  event.preventDefault();
  closeInspector();
  const selected = state.selectedNodes.includes(node.id)
    ? state.workflow.nodes.filter((item) => state.selectedNodes.includes(item.id))
    : [node];
  interaction = {
    kind: 'node',
    node,
    nodes: selected.map((item) => ({ node: item, startX: item.x, startY: item.y })),
    startX: event.clientX,
    startY: event.clientY,
    moved: false,
  };
  window.addEventListener('pointermove', onPointerMove);
  window.addEventListener('pointerup', onPointerUp);
}

function startPan(event) {
  if (event.button !== 1 && event.button !== 2) return;
  event.preventDefault();
  interaction = {
    kind: 'pan',
    startX: event.clientX,
    startY: event.clientY,
    originX: state.view.x,
    originY: state.view.y,
  };
  $('#viewport').classList.add('is-panning');
  window.addEventListener('pointermove', onPointerMove);
  window.addEventListener('pointerup', onPointerUp);
}

function startMarquee(event) {
  if (event.button !== 0) return;
  event.preventDefault();
  const additive = event.shiftKey || event.ctrlKey || event.metaKey;
  const base = additive ? [...state.selectedNodes] : [];
  if (!additive) clearSelection();
  const box = h('div', { class: 'marquee' });
  $('#viewport').append(box);
  interaction = {
    kind: 'marquee',
    startX: event.clientX,
    startY: event.clientY,
    base,
    box,
    moved: false,
  };
  window.addEventListener('pointermove', onPointerMove);
  window.addEventListener('pointerup', onPointerUp);
}

function updateMarquee(currentX, currentY) {
  if (!interaction || interaction.kind !== 'marquee') return;
  const viewport = $('#viewport').getBoundingClientRect();
  const left = Math.min(interaction.startX, currentX) - viewport.left;
  const top = Math.min(interaction.startY, currentY) - viewport.top;
  const right = Math.max(interaction.startX, currentX) - viewport.left;
  const bottom = Math.max(interaction.startY, currentY) - viewport.top;
  const box = interaction.box;
  box.style.left = `${left}px`;
  box.style.top = `${top}px`;
  box.style.width = `${right - left}px`;
  box.style.height = `${bottom - top}px`;

  const ids = new Set(interaction.base);
  for (const node of state.workflow.nodes) {
    const x = viewport.left + state.view.x + node.x * state.view.z;
    const y = viewport.top + state.view.y + node.y * state.view.z;
    const width = NODE_W * state.view.z;
    const height = nodeHeight(node.type) * state.view.z;
    const hit = x <= viewport.left + right && x + width >= viewport.left + left
      && y <= viewport.top + bottom && y + height >= viewport.top + top;
    if (hit) ids.add(node.id);
  }
  state.selectedNodes = [...ids];
  state.selectedNode = state.selectedNodes[0] || null;
  state.selectedEdge = null;
  syncSelection();
  renderWires();
}

function startLink(event, node, pin, dir) {
  if (event.button !== 0) return;
  event.stopPropagation();
  event.preventDefault();
  closeInspector();

  const origin = pinPosition(node, pin.id, dir);
  interaction = {
    kind: 'link',
    node,
    pin,
    dir,
    kindPin: pin.kind,
    origin,
    cursor: origin,
    snap: null,
  };

  $('#tempWire').setAttribute('d', wireGeometry(origin, origin).d);
  $('#tempWire').classList.add('is-visible');

  for (const el of $$('.pin')) {
    const sameKind = el.dataset.kind === pin.kind;
    const opposite = el.dataset.dir !== dir;
    el.classList.toggle('is-linkable', sameKind && opposite);
  }

  window.addEventListener('pointermove', onPointerMove);
  window.addEventListener('pointerup', onPointerUp);
}

function startPaletteDrag(event, type) {
  if (event.button !== 0) return;
  event.preventDefault();
  const def = NODE_TYPES[type];

  const ghost = h(
    'div',
    { class: 'node drag-ghost', dataset: { cat: def.cat } },
    h('div', { class: 'node__head' }, h('span', { class: 'node__icon' }, svgIcon(def.icon)), h('span', { class: 'node__title', text: def.title })),
  );
  ghost.style.setProperty('--tint', CATEGORIES[def.cat].tint);
  document.body.append(ghost);

  interaction = {
    kind: 'palette',
    type,
    ghost,
    startX: event.clientX,
    startY: event.clientY,
    moved: false,
  };
  movePaletteGhost(event.clientX, event.clientY);
  window.addEventListener('pointermove', onPointerMove);
  window.addEventListener('pointerup', onPointerUp);
}

function movePaletteGhost(x, y) {
  const ghost = interaction.ghost;
  ghost.style.transform = `translate3d(${x - 60}px, ${y - 18}px, 0) rotate(-1deg)`;
}

function onPointerMove(event) {
  if (!interaction) return;

  if (interaction.kind === 'marquee') {
    if (!interaction.moved && Math.hypot(event.clientX - interaction.startX, event.clientY - interaction.startY) < 3) return;
    interaction.moved = true;
    updateMarquee(event.clientX, event.clientY);
    return;
  }

  if (interaction.kind === 'node') {
    if (!interaction.moved && Math.hypot(event.clientX - interaction.startX, event.clientY - interaction.startY) < 3) return;
    interaction.moved = true;
    const dx = (event.clientX - interaction.startX) / state.view.z;
    const dy = (event.clientY - interaction.startY) / state.view.z;
    for (const item of interaction.nodes) {
      item.node.x = item.startX + dx;
      item.node.y = item.startY + dy;
      const el = $(`.node[data-id="${item.node.id}"]`);
      if (el) {
        el.style.left = `${item.node.x}px`;
        el.style.top = `${item.node.y}px`;
      }
    }
    renderWires();
    return;
  }

  if (interaction.kind === 'pan') {
    state.view.x = interaction.originX + (event.clientX - interaction.startX);
    state.view.y = interaction.originY + (event.clientY - interaction.startY);
    applyView();
    return;
  }

  if (interaction.kind === 'link') {
    const world = screenToWorld(event.clientX, event.clientY);
    if (event.shiftKey) {
      const magnet = nearestLinkMagnet(event.clientX, event.clientY, interaction);
      interaction.snap = magnet;
      setLinkMagnet(magnet);
      const target = magnet ? { x: magnet.x, y: magnet.y } : world;
      interaction.cursor = target;
      $('#tempWire').setAttribute('d', wireGeometry(interaction.origin, target).d);
    } else {
      interaction.snap = null;
      setLinkMagnet(null);
      interaction.cursor = world;
      $('#tempWire').setAttribute('d', wireGeometry(interaction.origin, world).d);
    }
    return;
  }

  if (interaction.kind === 'palette') {
    interaction.moved = true;
    movePaletteGhost(event.clientX, event.clientY);
  }
}

function onPointerUp(event) {
  if (!interaction) return;
  const current = interaction;
  interaction = null;

  window.removeEventListener('pointermove', onPointerMove);
  window.removeEventListener('pointerup', onPointerUp);
  $('#viewport').classList.remove('is-panning');

  if (current.kind === 'marquee') {
    current.box.remove();
    if (!current.moved) {
      state.selectedNodes = current.base;
      state.selectedNode = current.base[0] || null;
      syncSelection();
      renderWires();
    }
    renderInspector();
    return;
  }

  if (current.kind === 'node') {
    if (current.moved) {
      for (const item of current.nodes) {
        item.node.x = snap(item.node.x);
        item.node.y = snap(item.node.y);
        const el = $(`.node[data-id="${item.node.id}"]`);
        if (el) {
          el.style.left = `${item.node.x}px`;
          el.style.top = `${item.node.y}px`;
        }
      }
      renderWires();
      saveWorkflow();
    }
    renderInspector();
    return;
  }

  if (current.kind === 'link') {
    $('#tempWire').classList.remove('is-visible');
    for (const el of $$('.pin.is-linkable, .pin.is-magnet')) el.classList.remove('is-linkable', 'is-magnet');

    const target = document.elementFromPoint(event.clientX, event.clientY);
    const pinEl = target && target.closest ? target.closest('.pin') : null;
    const snap = current.snap;
    const targetNode = pinEl ? findNode(pinEl.dataset.node) : snap ? snap.node : null;
    const targetPort = pinEl ? pinEl.dataset.port : snap ? snap.port : null;
    if (!targetNode || !targetPort) return;

    if (current.dir === 'out') {
      if (connectPins(current.node, current.pin.id, targetNode, targetPort)) {
        renderWires();
        saveWorkflow();
      }
    } else if (connectPins(targetNode, targetPort, current.node, current.pin.id)) {
      renderWires();
      saveWorkflow();
    }
    renderInspector();
    return;
  }

  if (current.kind === 'palette') {
    current.ghost.remove();
    const rect = $('#viewport').getBoundingClientRect();
    const inside = event.clientX >= rect.left && event.clientX <= rect.right && event.clientY >= rect.top && event.clientY <= rect.bottom;
    if (inside) {
      const world = screenToWorld(event.clientX, event.clientY);
      addNode(current.type, world.x, world.y);
    } else if (!current.moved) {
      addNodeAtCenter(current.type);
    }
  }
}





function validate() {
  const nodes = state.workflow.nodes;
  if (!nodes.length) return 'Перетащите узлы на холст или выберите пресет';
  const triggers = nodes.filter((n) => n.type.startsWith('trigger.'));
  if (!triggers.length) return 'Добавьте узел запуска';
  for (const trigger of triggers.filter((node) => node.type === 'trigger.schedule')) {
    if (!/^\d{2}:\d{2}$/.test(String(trigger.params.runTime || ''))) {
      return 'Укажите время запуска в формате ЧЧ:ММ';
    }
    if (trigger.params.mode === 'once') {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(String(trigger.params.runDate || ''))) {
        return 'Выберите дату однократного запуска';
      }
    }
  }
  const sources = nodes.filter((n) => n.type === 'source.repo');
  if (!sources.length) return 'Добавьте узел «Репозиторий»';
  const scans = nodes.filter((n) => n.type.startsWith('scan.'));
  if (!scans.length) return 'Добавьте хотя бы одну проверку';

  const outgoing = new Map(nodes.map((n) => [n.id, []]));
  const execPort = (nodeId, portId, dir) => {
    const node = nodes.find((item) => item.id === nodeId);
    if (!node) return false;
    const def = NODE_TYPES[node.type];
    const list = dir === 'out' ? def.outputs : def.inputs;
    const port = list.find((item) => item.id === portId);
    return Boolean(port) && port.kind === 'exec';
  };
  for (const edge of state.workflow.edges) {
    if (!execPort(edge.from.node, edge.from.port, 'out')) continue;
    if (!execPort(edge.to.node, edge.to.port, 'in')) continue;
    (outgoing.get(edge.from.node) || []).push(edge.to.node);
  }
  const reachable = (starts) => {
    const seen = new Set();
    const queue = [...starts];
    while (queue.length) {
      const id = queue.shift();
      if (seen.has(id)) continue;
      seen.add(id);
      for (const next of outgoing.get(id) || []) queue.push(next);
    }
    return seen;
  };

  const fromTrigger = reachable(triggers.map((n) => n.id));
  if (!sources.some((source) => fromTrigger.has(source.id))) {
    return 'Источник «Репозиторий» не соединён с запуском. Соедините запуск → репозиторий.';
  }
  const fromSource = reachable(sources.map((src) => src.id));
  if (!scans.some((scan) => fromSource.has(scan.id))) {
    return 'Проверки не соединены с источником. Соедините «Репозиторий» → проверка.';
  }
  return null;
}

function setRunning(active) {
  state.running = active;
  const button = $('#runBtn');
  button.classList.toggle('is-running', active);
  $('#runLabel').textContent = active ? 'Остановить' : (isScheduleOnlyWorkflow() ? 'В очередь' : 'Запустить');
  button.querySelector('use').setAttribute('href', active ? '#i-stop' : '#i-play');
}

function setStatus(text, kind) {
  $('#statusText').textContent = text;
  const dot = $('#statusDot');
  dot.classList.remove('is-run', 'is-done', 'is-error');
  if (kind) dot.classList.add('is-' + kind);
}

async function queueScheduledRun(scheduleNodes) {
  const active = scheduleNodes.filter((node) => node.params.enabled !== false);
  if (!active.length) {
    toast('Расписание выключено — включите ноду «По расписанию»', 'warn');
    return;
  }
  saveWorkflow();
  clearTimeout(syncTimer);
  if (!api.isRemote) {
    toast('Сценарий сохранён локально; планировщик работает только с сервером', 'warn');
    return;
  }
  const saved = await syncRemote();
  if (!saved) {
    toast('Не удалось сохранить расписание на сервере', 'warn');
    return;
  }
  showWorkspace('runs');
  toast('Сценарий добавлен в процессы и ждёт времени запуска', 'ok');
  setStatus('Ожидает расписания', 'done');
}

async function startRun() {
  if (state.running) {
    if (state.token) {
      state.token.cancelled = true;
      api.cancel(state.token);
    }
    setStatus('Останавливаем…', 'run');
    return;
  }

  const problem = validate();
  if (problem) return toast(problem, 'warn');

  const triggers = state.workflow.nodes.filter((node) => node.type.startsWith('trigger.'));
  const scheduleNodes = triggers.filter((node) => node.type === 'trigger.schedule');
  if (triggers.length && scheduleNodes.length === triggers.length) {
    await queueScheduledRun(scheduleNodes);
    return;
  }

  resetStatuses();
  state.run = null;
  state.liveFindings = [];
  state.activeFindingId = null;
  state.token = { cancelled: false };
  renderAll();
  closeDrawer();
  closeInspector();
  setRunning(true);
  setStatus('Выполняется…', 'run');

  try {
    await api.run(state.workflow, { onEvent }, state.token);
  } catch (error) {
    setRunning(false);
    setStatus('Ошибка выполнения', 'error');
    toast(error && error.message ? error.message : 'Не удалось выполнить сценарий', 'warn');
  }
}

function uiNodeId(nodeId) {
  if (!nodeId || !String(nodeId).includes('/')) return nodeId;
  const outer = String(nodeId).split('/')[0];
  return findNode(outer) ? outer : nodeId;
}

function onEvent(event) {
  switch (event.type) {
    case 'run.started':
      setStatus(`Выполняется · ${event.total} ${plural(event.total, 'узел', 'узла', 'узлов')}`, 'run');
      break;
    case 'node.started': {
      const id = uiNodeId(event.nodeId);
      state.statuses[id] = 'running';
      updateNodeElement(id);
      break;
    }
    case 'node.pending': {
      const id = uiNodeId(event.nodeId);
      state.statuses[id] = 'pending';
      state.chips[id] = event.chip || 'ждём';
      updateNodeElement(id);
      break;
    }
    case 'node.done': {
      const id = uiNodeId(event.nodeId);
      state.statuses[id] = event.status || 'done';
      state.chips[id] = event.chip || '';
      if (event.output) state.outputs[id] = event.output;
      updateNodeElement(id);
      renderWires();
      break;
    }
    case 'edge.active': {
      const wire = $(`.wire[data-id="${event.edgeId}"]`);
      if (wire) {
        wire.classList.add('is-active');
        setTimeout(() => wire.classList.remove('is-active'), 420);
      }
      break;
    }
    case 'findings':
      state.liveFindings.push(...event.items);
      $('#countBadge').textContent = String(state.liveFindings.length);
      break;
    case 'run.done':
      finishRun(event.result, false);
      break;
    case 'run.cancelled':
      finishRun(event.result, true);
      break;
    case 'run.error':
      setStatus('Ошибка выполнения', 'error');
      break;
    default:
      break;
  }
}

function finishRun(result, cancelled) {
  if (!state.running) return;
  setRunning(false);
  state.run = { ...result, at: new Date().toISOString(), target: targetName() };
  setStatus(
    cancelled ? 'Остановлено' : `Готово · ${result.findings.length} ${plural(result.findings.length, 'находка', 'находки', 'находок')}`,
    cancelled ? 'error' : 'done',
  );
  state.activeFindingId = result.findings[0] ? result.findings[0].id : null;
  openDrawer();
  renderResults();
  saveHistoryEntry(result);
  if (cancelled) toast('Проверка остановлена', 'warn');
}





function openDrawer() {
  $('#drawer').classList.add('is-open');
}

function closeDrawer() {
  $('#drawer').classList.remove('is-open');
}

function renderResults() {
  const run = state.run;
  if (!run) return;
  const summary = summarize(run.findings);
  $('#countBadge').textContent = String(run.findings.length);
  renderStats(summary);
  renderFindingsList();
  renderAiView();
  renderReportView();
}

function renderStats(summary) {
  const card = (label, value, cls = '') => h('div', { class: 'stat ' + cls }, h('div', { class: 'stat__label', text: label }), h('div', { class: 'stat__value', text: String(value) }));
  $('#stats').replaceChildren(
    card('Всего', summary.total),
    card('Критично', summary.by.CRITICAL || 0, 'stat--crit'),
    card('Высоко', summary.by.HIGH || 0, 'stat--high'),
    card('Средне', summary.by.MEDIUM || 0, 'stat--med'),
    card('Низко', summary.by.LOW || 0),
  );
}

function renderFindingsList() {
  const run = state.run;
  const list = $('#findingsList');
  list.replaceChildren();

  if (!run.findings.length) {
    list.append(h('div', { class: 'inspector__empty' }, h('p', { text: 'Находок нет — проверка чистая.' })));
    renderFindingDetail(null);
    return;
  }

  for (const finding of run.findings) {
    const row = h(
      'div',
      { class: 'finding-row' + (finding.id === state.activeFindingId ? ' is-active' : ''), role: 'button', tabindex: '0' },
      h('span', { class: 'finding-row__dot', style: `background:${SEVERITY_COLOR[finding.severity]}` }),
      h('span', { class: 'finding-row__cat', text: finding.category }),
      h('span', { class: 'finding-row__title' }, h('b', { text: finding.title }), h('span', { text: `${finding.path}:${finding.line}` })),
      h('span', { class: 'finding-row__sev', style: `color:${SEVERITY_COLOR[finding.severity]}`, text: SEVERITY_LABEL[finding.severity] }),
      h('span', { class: 'finding-row__line', text: finding.endLine ? `${finding.line}–${finding.endLine}` : String(finding.line) }),
    );
    row.addEventListener('click', () => {
      state.activeFindingId = finding.id;
      renderFindingsList();
    });
    row.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        state.activeFindingId = finding.id;
        renderFindingsList();
      }
    });
    list.append(row);
  }

  renderFindingDetail(run.findings.find((f) => f.id === state.activeFindingId) || run.findings[0]);
}

function renderFindingDetail(finding) {
  const root = $('#findingDetail');
  const grid = $('.findings-grid');

  if (!finding) {
    root.hidden = true;
    grid.classList.add('is-solo');
    return;
  }

  grid.classList.remove('is-solo');
  root.hidden = false;
  root.replaceChildren();

  const location = finding.endLine ? `${finding.path}:${finding.line}–${finding.endLine}` : `${finding.path}:${finding.line}`;

  root.append(
    h('div', { class: 'finding-detail__top' },
      h('span', { class: `chip chip--${finding.category}`, text: finding.category }),
      h('span', { class: 'mini-chip', style: `color:${SEVERITY_COLOR[finding.severity]}`, text: SEVERITY_LABEL[finding.severity] }),
      h('span', { class: 'mini-chip', text: finding.class })),
    h('h3', { text: finding.title }),
    h('div', { class: 'finding-detail__path', text: location }),
    h('p', { text: finding.description }),
  );

  if (finding.category === 'SCA') {
    root.append(h('h4', { text: 'Зависимость' }), h('p', { text: `${finding.group}:${finding.artifact}:${finding.version} · ${finding.advisoryId}` }));
  }
  if (finding.why) root.append(h('h4', { text: 'Почему это важно' }), h('p', { text: finding.why }));
  root.append(h('h4', { text: 'Как исправить' }), h('p', { text: finding.remediation }));
  if (finding.snippet) root.append(h('h4', { text: 'Код' }), h('pre', { class: 'code', text: finding.snippet }));

  const copyPath = h('button', { class: 'btn btn--ghost btn--sm', type: 'button' }, svgIcon('copy'), h('span', { text: 'Путь' }));
  copyPath.addEventListener('click', () => copy(location, 'Путь скопирован'));

  const copyJson = h('button', { class: 'btn btn--ghost btn--sm', type: 'button' }, svgIcon('copy'), h('span', { text: 'JSON' }));
  copyJson.addEventListener('click', () => copy(JSON.stringify(toOutputJson([finding]).findings[0], null, 2), 'Фрагмент отчёта скопирован'));

  root.append(h('div', { class: 'finding-detail__actions' }, copyPath, copyJson));
}

function renderAiView() {
  const root = $('#viewAi');
  root.replaceChildren();
  const run = state.run;

  if (!run || !run.ai) {
    root.append(h('div', { class: 'inspector__empty' }, h('p', { text: 'В этом сценарии не было узла AI-объяснения.' })));
    return;
  }

  root.append(
    h('div', { class: 'ai-hero' },
      h('span', { class: 'ai-hero__icon' }, svgIcon('sparkles')),
      h('div', {}, h('h3', { text: 'Сводка по проверке' }), h('p', { text: run.ai.summary }), h('p', { class: 'field__hint', text: `Модель: ${run.ai.model}` }))),
  );
  if (run.ai.provider === 'fallback' || (run.ai.validation && run.ai.validation.errors && run.ai.validation.errors.length)) {
    const errors = (run.ai.validation && run.ai.validation.errors) || [];
    root.append(
      h('div', { class: 'ai-warning' },
        h('b', { text: 'Использован детерминированный fallback' }),
        h('p', { text: errors.length ? errors.slice(0, 3).join(' · ') : 'LLM не ответила или ответ не прошёл проверку.' })),
    );
  }

  const list = h('div', { class: 'ai-list' });
  run.ai.items.forEach((item, index) => {
    list.append(h('div', { class: 'ai-item' }, h('span', { class: 'ai-item__n', text: String(index + 1) }), h('div', {}, h('b', { text: item.title }), h('p', { text: item.why }))));
  });
  root.append(list);
}

function renderReportView() {
  const root = $('#viewReport');
  root.replaceChildren();
  const run = state.run;

  if (!run || !run.report) {
    root.append(h('div', { class: 'inspector__empty' }, h('p', { text: 'Узел «Отчёт» не выполнялся в этом сценарии.' })));
    return;
  }

  const copyJson = h('button', { class: 'btn btn--ghost btn--sm', type: 'button', text: 'Копировать' });
  copyJson.addEventListener('click', () => copy(run.report.json, 'JSON скопирован'));
  const copyMd = h('button', { class: 'btn btn--ghost btn--sm', type: 'button', text: 'Копировать' });
  copyMd.addEventListener('click', () => copy(run.report.markdown, 'Markdown скопирован'));

  const block = (title, content, action) =>
    h('div', { class: 'report-block' }, h('div', { class: 'report-block__head' }, h('span', { text: title }), action), h('pre', { text: content }));

  root.append(h('div', { class: 'report-grid' }, block('findings.json', run.report.json, copyJson), block('report.md', run.report.markdown, copyMd)));
}

function setTab(tab) {
  state.tab = tab;
  for (const el of $$('.tab')) el.classList.toggle('is-active', el.dataset.view === tab);
  $('#viewFindings').hidden = tab !== 'findings';
  $('#viewAi').hidden = tab !== 'ai';
  $('#viewReport').hidden = tab !== 'report';
}





function openModal() {
  $('#modalTitle').textContent = 'История запусков';
  const root = $('#modalBody');
  root.replaceChildren();

  if (!state.history.length) {
    root.append(h('div', { class: 'inspector__empty' }, h('p', { text: 'Пока нет завершённых запусков.' })));
  }

  for (const entry of state.history) {
    const counts = summarize(entry.findings);
    const item = h(
      'div',
      { class: 'run-item' },
      h('div', { class: 'run-item__main' },
        h('b', { text: `${entry.target} · ${new Date(entry.at).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' })}` }),
        h('span', { text: `${entry.findings.length} ${plural(entry.findings.length, 'находка', 'находки', 'находок')} · ${entry.nodes} ${plural(entry.nodes, 'узел', 'узла', 'узлов')}` })),
      h('div', { class: 'run-item__counts' }, h('span', { class: 'mini-chip', text: `CRIT ${counts.by.CRITICAL || 0}` }), h('span', { class: 'mini-chip', text: `HIGH ${counts.by.HIGH || 0}` })),
    );

    const open = h('button', { class: 'btn btn--ghost btn--sm', type: 'button', text: 'Открыть' });
    open.addEventListener('click', () => {
      state.run = entry;
      state.activeFindingId = entry.findings[0] ? entry.findings[0].id : null;
      closeModal();
      openDrawer();
      renderResults();
    });

    const remove = h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Удалить запись' }, svgIcon('trash'));
    remove.addEventListener('click', () => {
      state.history = state.history.filter((x) => x.id !== entry.id);
      try {
        localStorage.setItem(LS_HISTORY, JSON.stringify(state.history));
      } catch {

      }
      openModal();
    });

    item.append(open, remove);
    root.append(item);
  }

  $('#modal').hidden = false;
}

function openLibraryView() {
  renderLibraryPage();
  const stale = !state.libraryAt || Date.now() - state.libraryAt > 60000;
  if ((!state.libraryData || stale) && !state.libraryLoading) loadLibrary(false);
}

async function loadLibrary(force = false) {
  if (state.libraryLoading) return;
  state.libraryLoading = true;
  state.libraryError = '';
  if (!state.libraryData) renderLibraryPage();
  try {
    const data = await api.libraryPresets(force);
    state.libraryData = data;
    state.libraryItems = Array.isArray(data.items) ? data.items : [];
    state.libraryAt = Date.now();
  } catch (error) {
    state.libraryError = error && error.message ? error.message : 'Не удалось получить библиотеку';
  } finally {
    state.libraryLoading = false;
    if (state.workspaceView === 'library') renderLibraryPage();
    if (state.workspaceView === 'presets') renderPresets();
  }
}

function renderLibraryPage() {
  const root = $('#libraryGrid');
  const repoLine = $('#libraryRepoLine');
  if (!root) return;
  const data = state.libraryData;
  const publishButton = $('#libraryPublishBtn');
  if (publishButton) publishButton.disabled = !data || !data.publish_enabled || state.libraryLoading;
  if (repoLine) {
    if (!data) {
      repoLine.textContent = state.libraryError || 'Загрузка пресетов из GitHub…';
    } else if (!data.configured) {
      repoLine.textContent = data.error || 'GitHub-репозиторий не настроен. Укажите LDWARDEN_LIBRARY_REPO в .env.';
    } else {
      const when = state.libraryAt ? new Date(state.libraryAt).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }) : '';
      repoLine.textContent = `${data.repo} · ${data.branch || 'main'} / ${data.path || 'presets'}${when ? ` · кеш ${when}` : ''}${data.publish_enabled ? '' : ' · публикация недоступна без токена'}`;
    }
  }
  root.replaceChildren();

  if (state.libraryError && !data) {
    root.append(h('div', { class: 'workspace-empty' },
      h('h3', { text: 'Библиотека недоступна' }),
      h('p', { text: state.libraryError }),
      h('button', { class: 'btn btn--ghost btn--sm', type: 'button', text: 'Повторить', onclick: () => loadLibrary(true) })));
    return;
  }
  if (!data) {
    root.append(h('div', { class: 'workspace-empty' }, h('p', { text: 'Загружаем пресеты…' })));
    return;
  }
  if (!data.configured) {
    root.append(h('div', { class: 'workspace-empty' },
      h('h3', { text: 'Подключите GitHub-библиотеку' }),
      h('p', { text: 'Создайте репозиторий и добавьте в .env:' }),
      h('pre', { class: 'library-code', text: 'LDWARDEN_LIBRARY_REPO=your-org/ldwarden-presets\nLDWARDEN_LIBRARY_BRANCH=main\nLDWARDEN_LIBRARY_PATH=presets\nLDWARDEN_LIBRARY_TOKEN=github_pat_...' }),
      h('p', { class: 'field__hint', text: 'Токен нужен для публикации; для чтения публичного репозитория можно оставить пустым.' })));
    return;
  }
  const query = state.libraryQuery.trim().toLowerCase();
  const filter = state.libraryFilter || 'all';
  const items = (data.items || []).filter((item) => {
    if (filter === 'nodes') return false;
    if (!query) return true;
    return `${item.name || ''} ${item.description || ''} ${(item.tags || []).join(' ')}`.toLowerCase().includes(query);
  });
  const nodeItems = (data.nodes || []).filter((item) => {
    if (filter === 'presets') return false;
    if (!query) return true;
    return `${item.name || ''} ${item.description || ''} ${item.kind || ''}`.toLowerCase().includes(query);
  });
  const total = filter === 'presets' ? items.length : filter === 'nodes' ? nodeItems.length : items.length + nodeItems.length;
  const setCounts = () => {
    const labels = { all: `Все (${(data.items || []).length + (data.nodes || []).length})`, presets: `Пресеты (${(data.items || []).length})`, nodes: `Ноды (${(data.nodes || []).length})` };
    for (const el of $$('#libraryFilters .library-filter')) {
      if (labels[el.dataset.libraryFilter]) el.textContent = labels[el.dataset.libraryFilter];
      el.classList.toggle('is-active', el.dataset.libraryFilter === filter);
    }
  };
  setCounts();
  if (!total) {
    root.append(h('div', { class: 'workspace-empty' },
      h('h3', { text: query ? 'Ничего не найдено' : 'В библиотеке пока пусто' }),
      h('p', { text: query ? 'Попробуйте другой запрос.' : 'Опубликуйте сценарий или ноду — они появятся здесь.' })));
    return;
  }
  for (const item of nodeItems) {
    const kind = item.kind === 'http' ? 'HTTP' : item.kind === 'ai' ? 'AI' : 'Композит';
    const install = h('button', { class: 'btn btn--primary btn--sm', type: 'button', text: 'Установить' });
    install.addEventListener('click', () => installLibraryNode(item));
    root.append(h('article', { class: 'preset-card library-card' },
      h('div', { class: 'preset-card__top' },
        h('span', { class: 'preset-card__badge', text: 'Нода' }),
        h('span', { class: 'preset-card__active', text: `${kind} · v${item.version || 1}` })),
      h('h2', { class: 'preset-card__title', text: item.name || item.id }),
      item.description ? h('p', { class: 'library-card__text', text: item.description }) : null,
      h('div', { class: 'preset-card__actions' },
        h('span', { class: 'field__hint', text: item.updated_at ? String(item.updated_at).slice(0, 10) : '' }),
        install)));
  }
  for (const item of items) {
    const tags = (item.tags || []).map((tag) => h('span', { class: 'library-tag', text: tag }));
    const card = h('article', { class: 'preset-card library-card' },
      h('div', { class: 'preset-card__top' },
        h('span', { class: 'preset-card__badge', text: 'GitHub' }),
        item.author ? h('span', { class: 'preset-card__active', text: item.author }) : null),
      h('h2', { class: 'preset-card__title', text: item.name || 'Без названия' }),
      item.description ? h('p', { class: 'library-card__text', text: item.description }) : null,
      Array.isArray(item.custom_nodes) && item.custom_nodes.length
        ? h('p', { class: 'field__hint', text: `Требует своих нод: ${item.custom_nodes.length}` })
        : null,
      tags.length ? h('div', { class: 'library-tags' }, ...tags) : null,
      h('div', { class: 'preset-card__actions' },
        h('span', { class: 'field__hint', text: item.updated_at ? String(item.updated_at).slice(0, 10) : '' }),
        h('button', { class: 'btn btn--primary btn--sm', type: 'button', text: 'Добавить в пресеты', onclick: () => addLibraryPreset(item) })),
    );
    root.append(card);
  }
}

async function installLibraryNode(item) {
  try {
    await api.libraryInstall({ custom_nodes: [{ id: item.id, path: item.path }] });
    await loadCustomCatalog();
    await refreshCustomNodes();
    toast(`Нода «${item.name || item.id}» установлена`, 'ok');
  } catch (error) {
    toast(error && error.message ? error.message : 'Не удалось установить ноду', 'warn');
  }
}

async function addLibraryPreset(item) {
  try {
    if (Array.isArray(item.custom_nodes) && item.custom_nodes.length) {
      const installed = await api.libraryInstall({ custom_nodes: item.custom_nodes });
      await loadCustomCatalog();
      await refreshCustomNodes();
      if (installed && installed.count) toast(`Установлено нод: ${installed.count}`, 'info');
    }
    const imported = api.fromBackendWorkflow({ id: item.id, name: item.name, graph: item.graph });
    if (!imported.nodes.length) throw new Error('В пресете нет узлов');
    const baseName = String(item.name || 'Пресет из библиотеки').slice(0, 60);
    let name = baseName;
    let index = 2;
    while (customPresets.some((preset) => preset.name === name)) name = `${baseName} (${index++})`;
    const preset = {
      id: 'library-' + Date.now().toString(36),
      name,
      source: 'library',
      workflow: { name, nodes: imported.nodes, edges: imported.edges },
    };
    customPresets = [...customPresets, preset].slice(-50);
    saveCustomPresets();
    renderPresets();
    toast(`«${name}» добавлен в пресеты`, 'ok');
    showWorkspace('presets');
  } catch (error) {
    toast(error && error.message ? error.message : 'Не удалось добавить пресет', 'warn');
  }
}

async function publishCurrentToLibrary() {
  const name = window.prompt('Название шаблона в библиотеке', state.workflow.name || 'Мой шаблон');
  if (!name || !name.trim()) return;
  const description = window.prompt('Описание (необязательно)', '') || '';
  const tagsText = window.prompt('Теги через запятую', '') || '';
  try {
    const saved = await api.saveWorkflow(state.workflow);
    if (!saved || !saved.id) throw new Error('Не удалось сохранить сценарий на сервере');
    const workflowId = saved.id;
    state.workflow.backendId = workflowId;
    const result = await api.publishLibraryPreset(workflowId, {
      name: name.trim(),
      description,
      tags: tagsText.split(',').map((tag) => tag.trim()).filter(Boolean),
    });
    const nodesNote = result.nodes_count ? ` и ${result.nodes_count} нод(ы)` : '';
    toast(`Опубликовано: ${result.path || name}${nodesNote}`, 'ok');
    await loadLibrary(true);
    renderLibraryPage();
  } catch (error) {
    toast(error && error.message ? error.message : 'Не удалось опубликовать шаблон', 'warn');
  }
}

function closeModal() {
  $('#modal').hidden = true;
  stopTelegramPoll();
}

function exportJson() {
  if (!state.run) return toast('Сначала запустите сценарий', 'warn');
  download('ldwarden-findings.json', JSON.stringify(toOutputJson(state.run.findings), null, 2), 'application/json');
  toast('JSON выгружен', 'ok');
}

function exportMarkdown() {
  if (!state.run) return toast('Сначала запустите сценарий', 'warn');
  download('ldwarden-report.md', toMarkdown(state.run.findings, { target: state.run.target }), 'text/markdown');
  toast('Отчёт выгружен', 'ok');
}

async function exportHtml() {
  if (!state.run) return toast('Сначала запустите сценарий', 'warn');
  if (api.isRemote && state.run.runId) {
    try {
      const response = await fetch(
        `/api/runs/${encodeURIComponent(state.run.runId)}/report?format=html&download=1&theme=${encodeURIComponent(currentTheme)}`,
      );
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'ldwarden-report.html';
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
      toast('HTML-отчёт выгружен', 'ok');
    } catch (error) {
      toast('Не удалось получить HTML-отчёт с сервера', 'warn');
    }
    return;
  }
  download('ldwarden-report.html', toHtml(state.run.findings, { target: state.run.target }), 'text/html');
  toast('HTML-отчёт выгружен', 'ok');
}





function bindEvents() {
  for (const tab of $$('#workspaceTabs .workspace-tab')) {
    tab.addEventListener('click', () => showWorkspace(tab.dataset.workspace));
  }
  $('#runBtn').addEventListener('click', startRun);
  $('#savePresetBtn').addEventListener('click', saveCurrentAsPreset);
  $('#historyBtn').addEventListener('click', openModal);
  $('#runsRefreshBtn').addEventListener('click', () => loadRuns(true));
  $('#compositeBtn').addEventListener('click', openCompositeDialog);
  $('#compositeSaveBtn').addEventListener('click', saveCompositeEdit);
  $('#compositeCancelBtn').addEventListener('click', cancelCompositeEdit);
  $('#nodesToGraphBtn').addEventListener('click', () => showWorkspace('graph'));
  $('#closeDrawer').addEventListener('click', closeDrawer);
  $('#presetCreateBtn').addEventListener('click', saveCurrentAsPreset);
  $('#presetExportBtn').addEventListener('click', exportCustomPresets);
  $('#presetImportBtn').addEventListener('click', () => $('#presetImportInput').click());
  $('#presetImportInput').addEventListener('change', async (event) => {
    const file = event.target.files && event.target.files[0];
    event.target.value = '';
    await importCustomPresets(file);
  });
  $('#presetSearch').addEventListener('input', (event) => {
    state.presetQuery = event.target.value;
    renderPresets();
  });
  $('#generatorRunBtn').addEventListener('click', runGenerator);
  for (const example of $$('#generatorExamples .preset')) {
    example.addEventListener('click', () => {
      const prompt = $('#generatorPrompt');
      if (prompt) prompt.value = example.textContent || '';
      state.generatorError = '';
      renderGeneratorPage();
    });
  }
  $('#ciRefreshBtn').addEventListener('click', () => loadCiView(true));
  $('#ciGenerateBtn').addEventListener('click', generateCiSnippet);
  $('#ciWorkflow').addEventListener('change', (event) => {
    state.ciWorkflowId = event.target.value;
    generateCiSnippet();
  });
  $('#ciBaseUrl').addEventListener('input', (event) => { state.ciBaseUrl = event.target.value.trim(); });
  $('#ciTarget').addEventListener('input', (event) => { state.ciTarget = event.target.value.trim(); });
  for (const platform of $$('.ci-platform')) {
    platform.addEventListener('click', () => {
      state.ciPlatform = platform.dataset.platform || 'github';
      renderCiPage();
    });
  }
  $('#ciCopyBtn').addEventListener('click', () => {
    if (state.ciSnippet) copy(state.ciSnippet, 'CI-конфиг скопирован');
  });
  $('#ciDownloadBtn').addEventListener('click', () => {
    if (!state.ciSnippet) return;
    const filename = state.ciPlatform === 'gitlab' ? 'ldwarden-gitlab-ci.yml' : 'ldwarden-github-actions.yml';
    download(filename, state.ciSnippet, 'text/yaml');
    toast('CI-конфиг выгружен', 'ok');
  });
  $('#ciCheckBtn').addEventListener('click', ciCheckWorkflow);
  $('#libraryRefreshBtn').addEventListener('click', () => loadLibrary(true));
  for (const filter of $$('#libraryFilters .library-filter')) {
    filter.addEventListener('click', () => {
      state.libraryFilter = filter.dataset.libraryFilter || 'all';
      for (const el of $$('#libraryFilters .library-filter')) el.classList.toggle('is-active', el === filter);
      renderLibraryPage();
    });
  }
  $('#libraryPublishBtn').addEventListener('click', publishCurrentToLibrary);
  $('#librarySearch').addEventListener('input', (event) => {
    state.libraryQuery = event.target.value;
    renderLibraryPage();
  });
  $('#exportJson').addEventListener('click', exportJson);
  $('#exportMd').addEventListener('click', exportMarkdown);
  $('#exportHtml').addEventListener('click', exportHtml);

  for (const tab of $$('.tab')) tab.addEventListener('click', () => setTab(tab.dataset.view));
  for (const closer of $$('[data-close-modal]')) closer.addEventListener('click', closeModal);

  $('#zoomIn').addEventListener('click', () => {
    const rect = $('#viewport').getBoundingClientRect();
    zoomAt(rect.left + rect.width / 2, rect.top + rect.height / 2, 1.15);
  });
  $('#zoomOut').addEventListener('click', () => {
    const rect = $('#viewport').getBoundingClientRect();
    zoomAt(rect.left + rect.width / 2, rect.top + rect.height / 2, 1 / 1.15);
  });
  $('#zoomLabel').addEventListener('click', () => {
    state.view.z = 1;
    applyView();
  });
  $('#fitView').addEventListener('click', fitView);

  $('#viewport').addEventListener('pointerdown', (event) => {
    if (event.button === 2 || event.button === 1) {
      event.preventDefault();
      startPan(event);
      return;
    }
    if (event.button !== 0) return;
    if (event.target.closest('.node') || event.target.closest('.pin')) return;
    if (event.target.closest('.wire')) return;
    startMarquee(event);
  });
  $('#viewport').addEventListener('contextmenu', (event) => event.preventDefault());

  $('#viewport').addEventListener('wheel', (event) => {
    event.preventDefault();
    zoomAt(event.clientX, event.clientY, event.deltaY < 0 ? 1.1 : 1 / 1.1);
  }, { passive: false });

  window.addEventListener('resize', () => applyView());

  document.addEventListener('keydown', (event) => {
    const typing = /^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement ? document.activeElement.tagName : '');
    const mod = event.metaKey || event.ctrlKey;
    const key = String(event.key || '').toLowerCase();

    if (mod && !event.altKey && key === 's') {
      event.preventDefault();
      if (state.compositeEdit) saveCompositeEdit();
      else saveCurrentAsPreset();
      return;
    }
    if (!typing && mod && !event.altKey) {
      if (key === 'z' && event.shiftKey) {
        if (redo()) event.preventDefault();
        return;
      }
      if (key === 'z') {
        if (undo()) event.preventDefault();
        return;
      }
      if (key === 'y') {
        if (redo()) event.preventDefault();
        return;
      }
      if (key === 'a') {
        event.preventDefault();
        selectMany(state.workflow.nodes.map((node) => node.id));
        return;
      }
      if (key === 'c') {
        if (copySelectedNodes()) event.preventDefault();
        return;
      }
      if (key === 'v') {
        if (pasteNodes()) event.preventDefault();
        return;
      }
    }

    if (mod && event.key === 'Enter') {
      event.preventDefault();
      startRun();
      return;
    }
    if (event.key === 'Escape') {
      closeModal();
      closeDrawer();
      return;
    }
    if (!typing && (event.key === 'Delete' || event.key === 'Backspace')) {
      if (state.selectedNodes.length) {
        event.preventDefault();
        deleteSelectedNodes();
      } else if (state.selectedEdge) {
        event.preventDefault();
        deleteEdge(state.selectedEdge);
      }
    }
  });
}





function init() {
  applyTheme(readTheme(), { persist: false });
  initThemeSwitch();
  initEdgeMenu();
  renderPalette();
  renderPresets();
  renderAll();
  renderInspector();
  bindEvents();
  setTab('findings');
  fitView();

  const params = new URLSearchParams(location.search);
  if (params.get('demo') === '1') {
    const preset = PRESETS.find((p) => p.id === 'release') || PRESETS[0];
    applyPreset(preset);
    setTimeout(() => startRun(), 700);
  } else {
    hydrateRemote();
  }
}

init();
