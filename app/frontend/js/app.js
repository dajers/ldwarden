/**
 * ldwarden — граф-редактор проверок безопасности.
 * Ноды с пинами, провода на безье, панорама и масштаб.
 */

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
import { plural, summarize, toMarkdown, toOutputJson } from './engine.js';

/* ------------------------------------------------------------------ */
/* утилиты                                                             */
/* ------------------------------------------------------------------ */

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
    /* запасной путь ниже */
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


/* ------------------------------------------------------------------ */
/* темы оформления                                                     */
/* ------------------------------------------------------------------ */

const THEME_KEY = 'sakura.theme';
const THEMES = ['sakura', 'mono', 'warden'];
let currentTheme = readTheme();

function readTheme() {
  try {
    const saved = localStorage.getItem(THEME_KEY);
    if (THEMES.includes(saved)) return saved;
  } catch {
    /* приватный режим */
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
      /* ignore */
    }
  }
  for (const option of $$('.theme-option')) option.classList.toggle('is-active', option.dataset.theme === next);
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

/* ------------------------------------------------------------------ */
/* цвет связей                                                         */
/* ------------------------------------------------------------------ */

let edgeMenuTarget = null;

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

/* ------------------------------------------------------------------ */
/* состояние                                                           */
/* ------------------------------------------------------------------ */

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
};

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
      const label = { local: 'AI · локальная модель', fake: 'AI · тест', openai: 'AI · API', ollama: 'AI · Ollama', none: 'AI · fallback' }[provider] || `AI · ${provider}`;
      setAiPill(label);
    }
  } catch {
    /* сервер может быть недоступен — работаем локально */
  }
  try {
    const remote = await api.loadWorkflow();
    if (remote && remote.workflow && remote.workflow.nodes.length) {
      state.workflow = remote.workflow;
      state.selectedNode = null;
      state.selectedNodes = [];
      state.selectedEdge = null;
      resetStatuses();
      renderAll();
      fitView();
      try {
        localStorage.setItem(LS_WORKFLOW, JSON.stringify(localSnapshot(state.workflow)));
      } catch {
        /* ignore */
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
  if (!api.isRemote || !state.workflow.nodes.length) return;
  try {
    const saved = await api.saveWorkflow(state.workflow);
    if (saved && saved.id) {
      state.workflow.backendId = saved.id;
      setSavePill('Сохранено на сервере', 'ok');
      syncWarned = false;
    }
  } catch (error) {
    setSavePill('Локальный черновик');
    if (!syncWarned) {
      syncWarned = true;
      toast(error && error.message ? error.message : 'Не удалось сохранить на сервере', 'warn');
    }
  }
}

function normalizeGraph(raw) {
  const nodes = Array.isArray(raw && raw.nodes) ? raw.nodes.filter((n) => n && NODE_TYPES[n.type]) : [];
  const normalized = nodes.map((n) => {
    const def = NODE_TYPES[n.type];
    const params = {};
    for (const p of def.params) params[p.key] = n.params && p.key in n.params ? n.params[p.key] : p.def;
    if (n.type === 'logic.branch') {
      const fields = { total: 'findings.total', critical: 'findings.CRITICAL', secret: 'findings.by_category.SECRET' };
      const operators = { '>=': 'gte', '==': 'eq', '<=': 'lte', '>': 'gt' };
      if (fields[params.field]) params.field = fields[params.field];
      if (n.params && operators[n.params.op]) params.operator = operators[n.params.op];
      params.value = String(params.value);
    }
    return {
      id: n.id || newIdent('n'),
      type: n.type,
      x: Number.isFinite(n.x) ? n.x : 120,
      y: Number.isFinite(n.y) ? n.y : 160,
      params,
    };
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
    if (node.type === 'notify.send' && node.params && node.params.token) node.params.token = '••••••';
    if (node.type === 'source.repo' && node.params && node.params.gitToken) node.params.gitToken = '••••••';
    if (node.type === 'notify.send' && node.params && node.params.hmacSecret) node.params.hmacSecret = '••••••';
    if (node.type === 'trigger.webhook' && node.params && node.params.secret) node.params.secret = '••••••';
  }
  return copy;
}

function saveWorkflow() {
  try {
    localStorage.setItem(LS_WORKFLOW, JSON.stringify(localSnapshot(state.workflow)));
  } catch {
    /* приватный режим */
  }
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
    /* переполнение игнорируем */
  }
}

function targetName() {
  const node = state.workflow.nodes.find((n) => n.type === 'source.repo');
  return (node && node.params.target) || 'training-project';
}

const findNode = (id) => state.workflow.nodes.find((n) => n.id === id) || null;

/* ------------------------------------------------------------------ */
/* геометрия и провода                                                 */
/* ------------------------------------------------------------------ */

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

function wireD(from, to) {
  const dx = Math.max(48, Math.abs(to.x - from.x) * 0.45);
  return `M ${from.x} ${from.y} C ${from.x + dx} ${from.y}, ${to.x - dx} ${to.y}, ${to.x} ${to.y}`;
}

/* ------------------------------------------------------------------ */
/* палитра и пресеты                                                  */
/* ------------------------------------------------------------------ */

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
    /* приватный режим */
  }
}

function saveCurrentAsPreset() {
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
  saveCustomPresets();
  renderPresets();
  toast(`Пресет «${preset.name}» сохранён`, 'ok');
}

function deleteCustomPreset(id) {
  const preset = customPresets.find((item) => item.id === id);
  if (!preset) return;
  if (!window.confirm(`Удалить пресет «${preset.name}»?`)) return;
  customPresets = customPresets.filter((item) => item.id !== id);
  saveCustomPresets();
  renderPresets();
  toast(`Пресет «${preset.name}» удалён`, 'ok');
}

function renderPresets() {
  const root = $('#presets');
  root.replaceChildren(h('span', { class: 'presets__label' }, 'Пресеты:'));
  for (const preset of [...PRESETS, ...customPresets]) {
    const button = h('button', { class: 'preset' + (preset.workflow ? ' preset--custom' : ''), type: 'button' }, h('span', { text: preset.name }));
    button.addEventListener('click', () => applyPreset(preset));
    if (preset.workflow) {
      const remove = h('span', { class: 'preset__remove', role: 'button', tabindex: '0', title: 'Удалить пресет', text: '×' });
      remove.addEventListener('click', (event) => {
        event.stopPropagation();
        deleteCustomPreset(preset.id);
      });
      remove.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          event.stopPropagation();
          deleteCustomPreset(preset.id);
        }
      });
      button.append(remove);
    }
    root.append(button);
  }
  const add = h('button', { class: 'preset preset--add', type: 'button', text: '+ Свой пресет' });
  add.addEventListener('click', saveCurrentAsPreset);
  root.append(add);
}

function applyPreset(preset) {
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
  toast(`Пресет «${preset.name}» загружен`, 'ok');
}

function resetStatuses() {
  state.statuses = {};
  state.chips = {};
  state.outputs = {};
}

/* ------------------------------------------------------------------ */
/* отрисовка графа                                                     */
/* ------------------------------------------------------------------ */

function renderAll() {
  renderNodes();
  renderWires();
  updateEmpty();
  $('#footStats').textContent = `${state.workflow.nodes.length} ${plural(state.workflow.nodes.length, 'узел', 'узла', 'узлов')} · ${state.workflow.edges.length} ${plural(state.workflow.edges.length, 'связь', 'связи', 'связей')}`;
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
  body.append(h('div', { class: 'node__chip' + (chip ? ' is-visible' : ''), text: chip }));

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

function renderWires() {
  const group = $('#wiresGroup');
  const frag = document.createDocumentFragment();

  for (const edge of state.workflow.edges) {
    const from = findNode(edge.from.node);
    const to = findNode(edge.to.node);
    if (!from || !to) continue;

    const kind = portKind(from, edge.from.port, 'out');
    const d = wireD(pinPosition(from, edge.from.port, 'out'), pinPosition(to, edge.to.port, 'in'));

    const g = document.createElementNS(NS, 'g');
    g.setAttribute('class', `wire wire--${kind}${state.selectedEdge === edge.id ? ' is-selected' : ''}`);
    g.dataset.id = edge.id;

    const hit = svgPath(d, 'wire__hit');
    const line = svgPath(d, 'wire__line');
    if (edge.color) line.style.stroke = edge.color;
    hit.addEventListener('pointerdown', (event) => {
      if (event.button === 0) event.stopPropagation();
    });
    hit.addEventListener('click', (event) => {
      event.stopPropagation();
      selectEdge(edge.id);
      openEdgeMenu(edge, event.clientX, event.clientY);
    });

    g.append(hit, line);
    frag.append(g);
  }

  group.replaceChildren(frag);
}

function updateNodeElement(id) {
  const el = $(`.node[data-id="${id}"]`);
  if (!el) return;
  const status = state.statuses[id];
  el.classList.remove('is-running', 'is-done', 'is-skipped', 'is-error');
  if (status) el.classList.add('is-' + status);

  const chip = el.querySelector('.node__chip');
  if (chip) {
    chip.textContent = state.chips[id] || '';
    chip.classList.toggle('is-visible', Boolean(state.chips[id]));
  }
}

/* ------------------------------------------------------------------ */
/* выбор                                                               */
/* ------------------------------------------------------------------ */

function syncSelection() {
  for (const el of $$('.node')) {
    const selected = state.selectedNodes.includes(el.dataset.id);
    el.classList.toggle('is-selected', selected);
    el.classList.toggle('is-multi-selected', selected && state.selectedNodes.length > 1);
  }
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

/* ------------------------------------------------------------------ */
/* инспектор                                                           */
/* ------------------------------------------------------------------ */

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

async function connectTelegram(node) {
  try {
    const session = await api.telegramConnect();
    const link = document.createElement('a');
    link.href = session.connect_url;
    link.target = '_blank';
    link.rel = 'noopener';
    document.body.append(link);
    link.click();
    link.remove();
    toast('В Telegram нажмите Start — ждём подключение…', 'info');
    const started = Date.now();
    while (Date.now() - started < 90000) {
      await new Promise((resolve) => setTimeout(resolve, 2000));
      const result = await api.telegramChats(session.state);
      if (result.items && result.items.length) {
        const chat = result.items[0];
        node.params.chatId = String(chat.chat_id);
        saveWorkflow();
        renderInspector();
        try {
          const saved = await api.saveWorkflow(state.workflow);
          if (saved && saved.id && result.items.length === 1) {
            await api.telegramLink(session.state, chat.chat_id, saved.id);
          }
        } catch {
          /* привязка не критична, chat_id уже в ноде */
        }
        toast(`Telegram подключён: ${chat.title || chat.chat_id}`, 'ok');
        return;
      }
    }
    toast('Не дождались Start в Telegram', 'warn');
  } catch (error) {
    toast(error && error.message ? error.message : 'Не удалось подключить Telegram', 'warn');
  }
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
  root.style.setProperty('--cat', CATEGORIES[def.cat].color);

  root.append(inspectorHead(CATEGORIES[def.cat].label, def.title, def.icon));

  const body = h('div', { class: 'inspector__body' });
  for (const param of def.params) body.append(renderField(node, param));
  if (api.isRemote && node.type === 'notify.send' && node.params.channel === 'Telegram') {
    const connect = h('button', { class: 'btn btn--ghost btn--sm', type: 'button' }, svgIcon('send'), h('span', { text: 'Подключить Telegram' }));
    connect.addEventListener('click', () => connectTelegram(node));
    body.append(
      h('div', { class: 'field' },
        connect,
        h('p', { class: 'field__hint', text: 'Откроется бот. Нажмите Start — Chat ID подставится автоматически.' })),
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

  if (param.type === 'select') {
    const select = h('select', { class: 'select' });
    for (const option of param.options) {
      const label = param.labels && param.labels[option] ? param.labels[option] : option;
      const optionEl = h('option', { value: option, text: label });
      if (String(option) === String(value)) optionEl.selected = true;
      select.append(optionEl);
    }
    select.addEventListener('change', () => setParam(node, param.key, select.value));
    wrap.append(select);
  } else {
    const input = h('input', {
      class: 'input',
      type: param.type === 'number' ? 'number' : param.type === 'secret' ? 'password' : 'text',
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

function setParam(node, key, value) {
  node.params[key] = value;
  const meta = $(`.node[data-id="${node.id}"] .node__meta`);
  if (meta) meta.textContent = nodeSub(node);
  saveWorkflow();
}

/* ------------------------------------------------------------------ */
/* операции с графом                                                   */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/* вид: панорама и масштаб                                             */
/* ------------------------------------------------------------------ */

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
  const z = clamp(Math.min((rect.width - pad * 2) / w, (rect.height - pad * 2) / hgt, 1.15), 0.66, 1.2);
  state.view.z = z;
  state.view.x = (rect.width - w * z) / 2 - minX * z;
  state.view.y = (rect.height - hgt * z) / 2 - minY * z;
  applyView();
}

/* ------------------------------------------------------------------ */
/* перетаскивание: узел, панорама, провод                              */
/* ------------------------------------------------------------------ */

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
  };

  $('#tempWire').setAttribute('d', wireD(origin, origin));
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
    interaction.cursor = world;
    $('#tempWire').setAttribute('d', wireD(interaction.origin, world));
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
    for (const el of $$('.pin.is-linkable')) el.classList.remove('is-linkable');

    const target = document.elementFromPoint(event.clientX, event.clientY);
    const pinEl = target && target.closest ? target.closest('.pin') : null;
    if (!pinEl) return;

    const other = findNode(pinEl.dataset.node);
    if (!other) return;

    if (current.dir === 'out') {
      if (connectPins(current.node, current.pin.id, other, pinEl.dataset.port)) {
        renderWires();
        saveWorkflow();
      }
    } else if (connectPins(other, pinEl.dataset.port, current.node, current.pin.id)) {
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

/* ------------------------------------------------------------------ */
/* запуск                                                              */
/* ------------------------------------------------------------------ */

function validate() {
  const nodes = state.workflow.nodes;
  if (!nodes.length) return 'Перетащите узлы на холст или выберите пресет';
  const triggers = nodes.filter((n) => n.type.startsWith('trigger.'));
  if (!triggers.length) return 'Добавьте узел запуска';
  const sources = nodes.filter((n) => n.type === 'source.repo');
  if (!sources.length) return 'Добавьте узел «Репозиторий»';
  const scans = nodes.filter((n) => n.type.startsWith('scan.'));
  if (!scans.length) return 'Добавьте хотя бы одну проверку';

  const outgoing = new Map(nodes.map((n) => [n.id, []]));
  for (const edge of state.workflow.edges) {
    if (!['out', 'true', 'false', 'pass', 'fail'].includes(edge.from.port) || edge.to.port !== 'in') continue;
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
  $('#runLabel').textContent = active ? 'Остановить' : 'Запустить';
  button.querySelector('use').setAttribute('href', active ? '#i-stop' : '#i-play');
}

function setStatus(text, kind) {
  $('#statusText').textContent = text;
  const dot = $('#statusDot');
  dot.classList.remove('is-run', 'is-done', 'is-error');
  if (kind) dot.classList.add('is-' + kind);
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

function onEvent(event) {
  switch (event.type) {
    case 'run.started':
      setStatus(`Выполняется · ${event.total} ${plural(event.total, 'узел', 'узла', 'узлов')}`, 'run');
      break;
    case 'node.started':
      state.statuses[event.nodeId] = 'running';
      updateNodeElement(event.nodeId);
      break;
    case 'node.done':
      state.statuses[event.nodeId] = event.status || 'done';
      state.chips[event.nodeId] = event.chip || '';
      if (event.output) state.outputs[event.nodeId] = event.output;
      updateNodeElement(event.nodeId);
      break;
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

/* ------------------------------------------------------------------ */
/* результаты                                                          */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/* история и экспорт                                                   */
/* ------------------------------------------------------------------ */

function openModal() {
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
        /* ignore */
      }
      openModal();
    });

    item.append(open, remove);
    root.append(item);
  }

  $('#modal').hidden = false;
}

function closeModal() {
  $('#modal').hidden = true;
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

/* ------------------------------------------------------------------ */
/* события интерфейса                                                  */
/* ------------------------------------------------------------------ */

function bindEvents() {
  $('#runBtn').addEventListener('click', startRun);
  $('#historyBtn').addEventListener('click', openModal);
  $('#closeDrawer').addEventListener('click', closeDrawer);
  $('#exportJson').addEventListener('click', exportJson);
  $('#exportMd').addEventListener('click', exportMarkdown);

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

    if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') {
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

/* ------------------------------------------------------------------ */
/* старт                                                               */
/* ------------------------------------------------------------------ */

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
