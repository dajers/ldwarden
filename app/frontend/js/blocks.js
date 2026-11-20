/**
 * Каталог узлов графа.
 * Узел = карточка с пинами (exec и data), параметрами и выходными данными.
 * Геометрия узла детерминирована, чтобы провода считались без измерения DOM.
 */

export const CATEGORIES = {
  trigger: { label: 'Запуск', color: 'var(--cat-trigger)', tint: '#faf6fd' },
  source: { label: 'Источник', color: 'var(--cat-source)', tint: '#f6f8fd' },
  scan: { label: 'Проверки', color: 'var(--cat-scan)', tint: '#fdf5f7' },
  logic: { label: 'Логика', color: 'var(--cat-logic)', tint: '#fdfaf4' },
  action: { label: 'Действия', color: 'var(--cat-action)', tint: '#f6faf5' },
};

export const CATEGORY_ORDER = ['trigger', 'source', 'scan', 'logic', 'action'];

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
export const SEVERITY_RANK = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
export const SEVERITY_LABEL = { CRITICAL: 'Критично', HIGH: 'Высоко', MEDIUM: 'Средне', LOW: 'Низко' };
export const SEVERITY_COLOR = { CRITICAL: 'var(--crit)', HIGH: 'var(--bad)', MEDIUM: 'var(--warn)', LOW: '#6e8fa8' };

/* ---------- геометрия ---------- */

export const NODE_W = 232;
export const HEADER_H = 38;
export const BODY_PAD = 10;
export const ROW_H = 26;
export const META_H = 26;
export const CHIP_H = 22;

export function nodeRows(type) {
  const def = NODE_TYPES[type];
  return Math.max(def.inputs.length, def.outputs.length, 1);
}

export function nodeHeight(type) {
  return HEADER_H + BODY_PAD + nodeRows(type) * ROW_H + META_H + CHIP_H + 6;
}

/** Y-координата пина относительно верхней границы узла. */
export function pinOffsetY(type, index) {
  return HEADER_H + BODY_PAD + index * ROW_H + ROW_H / 2;
}

export function portIndex(type, portId, dir) {
  const def = NODE_TYPES[type];
  const list = dir === 'out' ? def.outputs : def.inputs;
  return list.findIndex((p) => p.id === portId);
}

/* ---------- описания узлов ---------- */

const CONDITION_FIELDS = { total: 'находок', critical: 'критичных', secret: 'секретов' };

export const NODE_TYPES = {
  'trigger.manual': {
    cat: 'trigger',
    icon: 'play',
    title: 'Запуск вручную',
    sub: () => 'кнопка «Запустить»',
    inputs: [],
    outputs: [{ id: 'out', kind: 'exec', label: 'Запуск' }],
    params: [],
  },
  'trigger.webhook': {
    cat: 'trigger',
    icon: 'play',
    title: 'Webhook / CI',
    sub: () => 'внешний HTTP-запуск',
    inputs: [],
    outputs: [{ id: 'out', kind: 'exec', label: 'Запуск' }],
    params: [],
  },
  'trigger.schedule': {
    cat: 'trigger',
    icon: 'clock',
    title: 'По расписанию',
    sub: (p) => p.cron,
    inputs: [],
    outputs: [{ id: 'out', kind: 'exec', label: 'Сработало' }],
    params: [
      {
        key: 'cron',
        label: 'Когда запускать',
        type: 'select',
        options: ['Каждый день в 14:00', 'Каждый час', 'По понедельникам в 09:00'],
        def: 'Каждый день в 14:00',
      },
    ],
  },
  'source.repo': {
    cat: 'source',
    icon: 'box',
    title: 'Репозиторий',
    sub: (p) => p.target,
    inputs: [{ id: 'in', kind: 'exec', label: 'Вход' }],
    outputs: [
      { id: 'out', kind: 'exec', label: 'Готово' },
      { id: 'files', kind: 'data', label: 'файлы' },
    ],
    params: [
      { key: 'target', label: 'Путь или ссылка', type: 'text', def: 'training-project' },
      { key: 'branch', label: 'Ветка', type: 'text', def: 'main' },
    ],
  },
  'scan.secret': {
    cat: 'scan',
    icon: 'key',
    title: 'Поиск секретов',
    sub: (p) => `SECRET · порог ${p.minSeverity}`,
    inputs: [{ id: 'in', kind: 'exec', label: 'Вход' }],
    outputs: [
      { id: 'out', kind: 'exec', label: 'Готово' },
      { id: 'findings', kind: 'data', label: 'находки' },
    ],
    params: [
      { key: 'minSeverity', label: 'Минимальная критичность', type: 'select', options: SEVERITIES, def: 'LOW' },
      { key: 'mask', label: 'Маскировать значения', type: 'toggle', def: true, hint: 'Значение секрета скрывается в интерфейсе и отчёте.' },
    ],
  },
  'scan.sca': {
    cat: 'scan',
    icon: 'package',
    title: 'Уязвимые зависимости',
    sub: () => 'SCA · Maven-справочник',
    inputs: [{ id: 'in', kind: 'exec', label: 'Вход' }],
    outputs: [
      { id: 'out', kind: 'exec', label: 'Готово' },
      { id: 'findings', kind: 'data', label: 'находки' },
    ],
    params: [{ key: 'db', label: 'Справочник уязвимостей', type: 'text', def: 'vulnerabilities.json' }],
  },
  'scan.sast': {
    cat: 'scan',
    icon: 'shield',
    title: 'Статический анализ',
    sub: (p) => `SAST · ${p.lang}`,
    inputs: [{ id: 'in', kind: 'exec', label: 'Вход' }],
    outputs: [
      { id: 'out', kind: 'exec', label: 'Готово' },
      { id: 'findings', kind: 'data', label: 'находки' },
    ],
    params: [{ key: 'lang', label: 'Язык', type: 'select', options: ['Kotlin', 'Java'], def: 'Kotlin' }],
  },
  'logic.branch': {
    cat: 'logic',
    icon: 'branch',
    title: 'Ветвление',
    sub: (p) => `${CONDITION_FIELDS[p.field] || p.field} ${p.op} ${p.value}`,
    inputs: [{ id: 'in', kind: 'exec', label: 'Вход' }],
    outputs: [
      { id: 'true', kind: 'exec', label: 'Да' },
      { id: 'false', kind: 'exec', label: 'Нет' },
    ],
    params: [
      { key: 'field', label: 'Что проверяем', type: 'select', options: ['total', 'critical', 'secret'], def: 'critical', labels: CONDITION_FIELDS },
      { key: 'op', label: 'Условие', type: 'select', options: ['>=', '==', '<=', '>'], def: '>=' },
      { key: 'value', label: 'Значение', type: 'number', def: 1 },
    ],
  },
  'control.gate': {
    cat: 'logic',
    icon: 'shield',
    title: 'Порог критичности',
    sub: (p) => `${p.threshold}${p.blocking ? ' · блокирует' : ''}`,
    inputs: [{ id: 'in', kind: 'exec', label: 'Вход' }],
    outputs: [
      { id: 'pass', kind: 'exec', label: 'Пройден' },
      { id: 'fail', kind: 'exec', label: 'Превышен' },
    ],
    params: [
      { key: 'threshold', label: 'Порог', type: 'select', options: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], def: 'HIGH' },
      { key: 'blocking', label: 'Блокировать запуск', type: 'toggle', def: true },
    ],
  },
  'ai.explain': {
    cat: 'action',
    icon: 'sparkles',
    title: 'AI-объяснение',
    sub: (p) => p.model,
    inputs: [
      { id: 'in', kind: 'exec', label: 'Вход' },
      { id: 'findings', kind: 'data', label: 'находки' },
    ],
    outputs: [
      { id: 'out', kind: 'exec', label: 'Готово' },
      { id: 'summary', kind: 'data', label: 'сводка' },
    ],
    params: [
      {
        key: 'model',
        label: 'Модель',
        type: 'select',
        options: ['Qwen2.5-Coder 7B · локально', 'Llama 3.1 8B · локально', 'GigaChat · API'],
        def: 'Qwen2.5-Coder 7B · локально',
      },
      { key: 'tone', label: 'Тон объяснения', type: 'select', options: ['Для разработчика', 'Для менеджера'], def: 'Для разработчика' },
    ],
  },
  'notify.send': {
    cat: 'action',
    icon: 'send',
    title: 'Уведомление',
    sub: (p) => `${p.channel}${p.onlyCritical ? ' · только критичные' : ''}`,
    inputs: [
      { id: 'in', kind: 'exec', label: 'Вход' },
      { id: 'payload', kind: 'data', label: 'данные' },
    ],
    outputs: [{ id: 'out', kind: 'exec', label: 'Отправлено' }],
    params: [
      { key: 'channel', label: 'Канал', type: 'select', options: ['Telegram', 'HTTP webhook', 'E-mail'], def: 'Telegram' },
      { key: 'token', label: 'Токен / URL / пароль', type: 'secret', def: '', hint: 'Шифруется на бэкенде и маскируется в интерфейсе.' },
      { key: 'chatId', label: 'Chat ID / адрес', type: 'text', def: '', hint: 'Для Telegram можно оставить пустым — возьмётся из .env или подключения.' },
      { key: 'attachReport', label: 'Приложить отчёт', type: 'toggle', def: true },
      { key: 'dryRun', label: 'Dry-run', type: 'toggle', def: false },
    ],
  },
  'report.build': {
    cat: 'action',
    icon: 'file',
    title: 'Отчёт',
    sub: (p) => p.formats,
    inputs: [
      { id: 'in', kind: 'exec', label: 'Вход' },
      { id: 'findings', kind: 'data', label: 'находки' },
    ],
    outputs: [{ id: 'out', kind: 'exec', label: 'Готово' }],
    params: [{ key: 'formats', label: 'Форматы', type: 'select', options: ['JSON + Markdown + SARIF', 'JSON + Markdown', 'Только JSON', 'Только Markdown'], def: 'JSON + Markdown' }],
  },
};

/* ---------- конструкторы ---------- */

const uid = (prefix) => {
  const c = globalThis.crypto;
  if (c && typeof c.randomUUID === 'function') return `${prefix}-${c.randomUUID().slice(0, 8)}`;
  return `${prefix}-${Date.now().toString(36)}-${Math.floor(Math.random() * 1e6).toString(36)}`;
};

export function createNode(type, x = 0, y = 0, params = {}) {
  const def = NODE_TYPES[type];
  if (!def) throw new Error('Неизвестный тип узла: ' + type);
  const values = {};
  for (const param of def.params) values[param.key] = param.key in params ? params[param.key] : param.def;
  return { id: uid('n'), type, x, y, params: values };
}

export function connect(from, fromPort, to, toPort) {
  return { id: uid('e'), from: { node: from.id, port: fromPort }, to: { node: to.id, port: toPort } };
}

export function nodeTitle(node) {
  return NODE_TYPES[node.type]?.title ?? node.type;
}

export function nodeSub(node) {
  const def = NODE_TYPES[node.type];
  if (!def) return '';
  try {
    return def.sub(node.params) || '';
  } catch {
    return '';
  }
}

export function nodeIcon(node) {
  return NODE_TYPES[node.type]?.icon ?? 'box';
}

export function nodeCat(node) {
  return NODE_TYPES[node.type]?.cat ?? 'action';
}

export function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

export function cloneNode(node, dx = 36, dy = 36) {
  const copy = createNode(node.type, node.x + dx, node.y + dy, clone(node.params));
  return copy;
}

/* ---------- пресеты ---------- */

function graph(nodes, edges = []) {
  return { nodes, edges };
}

export const PRESETS = [
  {
    id: 'quick',
    name: 'Быстрый аудит',
    build: () => {
      const trigger = createNode('trigger.manual', 80, 220);
      const repo = createNode('source.repo', 360, 220);
      const secret = createNode('scan.secret', 640, 120);
      const sca = createNode('scan.sca', 640, 300);
      const sast = createNode('scan.sast', 640, 480);
      const ai = createNode('ai.explain', 940, 300);
      const report = createNode('report.build', 1220, 300);
      const edges = [
        connect(trigger, 'out', repo, 'in'),
        connect(repo, 'out', secret, 'in'),
        connect(secret, 'out', sca, 'in'),
        connect(sca, 'out', sast, 'in'),
        connect(sast, 'out', ai, 'in'),
        connect(ai, 'out', report, 'in'),
        connect(sast, 'findings', ai, 'findings'),
      ];
      return graph([trigger, repo, secret, sca, sast, ai, report], edges);
    },
  },
  {
    id: 'secrets',
    name: 'Только секреты',
    build: () => {
      const trigger = createNode('trigger.schedule', 80, 240);
      const repo = createNode('source.repo', 380, 240);
      const secret = createNode('scan.secret', 680, 240);
      const notify = createNode('notify.send', 980, 240);
      const edges = [
        connect(trigger, 'out', repo, 'in'),
        connect(repo, 'out', secret, 'in'),
        connect(secret, 'out', notify, 'in'),
        connect(secret, 'findings', notify, 'payload'),
      ];
      return graph([trigger, repo, secret, notify], edges);
    },
  },
  {
    id: 'release',
    name: 'Перед релизом',
    build: () => {
      const trigger = createNode('trigger.manual', 80, 340);
      const repo = createNode('source.repo', 360, 340);
      const secret = createNode('scan.secret', 640, 180);
      const sca = createNode('scan.sca', 640, 360);
      const sast = createNode('scan.sast', 640, 540);
      const ai = createNode('ai.explain', 940, 360);
      const branch = createNode('logic.branch', 1220, 360);
      const notify = createNode('notify.send', 1500, 260);
      const report = createNode('report.build', 1500, 480);
      const edges = [
        connect(trigger, 'out', repo, 'in'),
        connect(repo, 'out', secret, 'in'),
        connect(secret, 'out', sca, 'in'),
        connect(sca, 'out', sast, 'in'),
        connect(sast, 'out', ai, 'in'),
        connect(ai, 'out', branch, 'in'),
        connect(branch, 'true', notify, 'in'),
        connect(branch, 'false', report, 'in'),
        connect(notify, 'out', report, 'in'),
        connect(sast, 'findings', ai, 'findings'),
        connect(ai, 'summary', notify, 'payload'),
      ];
      return graph([trigger, repo, secret, sca, sast, ai, branch, notify, report], edges);
    },
  },
];

export const EMPTY_WORKFLOW = { id: 'wf-' + Date.now().toString(36), name: 'Новый сценарий', nodes: [], edges: [] };
