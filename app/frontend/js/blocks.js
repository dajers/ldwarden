/**
 * Каталог узлов графа.
 * Узел = карточка с пинами (exec и data), параметрами и выходными данными.
 * Геометрия узла детерминирована, чтобы провода считались без измерения DOM.
 */

export const CATEGORIES = {
  trigger: { label: 'Запуск', color: 'var(--cat-trigger)', tint: 'var(--cat-trigger-tint)' },
  source: { label: 'Источник', color: 'var(--cat-source)', tint: 'var(--cat-source-tint)' },
  scan: { label: 'Проверки', color: 'var(--cat-scan)', tint: 'var(--cat-scan-tint)' },
  logic: { label: 'Логика', color: 'var(--cat-logic)', tint: 'var(--cat-logic-tint)' },
  action: { label: 'Действия', color: 'var(--cat-action)', tint: 'var(--cat-action-tint)' },
};

export const CATEGORY_ORDER = ['trigger', 'source', 'scan', 'logic', 'action'];

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
export const SEVERITY_RANK = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
export const SEVERITY_LABEL = { CRITICAL: 'Критично', HIGH: 'Высоко', MEDIUM: 'Средне', LOW: 'Низко' };
export const SEVERITY_COLOR = { CRITICAL: 'var(--crit)', HIGH: 'var(--bad)', MEDIUM: 'var(--warn)', LOW: 'var(--low)' };

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

const REGEX_FIELDS = {
  path: 'путь файла',
  class: 'класс уязвимости',
  message: 'сообщение правила',
  category: 'категория',
};

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
    params: [
      { key: 'secret', label: 'HMAC-секрет', type: 'secret', def: '', hint: 'Проверяется по заголовку X-LDWarden-Signature. Шифруется на сервере.' },
      { key: 'description', label: 'Описание', type: 'text', def: '' },
    ],
  },
  'trigger.schedule': {
    cat: 'trigger',
    icon: 'clock',
    title: 'По расписанию',
    sub: (p) => {
      if (p.mode === 'once') return `${p.runDate || 'дата не выбрана'} ${p.runTime || ''}`.trim();
      const days = { '*': 'каждый день', '1': 'пн', '2': 'вт', '3': 'ср', '4': 'чт', '5': 'пт', '6': 'сб', '7': 'вс' };
      const day = days[p.weekday] || 'день недели';
      return `${day} ${p.runTime || ''}`.trim();
    },
    inputs: [],
    outputs: [{ id: 'out', kind: 'exec', label: 'Сработало' }],
    params: [
      {
        key: 'mode',
        label: 'Режим',
        type: 'select',
        options: ['weekly', 'once'],
        labels: { weekly: 'Регулярно', once: 'Один раз' },
        def: 'weekly',
      },
      {
        key: 'runDate',
        label: 'Дата',
        type: 'date',
        def: '',
        dependsOn: { key: 'mode', value: 'once' },
        hint: 'Для однократного запуска.',
      },
      {
        key: 'runTime',
        label: 'Время',
        type: 'time',
        def: '09:00',
      },
      {
        key: 'weekday',
        label: 'День недели',
        type: 'select',
        options: ['*', '1', '2', '3', '4', '5', '6', '7'],
        labels: { '*': 'Каждый день', '1': 'Понедельник', '2': 'Вторник', '3': 'Среда', '4': 'Четверг', '5': 'Пятница', '6': 'Суббота', '7': 'Воскресенье' },
        def: '1',
        dependsOn: { key: 'mode', value: 'weekly' },
      },
      {
        key: 'timezone',
        label: 'Часовой пояс',
        type: 'select',
        options: ['Europe/Moscow', 'UTC', 'Europe/Berlin', 'Asia/Almaty', 'Asia/Yekaterinburg'],
        def: 'Europe/Moscow',
      },
      { key: 'cron', type: 'string', def: '', hidden: true },
    ],
  },
  'source.repo': {
    cat: 'source',
    icon: 'box',
    title: 'Репозиторий',
    sub: (p) => p.target,
    inputs: [{ id: 'in', kind: 'exec', label: 'Вход' }],
    outputs: [
      { id: 'out', kind: 'exec', label: 'Выход' },
      { id: 'files', kind: 'data', label: 'файлы' },
    ],
    params: [
      {
        key: 'target',
        label: 'Путь или ссылка',
        type: 'text',
        def: 'training-project',
        hint: 'Можно указать абсолютный путь к любой папке — просканируются все текстовые файлы внутри.',
      },
      { key: 'branch', label: 'Ветка', type: 'text', def: 'main' },
      { key: 'gitToken', label: 'Git-токен', type: 'secret', def: '', hint: 'Для приватного репозитория. Шифруется на сервере; в браузере не сохраняется.' },
      { key: 'gitUsername', label: 'Git-пользователь', type: 'text', def: 'x-access-token', hint: 'GitHub: x-access-token, GitLab: oauth2.' },
    ],
  },
  'scan.secret': {
    cat: 'scan',
    icon: 'key',
    title: 'Поиск секретов',
    sub: (p) => `SECRET · порог ${p.minSeverity}`,
    inputs: [{ id: 'in', kind: 'exec', label: 'Вход' }],
    outputs: [
      { id: 'out', kind: 'exec', label: 'Выход' },
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
      { id: 'out', kind: 'exec', label: 'Выход' },
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
      { id: 'out', kind: 'exec', label: 'Выход' },
      { id: 'findings', kind: 'data', label: 'находки' },
    ],
    params: [{ key: 'lang', label: 'Язык', type: 'select', options: ['Kotlin', 'Java'], def: 'Kotlin' }],
  },
  'logic.branch': {
    cat: 'logic',
    icon: 'branch',
    title: 'Условие',
    sub: (p) => `${p.field} ${p.operator} ${p.value}`,
    inputs: [{ id: 'in', kind: 'exec', label: 'Вход' }],
    outputs: [
      { id: 'true', kind: 'exec', label: 'Да' },
      { id: 'false', kind: 'exec', label: 'Нет' },
    ],
    params: [
      {
        key: 'field',
        label: 'Поле',
        type: 'text',
        def: 'findings.CRITICAL',
        hint: 'Например: findings.total, findings.CRITICAL, findings.by_category.SECRET, gate.passed, ai.overall_risk.',
      },
      {
        key: 'operator',
        label: 'Оператор',
        type: 'select',
        options: ['eq', 'ne', 'gt', 'gte', 'lt', 'lte', 'contains', 'regex', 'truthy', 'empty'],
        def: 'gte',
        labels: { eq: 'равно', ne: 'не равно', gt: 'больше', gte: 'больше или равно', lt: 'меньше', lte: 'меньше или равно', contains: 'содержит', regex: 'регулярное выражение', truthy: 'непустое/истина', empty: 'пустое' },
      },
      { key: 'value', label: 'Значение', type: 'text', def: '1', hint: 'Для regex — шаблон; для contains — подстрока; для truthy/empty можно оставить пустым.' },
      { key: 'caseSensitive', label: 'Учитывать регистр', type: 'toggle', def: false },
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
  'logic.custom': {
    cat: 'logic',
    icon: 'code',
    title: 'Своё условие',
    sub: (p) => String(p.expr || '').trim() || 'выражение',
    inputs: [{ id: 'in', kind: 'exec', label: 'Вход' }],
    outputs: [
      { id: 'true', kind: 'exec', label: 'Да' },
      { id: 'false', kind: 'exec', label: 'Нет' },
    ],
    params: [
      {
        key: 'expr',
        label: 'Условие',
        type: 'expression',
        def: 'critical >= 1',
        hint: 'total, critical, high, medium, low, secret, sca, sast, hasCritical, target · anyPath("regex") · and/or/not',
      },
    ],
  },
  'logic.regex': {
    cat: 'logic',
    icon: 'search',
    title: 'Регулярка',
    sub: (p) => `/${p.pattern || ''}/ по ${REGEX_FIELDS[p.field] || p.field}`,
    inputs: [{ id: 'in', kind: 'exec', label: 'Вход' }],
    outputs: [
      { id: 'true', kind: 'exec', label: 'Совпало' },
      { id: 'false', kind: 'exec', label: 'Не совпало' },
    ],
    params: [
      { key: 'field', label: 'Где искать', type: 'select', options: ['path', 'class', 'message', 'category'], def: 'path', labels: REGEX_FIELDS },
      { key: 'pattern', label: 'Регулярное выражение', type: 'text', def: '\\.kt$' },
      { key: 'negate', label: 'Инвертировать результат', type: 'toggle', def: false, hint: 'Совпадением будет считаться отсутствие match.' },
    ],
  },
  'logic.fork': {
    cat: 'logic',
    icon: 'fork',
    title: 'Разветвитель',
    sub: () => '1 вход · 3 ветки',
    inputs: [{ id: 'in', kind: 'exec', label: 'Вход' }],
    outputs: [
      { id: 'a', kind: 'exec', label: 'Ветка 1' },
      { id: 'b', kind: 'exec', label: 'Ветка 2' },
      { id: 'c', kind: 'exec', label: 'Ветка 3' },
    ],
    params: [],
  },
  'logic.join': {
    cat: 'logic',
    icon: 'join',
    title: 'Собиратель',
    sub: () => 'входы A/B · один выход',
    inputs: [
      { id: 'a', kind: 'exec', label: 'Вход A' },
      { id: 'b', kind: 'exec', label: 'Вход B' },
    ],
    outputs: [{ id: 'out', kind: 'exec', label: 'Дальше' }],
    params: [],
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
      { id: 'out', kind: 'exec', label: 'Выход' },
      { id: 'summary', kind: 'data', label: 'сводка' },
    ],
    params: [
      {
        key: 'provider',
        label: 'Провайдер',
        type: 'select',
        options: ['auto', 'local', 'openai', 'none'],
        def: 'auto',
        labels: { auto: 'auto (из настроек)', local: 'локальная GGUF', openai: 'OpenAI-совместимый', none: 'без LLM' },
      },
      {
        key: 'model',
        label: 'Модель',
        type: 'select',
        options: ['auto'],
        labels: { auto: 'auto (из .env)' },
        def: 'auto',
        dynamicOptions: 'models',
        hint: 'Список файлов .gguf из папки llms; auto — путь из LDWARDEN_LLM_MODEL_PATH.',
      },
      { key: 'tone', label: 'Тон объяснения', type: 'select', options: ['Для разработчика', 'Для менеджера'], def: 'Для разработчика' },
      { key: 'maxFindings', label: 'Находок в LLM', type: 'number', def: 2, hint: 'Остальные получат детерминированное объяснение.' },
      { key: 'threads', label: 'Потоков CPU', type: 'number', def: 4, hint: 'Для локальной модели: меньше — тише, но медленнее.' },
      { key: 'timeout', label: 'Таймаут, сек', type: 'number', def: 180, hint: 'После таймаута — fallback без зависания.' },
    ],
  },
  'notify.telegram': {
    cat: 'action',
    icon: 'send',
    title: 'Telegram',
    sub: (p) => p.chatId || 'чат не задан',
    inputs: [
      { id: 'in', kind: 'exec', label: 'Вход' },
      { id: 'payload', kind: 'data', label: 'данные' },
    ],
    outputs: [{ id: 'out', kind: 'exec', label: 'Отправлено' }],
    params: [
      { key: 'botToken', label: 'Токен бота', type: 'secret', def: '', hint: 'Получить у @BotFather; шифруется на сервере.' },
      { key: 'chatId', label: 'Chat ID', type: 'text', def: '', hint: 'Числовой ID, @username канала или пусто — возьмётся из подключения/.env.' },
      { key: 'subject', label: 'Заголовок', type: 'text', def: 'LDWarden: отчёт о проверке' },
      { key: 'attachReport', label: 'Приложить отчёт', type: 'toggle', def: true },
      { key: 'dryRun', label: 'Dry-run', type: 'toggle', def: false },
      { key: 'failOnError', label: 'Ошибка доставки валит run', type: 'toggle', def: false },
    ],
  },
  'notify.webhook': {
    cat: 'action',
    icon: 'send',
    title: 'HTTP webhook',
    sub: (p) => p.url || 'URL не задан',
    inputs: [
      { id: 'in', kind: 'exec', label: 'Вход' },
      { id: 'payload', kind: 'data', label: 'данные' },
    ],
    outputs: [{ id: 'out', kind: 'exec', label: 'Отправлено' }],
    params: [
      { key: 'url', label: 'URL', type: 'text', def: 'local://inbox', hint: 'http(s)://… или local://inbox для демо.' },
      { key: 'method', label: 'Метод', type: 'select', options: ['POST', 'PUT'], def: 'POST' },
      { key: 'hmacSecret', label: 'HMAC-секрет', type: 'secret', def: '', hint: 'Подпись X-LDWarden-Signature; шифруется.' },
      { key: 'subject', label: 'Заголовок', type: 'text', def: 'LDWarden: отчёт о проверке' },
      { key: 'attachReport', label: 'Приложить отчёт', type: 'toggle', def: true },
      { key: 'dryRun', label: 'Dry-run', type: 'toggle', def: false },
      { key: 'failOnError', label: 'Ошибка доставки валит run', type: 'toggle', def: false },
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
    outputs: [{ id: 'out', kind: 'exec', label: 'Выход' }],
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
      const notify = createNode('notify.webhook', 980, 240, { url: 'local://inbox' });
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
    id: 'config-secrets',
    name: 'Секреты в конфигах',
    build: () => {
      const trigger = createNode('trigger.manual', 80, 260);
      const repo = createNode('source.repo', 360, 260);
      const secret = createNode('scan.secret', 640, 260);
      const regex = createNode('logic.regex', 920, 260, { field: 'path', pattern: '\\.(ya?ml|properties|env|conf)$' });
      const notify = createNode('notify.webhook', 1200, 160, { url: 'local://inbox' });
      const report = createNode('report.build', 1200, 380);
      const edges = [
        connect(trigger, 'out', repo, 'in'),
        connect(repo, 'out', secret, 'in'),
        connect(secret, 'out', regex, 'in'),
        connect(regex, 'true', notify, 'in'),
        connect(regex, 'false', report, 'in'),
        connect(secret, 'findings', notify, 'payload'),
      ];
      return graph([trigger, repo, secret, regex, notify, report], edges);
    },
  },
  {
    id: 'authz-regex',
    name: 'Проверки авторизации',
    build: () => {
      const trigger = createNode('trigger.manual', 80, 260);
      const repo = createNode('source.repo', 360, 260);
      const sast = createNode('scan.sast', 640, 260);
      const regex = createNode('logic.regex', 920, 260, { field: 'class', pattern: 'route-authorization|object-authorization' });
      const notify = createNode('notify.webhook', 1200, 160, { url: 'local://inbox' });
      const report = createNode('report.build', 1200, 380);
      const edges = [
        connect(trigger, 'out', repo, 'in'),
        connect(repo, 'out', sast, 'in'),
        connect(sast, 'out', regex, 'in'),
        connect(regex, 'true', notify, 'in'),
        connect(regex, 'false', report, 'in'),
        connect(sast, 'findings', notify, 'payload'),
      ];
      return graph([trigger, repo, sast, regex, notify, report], edges);
    },
  },
  {
    id: 'cve-regex',
    name: 'Уязвимые зависимости по CVE',
    build: () => {
      const trigger = createNode('trigger.schedule', 80, 260);
      const repo = createNode('source.repo', 360, 260);
      const sca = createNode('scan.sca', 640, 260);
      const regex = createNode('logic.regex', 920, 260, { field: 'message', pattern: 'CVE-\\d{4}-\\d{4,}' });
      const notify = createNode('notify.webhook', 1200, 160, { url: 'local://inbox' });
      const report = createNode('report.build', 1200, 380);
      const edges = [
        connect(trigger, 'out', repo, 'in'),
        connect(repo, 'out', sca, 'in'),
        connect(sca, 'out', regex, 'in'),
        connect(regex, 'true', notify, 'in'),
        connect(regex, 'false', report, 'in'),
        connect(sca, 'findings', notify, 'payload'),
      ];
      return graph([trigger, repo, sca, regex, notify, report], edges);
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
      const notify = createNode('notify.webhook', 1500, 260, { url: 'local://inbox' });
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
