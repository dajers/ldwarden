/**
 * Мок-движок исполнения графа.
 * Идёт по exec-связям от триггеров, ветвится на logic.branch,
 * события повторяют будущий SSE-контракт бэкенда.
 */

import { FINDINGS } from './fixtures.js';
import { SEVERITY_RANK, SEVERITY_LABEL, NODE_TYPES } from './blocks.js';
import { evaluateExpression } from './expression.js';

const DELAY = {
  'logic.fork': 220,
  'logic.join': 220,
  'logic.regex': 260,
  'logic.custom': 240,
  'scan.secret': 780,
  'scan.sca': 860,
  'scan.sast': 940,
  'ai.explain': 1150,
  'notify.send': 560,
  'notify.telegram': 560,
  'notify.webhook': 560,
  'report.build': 380,
  'logic.branch': 260,
  default: 260,
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

class Cancelled extends Error {
  constructor() {
    super('cancelled');
    this.__cancel = true;
  }
}

const check = (token) => {
  if (token && token.cancelled) throw new Cancelled();
};

const findingKey = (f) => `${f.category}|${f.path}|${f.line}|${f.class}`;

export async function runGraph(workflow, { onEvent = () => {}, token = { cancelled: false } } = {}) {
  const startedAt = Date.now();
  const nodes = workflow.nodes || [];
  const edges = workflow.edges || [];
  const byId = new Map(nodes.map((n) => [n.id, n]));

  const ctx = { findings: [], ai: null, notified: null, report: null, outputs: {}, target: '' };
  const visited = new Set();
  const joinArrivals = new Map();

  onEvent({ type: 'run.started', total: nodes.length, at: startedAt });

  const execFrom = (nodeId, portId) => edges.filter((e) => e.from.node === nodeId && e.from.port === portId);
  const dataInto = (nodeId, portId) => edges.find((e) => e.to.node === nodeId && e.to.port === portId);

  const portKind = (node, portId, dir) => {
    const def = NODE_TYPES[node.type];
    const list = dir === 'out' ? def.outputs : def.inputs;
    return list.find((p) => p.id === portId)?.kind;
  };

  async function walk(node, viaEdge = null) {
    if (!node) return;

    // «Собиратель» ждёт все подключённые входы
    if (node.type === 'logic.join') {
      const incoming = edges.filter((edge) => edge.to.node === node.id);
      const arrived = joinArrivals.get(node.id) || new Set();
      if (viaEdge) arrived.add(viaEdge.id);
      joinArrivals.set(node.id, arrived);
      if (arrived.size < incoming.length) {
        onEvent({ type: 'node.pending', nodeId: node.id, chip: `ждём ${incoming.length - arrived.size}` });
        return;
      }
    }

    if (visited.has(node.id)) return;
    visited.add(node.id);

    onEvent({ type: 'node.started', nodeId: node.id });
    await sleep(DELAY[node.type] ?? DELAY.default);
    check(token);

    const { port, ports, chip, output, status } = await execute(node);

    onEvent({ type: 'node.done', nodeId: node.id, status: status || 'done', chip, output });

    const outPorts = Array.isArray(ports) ? ports : port ? [port] : [];
    for (const portId of outPorts) {
      for (const edge of execFrom(node.id, portId)) {
        onEvent({ type: 'edge.active', edgeId: edge.id });
        await sleep(110);
        check(token);
        await walk(byId.get(edge.to.node), edge);
      }
    }
  }

  async function execute(node) {
    switch (node.type) {
      case 'trigger.manual':
      case 'trigger.webhook':
        return { port: 'out', chip: node.type === 'trigger.webhook' ? 'webhook' : 'по кнопке', output: { fired: node.type === 'trigger.webhook' ? 'webhook' : 'manual' } };
      case 'trigger.schedule':
        return { port: 'out', chip: node.params.cron, output: { fired: 'schedule', cron: node.params.cron } };

      case 'source.repo': {
        const chip = `${String(node.params.target).split('/').pop() || 'проект'} · 132 файла`;
        const output = { target: node.params.target, files: 132 };
        ctx.target = node.params.target;
        ctx.outputs[node.id] = output;
        return { port: 'out', chip, output };
      }

      case 'scan.secret':
      case 'scan.sca':
      case 'scan.sast': {
        const category = { 'scan.secret': 'SECRET', 'scan.sca': 'SCA', 'scan.sast': 'SAST' }[node.type];
        let items = FINDINGS.filter((f) => f.category === category);
        if (node.type === 'scan.secret') {
          const min = SEVERITY_RANK[node.params.minSeverity] || 1;
          items = items.filter((f) => SEVERITY_RANK[f.severity] >= min);
        }
        const known = new Set(ctx.findings.map(findingKey));
        const fresh = items.filter((f) => !known.has(findingKey(f)));
        ctx.findings.push(...fresh);
        ctx.outputs[node.id] = items;
        onEvent({ type: 'findings', items: fresh });
        return { port: 'out', chip: `${items.length} ${plural(items.length, 'находка', 'находки', 'находок')}`, output: { count: items.length } };
      }

      case 'logic.branch': {
        const hit = evaluate(node.params, ctx.findings);
        return { port: hit ? 'true' : 'false', chip: hit ? 'да' : 'нет', output: { decision: hit } };
      }

      case 'logic.custom': {
        const result = evaluateExpression(node.params.expr, ctx.findings, ctx.target || '');
        if (!result.ok) {
          return { ports: [], chip: 'ошибка условия', status: 'error', output: { error: result.error } };
        }
        return { ports: [result.value ? 'true' : 'false'], chip: result.value ? 'да' : 'нет', output: { value: result.value } };
      }

      case 'logic.regex': {
        const fields = {
          path: (f) => f.path || '',
          class: (f) => f.class || '',
          message: (f) => f.message || f.description || '',
          category: (f) => f.category || '',
        };
        const getter = fields[node.params.field] || fields.path;
        let expression;
        try {
          expression = new RegExp(node.params.pattern || '');
        } catch (error) {
          return { ports: [], chip: 'ошибка regex', status: 'error', output: { error: error.message } };
        }
        const matched = ctx.findings.some((finding) => expression.test(getter(finding)));
        const value = node.params.negate ? !matched : matched;
        return { ports: [value ? 'true' : 'false'], chip: value ? 'совпало' : 'нет', output: { matched, value } };
      }

      case 'logic.fork':
        return { ports: ['a', 'b', 'c'], chip: '3 ветки', output: { branches: ['a', 'b', 'c'] } };

      case 'logic.join':
        return { ports: ['out'], chip: 'объединено', output: { merged: true } };

      case 'ai.explain': {
        const linked = dataInto(node.id, 'findings');
        const source = linked ? ctx.outputs[linked.from.node] : null;
        const scope = Array.isArray(source) ? source : ctx.findings;

        if (!scope.length) {
          ctx.ai = { summary: 'Находок нет — объяснять нечего.', model: node.params.model, items: [] };
          ctx.outputs[node.id] = [];
          return { port: 'out', chip: 'нечего объяснять', output: { items: 0 } };
        }

        ctx.ai = {
          summary: buildSummary(scope),
          model: node.params.model,
          items: scope.map((f) => ({ id: f.id, title: f.title, why: f.why })),
        };
        ctx.outputs[node.id] = ctx.ai;
        return { port: 'out', chip: `${scope.length} объяснений`, output: { items: scope.length } };
      }

      case 'control.gate': {
        const rank = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
        const limit = rank[node.params.threshold] || 3;
        const hit = ctx.findings.some((f) => (rank[f.severity] || 0) >= limit);
        return { port: hit ? 'fail' : 'pass', chip: hit ? 'превышен' : 'пройден', output: { passed: !hit } };
      }

      case 'notify.webhook':
      case 'notify.send': {
        const linked = dataInto(node.id, 'payload');
        const payload = linked ? ctx.outputs[linked.from.node] : null;
        const size = Array.isArray(payload) ? payload.length : ctx.findings.length;
        const dry = Boolean(node.params.dryRun);
        const channel =
          node.type === 'notify.telegram'
            ? 'telegram'
            : node.type === 'notify.webhook'
              ? 'webhook'
              : node.params.channel;
        ctx.notified = { channel, findings: size, at: Date.now(), dryRun: dry };
        return { port: 'out', chip: `${channel}${dry ? ' · dry-run' : ''} · ${size}`, output: { channel, size, dryRun: dry } };
      }

      case 'report.build': {
        const linked = dataInto(node.id, 'findings');
        const source = linked ? ctx.outputs[linked.from.node] : null;
        const scope = Array.isArray(source) ? source : ctx.findings;
        ctx.report = buildReport(scope, node.params.formats);
        ctx.outputs[node.id] = scope;
        return { port: 'out', chip: node.params.formats, output: { findings: scope.length } };
      }

      default:
        return { port: 'out', chip: 'выполнено', output: null };
    }
  }

  const triggers = nodes.filter((n) => n.type.startsWith('trigger.'));
  try {
    for (const trigger of triggers) await walk(trigger);
  } catch (error) {
    if (error && error.__cancel) {
      const result = snapshot(ctx, startedAt, true);
      onEvent({ type: 'run.cancelled', result });
      return result;
    }
    onEvent({ type: 'run.error', message: String(error && error.message ? error.message : error) });
    throw error;
  }

  for (const node of nodes) {
    if (!visited.has(node.id)) {
      onEvent({ type: 'node.done', nodeId: node.id, status: 'skipped', chip: 'не выполнялся' });
    }
  }

  const result = snapshot(ctx, startedAt, false);
  onEvent({ type: 'run.done', result });
  return result;
}

function snapshot(ctx, startedAt, cancelled) {
  return {
    cancelled,
    findings: ctx.findings,
    ai: ctx.ai,
    notified: ctx.notified,
    report: ctx.report,
    duration: Date.now() - startedAt,
    summary: summarize(ctx.findings),
  };
}

function evaluate(params, findings) {
  const total = findings.length;
  const critical = findings.filter((f) => f.severity === 'CRITICAL').length;
  const secret = findings.filter((f) => f.category === 'SECRET').length;
  const fields = {
    total,
    critical,
    secret,
    'findings.total': total,
    'findings.CRITICAL': critical,
    'findings.by_category.SECRET': secret,
  };
  const actual = params.field in fields ? fields[params.field] : total;
  const expected = params.value;
  const operator = params.operator || params.op || 'gte';
  const left = Number(actual);
  const right = Number(expected);
  const numeric = Number.isFinite(left) && Number.isFinite(right);
  switch (operator) {
    case 'eq':
      return String(actual) === String(expected);
    case 'ne':
      return String(actual) !== String(expected);
    case 'gt':
      return numeric && left > right;
    case 'gte':
      return numeric && left >= right;
    case 'lt':
      return numeric && left < right;
    case 'lte':
      return numeric && left <= right;
    case 'contains':
      return String(actual).toLowerCase().includes(String(expected).toLowerCase());
    case 'regex':
      try {
        return new RegExp(String(expected), params.caseSensitive ? '' : 'i').test(String(actual));
      } catch {
        return false;
      }
    case 'truthy':
      return Boolean(actual);
    case 'empty':
      return !actual;
    default:
      return false;
  }
}

/* ---------- сводки и отчёты ---------- */

export function summarize(findings) {
  const by = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const byCategory = { SECRET: 0, SCA: 0, SAST: 0 };
  for (const f of findings) {
    by[f.severity] = (by[f.severity] || 0) + 1;
    byCategory[f.category] = (byCategory[f.category] || 0) + 1;
  }
  return { total: findings.length, by, byCategory };
}

function buildSummary(findings) {
  const { by, total } = summarize(findings);
  const parts = [];
  if (by.CRITICAL) parts.push(`${by.CRITICAL} критичных`);
  if (by.HIGH) parts.push(`${by.HIGH} высоких`);
  if (by.MEDIUM) parts.push(`${by.MEDIUM} средних`);
  if (by.LOW) parts.push(`${by.LOW} низких`);

  const top = [...findings]
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])
    .slice(0, 3)
    .map((f) => f.title);

  return (
    `Найдено ${total} ${plural(total, 'находка', 'находки', 'находок')}: ${parts.join(', ')}. ` +
    `В первую очередь закройте: ${top.join('; ')}.`
  );
}

export function toOutputJson(findings) {
  return {
    findings: findings.map((f) => {
      if (f.category === 'SCA') {
        return {
          category: 'SCA',
          path: f.path,
          group: f.group,
          artifact: f.artifact,
          version: f.version,
          advisoryId: f.advisoryId,
          severity: f.severity,
          description: f.description,
          remediation: f.remediation,
        };
      }
      const out = { category: f.category, path: f.path, class: f.class, line: f.line };
      if (f.endLine) out.endLine = f.endLine;
      out.severity = f.severity;
      out.description = f.description;
      out.remediation = f.remediation;
      return out;
    }),
  };
}

export function toHtml(findings, meta = {}) {
  const { by, byCategory, total } = summarize(findings);
  const esc = (value) =>
    String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  const date = new Date().toLocaleString('ru-RU', { dateStyle: 'long', timeStyle: 'short' });
  const cards = findings
    .map((f) => {
      const location = f.endLine ? `${f.path}:${f.line}–${f.endLine}` : `${f.path}:${f.line}`;
      const why = f.why ? `<h4>Почему это важно</h4><p>${esc(f.why)}</p>` : '';
      const fix = f.remediation ? `<h4>Как исправить</h4><p>${esc(f.remediation)}</p>` : '';
      const evidence = f.snippet ? `<pre>${esc(f.snippet)}</pre>` : '';
      return `<article class="finding sev-${esc(f.severity).toLowerCase()}">
        <div class="top"><span class="chip">${esc(f.category)}</span><span class="chip">${esc(f.class)}</span><b>${esc(SEVERITY_LABEL[f.severity] || f.severity)}</b></div>
        <h3>${esc(f.title)}</h3><div class="path">${esc(location)}</div>
        <p>${esc(f.description)}</p>${evidence}${why}${fix}
      </article>`;
    })
    .join('');
  const cats = Object.entries(byCategory)
    .filter(([, value]) => value)
    .map(([name, value]) => `${esc(name)} — ${value}`)
    .join(', ');
  return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>LDWarden — отчёт</title>
<style>
body{margin:0;padding:32px 20px;background:#faf4f6;color:#221a1d;font:14px/1.55 -apple-system,"Segoe UI",Roboto,Arial,sans-serif}
.wrap{max-width:960px;margin:0 auto}h1{font-size:24px;margin:6px 0 18px}h2{font-size:16px;margin:26px 0 12px}h3{font-size:14px;margin:0 0 4px}
h4{font-size:12px;margin:14px 0 4px;color:#7a6a70;text-transform:uppercase;letter-spacing:.04em}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:14px 0}
.stat{background:#fff;border:1px solid #ecd9df;border-radius:12px;padding:10px 12px}
.stat b{display:block;font-size:22px}.stat span{font-size:11px;color:#7a6a70}
.finding{background:#fff;border:1px solid #ecd9df;border-radius:12px;padding:14px 16px;margin-bottom:12px;break-inside:avoid}
.finding.sev-critical{border-left:4px solid #b91c1c}.finding.sev-high{border-left:4px solid #dc2626}
.finding.sev-medium{border-left:4px solid #d97706}.finding.sev-low{border-left:4px solid #2563eb}
.top{display:flex;gap:8px;align-items:center;margin-bottom:6px}.top b{font-size:11px}
.chip{font-size:10px;text-transform:uppercase;letter-spacing:.05em;padding:2px 8px;border-radius:999px;background:#faf4f6;border:1px solid #ecd9df;color:#7a6a70}
.path{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px;color:#7a6a70}
pre{margin:8px 0 0;padding:10px 12px;background:#fbf7f8;border:1px solid #ecd9df;border-radius:8px;overflow-x:auto;font-size:11.5px}
.cats{color:#7a6a70;font-size:12px}footer{margin-top:28px;color:#7a6a70;font-size:11px;text-align:center}
@media print{body{background:#fff;padding:0}.wrap{max-width:none}}
</style></head><body><div class="wrap">
<div><b style="font-size:20px">LDWarden</b> <span style="color:#7a6a70;font-size:12px">конструктор проверок безопасности</span></div>
<h1>Отчёт о проверке безопасности</h1>
<p class="cats">Источник: ${esc(meta.target || '—')} · ${esc(date)}</p>
<div class="stats"><div class="stat"><b>${total}</b><span>Всего</span></div>
<div class="stat"><b>${by.CRITICAL || 0}</b><span>Критическая</span></div>
<div class="stat"><b>${by.HIGH || 0}</b><span>Высокая</span></div>
<div class="stat"><b>${by.MEDIUM || 0}</b><span>Средняя</span></div>
<div class="stat"><b>${by.LOW || 0}</b><span>Низкая</span></div></div>
<p class="cats">Категории: ${cats || '—'}</p>
<h2>Находки</h2>${cards || '<p class="cats">Находок нет — проверка чистая.</p>'}
<footer>Сформировано LDWarden · ${esc(date)}</footer></div></body></html>`;
}

export function toMarkdown(findings, meta = {}) {
  const { by, byCategory, total } = summarize(findings);
  const date = new Date().toLocaleString('ru-RU', { dateStyle: 'long', timeStyle: 'short' });
  const lines = [];

  lines.push('# Отчёт о проверке безопасности', '');
  lines.push(`**Проект:** ${meta.target || 'training-project'}  `);
  lines.push(`**Дата:** ${date}  `);
  lines.push(`**Найдено:** ${total} — SECRET ${byCategory.SECRET}, SCA ${byCategory.SCA}, SAST ${byCategory.SAST}`, '');

  lines.push('## Сводка', '', '| Критичность | Количество |', '| --- | --- |');
  for (const s of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) lines.push(`| ${SEVERITY_LABEL[s]} | ${by[s]} |`);
  lines.push('');

  lines.push('## Находки', '');
  findings.forEach((f, i) => {
    const loc = f.endLine ? `${f.path}:${f.line}–${f.endLine}` : `${f.path}:${f.line}`;
    lines.push(`### ${i + 1}. ${f.title}`, '');
    lines.push(`\`${f.category}\` · \`${f.severity}\` · \`${loc}\``, '');
    if (f.category === 'SCA') lines.push(`Зависимость: \`${f.group}:${f.artifact}:${f.version}\` · advisory \`${f.advisoryId}\``, '');
    lines.push(f.description, '');
    if (f.why) lines.push(`**Почему это важно.** ${f.why}`, '');
    lines.push(`**Как исправить.** ${f.remediation}`, '');
    if (f.snippet) lines.push('```', ...f.snippet.split('\n'), '```', '');
  });

  lines.push('## Ограничения проверки', '');
  lines.push(
    '- Анализ статический: уязвимость подтверждена по коду, но не эксплуатировалась.',
    '- Секреты в отчёте замаскированы; исходные значения не выгружаются.',
    '- SCA проверяет только явно объявленные зависимости из `build.gradle.kts` и `gradle.properties`.',
    '',
  );

  return lines.join('\n');
}

function buildReport(findings, formats) {
  return {
    formats,
    json: JSON.stringify(toOutputJson(findings), null, 2),
    markdown: toMarkdown(findings),
  };
}

function plural(n, one, few, many) {
  const mod10 = n % 10;
  const mod100 = n % 100;
  if (mod10 === 1 && mod100 !== 11) return one;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return few;
  return many;
}

export { plural };
