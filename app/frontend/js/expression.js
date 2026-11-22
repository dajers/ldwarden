




















const OPERATORS = ['==', '!=', '>=', '<=', '&&', '||'];

function tokenize(source) {
  const tokens = [];
  let i = 0;

  while (i < source.length) {
    const char = source[i];

    if (/\s/.test(char)) {
      i += 1;
      continue;
    }

    if (/[0-9]/.test(char)) {
      let j = i;
      while (j < source.length && /[0-9.]/.test(source[j])) j += 1;
      tokens.push({ type: 'num', value: Number(source.slice(i, j)) });
      i = j;
      continue;
    }

    if (char === '"' || char === "'") {
      const quote = char;
      let j = i + 1;
      let value = '';
      while (j < source.length && source[j] !== quote) {
        if (source[j] === '\\' && j + 1 < source.length) {
          value += source[j + 1];
          j += 2;
        } else {
          value += source[j];
          j += 1;
        }
      }
      if (j >= source.length) throw new Error('незакрытая строка');
      tokens.push({ type: 'str', value });
      i = j + 1;
      continue;
    }

    const pair = source.slice(i, i + 2);
    if (OPERATORS.includes(pair)) {
      tokens.push({ type: 'op', value: pair });
      i += 2;
      continue;
    }

    if (char === '>' || char === '<') {
      tokens.push({ type: 'op', value: char });
      i += 1;
      continue;
    }

    if ('()!,'.includes(char)) {
      tokens.push({ type: char === '(' ? 'lp' : char === ')' ? 'rp' : char === ',' ? 'comma' : 'op', value: char });
      i += 1;
      continue;
    }

    if (/[A-Za-z_]/.test(char)) {
      let j = i;
      while (j < source.length && /[A-Za-z0-9_]/.test(source[j])) j += 1;
      const word = source.slice(i, j);
      const lower = word.toLowerCase();
      if (lower === 'and') tokens.push({ type: 'op', value: '&&' });
      else if (lower === 'or') tokens.push({ type: 'op', value: '||' });
      else if (lower === 'not') tokens.push({ type: 'op', value: '!' });
      else if (lower === 'true') tokens.push({ type: 'bool', value: true });
      else if (lower === 'false') tokens.push({ type: 'bool', value: false });
      else tokens.push({ type: 'id', value: word });
      i = j;
      continue;
    }

    throw new Error(`неизвестный символ «${char}»`);
  }

  return tokens;
}

function parse(tokens) {
  let pos = 0;
  const peek = () => tokens[pos];
  const next = () => tokens[pos++];

  function parseOr() {
    let left = parseAnd();
    while (peek() && peek().type === 'op' && peek().value === '||') {
      next();
      left = { kind: 'or', left, right: parseAnd() };
    }
    return left;
  }

  function parseAnd() {
    let left = parseUnary();
    while (peek() && peek().type === 'op' && peek().value === '&&') {
      next();
      left = { kind: 'and', left, right: parseUnary() };
    }
    return left;
  }

  function parseUnary() {
    if (peek() && peek().type === 'op' && peek().value === '!') {
      next();
      return { kind: 'not', value: parseUnary() };
    }
    return parseComparison();
  }

  function parseComparison() {
    const left = parsePrimary();
    const token = peek();
    if (token && token.type === 'op' && ['==', '!=', '>', '>=', '<', '<='].includes(token.value)) {
      next();
      return { kind: 'cmp', op: token.value, left, right: parsePrimary() };
    }
    return left;
  }

  function parsePrimary() {
    const token = next();
    if (!token) throw new Error('выражение обрывается');

    if (token.type === 'num') return { kind: 'num', value: token.value };
    if (token.type === 'str') return { kind: 'str', value: token.value };
    if (token.type === 'bool') return { kind: 'bool', value: token.value };

    if (token.type === 'lp') {
      const inner = parseOr();
      const close = next();
      if (!close || close.type !== 'rp') throw new Error('не хватает «)»');
      return inner;
    }

    if (token.type === 'id') {
      if (peek() && peek().type === 'lp') {
        next();
        const args = [];
        if (peek() && peek().type !== 'rp') {
          args.push(parseOr());
          while (peek() && peek().type === 'comma') {
            next();
            args.push(parseOr());
          }
        }
        const close = next();
        if (!close || close.type !== 'rp') throw new Error('не хватает «)»');
        return { kind: 'call', name: token.value, args };
      }
      return { kind: 'var', name: token.value };
    }

    throw new Error(`неожиданный элемент «${token.value}»`);
  }

  const ast = parseOr();
  if (pos < tokens.length) throw new Error('лишние символы в конце выражения');
  return ast;
}

const truthy = (value) => (typeof value === 'number' ? value !== 0 : Boolean(value));

const toNumber = (value) => {
  if (typeof value === 'number') return value;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : NaN;
};

function compare(op, left, right) {
  if (typeof left === 'number' || typeof right === 'number') {
    const a = toNumber(left);
    const b = toNumber(right);
    if (Number.isNaN(a) || Number.isNaN(b)) return op === '!=' ? true : false;
    switch (op) {
      case '==': return a === b;
      case '!=': return a !== b;
      case '>': return a > b;
      case '>=': return a >= b;
      case '<': return a < b;
      case '<=': return a <= b;
      default: return false;
    }
  }

  const a = String(left);
  const b = String(right);
  switch (op) {
    case '==': return a === b;
    case '!=': return a !== b;
    case '>': return a > b;
    case '>=': return a >= b;
    case '<': return a < b;
    case '<=': return a <= b;
    default: return false;
  }
}

function buildContext(findings, target) {
  const count = (severity) => findings.filter((f) => f.severity === severity).length;
  const category = (name) => findings.filter((f) => f.category === name).length;
  return {
    findings,
    target: target ? String(target) : '',
    total: findings.length,
    critical: count('CRITICAL'),
    high: count('HIGH'),
    medium: count('MEDIUM'),
    low: count('LOW'),
    secret: category('SECRET'),
    sca: category('SCA'),
    sast: category('SAST'),
    hasCritical: count('CRITICAL') > 0,
    hasSecrets: category('SECRET') > 0,
  };
}

function callFunction(name, args, context) {
  const findings = context.findings || [];
  const pattern = (value) => new RegExp(String(value));

  switch (name) {
    case 'count':
      return findings.length;
    case 'contains':
      return String(args[0] ?? '').includes(String(args[1] ?? ''));
    case 'matches':
      return pattern(args[1]).test(String(args[0] ?? ''));
    case 'anyPath':
      return findings.some((f) => pattern(args[0]).test(String(f.path || '')));
    case 'anyClass':
      return findings.some((f) => pattern(args[0]).test(String(f.class || '')));
    case 'anyMessage':
      return findings.some((f) => pattern(args[0]).test(String(f.message || f.description || '')));
    default:
      throw new Error(`неизвестная функция «${name}»`);
  }
}

function evaluateNode(node, context) {
  switch (node.kind) {
    case 'num':
    case 'str':
    case 'bool':
      return node.value;
    case 'var':
      if (!(node.name in context)) throw new Error(`неизвестная переменная «${node.name}»`);
      return context[node.name];
    case 'not':
      return !truthy(evaluateNode(node.value, context));
    case 'and':
      return truthy(evaluateNode(node.left, context)) && truthy(evaluateNode(node.right, context));
    case 'or':
      return truthy(evaluateNode(node.left, context)) || truthy(evaluateNode(node.right, context));
    case 'cmp':
      return compare(node.op, evaluateNode(node.left, context), evaluateNode(node.right, context));
    case 'call':
      return callFunction(node.name, node.args.map((arg) => evaluateNode(arg, context)), context);
    default:
      return false;
  }
}


export function evaluateExpression(sourceText, findings = [], target = '') {
  const source = String(sourceText || '').trim();
  if (!source) return { ok: false, error: 'условие пустое' };

  try {
    const ast = parse(tokenize(source));
    return { ok: true, value: truthy(evaluateNode(ast, buildContext(findings, target))) };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}


export default evaluateExpression;
