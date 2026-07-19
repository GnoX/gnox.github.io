// Annotation model, expression evaluation and export generation
// (annotations JSON + Python matching ha-ef-ble eflib conventions).
'use strict';

// Suggestions for the unit input - any free-text value is also accepted
const UNITS = [
  { value: 'W', label: 'power' },
  { value: 'kW', label: 'power' },
  { value: 'V', label: 'voltage' },
  { value: 'mV', label: 'voltage (cell)' },
  { value: 'A', label: 'current' },
  { value: 'mA', label: 'current' },
  { value: 'Ah', label: 'capacity' },
  { value: 'mAh', label: 'capacity (BMS)' },
  { value: '%', label: 'battery/level' },
  { value: 'C', label: 'temp °C' },
  { value: 'F', label: 'temp °F' },
  { value: 'K', label: 'temp Kelvin' },
  { value: 'Wh', label: 'energy' },
  { value: 'kWh', label: 'energy' },
  { value: 'Hz', label: 'frequency' },
  { value: 's', label: 'duration' },
  { value: 'min', label: 'duration' },
  { value: 'h', label: 'duration' },
  { value: 'ms', label: 'duration' },
  { value: 'mΩ', label: 'resistance (BMS)' },
  { value: 'dBm', label: 'signal' },
  { value: 'cycles', label: 'battery cycles' },
  { value: 'bool', label: 'on/off' },
  { value: 'bitfield', label: 'bitmask' },
  { value: 'enum', label: 'enum' },
];

// Interpretation choices for schema-less protobuf fields
const INTERPRETATIONS = ['auto', 'uint', 'sint', 'int', 'float', 'double', 'text', 'hex'];

function defaultAnnotation() {
  return {
    name: '',          // python field name (snake_case)
    unit: '',
    interp: 'auto',    // schema-less wire interpretation
    divisor: 1,
    multiplier: 1,
    precision: 2,
    negate: false,
    bit: null,         // bit index for prop_has_bit_on
    transform: '',     // custom transform over `x`, e.g. "x / 10 - 273.15"
    expr: '',          // combined-field expression, e.g. "ac_in + dc_in"
    enumMap: {},       // raw value -> NAME for enum fields
    translation: '',   // display name for translations/en.json
    notes: '',
  };
}

function applyAnnotation(value, ann) {
  if (value == null || typeof value === 'string') return value;
  if (ann.enumMap && ann.enumMap[value] !== undefined) {
    return String(ann.enumMap[value]).toLowerCase();
  }
  let v = value;
  if (ann.transform) {
    // custom transform replaces the ÷/×/neg/bit pipeline (it can express them)
    try {
      v = evalExpr(ann.transform, name => name === 'x' ? value : null);
    } catch {
      return value;
    }
    if (v == null) return value;
  } else {
    if (ann.bit != null && ann.bit !== '') return (v >> ann.bit) & 1 ? 1 : 0;
    if (ann.divisor && ann.divisor !== 1) v = v / ann.divisor;
    if (ann.multiplier && ann.multiplier !== 1) v = v * ann.multiplier;
    if (ann.negate) v = v === 0 ? 0 : -v;
  }
  if (ann.precision != null && ann.precision !== '') {
    const p = Math.pow(10, ann.precision);
    v = Math.round(v * p) / p;
  }
  return v;
}

// ---------------------------------------------------------------------------
// Tiny safe expression evaluator: numbers, identifiers, + - * / ( )
// Identifiers resolve via lookup(name) -> number|null.
// ---------------------------------------------------------------------------

function tokenizeExpr(src) {
  const tokens = [];
  const re = /\s*(0[xX][0-9a-fA-F]+|[A-Za-z_][A-Za-z0-9_.\[\]]*|\d+\.?\d*|<<|>>|[()+\-*/%&|^~,])/y;
  let pos = 0;
  while (pos < src.length) {
    re.lastIndex = pos;
    const m = re.exec(src);
    if (!m) throw new Error(`bad token at ${pos}`);
    tokens.push(m[1]);
    pos = re.lastIndex;
  }
  return tokens;
}

// Insert explicit '*' where math notation implies it: 2x, 2(…), (a)(b),
// x(…) for non-function identifiers, x 2. Function calls stay calls.
function withImplicitMul(tokens) {
  const isNum = t => /^(\d|0[xX])/.test(t);
  const isIdent = t => /^[A-Za-z_]/.test(t);
  const out = [];
  for (const t of tokens) {
    const prev = out[out.length - 1];
    if (prev !== undefined) {
      const prevNum = isNum(prev);
      const prevClose = prev === ')';
      const prevVar = isIdent(prev) && !(prev in EXPR_FUNCS);
      const need =
        (prevNum && (isIdent(t) || t === '(')) ||
        (prevClose && (isNum(t) || isIdent(t) || t === '(')) ||
        (prevVar && (t === '(' || isNum(t)));
      if (need) out.push('*');
    }
    out.push(t);
  }
  return out;
}

function normalizeExpr(src) {
  try {
    return withImplicitMul(tokenizeExpr(src)).join(' ');
  } catch {
    return src;
  }
}

// Precedence (low to high) matches Python, so expressions export verbatim:
// | < ^ < & < shifts < add < mul < unary
function evalExpr(src, lookup) {
  const tokens = withImplicitMul(tokenizeExpr(src));
  let i = 0;
  const binary = (ops, next) => () => {
    let left = next();
    while (ops.includes(tokens[i])) {
      const op = tokens[i++];
      const right = next();
      if (left == null || right == null) return null;
      switch (op) {
        case '|': left |= right; break;
        case '^': left ^= right; break;
        case '&': left &= right; break;
        case '<<': left <<= right; break;
        case '>>': left >>= right; break;
        case '+': left += right; break;
        case '-': left -= right; break;
        case '*': left *= right; break;
        case '/': left /= right; break;
        case '%': left %= right; break;
      }
    }
    return left;
  };
  function parseFactor() {
    const t = tokens[i++];
    if (t === undefined) throw new Error('unexpected end of expression');
    if (t === '(') {
      const v = parseBitOr();
      if (tokens[i++] !== ')') throw new Error('missing )');
      return v;
    }
    if (t === '-') { const v = parseFactor(); return v == null ? null : -v; }
    if (t === '~') { const v = parseFactor(); return v == null ? null : ~v; }
    if (/^0[xX]/.test(t)) return parseInt(t, 16);
    if (/^\d/.test(t)) return parseFloat(t);
    if (t in EXPR_FUNCS) {
      if (tokens[i++] !== '(') throw new Error(`${t} needs parentheses`);
      const args = [parseBitOr()];
      while (tokens[i] === ',') { i++; args.push(parseBitOr()); }
      if (tokens[i++] !== ')') throw new Error('missing )');
      if (args.some(a => a == null)) return null;
      return applyExprFunc(t, args);
    }
    if (/^[A-Za-z_]/.test(t)) return lookup(t);
    throw new Error(`unexpected token '${t}'`);
  }
  const parseMul = binary(['*', '/', '%'], parseFactor);
  const parseAdd = binary(['+', '-'], parseMul);
  const parseShift = binary(['<<', '>>'], parseAdd);
  const parseBitAnd = binary(['&'], parseShift);
  const parseBitXor = binary(['^'], parseBitAnd);
  const parseBitOr = binary(['|'], parseBitXor);

  const result = parseBitOr();
  if (i !== tokens.length) throw new Error(`unexpected trailing '${tokens[i]}'`);
  return result;
}

const EXPR_FUNCS = {
  exp: Math.exp, log: Math.log, log2: Math.log2, log10: Math.log10,
  sqrt: Math.sqrt, abs: Math.abs,
  round: Math.round, ceil: Math.ceil, floor: Math.floor,
};

// round/ceil/floor take an optional second arg: decimal places
const ROUNDING_FUNCS = { round: Math.round, ceil: Math.ceil, floor: Math.floor };

function applyExprFunc(name, args) {
  if (name in ROUNDING_FUNCS) {
    const n = args.length > 1 ? Math.trunc(args[1]) : 0;
    const f = 10 ** n;
    return ROUNDING_FUNCS[name](args[0] * f) / f;
  }
  return EXPR_FUNCS[name](args[0]);
}

function exprIdentifiers(src) {
  try {
    return tokenizeExpr(src)
      .filter(t => /^[A-Za-z_]/.test(t) && !(t in EXPR_FUNCS));
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Python code generation
// ---------------------------------------------------------------------------

const DEFAULT_PRECISION = 2;

function pyTransform(ann, { isFloat = false } = {}) {
  // Returns the transform argument string for pb_field/raw_field, or ''.
  // The default display precision (2) reaches the export only for float
  // fields or when combined with another transform; integer fields stay
  // bare unless the user picks a non-default precision.
  const hasDiv = ann.divisor && Number(ann.divisor) !== 1;
  const hasMul = ann.multiplier && Number(ann.multiplier) !== 1;
  const hasPrec = ann.precision != null && ann.precision !== '' &&
    (hasDiv || hasMul || ann.negate || isFloat ||
      Number(ann.precision) !== DEFAULT_PRECISION);
  if (ann.bit != null && ann.bit !== '') return `prop_has_bit_on(${ann.bit})`;
  // out_power carries power semantics (negate + round 2, 0 stays 0) - only
  // reached for plain negation on W fields; everything else negates through
  // a synthesized helper (see negationTransform)
  if (ann.negate) return 'out_power';
  if (hasDiv) return `pdiv(${ann.divisor}${hasPrec ? `, ${ann.precision}` : ''})`;
  if (hasMul) return `pmultiply(${ann.multiplier})`;
  if (hasPrec) return `pround(${ann.precision})`;
  return '';
}

function sanitizePyName(name) {
  const n = name.trim().replace(/[^A-Za-z0-9_]/g, '_').replace(/^(\d)/, '_$1');
  return n || 'field';
}

function noteComment(notes) {
  return String(notes).split('\n').filter(Boolean).map(l => `# note: ${l}`);
}

function unitComment(ann) {
  return ann.unit ? `  # ${ann.unit}` : '';
}

function hasEnum(ann) {
  return ann.enumMap && Object.keys(ann.enumMap).length > 0;
}

function enumMemberName(name) {
  const n = String(name).trim().toUpperCase().replace(/[^A-Z0-9_]/g, '_')
    .replace(/^(\d)/, '_$1');
  return n || 'VALUE';
}

function enumClassName(fieldName) {
  return sanitizePyName(fieldName).split('_').filter(Boolean)
    .map(w => w[0].toUpperCase() + w.slice(1)).join('') || 'FieldEnum';
}

function enumClassDef(ann) {
  const cls = enumClassName(ann.name);
  const entries = Object.entries(ann.enumMap)
    .map(([v, n]) => [Number(v), enumMemberName(n)])
    .sort((a, b) => a[0] - b[0]);
  const code = [
    `class ${cls}(IntFieldValue):`,
    '    UNKNOWN = -1',
    '',
    ...entries.map(([v, n]) => `    ${n} = ${v}`),
  ].join('\n');
  return { cls, code };
}

// Compile an expression to Python using the same grammar as evalExpr, so
// nested calls and precision args (round/ceil/floor with 2 args) translate
// correctly instead of via fragile regex substitution.
function exprToPython(src, mapIdent) {
  const tokens = withImplicitMul(tokenizeExpr(src));
  let i = 0;
  const binary = (ops, next) => () => {
    let left = next();
    while (ops.includes(tokens[i])) { const op = tokens[i++]; left = `${left} ${op} ${next()}`; }
    return left;
  };
  const roundedFn = (name, args) => {
    // math.ceil/floor take no precision; scale to emulate decimal places
    const mfn = `math.${name}`;
    if (args.length < 2) return `${mfn}(${args[0]})`;
    const n = Number(args[1]);
    if (Number.isFinite(n) && Number(args[1]) === n && /^\d+$/.test(args[1].trim?.() ?? '')) {
      // arg captured as a plain literal string
    }
    const nTok = args[1].trim();
    if (/^\d+$/.test(nTok)) {
      if (nTok === '0') return `${mfn}(${args[0]})`;
      const f = `10 ** ${nTok}`;
      return `${mfn}((${args[0]}) * ${f}) / ${f}`;
    }
    return `${mfn}(${args[0]})  # precision arg must be an integer literal`;
  };
  function parseFactor() {
    const t = tokens[i++];
    if (t === undefined) throw new Error('unexpected end');
    if (t === '(') { const v = parseBitOr(); if (tokens[i++] !== ')') throw new Error('missing )'); return `(${v})`; }
    if (t === '-') return `-${parseFactor()}`;
    if (t === '~') return `~${parseFactor()}`;
    if (/^0[xX]/.test(t) || /^\d/.test(t)) return t;
    if (t in EXPR_FUNCS) {
      if (tokens[i++] !== '(') throw new Error(`${t} needs parens`);
      const args = [parseBitOr()];
      while (tokens[i] === ',') { i++; args.push(parseBitOr()); }
      if (tokens[i++] !== ')') throw new Error('missing )');
      if (t === 'round') {
        return args.length > 1 ? `round(${args[0]}, ${args[1]})` : `round(${args[0]})`;
      }
      if (t === 'ceil' || t === 'floor') return roundedFn(t, args);
      if (t === 'abs') return `abs(${args[0]})`;
      return `math.${t}(${args[0]})`;
    }
    if (/^[A-Za-z_]/.test(t)) return mapIdent(t);
    throw new Error(`unexpected '${t}'`);
  }
  const parseMul = binary(['*', '/', '%'], parseFactor);
  const parseAdd = binary(['+', '-'], parseMul);
  const parseShift = binary(['<<', '>>'], parseAdd);
  const parseBitAnd = binary(['&'], parseShift);
  const parseBitXor = binary(['^'], parseBitAnd);
  const parseBitOr = binary(['|'], parseBitXor);
  return parseBitOr();
}

function negationTransform(ann) {
  // negation that out_power does not fit: non-W unit, or combined with a
  // divisor/multiplier - synthesize a None-safe helper instead
  const hasDiv = ann.divisor && Number(ann.divisor) !== 1;
  const hasMul = ann.multiplier && Number(ann.multiplier) !== 1;
  if (!ann.negate || ann.transform || hasEnum(ann)) return null;
  if (ann.unit === 'W' && !hasDiv && !hasMul) return null;   // out_power fits
  let expr = 'x';
  if (hasDiv) expr = `x / ${ann.divisor}`;
  if (hasMul) expr = `${expr} * ${ann.multiplier}`;
  return `-(${expr})`;
}

function transformHelper(ann) {
  // custom transform expression -> standalone None-safe helper function
  const fname = `_${sanitizePyName(ann.name)}_transform`;
  const prec = ann.precision != null && ann.precision !== '' ? ann.precision : null;
  const expr = exprToPython(ann.transform, n => n === 'x' ? 'value' : n);
  return {
    fname,
    code: [
      `def ${fname}(value: float | None) -> float | None:`,
      '    if value is None:',
      '        return None',
      `    return ${prec != null ? `round(${expr}, ${prec})` : expr}`,
    ].join('\n'),
  };
}

// V3 with schema: annotations keyed by proto field name (dotted path allowed)
function generatePbFields(groupAnn, protoInfo) {
  const lines = [];
  const imports = new Set();
  const defs = [];
  const floats = new Set(groupAnn.floatFields ?? []);
  for (const [key, ann] of Object.entries(groupAnn.fields)) {
    if (!ann.name || ann.combined || ann.expr || ann.known || ann.partOf ||
      key.startsWith('__expr_')) continue;
    let t;
    const neg = negationTransform(ann);
    if (hasEnum(ann)) {
      const { cls, code } = enumClassDef(ann);
      defs.push(code);
      imports.add('__enum__');
      t = `${cls}.from_value`;
    } else if (neg) {
      const helper = transformHelper({ ...ann, transform: neg });
      defs.push(helper.code);
      t = helper.fname;
    } else if (ann.transform) {
      const helper = transformHelper(ann);
      defs.push(helper.code);
      t = helper.fname;
    } else {
      t = pyTransform(ann, { isFloat: floats.has(key) });
      if (t) imports.add(t.split('(')[0].split(' ')[0]);
    }
    if (ann.group) {
      // one declaration covers the whole numbered family
      if (!ann.name.includes('{n}')) {
        lines.push(`# field group '${ann.name}' skipped - name template must contain {n}`);
        continue;
      }
      const attr = sanitizePyName(ann.name.replace(/_?\{n\}_?/, '_')
        .replace(/^_+|_+$/g, '').replace(/__+/g, '_'));
      const count = ann.group.members.length;
      const start = ann.group.start ?? 1;
      const args = [
        `pb.${key}`,
        `match="${ann.group.match}"`,
        `count=${count}`,
      ];
      if (start !== 1) args.push(`start=${start}`);
      if (t) args.push(`transform=${t}`);
      args.push(`name_template="${ann.name}"`);
      if (ann.notes) lines.push(...noteComment(ann.notes));
      lines.push(`${attr} = pb_field_group(${args.join(', ')})${unitComment(ann)}`);
      lines.push(`# grouped sensors need a SENSOR_TYPES["${ann.name}"] entry with ` +
        'translation_key + indexed_range instead of a plain translation');
      continue;
    }
    const name = sanitizePyName(ann.name);
    if (ann.notes) lines.push(...noteComment(ann.notes));
    lines.push(
      t
        ? `${name} = pb_field(pb.${key}, ${t})${unitComment(ann)}`
        : `${name} = pb_field(pb.${key})${unitComment(ann)}`
    );
  }
  return { lines, imports, defs };
}

// Schema-less: annotations keyed by wire path ("1", "3.2") - emit .proto
// snippet plus pb_field lines using the chosen names
function wireTypeToProto(interp, ann) {
  switch (ann.interp) {
    case 'sint': return 'sint32';
    case 'int': return 'int32';
    case 'float': return 'float';
    case 'double': return 'double';
    case 'text': return 'string';
    case 'hex': return 'bytes';
    default:
      if (interp?.wireType === 5) return interp.float !== undefined ? 'float' : 'uint32';
      if (interp?.wireType === 1) return 'uint64';
      if (interp?.wireType === 2) return 'bytes';
      return 'uint32';
  }
}

function generateProtoSnippet(groupAnn, latestInterps, messageName) {
  // Only top-level paths become message fields; nested paths become nested
  // messages. Keep it simple: group by top-level field number.
  const lines = [`message ${messageName} {`];
  const nested = new Map();
  for (const [path, ann] of Object.entries(groupAnn.fields)) {
    if (!ann.name || ann.combined || ann.expr || ann.known ||
      path.startsWith('__expr_')) continue;
    const clean = path.replace(/\[\d+\]/g, '');
    const parts = clean.split('.');
    const interp = latestInterps?.get(path);
    if (parts.length === 1) {
      lines.push(
        `  optional ${wireTypeToProto(interp, ann)} ${sanitizePyName(ann.name)} = ${parts[0]};${ann.unit ? ` // ${ann.unit}` : ''}`
      );
    } else {
      if (!nested.has(parts[0])) nested.set(parts[0], []);
      nested.get(parts[0]).push(
        `    optional ${wireTypeToProto(interp, ann)} ${sanitizePyName(ann.name)} = ${parts.slice(1).join('_')};${ann.unit ? ` // ${ann.unit}` : ''}`
      );
    }
  }
  for (const [fieldNo, subLines] of nested) {
    lines.push(`  message Sub${fieldNo} {`);
    lines.push(...subLines);
    lines.push('  }');
    lines.push(`  optional Sub${fieldNo} sub_${fieldNo} = ${fieldNo};`);
  }
  lines.push('}');
  return lines.join('\n');
}

// V2: struct fields -> RawData model + raw_field lines
function generateRawDataModel(structFields, groupAnn, modelName) {
  const modelLines = [`class ${modelName}(RawData):`];
  const fieldLines = [];
  const imports = new Set();
  const defs = [];
  if (!structFields.length) modelLines.push('    pass');
  for (const f of structFields) {
    const ann = groupAnn.fields[f.name];
    const unit = ann?.unit ? `  # ${ann.unit}` : '';
    const pyType = /s$/.test(f.fmt) ? 'bytes' : (f.fmt === 'f' || f.fmt === 'd' ? 'float' : 'int');
    modelLines.push(
      `    ${sanitizePyName(f.name)}: Annotated[${pyType}, "${f.fmt}"${f.orig ? `, "${f.orig}"` : ''}]${unit}`
    );
    if (ann?.name && !ann.known) {
      let t;
      const neg = negationTransform(ann);
      if (hasEnum(ann)) {
        const { cls, code } = enumClassDef(ann);
        defs.push(code);
        imports.add('__enum__');
        t = `${cls}.from_value`;
      } else if (neg) {
        const helper = transformHelper({ ...ann, transform: neg });
        defs.push(helper.code);
        t = helper.fname;
      } else if (ann.transform) {
        const helper = transformHelper(ann);
        defs.push(helper.code);
        t = helper.fname;
      } else {
        t = pyTransform(ann, { isFloat: f.fmt === 'f' || f.fmt === 'd' });
        if (t) imports.add(t.split('(')[0].split(' ')[0]);
      }
      if (ann.notes) fieldLines.push(...noteComment(ann.notes));
      fieldLines.push(
        t
          ? `${sanitizePyName(ann.name)} = raw_field(pb_model.${sanitizePyName(f.name)}, ${t})${unitComment(ann)}`
          : `${sanitizePyName(ann.name)} = raw_field(pb_model.${sanitizePyName(f.name)})${unitComment(ann)}`
      );
    }
  }
  return { modelLines, fieldLines, imports, defs };
}

function combinedFieldError(ann, validNames) {
  // syntax check with a dummy lookup, then reference check
  try {
    evalExpr(ann.expr, () => 1);
  } catch (e) {
    return `invalid expression: ${e.message}`;
  }
  const unknown = [...new Set(exprIdentifiers(ann.expr))]
    .filter(id => !validNames.has(id));
  if (unknown.length) return `unknown field(s): ${unknown.join(', ')}`;
  return null;
}

function allFieldNames(state) {
  // every named field across every group lives on the same device class
  const names = new Set();
  for (const g of Object.values(state.groups ?? {})) {
    for (const a of Object.values(g.fields ?? {})) {
      if (a.name) names.add(sanitizePyName(a.name));
    }
  }
  return names;
}

function generateComputedFields(groupAnn, validNames) {
  const blocks = [];

  for (const ann of Object.values(groupAnn.fields)) {
    if ((!ann.combined && !ann.expr) || !ann.name) continue;
    const name = sanitizePyName(ann.name);
    const error = ann.expr ? combinedFieldError(ann, validNames)
      : 'empty expression';
    if (error) {
      blocks.push(`# combined field '${name}' not exported - ${error}`);
      continue;
    }
    const notePrefix = ann.notes ? noteComment(ann.notes).join('\n') + '\n' : '';
    const ids = [...new Set(exprIdentifiers(ann.expr))];
    const guard = ids.map(i => `self.${i} is None`).join(' or ');
    const expr = exprToPython(ann.expr, n => `self.${n}`);
    const prec = ann.precision != null && ann.precision !== '' ? ann.precision : 2;
    blocks.push(notePrefix + [
      '@computed_field',
      `def ${name}(self) -> float | None:${unitComment(ann)}`,
      ...(ids.length ? [`    if ${guard}:`, '        return None'] : []),
      `    return round(${expr}, ${prec})`,
    ].join('\n'));
  }
  return blocks;
}

function titleCase(name) {
  return sanitizePyName(name).split('_').filter(Boolean)
    .map(w => w[0].toUpperCase() + w.slice(1)).join(' ');
}

function generateTranslations(state) {
  // translations/en.json additions for every exported (non-known) field
  const sensor = {};
  const binarySensor = {};
  const validNames = allFieldNames(state);
  for (const g of Object.values(state.groups)) {
    for (const [fieldKey, ann] of Object.entries(g.fields)) {
      if (!ann.name || ann.known || ann.partOf || ann.group) continue;
      if ((ann.combined || ann.expr || fieldKey.startsWith('__expr_')) &&
          (!ann.expr || combinedFieldError(ann, validNames))) continue;
      const key = sanitizePyName(ann.name);
      const entry = { name: ann.translation || titleCase(ann.name) };
      if (hasEnum(ann)) {
        entry.state = Object.fromEntries(Object.entries(ann.enumMap).map(([v, n]) => [
          enumMemberName(n).toLowerCase(),
          ann.enumTrans?.[v] || titleCase(enumMemberName(n).toLowerCase()),
        ]));
      }
      if (ann.unit === 'bool' || (ann.bit != null && ann.bit !== '')) {
        binarySensor[key] = entry;
      } else {
        sensor[key] = entry;
      }
    }
  }
  const out = {};
  if (Object.keys(sensor).length) out.sensor = sensor;
  if (Object.keys(binarySensor).length) out.binary_sensor = binarySensor;
  return Object.keys(out).length ? { entity: out } : null;
}

function generatePython(state) {
  // state: {info, groups: {key: {mode, proto, message, fields, struct, latestInterps}}}
  const out = [];
  const transformImports = new Set();
  const needsComputed = [];

  const globalNames = allFieldNames(state);
  out.push('# Generated by ecoflow-diag-analyzer');
  if (state.info?.device) out.push(`# Device: ${state.info.device} (${state.info.snPrefix ?? '?'})`);
  out.push('');

  for (const [groupKey, g] of Object.entries(state.groups)) {
    // only user-made annotations count - prefilled (known) fields and an
    // untouched default struct produce nothing worth exporting
    const annCount = Object.values(g.fields)
      .filter(a => a.name && !a.known).length;
    if (!annCount) continue;
    out.push(`# --- packet group ${groupKey} ---`);
    if (g.mode === 'proto' && g.message) {
      const messages = Array.isArray(g.message) ? g.message : [g.message];
      for (const msg of messages) {
        out.push(`# pb = proto_attr_mapper(${g.protoModule ?? 'xxx_pb2'}.${msg})`);
      }
      const { lines, imports, defs } = generatePbFields(g, null);
      imports.forEach(i => transformImports.add(i));
      if (defs.length) out.push(...defs.flatMap(d => [...d.split('\n'), '']));
      out.push(...lines);
    } else if (g.mode === 'wire') {
      const msgName = `Group${groupKey.replace(/[^A-Za-z0-9]/g, '_')}`;
      out.push('# Unmapped protobuf fields - add to a .proto and regenerate pb2:');
      out.push(...generateProtoSnippet(g, g.latestInterps, msgName).split('\n').map(l => `# ${l}`));
      out.push('');
      const { lines, imports, defs } = generatePbFields(g, null);
      imports.forEach(i => transformImports.add(i));
      if (defs.length) out.push(...defs.flatMap(d => [...d.split('\n'), '']));
      out.push(...lines.map(l => l.replace(/pb_field\(pb\./, 'pb_field(pb.')));
    } else if (g.mode === 'struct') {
      const modelName = g.modelName || 'NewHeartbeat';
      const { modelLines, fieldLines, imports, defs } = generateRawDataModel(g.struct ?? [], g, modelName);
      imports.forEach(i => transformImports.add(i));
      if (g.structIsDefault) {
        out.push(`# model ${modelName} already exists in eflib/model - reuse its mapper`);
      } else {
        out.push(...modelLines);
        out.push('');
      }
      out.push(`pb_model = dataclass_attr_mapper(${modelName})`);
      out.push('');
      if (defs.length) out.push(...defs.flatMap(d => [...d.split('\n'), '']));
      out.push(...fieldLines);
    }
    const computed = generateComputedFields(g, globalNames);
    if (computed.length) {
      // error comments don't need the computed_field import
      needsComputed.push(...computed.filter(b => b.startsWith('@')));
      out.push('');
      out.push(...computed.flatMap(b => b.split('\n')));
    }
    out.push('');
  }

  const header = [];
  const needsEnum = transformImports.delete('__enum__');
  if (transformImports.size) {
    header.push(
      `from ..props.transforms import ${[...transformImports].sort().join(', ')}`
    );
  }
  if (needsEnum) header.push('from ..props.enums import IntFieldValue');
  if (needsComputed.length) header.push('from ..props import computed_field');
  if (header.length) header.push('');

  if (out.some(l => /\bmath\./.test(l))) header.unshift('import math', '');

  const translations = generateTranslations(state);
  if (translations) {
    out.push('# --- translations/en.json additions (merge under "entity") ---');
    out.push(...JSON.stringify(translations, null, 2).split('\n').map(l => `# ${l}`));
    out.push('');
  }

  return [...out.slice(0, 1), ...header, ...out.slice(1)].join('\n');
}

function buildExportBundle(state) {
  return {
    version: 1,
    tool: 'ecoflow-diag-analyzer',
    exported_at: new Date().toISOString(),
    device: state.info ?? {},
    groups: Object.fromEntries(
      Object.entries(state.groups).map(([k, g]) => [k, {
        mode: g.mode,
        proto: g.proto ?? null,
        message: g.message ?? null,
        modelName: g.modelName ?? null,
        struct: g.struct ?? null,
        fields: g.fields,
      }])
    ),
    translations: generateTranslations(state),
    python: generatePython(state),
  };
}

export {
  UNITS, INTERPRETATIONS, EXPR_FUNCS, defaultAnnotation, applyAnnotation,
  evalExpr, exprIdentifiers, tokenizeExpr, normalizeExpr, generatePython,
  generateTranslations, buildExportBundle, sanitizePyName,
};
