// EcoFlow diagnostics analyzer - main application
import {
  bytesToHex, decodeDump, walkMessage, decodeStruct, structFieldSize,
} from './decode.js';
import {
  UNITS, EXPR_FUNCS, defaultAnnotation, applyAnnotation, evalExpr,
  tokenizeExpr, normalizeExpr, buildExportBundle, generatePython,
  sanitizePyName,
} from './annotate.js';
import {
  DEVICE_MAPPINGS, V2_STRUCTS, KNOWN_FIELDS, EXTRA_PROTO_FILES,
} from './mappings.js';

// protos.js (from ecoflow-ble-debug) lacks a few schemas used by mappings
Object.assign(PROTO_FILES, EXTRA_PROTO_FILES);

'use strict';

const $ = id => document.getElementById(id);
const h = (tag, attrs = {}, ...children) => {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else el.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c == null) continue;
    el.append(c.nodeType ? c : document.createTextNode(c));
  }
  return el;
};

function hexByte(v) { return '0x' + v.toString(16).padStart(2, '0').toUpperCase(); }

function autoTitle(name) {
  return name.split('_').filter(Boolean)
    .map(w => w[0].toUpperCase() + w.slice(1)).join(' ');
}

const state = {
  fileName: null,
  info: null,
  packets: [],
  errors: [],
  groups: new Map(),       // key -> {indices: number[], ...groupConfig}
  selectedGroup: null,
  selectedPacket: 0,       // index within group
  xorPayload: true,
  onlyChanging: false,
  hideKnown: false,
  fieldFilter: '',
  view: 'fields',          // fields | changes | hex | export
  detailField: null,       // field key opened in the detail panel
  detailMember: null,      // selected member key when detailField is a group
  builderFor: null,        // combined-field key with the chip builder open
  builderTransform: false, // chip builder open for the detail transform
  structOpen: false,       // struct layout editor expanded (per selected group)
  colWidths: {},           // tableKey -> {colIndex: px}, persisted
  detailHeight: null,      // resized detail panel height, persisted
};

try {
  state.detailHeight = Number(localStorage.getItem('efdiag:detailh')) || null;
} catch { /* ignore */ }

try {
  state.colWidths = JSON.parse(localStorage.getItem('efdiag:cols') ?? '{}');
} catch { /* corrupted - keep defaults */ }

function makeResizable(table, key) {
  const ths = table.tHead?.rows[0]?.cells;
  if (!ths) return table;
  const saved = state.colWidths[key] ?? {};
  if (Object.keys(saved).length) table.style.tableLayout = 'fixed';
  [...ths].forEach((th, i) => {
    if (saved[i]) th.style.width = saved[i] + 'px';
    const grip = h('span', { class: 'col-grip' });
    grip.addEventListener('mousedown', e => {
      e.preventDefault();
      const startX = e.clientX;
      const startW = th.offsetWidth;
      // freeze current widths so only the dragged column changes
      if (table.style.tableLayout !== 'fixed') {
        [...ths].forEach(c => { c.style.width = c.offsetWidth + 'px'; });
        table.style.tableLayout = 'fixed';
      }
      const move = ev => {
        const w = Math.max(40, startW + ev.clientX - startX);
        th.style.width = w + 'px';
        (state.colWidths[key] ??= {})[i] = w;
      };
      const up = () => {
        document.removeEventListener('mousemove', move);
        document.removeEventListener('mouseup', up);
        try {
          localStorage.setItem('efdiag:cols', JSON.stringify(state.colWidths));
        } catch { /* quota - ignore */ }
      };
      document.addEventListener('mousemove', move);
      document.addEventListener('mouseup', up);
    });
    grip.addEventListener('dblclick', () => {
      // reset this table's widths
      delete state.colWidths[key];
      try {
        localStorage.setItem('efdiag:cols', JSON.stringify(state.colWidths));
      } catch { /* ignore */ }
      render();
    });
    th.append(grip);
  });
  return table;
}

function groupKeyOf(p) {
  return `${hexByte(p.src)}→${hexByte(p.dst)} ${hexByte(p.cmdSet)}:${hexByte(p.cmdId)} v${p.version.toString(16)}`;
}

function storageKey() {
  return `efdiag:${state.info?.snPrefix ?? 'unknown'}`;
}

function newGroupConfig(samplePacket) {
  // Heuristic default mode: V2 packets -> struct, others -> wire walk
  const isV2 = (samplePacket.version & 0x0F) === 2 && samplePacket.version !== 4;
  return {
    indices: [],
    mode: isV2 ? 'struct' : 'wire',
    proto: '',
    message: '',
    modelName: 'NewHeartbeat',
    struct: [],
    fields: {},
    protoModule: '',
    payloadOffset: 0,
  };
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

function autoNameFields() {
  // an annotation with meaning but no name inherits the field key as its
  // default name (wire paths are numeric - those still ask for a name)
  for (const [, g] of state.groups) {
    if (g.mode === 'wire') continue;
    for (const [k, ann] of Object.entries(g.fields)) {
      if (!needsName(ann) || k.startsWith('__expr_')) continue;
      let name = sanitizePyName(k);
      if (ann.group && !name.includes('{n}')) name += '_{n}';
      ann.name = name;
    }
  }
}

function saveAnnotations() {
  autoNameFields();
  const groups = {};
  for (const [k, g] of state.groups) {
    groups[k] = {
      mode: g.mode, proto: g.proto, message: g.message,
      modelName: g.modelName, struct: g.struct, fields: g.fields,
      payloadOffset: g.payloadOffset || 0,
    };
  }
  try {
    localStorage.setItem(storageKey(), JSON.stringify(groups));
  } catch { /* quota - ignore */ }
}

function migrateCombinedFlags(fields) {
  // annotations saved before the `combined` flag existed identify combined
  // fields only by their synthetic key
  for (const [key, ann] of Object.entries(fields ?? {})) {
    if (key.startsWith('__expr_')) ann.combined = true;
  }
  return fields;
}

function loadAnnotations() {
  let saved;
  try { saved = JSON.parse(localStorage.getItem(storageKey()) ?? 'null'); } catch { return; }
  if (!saved) return;
  for (const s of Object.values(saved)) migrateCombinedFlags(s.fields);
  for (const [k, g] of state.groups) {
    const s = saved[k];
    if (!s) continue;
    // saved config wins over auto-mapping only when the user actually did
    // something with the group (annotated fields or built a struct)
    const touched = Object.keys(s.fields ?? {}).length > 0 ||
      (s.struct ?? []).length > 0;
    if (touched) Object.assign(g, s, { indices: g.indices });
    else g.fields = s.fields ?? g.fields;
  }
}

function deviceMapping(snPrefix) {
  if (!snPrefix) return null;
  // longest prefix wins so "D3N1" (Delta 3 Max) beats "D3" (original Delta)
  let best = null, bestLen = 0;
  for (const family of DEVICE_MAPPINGS) {
    for (const p of family.prefixes) {
      if (snPrefix.startsWith(p) && p.length > bestLen) {
        best = family; bestLen = p.length;
      }
    }
  }
  return best;
}

function mappingRuleFor(g) {
  const family = deviceMapping(state.info?.snPrefix);
  if (!family) return null;
  const sample = state.packets[g.indices[0]];
  return family.rules.find(r =>
    (r.src == null || r.src === sample.src) &&
    (r.cmdSet == null || r.cmdSet === sample.cmdSet) &&
    (r.cmdId == null || r.cmdId === sample.cmdId)) ?? null;
}

function applyMappingToGroup(g, r) {
  g.mode = r.mode;
  g.payloadOffset = r.offset ?? 0;
  let knownKey = null;
  if (r.mode === 'proto') {
    g.proto = r.proto;
    g.message = r.message;
    g.protoModule = r.proto.replace('.proto', '_pb2');
    knownKey = r.message;
  } else if (r.mode === 'struct' && V2_STRUCTS[r.struct]) {
    g.struct = V2_STRUCTS[r.struct].map(f => ({ orig: '', ...f }));
    g.modelName = r.struct;
    knownKey = r.struct;
  }
  // prefill annotations for fields already implemented in ha-ef-ble; fields
  // the user already named are left untouched
  const snPrefix = state.info?.snPrefix ?? '';
  for (const kk of Array.isArray(knownKey) ? knownKey : [knownKey]) {
    for (const [fieldKey, known] of Object.entries(KNOWN_FIELDS[kk] ?? {})) {
      // entries tagged with SN prefixes belong to specific devices sharing
      // this message - only prefill the ones matching the dump's device
      if (known.sn?.length && !known.sn.some(p => snPrefix.startsWith(p))) {
        continue;
      }
      if (!g.fields[fieldKey]?.name) {
        const { sn, ...ann } = known;
        g.fields[fieldKey] = { ...defaultAnnotation(), ...ann, known: true };
      }
    }
  }
}

function applyDeviceMapping() {
  for (const [, g] of state.groups) {
    const r = mappingRuleFor(g);
    if (r) applyMappingToGroup(g, r);
  }
}

function importAnnotationBundle(bundle) {
  const groups = bundle.groups ?? {};
  for (const [k, g] of state.groups) {
    if (groups[k]) {
      Object.assign(g, {
        mode: groups[k].mode ?? g.mode,
        proto: groups[k].proto ?? '',
        message: groups[k].message ?? '',
        modelName: groups[k].modelName ?? g.modelName,
        struct: groups[k].struct ?? [],
        fields: migrateCombinedFlags(groups[k].fields ?? {}),
      });
    }
  }
  saveAnnotations();
  render();
}

// ---------------------------------------------------------------------------
// Loading dumps
// ---------------------------------------------------------------------------

async function loadDumpText(text, fileName, { keepXor = false } = {}) {
  let dump;
  try { dump = JSON.parse(text); } catch (e) {
    setStatus(`Not valid JSON: ${e.message}`, 'error');
    return;
  }
  // Allow loading an annotation bundle back in
  if (dump.tool === 'ecoflow-diag-analyzer') {
    if (!state.packets.length) {
      setStatus('Load a diagnostics dump first, then import annotations', 'error');
      return;
    }
    importAnnotationBundle(dump);
    setStatus(`Annotations imported from ${fileName}`, 'ok');
    return;
  }
  setStatus('Decoding…');
  // XOR is per-device (e.g. Delta 2 XORs, Delta 2 Max does not) - take the
  // default from the device mapping; the header checkbox stays an override
  const snPrefix = (dump.data ?? dump)?.sn_prefix;
  const family = deviceMapping(snPrefix);
  if (family && !keepXor) {
    state.xorPayload = family.xor !== false;
    $('xor-toggle').checked = state.xorPayload;
  }
  state.rawDump = { text, fileName };
  let result;
  try {
    result = await decodeDump(dump, { xorPayload: state.xorPayload });
  } catch (e) {
    setStatus(String(e.message ?? e), 'error');
    return;
  }
  state.fileName = fileName;
  state.info = result.info;
  state.packets = result.packets;
  state.errors = result.errors;
  state.groups = new Map();
  for (let i = 0; i < result.packets.length; i++) {
    const key = groupKeyOf(result.packets[i]);
    if (!state.groups.has(key)) state.groups.set(key, newGroupConfig(result.packets[i]));
    state.groups.get(key).indices.push(i);
  }
  // biggest group first is usually the heartbeat
  state.groups = new Map(
    [...state.groups.entries()].sort((a, b) => b[1].indices.length - a[1].indices.length)
  );
  state.selectedGroup = state.groups.keys().next().value ?? null;
  state.selectedPacket = 0;
  applyDeviceMapping();
  loadAnnotations();
  setStatus(
    `${result.packets.length} packets in ${state.groups.size} groups` +
    (result.errors.length ? `, ${result.errors.length} decode errors` : ''),
    result.packets.length ? 'ok' : 'error'
  );
  render();
}

function setStatus(msg, kind = '') {
  const el = $('status');
  el.textContent = msg;
  el.className = kind;
  // errors get a prominent banner - the header status is easy to miss
  document.querySelector('.error-banner')?.remove();
  if (kind === 'error') {
    const banner = h('div', { class: 'error-banner' },
      h('span', { class: 'error-icon' }, '⚠'),
      h('span', {}, msg),
      h('span', { class: 'spacer' }),
      h('button', { class: 'small', onclick: () => banner.remove() }, '✕'),
    );
    document.querySelector('header').after(banner);
  }
}

// ---------------------------------------------------------------------------
// Field extraction per group
// ---------------------------------------------------------------------------

let protoRootCache = new Map();
function getProtoRoot(protoFile) {
  if (!protoRootCache.has(protoFile)) {
    try {
      protoRootCache.set(protoFile,
        protobuf.parse(PROTO_FILES[protoFile], { keepCase: true }).root);
    } catch (e) {
      protoRootCache.set(protoFile, null);
      console.error('proto parse failed', protoFile, e);
    }
  }
  return protoRootCache.get(protoFile);
}

function listMessages(protoFile) {
  const root = getProtoRoot(protoFile);
  if (!root) return [];
  const out = [];
  (function walk(ns, prefix) {
    if (!ns.nested) return;
    for (const [name, obj] of Object.entries(ns.nested)) {
      const full = prefix ? `${prefix}.${name}` : name;
      if (obj.fields) out.push(full);
      walk(obj, full);
    }
  })(root, '');
  return out;
}

function flattenObj(obj, prefix, out) {
  for (const [k, v] of Object.entries(obj)) {
    const path = prefix ? `${prefix}.${k}` : k;
    if (Array.isArray(v)) {
      v.forEach((item, i) => {
        const p = `${path}[${i}]`;
        if (item !== null && typeof item === 'object') flattenObj(item, p, out);
        else out.set(p, item);
      });
    } else if (v !== null && typeof v === 'object' && !(v instanceof Uint8Array)) {
      flattenObj(v, path, out);
    } else if (v instanceof Uint8Array) {
      out.set(path, bytesToHex(v));
    } else {
      out.set(path, typeof v === 'bigint' ? Number(v) : v);
    }
  }
  return out;
}

function pickWireValue(interp, ann) {
  if (!interp) return undefined;
  const mode = ann?.interp && ann.interp !== 'auto' ? ann.interp : null;
  if (mode) {
    const v = interp[mode];
    return v !== undefined ? v : interp.uint ?? interp.hex;
  }
  if (interp.wireType === 0) return interp.uint;
  if (interp.wireType === 5) return interp.int;
  if (interp.wireType === 1) return interp.int ?? interp.uint;
  if (interp.isMessage) return undefined; // children shown separately
  if (interp.text !== undefined) return interp.text;
  return interp.hex;
}

// Returns {fieldKeys: string[], series: Map(key -> array), interps: Map(key -> latest interp)|null}
function extractGroupFields(group) {
  const packets = group.indices.map(i => state.packets[i]);
  const series = new Map();
  const interps = new Map();
  const ensure = key => {
    if (!series.has(key)) series.set(key, new Array(packets.length).fill(undefined));
    return series.get(key);
  };

  // some devices (SHP3) prefix the payload with a routing header
  const off = group.payloadOffset || 0;
  const body = p => off ? p.payload.subarray(off) : p.payload;

  if (group.mode === 'wire') {
    packets.forEach((p, pi) => {
      const m = walkMessage(body(p));
      if (!m) return;
      for (const [path, interp] of m) {
        interps.set(path, interp);
        ensure(path)[pi] = pickWireValue(interp, group.fields[path]);
      }
    });
    // re-pick with annotations (interp choice) applied
    for (const [path, ann] of Object.entries(group.fields)) {
      if (ann.interp && ann.interp !== 'auto' && series.has(path)) {
        packets.forEach((p, pi) => {
          const m = walkMessage(body(p));
          const interp = m?.get(path);
          series.get(path)[pi] = pickWireValue(interp, ann);
        });
      }
    }
  } else if (group.mode === 'proto' && group.proto && group.message) {
    const root = getProtoRoot(group.proto);
    // some devices decode one body with several schemas (Display + Runtime)
    const names = Array.isArray(group.message) ? group.message : [group.message];
    for (const name of names) {
      let Msg = null;
      try { Msg = root?.lookupType(name); } catch { /* unknown message */ }
      if (!Msg) continue;
      packets.forEach((p, pi) => {
        try {
          const decoded = Msg.decode(body(p));
          const obj = Msg.toObject(decoded, { defaults: false, longs: Number, enums: Number });
          const flat = flattenObj(obj, '', new Map());
          for (const [path, value] of flat) ensure(path)[pi] = value;
        } catch { /* not this message - leave row empty */ }
      });
    }
  } else if (group.mode === 'struct') {
    packets.forEach((p, pi) => {
      const { values } = decodeStruct(p.payload, group.struct);
      for (const [name, value] of Object.entries(values)) ensure(name)[pi] = value;
    });
  }

  // stable sort: numeric-ish paths sorted naturally
  const fieldKeys = [...series.keys()].sort((a, b) =>
    a.localeCompare(b, undefined, { numeric: true }));
  return { fieldKeys, series, interps };
}

function changeCount(values) {
  let n = 0, prev;
  let first = true;
  for (const v of values) {
    if (v === undefined) continue;
    if (!first && v !== prev) n++;
    prev = v; first = false;
  }
  return n;
}

function sparkline(values) {
  const nums = values.map(v => typeof v === 'number' ? v : null);
  const present = nums.filter(v => v !== null);
  if (present.length < 2) return null;
  const min = Math.min(...present), max = Math.max(...present);
  const W = 120, H = 24, PAD = 2;
  const span = max - min || 1;
  const pts = [];
  const step = (W - 2 * PAD) / Math.max(nums.length - 1, 1);
  nums.forEach((v, i) => {
    if (v === null) return;
    const x = PAD + i * step;
    const y = H - PAD - ((v - min) / span) * (H - 2 * PAD);
    pts.push(`${x.toFixed(1)},${y.toFixed(1)}`);
  });
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  svg.setAttribute('class', 'spark');
  const poly = document.createElementNS('http://www.w3.org/2000/svg', 'polyline');
  poly.setAttribute('points', pts.join(' '));
  svg.append(poly);
  svg.setAttribute('title', `min ${min} max ${max}`);
  return svg;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

let _lastScrollCtx = null;

function render() {
  // preserve the table scroll position across re-renders (annotation edits,
  // detail panel open/close) - reset only when group or view changes
  const ctx = `${state.selectedGroup}|${state.view}`;
  const prevBody = document.querySelector('.view-body');
  const scroll = prevBody && _lastScrollCtx === ctx
    ? { top: prevBody.scrollTop, left: prevBody.scrollLeft }
    : null;
  renderInfo();
  renderGroups();
  renderMain();
  if (scroll) {
    const body = document.querySelector('.view-body');
    if (body) { body.scrollTop = scroll.top; body.scrollLeft = scroll.left; }
  }
  _lastScrollCtx = ctx;
}

function renderInfo() {
  const el = $('device-info');
  el.replaceChildren();
  if (!state.info) return;
  const i = state.info;
  el.append(...[
    h('span', { class: 'chip' }, i.device ?? '?'),
    h('span', { class: 'chip' }, i.snPrefix ?? '?'),
    deviceMapping(i.snPrefix)
      ? h('span', { class: 'chip ok', title:
          'decode rules for this device are built in; the device name above ' +
          'is whatever the integration reported when the dump was captured' },
          'auto-mapped ✓')
      : null,
    i.encryptType != null ? h('span', { class: 'chip' }, `enc_type ${i.encryptType}`) : null,
    state.fileName ? h('span', { class: 'chip muted' }, state.fileName) : null,
    i.exception ? h('span', { class: 'chip err' }, `exception: ${i.exception.type}`) : null,
  ].filter(Boolean));
}

function renderGroups() {
  const list = $('group-list');
  list.replaceChildren();
  for (const [key, g] of state.groups) {
    const annotated = Object.values(g.fields).filter(a => a.name).length;
    list.append(h('div', {
      class: 'group-item' + (key === state.selectedGroup ? ' selected' : ''),
      onclick: () => {
        state.selectedGroup = key; state.selectedPacket = 0;
        state.detailField = null; state.structOpen = false;
        state.builderFor = null; state.builderTransform = false; render();
      },
    },
      h('div', { class: 'group-key' }, key),
      h('div', { class: 'group-meta' },
        `${g.indices.length} pkts`,
        annotated ? h('span', { class: 'badge' }, `${annotated}✓`) : null,
      ),
    ));
  }
}

function currentGroup() {
  return state.selectedGroup ? state.groups.get(state.selectedGroup) : null;
}

function renderMain() {
  const main = $('main-content');
  main.replaceChildren();
  const g = currentGroup();
  if (!g) {
    main.append(h('div', { class: 'placeholder' },
      h('p', {}, 'Drop an (unencrypted) diagnostics JSON here, or use Open.'),
      h('p', {},
        h('button', { onclick: showHelp }, '? How to use this tool'),
        ' ',
        h('button', { onclick: async () => {
          try {
            const resp = await fetch('test_dump.json');
            await loadDumpText(await resp.text(), 'test_dump.json (sample)');
          } catch {
            setStatus('sample dump not reachable', 'error');
          }
        } }, '⚗ Load sample data')),
    ));
    return;
  }
  main.append(renderViewTabs(), renderGroupToolbar(g));
  const extraction = extractGroupFields(g);
  const body = h('div', { class: 'view-body' });
  switch (state.view) {
    case 'fields': body.append(renderFieldTable(g, extraction)); break;
    case 'changes': body.append(renderChanges(g, extraction)); break;
    case 'hex': body.append(renderHex(g, extraction)); break;
    case 'export': body.append(renderExport(g, extraction)); break;
  }
  main.append(body);
  // bottom-docked so opening/closing it never shifts the table
  if (state.view === 'fields' && state.detailField != null) {
    main.append(renderFieldDetail(g, extraction));
  }
}

function renderGroupToolbar(g) {
  const bar = h('div', { class: 'toolbar' });

  const rule = mappingRuleFor(g);
  if (rule) {
    const fmtMsg = m => Array.isArray(m)
      ? m.map(x => x.split('.').pop()).join(' + ') : m;
    const target = rule.mode === 'proto' ? fmtMsg(rule.message) : `struct ${rule.struct}`;
    const isApplied = rule.mode === g.mode &&
      (rule.mode === 'proto'
        ? g.proto === rule.proto &&
          JSON.stringify(g.message) === JSON.stringify(rule.message)
        : g.modelName === rule.struct);
    bar.append(h('button', {
      class: 'small' + (isApplied ? ' applied' : ' suggest'),
      title: isApplied
        ? `device mapping active: ${target}`
        : `reset decode config to the known device mapping: ${target}`,
      onclick: () => {
        applyMappingToGroup(g, rule);
        saveAnnotations();
        render();
      },
    }, isApplied ? `✓ ${target}` : `↺ auto: ${target}`));
  }

  const modeSel = h('select', {
    onchange: e => { g.mode = e.target.value; saveAnnotations(); render(); },
  },
    ...['wire', 'proto', 'struct'].map(m =>
      h('option', { value: m, ...(g.mode === m ? { selected: '' } : {}) },
        { wire: 'wire walk (no schema)', proto: 'protobuf schema', struct: 'V2 struct' }[m]))
  );
  bar.append(h('label', {}, 'Decode: ', modeSel));

  if (g.mode === 'proto') {
    const protoSel = h('select', {
      onchange: e => { g.proto = e.target.value; g.message = ''; saveAnnotations(); render(); },
    },
      h('option', { value: '' }, '(proto file)'),
      ...Object.keys(PROTO_FILES).map(f =>
        h('option', { value: f, ...(g.proto === f ? { selected: '' } : {}) }, f))
    );
    bar.append(protoSel);
    if (g.proto) {
      const multi = Array.isArray(g.message);
      const msgSel = h('select', {
        onchange: e => {
          g.message = e.target.value;
          g.protoModule = g.proto.replace('.proto', '_pb2');
          saveAnnotations(); render();
        },
      },
        h('option', { value: '' }, '(message)'),
        multi ? h('option', { value: '', selected: '' },
          g.message.map(x => x.split('.').pop()).join(' + ')) : null,
        ...listMessages(g.proto).map(m =>
          h('option', { value: m, ...(!multi && g.message === m ? { selected: '' } : {}) }, m))
      );
      bar.append(msgSel);
    }
  }

  if (g.mode === 'struct') {
    bar.append(h('label', {}, 'Model name: ',
      h('input', {
        type: 'text', value: g.modelName, size: 18,
        onchange: e => { g.modelName = e.target.value; saveAnnotations(); },
      })));
  }

  bar.append(h('label', { title: 'bytes to skip before decoding (routing header)' },
    'offset: ',
    h('input', {
      type: 'text', class: 'num', value: g.payloadOffset || 0,
      onchange: e => {
        g.payloadOffset = Number(e.target.value) || 0;
        saveAnnotations(); render();
      },
    })));

  return bar;
}

function renderViewTabs() {
  const tabs = h('div', { class: 'view-tabs' });
  for (const [view, label, hint] of [
    ['fields', '⊞ Fields', 'raw fields, values and annotations'],
    ['changes', 'Δ Changes', 'what changed, packet by packet'],
    ['hex', '⌗ Hex', 'per-packet hex dump'],
    ['export', '⬇ Export', 'annotation bundle + generated Python'],
  ]) {
    tabs.append(h('button', {
      class: state.view === view ? 'view-tab active' : 'view-tab',
      title: hint,
      onclick: () => { state.view = view; render(); },
    }, label));
  }
  return tabs;
}

function annOf(g, key) {
  if (!g.fields[key]) g.fields[key] = defaultAnnotation();
  return g.fields[key];
}

function fmtVal(v) {
  if (v === undefined || v === null) return '—';
  if (typeof v === 'number' && !Number.isInteger(v)) return String(Math.round(v * 1e6) / 1e6);
  return String(v);
}

function renderFieldTable(g, { fieldKeys, series, interps }) {
  const wrap = h('div', { class: 'field-wrap' });

  // one pass over all keys: which fields belong to an unclaimed numbered
  // family and could be grouped
  const groupable = new Map();
  if (g.mode !== 'wire') {
    const seen = new Set();
    for (const key of fieldKeys) {
      if (seen.has(key) || g.fields[key]?.group || g.fields[key]?.partOf) continue;
      const cand = groupCandidates(key, fieldKeys);
      if (!cand) continue;
      if (cand.members.some(m => g.fields[m.key]?.name ||
          g.fields[m.key]?.partOf || g.fields[m.key]?.group)) continue;
      for (const m of cand.members) {
        groupable.set(m.key, cand);
        seen.add(m.key);
      }
    }
  }

  const filterBar = h('div', { class: 'filter-bar' },
    h('input', {
      type: 'search', placeholder: 'filter fields…', value: state.fieldFilter,
      oninput: e => { state.fieldFilter = e.target.value; render(); },
    }),
    h('label', {},
      h('input', {
        type: 'checkbox', ...(state.onlyChanging ? { checked: '' } : {}),
        onchange: e => { state.onlyChanging = e.target.checked; render(); },
      }), ' only changing'),
    h('label', { title: 'hide fields already implemented in ha-ef-ble' },
      h('input', {
        type: 'checkbox', ...(state.hideKnown ? { checked: '' } : {}),
        onchange: e => { state.hideKnown = e.target.checked; render(); },
      }), ' hide implemented'),
    h('button', {
      class: 'small',
      onclick: () => { addCombinedField(g); },
    }, '+ combined field'),
    (() => {
      const patterns = new Set([...groupable.values()].map(c => c.pattern));
      return patterns.size ? h('span', {
        class: 'chip groupable-hint',
        title: 'fields with the ⊞ badge have numbered siblings - open their ' +
          'details to group the whole family into one declaration',
      }, `⊞ ${patterns.size} groupable families`) : null;
    })(),
  );
  wrap.append(filterBar);

  const FIELD_COLS = [
    ['field', 'field identifier: protobuf field name, wire path (schema-less) ' +
      'or struct field - click to open the detail panel with a time chart'],
    ['latest', 'most recent raw decoded value'],
    ['annotated', 'value after applying the annotation (÷ × neg bit precision)'],
    ['name', 'Python field name for the generated pb_field/raw_field (snake_case)'],
    ['unit', 'measurement unit - free text with suggestions (W, V, mAh, K…)'],
    ['÷', 'divisor - raw value is divided by this (exports as pdiv)'],
    ['×', 'multiplier - raw value is multiplied by this (exports as pmultiply)'],
    ['prec', 'decimal places to round to (default 2; exports as pround for floats)'],
    ['neg', 'negate the value - for output power (exports as out_power)'],
    ['bit', 'extract a single bit by index - for bitmask flags (exports as prop_has_bit_on)'],
    ['interp', 'how to read the raw wire value: unsigned/signed varint, float…'],
    ['chg', 'how many times the value changed across the dump'],
    ['trend', 'value trend over the whole dump (sparkline)'],
  ];
  const table = h('table', { class: 'fields' },
    h('thead', {}, h('tr', {},
      ...FIELD_COLS.map(([c, tip]) => thWithTip(c, tip)))));
  const tbody = h('tbody');
  table.append(tbody);

  const latestOf = key => {
    const vals = series.get(key) ?? [];
    for (let i = vals.length - 1; i >= 0; i--) if (vals[i] !== undefined) return vals[i];
    return undefined;
  };
  const annotatedLookup = name => {
    for (const [key, ann] of Object.entries(g.fields)) {
      if (ann.name === name && !ann.expr) {
        return applyAnnotation(latestOf(key), ann);
      }
    }
    // fall back to raw path lookup
    return series.has(name) ? latestOf(name) : null;
  };

  const filter = state.fieldFilter.toLowerCase();
  const dupNames = duplicateNames();
  const rows = [];
  for (const key of fieldKeys) {
    const vals = series.get(key);
    const chg = changeCount(vals);
    if (state.onlyChanging && chg === 0) continue;
    const ann = g.fields[key];
    if (ann?.partOf) continue;   // rendered as part of its group anchor
    if (state.hideKnown && ann?.known) continue;
    const label = `${key} ${ann?.name ?? ''}`.toLowerCase();
    if (filter && !label.includes(filter)) continue;
    rows.push([key, vals, chg, interps?.get(key)]);
  }

  // combined (expression) fields first so they are not missed at the bottom
  for (const [key, ann] of Object.entries(g.fields)) {
    if (!ann.combined && !ann.expr) continue;
    const cs = combinedSeries(g, { series }, ann);
    const chg = changeCount(cs);
    let value, err = '';
    for (let i = cs.length - 1; i >= 0; i--) {
      if (cs[i] !== undefined) { value = cs[i]; break; }
    }
    if (ann.expr && value === undefined) {
      try { evalExpr(ann.expr, () => 1); err = 'fields not resolvable'; }
      catch (e) { err = String(e.message); }
    }
    const builderOpen = state.builderFor === key;
    const isDetail = state.detailField === key;
    tbody.append(h('tr', {
      class: 'annotated combined' + (isDetail ? ' detail-open' : ''),
    },
      h('td', { class: 'mono key' },
        h('span', {
          class: 'expr-view' + (builderOpen ? ' editing' : ''), title: err ||
            (builderOpen ? 'close the builder' : 'open the builder'),
          onclick: () => { state.builderFor = builderOpen ? null : key; render(); },
        }, 'ƒ ', ann.expr || '(empty - click to build)', ' ⚒')),
      h('td', { class: 'mono' }, ''),
      h('td', { class: 'mono val' + (err ? ' err' : ''), title: err },
        err ? 'err' : fmtVal(value)),
      h('td', {}, h('input', {
        type: 'text',
        class: 'name' + (ann.name && dupNames.has(sanitizePyName(ann.name)) ? ' dup'
          : needsName(ann) ? ' dup' : ''),
        value: ann.name,
        title: ann.name && dupNames.has(sanitizePyName(ann.name))
          ? 'duplicate name - another field uses it too'
          : needsName(ann) ? 'annotated but unnamed - it will not be exported' : '',
        onchange: e => { ann.name = e.target.value; ann.known = false; saveAnnotations(); render(); },
      })),
      h('td', {}, unitInput(ann)),
      h('td', {}), h('td', {}),
      h('td', {}, numInput(ann, 'precision', null)),
      h('td', {}), h('td', {}), h('td', {}),
      h('td', { class: 'mono chg' }, chg || ''),
      h('td', {
        class: 'trend-cell', title: 'click for graph + details',
        onclick: () => {
          state.detailField = isDetail ? null : key;
          state.builderTransform = false; render();
        },
      },
        sparkline(cs) ?? '',
        h('button', {
          class: 'small danger',
          onclick: e => {
            e.stopPropagation();
            delete g.fields[key]; saveAnnotations(); render();
          },
        }, '×')),
    ));
    if (builderOpen) {
      tbody.append(h('tr', { class: 'builder-row' },
        h('td', { colspan: '13' }, exprBuilder({
          value: ann.expr,
          stateKey: `combined:${key}`,
          fields: annotatedFieldNames(),
          onChange: expr => { ann.expr = expr; saveAnnotations(); render(); },
        }))));
    }
  }

  for (const [key, vals, chg, interp] of rows) {
    const ann = annOf(g, key);
    const latest = (() => {
      for (let i = vals.length - 1; i >= 0; i--) if (vals[i] !== undefined) return vals[i];
      return undefined;
    })();
    const isDetail = state.detailField === key;
    const rowCls = (ann.name ? (ann.known ? 'known' : 'annotated') : '') +
      (isDetail ? ' detail-open' : '');
    const tr = h('tr', { class: rowCls },
      h('td', {
        class: 'mono key clickable',
        title: (interp ? interpTooltip(interp) + '\n' : '') + 'click for graph + details',
        onclick: () => {
          state.detailField = isDetail ? null : key;
          state.detailMember = null;
          state.builderTransform = false; render();
        },
      }, ann.group ? `${ann.group.match} ` : key,
        ann.group ? h('span', {
          class: 'badge grouped', title: 'click to ungroup',
          onclick: e => { e.stopPropagation(); ungroupField(g, key); },
        }, `×${ann.group.members.length}`)
          : groupable.has(key) ? h('span', {
              class: 'badge groupable',
              title: `${groupable.get(key).members.length} similar fields ` +
                `match ${groupable.get(key).pattern} - click to group them ` +
                '(open details for max-index config)',
              onclick: e => {
                e.stopPropagation();
                const cand = groupable.get(key);
                const anchorKey = cand.members[0].key;
                const anchorAnn = annOf(g, anchorKey);
                anchorAnn.group = {
                  match: cand.pattern,
                  members: cand.members.map(m => m.key),
                  start: cand.members[0].n,
                };
                for (const m of cand.members.slice(1)) {
                  g.fields[m.key] = { ...defaultAnnotation(), partOf: anchorKey };
                }
                saveAnnotations(); render();
              },
            }, `⊞ ×${groupable.get(key).members.length}`) : null),
      h('td', { class: 'mono' }, fmtVal(latest)),
      h('td', { class: 'mono val' }, fmtVal(applyAnnotation(latest, ann))),
      h('td', {}, h('input', {
        type: 'text',
        class: 'name' + (ann.name && dupNames.has(sanitizePyName(ann.name)) ? ' dup'
          : needsName(ann) ? ' dup' : ''),
        value: ann.name, placeholder: 'field_name',
        title: ann.name && dupNames.has(sanitizePyName(ann.name))
          ? 'duplicate name - another field uses it too'
          : needsName(ann) ? 'annotated but unnamed - it will not be exported' : '',
        onchange: e => { ann.name = e.target.value; ann.known = false; saveAnnotations(); render(); },
      })),
      h('td', {}, unitInput(ann)),
      h('td', {}, numInput(ann, 'divisor', 1)),
      h('td', {}, numInput(ann, 'multiplier', 1)),
      h('td', {}, numInput(ann, 'precision', null)),
      h('td', {}, h('input', {
        type: 'checkbox', ...(ann.negate ? { checked: '' } : {}),
        onchange: e => { ann.negate = e.target.checked; ann.known = false; saveAnnotations(); render(); },
      })),
      h('td', {}, numInput(ann, 'bit', null)),
      h('td', {}, interp ? h('select', {
        onchange: e => { ann.interp = e.target.value; ann.known = false; saveAnnotations(); render(); },
      }, ...interpOptions(interp, ann)) : ''),
      h('td', { class: 'mono chg' }, chg || ''),
      h('td', {
        class: 'trend-cell', title: 'click for graph + details',
        onclick: () => {
          state.detailField = isDetail ? null : key;
          state.builderTransform = false; render();
        },
      }, sparkline(vals) ?? ''),
    );
    tbody.append(tr);
  }

  if (g.mode === 'struct') wrap.append(renderStructBuilder(g));
  wrap.append(makeResizable(table, 'fields'));
  return wrap;
}

// ---------------------------------------------------------------------------
// Field detail panel: time chart + stats for one clicked field
// ---------------------------------------------------------------------------

function svgEl(tag, attrs = {}, text) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  if (text != null) el.textContent = text;
  return el;
}

function fmtTick(v) {
  if (Math.abs(v) >= 1000) return v.toFixed(0);
  const r = Math.round(v * 100) / 100;
  return String(r);
}

function timeChart(points, unit, categories = null) {
  // points: [{t, v}] numeric, time-sorted; with `categories`, v is an index
  // into the category list and the y axis shows the category names
  if (points.length < 2) return null;
  // size the coordinate system to the actual panel width so the chart fills
  // it without stretching text
  const W = Math.max(600, (document.querySelector('#main-content')?.clientWidth ?? 900) - 60);
  const H = 220, R = 14, T = 14, B = 26;
  const ts = points.map(p => p.t), vs = points.map(p => p.v);
  const t0 = Math.min(...ts), t1 = Math.max(...ts);
  let v0 = Math.min(...vs), v1 = Math.max(...vs);
  if (categories) { v0 = -0.5; v1 = categories.length - 0.5; }
  else if (v0 === v1) { v0 -= 1; v1 += 1; }

  const tickVals = categories
    ? categories.map((_, i) => i)
    : [0, 1, 2, 3, 4].map(i => v0 + (i / 4) * (v1 - v0));
  const tickLabel = v => categories ? String(categories[v]) : fmtTick(v);
  // left margin sized to the longest tick label so it never crops
  const L = 14 + Math.max(...tickVals.map(v => tickLabel(v).length)) * 6.5;

  const svg = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, class: 'chart' });
  const x = t => L + ((t - t0) / (t1 - t0 || 1)) * (W - L - R);
  const y = v => H - B - ((v - v0) / (v1 - v0)) * (H - T - B);

  for (const v of tickVals) {
    svg.append(svgEl('line', {
      x1: L, x2: W - R, y1: y(v), y2: y(v), class: 'grid' }));
    svg.append(svgEl('text', {
      x: L - 6, y: y(v) + 4, class: 'tick', 'text-anchor': 'end' }, tickLabel(v)));
  }
  for (let i = 0; i <= 5; i++) {
    const t = t0 + (i / 5) * (t1 - t0);
    svg.append(svgEl('text', {
      x: x(t), y: H - 8, class: 'tick', 'text-anchor': 'middle' }, `${t.toFixed(0)}s`));
  }
  if (unit) svg.append(svgEl('text', { x: 4, y: T + 4, class: 'tick' }, unit));

  // stepped line reads better for state-like telemetry than interpolation
  let d = `M ${x(points[0].t)} ${y(points[0].v)}`;
  for (let i = 1; i < points.length; i++) {
    d += ` H ${x(points[i].t)} V ${y(points[i].v)}`;
  }
  svg.append(svgEl('path', { d, class: 'line' }));

  for (const p of points) {
    svg.append(svgEl('circle', { cx: x(p.t), cy: y(p.v), r: 2.5, class: 'dot' }));
  }

  // hover readout: crosshair + value label following the nearest point
  const hover = svgEl('g', { class: 'hover', visibility: 'hidden' });
  const hLine = svgEl('line', { y1: T, y2: H - B, class: 'crosshair' });
  const hDot = svgEl('circle', { r: 4, class: 'hover-dot' });
  const hBg = svgEl('rect', { class: 'hover-bg', rx: 4, height: 18 });
  const hText = svgEl('text', { class: 'hover-text' });
  hover.append(hLine, hDot, hBg, hText);
  svg.append(hover);

  svg.addEventListener('mousemove', e => {
    const rect = svg.getBoundingClientRect();
    const mx = (e.clientX - rect.left) * (W / rect.width);
    let best = points[0], bd = Infinity;
    for (const p of points) {
      const dd = Math.abs(x(p.t) - mx);
      if (dd < bd) { bd = dd; best = p; }
    }
    const px = x(best.t), py = y(best.v);
    hLine.setAttribute('x1', px); hLine.setAttribute('x2', px);
    hDot.setAttribute('cx', px); hDot.setAttribute('cy', py);
    const shown = categories ? String(categories[best.v]) : fmtVal(best.v);
    const label = `${shown}${unit && !categories ? ' ' + unit : ''} @ ${best.t.toFixed(1)}s`;
    hText.textContent = label;
    const tw = label.length * 6.5 + 10;
    const tx = px + 10 + tw > W - R ? px - 10 - tw : px + 10;
    const ty = Math.max(T + 14, py - 10);
    hBg.setAttribute('x', tx); hBg.setAttribute('y', ty - 13);
    hBg.setAttribute('width', tw);
    hText.setAttribute('x', tx + 5); hText.setAttribute('y', ty);
    hover.setAttribute('visibility', 'visible');
  });
  svg.addEventListener('mouseleave', () => hover.setAttribute('visibility', 'hidden'));

  return svg;
}

function renderFieldDetail(g, { series, interps }) {
  const key = state.detailField;
  const isCombined = g.fields[key]?.combined || g.fields[key]?.expr;
  // grouped anchors can inspect any member's data individually
  const groupInfo = g.fields[key]?.group;
  const memberKey = groupInfo && state.detailMember &&
    groupInfo.members.includes(state.detailMember)
      ? state.detailMember : key;
  const vals = isCombined
    ? combinedSeries(g, { series }, g.fields[key])
    : series.get(memberKey) ?? series.get(key);
  if (!vals) { state.detailField = null; return h('div'); }
  const ann = annOf(g, key);
  const packets = g.indices.map(i => state.packets[i]);

  // combined values are already fully annotated by combinedSeries
  const annotated = isCombined ? vals : vals.map(v => applyAnnotation(v, ann));
  const points = [];
  annotated.forEach((v, i) => {
    if (typeof v === 'number') points.push({ t: packets[i].time ?? i, v });
  });

  // non-numeric (enum/bool/text) series still deserve a timeline: map each
  // distinct value to a categorical level
  let categories = null;
  const catValues = [...new Set(annotated.filter(v => v !== undefined && v !== null))];
  if (points.length < 2 && catValues.length >= 1 && catValues.length <= 12) {
    categories = catValues;
    points.length = 0;
    annotated.forEach((v, i) => {
      if (v === undefined || v === null) return;
      points.push({ t: packets[i].time ?? i, v: categories.indexOf(v) });
    });
  }

  const present = annotated.filter(v => v !== undefined && v !== null);
  const nums = present.filter(v => typeof v === 'number');
  const distinct = new Map();
  for (const v of present) distinct.set(v, (distinct.get(v) ?? 0) + 1);

  const stats = h('div', { class: 'detail-stats' });
  const stat = (label, value) => stats.append(
    h('div', { class: 'stat' }, h('span', { class: 'stat-label' }, label),
      h('span', { class: 'stat-value mono' }, value)));
  stat('samples', `${present.length}/${vals.length}`);
  stat('changes', String(changeCount(vals)));
  if (nums.length) {
    stat('min', fmtVal(Math.min(...nums)));
    stat('max', fmtVal(Math.max(...nums)));
    stat('avg', fmtVal(nums.reduce((a, b) => a + b, 0) / nums.length));
    stat('last', fmtVal(present[present.length - 1]));
  }
  stat('distinct', String(distinct.size));

  const interp = interps?.get(key);
  const labeled = (label, input) =>
    h('label', { class: 'detail-edit-item' }, label, input);
  const edit = isCombined ? h('div', { class: 'detail-edit' },
    labeled('name', h('input', {
      type: 'text', class: 'name', value: ann.name, placeholder: 'field_name',
      onchange: e => { ann.name = e.target.value; saveAnnotations(); render(); },
    })),
    labeled('translation (display name)', h('input', {
      type: 'text', class: 'name', value: ann.translation ?? '',
      placeholder: ann.name ? autoTitle(ann.name) : 'Total Power',
      onchange: e => { ann.translation = e.target.value; saveAnnotations(); render(); },
    })),
    labeled('unit', unitInput(ann)),
    labeled('precision', numInput(ann, 'precision', null)),
  ) : h('div', { class: 'detail-edit' },
    labeled('name', h('input', {
      type: 'text',
      class: 'name' + (ann.name && duplicateNames().has(sanitizePyName(ann.name)) ? ' dup'
        : needsName(ann) ? ' dup' : ''),
      value: ann.name, placeholder: 'field_name',
      title: ann.name && duplicateNames().has(sanitizePyName(ann.name))
        ? 'duplicate name - another field uses it too'
        : needsName(ann) ? 'annotated but unnamed - it will not be exported' : '',
      onchange: e => { ann.name = e.target.value; ann.known = false; saveAnnotations(); render(); },
    })),
    labeled('translation (display name)', h('input', {
      type: 'text', class: 'name', value: ann.translation ?? '',
      placeholder: ann.name ? autoTitle(ann.name) : 'Battery Level',
      title: 'entity name for translations/en.json; defaults to title-cased field name',
      onchange: e => {
        ann.translation = e.target.value;
        ann.known = false; saveAnnotations(); render();
      },
    })),
    labeled('unit', unitInput(ann)),
    labeled('÷', numInput(ann, 'divisor', 1)),
    labeled('×', numInput(ann, 'multiplier', 1)),
    labeled('precision', numInput(ann, 'precision', null)),
    labeled('negate', h('input', {
      type: 'checkbox', ...(ann.negate ? { checked: '' } : {}),
      onchange: e => { ann.negate = e.target.checked; ann.known = false; saveAnnotations(); render(); },
    })),
    labeled('custom transform (x = raw)', h('span', { class: 'transform-wrap' },
      h('span', {
        class: 'expr-view' + (state.builderTransform ? ' editing' : ''),
        title: 'expression over x; replaces ÷/×/neg/bit, precision still ' +
          'applies; exports as a None-safe helper function - click to build',
        onclick: () => { state.builderTransform = !state.builderTransform; render(); },
      }, ann.transform || '(none - click to build)', ' ⚒'))),
    labeled('bit', numInput(ann, 'bit', null)),
    interp ? labeled('interp', h('select', {
      onchange: e => { ann.interp = e.target.value; ann.known = false; saveAnnotations(); render(); },
    }, ...interpOptions(interp, ann))) : null,
  );

  const memberN = k => {
    if (!groupInfo) return null;
    const re = new RegExp('^' + escapeRe(groupInfo.match)
      .replace(/\\\{n\\\}/, '(\\d+)') + '$');
    return re.exec(k)?.[1] ?? null;
  };
  const notesArea = h('textarea', {
    class: 'notes-area', rows: '2',
    placeholder: 'notes for developers - observations, app behavior while ' +
      'capturing, doubts about the unit…',
    onchange: e => {
      ann.notes = e.target.value;
      ann.known = false;
      saveAnnotations(); render();
    },
  });
  notesArea.value = ann.notes ?? '';

  const grip = h('div', {
    class: 'panel-grip', title: 'drag to resize',
    onmousedown: e => {
      e.preventDefault();
      const startY = e.clientY;
      const startH = panel.offsetHeight;
      const move = ev => {
        const hpx = Math.max(160, Math.min(innerHeight * 0.85,
          startH + (startY - ev.clientY)));
        panel.style.height = `${hpx}px`;
        panel.style.maxHeight = 'none';
        state.detailHeight = hpx;
      };
      const up = () => {
        document.removeEventListener('mousemove', move);
        document.removeEventListener('mouseup', up);
        try { localStorage.setItem('efdiag:detailh', String(state.detailHeight)); }
        catch { /* ignore */ }
      };
      document.addEventListener('mousemove', move);
      document.addEventListener('mouseup', up);
    },
  });

  const panel = h('div', { class: 'detail-panel' },
    grip,
    h('div', { class: 'detail-head' },
      h('span', { class: 'mono key' }, groupInfo ? groupInfo.match : key),
      groupInfo ? h('span', { class: 'member-picker' },
        ...groupInfo.members.map(mk => h('button', {
          class: 'small' + (mk === memberKey ? ' tab active' : ''),
          title: mk,
          onclick: () => { state.detailMember = mk; render(); },
        }, `n=${memberN(mk) ?? '?'}`))) : null,
      ann.name ? h('span', { class: 'chip' }, ann.name) : null,
      ann.unit ? h('span', { class: 'chip' }, ann.unit) : null,
      h('span', { class: 'spacer' }),
      h('button', { class: 'small', onclick: () => { state.detailField = null; render(); } }, '✕ close'),
    ),
    edit,
    notesArea,
    isCombined ? exprBuilder({
      value: ann.expr,
      stateKey: `combined:${key}`,
      fields: annotatedFieldNames(),
      onChange: expr => { ann.expr = expr; saveAnnotations(); render(); },
    }) : null,
    !isCombined && state.builderTransform ? exprBuilder({
      value: ann.transform ?? '',
      stateKey: `transform:${key}`,
      fields: ['x'],
      onChange: expr => {
        ann.transform = expr;
        ann.known = false; saveAnnotations(); render();
      },
    }) : null,
    stats,
  );

  if (ann.unit === 'enum' || (ann.enumMap && Object.keys(ann.enumMap).length)) {
    panel.append(renderEnumEditor(ann, vals));
  }

  // field-group section: numbered siblings can be annotated as one family
  if (!isCombined) {
    const regroup = maxN => {
      // re-derive members from the live field list, honoring the index cap
      const re = new RegExp('^' + escapeRe(ann.group.match)
        .replace(/\\\{n\\\}/, '(\\d+)') + '$');
      const members = [...series.keys()]
        .map(k => ({ key: k, n: Number(re.exec(k)?.[1]) }))
        .filter(m => Number.isFinite(m.n) && (!maxN || m.n <= maxN))
        .sort((a, b) => a.n - b.n);
      for (const mk of ann.group.members) {
        if (g.fields[mk]?.partOf === key) delete g.fields[mk];
      }
      ann.group.members = members.map(m => m.key);
      ann.group.start = members[0]?.n ?? 1;
      ann.group.maxN = maxN || null;
      for (const m of members) {
        if (m.key !== key) g.fields[m.key] = { ...defaultAnnotation(), partOf: key };
      }
      saveAnnotations(); render();
    };
    if (ann.group) {
      panel.append(h('div', { class: 'group-editor' },
        h('div', { class: 'enum-head' },
          `field group ${ann.group.match} - name must contain {n}`,
          h('span', { class: 'spacer' }),
          h('label', { title: 'ignore members with a higher index' }, 'max n: ',
            h('input', {
              type: 'text', class: 'num', value: ann.group.maxN ?? '',
              placeholder: 'all',
              onchange: e => regroup(Number(e.target.value) || null),
            })),
          h('button', { class: 'small danger', onclick: () => ungroupField(g, key) },
            'ungroup'),
        ),
        h('div', { class: 'group-members mono' },
          ann.group.members.map(mk => {
            const re = new RegExp('^' + escapeRe(ann.group.match)
              .replace(/\\\{n\\\}/, '(\\d+)') + '$');
            const n = re.exec(mk)?.[1] ?? '?';
            const nm = (ann.name || '').replace('{n}', n);
            return h('div', {}, `${mk} → ${nm}`);
          }),
        ),
      ));
    } else {
      const cand = groupCandidates(key, [...series.keys()]);
      if (cand) {
        const maxInput = h('input', {
          type: 'text', class: 'num', placeholder: 'all',
        });
        panel.append(h('div', { class: 'group-editor' },
          h('div', { class: 'enum-head' },
            `${cand.members.length} similar fields match ${cand.pattern}`,
            h('span', { class: 'spacer' }),
            h('label', { title: 'ignore members with a higher index' },
              'max n: ', maxInput),
            h('button', { class: 'small group-btn', onclick: () => {
              const maxN = Number(maxInput.value) || null;
              const members = cand.members.filter(m => !maxN || m.n <= maxN);
              if (members.length < 2) return;
              ann.group = {
                match: cand.pattern,
                members: members.map(m => m.key),
                start: members[0].n,
                maxN,
              };
              if (ann.name && !ann.name.includes('{n}')) ann.name += '_{n}';
              for (const m of members) {
                if (m.key === key) continue;
                g.fields[m.key] = { ...defaultAnnotation(), partOf: key };
              }
              ann.known = false;
              saveAnnotations(); render();
            } }, '⊞ group them'),
          ),
        ));
      }
    }
  }

  const chart = timeChart(points, ann.unit, categories);
  if (chart) panel.append(chart);
  else if (distinct.size <= 12 && present.length) {
    // non-numeric or constant: show value distribution instead
    panel.append(h('div', { class: 'detail-values mono' },
      [...distinct.entries()].map(([v, n]) =>
        h('div', {}, `${fmtVal(v)} × ${n}`))));
  }

  if (interp) {
    panel.append(h('div', { class: 'detail-interp mono' },
      'latest raw interpretations: ' + interpTooltip(interp).replaceAll('\n', '   ')));
  }
  if (state.detailHeight) {
    panel.style.height = `${state.detailHeight}px`;
    panel.style.maxHeight = 'none';
  }
  return panel;
}

function renderEnumEditor(ann, rawVals) {
  // map every observed raw value (plus any manually added) to an enum NAME
  ann.enumMap ??= {};
  const counts = new Map();
  for (const v of rawVals) {
    if (typeof v === 'number') counts.set(v, (counts.get(v) ?? 0) + 1);
  }
  const values = [...new Set([
    ...counts.keys(), ...Object.keys(ann.enumMap).map(Number),
  ])].sort((a, b) => a - b);

  ann.enumTrans ??= {};
  const rows = values.map(v => h('div', { class: 'enum-row' },
    h('span', { class: 'mono enum-val' }, String(v)),
    h('span', { class: 'enum-count' },
      counts.has(v) ? `×${counts.get(v)}` : 'unseen'),
    h('input', {
      type: 'text', class: 'name', value: ann.enumMap[v] ?? '',
      placeholder: 'NAME (e.g. CHARGING)',
      onchange: e => {
        const name = e.target.value.trim().toUpperCase().replace(/[^A-Z0-9_]/g, '_');
        if (name) ann.enumMap[v] = name; else delete ann.enumMap[v];
        ann.known = false;
        saveAnnotations(); render();
      },
    }),
    h('input', {
      type: 'text', class: 'name enum-trans', value: ann.enumTrans[v] ?? '',
      placeholder: 'translation (optional)',
      title: 'display name in translations/en.json; defaults to the ' +
        'title-cased NAME',
      onchange: e => {
        const tr = e.target.value.trim();
        if (tr) ann.enumTrans[v] = tr; else delete ann.enumTrans[v];
        ann.known = false;
        saveAnnotations(); render();
      },
    }),
  ));

  const addVal = h('input', { type: 'text', class: 'num wide', placeholder: 'value' });
  return h('div', { class: 'enum-editor' },
    h('div', { class: 'enum-head' },
      'enum mapping - exports as an IntFieldValue class',
      h('span', { class: 'spacer' }),
      addVal,
      h('button', { class: 'small', onclick: () => {
        const v = Number(addVal.value);
        if (Number.isFinite(v) && ann.enumMap[v] === undefined) {
          ann.enumMap[v] = 'VALUE_' + String(v).replace('-', 'M');
          saveAnnotations(); render();
        }
      } }, '+ value'),
    ),
    ...rows,
  );
}

function interpTooltip(interp) {
  return Object.entries(interp)
    .filter(([k, v]) => !['wireType', 'bytes', 'isMessage'].includes(k) && v !== undefined)
    .map(([k, v]) => `${k}: ${v}`).join('\n');
}

function interpOptions(interp, ann) {
  const avail = ['auto'];
  if (interp.wireType === 0) avail.push('uint', 'sint', 'int');
  else if (interp.wireType === 5) avail.push('uint', 'int', 'float');
  else if (interp.wireType === 1) avail.push('uint', 'int', 'double');
  else if (interp.wireType === 2) avail.push('text', 'hex');
  return avail.map(o =>
    h('option', { value: o, ...(ann.interp === o ? { selected: '' } : {}) }, o));
}

function unitInput(ann) {
  // free text with a custom suggestion menu - native datalist rendering is
  // inconsistent across browsers (Firefox hides the values entirely)
  const input = h('input', {
    type: 'text', class: 'unit', value: ann.unit, placeholder: 'unit',
    autocomplete: 'off',
    onchange: e => {
      ann.unit = e.target.value.trim();
      ann.known = false; saveAnnotations(); render();
    },
  });
  const menu = h('div', { class: 'unit-menu', style: 'display:none' });
  const openMenu = () => {
    const q = input.value.trim().toLowerCase();
    const hits = UNITS.filter(u =>
      !q || u.value.toLowerCase().includes(q) || u.label.toLowerCase().includes(q));
    if (!hits.length) { menu.style.display = 'none'; return; }
    menu.replaceChildren(...hits.map(u => h('div', {
      class: 'unit-item',
      onmousedown: e => {
        e.preventDefault();   // keep focus so blur doesn't race the pick
        input.value = u.value;
        ann.unit = u.value;
        ann.known = false;
        menu.style.display = 'none';
        saveAnnotations(); render();
      },
    },
      h('span', { class: 'unit-value mono' }, u.value),
      h('span', { class: 'unit-label' }, u.label))));
    // fixed positioning escapes the table cell's overflow:hidden clipping
    const r = input.getBoundingClientRect();
    menu.style.left = `${Math.min(r.left, innerWidth - 200)}px`;
    menu.style.top = r.bottom + 244 < innerHeight
      ? `${r.bottom + 2}px` : `${Math.max(4, r.top - 244)}px`;
    menu.style.display = 'block';
  };
  input.addEventListener('focus', openMenu);
  input.addEventListener('input', openMenu);
  input.addEventListener('blur', () => { menu.style.display = 'none'; });
  input.addEventListener('keydown', e => {
    if (e.key === 'Escape') menu.style.display = 'none';
  });
  return h('span', { class: 'unit-wrap' }, input, menu);
}

function thWithTip(label, tip) {
  // instant CSS tooltip - the native title attribute takes a second to show
  // and gives no hint that help exists
  if (!tip) return h('th', {}, label);
  return h('th', {}, label, ' ',
    h('span', { class: 'qmark', dataset: { tip } }, '?'));
}

function numInput(ann, prop, dflt) {
  // divisor/multiplier take values like 0.0001 or 10000 - keep them wide
  const cls = prop === 'divisor' || prop === 'multiplier' ? 'num wide' : 'num';
  return h('input', {
    type: 'text', class: cls, value: ann[prop] ?? '',
    onchange: e => {
      const v = e.target.value.trim();
      ann[prop] = v === '' ? dflt : Number(v);
      ann.known = false;
      saveAnnotations(); render();
    },
  });
}

// ---------------------------------------------------------------------------
// Expression builder: compose expressions by clicking field / operator chips
// instead of typing. Writes back the plain expression string.
// ---------------------------------------------------------------------------

const BUILDER_OPS = ['+', '-', '*', '/', '%', '(', ')', ',', '<<', '>>', '&', '|', '^', '~'];

const OP_DESC = {
  '+': 'add', '-': 'subtract', '*': 'multiply', '/': 'divide',
  '%': 'modulo (remainder)', '(': 'open group', ')': 'close group',
  '<<': 'shift bits left (×2 per step)', '>>': 'shift bits right (÷2 per step)',
  '&': 'bitwise AND (mask bits)', '|': 'bitwise OR (combine bits)',
  '^': 'bitwise XOR', '~': 'bitwise NOT (invert bits)',
};

const FN_DESC = {
  exp: 'e to the power of the argument',
  log: 'natural logarithm (base e)',
  log2: 'logarithm base 2',
  log10: 'logarithm base 10',
  sqrt: 'square root',
  abs: 'absolute value',
  round: 'round to nearest integer, or round(x, n) for n decimals',
  ceil: 'round up, or ceil(x, n) for n decimals',
  floor: 'round down, or floor(x, n) for n decimals',
};

// caret survives the re-render that follows every committed change
const _builderState = {
  key: null, offset: null, focused: false,
  insertTok: null, insideParen: false, pendingCaret: null, reenter: null,
};

function exprBuilder({ value, fields, onChange, stateKey = 'default' }) {
  if (_builderState.key !== stateKey) {
    _builderState.key = stateKey;
    _builderState.offset = null;
    _builderState.focused = false;
  }

  const isNumber = t => /^(\d+\.?\d*|0[xX][0-9a-fA-F]+)$/.test(t);
  const isValid = t => BUILDER_OPS.includes(t) || isNumber(t) ||
    fields.includes(t) || t in EXPR_FUNCS || t === ',';

  const wrap = h('div', { class: 'expr-builder' });
  // one editable surface, native caret. The token under the caret renders as
  // plain text (dereferenced); every other token is an atomic chip. Moving
  // the caret out of a token re-chips it automatically.
  const editor = h('div', {
    class: 'eb-expr', contenteditable: 'true', spellcheck: 'false',
  });

  let committed = value || '';
  let rendering = false;

  // --- text model: serialize() and caret share the same coordinates -------
  const serialize = () =>
    [...editor.childNodes].map(n =>
      n.nodeType === Node.TEXT_NODE ? n.data : n.dataset.token
    ).join('');

  const parseWithPos = str => {
    const re = /\s*(0[xX][0-9a-fA-F]+|[A-Za-z_][A-Za-z0-9_.\[\]]*|\d+\.?\d*|<<|>>|[()+\-*/%&|^~,])/y;
    const out = [];
    let pos = 0;
    while (pos < str.length) {
      if (!str.slice(pos).trim()) break;   // trailing whitespace is fine
      re.lastIndex = pos;
      const m = re.exec(str);
      if (!m) return null;   // incomplete token mid-typing (e.g. lone '<')
      out.push({ t: m[1], start: m.index + m[0].length - m[1].length, end: re.lastIndex });
      pos = re.lastIndex;
    }
    return out;
  };

  const caretOffset = () => {
    const sel = getSelection();
    if (!sel.rangeCount || !editor.contains(sel.anchorNode)) return null;
    let off = 0;
    const anchor = sel.anchorNode === editor
      ? editor.childNodes[sel.anchorOffset] ?? null : sel.anchorNode;
    for (const n of editor.childNodes) {
      if (n === anchor) {
        return off + (sel.anchorNode === editor ? 0 : sel.anchorOffset);
      }
      off += n.nodeType === Node.TEXT_NODE ? n.data.length : n.dataset.token.length;
    }
    return off;
  };

  const setCaret = target => {
    if (target === null) return;
    let off = 0;
    for (const n of editor.childNodes) {
      const len = n.nodeType === Node.TEXT_NODE ? n.data.length : n.dataset.token.length;
      if (target <= off + len && n.nodeType === Node.TEXT_NODE) {
        const range = document.createRange();
        range.setStart(n, Math.max(0, Math.min(target - off, n.data.length)));
        range.collapse(true);
        const sel = getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        return;
      }
      off += len;
    }
    const last = editor.lastChild;
    if (last && last.nodeType === Node.TEXT_NODE) {
      const range = document.createRange();
      range.setStart(last, last.data.length);
      range.collapse(true);
      const sel = getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    }
  };

  const commit = () => {
    const toks = parseWithPos(serialize());
    if (!toks) return;
    const expr = normalizeExpr(toks.map(x => x.t).join(' '));
    _builderState.offset = caretOffset();
    if (expr === committed) return;
    committed = expr;
    onChange(expr);
  };

  // --- chips -----------------------------------------------------------------
  let dragIdx = null;
  const chipEl = (tok, { cls = null, removeAlso = null, label = null } = {}) => {
    const bad = !isValid(tok) && cls === null;
    const chip = h('span', {
      class: 'eb-chip' + (cls ? ` ${cls}` : bad ? ' bad'
        : BUILDER_OPS.includes(tok) ? ' op' : isNumber(tok) ? ' lit'
        : tok in EXPR_FUNCS ? ' fn' : ' field'),
      contenteditable: 'false',
      draggable: 'true',
      title: 'click to edit as text, drag to reorder, × to remove',
      dataset: { token: tok },
      onclick: e => {
        e.preventDefault();
        // dereference by placing the caret at the end of this token's text
        let off = 0;
        for (const n of editor.childNodes) {
          const len = n.nodeType === Node.TEXT_NODE ? n.data.length : n.dataset.token.length;
          if (n === chip) {
            editor.focus();
            rerender(off + len, { force: true, activeStart: off });
            return;
          }
          off += len;
        }
      },
      ondragstart: e => {
        dragIdx = [...editor.querySelectorAll('.eb-chip')].indexOf(chip);
        e.dataTransfer.effectAllowed = 'move';
      },
      ondragover: e => { e.preventDefault(); chip.classList.add('drop-target'); },
      ondragleave: () => chip.classList.remove('drop-target'),
      ondrop: e => {
        e.preventDefault();
        chip.classList.remove('drop-target');
        const chips = [...editor.querySelectorAll('.eb-chip')];
        const from = dragIdx !== null ? chips[dragIdx] : null;
        dragIdx = null;
        if (!from || from === chip) return;
        from.remove();
        chip.before(from, document.createTextNode(' '));
        rerender(null, { force: true });
        commit();
      },
      ondragend: () => { dragIdx = null; },
    }, label ?? tok,
      h('span', { class: 'eb-x', contenteditable: 'false', title: 'remove',
        onclick: e => {
          e.stopPropagation();
          for (const other of removeAlso?.() ?? []) {
            other.replaceWith(document.createTextNode(' '));
          }
          chip.replaceWith(document.createTextNode(' '));
          rerender(null, { force: true, chipAll: true });
          commit();
        } }, '×'));
    return chip;
  };

  // --- central rebuild: chip everything except the token under the caret ---
  let lastDom = { expr: null, active: null };
  // normalized start offset of the currently dereferenced token: keeps it
  // dereferenced while the caret sits on its (otherwise neutral) boundaries
  let stickyStart = null;
  const rerender = (caretTarget, { force = false, activeStart = null, chipAll = false } = {}) => {
    if (rendering) return;
    rendering = true;
    try {
      const raw = serialize();
      const toks = parseWithPos(raw);
      if (!toks) return;   // incomplete token - leave the DOM alone
      const caret = chipAll ? null
        : caretTarget !== undefined && caretTarget !== null
          ? caretTarget : caretOffset();
      // token is "active" (stays text) while the caret is inside it.
      // left-exclusive so token boundaries (== the single-space gaps) are
      // neutral - otherwise a caret parked between chips would endlessly
      // dereference its neighbor
      let active = -1;
      if (activeStart !== null) {
        active = toks.findIndex(x => x.start === activeStart);
      } else if (caret !== null) {
        active = toks.findIndex(x => x.start < caret && caret <= x.end);
        if (active === -1 && stickyStart !== null) {
          const i = toks.findIndex(x => x.start === stickyStart);
          if (i !== -1 && toks[i].start <= caret && caret <= toks[i].end) {
            active = i;
          }
        }
      }
      // leave the DOM (and the user's caret) alone when nothing changed -
      // rebuilding on every selectionchange would wipe a freshly placed caret
      const exprNow = toks.map(x => x.t).join(' ');
      if (!force && exprNow === lastDom.expr && active === lastDom.active) {
        _builderState.offset = caret;
        return;
      }
      lastDom = { expr: exprNow, active };
      // function calls render as a unit: "log(" is one chip and its matching
      // ")" is function-colored; removing either removes the whole pair.
      // Pairs containing the active (dereferenced) token fall back to plain
      // tokens so editing stays granular.
      const fnOpen = new Set();    // index of a func token merged with its '('
      const fnClose = new Map();   // index of ')' -> index of its func token
      for (let i = 0; i < toks.length - 1; i++) {
        if (!(toks[i].t in EXPR_FUNCS) || toks[i + 1].t !== '(') continue;
        let depth = 0;
        for (let j = i + 1; j < toks.length; j++) {
          if (toks[j].t === '(') depth++;
          else if (toks[j].t === ')' && --depth === 0) {
            if (active < i || (active > i + 1 && active !== j)) {
              fnOpen.add(i);
              fnClose.set(j, i);
            }
            break;
          }
        }
      }
      const chipByIdx = new Map();
      const parts = [document.createTextNode(' ')];
      let newCaret = null;
      let off = 1;
      stickyStart = null;
      for (let i = 0; i < toks.length; i++) {
        const x = toks[i];
        if (i === active) {
          parts.push(document.createTextNode(x.t));
          stickyStart = off;
          if (caret !== null) {
            const rel = Math.max(0, Math.min(caret - x.start, x.t.length));
            newCaret = off + rel;
          }
          parts.push(document.createTextNode(' '));
          off += x.t.length + 1;
        } else if (fnOpen.has(i)) {
          const merged = `${x.t} (`;
          const openIdx = i;
          const chip = chipEl(merged, {
            cls: 'fn',
            label: `${x.t}(`,
            removeAlso: () => {
              const closeIdx = [...fnClose.entries()]
                .find(([, o]) => o === openIdx)?.[0];
              return closeIdx !== undefined && chipByIdx.has(closeIdx)
                ? [chipByIdx.get(closeIdx)] : [];
            },
          });
          chipByIdx.set(i, chip);
          parts.push(chip, document.createTextNode(' '));
          off += merged.length + 1;
          i++;   // the '(' was consumed into the merged chip
        } else if (fnClose.has(i)) {
          const openIdx = fnClose.get(i);
          const chip = chipEl(')', {
            cls: 'fn',
            removeAlso: () =>
              chipByIdx.has(openIdx) ? [chipByIdx.get(openIdx)] : [],
          });
          chipByIdx.set(i, chip);
          parts.push(chip, document.createTextNode(' '));
          off += 2;
        } else {
          const chip = chipEl(x.t);
          chipByIdx.set(i, chip);
          parts.push(chip, document.createTextNode(' '));
          off += x.t.length + 1;
        }
      }
      if (caret !== null && active === -1) {
        // caret was in whitespace - land it in the gap after the last token
        // it passed (gaps are neutral, so this position is stable)
        newCaret = caret === 0 ? 0 : 1;
        let acc = 1;
        for (const x of toks) {
          if (x.end <= caret) newCaret = acc + x.t.length + 1;
          acc += x.t.length + 1;
        }
      }
      editor.replaceChildren(...parts);
      if (!editor.lastChild || editor.lastChild.nodeType !== Node.TEXT_NODE) {
        editor.append(document.createTextNode(' '));
      }
      if (_builderState.focused && newCaret !== null) setCaret(newCaret);
      _builderState.offset = newCaret;
    } finally {
      rendering = false;
    }
  };

  // --- events ----------------------------------------------------------------
  editor.addEventListener('input', () => {
    _builderState.insertTok = null; _builderState.insideParen = false;
    _builderState.reenter = null;
    rerender();
  });

  document.addEventListener('selectionchange', () => {
    if (!_builderState.focused || rendering) return;
    if (!editor.isConnected) return;
    rerender();
  });

  const chipOffsets = chip => {
    let off = 0;
    for (const n of editor.childNodes) {
      const len = n.nodeType === Node.TEXT_NODE ? n.data.length : n.dataset.token.length;
      if (n === chip) return { start: off, end: off + len };
      off += len;
    }
    return null;
  };

  const adjacentChip = dir => {
    const sel = getSelection();
    if (!sel.rangeCount || !sel.isCollapsed) return null;
    const { anchorNode: n, anchorOffset: o } = sel;
    if (n === editor) {
      const c = editor.childNodes[dir < 0 ? o - 1 : o];
      return c && c.nodeType !== Node.TEXT_NODE ? c : null;
    }
    if (n.nodeType !== Node.TEXT_NODE || !editor.contains(n)) return null;
    if (dir < 0) {
      // only whitespace between the caret and the previous chip
      if (n.data.slice(0, o).trim() !== '') return null;
      const prev = n.previousSibling;
      return prev && prev.nodeType !== Node.TEXT_NODE ? prev : null;
    }
    if (n.data.slice(o).trim() !== '') return null;
    const next = n.nextSibling;
    return next && next.nodeType !== Node.TEXT_NODE ? next : null;
  };

  editor.addEventListener('keydown', e => {
    if (e.key === 'ArrowLeft') {
      const chip = adjacentChip(-1);
      if (chip) {
        e.preventDefault();
        const { start, end } = chipOffsets(chip);
        rerender(end, { force: true, activeStart: start });
        return;
      }
    } else if (e.key === 'ArrowRight') {
      const chip = adjacentChip(1);
      if (chip) {
        e.preventDefault();
        const { start } = chipOffsets(chip);
        rerender(start, { force: true, activeStart: start });
        return;
      }
    } else if (e.key === 'Backspace') {
      const chip = adjacentChip(-1);
      if (chip) {
        e.preventDefault();
        const { start, end } = chipOffsets(chip);
        chip.replaceWith(document.createTextNode(chip.dataset.token.slice(0, -1)));
        rerender(end - 1, { force: true, activeStart: start });
        return;
      }
    } else if (e.key === 'Delete') {
      const chip = adjacentChip(1);
      if (chip) {
        e.preventDefault();
        const { start } = chipOffsets(chip);
        chip.replaceWith(document.createTextNode(chip.dataset.token.slice(1)));
        rerender(start, { force: true, activeStart: start });
        return;
      }
    }
    if (e.key === 'Enter') {
      e.preventDefault();
      _builderState.focused = false;
      rerender(null, { force: true, chipAll: true });
      commit();
      editor.blur();
    }
  });

  editor.addEventListener('focus', () => { _builderState.focused = true; });
  editor.addEventListener('blur', () => {
    _builderState.focused = false;
    rerender(null, { force: true, chipAll: true });
    commit();
  });

  // palette insertion tracks a TOKEN INDEX, not a char offset - immune to
  // the merged-chip coordinate quirks that plagued the offset approach
  const currentTokens = () => (parseWithPos(serialize()) ?? []).map(x => x.t);

  const resolveInsert = tokens => {
    if (_builderState.insertTok != null) {
      return Math.max(0, Math.min(_builderState.insertTok, tokens.length));
    }
    // derive from the live caret
    const off = caretOffset();
    if (off == null) return tokens.length;
    const parsed = parseWithPos(serialize()) ?? [];
    for (let i = 0; i < parsed.length; i++) {
      if (parsed[i].start >= off) return i;
    }
    return tokens.length;
  };

  const matchClose = (tokens, fromIdx) => {
    let depth = 1;
    for (let i = fromIdx; i < tokens.length; i++) {
      if (tokens[i] === '(') depth++;
      else if (tokens[i] === ')' && --depth === 0) return i;
    }
    return tokens.length - 1;
  };

  const applyTokens = (tokens, caretIdx) => {
    const text = ` ${tokens.join(' ')} `;
    editor.replaceChildren(document.createTextNode(text));
    const parsed = parseWithPos(text) ?? [];
    const off = caretIdx >= parsed.length
      ? text.length : caretIdx <= 0 ? 0 : parsed[caretIdx].start;
    editor.focus();
    rerender(off, { force: true });
    // commit() re-renders the whole panel and blurs this editor; stash the
    // caret so the rebuilt builder restores it (blur clears `focused`)
    _builderState.pendingCaret = off;
    commit();
  };

  const add = (...ts) => {
    const tokens = currentTokens();
    // comma right after a just-closed call re-enters its parens so
    // round(x , 2)-style precision args land inside, not outside
    if (ts.length === 1 && ts[0] === ',' &&
        _builderState.reenter != null && tokens[_builderState.reenter] === ')') {
      const at = _builderState.reenter;
      tokens.splice(at, 0, ',');
      _builderState.reenter = null;
      _builderState.insideParen = false;
      _builderState.insertTok = at + 1;      // after comma, before ')'
      applyTokens(tokens, at + 1);
      return;
    }
    _builderState.reenter = null;
    let idx = resolveInsert(tokens);
    // a binary operator right before a ')' can only belong outside the group
    // (a dangling "… + )" is never valid) - skip past the close paren(s)
    const BINARY = ['+', '-', '*', '/', '%', '<<', '>>', '&', '|', '^'];
    if (ts.length === 1 && BINARY.includes(ts[0])) {
      while (tokens[idx] === ')') idx++;
    }
    tokens.splice(idx, 0, ...ts);
    let caretIdx;
    if (_builderState.insideParen) {
      // argument placed - continue after the call's closing paren, but
      // remember it so an immediate comma can dive back in for a 2nd arg
      const close = matchClose(tokens, idx + ts.length);
      caretIdx = close + 1;
      _builderState.insideParen = false;
      _builderState.reenter = close;
    } else {
      caretIdx = idx + ts.length;
    }
    _builderState.insertTok = caretIdx;
    applyTokens(tokens, caretIdx);
  };

  const palette = h('div', { class: 'eb-palette' },
    h('div', { class: 'eb-row' },
      ...fields.map(f => h('button', { class: 'eb-add field', onclick: () => add(f) }, f))),
    h('div', { class: 'eb-row' },
      ...BUILDER_OPS.map(op =>
        h('button', { class: 'eb-add op', title: OP_DESC[op] ?? '',
          onclick: () => add(op) }, op)),
      ...Object.keys(EXPR_FUNCS).map(fn =>
        h('button', { class: 'eb-add fn',
          title: `${fn}(…) - ${FN_DESC[fn] ?? ''}`,
          onclick: () => {
            const tokens = currentTokens();
            const idx = resolveInsert(tokens);
            tokens.splice(idx, 0, fn, '(', ')');
            // next palette pick lands between the parens; add() then jumps
            // past the closing paren once the argument is placed
            _builderState.insertTok = idx + 2;
            _builderState.insideParen = true;
            applyTokens(tokens, idx + 2);
          } }, `${fn}()`)),
      h('span', { class: 'spacer' }),
      h('button', { class: 'eb-add danger', title: 'clear expression',
        onclick: () => {
          editor.replaceChildren(document.createTextNode(' '));
          commit();
          editor.focus();
        } }, 'clear'),
    ),
  );
  // keep the editor focused while using the palette - a blur would commit
  // and rebuild mid-click
  palette.addEventListener('mousedown', e => e.preventDefault());

  // initial content: all chips
  editor.append(document.createTextNode(value || ' '));
  rerender(null, { force: true });
  if (_builderState.focused || _builderState.pendingCaret != null) {
    const want = _builderState.pendingCaret ?? _builderState.offset;
    _builderState.pendingCaret = null;
    setTimeout(() => { editor.focus(); setCaret(want); }, 0);
  }

  wrap.append(editor, palette);
  return wrap;
}

const escapeRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function groupCandidates(key, fieldKeys) {
  // for each number in the key, try treating it as the index of a field
  // family; return the pattern that matches the most sibling keys
  let best = null;
  for (const m of key.matchAll(/\d+/g)) {
    const pattern = key.slice(0, m.index) + '{n}' + key.slice(m.index + m[0].length);
    const re = new RegExp('^' + escapeRe(pattern).replace(/\\\{n\\\}/, '(\\d+)') + '$');
    const members = [];
    for (const k of fieldKeys) {
      const mm = re.exec(k);
      if (mm) members.push({ key: k, n: Number(mm[1]) });
    }
    if (members.length >= 2 && (!best || members.length > best.members.length)) {
      best = { pattern, members: members.sort((a, b) => a.n - b.n) };
    }
  }
  return best;
}

function ungroupField(g, key) {
  const ann = g.fields[key];
  for (const mk of ann.group?.members ?? []) {
    if (g.fields[mk]?.partOf === key) delete g.fields[mk];
  }
  delete ann.group;
  if (ann.name?.includes('{n}')) ann.name = ann.name.replace(/_?\{n\}_?/, '');
  saveAnnotations();
  render();
}

function needsName(ann) {
  // annotation carries meaning but has no name -> it won't be exported
  return !ann.name && !ann.known && Boolean(
    ann.unit || ann.transform || ann.expr || ann.negate ||
    (ann.divisor && Number(ann.divisor) !== 1) ||
    (ann.multiplier && Number(ann.multiplier) !== 1) ||
    (ann.bit !== null && ann.bit !== '' && ann.bit !== undefined) ||
    (ann.enumMap && Object.keys(ann.enumMap).length),
  );
}

function duplicateNames() {
  // names live on one device class regardless of message - global uniqueness
  const counts = {};
  for (const [, gg] of state.groups) {
    for (const ann of Object.values(gg.fields)) {
      if (!ann.name) continue;
      const n = sanitizePyName(ann.name);
      counts[n] = (counts[n] ?? 0) + 1;
    }
  }
  return new Set(Object.keys(counts).filter(n => counts[n] > 1));
}

function annotatedFieldNames() {
  // all annotated plain fields across every packet group: a combined field
  // may reference fields from other messages of the same device
  const names = new Set();
  for (const [, gg] of state.groups) {
    for (const a of Object.values(gg.fields)) {
      if (a.name && !a.combined && !a.expr) names.add(sanitizePyName(a.name));
    }
  }
  return [...names].sort();
}

function fieldNameIndex() {
  const idx = {};
  for (const [gk, gg] of state.groups) {
    for (const [fk, a] of Object.entries(gg.fields)) {
      if (a.name && !a.combined && !a.expr) {
        idx[sanitizePyName(a.name)] ??= { gg, fk, a };
      }
    }
  }
  return idx;
}

function combinedSeries(g, extraction, ann) {
  // evaluate the expression per packet of the owning group; fields from
  // other groups resolve to their last value at or before that packet's time
  if (!ann.expr) return g.indices.map(() => undefined);
  const packets = g.indices.map(i => state.packets[i]);
  const idx = fieldNameIndex();
  const foreignCache = new Map();
  const valueAt = (entry, time, i) => {
    let series, times;
    if (entry.gg === g) {
      series = extraction.series.get(entry.fk);
      const v = series?.[i];
      const av = applyAnnotation(v, entry.a);
      return typeof av === 'number' ? av : null;
    }
    let fc = foreignCache.get(entry.gg);
    if (!fc) {
      fc = {
        ex: extractGroupFields(entry.gg),
        times: entry.gg.indices.map(j => state.packets[j].time ?? 0),
      };
      foreignCache.set(entry.gg, fc);
    }
    const vals = fc.ex.series.get(entry.fk);
    if (!vals) return null;
    let best;
    for (let j = 0; j < vals.length; j++) {
      if (fc.times[j] > time) break;
      if (vals[j] !== undefined) best = vals[j];
    }
    if (best === undefined) best = vals.find(v => v !== undefined);
    const av = applyAnnotation(best, entry.a);
    return typeof av === 'number' ? av : null;
  };
  return packets.map((p, i) => {
    try {
      const v = evalExpr(ann.expr, n => idx[n] ? valueAt(idx[n], p.time ?? 0, i) : null);
      const rounded = typeof v === 'number' && Number.isFinite(v)
        ? applyAnnotation(v, { ...ann, expr: '', divisor: 1, multiplier: 1 }) : undefined;
      return typeof rounded === 'number' ? rounded : undefined;
    } catch { return undefined; }
  });
}

let combinedCounter = 0;
function addCombinedField(g) {
  const key = `__expr_${Date.now()}_${combinedCounter++}`;
  g.fields[key] = {
    ...defaultAnnotation(), combined: true, expr: '', name: 'combined_field',
  };
  state.builderFor = key;
  saveAnnotations();
  render();
}

// ---------------------------------------------------------------------------
// Struct builder (V2)
// ---------------------------------------------------------------------------

const STRUCT_FMTS = ['B', 'b', 'H', 'h', 'I', 'i', 'Q', 'q', 'f', 'd', '2s', '4s', '8s', '14s', '16s'];

function renderStructBuilder(g) {
  const packets = g.indices.map(i => state.packets[i]);
  const sample = packets[Math.min(state.selectedPacket, packets.length - 1)];
  const { consumed } = decodeStruct(sample.payload, g.struct);
  // collapsed by default - the prefilled layouts are long and usually right
  const details = h('details', {
    class: 'struct-builder',
    ...(state.structOpen ? { open: '' } : {}),
  });
  details.addEventListener('toggle', () => { state.structOpen = details.open; });
  details.append(h('summary', {},
    `Struct layout — ${g.struct.length} fields, mapped ${consumed}/` +
    `${sample.payload.length} B`));
  const wrap = h('div');
  details.append(wrap);
  wrap.append(h('div', { class: 'struct-head' },
    h('button', { class: 'small', onclick: () => {
      g.struct.push({ name: `field_${g.struct.length}`, fmt: 'B', orig: '' });
      saveAnnotations(); render();
    } }, '+ field'),
    h('button', { class: 'small', onclick: () => {
      // fill remaining payload with u8 placeholder fields
      let off = consumed;
      let i = g.struct.length;
      while (off < sample.payload.length) {
        g.struct.push({ name: `unk_${off}`, fmt: 'B', orig: '' });
        off += 1; i++;
      }
      saveAnnotations(); render();
    } }, 'fill rest u8'),
  ));

  const STRUCT_COLS = [
    ['off', 'byte offset of the field within the payload (computed)'],
    ['name', 'field name in the RawData model class'],
    ['fmt', 'Python struct format char: B/b = u8/i8, H/h = u16/i16, ' +
      'I/i = u32/i32, Q/q = u64/i64, f/d = float/double, Ns = N raw bytes ' +
      '(little-endian)'],
    ['orig name', 'name from the decompiled EcoFlow app (optional, kept as ' +
      'the third Annotated arg)'],
    ['', 'reorder / delete'],
  ];
  const table = h('table', { class: 'struct' },
    h('thead', {}, h('tr', {},
      ...STRUCT_COLS.map(([c, tip]) => thWithTip(c, tip)))));
  const tbody = h('tbody');
  let off = 0;
  g.struct.forEach((f, idx) => {
    const size = structFieldSize(f.fmt) ?? 0;
    const myOff = off;
    off += size;
    tbody.append(h('tr', {},
      h('td', { class: 'mono' }, `${myOff}`),
      h('td', {}, h('input', {
        type: 'text', value: f.name,
        onchange: e => {
          const old = f.name;
          f.name = sanitizePyName(e.target.value);
          if (g.fields[old]) { g.fields[f.name] = g.fields[old]; delete g.fields[old]; }
          saveAnnotations(); render();
        },
      })),
      h('td', {}, h('select', {
        onchange: e => { f.fmt = e.target.value; saveAnnotations(); render(); },
      }, ...STRUCT_FMTS.map(fmt =>
        h('option', { value: fmt, ...(f.fmt === fmt ? { selected: '' } : {}) }, fmt)))),
      h('td', {}, h('input', {
        type: 'text', value: f.orig ?? '',
        onchange: e => { f.orig = e.target.value; saveAnnotations(); },
      })),
      h('td', {},
        h('button', { class: 'small', onclick: () => {
          if (idx > 0) {
            [g.struct[idx - 1], g.struct[idx]] = [g.struct[idx], g.struct[idx - 1]];
            saveAnnotations(); render();
          }
        } }, '↑'),
        h('button', { class: 'small danger', onclick: () => {
          g.struct.splice(idx, 1); saveAnnotations(); render();
        } }, '×'),
      ),
    ));
  });
  table.append(tbody);
  wrap.append(makeResizable(table, 'struct'));
  return details;
}

// ---------------------------------------------------------------------------
// Changes view
// ---------------------------------------------------------------------------

function renderChanges(g, { fieldKeys, series }) {
  const packets = g.indices.map(i => state.packets[i]);
  const wrap = h('div', { class: 'changes-wrap' });
  const events = [];
  for (const key of fieldKeys) {
    const vals = series.get(key);
    let prev, first = true;
    vals.forEach((v, pi) => {
      if (v === undefined) return;
      if (!first && v !== prev) {
        events.push({ pi, time: packets[pi].time, key, from: prev, to: v });
      }
      prev = v; first = false;
    });
  }
  events.sort((a, b) => a.pi - b.pi || a.key.localeCompare(b.key, undefined, { numeric: true }));
  if (!events.length) {
    wrap.append(h('div', { class: 'placeholder' }, 'No field changes in this group.'));
    return wrap;
  }
  const CHANGE_COLS = [
    ['pkt#', 'packet index within this group where the value changed'],
    ['t (s)', 'capture time in seconds since diagnostics collection started'],
    ['field', 'field identifier (same as in the Fields tab)'],
    ['name', 'annotated Python name, if assigned'],
    ['from', 'raw value before the change'],
    ['to', 'raw value after the change'],
  ];
  const table = h('table', { class: 'fields' },
    h('thead', {}, h('tr', {},
      ...CHANGE_COLS.map(([c, tip]) => thWithTip(c, tip)))));
  const tbody = h('tbody');
  for (const ev of events) {
    const ann = g.fields[ev.key];
    tbody.append(h('tr', {},
      h('td', { class: 'mono' }, ev.pi),
      h('td', { class: 'mono' }, ev.time?.toFixed?.(1) ?? ''),
      h('td', {
        class: 'mono key clickable', title: 'open in Fields with details',
        onclick: () => {
          state.view = 'fields';
          state.detailField = ev.key;
          state.builderTransform = false;
          render();
        },
      }, ev.key),
      h('td', {}, ann?.name ?? ''),
      h('td', { class: 'mono' }, fmtVal(ev.from)),
      h('td', { class: 'mono val' }, fmtVal(ev.to)),
    ));
  }
  table.append(tbody);
  wrap.append(makeResizable(table, 'changes'));
  return wrap;
}

// ---------------------------------------------------------------------------
// Hex view
// ---------------------------------------------------------------------------

function renderHex(g, extraction) {
  const packets = g.indices.map(i => state.packets[i]);
  const wrap = h('div', { class: 'hex-wrap' });
  const idx = Math.min(state.selectedPacket, packets.length - 1);
  const p = packets[idx];

  wrap.append(h('div', { class: 'hex-nav' },
    h('button', { class: 'small', onclick: () => {
      state.selectedPacket = Math.max(0, idx - 1); render();
    } }, '◀'),
    h('input', {
      type: 'range', min: 0, max: packets.length - 1, value: idx,
      oninput: e => { state.selectedPacket = Number(e.target.value); render(); },
    }),
    h('button', { class: 'small', onclick: () => {
      state.selectedPacket = Math.min(packets.length - 1, idx + 1); render();
    } }, '▶'),
    h('span', { class: 'mono' }, ` pkt ${idx + 1}/${packets.length}` +
      (p.time != null ? ` @ ${p.time.toFixed(1)}s` : '')),
    h('button', { class: 'small', onclick: () =>
      navigator.clipboard.writeText(bytesToHex(p.payload)) }, 'copy payload'),
    h('button', { class: 'small', onclick: () =>
      navigator.clipboard.writeText(bytesToHex(p.raw)) }, 'copy raw'),
  ));

  // Byte->field coloring for struct mode
  const colorOf = new Array(p.payload.length).fill(-1);
  if (g.mode === 'struct') {
    const { offsets } = decodeStruct(p.payload, g.struct);
    let ci = 0;
    for (const f of g.struct) {
      const o = offsets[f.name];
      if (o) for (let b = o[0]; b < Math.min(o[0] + o[1], p.payload.length); b++) colorOf[b] = ci;
      ci++;
    }
  }

  const pre = h('div', { class: 'hexdump mono' });
  const ascii = b => (b >= 0x20 && b <= 0x7E) ? String.fromCharCode(b) : '.';
  for (let row = 0; row < p.payload.length; row += 16) {
    const line = h('div', { class: 'hexline' });
    line.append(h('span', { class: 'off' }, row.toString(16).padStart(4, '0')));
    const hexPart = h('span', { class: 'bytes' });
    let asciiStr = '';
    for (let i = row; i < Math.min(row + 16, p.payload.length); i++) {
      const b = p.payload[i];
      const cls = colorOf[i] >= 0 ? ` c${colorOf[i] % 8}` : '';
      hexPart.append(h('span', { class: 'byte' + cls, title: `offset ${i}` },
        b.toString(16).padStart(2, '0')));
      asciiStr += ascii(b);
    }
    line.append(hexPart, h('span', { class: 'ascii' }, asciiStr));
    pre.append(line);
  }
  wrap.append(pre);

  wrap.append(h('div', { class: 'pkt-meta mono' },
    `src=${hexByte(p.src)} dst=${hexByte(p.dst)} cmd_set=${hexByte(p.cmdSet)} ` +
    `cmd_id=${hexByte(p.cmdId)} version=0x${p.version.toString(16).padStart(2, '0')} ` +
    `seq=[${p.seq.join(', ')}] payload=${p.payload.length} B`));
  return wrap;
}

// ---------------------------------------------------------------------------
// Export view
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Minimal Python syntax highlighting for the export preview
// ---------------------------------------------------------------------------

const PY_KEYWORDS = new Set([
  'def', 'class', 'return', 'if', 'else', 'elif', 'for', 'while', 'in',
  'is', 'not', 'and', 'or', 'None', 'True', 'False', 'from', 'import',
  'pass', 'lambda', 'try', 'except', 'raise', 'with', 'as',
]);

function highlightPython(code) {
  const pre = h('pre', { class: 'code mono' });
  const re = /(#[^\n]*)|("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|(@\w+)|\b(\d+\.?\d*|0[xX][0-9a-fA-F]+)\b|\b([A-Za-z_]\w*)\b|([\s\S])/g;
  let m;
  let afterDef = false;
  while ((m = re.exec(code)) !== null) {
    const [, comment, str, dec, num, word, other] = m;
    if (comment !== undefined) {
      pre.append(h('span', { class: 'py-com' }, comment));
      afterDef = false;
    } else if (str !== undefined) {
      pre.append(h('span', { class: 'py-str' }, str));
    } else if (dec !== undefined) {
      pre.append(h('span', { class: 'py-dec' }, dec));
    } else if (num !== undefined) {
      pre.append(h('span', { class: 'py-num' }, num));
    } else if (word !== undefined) {
      if (PY_KEYWORDS.has(word)) {
        pre.append(h('span', { class: 'py-kw' }, word));
        afterDef = word === 'def' || word === 'class';
      } else if (afterDef) {
        pre.append(h('span', { class: 'py-def' }, word));
        afterDef = false;
      } else {
        pre.append(word);
      }
    } else {
      pre.append(other);
      if (other === '\n') afterDef = false;
    }
  }
  return pre;
}

function exportState() {
  const groups = {};
  for (const [k, g] of state.groups) {
    const extraction = extractGroupFields(g);
    // fields whose decoded values are ever non-integer get pround(2) in the
    // export even without an explicit precision choice
    const floatFields = [...extraction.series.entries()]
      .filter(([, vals]) => vals.some(v => typeof v === 'number' && !Number.isInteger(v)))
      .map(([key]) => key);
    // an unmodified prefilled struct layout already exists in eflib/model -
    // no point regenerating the class
    const structIsDefault = g.mode === 'struct' &&
      JSON.stringify(g.struct?.map(f => ({ name: f.name, fmt: f.fmt }))) ===
      JSON.stringify((V2_STRUCTS[g.modelName] ?? []).map(f => ({ name: f.name, fmt: f.fmt })));
    groups[k] = { ...g, latestInterps: extraction.interps, floatFields, structIsDefault };
  }
  return { info: state.info, groups };
}

function renderExport(g, extraction) {
  const wrap = h('div', { class: 'export-wrap' });
  const st = exportState();
  const python = generatePython(st);
  const bundle = buildExportBundle(st);

  wrap.append(h('div', { class: 'export-actions' },
    h('button', { onclick: () => {
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
      const a = h('a', {
        href: URL.createObjectURL(blob),
        download: `${state.info?.snPrefix ?? 'device'}_annotations.json`,
      });
      a.click();
      URL.revokeObjectURL(a.href);
    } }, '⬇ download bundle (.json)'),
    h('button', { onclick: () => navigator.clipboard.writeText(python) },
      '⧉ copy Python'),
    h('label', { class: 'small file-label' }, 'import annotations…',
      h('input', { type: 'file', accept: '.json', style: 'display:none',
        onchange: async e => {
          const f = e.target.files[0];
          if (f) await loadDumpText(await f.text(), f.name);
        } })),
  ));
  wrap.append(highlightPython(python));
  return wrap;
}

// ---------------------------------------------------------------------------
// Guided tour
// ---------------------------------------------------------------------------

const TOUR_STEPS = [
  {
    icon: '👋',
    title: 'Welcome!',
    text: 'This tool analyzes diagnostics dumps from the ha-ef-ble ' +
      'integration: inspect every raw field a device sends, annotate them, ' +
      'and export paste-ready Python for new sensors. This quick tour shows ' +
      'the main pieces.',
    items: [
      ['navigate', 'move with `→` and `←` (also `l`/`h` for vim enjoyers, ' +
        '`d`/`a` for gamers)'],
      ['dots below', 'click one to jump straight to that step'],
      ['leave', 'press `Esc` any time - restart from the ? help menu'],
    ],
  },
  {
    selector: '#file-input',
    parent: true,
    icon: '📂',
    title: 'Load a dump',
    text: 'Open a diagnostics JSON here or drag it anywhere onto the page.',
    rich: [
      'Before downloading it in Home Assistant, open the integration ',
      'options and make sure ', { on: 'Enable packet collection' },
      ' is enabled and ', { off: 'Encrypt diagnostics data' },
      ' is disabled - then press "Download diagnostics" on the device page.',
      { br: true },
      'Once you are done capturing, re-enable ',
      { on: 'Encrypt diagnostics data' },
      ' - unencrypted dumps contain your device serial number and usage data.',
      { br: true },
      { warn: '⚠ Never share an unencrypted diagnostics file publicly - it ' +
        'contains sensitive data: your serial number and, for some devices, ' +
        'even full GPS location. Share the exported annotation bundle ' +
        'instead, or an encrypted dump.' },
    ],
  },
  {
    selector: '#group-list',
    icon: '📦',
    title: 'Packet groups',
    text: 'Decoded packets are grouped by source and command. The biggest ' +
      'group is usually the device heartbeat - start there. A green badge ' +
      'counts annotated fields.',
  },
  {
    selector: '.toolbar',
    icon: '⚙️',
    title: 'Decode config',
    text: 'Known devices are configured automatically - the green ✓ button ' +
      'shows the active mapping and ↺ restores it if you stray.',
    items: [
      ['protobuf schema', 'decode with a bundled .proto message'],
      ['wire walk', 'schema-less decode for discovering unknown fields'],
      ['V2 struct', 'fixed-width binary layout for old devices'],
    ],
  },
  {
    selector: '.filter-bar',
    icon: '🔎',
    before: () => switchTourView('fields'),
    title: 'Filters',
    items: [
      ['only changing', 'hide fields whose value never moves'],
      ['hide implemented', 'hide ✓ fields already in ha-ef-ble - together ' +
        'they leave exactly the undiscovered fields'],
    ],
  },
  {
    selector: 'table.fields tbody tr',
    icon: '✏️',
    before: () => switchTourView('fields'),
    title: 'Annotate fields',
    text: 'Fill in a name, unit and scaling for fields you identify. The ' +
      'field key in the left column is clickable - let\'s open one…',
  },
  {
    selector: '.detail-panel',
    before: openFirstFieldDetail,
    icon: '📈',
    title: 'Field detail',
    text: 'Clicking a field key (or its trend sparkline) opens this panel.',
    items: [
      ['chart', 'value over the whole capture - hover for exact values; ' +
        'enum and bool fields chart on a categorical axis'],
      ['stats', 'samples, changes, min / max / avg / last'],
      ['interpretations', 'all plausible readings of the raw wire value'],
      ['enums', 'set unit to "enum" and a mapper appears: name each raw ' +
        'value (0 → IDLE, 1 → CHARGING…) - exports as an IntFieldValue class'],
    ],
  },
  {
    selector: '.transform-wrap',
    parent: true,
    before: openFirstFieldDetail,
    demo: 'transform',
    icon: '🧪',
    title: 'Custom transforms',
    text: 'The "custom transform" input takes any expression over x (the ' +
      'raw value) and exports as a None-safe helper function:',
    items: [
      ['x', 'the raw decoded value'],
      ['+ - * / %', 'arithmetic and modulo'],
      ['<< >>', 'bit shifts'],
      ['& | ^ ~', 'bitwise and, or, xor, not'],
      ['0xff', 'hex literals, plus ( ) grouping'],
      ['x / 10 - 273.15', 'example: deci-Kelvin → °C'],
      ['(x >> 8) & 0xff', 'example: extract the high byte'],
    ],
  },
  {
    selector: '.filter-bar button',
    icon: 'ƒ',
    before: () => switchTourView('fields'),
    demo: 'combined',
    title: 'Combined fields',
    text: 'This button adds a virtual field computed from other annotated ' +
      'fields - useful when the device reports parts but not the total. ' +
      'Reference fields by their annotated names; it exports as ' +
      '@computed_field.',
  },
  {
    icon: '🎰',
    selector: '.enum-editor',
    before: tourEnumDemo,
    title: 'Enum fields',
    text: 'Fields that cycle through a few integer states are enums. Set ' +
      'the unit to `enum` (the tour just did) and this mapper appears, ' +
      'listing every observed raw value with its count.',
    items: [
      ['NAME', 'name each value (0 → IDLE, 1 → CHARGING…) - values then ' +
        'display and chart as states, and export as an IntFieldValue class'],
      ['translation', 'optional per-value display name for ' +
        'translations/en.json'],
      ['+ value', 'add codes the capture never showed'],
    ],
  },
  {
    icon: '⊞',
    selector: '.badge.groupable',
    before: () => { switchTourView('fields'); tourUndoGroup(); },
    title: 'Field groups',
    text: 'Numbered families like pow_get_4p8_1 / pow_get_4p8_2 carry this ' +
      'badge - clicking it groups the whole family into one declaration ' +
      'on the spot (and the green counter ungroups it again).',
  },
  {
    icon: '⊞',
    selector: '.group-btn',
    before: openGroupableDetail,
    title: 'Or group from the details',
    text: 'The detail panel offers the same grouping plus "max n" to cap ' +
      'the index range if the tail values are garbage. Hit next and the ' +
      'tour presses the button for you…',
  },
  {
    icon: '✨',
    selector: '.badge.grouped',
    before: tourGroupIt,
    title: 'Grouped!',
    text: 'The family collapsed into a single row - the green counter shows ' +
      'how many members it covers, and the name became a template (the {n} ' +
      'placeholder resolves to each index). It exports as ONE ' +
      'pb_field_group declaration.',
  },
  {
    icon: '📊',
    selector: '.member-picker',
    before: tourGroupIt,
    title: 'Inspect individual members',
    items: [
      ['n=1 n=2 …', 'these buttons switch the chart and stats between ' +
        'individual members of the group'],
      ['ungroup', 'restores the individual rows if you change your mind ' +
        '(the tour will undo this demo group for you)'],
    ],
  },
  {
    icon: '🗂️',
    selector: '.view-tabs',
    title: 'Now let\'s go over the views',
    text: 'These tabs are four ways to look at the same packet group - ' +
      'switching is one click. We\'ll walk through Changes, Hex and ' +
      'Export next.',
  },
  {
    icon: 'Δ',
    selector: ['.view-tab.active', '.view-body'],
    before: () => switchTourView('changes'),
    title: 'Changes tab',
    text: 'Every field change in order - static noise stays out of the way.',
    items: [
      ['workflow', 'while diagnostics collect, toggle a feature in the ' +
        'EcoFlow app and note the time'],
      ['then', 'find that moment here - the field that changed is your ' +
        'candidate'],
    ],
  },
  {
    icon: '⌗',
    selector: ['.view-tab.active', '.view-body'],
    before: () => switchTourView('hex'),
    title: 'Hex tab',
    text: 'The raw payload of each packet.',
    items: [
      ['navigate', 'step through packets with the slider or ◀ ▶'],
      ['offsets', 'hover a byte to see its position'],
      ['colors', 'V2 struct fields color the bytes they occupy'],
      ['copy', 'grab the payload or the whole frame as hex'],
    ],
  },
  {
    icon: '⬇',
    selector: ['.view-tab.active', '.view-body'],
    before: () => switchTourView('export'),
    title: 'Export tab',
    text: 'The result of your work, in two formats. Already-implemented ✓ ' +
      'fields are excluded automatically.',
    items: [
      ['Python', 'paste-ready pb_field / raw_field lines with eflib ' +
        'transforms, computed fields, a .proto snippet and a ' +
        'translations/en.json block'],
      ['.json bundle', 're-importable - drop it on the page later to ' +
        'restore or share annotations'],
    ],
  },
  {
    selector: '.export-actions button',
    icon: '🐞',
    before: () => switchTourView('export'),
    title: 'Found new fields?',
    text: 'This button downloads the annotation bundle. If you identified ' +
      'fields that ha-ef-ble does not expose yet, attach that .json to a ' +
      'GitHub issue on ha-ef-ble - it gives the developers everything they ' +
      'need to add the sensors: field mapping, unit, scaling and your notes.',
  },
  {
    selector: '#help-btn',
    icon: '💡',
    before: () => switchTourView('fields'),
    title: 'Help',
    text: 'The full written guide lives behind this button - it also lets ' +
      'you restart this tour. Have fun reverse-engineering!',
  },
];

function miniChart(points) {
  const W = 320, H = 90, L = 40, R = 6, T = 8, B = 6;
  const vs = points.map(p => p.v);
  let v0 = Math.min(...vs), v1 = Math.max(...vs);
  if (v0 === v1) { v0 -= 1; v1 += 1; }
  const x = i => L + (i / (points.length - 1)) * (W - L - R);
  const y = v => H - B - ((v - v0) / (v1 - v0)) * (H - T - B);
  const svg = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, class: 'chart demo' });
  for (const v of [v0, v1]) {
    svg.append(svgEl('line', { x1: L, x2: W - R, y1: y(v), y2: y(v), class: 'grid' }));
    svg.append(svgEl('text', {
      x: L - 4, y: y(v) + 3, class: 'tick', 'text-anchor': 'end' }, fmtTick(v)));
  }
  svg.append(svgEl('polyline', {
    points: points.map((p, i) => `${x(i)},${y(p.v)}`).join(' '),
    class: 'line', fill: 'none',
  }));
  return svg;
}

function expressionDemo({ label, initial, fields, lookups }) {
  // live playground built on the real hybrid builder: click chips or type,
  // the curve redraws on every change
  const chartWrap = h('div', { class: 'tour-demo-chart' });
  const draw = expr => {
    let pts = null;
    try {
      pts = lookups.map((lookup, i) => ({ t: i, v: evalExpr(expr, lookup) }));
      if (!pts.every(p => typeof p.v === 'number' && Number.isFinite(p.v))) pts = null;
    } catch { pts = null; }
    chartWrap.replaceChildren(
      pts ? miniChart(pts) : h('div', { class: 'demo-err' }, 'invalid expression'));
  };
  const builder = exprBuilder({
    value: initial, fields, onChange: draw, stateKey: `demo:${label}`,
  });
  draw(initial);
  return h('div', { class: 'tour-demo' },
    h('div', { class: 'tour-demo-label' }, label),
    builder, chartWrap);
}

function transformDemo() {
  const raw = [3031, 3032, 3034, 3038, 3045, 3052, 3055, 3050, 3042, 3036, 3033, 3031];
  return expressionDemo({
    label: 'try it - raw values are battery temps in deci-Kelvin:',
    initial: 'x / 10 - 273.15',
    fields: ['x'],
    lookups: raw.map(v => n => n === 'x' ? v : null),
  });
}

function combinedDemo() {
  // two series a device reports separately, merged into one virtual field
  const acIn = [120, 140, 180, 220, 200, 160, 120, 100, 90, 110, 150, 190];
  const dcOut = [80, 90, 100, 110, 105, 95, 85, 80, 78, 82, 92, 102];
  return expressionDemo({
    label: 'try it:',
    initial: 'ac_in_power - dc_out_power',
    fields: ['ac_in_power', 'dc_out_power'],
    lookups: acIn.map((_, i) =>
      n => ({ ac_in_power: acIn[i], dc_out_power: dcOut[i] })[n] ?? null),
  });
}

const TOUR_DEMOS = { transform: transformDemo, combined: combinedDemo };

// `x` segments in tour item text become keyboard-key chips
function renderKbd(text) {
  return text.split(/`([^`]+)`/).map((seg, i) =>
    i % 2 ? h('kbd', {}, seg) : seg);
}

function switchTourView(view) {
  if (state.view !== view) {
    state.view = view;
    render();
  }
}

function tourEnumDemo() {
  switchTourView('fields');
  const g = currentGroup();
  if (!g) return;
  if (state._tourEnum) {
    state.detailField = state._tourEnum.key;
    render();
    return;
  }
  const { series } = extractGroupFields(g);
  // a small-domain integer field that nobody annotated yet
  let key = series.has('flow_info_typec2') ? 'flow_info_typec2' : null;
  if (!key) {
    for (const [k, vals] of series) {
      if (g.fields[k]?.name || g.fields[k]?.partOf || g.fields[k]?.group) continue;
      const nums = [...new Set(vals.filter(v => typeof v === 'number' && Number.isInteger(v)))];
      if (nums.length >= 2 && nums.length <= 5) { key = k; break; }
    }
  }
  if (!key) return;
  const ann = annOf(g, key);
  const created = !ann.unit;
  if (created) ann.unit = 'enum';
  state._tourEnum = { groupKey: state.selectedGroup, key, created };
  state.detailField = key;
  state._tourOpenedDetail = true;
  saveAnnotations();
  render();
}

function findGroupableKey() {
  const g = currentGroup();
  if (!g || g.mode === 'wire') return null;
  const { fieldKeys } = extractGroupFields(g);
  for (const key of fieldKeys) {
    if (g.fields[key]?.group || g.fields[key]?.partOf || g.fields[key]?.name) continue;
    const cand = groupCandidates(key, fieldKeys);
    if (!cand) continue;
    if (cand.members.some(m => g.fields[m.key]?.name ||
        g.fields[m.key]?.partOf || g.fields[m.key]?.group)) continue;
    return { key, cand };
  }
  return null;
}

function tourUndoGroup() {
  if (!state._tourGrouped) return;
  const g = state.groups.get(state._tourGrouped.groupKey);
  if (g?.fields[state._tourGrouped.anchor]?.group) {
    ungroupField(g, state._tourGrouped.anchor);
  }
  state._tourGrouped = null;
}

function openGroupableDetail() {
  switchTourView('fields');
  tourUndoGroup();
  const found = findGroupableKey();
  if (found) {
    state.detailField = found.key;
    state._tourOpenedDetail = true;
    render();
  }
}

function tourGroupIt() {
  switchTourView('fields');
  const g = currentGroup();
  if (state._tourGrouped) return;   // already done (back/forward navigation)
  const found = findGroupableKey();
  if (!g || !found) return;
  state.detailField = found.key;
  const ann = annOf(g, found.key);
  ann.group = {
    match: found.cand.pattern,
    members: found.cand.members.map(m => m.key),
    start: found.cand.members[0].n,
  };
  for (const m of found.cand.members) {
    if (m.key !== found.key) {
      g.fields[m.key] = { ...defaultAnnotation(), partOf: found.key };
    }
  }
  state._tourGrouped = { groupKey: state.selectedGroup, anchor: found.key };
  saveAnnotations();
  render();
}

function openFirstFieldDetail() {
  switchTourView('fields');
  if (state.detailField != null) return;
  const g = currentGroup();
  if (!g) return;
  const { fieldKeys } = extractGroupFields(g);
  if (fieldKeys.length) {
    state.detailField = fieldKeys[0];
    state._tourOpenedDetail = true;
    render();
  }
}

async function startTour() {
  // most tour targets need data - load the bundled sample if nothing is open
  if (!state.packets.length) {
    try {
      const resp = await fetch('test_dump.json');
      await loadDumpText(await resp.text(), 'test_dump.json (sample)');
    } catch { /* offline / file missing - tour still runs, steps skip */ }
  }
  let idx = 0;

  const overlay = h('div', { class: 'tour-overlay' });
  const spotlight = h('div', { class: 'tour-spotlight' });
  const tip = h('div', { class: 'tour-tip' });
  overlay.append(spotlight, tip);
  document.body.append(overlay);

  // arrows for everyone, h/l for vim hands, a/d for gamers
  const keyNav = e => {
    const target = e.target;
    if (target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' ||
        target.isContentEditable)) return;
    const next = ['ArrowRight', 'l', 'd', 'Enter', ' '].includes(e.key);
    const back = ['ArrowLeft', 'h', 'a'].includes(e.key);
    if (e.key === 'Escape') { e.preventDefault(); finish(); return; }
    if (!next && !back) return;
    e.preventDefault();
    if (back) { if (idx > 0) { idx--; show(); } return; }
    idx++;
    if (idx >= TOUR_STEPS.length) finish(); else show();
  };
  document.addEventListener('keydown', keyNav, true);

  // reposition spotlight + tooltip when the window is resized or moved to a
  // screen with a different geometry
  let resizeTimer = null;
  const onResize = () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => show(), 100);
  };
  window.addEventListener('resize', onResize);

  const finish = () => {
    document.removeEventListener('keydown', keyNav, true);
    window.removeEventListener('resize', onResize);
    overlay.remove();
    tourUndoGroup();
    if (state._tourEnum) {
      const g = state.groups.get(state._tourEnum.groupKey);
      const ann = g?.fields[state._tourEnum.key];
      if (ann && state._tourEnum.created) delete g.fields[state._tourEnum.key];
      state._tourEnum = null;
      saveAnnotations();
    }
    if (state._tourOpenedDetail) {
      state._tourOpenedDetail = false;
      state.detailField = null;
    }
    // land back on the field table whatever tab the tour ended on
    state.view = 'fields';
    render();
    try { localStorage.setItem('efdiag:tour-done', '1'); } catch { /* ignore */ }
  };

  const resolveTarget = step => {
    step.before?.();   // e.g. open the detail panel or switch the tab first
    const selectors = Array.isArray(step.selector)
      ? step.selector : step.selector ? [step.selector] : [];
    const els = selectors.map(s => document.querySelector(s)).filter(Boolean);
    if (els.length && step.parent) els[0] = els[0].parentElement;
    return els.length ? els : null;
  };

  const unionRect = els => {
    const rects = els.map(e => e.getBoundingClientRect());
    const left = Math.min(...rects.map(r => r.left));
    const top = Math.min(...rects.map(r => r.top));
    return {
      left, top,
      width: Math.max(...rects.map(r => r.right)) - left,
      height: Math.max(...rects.map(r => r.bottom)) - top,
      right: Math.max(...rects.map(r => r.right)),
      bottom: Math.max(...rects.map(r => r.bottom)),
    };
  };

  const show = () => {
    while (idx < TOUR_STEPS.length) {
      const step = TOUR_STEPS[idx];
      if (!step.selector || resolveTarget(step)) break;
      idx++;   // target not on screen (e.g. no dump) - skip the step
    }
    if (idx >= TOUR_STEPS.length) { finish(); return; }
    const step = TOUR_STEPS[idx];
    const el = resolveTarget(step);

    if (el) {
      // targets inside scrollable panels may be out of view
      const pre = el[0].getBoundingClientRect();
      if (pre.top < 0 || pre.bottom > innerHeight) {
        el[0].scrollIntoView({ block: 'nearest' });
      }
      const r = unionRect(el);
      spotlight.style.display = 'block';
      spotlight.style.left = `${r.left - 6}px`;
      spotlight.style.top = `${r.top - 6}px`;
      spotlight.style.width = `${r.width + 12}px`;
      spotlight.style.height = `${r.height + 12}px`;
    } else {
      spotlight.style.display = 'none';
    }

    // replaceChildren is raw DOM - a literal null would render as "null"
    tip.replaceChildren(...[
      h('div', { class: 'tour-progress' },
        h('div', {
          class: 'tour-progress-fill',
          style: `width: ${((idx + 1) / TOUR_STEPS.length) * 100}%`,
        })),
      h('div', { class: 'tour-head' },
        step.icon ? h('span', { class: 'tour-icon' }, step.icon) : null,
        h('h3', {}, step.title),
        h('span', { class: 'spacer' }),
        // skip lives up here, away from back/next, so it cannot be fat-fingered
        h('button', { class: 'tour-skip', onclick: finish }, 'skip tour'),
      ),
      step.text ? h('p', {}, step.text) : null,
      ...(step.rich ? (() => {
        // {br: true} splits the rich text into separate paragraphs
        const paras = [[]];
        for (const seg of step.rich) {
          if (seg && seg.br) paras.push([]);
          else paras[paras.length - 1].push(seg);
        }
        return paras.map(segs =>
          segs.length === 1 && segs[0]?.warn
            ? h('p', { class: 'tour-warn' }, segs[0].warn)
            : h('p', {}, ...segs.map(seg =>
                typeof seg === 'string' ? seg
                  : seg.on ? h('span', { class: 'opt-chip on' }, seg.on, ' ✔')
                  : h('span', { class: 'opt-chip off' }, seg.off, ' ✘'))));
      })() : []),
      ...(step.items ?? []).map(([term, text]) =>
        h('div', { class: 'help-item' },
          h('span', { class: 'help-term' }, term),
          h('span', { class: 'help-text' }, ...renderKbd(text)))),
      step.demo ? TOUR_DEMOS[step.demo]() : null,
      h('div', { class: 'tour-nav' },
        h('span', { class: 'tour-dots' },
          ...TOUR_STEPS.map((s, i) =>
            h('span', {
              class: i === idx ? 'dot active' : i < idx ? 'dot done' : 'dot',
              dataset: { tip: `${i + 1}. ${s.title}` },
              onclick: () => { idx = i; show(); },
            }))),
        h('span', { class: 'spacer' }),
        idx > 0 ? h('button', { class: 'small', onclick: () => { idx--; show(); } }, '← back') : null,
        h('button', { class: 'small primary', onclick: () => {
          idx++;
          if (idx >= TOUR_STEPS.length) finish(); else show();
        } }, idx + 1 >= TOUR_STEPS.length ? 'done ✓' : 'next →'),
      ),
    ].filter(Boolean));
    // retrigger the entrance animation on each step change
    tip.classList.remove('pop');
    void tip.offsetWidth;
    tip.classList.add('pop');

    // position AFTER content is in the DOM so the real tip height is known
    // and it never gets cropped by the viewport
    const tipH = tip.offsetHeight;
    const tipW = Math.min(460, innerWidth * 0.92);
    if (el) {
      const r = unionRect(el);
      const spaceBelow = innerHeight - r.bottom - 22;
      const spaceAbove = r.top - 22;
      let tipTop, tipLeft;
      if (spaceBelow >= tipH) {
        tipTop = r.bottom + 12;
        tipLeft = Math.min(Math.max(10, r.left), innerWidth - tipW - 10);
      } else if (spaceAbove >= tipH) {
        tipTop = r.top - tipH - 12;
        tipLeft = Math.min(Math.max(10, r.left), innerWidth - tipW - 10);
      } else {
        // target fills the screen (e.g. a whole tab panel) - tuck the tip
        // into its bottom-right corner, over the least important content
        tipTop = Math.max(10, r.bottom - tipH - 16);
        tipLeft = r.right - tipW - 16;
      }
      tipTop = Math.min(Math.max(10, tipTop), Math.max(10, innerHeight - tipH - 10));
      tip.style.top = `${tipTop}px`;
      tip.style.left = `${Math.min(Math.max(10, tipLeft), innerWidth - tipW - 10)}px`;
    } else {
      tip.style.top = `${Math.max(10, innerHeight / 2 - tipH / 2)}px`;
      tip.style.left = `${innerWidth / 2 - tipW / 2}px`;
    }
    // whatever branch positioned it: never let the tip leave the viewport
    const finalTop = parseFloat(tip.style.top);
    const finalLeft = parseFloat(tip.style.left);
    tip.style.top = `${Math.min(Math.max(10, finalTop),
      Math.max(10, innerHeight - tipH - 10))}px`;
    tip.style.left = `${Math.min(Math.max(10, finalLeft),
      Math.max(10, innerWidth - tipW - 10))}px`;
  };
  show();
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

// Help content: items are plain text, or [term, text] pairs rendered as a
// highlighted term chip followed by its explanation.
const HELP_SECTIONS = [
  { icon: '📥', title: 'Get a diagnostics dump', items: [
    ['Configure', 'Settings → Devices & services → EcoFlow BLE → Configure: ' +
      'enable "Enable packet collection" and DISABLE "Encrypt diagnostics ' +
      'data" - encrypted dumps (the default) can only be read by the maintainer.'],
    ['Capture', 'let the device run so packets accumulate; toggle things in ' +
      'the EcoFlow app meanwhile if you want to identify specific fields.'],
    ['Download', 'press the "Download diagnostics" button on the device ' +
      'page in Home Assistant.'],
    ['Afterwards', 're-enable "Encrypt diagnostics data" - unencrypted ' +
      'dumps contain your device serial number and usage data.'],
  ] },
  { icon: '📂', title: 'Load it', items: [
    'Drag the JSON anywhere onto the page, or use "Open dump…". Packets are ' +
    'decrypted, reassembled and grouped by source + command (left sidebar). ' +
    'The biggest group is usually the heartbeat.',
    ['auto-mapped ✓', 'known devices get the right schema (or V2 struct ' +
      'layout) preselected, and fields already implemented in ha-ef-ble are ' +
      'prefilled and marked with a blue ✓.'],
  ] },
  { icon: '🔍', title: 'Identify fields', items: [
    ['Fields tab', 'every decoded field with raw + annotated value, change ' +
      'count and a trend sparkline. Click a field key to open the detail ' +
      'panel: time chart, stats and all annotation inputs.'],
    ['Changes tab', 'what changed, packet by packet - whatever you switched ' +
      'in the app during capture shows up here at that moment.'],
    ['only changing', 'hides static fields.'],
    ['hide implemented', 'hides ✓ fields - leaving exactly the undiscovered ones.'],
    ['wire walk', 'schema-less decode showing every protobuf field by ' +
      'number with all plausible readings (uint / sint / float…) - pick one ' +
      'with the interp dropdown.'],
    ['struct builder', 'for V2 devices: define fields with Python struct ' +
      'chars (B, H, I, i, f, 4s…); bytes are color-coded in the Hex tab.'],
  ] },
  { icon: '✏️', title: 'Annotate', items: [
    ['name', 'Python field name (snake_case) for the generated code.'],
    ['unit', 'free text with suggestions - W, V, mAh, K, mΩ…'],
    ['÷ × prec neg bit', 'simple transforms matching eflib helpers: pdiv, ' +
      'pmultiply, pround, out_power, prop_has_bit_on.'],
    ['custom transform', 'any expression over x, e.g. "x / 10 - 273.15" or ' +
      '"(x >> 8) & 0xff" - exports as a None-safe helper function (detail panel).'],
    ['+ combined field', 'expression over other annotated names, e.g. ' +
      '"ac_in_power + dc_in_power" - exports as @computed_field.'],
    ['enum mapping', 'set unit to "enum" and the detail panel opens a value ' +
      'mapper: name every observed raw value (0 → IDLE, 1 → CHARGING…) - ' +
      'exports as an IntFieldValue class with state translations.'],
    ['translation', 'entity display name for translations/en.json; defaults ' +
      'to the title-cased field name (detail panel).'],
    ['offset', 'bytes to skip before decoding for devices that prefix a ' +
      'routing header (SHP3 = 22) - in the toolbar.'],
    'Annotations save automatically per device SN prefix. Editing a ' +
    'prefilled ✓ field un-marks it so it gets exported.',
  ] },
  { icon: '📤', title: 'Export', items: [
    'Download the bundle (.json) or copy the generated Python from the ' +
    'Export tab.',
    ['Python', 'paste-ready pb_field / raw_field declarations with eflib ' +
      'transforms, a RawData model for changed V2 structs, a .proto snippet ' +
      'for unmapped wire fields, @computed_field blocks and a ' +
      'translations/en.json snippet.'],
    ['.json bundle', 're-importable: drop it onto the page (after loading ' +
      'a dump) to restore annotations - useful for sharing.'],
  ] },
  { icon: '💡', title: 'Tips', items: [
    ['resize', 'drag column edges; double-click a grip to reset widths.'],
    ['XOR payload', 'auto-selected per device; toggle it if values look ' +
      'like a rising/falling sawtooth - it re-decodes immediately.'],
    ['↺ auto', 'restores the correct schema if you changed the decode ' +
      'config while exploring.'],
  ] },
];

function showHelp() {
  const overlay = h('div', { class: 'help-overlay', onclick: e => {
    if (e.target === overlay) overlay.remove();
  } });
  const box = h('div', { class: 'help-box' },
    h('div', { class: 'help-head' },
      h('h2', {}, 'How to use the analyzer'),
      h('span', { class: 'spacer' }),
      h('button', { class: 'small', onclick: () => {
        overlay.remove(); startTour();
      } }, '↻ restart tour'),
      h('button', { class: 'small', onclick: () => overlay.remove() }, '✕ close'),
    ),
    ...HELP_SECTIONS.map((sec, i) =>
      h('section', { class: 'help-sec' },
        h('h3', {},
          h('span', { class: 'help-icon' }, sec.icon),
          i < 5 ? h('span', { class: 'help-step' }, String(i + 1)) : null,
          sec.title),
        ...sec.items.map(item => Array.isArray(item)
          ? h('div', { class: 'help-item' },
              h('span', { class: 'help-term' }, item[0]),
              h('span', { class: 'help-text' }, item[1]))
          : h('p', { class: 'help-para' }, item)),
      )),
  );
  overlay.append(box);
  document.body.append(overlay);
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

function init() {
  $('help-btn').addEventListener('click', showHelp);
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') document.querySelector('.help-overlay')?.remove();
  });

  $('file-input').addEventListener('change', async e => {
    const f = e.target.files[0];
    // reset so selecting the same file path fires change again
    e.target.value = '';
    if (f) await loadDumpText(await f.text(), f.name);
  });

  $('xor-toggle').addEventListener('change', async e => {
    state.xorPayload = e.target.checked;
    if (state.rawDump) {
      await loadDumpText(state.rawDump.text, state.rawDump.fileName, { keepXor: true });
    }
  });

  const drop = document.body;
  drop.addEventListener('dragover', e => { e.preventDefault(); });
  drop.addEventListener('drop', async e => {
    e.preventDefault();
    const f = e.dataTransfer.files[0];
    if (f) await loadDumpText(await f.text(), f.name);
  });

  render();

  let tourDone = null;
  try { tourDone = localStorage.getItem('efdiag:tour-done'); } catch { /* ignore */ }
  if (!tourDone) startTour();
}

init();
