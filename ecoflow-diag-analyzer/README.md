# ecoflow-diag-analyzer

Browser-only analyzer for [ha-ef-ble](https://github.com/rabits/ha-ef-ble)
diagnostics dumps. Load a dump, inspect every raw field the device sends,
annotate fields (name, unit, scaling, precision, combined expressions), and
export the annotations as paste-ready Python for implementing new sensors.

**Live:** [https://gnox.github.io/ecoflow-diag-analyzer/](https://gnox.github.io/ecoflow-diag-analyzer/)

## What it does

Reimplements the eflib decode pipeline in the browser:

1. Reads `raw_data_connection` / `raw_data_messages` (raw BLE notifications)
   from the dump, plus `session_key` + `iv`
2. Frame reassembly per `encrypt_type` from the scan record: 0 = plain,
   1 = raw-header AES, 7 = EncPacket (0x5A5A) AES
3. AES-CBC decrypt (WebCrypto), packet parsing for V2 / V3 / V19 / V4
   formats including seq-XOR payload deobfuscation
4. Groups packets by `src→dst cmd_set:cmd_id version` — the biggest group is
   usually the heartbeat

## Requirements

Configure the integration first (Settings → Devices & services → EcoFlow
BLE → Configure): enable **Enable packet collection** and disable
**Encrypt diagnostics data**, let packets accumulate, then use the
**Download diagnostics** button on the device page. Encrypted dumps (ECIES
to the developer key, the default) are rejected with a hint - only the
maintainer holds the private key to decrypt those. Re-enable encryption
once you are done capturing - unencrypted dumps contain the device serial
number and usage data.

## Auto-mapping

Known devices are recognized by SN prefix and each packet group is
pre-configured automatically: proto file + message type for V3 devices
(e.g. R6xx → `pr705.DisplayPropertyUpload`), full struct layouts from the
eflib `RawData` models for V2 devices (Delta 2 / River 2 / Wave 2 /
Delta Pro era). Manual selection is only needed for unknown groups.
Mappings live in `mappings.js`, generated from eflib by `gen_mappings.py` —
rerun it after device changes in ha-ef-ble. Your saved edits for a group
always win over the auto-mapping.

Fields already implemented in ha-ef-ble are **prefilled** (name, unit,
divisor/precision from the actual `pb_field`/`raw_field` transforms) and
marked with a blue ✓; the *hide implemented* filter leaves only the
undiscovered ones. Prefilled fields are excluded from the Python export
unless you edit them (any edit clears the "implemented" mark). Regenerate
with units by including the hass group:

```bash
uv run --project <ha-ef-ble> --group hass python gen_mappings.py <ha-ef-ble>
```

## Decode modes (per packet group)

- **wire walk** — schema-less protobuf decoding. Shows every field by wire
  path (`1`, `3.2`, …) with all plausible interpretations (uint / sint /
  float / …). This is the mode for discovering unknown fields.
- **protobuf schema** — decode with one of the bundled `.proto` files
  (shared with [ecoflow-ble-debug](../ecoflow-ble-debug/)); fields keyed by
  proto field name.
- **V2 struct** — fixed-width binary builder for old devices (Delta 2 /
  River 2 era). Define fields with Python `struct` format chars (`B H I i
  f 4s`…, little-endian) and watch decoded values update live; byte ranges
  are color-coded in the Hex view.

## Identifying fields

- **only changing** filter + **Changes** tab: toggle something in the
  EcoFlow app while diagnostics are collecting, then look at which fields
  changed at that moment (old → new per packet)
- sparklines show each field's trend across the whole dump
- hover a wire field to see all interpretations of its raw value

## Annotating

Per field: Python name, unit, divisor, multiplier, precision, negate
(output power), bit index (bitmask flags), wire interpretation. *Combined
fields* (`+ combined field`) accept expressions over annotated names, e.g.
`ac_in_power + dc_in_power`.

Annotations persist in localStorage per device SN prefix.

## Export

The Export tab produces one bundle:

- **JSON** — machine-readable annotations, re-importable into the tool
  (drop it like a dump)
- **Python** — generated `pb_field(...)` / `raw_field(...)` /
  `@computed_field` declarations using eflib transforms (`pdiv`, `pround`,
  `pmultiply`, `out_power`, `prop_has_bit_on`), plus a `.proto` snippet for
  wire-walk fields and a `RawData` model class for V2 structs

## Files

| File | Description |
|------|-------------|
| `index.html` | UI shell + styles |
| `app.js` | application: grouping, tables, timeline, hex view, export |
| `decode.js` | eflib port: CRC, AES-CBC, frame assemblers, packet parser, wire walker, struct decode |
| `annotate.js` | annotation model, expression eval, Python codegen |
| `mappings.js` | auto-generated device mappings (SN prefix → schema/struct per packet group) |
| `gen_mappings.py` | regenerates `mappings.js` from eflib (`uv run python gen_mappings.py <ha-ef-ble>`) |
| `test_dump.json` | synthetic V3 dump (River 3 style) for trying the tool |
| `test_dump_v2.json` | synthetic V2 dump (River 2 style, Type1 encryption) |

Proto schemas are reused from `../ecoflow-ble-debug/protos.js`;
protobuf.js is loaded from cdnjs.
