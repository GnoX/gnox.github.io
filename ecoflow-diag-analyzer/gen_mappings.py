# /// script
# dependencies = ["protobuf", "ecdsa", "crc", "PyCryptodome", "bleak", "bleak_retry_connector", "aiohttp"]
# ///
"""Generate mappings.js from ha-ef-ble eflib device implementations.

Emits per-device-prefix decode rules (packet group -> proto message or V2
struct layout) plus proto files missing from ecoflow-ble-debug's protos.js.
Run from this directory whenever eflib devices change:

    uv run python gen_mappings.py [path-to-ha-ef-ble]
"""

import json
import re
import sys
from inspect import get_annotations, getmro
from pathlib import Path
from typing import Annotated, get_args, get_origin

HA_EF_BLE = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("../../ha-ef-ble")
sys.path.insert(0, str(HA_EF_BLE.resolve()))

from custom_components.ef_ble.eflib.model import (  # noqa: E402
    DirectBmsMDeltaHeartbeatPack,
    DirectEmsDeltaHeartbeatPack,
    DirectInvDeltaHeartbeatPack,
    DirectMpptHeartbeatPack,
    DirectPdHeartbeatPack,
)
from custom_components.ef_ble.eflib.model.base import RawData  # noqa: E402
from custom_components.ef_ble.eflib.model.kt210_sac import KT210SAC  # noqa: E402


def struct_fields(cls: type[RawData]) -> list[dict]:
    """Extract [{name, fmt, orig}] walking the MRO like RawData does"""
    fields: list[dict] = []
    for klass in reversed(getmro(cls)):
        for name, annotation in get_annotations(klass).items():
            if get_origin(annotation) is not Annotated:
                continue
            _, *metadata = get_args(annotation)
            if not metadata:
                continue
            entry = {"name": name, "fmt": metadata[0]}
            if len(metadata) > 1:
                entry["orig"] = metadata[1]
            fields.append(entry)
    return fields


def resolve_heart_types() -> dict[str, type[RawData]]:
    """Resolve per-device pd/mppt heart model classes from device properties"""
    from custom_components.ef_ble.eflib.devices import delta2, delta2_max

    return {
        "delta2_pd": delta2.Device.pd_heart_type.fget(None),
        "delta2_mppt": delta2.Device.mppt_heart_type.fget(None),
        "delta2max_pd": delta2_max.Device.pd_heart_type.fget(None),
        "delta2max_mppt": delta2_max.Device.mppt_heart_type.fget(None),
    }


HEARTS = resolve_heart_types()

V2_MODELS: dict[str, type[RawData]] = {
    "DirectPdHeartbeatPack": DirectPdHeartbeatPack,
    "DirectEmsDeltaHeartbeatPack": DirectEmsDeltaHeartbeatPack,
    "DirectBmsMDeltaHeartbeatPack": DirectBmsMDeltaHeartbeatPack,
    "DirectInvDeltaHeartbeatPack": DirectInvDeltaHeartbeatPack,
    "DirectMpptHeartbeatPack": DirectMpptHeartbeatPack,
    "KT210SAC": KT210SAC,
    HEARTS["delta2_pd"].__name__: HEARTS["delta2_pd"],
    HEARTS["delta2_mppt"].__name__: HEARTS["delta2_mppt"],
    HEARTS["delta2max_pd"].__name__: HEARTS["delta2max_pd"],
    HEARTS["delta2max_mppt"].__name__: HEARTS["delta2max_mppt"],
}


def proto_package(proto_file: str) -> str:
    content = (HA_EF_BLE / "proto" / proto_file).read_text()
    m = re.search(r"^package\s+([a-zA-Z0-9_.]+)\s*;", content, re.MULTILINE)
    return m.group(1) if m else ""


def msg(proto_file: str, message: str | list[str]) -> dict:
    """Proto decode action; a list means the body decodes with every message
    (EcoFlow reuses one payload for e.g. Display + Runtime uploads)"""
    pkg = proto_package(proto_file)
    qualify = lambda m: f"{pkg}.{m}" if pkg else m  # noqa: E731
    return {
        "mode": "proto",
        "proto": proto_file,
        "message": (
            [qualify(m) for m in message]
            if isinstance(message, list)
            else qualify(message)
        ),
    }


def st(model: str) -> dict:
    return {"mode": "struct", "struct": model}


# Packet-match rules per device family, transcribed from each device's
# data_parse. src/cmdSet/cmdId of None = wildcard. offset skips a routing
# header at the start of the payload before decoding.
def rule(src, cmd_set, cmd_id, action, offset: int = 0) -> dict:
    out = {"src": src, "cmdSet": cmd_set, "cmdId": cmd_id, **action}
    if offset:
        out["offset"] = offset
    return out


DPU_RULES = [
    rule(0x02, 0x02, 0x01, msg("yj751_sys.proto", "AppShowHeartbeatReport")),
    rule(0x02, 0x02, 0x02, msg("yj751_sys.proto", "BackendRecordHeartbeatReport")),
    rule(0x02, 0x02, 0x03, msg("yj751_sys.proto", "APPParaHeartbeatReport")),
    rule(0x02, 0x02, 0x04, msg("yj751_sys.proto", "BpInfoReport")),
    rule(0x02, 0x0A, 0x20, msg("yj751_sys.proto", "CurrentNode")),
    rule(0x02, 0xFE, 0x15, msg("yj751_sys.proto", "DisplayPropertyUpload")),
    rule(0x02, 0x02, 0x17, msg("yj751_sys.proto", "DevRequest")),
]

DELTA2_COMMON = [
    rule(0x03, 0x20, 0x02, st("DirectEmsDeltaHeartbeatPack")),
    rule(0x03, 0x20, 0x32, st("DirectBmsMDeltaHeartbeatPack")),
    rule(0x06, 0x20, 0x32, st("DirectBmsMDeltaHeartbeatPack")),
    rule(0x04, None, 0x02, st("DirectInvDeltaHeartbeatPack")),
]

MAPPINGS = [
    # Delta 3 family (pd335)
    {
        "prefixes": ["P231", "P321", "P351", "D3N1", "D3M1", "D511", "D751",
                     "PR11", "PR12", "PR21"],
        "rules": [rule(0x02, 0xFE, 0x15, msg("pd335_sys.proto", "DisplayPropertyUpload"))],
    },
    # River 3 family (pr705)
    {
        "prefixes": ["R651", "R653", "R654", "R655", "R631", "R634", "R635"],
        "rules": [rule(0x02, 0xFE, 0x15, msg("pr705.proto", "DisplayPropertyUpload"))],
    },
    # Delta Pro 3 (mr521)
    {
        "prefixes": ["MR51", "MR54"],
        "rules": [rule(0x02, 0xFE, 0x15, msg("mr521.proto", "DisplayPropertyUpload"))],
    },
    # STREAM family (bk_series)
    {
        "prefixes": ["BK01", "BK02", "BK11", "BK12", "BK31", "BK41", "BK51",
                     "BK61", "ES11", "N011"],
        "rules": [rule(0x02, 0xFE, 0x15, msg("bk_series.proto", "DisplayPropertyUpload"))],
    },
    # Smart Generators (ge305)
    {
        "prefixes": ["G371", "G351"],
        "rules": [rule(0x08, 0xFE, 0x15, msg("ge305_sys.proto", "DisplayPropertyUpload"))],
    },
    # Alternator Charger (dc009)
    {
        "prefixes": ["F371", "F372", "DC01"],
        "rules": [rule(0x14, 0xFE, 0x15, msg("dc009_apl_comm.proto", "DisplayPropertyUpload"))],
    },
    # Wave 3 (ac517)
    {
        "prefixes": ["AC71"],
        "rules": [
            rule(0x42, 0xFE, 0x15, msg("ac517_apl_comm.proto", "DisplayPropertyUpload")),
            rule(0x42, 0xFE, 0x16, msg("ac517_apl_comm.proto", "RuntimePropertyUpload")),
        ],
    },
    # Delta Pro Ultra (yj751)
    {"prefixes": ["Y711"], "rules": DPU_RULES},
    # DPU X (pd100)
    {
        "prefixes": ["P101"],
        "rules": [rule(0x02, 0xFE, 0x15, msg("pd100.proto", "DisplayPropertyUpload"))],
    },
    # Smart Home Panel 3 (dev_apl_comm; V4 frames carry a 22-byte routing
    # header - device SN fragment (9) + envelope (13) - before the protobuf)
    {
        "prefixes": ["HR62", "HR63", "HR6C"],
        "rules": [
            rule(0x32, 0x40, 0x30,
                 msg("dev_apl_comm.proto", "DisplayPropertyUpload"), offset=22),
        ],
    },
    # OCEAN Pro inverter + panel (dev_apl_comm; same V4 framing as SHP3 but
    # telemetry src 0x30, and one body decodes as Display AND Runtime upload)
    {
        "prefixes": ["HR51", "HR61", "HR6B", "HR6D"],
        "rules": [
            rule(0x30, 0x40, 0x30,
                 msg("dev_apl_comm.proto",
                     ["DisplayPropertyUpload", "RuntimePropertyUpload"]),
                 offset=22),
        ],
    },
    # Smart Home Panel 2 (pd303, no payload XOR)
    {
        "prefixes": ["HD31"],
        "xor": False,
        "rules": [
            rule(0x0B, 0x0C, 0x01, msg("pd303.proto", "ProtoTime")),
            rule(0x0B, 0x0C, 0x20, msg("pd303.proto", "ProtoPushAndSet")),
            rule(0x0B, 0x0C, 0x21, msg("pd303.proto", "ProtoPushAndSet")),
        ],
    },
    # PowerStream (wn511)
    {
        "prefixes": ["HW51"],
        "rules": [
            rule(0x35, 0x14, 0x01, msg("wn511_sys.proto", "inverter_heartbeat")),
            rule(0x35, 0x14, 0x04, msg("wn511_sys.proto", "inv_heartbeat_type2")),
            rule(0x35, 0x14, 0x88, msg("wn511_sys.proto", "inv_power_pack")),
        ],
    },
    # PowerPulse EV chargers (cp307)
    {
        "prefixes": ["C101", "C102", "C103", "C371", "C372", "C373", "C374",
                     "C375", "C376"],
        "rules": [rule(0x02, 0x02, 0x21, msg("cp307_iot.proto", "HeartBeat"))],
    },
    # Delta 2 (V2 raw binary; the only Delta 2 variant that XORs payloads)
    {
        "prefixes": ["R331", "R335"],
        "rules": [
            rule(0x02, 0x20, 0x02, st(HEARTS["delta2_pd"].__name__)),
            rule(0x05, 0x20, 0x02, st(HEARTS["delta2_mppt"].__name__)),
            *DELTA2_COMMON,
        ],
    },
    # Delta 2 Plus / Black (V2 raw binary, no payload XOR)
    {
        "prefixes": ["R701", "D361"],
        "xor": False,
        "rules": [
            rule(0x02, 0x20, 0x02, st(HEARTS["delta2_pd"].__name__)),
            rule(0x05, 0x20, 0x02, st(HEARTS["delta2_mppt"].__name__)),
            *DELTA2_COMMON,
        ],
    },
    # Delta 2 Max family (V2 raw binary, no payload XOR)
    {
        "prefixes": ["R351", "R354", "P341"],
        "xor": False,
        "rules": [
            rule(0x02, 0x20, 0x02, st(HEARTS["delta2max_pd"].__name__)),
            rule(0x05, 0x20, 0x02, st(HEARTS["delta2max_mppt"].__name__)),
            *DELTA2_COMMON,
        ],
    },
    # River 2 family (V2 raw binary, no payload XOR)
    {
        "prefixes": ["R601", "R603", "R611", "R613", "R621", "R623"],
        "xor": False,
        "rules": [
            rule(0x02, 0x20, 0x02, st("DirectPdHeartbeatPack")),
            rule(0x05, 0x20, 0x02, st("DirectMpptHeartbeatPack")),
            *DELTA2_COMMON,
        ],
    },
    # Delta (Pro/Max/mini/original) V1-era raw binary
    {
        "prefixes": ["D8", "D5", "D1", "D2", "D3", "D4", "DB", "DA", "DD",
                     "DCA", "DCF", "R511", "Z0"],
        "rules": [
            rule(0x02, 0x20, 0x02, st("DirectPdHeartbeatPack")),
            rule(0x03, 0x20, 0x32, st("DirectBmsMDeltaHeartbeatPack")),
            rule(0x03, 0x20, 0x02, st("DirectEmsDeltaHeartbeatPack")),
            rule(0x04, 0x20, 0x02, st("DirectInvDeltaHeartbeatPack")),
            rule(0x05, 0x20, 0x02, st("DirectMpptHeartbeatPack")),
        ],
    },
    # Wave 2 (raw binary)
    {
        "prefixes": ["KT21"],
        "rules": [rule(0x42, 0x42, 0x50, st("KT210SAC"))],
    },
]

def extra_protos() -> list[str]:
    """Protos missing from or stale in ecoflow-ble-debug's protos.js

    The analyzer overrides `PROTO_FILES` entries with these, so it also picks
    up schemas that were updated in ha-ef-ble after protos.js was bundled.
    """
    import json as json_mod

    content = (Path(__file__).parent / "../ecoflow-ble-debug/protos.js").read_text()
    bundled: dict[str, str] = {}
    for m in re.finditer(r'"([a-z0-9_]+\.proto)":\s*("(?:[^"\\]|\\.)*")', content):
        bundled[m.group(1)] = json_mod.loads(m.group(2))
    out = []
    for p in sorted((HA_EF_BLE / "proto").glob("*.proto")):
        if bundled.get(p.name) != p.read_text():
            out.append(p.name)
    return out


# -----------------------------------------------------------------------------
# Known fields: introspect every Device class and export the already-implemented
# pb_field / raw_field mappings so the analyzer can prefill annotations.
# -----------------------------------------------------------------------------

_IDENTITY_CODE = (lambda x: x).__code__.co_code


def transform_annotation(fn) -> dict:
    """Reverse-engineer eflib transform closures into annotation values"""
    if fn is None:
        return {}

    # enum transforms are bound classmethods of an IntFieldValue subclass -
    # export the full value->NAME mapping so the analyzer prefills its enum
    # editor with what ha-ef-ble already knows
    from custom_components.ef_ble.eflib.props.enums import IntFieldValue

    bound = getattr(fn, "__self__", None)
    if isinstance(bound, type) and issubclass(bound, IntFieldValue):
        return {
            "unit": "enum",
            "enumMap": {
                int(m.value): m.name for m in bound if m.name != "UNKNOWN"
            },
        }

    qn = getattr(fn, "__qualname__", "")
    code = getattr(fn, "__code__", None)

    def cells() -> dict:
        closure = getattr(fn, "__closure__", None) or []
        return dict(
            zip(code.co_freevars, [c.cell_contents for c in closure], strict=False)
        )

    if code is None:
        return {"notes": f"transform: {fn!r}"}
    if "pdiv" in qn:
        c = cells()
        out = {"divisor": c.get("divisor")}
        if c.get("precision") is not None:
            out["precision"] = c["precision"]
        return out
    if "pround" in qn:
        return {"precision": cells().get("precision")}
    if "pmultiply" in qn:
        return {"multiplier": cells().get("x")}
    if qn == "out_power":
        return {"negate": True, "precision": 2}
    if "prop_has_bit_on" in qn:
        return {"bit": cells().get("bit_position")}
    if "prop_has_bit_off" in qn:
        return {"bit": cells().get("bit_position"), "notes": "inverted bit check"}
    if code.co_code == _IDENTITY_CODE and not code.co_freevars:
        return {}
    return {"notes": f"transform: {qn or fn!r}"}


def sensor_units() -> dict[str, str]:
    """Map device property name -> unit from the HA sensor descriptions"""
    try:
        from custom_components.ef_ble.sensor import SENSOR_TYPES
    except ImportError:
        print("homeassistant not importable - skipping units for known fields")
        return {}
    unit_fix = {"°C": "C", "°F": "F"}
    out = {}
    for name, desc in SENSOR_TYPES.items():
        unit = getattr(desc, "native_unit_of_measurement", None)
        if unit:
            out[name] = unit_fix.get(str(unit), str(unit))
        elif str(getattr(desc, "device_class", "")) == "enum":
            out[name] = "enum"
    return out


def select_enum_map(device_cls) -> dict[str, dict]:
    """Map field public_name -> enumMap for select controls backed by an
    IntFieldValue (fields whose transform alone doesn't reveal the enum)"""
    from custom_components.ef_ble.eflib.entity import controls
    from custom_components.ef_ble.eflib.props.enums import IntFieldValue

    out: dict[str, dict] = {}
    for klass in getmro(device_cls):
        for value in vars(klass).values():
            if not isinstance(value, controls.select):
                continue
            enum_cls = getattr(value, "_value_type", None)
            field = getattr(value, "field", None)
            if (
                enum_cls is None
                or field is None
                or not (
                    isinstance(enum_cls, type)
                    and issubclass(enum_cls, IntFieldValue)
                )
            ):
                continue
            out[field.public_name] = {
                int(m.value): m.name for m in enum_cls if m.name != "UNKNOWN"
            }
    return out


def known_fields() -> dict[str, dict[str, dict]]:
    from custom_components.ef_ble.eflib.devices import devices
    from custom_components.ef_ble.eflib.props.protobuf_field import ProtobufField
    from custom_components.ef_ble.eflib.props.raw_data_field import RawDataField

    units = sensor_units()
    known: dict[str, dict[str, dict]] = {}

    for module in devices:
        device_cls = getattr(module, "Device", None)
        if device_cls is None or not hasattr(device_cls, "_fields"):
            continue
        select_enums = select_enum_map(device_cls)
        raw_prefixes = getattr(device_cls, "SN_PREFIX", ())
        if isinstance(raw_prefixes, (bytes, str)):
            raw_prefixes = (raw_prefixes,)
        sn_prefixes = sorted({
            p.decode() if isinstance(p, bytes) else str(p) for p in raw_prefixes
        })
        for field in device_cls._fields:
            if isinstance(field, ProtobufField):
                message = field.pb_field.message_type.DESCRIPTOR.full_name
                key = ".".join(field.pb_field.attrs)
            elif isinstance(field, RawDataField):
                message = field.data_attr.message_type.__name__
                key = field.data_attr.attr
            else:
                continue
            ann = {"name": field.public_name}
            ann.update(transform_annotation(field._transform_value))
            if "enumMap" not in ann and field.public_name in select_enums:
                ann["unit"] = "enum"
                ann["enumMap"] = select_enums[field.public_name]
            if field.public_name in units and "unit" not in ann:
                ann["unit"] = units[field.public_name]
            # several devices can share a message but map different proto
            # attrs to the same name - record who owns each entry so the
            # analyzer prefills only fields of the dump's actual device
            existing = known.setdefault(message, {}).get(key)
            if existing is not None:
                existing["sn"] = sorted(set(existing.get("sn", [])) | set(sn_prefixes))
            else:
                ann["sn"] = sn_prefixes
                known[message][key] = ann

    return known


def main() -> None:
    structs = {name: struct_fields(cls) for name, cls in V2_MODELS.items()}
    extra = {
        name: (HA_EF_BLE / "proto" / name).read_text() for name in extra_protos()
    }

    known = known_fields()
    out = Path(__file__).parent / "mappings.js"
    out.write_text(
        "// AUTO-GENERATED by gen_mappings.py - do not edit by hand.\n"
        "// Regenerate after eflib device changes:\n"
        "//   uv run python gen_mappings.py <path-to-ha-ef-ble>\n"
        f"export const DEVICE_MAPPINGS = {json.dumps(MAPPINGS, indent=1)};\n\n"
        f"export const V2_STRUCTS = {json.dumps(structs, indent=1)};\n\n"
        f"export const KNOWN_FIELDS = {json.dumps(known, indent=1)};\n\n"
        f"export const EXTRA_PROTO_FILES = {json.dumps(extra)};\n"
    )
    n_rules = sum(len(m["rules"]) for m in MAPPINGS)
    n_known = sum(len(v) for v in known.values())
    print(f"wrote mappings.js: {len(MAPPINGS)} families, {n_rules} rules, "
          f"{len(structs)} structs, {n_known} known fields in {len(known)} "
          f"messages, {len(extra)} extra protos")


main()
