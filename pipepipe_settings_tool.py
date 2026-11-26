#!/usr/bin/env python3
"""
pipepipe_settings_tool.py

PipePipe (and upstream NewPipe) store app preferences inside the exported
backup zip as `newpipe.settings`. This isn't AES/crypto "encryption" - it's
a raw Java Object Serialization stream, written on the Android side as:

    ObjectOutputStream(FileOutputStream(fileLocator.settings)).use { out ->
        out.writeObject(preferences.all)   // Map<String, Any?> from SharedPreferences
    }

So "decrypting" = parsing the Java serialization protocol.
"Re-encrypting" = re-emitting a byte-for-protocol-compatible HashMap that
the app's ObjectInputStream can read back in.

`javaobj-py3` can *read* this format fine, but its writer does not support
serializing a HashMap (Java's HashMap uses a custom writeObject() method,
not plain field serialization), so this script implements a small,
purpose-built writer for exactly the shape SharedPreferences produces:

    java.util.HashMap<String, Object>
        values of type: String, Boolean, Integer, Long, Float,
                         or Set<String> (java.util.HashSet<String>)

These are the only types Android's SharedPreferences can hold, so this
covers every real .settings file.

Dependencies:
    pip install javaobj-py3      # only needed for decoding

Usage:
    # Decode to JSON for inspection/editing
    python pipepipe_settings_tool.py decode newpipe.settings settings.json

    # Re-encode edited JSON back into .settings format
    python pipepipe_settings_tool.py encode settings.json newpipe.settings

"""

import argparse
import json
import struct
import sys

# ---------------------------------------------------------------------------
# Decoding (delegated to javaobj-py3, which reads this format correctly)
# ---------------------------------------------------------------------------


def _unwrap(value):
  if value is None or isinstance(value, (str, int, float, bool)):
    return value

  if isinstance(value, dict):
    return {str(_unwrap(k)): _unwrap(v) for k, v in value.items()}

  if isinstance(value, (list, tuple, set)):
    return [_unwrap(v) for v in value]

  if hasattr(value, "value"):
    return _unwrap(value.value)

  return str(value)


def decode(in_path: str, out_path: str) -> None:
  try:
    import javaobj.v1 as javaobj

  except ImportError:
    sys.exit("Missing dependency. Install with: pip install javaobj-py3")

  with open(in_path, "rb") as f:
    data = f.read()

  obj = javaobj.loads(data)
  plain = _unwrap(obj)

  with open(out_path, "w", encoding="utf-8") as f:
    json.dump(plain, f, indent=2, ensure_ascii=False, sort_keys=True)

  print(f"Decoded {len(plain)} preference keys -> {out_path}")


# ---------------------------------------------------------------------------
# Encoding: hand-rolled Java Object Serialization Stream Protocol writer
# Spec: https://docs.oracle.com/javase/8/docs/platform/serialization/spec/protocol.html
# ---------------------------------------------------------------------------

STREAM_MAGIC = 0xACED
STREAM_VERSION = 0x0005

TC_NULL = 0x70
TC_REFERENCE = 0x71
TC_CLASSDESC = 0x72
TC_OBJECT = 0x73
TC_STRING = 0x74
TC_BLOCKDATA = 0x77
TC_ENDBLOCKDATA = 0x78

SC_WRITE_METHOD = 0x01
SC_SERIALIZABLE = 0x02

BASE_WIRE_HANDLE = 0x7E0000

# Known serialVersionUIDs for JDK core classes (verified byte-for-byte
# against a real exported .settings file's class descriptors)
SUID_HASHMAP = 0x0507DAC1C31660D1
SUID_HASHSET = -5024744406713321676
SUID_BOOLEAN = -3665804199014368530
SUID_INTEGER = 1360826667806852920
SUID_LONG = 4290774380558885855
SUID_FLOAT = -2671257302660747028
SUID_NUMBER = -8742448824652078965


class JavaSerializer:
  """Writes Java Object Serialization Stream Protocol bytes for a
  HashMap<String,Object> as produced by Android SharedPreferences.all."""

  def __init__(self):
    self.buf = bytearray()
    self._handle_count = 0
    self._classdesc_handles = {}

  def _u1(self, v):
    self.buf.append(v & 0xFF)

  def _u2(self, v):
    self.buf += struct.pack(">H", v & 0xFFFF)

  def _i4(self, v):
    self.buf += struct.pack(">i", v)

  def _i8(self, v):
    self.buf += struct.pack(">q", v)

  def _f4(self, v):
    self.buf += struct.pack(">f", v)

  def _utf(self, s: str):
    encoded = s.encode("utf-8")
    self._u2(len(encoded))
    self.buf += encoded

  def _new_handle(self):
    h = BASE_WIRE_HANDLE + self._handle_count
    self._handle_count += 1
    return h

  def _write_classdesc_simple(self, classname, suid, flags, fields, cache_key, superclass_writer=None):
    """superclass_writer: optional no-arg callable that writes the
    superClassDesc (another classdesc, a reference, or TC_NULL). If not
    given, TC_NULL (no superclass) is written."""
    if cache_key in self._classdesc_handles:
      self._u1(TC_REFERENCE)
      self._i4(self._classdesc_handles[cache_key])
      return

    self._u1(TC_CLASSDESC)
    self._utf(classname)
    self._i8(suid)
    self._classdesc_handles[cache_key] = self._new_handle()
    self._u1(flags)
    self._u2(len(fields))
    for typecode, name in fields:
      self._u1(ord(typecode))
      self._utf(name)

    self._u1(TC_ENDBLOCKDATA) # no class annotations
    if superclass_writer is not None:
      superclass_writer()
    else:
      self._u1(TC_NULL) # no superclass


  def _classdesc_number(self):
    # java.lang.Number: serializable, no fields, no superclass.
    self._write_classdesc_simple("java.lang.Number", SUID_NUMBER, SC_SERIALIZABLE, [], "Number")

  def _classdesc_hashmap(self):
    # Real java.util.HashMap declares TWO persistent fields, written via
    # defaultWriteObject before the custom writeInt(buckets)/writeInt(size)
    # block data. Order matters: loadFactor (float) then threshold (int).
    self._write_classdesc_simple(
      "java.util.HashMap",
      SUID_HASHMAP,
      SC_SERIALIZABLE | SC_WRITE_METHOD,
      [("F", "loadFactor"), ("I", "threshold")],
      "HashMap",
    )

  def _classdesc_hashset(self):
    self._write_classdesc_simple(
      "java.util.HashSet",
      SUID_HASHSET,
      SC_SERIALIZABLE | SC_WRITE_METHOD,
      [],
      "HashSet",
    )

  def _classdesc_wrapper(self, classname, suid, field_type, field_name, extends_number=False):
    superclass_writer = self._classdesc_number if extends_number else None
    self._write_classdesc_simple(
      classname,
      suid,
      SC_SERIALIZABLE,
      [(field_type, field_name)],
      classname,
      superclass_writer=superclass_writer,
    )

  def _write_string(self, s: str):
    self._u1(TC_STRING)
    self._new_handle()
    self._utf(s)

  def _write_boolean(self, v: bool):
    self._u1(TC_OBJECT)
    self._classdesc_wrapper("java.lang.Boolean", SUID_BOOLEAN, "Z", "value")
    self._new_handle()
    self._u1(1 if v else 0)

  def _write_integer(self, v: int):
    self._u1(TC_OBJECT)
    self._classdesc_wrapper("java.lang.Integer", SUID_INTEGER, "I", "value", extends_number=True)
    self._new_handle()
    self._i4(v)

  def _write_long(self, v: int):
    self._u1(TC_OBJECT)
    self._classdesc_wrapper("java.lang.Long", SUID_LONG, "J", "value", extends_number=True)
    self._new_handle()
    self._i8(v)

  def _write_float(self, v: float):
    self._u1(TC_OBJECT)
    self._classdesc_wrapper("java.lang.Float", SUID_FLOAT, "F", "value", extends_number=True)
    self._new_handle()
    self._f4(v)

  def _write_stringset(self, items):
    self._u1(TC_OBJECT)
    self._classdesc_hashset()
    self._new_handle()
    # HashSet.writeObject: defaultWriteObject() [no fields], then
    # writeInt(capacity), writeFloat(loadFactor), writeInt(size), elements.
    capacity = max(16, _next_pow2(len(items) * 2 if items else 1))
    block = bytearray()
    block += struct.pack(">i", capacity)
    block += struct.pack(">f", 0.75)
    block += struct.pack(">i", len(items))
    self._u1(TC_BLOCKDATA)
    self._u1(len(block))
    self.buf += block
    for item in items:
      self._write_string(str(item))

    self._u1(TC_ENDBLOCKDATA)

  def _write_value(self, v):
    if v is None:
      self._u1(TC_NULL)
    elif isinstance(v, bool):
      self._write_boolean(v)
    elif isinstance(v, int):
      if -(2**31) <= v <= 2**31 - 1:
        self._write_integer(v)
      else:
        self._write_long(v)

    elif isinstance(v, float):
      self._write_float(v)
    elif isinstance(v, str):
      self._write_string(v)
    elif isinstance(v, (list, tuple)):
      self._write_stringset(v)
    else:
      raise TypeError(f"Unsupported preference value type: {type(v)} ({v!r})")


  def write_hashmap(self, prefs: dict) -> bytes:
    self._u2(STREAM_MAGIC)
    self._u2(STREAM_VERSION)

    self._u1(TC_OBJECT)
    self._classdesc_hashmap()
    self._new_handle()

    n = len(prefs)
    buckets = max(16, _next_pow2(int(n / 0.75) + 1))
    threshold = int(buckets * 0.75)

    # defaultWriteObject: fields "loadFactor" (float) then "threshold" (int)
    self._f4(0.75)
    self._i4(threshold)

    block = struct.pack(">i", buckets) + struct.pack(">i", n)
    self._u1(TC_BLOCKDATA)
    self._u1(len(block))
    self.buf += block

    for k, v in prefs.items():
      self._write_string(str(k))
      self._write_value(v)

    self._u1(TC_ENDBLOCKDATA)
    return bytes(self.buf)


def _next_pow2(n):
  p = 1
  while p < n:
    p <<= 1

  return p


def encode(in_path: str, out_path: str) -> None:
  with open(in_path, "r", encoding="utf-8") as f:
    prefs = json.load(f)

  if not isinstance(prefs, dict):
    sys.exit("Input JSON must be an object of key -> value preference pairs.")

  data = JavaSerializer().write_hashmap(prefs)

  with open(out_path, "wb") as f:
    f.write(data)

  print(f"Encoded {len(prefs)} preference keys -> {out_path}")


def main() -> None:
  parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
  sub = parser.add_subparsers(dest="command", required=True)

  p_decode = sub.add_parser("decode", help="Convert a .settings file to readable JSON")
  p_decode.add_argument("input", help="Path to newpipe.settings (or PipePipe equivalent)")
  p_decode.add_argument("output", help="Path to write JSON output")

  p_encode = sub.add_parser("encode", help="Convert an edited JSON file back to .settings format")
  p_encode.add_argument("input", help="Path to JSON file")
  p_encode.add_argument("output", help="Path to write the .settings file")

  args = parser.parse_args()

  if args.command == "decode":
    decode(args.input, args.output)
  elif args.command == "encode":
    encode(args.input, args.output)


if __name__ == "__main__":
  main()
