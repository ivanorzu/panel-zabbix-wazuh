#!/usr/bin/env python3
"""
Chequeos de higiene del repositorio (corren en CI y antes de cada commit):
  1. Todo el XML de wazuh/ esta bien formado.
  2. Los IDs de regla son unicos y estan en el rango local de Wazuh (100000-120000).
  3. No se coló ningun dato sensible (IP de red real, tokens de bot, claves).
Uso:  python3 tests/validate_repo.py
"""
import pathlib
import re
import sys
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parent.parent
errors = []

# 1 y 2: XML de Wazuh
ids = {}
for f in sorted((ROOT / "wazuh").rglob("*.xml")):
    text = re.sub(r"<\?xml[^>]*\?>", "", f.read_text(encoding="utf-8"))
    try:
        root = ET.fromstring("<r>" + text + "</r>")
    except ET.ParseError as e:
        errors.append(f"XML mal formado: {f.relative_to(ROOT)}: {e}")
        continue
    for rule in root.iter("rule"):
        rid = int(rule.get("id"))
        if not 100000 <= rid <= 120000:
            errors.append(f"{f.name}: regla {rid} fuera del rango local 100000-120000")
        if rid in ids:
            errors.append(f"{f.name}: regla {rid} duplicada (ya en {ids[rid]})")
        ids[rid] = f.name

# 3: datos sensibles
PATTERNS = {
    "IP de red real (172.25.x.x)": r"\b172\.25\.\d+\.\d+\b",
    "token de bot de Telegram": r"\b\d{8,}:[A-Za-z0-9_-]{30,}\b",
    "clave privada": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "contraseña literal": r"(?i)(api_pass|indexer_pass|password)['\"]?\s*(=>|=|:)\s*['\"](?!PEGAR)[^'\"\s]{4,}['\"]",
}
SKIP = {".png", ".pdf", ".zip"}
for f in ROOT.rglob("*"):
    if not f.is_file() or ".git" in f.parts or f.suffix in SKIP or f.name == "validate_repo.py":
        continue
    try:
        text = f.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    for label, rx in PATTERNS.items():
        if re.search(rx, text):
            errors.append(f"{f.relative_to(ROOT)}: posible {label}")

print(f"{len(ids)} reglas: {sorted(ids)}")
if errors:
    print("\n".join("ERROR " + e for e in errors))
    sys.exit(1)
print("OK: XML valido, IDs unicos, sin datos sensibles")
