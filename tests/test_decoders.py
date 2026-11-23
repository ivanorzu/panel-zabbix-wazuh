#!/usr/bin/env python3
"""
Prueba los decoders de MikroTik SIN necesitar Wazuh.

Lee wazuh/decoders/mikrotik_decoders.xml, aplica prematch + regex (con offset
after_parent, como hace Wazuh) y compara los campos extraidos con lo esperado.
Es un simulador: la prueba definitiva sigue siendo `wazuh-logtest` en el servidor,
pero esto detecta errores de regex antes de tocar produccion.

    python3 tests/test_decoders.py
"""
import re
import sys
import pathlib
import xml.etree.ElementTree as ET

XML = pathlib.Path(__file__).resolve().parent.parent / "wazuh" / "decoders" / "mikrotik_decoders.xml"

root = ET.fromstring("<r>" + XML.read_text(encoding="utf-8") + "</r>")
decoders = {d.get("name"): d for d in root.findall("decoder")}


def decode(line):
    parent = decoders["mikrotik"]
    m = re.search(parent.find("prematch").text.strip(), line)
    if not m:
        return None, {}
    rest = line[m.end():]  # offset after_parent: el hijo busca despues de lo que consumio el padre
    for name, d in decoders.items():
        p = d.find("parent")
        if p is None or p.text != "mikrotik":
            continue
        if not re.search(d.find("prematch").text.strip(), rest):
            continue
        rx = re.search(d.find("regex").text.strip(), rest)
        if not rx:
            continue
        fields = [f.strip() for f in d.find("order").text.split(",")]
        return name, dict(zip(fields, rx.groups()))
    return "mikrotik", {}


CASES = [
    ("system,error,critical login failure for user admin from 203.0.113.50 via winbox",
     "mikrotik-login", {"dstuser": "admin", "srcip": "203.0.113.50", "protocol": "winbox"}),
    ("system,info,account user admin logged in from 192.168.10.97 via winbox",
     "mikrotik-session", {"dstuser": "admin", "action": "in", "srcip": "192.168.10.97", "protocol": "winbox"}),
    ("system,info,account user admin logged out from 192.168.10.97 via winbox",
     "mikrotik-session", {"dstuser": "admin", "action": "out", "srcip": "192.168.10.97", "protocol": "winbox"}),
    ("firewall,info WANIN-ISP1 input: in:sfp28-2 out:(unknown 0), connection-state:new proto TCP (SYN), "
     "198.51.100.23:51514->203.0.113.10:23, len 40",
     "mikrotik-fw", {"wan_link": "WANIN-ISP1", "wan_if": "sfp28-2", "protocol": "TCP",
                     "srcip": "198.51.100.23", "srcport": "51514", "dstip": "203.0.113.10", "dstport": "23"}),
    ("firewall,info WANIN-ISP2 input: in:sfp28-10 out:(unknown 0), connection-state:new proto TCP (SYN), "
     "198.51.100.77:40000->203.0.113.20:34567, len 60",
     "mikrotik-fw", {"wan_link": "WANIN-ISP2", "wan_if": "sfp28-10", "protocol": "TCP",
                     "srcip": "198.51.100.77", "srcport": "40000", "dstip": "203.0.113.20", "dstport": "34567"}),
    # No debe decodificar como hijo: linea que no es de MikroTik
    ("Nov 20 12:30:33 host sshd[123]: Failed password for root from 203.0.113.9 port 22 ssh2", None, {}),
]

fail = 0
for line, exp_name, exp_fields in CASES:
    name, fields = decode(line)
    ok = (name == exp_name) and (fields == exp_fields)
    print(("OK   " if ok else "FALLA"), name, fields if not ok else "")
    fail += not ok
print(f"\n{len(CASES) - fail}/{len(CASES)} casos correctos")
sys.exit(1 if fail else 0)
