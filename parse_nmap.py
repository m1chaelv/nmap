#!/usr/bin/env python3
"""
parse_nmap.py  •  Quick‑n‑dirty Nmap XML vulnerability summariser
==================================================================
Usage:
    python3 parse_nmap.py scan1.xml [scan2.xml ...]          # human table
    python3 parse_nmap.py --csv out.csv scan*.xml            # CSV output

Will look for <script> elements where the 'output' attribute or text contains
'any of'  (case‑insensitive):  VULNERABLE  FAIL  WARN
and list the host IP / port / script id / one‑line summary.
"""

import argparse
import csv
import re
import sys
from pathlib import Path

try:                    # lxml is faster & does huge files better
    from lxml import etree as ET
except ImportError:
    import xml.etree.ElementTree as ET


BADWORDS = re.compile(r'\b(VULNERABLE|FAIL|WARN)\b', re.I)
CLEAN_NL = re.compile(r'\s*\n\s*')


def parse_file(xml_path: Path):
    """Yield tuples: (ip, portstr, scriptid, shortsummary)"""
    tree = ET.parse(str(xml_path))
    root = tree.getroot()

    for host in root.findall("host"):
        # IP / hostname
        addrnode = host.find("address[@addrtype='ipv4']")
        ip = addrnode.get("addr") if addrnode is not None else "unknown"

        for port in host.findall(".//port"):
            proto = port.get("protocol")
            portid = port.get("portid")
            portstr = f"{portid}/{proto}"

            for sc in port.findall("script"):
                out = sc.get("output", "") + ''.join(sc.itertext())
                if BADWORDS.search(out):
                    # Take first line that is non‑empty as summary
                    firstline = CLEAN_NL.split(out.strip())[0][:120]
                    yield ip, portstr, sc.get("id"), firstline


def print_table(rows):
    if not rows:
        print("No VULNERABLE/FAIL/WARN hits found 🟢")
        return
    # column widths
    w_ip = max(len(r[0]) for r in rows)
    w_port = max(len(r[1]) for r in rows)
    w_sid = max(len(r[2]) for r in rows)
    header = f"{'Host':<{w_ip}}  {'Port':<{w_port}}  {'Script':<{w_sid}}  Summary"
    print(header)
    print("-" * len(header))
    for ip, port, sid, summary in rows:
        print(f"{ip:<{w_ip}}  {port:<{w_port}}  {sid:<{w_sid}}  {summary}")


def write_csv(rows, outfile):
    with open(outfile, "w", newline="") as fh:
        csvw = csv.writer(fh)
        csvw.writerow(["host", "port", "script", "summary"])
        csvw.writerows(rows)
    print(f"[+] CSV written to {outfile} ({len(rows)} rows)")


def main():
    ap = argparse.ArgumentParser(description="Summarise vulnerable findings from Nmap XML.")
    ap.add_argument("xml", nargs="+", help="One or more -oX XML files from Nmap")
    ap.add_argument("--csv", metavar="FILE", help="Write output as CSV instead of table")
    args = ap.parse_args()

    rows = []
    for xp in args.xml:
        p = Path(xp)
        if not p.exists():
            sys.stderr.write(f"[-] {p} not found, skipping\n")
            continue
        rows.extend(parse_file(p))

    if args.csv:
        write_csv(rows, args.csv)
    else:
        print_table(rows)


if __name__ == "__main__":
    main()
