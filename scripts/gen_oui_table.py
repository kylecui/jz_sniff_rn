#!/usr/bin/env python3
"""Generate src/common/oui_table.inc from IEEE OUI database.

Usage:
    curl -sL 'https://standards-oui.ieee.org/oui/oui.csv' -o /tmp/oui.csv
    python3 scripts/gen_oui_table.py /tmp/oui.csv > src/common/oui_table.inc
"""
import csv
import sys

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <oui.csv>", file=sys.stderr)
        sys.exit(1)

    entries = []
    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            if len(row) < 3 or row[0].strip() != 'MA-L':
                continue
            hex_str = row[1].strip()
            org_name = row[2].strip().strip('"')
            org_name = org_name.replace('\\', '\\\\').replace('"', '\\"')
            if len(org_name) > 48:
                org_name = org_name[:45] + '...'
            try:
                prefix = int(hex_str, 16)
            except ValueError:
                continue
            entries.append((prefix, org_name))

    entries.sort(key=lambda e: e[0])

    seen = set()
    unique = []
    for prefix, name in entries:
        if prefix not in seen:
            seen.add(prefix)
            unique.append((prefix, name))

    print(f"/* Auto-generated from IEEE OUI database (oui.csv)")
    print(f" * {len(unique)} entries, sorted by prefix for bsearch()")
    print(f" * DO NOT EDIT — regenerate with scripts/gen_oui_table.py")
    print(f" */")
    for prefix, name in unique:
        print(f'    {{ 0x{prefix:06X}U, "{name}" }},')

    print(f"{len(unique)} entries written", file=sys.stderr)

if __name__ == '__main__':
    main()
