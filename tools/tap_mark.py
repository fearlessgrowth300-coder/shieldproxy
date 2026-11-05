#!/usr/bin/env python3
"""Print the center of the home engine button, or exit if it is not a clickable button."""
import re
import sys

xml = open(sys.argv[1], encoding="utf-8", errors="replace").read()
for match in re.finditer(r"<node\b[^>]*>", xml):
    tag = match.group(0)
    if "homeEngineMark" not in tag:
        continue
    if 'clickable="true"' not in tag:
        sys.exit("homeEngineMark is not clickable: " + tag[:500])
    if "Button" not in tag:
        sys.exit("homeEngineMark is not a Button: " + tag[:500])
    bounds = re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', tag)
    if not bounds:
        sys.exit("homeEngineMark has no bounds")
    x1, y1, x2, y2 = (int(v) for v in bounds.groups())
    print(f"{(x1 + x2) // 2} {(y1 + y2) // 2}")
    raise SystemExit(0)
sys.exit("homeEngineMark was not in the UI dump")
