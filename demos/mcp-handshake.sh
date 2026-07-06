#!/usr/bin/env bash
# Drive the ikigai MCP server (stdio) with a scripted JSON-RPC session.
# Shows: the handshake, the capability-scoped tool list, and a tool call.
#
#   ./demos/mcp-handshake.sh [ikigai mcp args...]
#   ./demos/mcp-handshake.sh --scope urn:cap:demo:nothing   # narrow grant
#   ./demos/mcp-handshake.sh --grant research-agent          # a named grant
set -euo pipefail
IK="${IK:-./target/debug/ikigai}"
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"wc__source","arguments":{"in":"a\nb\nc","count":"lines"}}}' \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"grep__source","arguments":{"in":"apple\nbanana\napricot","pattern":"ap"}}}' \
  | "$IK" mcp "$@" 2>/dev/null | python3 -c '
import json, sys
for line in sys.stdin:
    m = json.loads(line); i = m.get("id")
    if i == 1: print("initialize →", m["result"]["serverInfo"]["name"], "· tools.listChanged:", m["result"]["capabilities"]["tools"]["listChanged"])
    elif i == 2: print(f"tools/list  → {len(m[\"result\"][\"tools\"])} tools under this grant")
    elif i == 3: print("wc(lines)   →", repr(m["result"]["content"][0]["text"]))
    elif i == 4: print("grep(ap)    →", repr(m["result"]["content"][0]["text"]))
'
