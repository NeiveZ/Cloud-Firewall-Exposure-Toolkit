#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLVX CLI Clean Edition
Direct command-line interface. No interactive direct CLI shell.
For authorized security testing only.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as _dt
import importlib
import io
import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any

TOOL = 'CLVX'
TAGLINE = 'Cloud & Firewall Evasion Framework'
VERSION = "3.0.0-cli"
COMMANDS = {'detect': {'module': 'modules.evade_detect', 'class': 'WAFDetector', 'summary': 'WAF/CDN/firewall fingerprinting', 'restricted': False}, 'cloudflare': {'module': 'modules.cloud_cloudflare', 'class': 'CloudflareBypass', 'summary': 'Cloudflare exposure and origin discovery checks', 'restricted': False}, 'azure': {'module': 'modules.cloud_azure', 'class': 'AzureRecon', 'summary': 'Azure cloud exposure checks', 'restricted': False}, 'portscan': {'module': 'modules.firewall_portscan', 'class': 'FirewallPortScan', 'summary': 'Polite TCP port scanning and banner checks', 'restricted': False}}

ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[90m",
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "cyan": "\033[96m",
    "white": "\033[97m",
}

USE_COLOR = True

def c(name: str, text: str) -> str:
    if not USE_COLOR:
        return text
    return ANSI.get(name, "") + text + ANSI["reset"]

def banner() -> None:
    art = r"""
   ________    _    ___  __
  / ____/ /   | |  / / |/ /
 / /   / /    | | / /|   / 
/ /___/ /___  | |/ //   |  
\____/_____/  |___//_/|_|  
"""
    print(c("bold", art))
    print(f"  {c('white', TOOL)}  {c('dim', TAGLINE)}  {c('white', VERSION)}")
    print(f"  {c('dim', 'Authorized security testing only. Direct CLI mode.')}")
    print()

def print_commands() -> None:
    print(c("bold", "Available commands"))
    print("-" * 78)
    print(f"{'Command':<16} {'Purpose'}")
    print("-" * 78)
    for name, meta in COMMANDS.items():
        suffix = "  [requires --authorized]" if meta.get("restricted") else ""
        print(f"{name:<16} {meta['summary']}{suffix}")
    print()
    print(c("bold", "Global options"))
    print("  --json                  Save JSON report")
    print("  --txt                   Save TXT report")
    print("  --out PATH              Output file or report prefix")
    print("  --verbose               Show raw module output")
    print("  --authorized            Required for intrusive/high-impact commands")
    print("  --no-color              Disable colors")
    print("  --check                 Validate local Python syntax")
    print()
    print(c("bold", "Examples"))
    for ex in EXAMPLES:
        print(f"  {ex}")

EXAMPLES = ['./clvx.sh detect -u https://example.com', './clvx.sh cloudflare -u https://example.com', './clvx.sh azure -u https://example.com']

def _load_class(spec: dict):
    mod = importlib.import_module(spec["module"])
    return getattr(mod, spec["class"])

def _get_options(module_obj) -> dict:
    return getattr(module_obj, "options", {}) or {}

def _option_desc(meta: dict) -> str:
    return meta.get("desc") or meta.get("description") or ""

def _normalize_key(s: str) -> str:
    return s.strip().replace("-", "_").upper()

def _target_alias_for(options: dict, alias: str) -> str:
    preferred = {
        "-t": ["TARGET", "HOST", "IP", "RHOST"],
        "-u": ["URL", "TARGET", "BASE_URL"],
        "-d": ["DOMAIN", "TARGET"],
        "-p": ["PORT", "RPORT"],
        "-w": ["WORDLIST", "PASSLIST", "USERLIST"],
        "-o": ["OUTPUT", "REPORT_FILE"],
        "-T": ["TIMEOUT"],
        "-j": ["THREADS"],
    }.get(alias, [])
    for p in preferred:
        if p in options:
            return p
    if preferred:
        return preferred[0]
    return alias.lstrip("-").upper()

def parse_module_args(raw: list[str], options: dict) -> tuple[dict, dict]:
    module_values = {}
    common = {
        "json": False,
        "txt": False,
        "out": "",
        "verbose": False,
        "authorized": False,
        "silent": False,
    }
    i = 0
    while i < len(raw):
        token = raw[i]
        if token in ("--json",):
            common["json"] = True; i += 1; continue
        if token in ("--txt",):
            common["txt"] = True; i += 1; continue
        if token in ("--verbose",):
            common["verbose"] = True; i += 1; continue
        if token in ("--authorized",):
            common["authorized"] = True; i += 1; continue
        if token in ("--silent",):
            common["silent"] = True; i += 1; continue
        if token in ("--no-color",):
            global USE_COLOR
            USE_COLOR = False; i += 1; continue
        if token in ("--out",):
            if i + 1 >= len(raw): raise ValueError("--out requires a value")
            common["out"] = raw[i+1]; i += 2; continue
        if token.startswith("--out="):
            common["out"] = token.split("=",1)[1]; i += 1; continue
        if token in ("-t", "-u", "-d", "-p", "-w", "-o", "-T", "-j"):
            if i + 1 >= len(raw): raise ValueError(f"{token} requires a value")
            key = _target_alias_for(options, token)
            module_values[key] = raw[i+1]; i += 2; continue
        if token.startswith("--"):
            if "=" in token:
                key, value = token[2:].split("=", 1)
                key = _normalize_key(key)
                module_values[key] = value
                i += 1
                continue
            key = _normalize_key(token[2:])
            if i + 1 < len(raw) and not raw[i+1].startswith("-"):
                module_values[key] = raw[i+1]; i += 2
            else:
                module_values[key] = "true"; i += 1
            continue
        raise ValueError(f"Unknown argument: {token}")
    return module_values, common

def _flatten_results(obj: Any) -> list[dict]:
    if obj is None:
        return []
    if isinstance(obj, list):
        out = []
        for item in obj:
            if isinstance(item, dict):
                out.append(item)
            else:
                out.append({"result": str(item)})
        return out
    if isinstance(obj, dict):
        # dict of module -> list
        if all(isinstance(v, list) for v in obj.values()):
            out = []
            for k, vals in obj.items():
                for v in vals:
                    if isinstance(v, dict):
                        row = dict(v); row.setdefault("source", k); out.append(row)
                    else:
                        out.append({"source": k, "result": str(v)})
            return out
        return [obj]
    return [{"result": str(obj)}]

def _cell(row: dict, *keys: str) -> str:
    for k in keys:
        if k in row and row[k] not in (None, ""):
            return str(row[k])
    return "-"

def print_result_table(rows: list[dict]) -> None:
    print()
    print(c("bold", "Results"))
    print("-" * 100)
    if not rows:
        print(c("dim", "No findings returned by the module."))
        return
    headers = ["Severity", "Target", "Check", "Detail"]
    print(f"{headers[0]:<12} {headers[1]:<28} {headers[2]:<24} {headers[3]}")
    print("-" * 100)
    for r in rows[:200]:
        sev = _cell(r, "severity", "risk", "status", "level").upper()
        target = _cell(r, "target", "url", "endpoint", "host", "ip", "hash", "domain", "email", "result")
        check = _cell(r, "check", "type", "types", "title", "module", "param", "name", "algorithm")
        detail = _cell(r, "detail", "evidence", "recommendation", "payload", "message", "length", "value", "count")
        color = "white"
        if sev in ("CRITICAL","HIGH","ERROR","FAILED"): color = "red"
        elif sev in ("MEDIUM","WARN","WARNING"): color = "yellow"
        elif sev in ("LOW","INFO"): color = "cyan"
        elif sev in ("OK","PASS","SAFE"): color = "green"
        print(f"{c(color, sev):<22} {target[:28]:<28} {check[:24]:<24} {detail[:90]}")
    if len(rows) > 200:
        print(c("dim", f"... {len(rows)-200} additional rows not displayed; use --json/--txt for full output."))

def save_reports(tool: str, command: str, rows: list[dict], raw_log: str, common: dict) -> list[str]:
    saved = []
    if not (common.get("json") or common.get("txt") or common.get("out")):
        return saved
    reports = Path("reports")
    reports.mkdir(exist_ok=True)
    ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = common.get("out") or str(reports / f"{tool.lower()}_{command}_{ts}")
    base_path = Path(base)
    if base_path.suffix:
        stem = base_path.with_suffix("")
    else:
        stem = base_path
    if common.get("json") or common.get("out"):
        path = str(stem) + ".json"
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps({
            "tool": tool,
            "command": command,
            "timestamp": ts,
            "results": rows,
            "raw_log": raw_log.splitlines()[-200:],
        }, indent=2, ensure_ascii=False), encoding="utf-8")
        saved.append(path)
    if common.get("txt"):
        path = str(stem) + ".txt"
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"{tool} {command} report\n")
            f.write("=" * 72 + "\n\n")
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
            if raw_log:
                f.write("\nRaw module output\n")
                f.write("-" * 72 + "\n")
                f.write(raw_log)
        saved.append(path)
    return saved

def run_check() -> int:
    import compileall
    ok = compileall.compile_dir(".", quiet=1)
    print(c("green" if ok else "red", "Check complete." if ok else "Check failed."))
    return 0 if ok else 1

def run_command(command: str, raw_args: list[str]) -> int:
    if command not in COMMANDS:
        print(c("red", f"Unknown command: {command}"))
        print_commands()
        return 2
    spec = COMMANDS[command]
    try:
        cls = _load_class(spec)
        module_obj = cls()
    except Exception as exc:
        print(c("red", f"Failed to load command '{command}': {exc}"))
        return 1

    options = _get_options(module_obj)
    try:
        module_values, common = parse_module_args(raw_args, options)
    except ValueError as exc:
        print(c("red", str(exc)))
        return 2

    if spec.get("restricted") and not common.get("authorized"):
        print(c("red", "This command is restricted and requires explicit authorization."))
        print("Add --authorized only when you are testing assets you own or have written permission to assess.")
        return 2

    for key, value in module_values.items():
        if key not in options:
            # tolerate common synonyms
            found = None
            for opt in options:
                if opt.replace("_","") == key.replace("_",""):
                    found = opt; break
            if found:
                key = found
            else:
                print(c("yellow", f"Ignoring unknown module option: {key}"))
                continue
        if hasattr(module_obj, "set_option"):
            module_obj.set_option(key, value)
        else:
            options[key]["value"] = value

    if not common.get("silent"):
        banner()
        print(c("bold", "Run Summary"))
        print(f"  Tool       : {TOOL}")
        print(f"  Command    : {command}")
        print(f"  Purpose    : {spec['summary']}")
        if options:
            print(f"  Options    :")
            for k, meta in options.items():
                val = meta.get("value")
                if meta.get("required") and not val:
                    val = c("yellow", "unset")
                print(f"    {k:<14} {val}")
        print()

    raw = ""
    result_obj = None
    try:
        if common.get("verbose"):
            result_obj = module_obj.run()
        else:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                result_obj = module_obj.run()
            raw = buf.getvalue()
    except KeyboardInterrupt:
        print(c("yellow", "Interrupted by user."))
        return 130
    except Exception:
        print(c("red", "Module execution failed."))
        print(traceback.format_exc(limit=2))
        return 1

    rows = _flatten_results(result_obj)
    if not common.get("silent"):
        print_result_table(rows)
        if not rows and raw.strip():
            print()
            print(c("bold", "Module Output"))
            print("-" * 100)
            # show compact last lines only
            lines = [line for line in raw.splitlines() if line.strip()]
            for line in lines[-40:]:
                print(line)
        saved = save_reports(TOOL, command, rows, raw, common)
        if saved:
            print()
            print(c("green", "Saved reports"))
            for p in saved:
                print(f"  {p}")
    else:
        if rows:
            for r in rows:
                print(json.dumps(r, ensure_ascii=False))
        elif raw:
            print(raw.strip())
    return 0

def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    global USE_COLOR
    if "--no-color" in argv:
        USE_COLOR = False
    if not argv or argv[0] in ("-h", "--help", "help"):
        banner()
        print_commands()
        return 0
    if argv[0] == "--check":
        return run_check()
    cmd, args = argv[0], argv[1:]
    if cmd in ("commands", "list"):
        banner(); print_commands(); return 0
    if "--help" in args or "-h" in args:
        banner()
        spec = COMMANDS.get(cmd)
        if not spec:
            print_commands(); return 0
        print(c("bold", f"Command: {cmd}"))
        print(f"{spec['summary']}\n")
        try:
            cls = _load_class(spec); obj = cls(); opts = _get_options(obj)
            print(c("bold", "Module options"))
            for k, meta in opts.items():
                req = "required" if meta.get("required") else "optional"
                print(f"  --{k.lower().replace('_','-'):<18} {req:<9} {_option_desc(meta)}")
        except Exception:
            print("Options are available after installing optional dependencies.")
        print("\nCommon: --json --txt --out PATH --verbose --authorized --no-color --silent")
        return 0
    return run_command(cmd, args)

if __name__ == "__main__":
    raise SystemExit(main())
