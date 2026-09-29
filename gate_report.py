#!/usr/bin/env python3
"""把安检的判断记录和 WorkBuddy 审计日志对起来看。

两边用命令的 SHA-256 对齐：安检记录在前（判断），审计日志在后（执行）。
只在本地读文件，不联网。
用法：python3 gate_report.py [--last 50]
"""
import argparse
import collections
import glob
import json
import os
import statistics
import time

CONFIG_DIR = os.environ.get("CODEBUDDY_CONFIG_DIR") or os.path.expanduser("~/.workbuddy")


def read_jsonl(path):
    rows = []
    try:
        with open(path, errors="ignore") as f:
            for line in f:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    pass
    except OSError:
        pass
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--last", type=int, default=30, help="列出最近多少条")
    a = ap.parse_args()

    decisions = read_jsonl(os.path.join(CONFIG_DIR, "iml-jev-gate", "decisions.jsonl"))
    if not decisions:
        print("还没有判断记录")
        return 0

    executed = collections.defaultdict(list)
    for path in glob.glob(os.path.join(CONFIG_DIR, "audit-log", "*.jsonl")):
        if path.endswith("manifest.jsonl"):
            continue
        for r in read_jsonl(path):
            if r.get("commandHash"):
                executed[r["commandHash"]].append(r["timestamp"])

    def ran(d):
        # 判断之后 2 分钟内审计日志里出现同一条命令，视为执行了
        return any(0 <= t - d["ts"] <= 120000 for t in executed.get(d["command_sha256"], []))

    by = collections.Counter((d["layer"], d["verdict"]) for d in decisions)
    jev_ms = [d["latency_ms"] for d in decisions if d["layer"] == "jev"]
    tokens = sum((d.get("signals") or {}).get("input_tokens") or 0 for d in decisions if d["layer"] == "jev")

    print(f"判断 {len(decisions)} 条")
    names = {"readonly": "只读直通", "rule": "本地规则", "jev": "Jev", "cache": "缓存", "fallback": "接口无响应兜底", "approved": "已放行过"}
    verdicts = {"pass": "放行", "ask": "询问", "deny": "拒绝"}
    for (layer, verdict), n in sorted(by.items(), key=lambda x: -x[1]):
        print(f"  {names.get(layer, layer)} → {verdicts.get(verdict, verdict)}：{n}")
    if jev_ms:
        print(f"Jev 这层耗时：中位 {statistics.median(jev_ms):.0f} ms，最大 {max(jev_ms)} ms；输入 {tokens} token，约 {tokens * 0.042 / 1e6:.5f} 美元")

    stopped = [d for d in decisions if d["verdict"] != "pass"]
    went = sum(1 for d in stopped if ran(d))
    print(f"被询问或拒绝 {len(stopped)} 条，其中之后仍然执行了 {went} 条")

    print(f"\n最近 {min(a.last, len(decisions))} 条")
    print(f"{'时间':8} {'判定':4} {'层':8} {'执行':4} {'耗时':>7}  命令")
    for d in decisions[-a.last:]:
        t = time.strftime("%H:%M:%S", time.localtime(d["ts"] / 1000))
        mark = "是" if ran(d) else "—"
        print(
            f"{t:8} {verdicts.get(d['verdict'], d['verdict']):4} {names.get(d['layer'], d['layer']):8} "
            f"{mark:4} {d['latency_ms']:5}ms  {d['preview'][:60]}"
        )
        if d["reasons"]:
            print(f"{'':36}{'；'.join(d['reasons'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
