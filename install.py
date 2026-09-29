#!/usr/bin/env python3
"""安装、卸载 iml-jev-gate（Jev 安检），以及设置密钥。

    python3 install.py --set-key                    写入或更换 Jev 密钥（输入时不显示）
    python3 install.py --check                      试判一条命令，看 Jev 接通没有
    python3 install.py --scope project --dir DIR    只对一个工作目录生效
    python3 install.py --scope user                 对所有任务生效（改 ~/.workbuddy/settings.json，先备份）
    python3 install.py --scope project --dir DIR --uninstall
    python3 install.py --status                     看现在装在哪、密钥有没有

脚本本体装在 ~/.workbuddy/iml-jev-gate/，不在工作目录里。
新开的任务才会读到改动；已经在跑的任务不受影响。
"""
import argparse
import getpass
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.environ.get("CODEBUDDY_CONFIG_DIR") or os.path.expanduser("~/.workbuddy")
GATE_HOME = os.path.join(CONFIG_DIR, "iml-jev-gate")
SCRIPT = os.path.join(GATE_HOME, "jev_gate.py")
COMMAND = f'python3 "{SCRIPT}"'
MARK = "jev-gate/jev_gate.py"

DEFAULT_CONFIG = {
    "env_file": "",
    "timeout_seconds": 7,
    "cache_seconds": 600,
    "send_task": True,
    "ask": {"risk": 1.5, "irreversible": 0.65, "exfil": 0.5, "deletes": 0.8, "overwrites": 0.8, "outside": 0.6,
            "off_task": 0.8},
    "deny": {"enabled": False, "risk": 2.5, "irreversible": 0.8},
    "confirm_via": "popup",
    "display_name": "Jev 安检",
    "approval_minutes": 15,
    "no_human_modes": ["bypassPermissions", "dontAsk"],
}


def settings_path(scope, directory):
    if scope == "user":
        return os.path.join(CONFIG_DIR, "settings.json")
    return os.path.join(os.path.abspath(os.path.expanduser(directory)), ".codebuddy", "settings.json")


def load(path):
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)


def is_ours(group):
    return any(MARK in (h.get("command") or "") for h in group.get("hooks", []))


def save(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        backup = f"{path}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
        n = 1
        while os.path.exists(backup):  # 同一秒内重复安装时不覆盖上一份备份
            n += 1
            backup = f"{path}.bak-{time.strftime('%Y%m%d-%H%M%S')}-{n}"
        shutil.copy2(path, backup)
        print(f"已备份：{backup}")
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def read_config():
    """默认值打底，已有的设置优先；嵌套的一层也逐项合并，升级后新加的阈值不会丢。"""
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    path = os.path.join(GATE_HOME, "config.json")
    if os.path.exists(path):
        with open(path) as f:
            user = json.load(f)
        for k, v in user.items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k].update(v)
            else:
                cfg[k] = v
    return cfg


def write_config(cfg):
    os.makedirs(GATE_HOME, exist_ok=True)
    with open(os.path.join(GATE_HOME, "config.json"), "w") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
        f.write("\n")


def key_file(cfg):
    return os.path.expanduser(cfg.get("env_file") or os.path.join(GATE_HOME, ".env"))


def has_key(cfg):
    try:
        with open(key_file(cfg)) as f:
            return any(line.strip().startswith(("TYPESAFE_API_KEY=", "export TYPESAFE_API_KEY=")) for line in f)
    except OSError:
        return False


def sync_script():
    os.makedirs(GATE_HOME, exist_ok=True)
    src = os.path.join(HERE, "jev_gate.py")
    if os.path.abspath(src) != os.path.abspath(SCRIPT):
        shutil.copy2(src, SCRIPT)
    write_config(read_config())
    print(f"脚本已就位：{SCRIPT}")


def set_key():
    """密钥单独存一个文件，只有本人可读。不走命令行参数，免得留在终端历史里。"""
    if sys.stdin.isatty():
        key = getpass.getpass("粘贴 Jev 密钥后回车（输入时不显示）：").strip()
    else:
        key = sys.stdin.readline().strip()
    if not key:
        sys.exit("没有读到密钥，未改动")
    if any(c.isspace() for c in key) or len(key) < 8:
        sys.exit("这不像一个密钥：里面有空白，或者太短。未改动")
    cfg = read_config()
    cfg["env_file"] = ""  # 统一用安检目录下的 .env
    os.makedirs(GATE_HOME, exist_ok=True)
    path = os.path.join(GATE_HOME, ".env")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(f"TYPESAFE_API_KEY={key}\n")
    os.chmod(path, 0o600)
    write_config(cfg)
    cache = os.path.join(GATE_HOME, "cache.json")
    if os.path.exists(cache):
        os.remove(cache)
    print(f"密钥已保存：{path}")
    print("只有你本人可读。下一条命令起生效，不用重启 WorkBuddy")


def check():
    """拿一条无害的命令试判，看走的是 Jev 还是兜底。"""
    script = SCRIPT if os.path.exists(SCRIPT) else os.path.join(HERE, "jev_gate.py")
    event = {
        "hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "install-check",
        "cwd": os.getcwd(), "tool_input": {"command": "mkdir -p iml-jev-gate-check-demo"},
    }
    p = subprocess.run(
        [sys.executable, script, "--explain"], input=json.dumps(event),
        capture_output=True, text=True, env=dict(os.environ, JEV_GATE_DRY="1"),
    )
    try:
        rec = json.loads(p.stderr[p.stderr.index("{"):])
    except ValueError:
        sys.exit(f"脚本没有正常返回：{p.stderr.strip()[:200]}")
    if rec.get("layer") == "jev":
        sig = rec.get("signals") or {}
        print(f"Jev 已接通：用时 {rec['latency_ms']} 毫秒，模型 {sig.get('model')}")
        return 0
    if rec.get("no_key"):
        print("没有找到密钥，现在只靠本地规则：先运行 python3 install.py --set-key")
    else:
        print(f"Jev 没接通：{rec.get('error') or '原因不明'}")
        print("常见原因：密钥不对（http 401）、网络连不上（http 000）、额度或限流（http 429）")
    return 1


def status():
    cfg = read_config()
    print(f"脚本：{'已安装' if os.path.exists(SCRIPT) else '未安装'}  {SCRIPT}")
    print(f"密钥：{'已设置' if has_key(cfg) else '未设置，只靠本地规则'}  {key_file(cfg)}")
    path = settings_path("user", None)
    try:
        groups = load(path).get("hooks", {}).get("PreToolUse", [])
    except ValueError:
        print(f"全局配置不是合法 JSON：{path}")
        return
    ours = [g for g in groups if is_ours(g)]
    print(f"全局：{'已挂，匹配 ' + ', '.join(g.get('matcher', '*') for g in ours) if ours else '未挂'}")
    log = os.path.join(GATE_HOME, "decisions.jsonl")
    if os.path.exists(log):
        with open(log) as f:
            n = sum(1 for _ in f)
        print(f"判断记录：{n} 条  {log}")


def main():
    ap = argparse.ArgumentParser(description="iml-jev-gate（Jev 安检）安装工具")
    ap.add_argument("--scope", choices=["user", "project"])
    ap.add_argument("--dir", help="项目级安装的工作目录")
    ap.add_argument("--matcher", default="^Bash$", help="要过安检的工具名正则，默认只管命令")
    ap.add_argument("--uninstall", action="store_true")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--set-key", action="store_true", help="写入或更换 Jev 密钥")
    ap.add_argument("--check", action="store_true", help="试判一条命令，看 Jev 接通没有")
    a = ap.parse_args()

    if a.set_key:
        set_key()
        return 0
    if a.check:
        return check()
    if a.status or not a.scope:
        status()
        return 0
    if a.scope == "project" and not a.dir:
        sys.exit("项目级安装要用 --dir 指定工作目录")

    path = settings_path(a.scope, a.dir)
    try:
        data = load(path)
    except ValueError:
        sys.exit(f"配置不是合法 JSON，没有改动：{path}")
    groups = data.setdefault("hooks", {}).setdefault("PreToolUse", [])
    kept = [g for g in groups if not is_ours(g)]

    if a.uninstall:
        if len(kept) == len(groups):
            print("没有找到安检钩子，未改动")
            return 0
        data["hooks"]["PreToolUse"] = kept
        if not kept:
            del data["hooks"]["PreToolUse"]
        if not data["hooks"]:
            del data["hooks"]
        save(path, data)
        print(f"已卸载：{path}")
        return 0

    sync_script()
    kept.append({"matcher": a.matcher, "hooks": [{"type": "command", "command": COMMAND, "timeout": 10}]})
    data["hooks"]["PreToolUse"] = kept
    save(path, data)
    print(f"已安装：{path}")
    print("新开的任务生效")
    if not has_key(read_config()):
        print("还没有设置密钥，现在只靠本地规则：python3 install.py --set-key")
    return 0


if __name__ == "__main__":
    sys.exit(main())
