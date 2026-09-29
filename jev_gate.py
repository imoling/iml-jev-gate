#!/usr/bin/env python3
"""iml-jev-gate（Jev 安检）：WorkBuddy 执行命令之前过一道安检。本地规则 → Jev 判断 → 拿不准问人。

作为 PreToolUse 钩子运行：从标准输入读钩子事件，需要拦或问时向标准输出写决策，
判为安全时不输出任何内容，让 WorkBuddy 自己的沙箱和确认流程照常走。

密钥：放在 ~/.workbuddy/iml-jev-gate/.env 里，一行 TYPESAFE_API_KEY=你的密钥。
用 python3 install.py --set-key 写入最省事。没有密钥也能用，只靠本地规则。

手动测试：
    echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/tmp/x",
           "tool_input":{"command":"rm -rf build"}}' | python3 jev_gate.py --explain
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time

VERSION = "1.0.0"
ENDPOINT = "https://api.typesafe.ai/v1/systemone"

DEFAULTS = {
    "model": "jev-latest",
    "env_file": "",  # 密钥文件的位置；留空就用安检目录下的 .env
    "timeout_seconds": 7,
    "cache_seconds": 600,
    "send_task": True,  # 把用户最近一条指令（脱敏、截断）一起发给 Jev，用来判断是否离题
    "task_max_chars": 300,
    "command_max_chars": 1500,
    # 任何一项达到阈值就要用户确认。除 risk 是 0 到 3 的分数外，其余都是 Jev 对一个是非题给的概率
    "ask": {"risk": 1.5, "irreversible": 0.65, "exfil": 0.5, "deletes": 0.8, "overwrites": 0.8, "outside": 0.6,
            "off_task": 0.8},
    # Jev 是概率判断，默认最重只到「要用户确认」；打开后高危直接拒绝
    "deny": {"enabled": False, "risk": 2.5, "irreversible": 0.8},
    # 需要用户确认时怎么问：
    #   popup  先拒绝，让智能体用「向用户提问」工具弹出「放行」「取消」，用户点了放行，同一条命令才能执行
    #   chat   先拒绝，用户在对话里回复「放行」
    #   dialog 让界面弹权限确认；实测完全访问模式下会被无视，理由也传不到界面
    # popup 模式下，用户直接打字回复「放行」同样有效
    "confirm_via": "popup",
    "display_name": "Jev 安检",  # 弹窗开头显示的名字
    "approval_minutes": 15,
    # confirm_via 为 dialog 时，这些权限模式下没有人可问，升级为拒绝
    "no_human_modes": ["bypassPermissions", "dontAsk"],
}

HOME = os.path.expanduser("~")
GATE_HOME = os.environ.get("JEV_GATE_HOME") or os.path.join(
    os.environ.get("CODEBUDDY_CONFIG_DIR") or os.path.join(HOME, ".workbuddy"), "iml-jev-gate"
)

# ---------------------------------------------------------------- 本地规则
# 高危：不问 Jev，直接处理
HARD_RULES = [
    (r"\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", "deny", "下载后直接执行"),
    (r"\brm\s+(-[a-zA-Z]+\s+)*(/|~|\$HOME|/\*|~/\*|\$HOME/\*)(\s|$)", "deny", "删除整个个人目录或根目录"),
    (
        r"\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*\s+(-[a-zA-Z]+\s+)*[\"']?(~|\$HOME|/Users/[^/\s]+)/"
        r"(Documents|Desktop|Downloads|Library|Pictures|Movies|Music)/?[\"']?(\s|$)",
        "deny",
        "递归删除个人目录",
    ),
    (r"\bmkfs(\.\w+)?\b|\bdiskutil\s+(erase|partition)\w*|\bdd\b[^|;&]*\bof=/dev/", "deny", "会抹掉磁盘"),
    (r"\bchmod\s+(-[a-zA-Z]+\s+)*777\s+/(\s|$)", "deny", "放开整个系统的权限"),
]
ASK_RULES = [
    (r"\bsudo\b", "需要管理员权限"),
    (r"(\.workbuddy|\.codebuddy)/settings(\.local)?\.json|jev-gate/", "会改动智能体自身的配置"),
]
# Jev 没响应时，含这些操作的命令要问用户
RISKY = re.compile(
    r"\b(rm|curl|wget|scp|rsync|ssh|nc|chmod|chown|kill|pkill|killall|osascript|launchctl|crontab)\b"
    r"|\bgit\s+(push|reset\s+--hard|clean)\b|\bdefaults\s+write\b"
    r"|\b(pip3?|npm|pnpm|yarn|brew|uv)\s+(install|add|i)\b"
)
SENSITIVE = re.compile(
    r"\.ssh|id_rsa|id_ed25519|\.env\b|credentials|\.aws|\.netrc|\.gnupg|keychain|token|secret|passw|api_?key",
    re.I,
)
READONLY = {
    "ls", "cat", "head", "tail", "grep", "egrep", "rg", "wc", "pwd", "which", "file", "stat", "du", "df",
    "date", "echo", "printf", "whoami", "uname", "basename", "dirname", "realpath", "tree", "uniq", "cut",
    "diff", "md5", "shasum", "sw_vers", "cd", "true", "test", "sleep", "jq", "awk", "tr", "column", "less",
}
GIT_READONLY = {"status", "log", "diff", "show", "branch", "remote", "rev-parse", "ls-files", "describe"}


def is_readonly(command: str) -> bool:
    """整条命令的每一段都只读，才走快速通道。解析不了一律当作不是。"""
    if SENSITIVE.search(command):
        return False
    stripped = re.sub(r"\d?>\s*/dev/null|\d?>&\d", "", command)
    if re.search(r"[`>]|\$\(|<\(", stripped):
        return False
    for seg in re.split(r"\|\||&&|;|\||\n", stripped):
        seg = seg.strip()
        if not seg:
            continue
        try:
            tokens = shlex.split(seg)
        except ValueError:
            return False
        while tokens and re.match(r"^\w+=", tokens[0]):
            tokens = tokens[1:]
        if not tokens:
            continue
        verb = os.path.basename(tokens[0])
        if verb == "git":
            if len(tokens) < 2 or tokens[1] not in GIT_READONLY:
                return False
        elif verb == "find":
            if any(t in ("-delete", "-exec", "-execdir", "-ok") for t in tokens):
                return False
        elif verb == "sed":
            if "-n" not in tokens or any(t.startswith("-i") for t in tokens):
                return False
        elif verb == "sort":
            if any(t.startswith("-o") for t in tokens):
                return False
        elif verb not in READONLY:
            return False
    return True


# ---------------------------------------------------------------- 脱敏
REDACTIONS = [
    (re.compile(r"(Bearer\s+)[A-Za-z0-9._\-]{8,}", re.I), r"\1<已脱敏>"),
    (re.compile(r"\b(sk|pk|ak|ghp|gho|xox[abp])[-_][A-Za-z0-9\-_]{12,}"), "<已脱敏>"),
    (
        re.compile(r"((?:api[_-]?key|token|secret|passw(?:or)?d|authorization)\w*\s*[=:]\s*)[\"']?[^\s\"'&]{4,}", re.I),
        r"\1<已脱敏>",
    ),
    # 长串随机字符：要同时含大小写和数字，且不含斜杠，免得把文件路径当成密钥
    (re.compile(r"\b(?=[A-Za-z0-9+_\-]*[a-z])(?=[A-Za-z0-9+_\-]*[A-Z])(?=[A-Za-z0-9+_\-]*\d)[A-Za-z0-9+_\-]{32,}={0,2}"), "<已脱敏>"),
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "<邮箱>"),
    (re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"), "<手机号>"),
]


def redact(text: str) -> str:
    text = text.replace(HOME, "~")
    text = re.sub(r"/(?:Users|home)/[^/\s\"']+", "~", text)
    for pat, rep in REDACTIONS:
        text = pat.sub(rep, text)
    return text


# ---------------------------------------------------------------- 配置、缓存、日志
def load_config() -> dict:
    cfg = json.loads(json.dumps(DEFAULTS))
    try:
        with open(os.path.join(GATE_HOME, "config.json")) as f:
            user = json.load(f)
        for k, v in user.items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k].update(v)
            else:
                cfg[k] = v
    except (OSError, ValueError):
        pass
    return cfg


def key_file(cfg: dict) -> str:
    return os.path.expanduser(cfg.get("env_file") or os.path.join(GATE_HOME, ".env"))


def load_key(cfg: dict) -> str | None:
    """先看密钥文件，再看环境变量。WorkBuddy 是从图形界面启动的，
    终端里 export 的变量它多半读不到，所以以文件为准。"""
    try:
        with open(key_file(cfg)) as f:
            for line in f:
                m = re.match(r"\s*(?:export\s+)?TYPESAFE_API_KEY\s*=\s*[\"']?([^\"'\s#]+)", line)
                if m:
                    return m.group(1)
    except OSError:
        pass
    return os.environ.get("TYPESAFE_API_KEY") or None


DRY = bool(os.environ.get("JEV_GATE_DRY"))  # 试判：不读写缓存，不记日志


def cache_get(key: str, ttl: int):
    if DRY:
        return None
    try:
        with open(os.path.join(GATE_HOME, "cache.json")) as f:
            hit = json.load(f).get(key)
        if hit and time.time() - hit["at"] < ttl:
            return hit
    except (OSError, ValueError, KeyError):
        pass
    return None


def cache_put(key: str, value: dict, ttl: int) -> None:
    if DRY:
        return
    path = os.path.join(GATE_HOME, "cache.json")
    try:
        try:
            with open(path) as f:
                data = json.load(f)
        except (OSError, ValueError):
            data = {}
        now = time.time()
        data = {k: v for k, v in data.items() if now - v.get("at", 0) < ttl}
        data[key] = dict(value, at=now)
        fd, tmp = tempfile.mkstemp(dir=GATE_HOME, suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, ensure_ascii=False)
        os.replace(tmp, path)
    except OSError:
        pass


def write_log(record: dict) -> None:
    if DRY:
        return
    try:
        os.makedirs(GATE_HOME, exist_ok=True)
        with open(os.path.join(GATE_HOME, "decisions.jsonl"), "a") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------- 取用户当前任务
# 放行必须是用户整句话只说这一句，避免引用、转述时误放行。后面的四位编号可有可无
APPROVAL = re.compile(r"\s*放行(?:\s*([0-9a-fA-F]{4}))?\s*[。.!！]?\s*")


def user_text(raw: str) -> str:
    """取用户原话。桌面端会把原话包在 <user_query> 里，前面带系统上下文和附件；
    只认最后一个 <user_query>，附件里夹带的同名标签排在它前面，不会被采用。"""
    queries = re.findall(r"<user_query>(.*?)</user_query>", raw, flags=re.S)
    if queries:
        raw = queries[-1]
    else:
        raw = re.sub(r"<([a-zA-Z_\-]+)[^>]*>.*?</\1>", " ", raw, flags=re.S)
    return re.sub(r"\s+", " ", raw).strip()


def user_events(transcript_path: str | None) -> list:
    """按时间顺序返回用户做过的事：
    ("say", 文本, 时间戳)                          用户说的话
    ("answer", {question, options, selected}, 时间戳)  用户在提问弹窗里点的选项"""
    if not transcript_path or not os.path.exists(transcript_path):
        return []
    out, asked = [], {}
    try:
        with open(transcript_path, errors="ignore") as f:
            for line in f:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                kind = r.get("type")
                if kind == "message" and r.get("role") == "user":
                    parts = r.get("content") or []
                    if isinstance(parts, str):
                        text = parts
                    else:
                        text = " ".join(p.get("text", "") for p in parts if isinstance(p, dict))
                    out.append(("say", user_text(text), r.get("timestamp") or 0))
                elif kind == "function_call" and r.get("name") == "AskUserQuestion":
                    try:
                        qs = json.loads(r.get("arguments") or "{}").get("questions") or []
                        if isinstance(qs, str):  # 有的模型会把问题列表再包成一层字符串
                            qs = json.loads(qs)
                    except ValueError:
                        qs = []
                    if not isinstance(qs, list):
                        qs = []
                    # 一次只问一件事才算数，免得放行被夹在一串问题里
                    asked[r.get("callId")] = qs[0] if len(qs) == 1 else {}
                elif kind == "function_call_result" and r.get("name") == "AskUserQuestion":
                    q = asked.get(r.get("callId")) or {}
                    text = (r.get("output") or {}).get("text") or ""
                    if not (q and "→" in text and r.get("status") == "completed"):
                        # 认不出来的回答也记一笔：它是用户最新的动作，之前的放行不能再算数
                        out.append(("answer", {"question": "", "options": [], "selected": ""}, r.get("timestamp") or 0))
                    else:
                        out.append(("answer", {
                            "question": str(q.get("question", "")),
                            "options": [(str(o.get("label", "")), str(o.get("description", "")))
                                        for o in q.get("options") or [] if isinstance(o, dict)],
                            "selected": text.rsplit("→", 1)[1].strip(),
                        }, r.get("timestamp") or 0))
    except OSError:
        return []
    return out


def last_user_task(events: list, limit: int) -> str:
    """最近一条不是「放行」的用户消息，当作当前任务。"""
    for kind, text, _ in reversed(events):
        if kind == "say" and text and not APPROVAL.fullmatch(text):
            return redact(text)[:limit]
    return ""


def squash(text: str) -> str:
    """比对用：去掉空白和引号，免得转述时多一个空格就对不上。"""
    return re.sub(r"[\s\"'`\\]+", "", text)


def last_denied(session_id) -> dict:
    """这个会话里，安检最近一次要求确认的是哪条命令。"""
    try:
        with open(os.path.join(GATE_HOME, "decisions.jsonl")) as f:
            lines = f.readlines()[-300:]
    except OSError:
        return {}
    for line in reversed(lines):
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if r.get("session_id") == session_id and r.get("verdict") == "deny" and r.get("code"):
            return r
    return {}


def approved(events: list, code: str, minutes: int, shown: str, full_shown: bool, denied: dict) -> bool:
    """用户最近做的一件事是放行这条命令，且没过期。用户不需要看到编号：
    弹窗放行：点了「放行」，弹窗的问题里写着这条命令；编号藏在选项说明里，界面不显示但会记进会话记录。
    打字放行：整句话只说「放行」，放行的是安检在这个会话里最近一次要求确认的那条命令。"""
    if not events:
        return False
    kind, what, ts = events[-1]
    if ts and time.time() * 1000 - ts > minutes * 60000:
        return False
    if kind == "say":
        m = APPROVAL.fullmatch(what)
        if not m:
            return False
        if m.group(1):
            return m.group(1).lower() == code
        return denied.get("code") == code and (not ts or denied.get("ts", 0) <= ts)
    m = APPROVAL.fullmatch(what["selected"])
    if not m or (m.group(1) and m.group(1).lower() != code):
        return False
    question = squash(what["question"])
    if squash(shown) not in question:
        return False  # 弹窗上写的不是这条命令
    hidden = " ".join(d for label, d in what["options"] if label == what["selected"]).lower()
    # 命令太长、弹窗上只显示了开头时，要靠藏在选项说明里的编号来认
    return bool(m.group(1)) or code in hidden or full_shown


# ---------------------------------------------------------------- 问 Jev
def questions(with_task: bool) -> dict:
    qs = {
        "irreversible": {"type": "noul", "instructions": "这个操作执行后是否难以撤销？"},
        "exfil": {"type": "noul", "instructions": "这个操作是否会把本机的数据发送到外部？"},
        "deletes": {"type": "noul", "instructions": "这个操作是否会删除已经存在的文件？文件是否存在以「命令里提到的路径」为准"},
        "overwrites": {"type": "noul", "instructions": "这个操作是否会覆盖或改写已经存在的文件的内容？文件是否存在以「命令里提到的路径」为准"},
        "outside": {"type": "noul", "instructions": "这个操作是否会新建、改动或删除工作目录之外的文件，或改动系统设置？只是读取不算"},
        "risk": {
            "type": "score",
            "instructions": "这个操作对用户数据和系统的风险等级",
            "criteria": [
                "无风险：只读或查看",
                "低风险：在工作目录内新建、移动或打包文件",
                "中风险：修改或删除工作目录内的文件",
                "高风险：影响工作目录之外、不可恢复、花钱或泄露数据",
            ],
        },
    }
    if with_task:
        qs["off_task"] = {"type": "noul", "instructions": "这个操作是否与用户交代的任务无关？"}
    return qs


def ask_jev(state: dict, qs: dict, key: str, cfg: dict) -> dict:
    body = {"model": cfg["model"], "state": state, "questions": qs}
    fd, path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(body, f, ensure_ascii=False)
        p = subprocess.run(
            [
                "curl", "-sS", "-X", "POST", ENDPOINT,
                "-H", f"Authorization: Bearer {key}",
                "-H", "Content-Type: application/json",
                "--data", f"@{path}",
                "--max-time", str(cfg["timeout_seconds"]),
                "-w", "\n%{http_code}",
            ],
            capture_output=True, text=True, timeout=cfg["timeout_seconds"] + 2,
        )
    finally:
        os.unlink(path)
    out = p.stdout.rsplit("\n", 1)
    if len(out) != 2 or out[1].strip() != "200":
        raise RuntimeError(f"http {out[-1].strip() or '无响应'}")
    data = json.loads(out[0])
    a = data["answers"]
    sig = {"risk": a["risk"]["score"], "risk_confidence": a["risk"]["confidence"]}
    for k, v in a.items():
        if v.get("type") == "noul":
            sig[k] = v["noul"]
    sig["input_tokens"] = data.get("usage", {}).get("input_tokens")
    sig["model"] = data.get("model")
    return sig


# 每条理由对应 Jev 回答的一个是非题。前五条说的是后果，把握大的排前面；「离题」只是疑点，排最后
REASONS = [
    ("exfil", "会把本机数据发到外部"),
    ("deletes", "会删除已有文件"),
    ("overwrites", "会覆盖已有文件"),
    ("outside", "会改动工作目录之外的内容"),
    ("irreversible", "执行后难以撤销"),
    ("off_task", "看起来和当前任务无关"),
]


def risk_level(sig: dict, cfg: dict) -> str:
    risk = (sig or {}).get("risk")
    if risk is None:
        return ""
    return "高" if risk >= 2.5 else "中" if risk >= cfg["ask"]["risk"] else "低"


def decide(sig: dict, cfg: dict):
    a, d = cfg["ask"], cfg["deny"]
    hits = [(key != "off_task", sig[key], -n, text)
            for n, (key, text) in enumerate(REASONS) if sig.get(key, 0) >= a[key]]
    reasons = [h[-1] for h in sorted(hits, reverse=True)]
    if not reasons:
        # 说不出具体理由就不拦，除非 Jev 把它判成了高风险
        if sig["risk"] < 2.5:
            return "pass", []
        reasons = ["Jev 判为高风险，但说不出具体哪一项"]
    if d["enabled"] and sig["risk"] >= d["risk"] and sig.get("irreversible", 0) >= d["irreversible"]:
        return "deny", reasons
    return "ask", reasons


def path_facts(command: str, cwd: str, limit: int = 6) -> list:
    """代码能确定的事先查好，再告诉 Jev：命令里提到的路径存不存在、在不在工作目录里。
    Jev 只看得到命令的字面，看不到磁盘。"""
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    here = os.path.realpath(os.path.expanduser(cwd or "."))
    facts, seen = [], set()
    for tok in tokens:
        for part in re.split(r"[=@]", tok):
            if not part or part.startswith("-") or "://" in part or part in seen:
                continue
            looks_like_path = part.startswith(("/", "~", "./", "../")) or "/" in part or re.search(r"\.\w{1,6}$", part)
            if not looks_like_path or re.fullmatch(r"[\d.]+", part):
                continue
            seen.add(part)
            full = os.path.expanduser(part)
            if not os.path.isabs(full):
                full = os.path.join(here, full)
            # 两边都解析到真实路径再比，否则 /var 和 /private/var 这种链接会被当成两个地方
            where = "在工作目录内" if (os.path.realpath(full) + "/").startswith(here + "/") else "在工作目录之外"
            if re.search(r"[*?\[]", part):
                n = len(glob.glob(full)[:200])
                state = f"匹配到 {n} 个已有的文件或目录" if n else "没有匹配到已有文件"
            else:
                state = "已存在" if os.path.lexists(full) else "不存在"
            facts.append(f"{redact(part)}：{state}，{where}")
            if len(facts) >= limit:
                return facts
    return facts


def display(command: str, cwd: str) -> str:
    """命令的规范写法：脱敏、把工作目录缩成 ./，去掉开头的 cd，压成一行。
    弹窗上显示的是它的前 160 个字，放行编号也按它算：智能体照着弹窗上的写法重新执行时，
    字面和原命令不同，但规范写法相同，算同一条命令。"""
    text = re.sub(r"\s+", " ", redact(command)).strip()
    here = redact(cwd or "").rstrip("/")
    if here and here != "~":
        text = re.sub(re.escape(here) + r"/?(?=[\s\"']|$)", ".", text)
        text = text.replace(here + "/", "./")
    return re.sub(r"^cd [\"']?\.[\"']?/? && ", "", text)


# ---------------------------------------------------------------- 输出
def emit(verdict: str, reasons: list, code: str = "", mode: str = "popup", shown: str = "",
         name: str = "", basis: str = "") -> None:
    if verdict == "pass":
        return
    why = "；".join(reasons[:2])
    out = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": verdict}}
    # 给用户看的一句话：谁拦的、依据、后果，然后才是命令。桌面端会把换行压成空格，所以写成一行
    head = f"{name}（{basis}）：{why}" if basis else f"{name}：{why}"
    ask = f"{head}。要放行这条命令吗：{shown}"
    if verdict == "ask":
        out["hookSpecificOutput"]["permissionDecisionReason"] = head
    elif code and mode == "popup":
        # 理由是给智能体看的：让它弹出选项。编号放在选项说明里，界面不显示，安检从会话记录里读
        out["hookSpecificOutput"]["permissionDecisionReason"] = (
            f"这条命令需要用户确认：{why}。请立刻用向用户提问的工具（AskUserQuestion）问用户，只问这一个问题，"
            "不要用文字代替，不要换写法重试，也不要执行别的命令来代替。"
            f"问题必须一字不差地写：「{ask}」。"
            f"选项只给两个，标签和说明必须一字不差：第一个标签「放行」，说明「编号 {code}」；第二个标签「取消」，说明「不执行」。"
            "用户选了放行，再原样执行你原来的那条命令；选了取消就停下。"
            f"如果你没有提问工具，就把这句话原样告诉用户，并加一句「同意就回复：放行」"
        )
        out["systemMessage"] = head
    elif code:
        # 理由是给智能体看的：让它把话带给用户，然后停下
        out["hookSpecificOutput"]["permissionDecisionReason"] = (
            f"这条命令需要用户确认：{why}。请把下面这句话原样告诉用户，然后停下等待，不要换写法重试，"
            f"也不要自己执行别的命令来代替：「{ask}；同意就回复：放行」。"
            "用户回复之后，再原样执行你原来的那条命令"
        )
        out["systemMessage"] = head
    else:
        # 拒绝理由是给智能体看的，要告诉它接下来怎么办
        out["hookSpecificOutput"]["permissionDecisionReason"] = (
            f"已被{name}拦下：{why}。不要换写法重试；请说明你想达到的目的，由用户决定是否手动执行"
        )
        out["systemMessage"] = f"{name}已拦下：{why}"
    print(json.dumps(out, ensure_ascii=False))


def describe(tool: str, tool_input: dict, limit: int) -> str:
    if tool == "Bash":
        return str(tool_input.get("command", ""))[:limit]
    return f"调用工具 {tool}，参数 {json.dumps(tool_input, ensure_ascii=False)[:limit]}"


def main() -> int:
    explain = "--explain" in sys.argv
    started = time.time()
    try:
        event = json.load(sys.stdin)
    except ValueError:
        return 0
    if event.get("hook_event_name") != "PreToolUse":
        return 0

    cfg = load_config()
    tool = event.get("tool_name", "")
    tool_input = event.get("tool_input") or {}
    raw = describe(tool, tool_input, 100000)
    action = describe(tool, tool_input, cfg["command_max_chars"])
    unsandboxed = bool(tool_input.get("dangerouslyDisableSandbox"))

    record = {
        "ts": int(started * 1000),
        "session_id": event.get("session_id"),
        "tool": tool,
        "command_sha256": hashlib.sha256(raw.encode()).hexdigest(),  # 与审计日志的 commandHash 同算法
        "preview": redact(action)[:200],
        "unsandboxed": unsandboxed,
        "permission_mode": event.get("permission_mode"),
    }

    events = user_events(event.get("transcript_path"))
    full = display(raw, event.get("cwd") or "") if tool == "Bash" else re.sub(r"\s+", " ", redact(raw))
    code = hashlib.sha256(full.encode()).hexdigest()[:4]  # 放行编号
    shown = full[:160]  # 弹窗里要显示的命令
    full_shown = len(full) <= 160  # 弹窗上是不是完整的一条
    by_user = cfg["confirm_via"] in ("popup", "chat")
    is_approved = lambda: approved(
        events, code, cfg["approval_minutes"], shown, full_shown, last_denied(event.get("session_id")))
    name = cfg["display_name"]

    def finish(layer, verdict, reasons, sig=None):
        give_code = ""
        if verdict == "ask" and by_user:
            if is_approved():
                verdict, layer = "pass", "approved"
            else:
                verdict, give_code = "deny", code
            record["code"] = code
        elif verdict == "ask" and event.get("permission_mode") in cfg["no_human_modes"]:
            verdict = "deny"
            record["escalated"] = True
        record.update(
            layer=layer, verdict=verdict, reasons=reasons, signals=sig or {},
            latency_ms=int((time.time() - started) * 1000),
        )
        write_log(record)
        if explain:
            print(json.dumps(record, ensure_ascii=False, indent=1), file=sys.stderr)
        # 括号里写依据：Jev 判的写风险高低，规则拦的写命中规则，Jev 没响应就如实说
        level = risk_level(sig, cfg) if layer in ("jev", "cache") else ""
        basis = f"{level}风险" if level else {
            "rule": "命中规则", "fallback": "没接 Jev" if record.get("no_key") else "Jev 没响应"}.get(layer, "")
        emit(verdict, reasons, give_code, mode=cfg["confirm_via"], shown=shown, name=name, basis=basis)
        return 0

    if tool == "Bash":
        for pat, verdict, why in HARD_RULES:
            if re.search(pat, raw):
                return finish("rule", verdict, [why])
        if not unsandboxed and is_readonly(raw):
            return finish("readonly", "pass", [])
        for pat, why in ASK_RULES:
            if re.search(pat, raw):
                return finish("rule", "ask", [why])

    # 用户已经对这条命令说了放行，就不必再问 Jev，也不再外发
    if by_user and is_approved():
        record["code"] = code
        return finish("approved", "pass", [])

    task = last_user_task(events, cfg["task_max_chars"]) if cfg["send_task"] else ""
    state = {
        "工作目录": redact(event.get("cwd") or ""),
        "待执行操作": redact(action),
        "要求在沙箱外运行": "是" if unsandboxed else "否",
    }
    facts = path_facts(raw, event.get("cwd") or "") if tool == "Bash" else []
    if facts:
        state["命令里提到的路径"] = facts
    if task:
        state = dict({"用户任务": task}, **state)

    ckey = hashlib.sha256(json.dumps(state, ensure_ascii=False, sort_keys=True).encode()).hexdigest()
    hit = cache_get(ckey, cfg["cache_seconds"])
    if hit:
        return finish("cache", hit["verdict"], hit["reasons"], hit.get("signals"))

    key = load_key(cfg)
    try:
        if not key:
            record["no_key"] = True
            raise RuntimeError("没有找到 TYPESAFE_API_KEY")
        sig = ask_jev(state, questions(bool(task)), key, cfg)
    except Exception as e:  # 接口失败不能让安检形同虚设，也不能卡死所有命令
        record["error"] = str(e)[:200]
        # Jev 不在的时候，只靠代码自己能确定的事来判
        why = []
        if tool != "Bash" or RISKY.search(raw) or unsandboxed:
            why.append("命令里有删除、联网或改权限这类操作")
        if any("在工作目录之外" in f for f in facts):
            why.append("命令涉及工作目录之外的路径")
        if re.search(r"(?<![0-9&>])>(?![&>])", raw) and any("已存在" in f for f in facts):
            why.append("命令可能覆盖已有文件")
        return finish("fallback", "ask" if why else "pass", why)

    verdict, reasons = decide(sig, cfg)
    if unsandboxed and verdict != "pass":
        reasons = (reasons + ["要求在沙箱外运行"])[:3]
    cache_put(ckey, {"verdict": verdict, "reasons": reasons, "signals": sig}, cfg["cache_seconds"])
    return finish("jev", verdict, reasons, sig)


if __name__ == "__main__":
    sys.exit(main())
