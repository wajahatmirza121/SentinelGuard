"""PHP analysis: comment stripping, statement splitting and a small per-class taint tracker (stdlib only)."""
import re

from .catalog import make

# ---------- sources and sanitizers ----------
SOURCE_RE = re.compile(
    r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b"
    r"|\$_SERVER\s*\[\s*['\"](?:HTTP_\w+|REQUEST_URI|QUERY_STRING|PHP_SELF|PATH_INFO)['\"]\s*\]"
    r"|php://input|\bgetallheaders\s*\(|\$GLOBALS\s*\[\s*['\"]_(?:GET|POST|REQUEST)")
VAR_RE = re.compile(r"\$(\w+)")

FULL = "intval|floatval|absint|abs|md5|sha1|crc32|count|strlen|is_numeric|number_format|ctype_digit|ctype_alnum|random_int"
SAN = {
    "sql": FULL + "|mysqli_real_escape_string|real_escape_string|esc_sql|pg_escape_string|pg_escape_literal|quote|addslashes|filter_var|prepare",
    "xss": FULL + "|htmlspecialchars|htmlentities|esc_html|esc_attr|esc_url|esc_js|strip_tags|urlencode|rawurlencode|json_encode|sanitize_text_field|sanitize_key|wp_kses|wp_kses_post",
    "cmd": FULL + "|escapeshellarg|escapeshellcmd",
    "path": FULL + "|basename",
    "deser": FULL,
    "redirect": FULL + "|esc_url_raw|wp_validate_redirect|wp_sanitize_redirect",
    "code": FULL,
    "upload": FULL + "|uniqid|random_bytes|bin2hex|time|mt_rand|rand|hash",
}
CLASSES = tuple(SAN)
SAN_RE = {c: re.compile(r"(?<![\w$>:])(?:\$\w+\s*->\s*)?(?:%s)\s*\(" % names) for c, names in SAN.items()}
CAST_RE = re.compile(r"\(\s*(?:int|integer|float|double|bool|boolean)\s*\)\s*\$?\w+(?:\s*\[[^\]]*\])*")


def strip_calls(expr: str, call_re) -> str:
    out, i = [], 0
    while True:
        m = call_re.search(expr, i)
        if not m:
            out.append(expr[i:])
            break
        out.append(expr[i:m.start()])
        j, depth, q = m.end(), 1, None
        while j < len(expr) and depth:
            ch = expr[j]
            if q:
                if ch == "\\":
                    j += 1
                elif ch == q:
                    q = None
            elif ch in "'\"":
                q = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            j += 1
        i = j
    return "".join(out)


def mask_single_quoted(expr: str) -> str:
    out, i, n, dq = [], 0, len(expr), False
    while i < n:
        c = expr[i]
        if dq:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(expr[i + 1])
                i += 2
                continue
            if c == '"':
                dq = False
            i += 1
            continue
        if c == '"':
            dq = True
            out.append(c)
            i += 1
            continue
        if c == "'":
            j = i + 1
            while j < n:
                if expr[j] == "\\":
                    j += 2
                    continue
                if expr[j] == "'":
                    break
                j += 1
            out.append("''")
            i = j + 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def tainted_for(expr: str, cls: str, vars_: dict) -> bool:
    e = CAST_RE.sub("", strip_calls(expr, SAN_RE[cls]))
    if SOURCE_RE.search(e):
        return True
    e = mask_single_quoted(e)
    return any(cls in vars_.get(m.group(1), ()) for m in VAR_RE.finditer(e))


# ---------- tokenizing ----------
TAG_RE = re.compile(r"<\?(php|=)?(.*?)(\?>|\Z)", re.S)


def php_segments(text: str):
    for m in TAG_RE.finditer(text):
        kind, body = m.group(1), m.group(2)
        if kind is None and body.lstrip().startswith("xml"):
            continue
        line = text.count("\n", 0, m.start(2)) + 1
        line += body[: len(body) - len(body.lstrip())].count("\n")
        body = body.lstrip()
        if kind == "=":
            body = "echo " + body.strip().rstrip(";")
        yield body, line


def strip_comments(s: str) -> str:
    out, i, n, q = [], 0, len(s), None
    while i < n:
        c = s[i]
        if q:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(s[i + 1])
                i += 2
                continue
            if c == q:
                q = None
            i += 1
            continue
        if c in "'\"`":
            q = c
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and s[i + 1] == "*":
            j = s.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append(re.sub(r"[^\n]", " ", s[i:j]))
            i = j
            continue
        if (c == "/" and i + 1 < n and s[i + 1] == "/") or (c == "#" and not (i + 1 < n and s[i + 1] == "[")):
            j = s.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def split_statements(code: str, base_line: int):
    out, buf, depth, q, i, n = [], [], 0, None, 0, len(code)
    line, start = base_line, None

    def flush():
        nonlocal buf, start
        s = "".join(buf).strip()
        if s:
            out.append((s, start or base_line))
        buf, start = [], None

    while i < n:
        c = code[i]
        if c == "\n":
            line += 1
        if q:
            buf.append(c)
            if c == "\\" and i + 1 < n:
                buf.append(code[i + 1])
                if code[i + 1] == "\n":
                    line += 1
                i += 2
                continue
            if c == q:
                q = None
            i += 1
            continue
        if c in "'\"`":
            q = c
        elif c in "([":
            depth += 1
        elif c in ")]":
            depth = max(0, depth - 1)
        elif depth == 0 and c in ";{}":
            flush()
            i += 1
            continue
        if start is None and not c.isspace():
            start = line
        buf.append(c)
        i += 1
    flush()
    return out


def balanced(s: str, pos: int):
    """s[pos] is just after '('. Returns (inner_text, end_index)."""
    depth, q, j = 1, None, pos
    while j < len(s) and depth:
        ch = s[j]
        if q:
            if ch == "\\":
                j += 1
            elif ch == q:
                q = None
        elif ch in "'\"":
            q = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        j += 1
    return s[pos:j - 1 if depth == 0 else j], j


def split_args(inner: str):
    args, depth, q, cur = [], 0, None, []
    for ch in inner:
        if q:
            cur.append(ch)
            if ch == q:
                q = None
            continue
        if ch in "'\"":
            q = ch
        elif ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == "," and depth == 0:
            args.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    args.append("".join(cur))
    return args


# ---------- sinks ----------
_NB = r"(?<![\w$>:])"
SINKS = [
    ("PHP001", "sql", re.compile(_NB + r"(?:mysqli_query|mysql_query|mysqli_multi_query|mysqli_real_query|pg_query|pg_send_query|sqlite_query|sqlsrv_query|mssql_query)\s*\("), "args"),
    ("PHP001", "sql", re.compile(r"->\s*(?:query|exec|multi_query|real_query|get_results|get_var|get_row|get_col)\s*\("), "args"),
    ("PHP001", "sql", re.compile(r"->\s*prepare\s*\("), "first"),
    ("PHP002", "xss", re.compile(_NB + r"(?:echo|print)\b"), "rest"),
    ("PHP002", "xss", re.compile(_NB + r"(?:printf|vprintf)\s*\("), "args"),
    ("PHP003", "path", re.compile(_NB + r"(?:include|include_once|require|require_once)\b"), "rest"),
    ("PHP004", "cmd", re.compile(_NB + r"(?:exec|system|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\("), "args"),
    ("PHP005", "deser", re.compile(_NB + r"unserialize\s*\("), "first"),
    ("PHP011", "path", re.compile(_NB + r"(?:file_get_contents|file_put_contents|fopen|readfile|file|unlink|rmdir|mkdir|highlight_file|show_source|parse_ini_file|simplexml_load_file|fpassthru|touch|chmod)\s*\("), "first"),
    ("PHP011", "path", re.compile(_NB + r"(?:copy|rename)\s*\("), "args"),
    ("PHP012", "redirect", re.compile(_NB + r"header\s*\("), "first"),
]
EVAL_RE = re.compile(_NB + r"(eval|assert|create_function)\s*\(")
UPLOAD_RE = re.compile(_NB + r"move_uploaded_file\s*\(")
BACKTICK_RE = re.compile(r"`([^`]*)`")
UPLOAD_VALID_RE = re.compile(r"pathinfo|getimagesize|finfo_|mime_content_type|exif_imagetype|in_array")
FILES_NAME_RE = re.compile(r"\$_FILES\s*\[[^\]]+\]\s*\[\s*['\"]name['\"]\s*\]")

SIMPLE = [
    ("PHP008", re.compile(_NB + r"(?:md5|sha1)\s*\([^;]*pass", re.I)),
    ("PHP013", re.compile(_NB + r"extract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)")),
    ("PHP014", re.compile(r"CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:false|0)\b", re.I)),
    ("PHP016", re.compile(r"ini_set\s*\(\s*['\"]display_errors['\"]\s*,\s*(?:['\"]?(?:1|on|true|stdout)['\"]?)", re.I)),
    ("PHP017", re.compile(_NB + r"phpinfo\s*\(")),
]
WEAK_RAND = re.compile(_NB + r"(?:mt_rand|rand|uniqid)\s*\(")
SECRET_WORDS = re.compile(r"token|csrf|password|passwd|reset|otp|nonce|secret|session", re.I)
ASSIGN_RE = re.compile(r"^\$(\w+)\s*(?:\[[^\]]*\]\s*)*(\.?=)(?!=)\s*(.+)$", re.S)
FOREACH_RE = re.compile(r"^foreach\s*\((.+?)\s+as\s+(.+)\)\s*$", re.S)


def scan_php(text: str, path: str):
    lines = text.splitlines()
    has_validation = bool(UPLOAD_VALID_RE.search(text))
    findings, seen, vars_ = [], set(), {}

    def src(line):
        return lines[line - 1].strip()[:160] if 0 < line <= len(lines) else ""

    def add(rid, line, **kw):
        if (rid, line) not in seen:
            seen.add((rid, line))
            findings.append(make(rid, path, line, src(line), **kw))

    for body, seg_line in php_segments(text):
        for stmt, sline in split_statements(strip_comments(body), seg_line):
            # --- taint propagation ---
            m = ASSIGN_RE.match(stmt)
            if m:
                name, op, rhs = m.groups()
                cls = {c for c in CLASSES if tainted_for(rhs, c, vars_)}
                vars_[name] = (vars_.get(name, set()) | cls) if op == ".=" else cls
            fm = FOREACH_RE.match(stmt)
            if fm:
                cls = {c for c in CLASSES if tainted_for(fm.group(1), c, vars_)}
                if cls:
                    for v in VAR_RE.findall(fm.group(2)):
                        vars_[v] = vars_.get(v, set()) | cls

            def line_of(idx):
                return sline + stmt.count("\n", 0, idx)

            # --- sinks ---
            for rid, cls, rx, mode in SINKS:
                for sm in rx.finditer(stmt):
                    if mode == "rest":
                        target = stmt[sm.end():]
                    else:
                        inner, _ = balanced(stmt, sm.end())
                        target = split_args(inner)[0] if mode == "first" else inner
                    if tainted_for(target, cls, vars_):
                        add(rid, line_of(sm.start()))

            for em in EVAL_RE.finditer(stmt):
                inner, _ = balanced(stmt, em.end())
                tainted = tainted_for(inner, "code", vars_)
                if tainted:
                    add("PHP006", line_of(em.start()), message=f"{em.group(1)}() executes user-controlled input")
                elif em.group(1) in ("eval", "create_function"):
                    add("PHP006", line_of(em.start()), severity="medium",
                        message=f"{em.group(1)}() used: dynamic code execution, review that no input reaches it")

            for bm in BACKTICK_RE.finditer(stmt):
                if tainted_for(bm.group(1), "cmd", vars_):
                    add("PHP004", line_of(bm.start()))

            for um in UPLOAD_RE.finditer(stmt):
                inner, _ = balanced(stmt, um.end())
                args = split_args(inner)
                dest = args[1] if len(args) > 1 else ""
                if FILES_NAME_RE.search(dest) or tainted_for(dest, "upload", vars_):
                    add("PHP007", line_of(um.start()), severity="medium" if has_validation else "high")

            for rid, rx in SIMPLE:
                sm = rx.search(stmt)
                if sm:
                    add(rid, line_of(sm.start()))
            wm = WEAK_RAND.search(stmt)
            if wm and SECRET_WORDS.search(stmt):
                add("PHP015", line_of(wm.start()))
    return findings
