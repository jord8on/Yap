"""Read-only source regression tests. Run with python3 -I -B on a source checkout."""
import ast
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
SWIFT = ROOT / "app/Sources/Yap"
SHELL = ROOT / "scripts"

# Keep quoted Swift strings intact so this also checks Process executable paths.
SWIFT_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|/\*.*?\*/|//[^\n]*', re.DOTALL)
BYPASS = re.compile(
    r"\b(?:remove|set|fremove|fset|lremove|lset)xattr\s*\("
    r"|/usr/bin/xattr\b|\bstripQuarantine\b"
    r"|\bxattr\s+(?:-[A-Za-z]+\s+)*(?:-[A-Za-z]*[cdw][A-Za-z]*\b|--(?:clear|delete|write)\b)"
    r"|\bspctl\b[^\n]*?\s--(?:master-disable|global-disable|disable|add)(?![-\w])"
    r"|\bsecurity\s+(?:add-trusted-cert|authorizationdb\s+write)\b"
    r"|\bcurl\b[^\n]*?\s-[A-Za-z]*k[A-Za-z]*(?![-\w])"
    r"|\bSetFile\s+[^\n]*-a\s+[^\s]*[Qq]"
    r"|(?<![\w-])--(?:no-quarantine|noqtn|noextattr|norsrc|insecure)(?![-\w])"
    r"|\bDITTONORSRC\s*="
)
INPUT_APIS = re.compile(
    r"\b(?:CGEventTapCreate(?:ForPid|ForPSN)?|IOHIDManagerCreate|IOHIDDeviceOpen"
    r"|pynput|keyboard\.(?:hook|on_press|on_release)|evdev\.InputDevice)\b"
)
MONITOR = re.compile(r"\b(add(?:Global|Local)MonitorForEvents)\s*\(\s*matching:\s*([^)]+)\)")


def read_source(path):
    if not path.resolve().is_relative_to(ROOT):
        raise ValueError(f"Source resolves outside repository: {path}")
    return path.read_text(encoding="utf-8")


def swift_code(source):
    return SWIFT_TOKEN.sub(
        lambda match: match[0] if match[0].startswith('"') else "\n" * match[0].count("\n"),
        source,
    )


def bypass_location(source):
    # Join shell continuations to catch split invocations in scripts and docs.
    return BYPASS.search(re.sub(r"\\\r?\n", " ", source))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def forwards(node):
    return (
        isinstance(node, ast.Return)
        and isinstance(node.value, ast.Await)
        and isinstance(node.value.value, ast.Call)
        and ast.unparse(node.value.value.func) == "call_next"
    )


def denies(branch, status):
    return (
        isinstance(branch, ast.If)
        and len(branch.body) == 1
        and isinstance(branch.body[0], ast.Return)
        and isinstance(response := branch.body[0].value, ast.Call)
        and ast.unparse(response.func) == "JSONResponse"
        and any(k.arg == "status_code" and ast.unparse(k.value) == str(status)
                for k in response.keywords)
    )


def check_server(source):
    module = ast.parse(source)
    functions = {item.name: item for item in module.body
                 if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))}
    token_loader = functions["_load_or_create_token"]
    for node in ast.walk(token_loader):
        require(not isinstance(node, ast.Return) or
                (node.value is not None and ast.unparse(node.value) != "None"),
                "token loader has a missing-token fallback")
    require(not any(isinstance(node, ast.Constant) and node.value == "YAP_AUTH_TOKEN"
                    for node in ast.walk(module)), "inline bearer token override")

    guard = functions["auth_guard"]
    dispatch = [node for node in ast.walk(guard) if forwards(node)]
    branches = [stmt for stmt in guard.body if isinstance(stmt, ast.If)]
    verify = next((stmt for stmt in branches
                   if ast.unparse(stmt.test) == "request.url.path == '/verify'"), None)
    require(verify is not None and not verify.orelse and len(verify.body) == 1
            and forwards(verify.body[0]) and forwards(guard.body[-1]) and len(dispatch) == 2,
            "unexpected unauthenticated dispatch path")
    before_verify = guard.body[:guard.body.index(verify)]
    require(any(denies(branch, 403) and ast.unparse(branch.test) == "_is_browser_request(request)"
                for branch in before_verify), "browser rejection must precede /verify")
    token_names = {"AUTH_TOKEN"}
    for stmt in before_verify:
        if isinstance(stmt, ast.Assign) and ast.unparse(stmt.value) == "AUTH_TOKEN":
            token_names.update(ast.unparse(target) for target in stmt.targets)
    require(any(denies(branch, 503) and any(
        ast.unparse(branch.test) in (f"not {name}", f"{name} is None") for name in token_names
    ) for branch in before_verify), "missing-token rejection must precede /verify")
    require(any(denies(branch, 401) and any(
        isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not)
        and isinstance(node.operand, ast.Call)
        and ast.unparse(node.operand.func) == "hmac.compare_digest"
        and any(ast.unparse(arg) in {f"{name}.encode()" for name in token_names}
                for arg in node.operand.args)
        for node in ast.walk(branch.test)
    ) for branch in branches), "protected dispatch is missing the bearer comparison gate")

    main = functions["main"]
    assignments = {ast.unparse(item.targets[0]): item.value for item in main.body
                   if isinstance(item, ast.Assign) and len(item.targets) == 1}
    bearer = assignments.get("AUTH_TOKEN")
    if isinstance(bearer, ast.Name):
        bearer = assignments.get(bearer.id)
    require(isinstance(bearer, ast.Call) and ast.unparse(bearer.func) == "_load_or_create_token",
            "listener startup must load a private token")
    listen = [node for node in ast.walk(module)
              if isinstance(node, ast.Call) and ast.unparse(node.func) == "uvicorn.run"]
    require(len(listen) == 1 and isinstance(main.body[-1], ast.Expr)
            and main.body[-1].value is listen[0], "unexpected backend listener path")
    tls = {arg.arg: arg.value for arg in listen[0].keywords}
    keys = ("ssl_certfile", "ssl_keyfile")
    require(all(isinstance(tls.get(key), ast.Call) and ast.unparse(tls[key].func) == "str"
                and len(tls[key].args) == 1 for key in keys), "backend listener TLS is required")
    files = ast.unparse(ast.Tuple(elts=[tls[key].args[0] for key in keys], ctx=ast.Load()))
    identity = assignments.get(files)
    require(isinstance(identity, ast.Call) and ast.unparse(identity.func) == "ensure_identity",
            "backend TLS listener must use the private identity")


def check_client(source):
    code = swift_code(source)
    auth = re.search(r"\bfunc\s+authed\b[^{}]*\{\s*guard\s+([^{}]+?)\s+else\s*\{([^{}]+)\}", code)
    require(auth is not None and re.match(r"isPinnedLoopbackOrigin\s*,", auth[1])
            and re.search(r"\blet\s+\w+\s*=\s*[\w.]+\.(?:bearerToken|token)\b", auth[1])
            and re.search(r"\bawait\s+verifyAuthentic\s*\([^)]*\)\s*(?:,|$)", auth[1])
            and re.match(r"\s*throw\s+", auth[2]), "Swift request auth must fail closed")
    pin = re.search(r"\bdidReceive\s+challenge\b[^{}]*\{\s*guard\s+([^{}]+?)\s+else\s*\{([^{}]+)\}", code)
    require(pin is not None and "pinnedTLSCertificateDER" in pin[1]
            and re.search(r"SecCertificateCopyData\([^)]*\)[^,]*==\s*\w+\s*(?:,|$)", pin[1])
            and re.search(r'\.host\s*==\s*"127\.0\.0\.1"', pin[1])
            and re.search(r'\.protocol\s*==\s*"https"', pin[1])
            and ".cancelAuthenticationChallenge" in pin[2] and re.search(r"\breturn\b", pin[2]),
            "TLS challenge must require the pinned loopback certificate")
    require(re.search(
        r"\bwillPerformHTTPRedirection\b[^{}]*\{\s*completionHandler\s*\(\s*nil\s*\)\s*\}", code
    ), "authenticated backend redirects must be rejected")


class RepositoryPolicyTests(unittest.TestCase):
    def test_no_quarantine_or_security_override(self):
        paths = [*SWIFT.rglob("*.swift"), *SHELL.rglob("*.sh"), *SHELL.rglob("*.swift"), SHELL / "yap",
                 *(ROOT / "backend").glob("*.py"), *(ROOT / ".github/workflows").glob("*.yml"),
                 *(ROOT / "docs").rglob("*.md"), ROOT / "README.md", ROOT / "AGENTS.md"]
        for path in paths:
            with self.subTest(path=path.relative_to(ROOT)):
                source = read_source(path)
                if path.suffix == ".swift":
                    source = swift_code(source)
                match = bypass_location(source)
                self.assertIsNone(match, f"Prohibited security override: {match[0] if match else ''}")

    def test_python_source_syntax_and_auth(self):
        for path in [*(ROOT / "backend").rglob("*.py"), *SHELL.rglob("*.py")]:
            with self.subTest(path=path.relative_to(ROOT)):
                ast.parse(read_source(path), filename=str(path.relative_to(ROOT)))
        check_server(read_source(ROOT / "backend/server.py"))

    def test_swift_backend_client_requires_pinned_auth(self):
        check_client(read_source(SWIFT / "BackendClient.swift"))
        for name in ("BackendClient.swift", "BackendManager.swift", "CLITest.swift"):
            with self.subTest(path=name):
                self.assertNotRegex(swift_code(read_source(SWIFT / name)), r'http://127\.0\.0\.1(?=[:/"])')

    def test_sealed_bundle_bytecode_policy(self):
        backend_manager = swift_code(read_source(SWIFT / "BackendManager.swift"))
        self.assertRegex(backend_manager, r'\.arguments\s*=\s*\[\s*"-B"[^\]]*\bserver\.path')
        script = re.sub(r"\\\r?\n", " ", read_source(SHELL / "bundle_python.sh"))
        self.assertRegex(script, r"\s-B\s+-m\s+pip\s+install\s+[^\n]*--no-compile\b")
        self.assertRegex(script, r"\s-B\s+-c\s+\"import\b")

    def test_signing_failure_and_evaluation_policy(self):
        build = read_source(SHELL / "build_app.sh")
        self.assertRegex(build, r"(?m)^set\s+-euo\s+pipefail$")
        self.assertNotRegex(build, r"(?m)^\s*[^#\n]*\bcodesign\b[^\n]*\|\|")
        evaluation = re.findall(r"^[ \t]*evaluation\)[ \t]*\n(.*?)^[ \t]*;;", build,
                                re.MULTILINE | re.DOTALL)
        self.assertEqual(len(evaluation), 2)
        self.assertNotRegex("\n".join(evaluation), r"\b(?:security|keychain)\b")
        ad_hoc = re.compile(r"\bcodesign\b[^\n]*--sign\s+-\s")
        self.assertRegex(evaluation[1], ad_hoc)
        self.assertEqual(len(ad_hoc.findall(build)), 1)

    def test_opt_in_and_input_monitor_policy(self):
        prefs = swift_code(read_source(SWIFT / "Prefs.swift"))
        for key in ("historyEnabled", "agentAPIEnabled", "agentListenEnabled", "autoUpdateCheck",
                    "dictationEnabled", "autoStartVoice"):
            self.assertRegex(prefs, rf'\b{key}\s*=\s*d\.bool\(\s*forKey:\s*"{key}"\s*\)')
        evaluation = swift_code(read_source(SWIFT / "EvaluationPolicy.swift"))
        self.assertRegex(evaluation, r"\bpocketEnabled\s*=\s*false\b")
        settings = SWIFT / "Views/SettingsView.swift"
        settings_code = swift_code(read_source(settings))
        recorder = re.search(r"\bstruct\s+HotKeyRecorder\b.*?(?=^}|\Z)", settings_code,
                             re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(recorder)
        global_sites, key_sites = [], []
        for path in SWIFT.rglob("*.swift"):
            code = swift_code(read_source(path))
            self.assertNotRegex(code, INPUT_APIS)
            for match in MONITOR.finditer(code):
                api, mask = match.groups()
                if api == "addGlobalMonitorForEvents":
                    global_sites.append((path, mask.strip()))
                elif not re.fullmatch(r"\s*\.(?:flagsChanged|leftMouseDown)\s*", mask):
                    key_sites.append((path, re.sub(r"\s", "", mask)))
                    self.assertEqual(path, settings)
                    self.assertTrue(recorder.start() < match.start() < recorder.end())
        self.assertEqual(global_sites, [(SWIFT / "HotKey.swift", ".flagsChanged")])
        self.assertEqual(key_sites, [(settings, "[.keyDown,.flagsChanged]")])
        self.assertRegex(recorder[0], r"recording\s*\?\s*startMonitor\(\)\s*:\s*stopMonitor\(\)")
        self.assertRegex(recorder[0], r"\.onDisappear\s*\{\s*stopMonitor\(\)\s*\}")
        self.assertRegex(recorder[0], r"recording\s*=\s*false\s+stopMonitor\(\)")
        for path in (ROOT / "backend").glob("*.py"):
            self.assertNotRegex(read_source(path), INPUT_APIS)


class MutationTests(unittest.TestCase):
    def test_bypass_mutations(self):
        clean = 'ditto --extattr --qtn "$src" "$dest"\n'
        self.assertIsNone(bypass_location(clean))
        for mutation in (
            'xattr \\\n  -rc "$dest"',
            'xattr -r -d com.apple.quarantine "$dest"',
            'spctl --global-disable',
            'ditto --noqtn "$src" "$dest"',
            'process.executableURL = URL(fileURLWithPath: "/usr/bin/xattr")',
            'os.removexattr(path, attribute)',
        ):
            with self.subTest(mutation=mutation):
                self.assertIsNotNone(bypass_location(clean + mutation))

    def test_auth_mutations(self):
        source = read_source(ROOT / "backend/server.py")
        check_server(source)
        for old, new in (
            ('if not token:', 'if token:'),
            ('request.url.path == "/verify"', 'request.url.path in ("/verify", "/health")'),
            ('not hmac.compare_digest(', 'hmac.compare_digest('),
            ('ssl_certfile=str(cert_file)', 'ssl_certfile=None'),
        ):
            with self.subTest(mutation=new):
                self.assertIn(old, source, "Update mutation to match the protected source")
                with self.assertRaises(ValueError):
                    check_server(source.replace(old, new, 1))

    def test_swift_pin_mutation(self):
        source = read_source(SWIFT / "BackendClient.swift")
        check_client(source)
        mutated, count = re.subn(r"(SecCertificateCopyData\([^)]*\)[^,\n]*?)==", r"\1!=", source, count=1)
        self.assertEqual(count, 1, "Update mutation to match the pin comparison")
        with self.assertRaisesRegex(ValueError, "TLS challenge"):
            check_client(mutated)


if __name__ == "__main__":
    unittest.main(verbosity=2)
