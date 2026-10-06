#!/usr/bin/env python3
"""Fail-closed source admission using owner-installed policy and SSH approvals.

The external policy and installed evaluator are cooperative integrity boundaries,
not a sandbox against a malicious process with the same operating-system user.
Local Git hooks are bypassable; protected-base CI is the publication backstop.
"""
import argparse
import base64
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import ssl
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

NAMESPACE = "naome-factory-v1"
LIMIT = 16 * 1024 * 1024
ABSOLUTE_EVIDENCE_LIMIT = 256 * 1024 * 1024
KINDS = {"production_source", "production_fixture", "production_tool", "license", "build_configuration", "agent_entrypoint"}
HOOK_MARKER = "# NAOME production admission hook v1"


class Rejection(Exception):
    def __init__(self, code, detail):
        super().__init__(detail)
        self.code = code


def reject(code, detail):
    raise Rejection(code, detail)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def bounded_read(path, limit=LIMIT):
    with Path(path).open("rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        reject("resource", "input exceeds configured bound")
    return data


def no_duplicate_keys(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            reject("schema", "duplicate JSON member: " + key)
        output[key] = value
    return output


def parse_json(data):
    def reject_constant(value):
        reject("schema", "nonfinite JSON number: " + value)
    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            reject("schema", "overflowed JSON number")
        return number
    return json.loads(data, object_pairs_hook=no_duplicate_keys, parse_constant=reject_constant, parse_float=finite_float)


def external(path, repo):
    target = Path(path).resolve(strict=True)
    if target == repo or repo in target.parents:
        reject("trust_location", "trust material must live outside candidate repository")
    if not target.is_file():
        reject("trust_location", "trust input must be a regular file")
    return target


def command(args, cwd=None, input=None, overrides=None):
    environment = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    environment.update({"GIT_OPTIONAL_LOCKS": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_NO_REPLACE_OBJECTS": "1"})
    environment.update(overrides or {})
    result = subprocess.run(args, cwd=cwd, input=input, capture_output=True, env=environment, timeout=30)
    if result.returncode:
        reject("command", "command failed: " + str(args[0]) + ": " + result.stderr.decode(errors="replace")[:2000])
    if len(result.stdout) > LIMIT:
        reject("resource", "command output exceeds input bound")
    return result.stdout


def git(repo, *args):
    overrides = {}
    index_file = os.environ.get("GIT_INDEX_FILE")
    if index_file:
        index = Path(index_file)
        if not index.is_absolute():
            index = Path.cwd() / index
        if index.is_symlink():
            reject("git_database", "symlink index override is forbidden")
        index = index.resolve()
        if repo / ".git" not in index.parents:
            reject("git_database", "index override must remain in standalone candidate .git")
        overrides["GIT_INDEX_FILE"] = str(index)
    safe_config = ["-c", "core.fsmonitor=false", "-c", "diff.external="]
    if args and args[0] != "config":
        safe_config.extend(["-c", "core.hooksPath=/dev/null"])
    return command(["git", *safe_config, "-C", str(repo), *args], overrides=overrides)


def revision(repo, name, kind):
    if not re.fullmatch(r"[0-9a-f]{40,64}", name):
        reject("identity", "revision must be an immutable hexadecimal object ID")
    return git(repo, "rev-parse", "--verify", name + "^{" + kind + "}").decode().strip()


def repository(path, candidate=False):
    if Path(path).is_symlink():
        reject("git_database", "repository root aliases are forbidden")
    repo = Path(path).resolve(strict=True)
    dotgit = repo / ".git"
    if not dotgit.is_dir() or dotgit.is_symlink():
        reject("git_database", "standalone non-symlink .git directory required")
    common = Path(git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir").decode().strip()).resolve()
    actual = Path(git(repo, "rev-parse", "--absolute-git-dir").decode().strip()).resolve()
    if common != dotgit.resolve() or actual != common:
        reject("git_database", "shared Git database is forbidden")
    if (common / "objects/info/alternates").exists() or (common / "commondir").exists():
        reject("git_database", "alternate/shared objects are forbidden")
    if (common / "info/grafts").exists() or (common / "refs/replace").exists() and any((common / "refs/replace").iterdir()):
        reject("git_database", "rewritten history views are forbidden")
    objects = common / "objects"
    for parent, directories, files in os.walk(objects):
        for name in directories + files:
            location = Path(parent) / name
            if location.is_symlink() or location.is_file() and location.stat().st_nlink > 1:
                reject("git_database", "symlink/hard-linked object storage is forbidden")
    for name in ("GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_DIR", "GIT_WORK_TREE"):
        if os.environ.get(name):
            reject("git_database", "external Git storage override: " + name)
    if candidate and git(repo, "remote").strip():
        reject("remote", "candidate repository must have no configured remotes")
    return repo


def validate_clean(repo, mode):
    if mode in {"commit", "candidate"}:
        if git(repo, "diff", "--no-ext-diff", "--no-textconv", "--name-only").strip() or git(repo, "ls-files", "--others", "--exclude-standard").strip():
            reject("dirty", "unstaged or untracked candidate files")
    elif git(repo, "status", "--porcelain", "--untracked-files=all").strip():
        reject("dirty", "publication requires a clean reviewed worktree")


def load_trust(repo, policy_path, bundle_path):
    policy_raw = bounded_read(external(policy_path, repo))
    policy = parse_json(policy_raw)
    if policy.get("version") != 1 or not isinstance(policy.get("production"), dict):
        reject("policy", "unsupported policy schema")
    evaluator_sha = sha256(bounded_read(Path(__file__).resolve()))
    if policy["production"].get("evaluator_sha256") != evaluator_sha:
        reject("evaluator", "running evaluator is not owner-pinned exact bytes")
    transport = policy["production"].get("evidence_transport", {})
    bundle_limit = min(ABSOLUTE_EVIDENCE_LIMIT, transport.get("maximum_bundle_bytes", 64 * 1024 * 1024))
    bundle = parse_json(bounded_read(external(bundle_path, repo), bundle_limit))
    if bundle.get("version") != 1 or not isinstance(bundle.get("receipts"), list) or not isinstance(bundle.get("objects"), dict):
        reject("schema", "unsupported approval bundle")
    return policy, sha256(policy_raw), evaluator_sha, bundle


def native_reference(reference, repo):
    if not isinstance(reference, dict) or not re.fullmatch(r"[0-9a-f]{64}", reference.get("sha256", "")):
        reject("native_prerequisite", "native artifact needs an exact digest")
    path = external(reference.get("path", ""), repo)
    if Path(reference["path"]).is_symlink():
        reject("native_prerequisite", "native artifact aliases are forbidden")
    raw = bounded_read(path)
    if not raw or sha256(raw) != reference["sha256"]:
        reject("native_prerequisite", "native artifact changed or empty")
    return raw


def native_projection(policy, repo=None):
    """Read only the declared current native configuration, including trust."""
    repo = Path(repo or policy["native_guard"]["shared_repositories"][0]).resolve()
    native = policy.get("production", {}).get("native_admission")
    if not isinstance(native, dict) or native.get("version") != 1:
        reject("native_prerequisite", "installed production requires native admission v1")
    projections = native.get("projections", [])
    required = {"hooks_definition", "hook_feature", "project_trust", "hook_trust"}
    output, seen = [], set()
    for projection in projections:
        identity = projection.get("id")
        if identity in seen or identity not in required:
            reject("native_prerequisite", "unexpected or duplicate native projection")
        seen.add(identity)
        path = external(projection.get("path", ""), repo)
        if Path(projection["path"]).is_symlink():
            reject("native_prerequisite", "native config aliases are forbidden")
        raw = bounded_read(path)
        if projection.get("format") == "toml":
            try:
                import tomllib
            except ImportError:
                try:
                    import tomli as tomllib
                except ImportError:
                    reject("native_prerequisite", "TOML parser is missing for current native state")
            source = tomllib.loads(raw.decode("utf-8"))
        elif projection.get("format") == "json":
            source = parse_json(raw)
        else:
            reject("native_prerequisite", "native projection format must be TOML or JSON")
        selectors = projection.get("selectors")
        if not isinstance(selectors, list) or not selectors:
            reject("native_prerequisite", "exact native field selectors required")
        values, handler_states = [], []
        for selector in selectors:
            keys = selector.get("path")
            if not isinstance(keys, list) or any(not isinstance(key, str) or not key for key in keys):
                reject("native_prerequisite", "native selector must contain exact field keys")
            current = source
            parent = None
            for key in keys:
                parent = current
                if not isinstance(current, dict) or key not in current:
                    reject("native_prerequisite", "current native field is missing: " + identity)
                current = current[key]
            if "expected" not in selector or canonical(current) != canonical(selector["expected"]):
                reject("native_prerequisite", "current native state differs: " + identity)
            if identity == "hook_feature" and current is not True:
                reject("native_prerequisite", "native hook feature must be enabled")
            if identity == "project_trust" and current != "trusted":
                reject("native_prerequisite", "native project is not trusted")
            if identity == "hook_trust":
                if not isinstance(current, str) or not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", current):
                    reject("native_prerequisite", "native trusted hook hash is missing")
                enabled = parent.get("enabled")
                # Official optional handler state defaults to enabled. Keep its
                # raw presence/value bound so later toggles cannot reuse proof.
                if enabled is not None and type(enabled) is not bool:
                    reject("native_prerequisite", "native handler enabled state must be optional boolean")
                if enabled is False:
                    reject("native_prerequisite", "native handler is explicitly disabled")
                handler_states.append({"path": keys[:-1]+["enabled"], "present": "enabled" in parent, "value": enabled})
            values.append({"path": keys, "value": current})
        output.append({"id":identity, "path":str(path), "format":projection["format"], "values":values+handler_states})
    if seen != required:
        reject("native_prerequisite", "hook definitions, feature, project and per-hook trust all required")
    return sorted(output, key=lambda item:item["id"])


def native_runtime_digest(record, repo):
    digest = record.get("sha256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        reject("native_prerequisite", "native runtime digest missing")
    path = external(record.get("path", ""), repo)
    value, count = hashlib.sha256(), 0
    with path.open("rb") as source:
        for chunk in iter(lambda:source.read(65536), b""):
            count += len(chunk)
            if count > 512*1024*1024:
                reject("native_prerequisite", "native runtime exceeds bound")
            value.update(chunk)
    if count == 0 or value.hexdigest() != digest:
        reject("native_prerequisite", "native runtime changed")
    return digest


def native_admission_check(policy, repo=None):
    """Fail closed before publication or work using owner-pinned native proof."""
    repo = Path(repo or policy["native_guard"]["shared_repositories"][0]).resolve()
    production = policy["production"]
    native = production.get("native_admission")
    if not isinstance(native, dict) or native.get("version") != 1:
        reject("native_prerequisite", "installed production requires owner-pinned current native proof")
    proof_raw = native_reference(native.get("proof"), repo)
    proof = parse_json(proof_raw)
    if proof.get("version") != 1 or proof.get("kind") != "native-admission":
        reject("native_prerequisite", "unsupported native proof")
    now = time.time()
    issued, expires, maximum = proof.get("issued_at"), proof.get("expires_at"), native.get("maximum_age_seconds")
    if any(type(value) not in (int,float) or not math.isfinite(value) for value in (issued, expires, maximum)) or not 0 < maximum <= 86400 or issued > now+30 or expires <= now or expires <= issued or now-issued > maximum:
        reject("native_prerequisite", "native proof is stale or expired")
    expected_runtime = {"evaluator":production.get("evaluator_sha256"), "guard":production.get("native_guard_sha256"), "operations":policy.get("journal", {}).get("evaluator_sha256")}
    if policy.get("native_guard", {}).get("temp_runner_path"):
        expected_runtime["temp-runner"] = production.get("temp_runner_sha256")
    runtimes, cli = {}, None
    for record in native.get("runtime", []):
        role = record.get("role")
        if role not in {*expected_runtime, "cli"} or role in runtimes:
            reject("native_prerequisite", "unexpected/duplicate native runtime role")
        runtimes[role] = native_runtime_digest(record, repo)
        if role == "cli":
            cli = external(record["path"], repo)
        elif runtimes[role] != expected_runtime[role]:
            reject("native_prerequisite", "native runtime differs from installed policy: " + role)
        if role == "evaluator" and external(record["path"], repo) != Path(__file__).resolve():
            reject("native_prerequisite", "native proof does not bind the running evaluator")
    if set(runtimes) != {*expected_runtime, "cli"} or proof.get("runtime_sha256") != runtimes:
        reject("native_prerequisite", "all current native runtime hashes must match proof")
    engine = proof.get("engine", {})
    if engine.get("feature") != "enabled" or engine.get("project_trust") != "trusted" or engine.get("hook_trust") != "trusted" or not isinstance(engine.get("version"), str):
        reject("native_prerequisite", "native engine state is untrusted or disabled")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][a-zA-Z0-9.-]+)?", engine["version"]) or native.get("cli_version") != engine["version"]:
        reject("native_prerequisite", "native CLI version differs from observed engine")
    projected = native_projection(policy, repo)
    projected_sha = sha256(canonical(projected))
    if proof.get("projection_sha256") != projected_sha:
        reject("native_prerequisite", "current native definitions/trust projection changed")
    required, denied = native.get("required_routes"), native.get("denied_routes")
    minimum = {"PreToolUse:Bash", "PreToolUse:apply_patch", "Interrupt", "SessionEnd"}
    if not isinstance(required, list) or not minimum.issubset(required) or len(set(required)) != len(required) or not isinstance(denied, list) or not denied or set(required).intersection(denied):
        reject("native_prerequisite", "all first-write and safety routes plus uncovered-route denial required")
    routes = {}
    for record in proof.get("coverage", []):
        route = record.get("route")
        if route in routes or route not in set(required+denied):
            reject("native_prerequisite", "unexpected/duplicate native coverage route")
        status = "covered" if route in required else "denied"
        if record.get("status") != status or not record.get("events") or not record.get("failures"):
            reject("native_prerequisite", "actual event and failure/denial evidence required: " + str(route))
        for reference in record["events"] + record["failures"]:
            native_reference(reference, repo)
        routes[route] = status
    if set(routes) != set(required+denied):
        reject("native_prerequisite", "native tool coverage incomplete; uncovered routes cannot publish")
    review_reference = proof.get("independent_review")
    review_raw = native_reference(review_reference, repo)
    review = parse_json(review_raw)
    core = {key:value for key,value in proof.items() if key != "independent_review"}
    principal = review_reference.get("principal")
    reviewers = production.get("required_review_roles", {}).get("reviewer", [])
    review_issued, review_expires = review.get("issued_at"), review.get("expires_at")
    if review.get("kind") != "native-admission-review" or review.get("decision") != "approve" or review.get("proof_core_sha256") != sha256(canonical(core)) or principal not in reviewers or any(type(value) not in (int,float) or not math.isfinite(value) for value in (review_issued, review_expires)) or review_issued > now+30 or review_expires <= now or now-review_issued > maximum:
        reject("native_prerequisite", "independent current native review does not approve exact proof")
    signature = external(review_reference.get("signature", ""), repo)
    with tempfile.TemporaryDirectory(prefix="factory-native-signature-") as directory:
        allowed = Path(directory)/"allowed-signers"
        allowed.write_text(principal+" "+policy["verifiers"][principal]+"\n")
        command(["ssh-keygen", "-Y", "verify", "-f", str(allowed), "-I", principal, "-n", NAMESPACE, "-s", str(signature)], input=canonical(review))
    return {"status":"approved", "proof_sha256":sha256(proof_raw), "projection_sha256":projected_sha, "runtime_sha256":runtimes, "native_routes":routes, "reviewed_by":principal}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def download_object(url, digest, size, policy):
    transport = policy.get("production", {}).get("evidence_transport", {})
    bound = transport.get("maximum_object_bytes", 64 * 1024 * 1024)
    if not isinstance(bound, int) or not 0 < bound <= ABSOLUTE_EVIDENCE_LIMIT:
        reject("policy", "invalid evidence resource ceiling")
    prefixes = transport.get("allowed_url_prefixes", [])
    if not isinstance(url, str) or not isinstance(prefixes, list):
        reject("transport", "owner-approved evidence origin required")
    parsed = urllib.parse.urlsplit(url)
    segments = urllib.parse.unquote(parsed.path).split("/")
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or any(p in {".", ".."} for p in segments):
        reject("transport", "HTTPS immutable unauthenticated evidence URL required")
    if not any(isinstance(prefix, str) and prefix.startswith("https://") and (url == prefix or prefix.endswith("/") and url.startswith(prefix)) for prefix in prefixes):
        reject("transport", "evidence URL is outside owner-approved origins")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or not isinstance(size, int) or not 0 < size <= bound:
        reject("resource", "digest and exact bounded evidence length required")
    timeout = transport.get("timeout_seconds", 15)
    if not isinstance(timeout, (int, float)) or not 0 < timeout <= 30:
        reject("policy", "invalid evidence transport timeout")
    request = urllib.request.Request(url, headers={"Accept-Encoding": "identity", "User-Agent": "NAOME-production-admission/1"})
    context = ssl.create_default_context(cafile=os.environ.get("SSL_CERT_FILE") or None)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context), NoRedirect())
    chunks, count, observed = [], 0, hashlib.sha256()
    try:
        with opener.open(request, timeout=timeout) as response:
            if response.getcode() != 200 or response.geturl() != url:
                reject("transport", "redirected or unsuccessful evidence response")
            length = response.headers.get("Content-Length")
            if length is not None and int(length) != size:
                reject("resource", "evidence Content-Length differs from exact declared size")
            if response.headers.get("Content-Encoding", "identity") != "identity":
                reject("transport", "encoded evidence transport is unsupported")
            while True:
                chunk = response.read(min(65536, size - count + 1))
                if not chunk:
                    break
                count += len(chunk)
                if count > size:
                    reject("resource", "evidence response exceeded exact declared size")
                observed.update(chunk)
                chunks.append(chunk)
    except (urllib.error.URLError, OSError, ValueError) as error:
        reject("transport", "evidence transport failed: " + str(error))
    if count != size or observed.hexdigest() != digest:
        reject("object_digest", "downloaded evidence bytes do not match immutable approval")
    return b"".join(chunks)


def object_bytes(bundle, digest, policy):
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        reject("evidence", "digest-bound object required")
    encoded = bundle["objects"].get(digest)
    if isinstance(encoded, dict):
        data = download_object(encoded.get("url"), digest, encoded.get("size"), policy)
        return data
    bound = min(ABSOLUTE_EVIDENCE_LIMIT, policy["production"].get("evidence_transport", {}).get("maximum_object_bytes", 64 * 1024 * 1024))
    if not isinstance(encoded, str) or len(encoded) > bound * 4 // 3 + 4:
        reject("evidence", "missing or oversized evidence object")
    try:
        data = base64.b64decode(encoded, validate=True)
    except ValueError:
        reject("evidence", "invalid evidence encoding")
    if len(data) > bound or sha256(data) != digest:
        reject("object_digest", "evidence object bytes do not match signed digest")
    return data


def signatures(statement, approvals, policy):
    verifiers = policy.get("verifiers", {})
    approved = set()
    keys = {}
    with tempfile.TemporaryDirectory(prefix="factory-signature-") as directory:
        directory = Path(directory)
        allowed = directory / "allowed_signers"
        for approval in approvals:
            principal = approval.get("principal")
            key = verifiers.get(principal)
            if not isinstance(principal, str) or not re.fullmatch(r"[A-Za-z0-9_.@-]+", principal) or not isinstance(key, str):
                reject("signature", "unknown approval identity")
            parts = key.split()
            if len(parts) < 2 or "\n" in key or "\r" in key:
                reject("signature", "invalid trusted SSH public key")
            key_identity = " ".join(parts[:2])
            if principal in approved:
                reject("signature", "duplicate approval")
            signature = approval.get("signature")
            if not isinstance(signature, str) or len(signature) > 16384:
                reject("signature", "invalid SSH signature")
            allowed.write_text(principal + " " + key + "\n")
            signature_file = directory / "approval.sig"
            signature_file.write_text(signature)
            result = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(allowed), "-I", principal, "-n", NAMESPACE, "-s", str(signature_file)], input=canonical(statement), capture_output=True, timeout=10)
            if result.returncode:
                reject("signature", "SSH approval verification failed for " + principal)
            approved.add(principal)
            keys[principal] = key_identity
    author = statement.get("author")
    if not isinstance(author, str) or not author or author in approved:
        reject("independence", "author cannot approve own source")
    roles = policy["production"].get("required_review_roles")
    if not isinstance(roles, dict) or not {"reviewer", "integrator"}.issubset(roles):
        reject("policy", "independent reviewer and integration owner are required")
    selections = []
    for role, principals in roles.items():
        matches = approved.intersection(principals)
        if not matches:
            reject("approval", "missing approval role: " + role)
        selections.append(matches)
    def distinct(index, used_principals, used_keys):
        if index == len(selections):
            return True
        return any(distinct(index + 1, used_principals | {p}, used_keys | {keys[p]}) for p in selections[index] if p not in used_principals and keys[p] not in used_keys)
    if not distinct(0, set(), set()):
        reject("independence", "review roles require distinct principals and keys")
    return sorted(approved)


def snapshot(repo, tree):
    entries = []
    for line in git(repo, "ls-tree", "-rz", "--full-tree", tree).split(b"\0"):
        if not line:
            continue
        header, path_raw = line.split(b"\t", 1)
        mode, kind, oid = header.decode().split()
        path = path_raw.decode("utf-8")
        if kind != "blob" or mode not in {"100644", "100755"}:
            reject("classification", "submodules/symlinks require a separately qualified deployment contract: " + path)
        if any(ord(char) < 32 for char in path):
            reject("classification", "control characters in source path")
        entries.append({"path": path, "mode": mode, "sha256": sha256(git(repo, "cat-file", "blob", oid))})
    return entries


def staged_view(repo):
    """Compute the selected Git tree without writing objects or the index."""
    root = {}
    blobs = {}
    for row in git(repo, "ls-files", "--stage", "-z").split(b"\0"):
        if not row:
            continue
        header, path_raw = row.split(b"\t", 1)
        mode, oid, stage = header.decode("ascii").split()
        path = path_raw.decode("utf-8")
        if stage != "0":
            reject("identity", "unmerged index cannot be admitted")
        if mode not in {"100644", "100755"}:
            reject("classification", "submodules/symlinks require a separately qualified deployment contract: " + path)
        parts = path.split("/")
        if any(part in {"", ".", ".."} for part in parts) or any(ord(char) < 32 for char in path):
            reject("classification", "invalid/control characters in source path")
        directory = root
        for part in parts[:-1]:
            if part in directory and not isinstance(directory[part], dict):
                reject("identity", "index path collision")
            directory = directory.setdefault(part, {})
        if parts[-1] in directory:
            reject("identity", "duplicate index path")
        data = git(repo, "cat-file", "blob", oid)
        directory[parts[-1]] = (mode, oid, {"path": path, "mode": mode, "sha256": sha256(data)})
        blobs[path] = oid
    algorithm = git(repo, "rev-parse", "--show-object-format").decode().strip()
    if algorithm not in {"sha1", "sha256"}:
        reject("git_database", "unsupported Git object format")
    entries = []
    def tree_hash(directory):
        raw = bytearray()
        ordered = sorted(directory.items(), key=lambda item: item[0].encode("utf-8") + (b"/" if isinstance(item[1], dict) else b"\0"))
        for name, entry in ordered:
            if isinstance(entry, dict):
                mode, oid = "40000", tree_hash(entry)
            else:
                mode, oid, record = entry
                entries.append(record)
            raw.extend(mode.encode("ascii") + b" " + name.encode("utf-8") + b"\0" + bytes.fromhex(oid))
        header = b"tree " + str(len(raw)).encode("ascii") + b"\0"
        return hashlib.new(algorithm, header + raw).hexdigest()
    return {"tree": tree_hash(root), "entries": entries, "blobs": blobs}


def selected_patch(repo, base, tree, staged=None):
    if staged is not None:
        return git(repo, "diff", "--cached", "--no-ext-diff", "--no-textconv", "--binary", "--full-index", base)
    return git(repo, "diff", "--no-ext-diff", "--no-textconv", "--binary", "--full-index", base, tree)


def validate_receipt(repo, tree, source_commit, mode, policy, policy_sha, evaluator_sha, bundle, staged=None):
    receipts = [r for r in bundle["receipts"] if isinstance(r, dict) and isinstance(r.get("statement"), dict) and r["statement"].get("tree") == tree]
    if len(receipts) != 1:
        reject("receipt_missing", "exact tree needs one unambiguous owner-approved receipt: " + tree)
    receipt = receipts[0]
    statement = receipt["statement"]
    if statement.get("version") != 1:
        reject("schema", "unsupported receipt schema")
    if statement.get("policy_sha256") != policy_sha:
        reject("policy", "receipt is bound to a different policy")
    if statement.get("evaluator_sha256") != evaluator_sha:
        reject("evaluator", "receipt is bound to a different evaluator")
    reviewed_by = signatures(statement, receipt.get("signatures", []), policy)
    now = int(time.time())
    issued, expires = statement.get("issued_at"), statement.get("expires_at")
    maximum_age = policy["production"].get("maximum_evidence_age_seconds", 86400)
    if not isinstance(issued, int) or not isinstance(expires, int) or issued > now + 30 or expires <= now or expires <= issued or now - issued > maximum_age:
        reject("expired", "qualification or approval is stale/expired")
    base = revision(repo, statement.get("base", ""), "commit")
    if mode in {"commit", "candidate"} and base != git(repo, "rev-parse", "HEAD").decode().strip():
        reject("identity", "staged admission must be relative to current HEAD")
    if source_commit:
        parents = git(repo, "rev-list", "--parents", "-n", "1", source_commit).decode().split()[1:]
        if parents != [base]:
            reject("identity", "publication must be the exact selected patch with one approved base parent")
    entries = staged["entries"] if staged is not None else snapshot(repo, tree)
    patch = selected_patch(repo, base, tree, staged)
    if statement.get("patch_sha256") != sha256(patch) or statement.get("snapshot_sha256") != sha256(canonical(entries)):
        reject("identity", "reviewed source snapshot or selected patch changed")
    capability = statement.get("capability", {})
    if capability.get("kind") != "production" or any(not isinstance(capability.get(k), str) or not capability[k].strip() for k in ("id", "consumer", "deployment_contract")):
        reject("capability", "real supported production consumer and deployment contract required")
    classification = statement.get("classification", [])
    if not isinstance(classification, list):
        reject("classification", "per-path classification required")
    paths = {e["path"] for e in entries}
    classified = set()
    denied = set(policy["production"].get("denied_path_segments", ["research"]))
    for record in classification:
        path = record.get("path")
        if path not in paths or path in classified or record.get("kind") not in KINDS or denied.intersection(Path(path).parts):
            reject("classification", "unqualified, duplicate or exploratory path: " + str(path))
        if any(not isinstance(record.get(k), str) or not record[k].strip() for k in ("consumer", "license", "provenance")):
            reject("classification", "consumer/license/provenance missing for " + path)
        classified.add(path)
    if classified != paths:
        reject("classification", "complete actual source tree must be classified; no legacy exemption")
    artifacts = statement.get("artifacts", [])
    if not artifacts or any(not isinstance(a, dict) or not a.get("name") for a in artifacts):
        reject("evidence", "deployable package/install artifact required")
    for artifact in artifacts:
        if not object_bytes(bundle, artifact.get("sha256"), policy):
            reject("evidence", "empty deployment artifact")
    evidence = statement.get("evidence", {})
    required = policy["production"].get("required_evidence", [])
    if not required or not isinstance(evidence, dict):
        reject("evidence", "qualification evidence required")
    for category in required:
        raw = object_bytes(bundle, evidence.get(category), policy)
        record = parse_json(raw)
        if not isinstance(record, dict) or record.get("source_tree") != tree or record.get("category") != category or record.get("exit_code") != 0:
            reject("evidence", "failed or wrong-source qualification: " + category)
        argv = record.get("command")
        if not isinstance(argv, list) or not argv or any(not isinstance(a, str) or not a for a in argv):
            reject("evidence", "executed qualification command required: " + category)
        checks = record.get("checks")
        if not isinstance(checks, list) or not checks:
            reject("evidence", "actual expected/observed contract checks required: " + category)
        for check in checks:
            if not isinstance(check, dict) or not check.get("name") or isinstance(check.get("expected"), bool) or check.get("expected") in (None, "", [], {}) or check.get("expected") != check.get("observed"):
                reject("evidence", "unmet/non-observational qualification check: " + category)
        if not object_bytes(bundle, record.get("log_sha256"), policy):
            reject("evidence", "retained execution output required: " + category)
    return {"status": "approved", "tree": tree, "base": base, "patch_sha256": sha256(patch), "snapshot_sha256": sha256(canonical(entries)), "classified_paths": len(paths), "capability": capability["id"], "reviewed_by": reviewed_by, "evidence_categories": required}


def allowed_remote(repo, policy, selected=None):
    allowed = policy["production"].get("allowed_publish_remotes", [])
    names = git(repo, "remote").decode().splitlines()
    if not names:
        reject("remote", "publication remote is not configured")
    found = False
    for name in names:
        urls = git(repo, "remote", "get-url", "--all", "--push", name).decode().splitlines()
        if any(url not in allowed for url in urls):
            reject("remote", "unapproved writable publication remote")
        if selected in urls:
            found = True
    if selected and not found:
        reject("remote", "pre-push destination differs from approved configured remote")


def check(args):
    repo = repository(args.repo, candidate=args.mode == "candidate")
    policy, policy_sha, evaluator_sha, bundle = load_trust(repo, args.policy, args.bundle)
    if args.mode in {"commit", "publish"}:
        native_admission_check(policy, repo)
    validate_clean(repo, args.mode)
    if args.mode == "publish":
        allowed_remote(repo, policy)
    commit = None
    staged = None
    if args.mode in {"commit", "candidate"}:
        staged = staged_view(repo)
        tree = staged["tree"]
    else:
        commit = revision(repo, args.tree or git(repo, "rev-parse", "HEAD").decode().strip(), "commit")
        tree = git(repo, "rev-parse", commit + "^{tree}").decode().strip()
    return validate_receipt(repo, tree, commit, args.mode, policy, policy_sha, evaluator_sha, bundle, staged)


def pre_push(args):
    repo = repository(args.repo)
    policy, policy_sha, evaluator_sha, bundle = load_trust(repo, args.policy, args.bundle)
    native_admission_check(policy, repo)
    validate_clean(repo, "publish")
    allowed_remote(repo, policy, args.remote_url)
    results = []
    input_data = sys.stdin.read(LIMIT + 1)
    if len(input_data) > LIMIT:
        reject("resource", "oversized push input")
    for line in input_data.splitlines():
        fields = line.split()
        if len(fields) != 4:
            reject("identity", "invalid pre-push ref input")
        _, local, _, remote = fields
        if set(local) == {"0"}:
            reject("identity", "ref deletion needs separate human authorization")
        local = revision(repo, local, "commit")
        if set(remote) == {"0"}:
            tree = git(repo, "rev-parse", local + "^{tree}").decode().strip()
            matching = [r["statement"]["base"] for r in bundle["receipts"] if r.get("statement", {}).get("tree") == tree]
            if len(matching) != 1:
                reject("receipt_missing", "new pushed branch lacks exact-source approval")
            base = revision(repo, matching[0], "commit")
        else:
            base = revision(repo, remote, "commit")
        if subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor", base, local], capture_output=True, timeout=30).returncode:
            reject("identity", "non-fast-forward publication is forbidden")
        commits = git(repo, "rev-list", "--reverse", base + ".." + local).decode().splitlines()
        if not commits:
            continue
        for commit in commits:
            tree = git(repo, "rev-parse", commit + "^{tree}").decode().strip()
            results.append(validate_receipt(repo, tree, commit, "publish", policy, policy_sha, evaluator_sha, bundle))
    if not input_data.strip():
        reject("identity", "missing pushed-ref input")
    return {"status": "approved", "pushed_commits": results}


def hook_state(repo):
    return repo / ".git/naome-factory-hooks.json"


def atomic_write(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".factory-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def install_hooks(args):
    repo = repository(args.repo)
    evaluator = external(args.evaluator, repo)
    policy_path, bundle_path = external(args.policy, repo), external(args.bundle, repo)
    policy = parse_json(bounded_read(policy_path))
    if sha256(bounded_read(evaluator)) != policy.get("production", {}).get("evaluator_sha256"):
        reject("evaluator", "installed external evaluator does not match trusted policy")
    native_admission_check(policy, repo)
    hooks_path = git(repo, "config", "--get", "core.hooksPath").decode().strip() if subprocess.run(["git", "-C", str(repo), "config", "--get", "core.hooksPath"], capture_output=True).returncode == 0 else ""
    if hooks_path:
        reject("hook_install", "custom hooksPath requires explicit integration; existing hooks are untouched")
    state_path = hook_state(repo)
    if state_path.exists():
        state = parse_json(bounded_read(state_path))
        for name, saved in state["hooks"].items():
            if sha256(bounded_read(repo / ".git/hooks" / name)) != saved["installed_sha256"]:
                reject("hook_install", "installed hook changed; refusing overwrite")
        return {"status": "installed", "already_installed": True, "hooks": state["hooks"]}
    hooks = {}
    for name in ("pre-commit", "pre-push"):
        path = repo / ".git/hooks" / name
        if path.is_symlink():
            reject("hook_install", "refusing symlink hook")
        old = bounded_read(path) if path.exists() else None
        backup = path.with_name(name + ".naome-before")
        if backup.exists():
            reject("hook_install", "pre-existing hook backup needs owner reconciliation")
        old_mode = path.stat().st_mode & 0o777 if path.exists() else None
        hooks[name] = {"original_b64": base64.b64encode(old).decode() if old is not None else None, "original_mode": old_mode, "backup": str(backup)}
    installed_names = []
    try:
        for name, saved in hooks.items():
            path = repo / ".git/hooks" / name
            if saved["original_b64"] is not None:
                atomic_write(saved["backup"], base64.b64decode(saved["original_b64"]), saved["original_mode"])
            argv = [sys.executable, str(evaluator), "check" if name == "pre-commit" else "pre-push", "--repo", str(repo), "--policy", str(policy_path), "--bundle", str(bundle_path)]
            if name == "pre-commit":
                argv += ["--mode", "commit"]
            shell = "#!/bin/sh\n" + HOOK_MARKER + "\nset -eu\n"
            if name == "pre-push":
                shell += "factory_input=$(mktemp)\ntrap 'rm -f \"$factory_input\"' EXIT HUP INT TERM\ncat > \"$factory_input\"\n"
                shell += shlex.join(argv) + ' --remote-url "$2" < "$factory_input"\n'
                if saved["original_b64"] is not None and saved["original_mode"] & 0o111:
                    shell += shlex.quote(saved["backup"]) + ' "$@" < "$factory_input"\n'
            else:
                shell += shlex.join(argv) + "\n"
                if saved["original_b64"] is not None and saved["original_mode"] & 0o111:
                    shell += shlex.quote(saved["backup"]) + ' "$@"\n'
            atomic_write(path, shell.encode(), 0o755)
            installed_names.append(name)
            saved["installed_sha256"] = sha256(bounded_read(path))
        atomic_write(state_path, canonical({"version": 1, "evaluator": str(evaluator), "policy": str(policy_path), "bundle": str(bundle_path), "hooks": hooks}))
        for name, saved in hooks.items():
            if sha256(bounded_read(repo / ".git/hooks" / name)) != saved["installed_sha256"]:
                reject("hook_install", "hook readback differs")
    except BaseException:
        for name in reversed(installed_names):
            saved = hooks[name]
            path = repo / ".git/hooks" / name
            if saved["original_b64"] is None:
                path.unlink(missing_ok=True)
            else:
                os.replace(saved["backup"], path)
        for saved in hooks.values():
            Path(saved["backup"]).unlink(missing_ok=True)
        state_path.unlink(missing_ok=True)
        raise
    return {"status": "installed", "hooks": hooks}


def uninstall_hooks(args):
    repo = repository(args.repo)
    state_path = hook_state(repo)
    state = parse_json(bounded_read(state_path))
    for name, saved in state["hooks"].items():
        if sha256(bounded_read(repo / ".git/hooks" / name)) != saved["installed_sha256"]:
            reject("hook_install", "changed hook blocks automatic uninstall")
    for name, saved in state["hooks"].items():
        path = repo / ".git/hooks" / name
        if saved["original_b64"] is None:
            path.unlink()
        else:
            atomic_write(path, base64.b64decode(saved["original_b64"]), saved["original_mode"])
        Path(saved["backup"]).unlink(missing_ok=True)
    state_path.unlink()
    return {"status": "uninstalled", "existing_hooks_restored": True}


def export_identity(args):
    repo = repository(args.repo, candidate=args.mode == "candidate")
    validate_clean(repo, "commit")
    base = git(repo, "rev-parse", "HEAD").decode().strip()
    staged = staged_view(repo)
    tree = staged["tree"]
    return {"base": base, "tree": tree, "patch_sha256": sha256(selected_patch(repo, base, tree, staged)), "snapshot_sha256": sha256(canonical(staged["entries"])), "paths": staged["entries"]}


def filesystem_snapshot(repo, entries):
    observed = []
    for entry in entries:
        location = repo / entry["path"]
        for component in [location, *location.parents]:
            if component == repo:
                break
            if component.is_symlink():
                reject("destination", "source path alias is forbidden: " + entry["path"])
        if not location.is_file():
            reject("destination", "missing/nonregular source: " + entry["path"])
        observed.append({"path": entry["path"], "mode": "100755" if location.stat().st_mode & 0o111 else "100644", "sha256": sha256(bounded_read(location))})
    return observed


def promote(args):
    candidate = repository(args.repo, candidate=True)
    policy, policy_sha, evaluator_sha, bundle = load_trust(candidate, args.policy, args.bundle)
    native_admission_check(policy, candidate)
    validate_clean(candidate, "candidate")
    staged = staged_view(candidate)
    tree = staged["tree"]
    approval = validate_receipt(candidate, tree, None, "candidate", policy, policy_sha, evaluator_sha, bundle, staged)
    destination = repository(args.destination)
    if destination == candidate or destination in candidate.parents or candidate in destination.parents:
        reject("destination", "candidate and publication checkout must be separate")
    external(args.policy, destination)
    external(args.bundle, destination)
    allowed_remote(destination, policy)
    validate_clean(destination, "publish")
    if git(destination, "rev-parse", "HEAD").decode().strip() != approval["base"]:
        reject("destination", "publication checkout moved from approved base")
    expected = staged["entries"]
    baseline = snapshot(destination, git(destination, "rev-parse", "HEAD^{tree}").decode().strip())
    if filesystem_snapshot(destination, baseline) != baseline:
        reject("destination", "publication filesystem differs from approved clean base")
    old = {e["path"]: e for e in baseline}
    new = {e["path"]: e for e in expected}
    changed = sorted(p for p in old.keys() | new.keys() if old.get(p) != new.get(p))
    saved = {}
    for relative in changed:
        location = destination / relative
        for component in [location, *location.parents]:
            if component == destination:
                break
            if component.is_symlink():
                reject("destination", "publication path alias is forbidden: " + relative)
        if relative not in old and location.exists():
            reject("destination", "publication would overwrite existing untracked/ignored input: " + relative)
        saved[relative] = (bounded_read(location), location.stat().st_mode & 0o777) if relative in old else None
    # All trust/source/destination checks above are read-only on publication checkout.
    lock = destination / ".git/naome-factory-promotion.lock"
    transaction = destination / ".git/naome-factory-promotion"
    if transaction.exists():
        reject("promotion_recovery", "retained promotion transaction needs recover-promotion")
    created_directories = []
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        reject("destination", "another promotion holds publication ownership")
    try:
        os.close(fd)
        transaction.mkdir(mode=0o700)
        (transaction / "originals").mkdir()
        (transaction / "selected").mkdir()
        paths = []
        for index, relative in enumerate(changed):
            original = saved[relative]
            if original is not None:
                atomic_write(transaction / "originals" / str(index), original[0], original[1])
            if relative in new:
                oid = staged["blobs"][relative]
                data = git(candidate, "cat-file", "blob", oid)
                atomic_write(transaction / "selected" / str(index), data, 0o755 if new[relative]["mode"] == "100755" else 0o644)
            paths.append({"path": relative, "old": old.get(relative), "new": new.get(relative), "original_mode": original[1] if original is not None else None})
        manifest = {"version": 1, "destination": str(destination), "base": approval["base"], "tree": tree, "policy_sha256": policy_sha, "paths": paths, "created_directories": created_directories}
        atomic_write(transaction / "manifest.json", canonical(manifest))
        validate_clean(destination, "publish")
        if filesystem_snapshot(destination, baseline) != baseline:
            reject("destination", "publication source changed during admission")
        for index, relative in enumerate(changed):
            location = destination / relative
            if relative not in new:
                location.unlink()
                continue
            missing = []
            parent = location.parent
            while not parent.exists():
                missing.append(parent)
                parent = parent.parent
            for directory in reversed(missing):
                directory.mkdir()
                created_directories.append(directory)
                manifest["created_directories"] = [str(d.relative_to(destination)) for d in created_directories]
                atomic_write(transaction / "manifest.json", canonical(manifest))
            os.replace(transaction / "selected" / str(index), location)
        observed = filesystem_snapshot(destination, expected)
        if observed != expected or sha256(canonical(observed)) != approval["snapshot_sha256"]:
            reject("destination", "copied publication source failed exact readback")
    except BaseException:
        if (transaction / "manifest.json").exists():
            restore_promotion(destination, transaction)
        else:
            shutil.rmtree(transaction, ignore_errors=True)
        raise
    finally:
        if not transaction.exists():
            lock.unlink(missing_ok=True)
    shutil.rmtree(transaction)
    lock.unlink(missing_ok=True)
    return {**approval, "status": "promoted", "destination": str(destination), "copied_paths": changed, "git_history_copied": False, "index_and_refs_unchanged": True}


def safe_relative(value):
    if not isinstance(value, str):
        reject("promotion_recovery", "invalid owned transaction path")
    path = Path(value)
    if path.is_absolute() or path.as_posix() != value or any(p in {".", "..", ".git"} for p in path.parts):
        reject("promotion_recovery", "unsafe owned transaction path")
    return path


def restore_promotion(destination, transaction):
    if transaction.is_symlink() or (transaction / "manifest.json").is_symlink():
        reject("promotion_recovery", "transaction aliases are forbidden")
    manifest = parse_json(bounded_read(transaction / "manifest.json"))
    if manifest.get("version") != 1 or manifest.get("destination") != str(destination) or manifest.get("base") != git(destination, "rev-parse", "HEAD").decode().strip():
        reject("promotion_recovery", "transaction base/owner changed")
    baseline = {e["path"]: e for e in snapshot(destination, git(destination, "rev-parse", "HEAD^{tree}").decode().strip())}
    paths, seen = manifest.get("paths", []), set()
    for index, record in enumerate(paths):
        relative = safe_relative(record.get("path"))
        if str(relative) in seen or record.get("old") != baseline.get(str(relative)):
            reject("promotion_recovery", "transaction is not bound to original source")
        seen.add(str(relative))
        location = destination / relative
        for component in [location, *location.parents]:
            if component == destination:
                break
            if component.is_symlink():
                reject("promotion_recovery", "source alias appeared after interrupted promotion")
        old, new = record.get("old"), record.get("new")
        for entry in (old, new):
            if entry is not None and (not isinstance(entry, dict) or entry.get("path") != str(relative) or entry.get("mode") not in {"100644", "100755"} or not re.fullmatch(r"[0-9a-f]{64}", entry.get("sha256", ""))):
                reject("promotion_recovery", "invalid transaction source identity")
        if location.exists():
            current = sha256(bounded_read(location))
            allowed = {entry["sha256"] for entry in (old, new) if entry is not None}
            if current not in allowed:
                reject("promotion_recovery", "later owner edits preserved; manual reconciliation required")
        elif old is not None and new is not None:
            # This transaction only replaces an updated path. Its absence can
            # therefore be a later owner's deletion, never our selected delete.
            reject("promotion_recovery", "later owner deletion preserved; manual reconciliation required")
        backup = transaction / "originals" / str(index)
        if old is not None and (not backup.is_file() or backup.is_symlink() or sha256(bounded_read(backup)) != old["sha256"]):
            reject("promotion_recovery", "original backup is missing or corrupt")
    directories = [destination / safe_relative(p) for p in manifest.get("created_directories", [])]
    # Validate all affected source and retained original bytes before any restore.
    for index in reversed(range(len(paths))):
        record = paths[index]
        location = destination / record["path"]
        if record["old"] is None:
            location.unlink(missing_ok=True)
        else:
            os.replace(transaction / "originals" / str(index), location)
    for directory in reversed(directories):
        try:
            directory.rmdir()
        except OSError:
            pass  # Preserve any later unrelated owner file rather than deleting it.
    shutil.rmtree(transaction)
    (destination / ".git/naome-factory-promotion.lock").unlink(missing_ok=True)
    return {"status": "recovered", "base": manifest["base"], "restored_paths": sorted(seen), "index_and_refs_unchanged": True}


def recover_promotion(args):
    destination = repository(args.destination)
    policy = parse_json(bounded_read(external(args.policy, destination)))
    if policy.get("production", {}).get("evaluator_sha256") != sha256(bounded_read(Path(__file__))):
        reject("evaluator", "recovery requires owner-pinned evaluator")
    allowed_remote(destination, policy)
    transaction = destination / ".git/naome-factory-promotion"
    if not transaction.is_dir() or not (destination / ".git/naome-factory-promotion.lock").is_file():
        reject("promotion_recovery", "no complete owned transaction to recover")
    return restore_promotion(destination, transaction)


def ci_materialize(args):
    destination = Path(args.directory).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    policy = os.environ.get("NAOME_FACTORY_POLICY_JSON", "").encode()
    encoded = os.environ.get("NAOME_FACTORY_APPROVALS_GZIP_B64", "")
    url = os.environ.get("NAOME_FACTORY_APPROVALS_URL", "")
    if not policy or not (encoded or url):
        reject("trust_missing", "protected owner-installed policy and approval variables are required")
    parsed_policy = parse_json(policy)
    if encoded and url:
        reject("transport", "ambiguous inline and external approval transport")
    if url:
        bundle = download_object(url, os.environ.get("NAOME_FACTORY_APPROVALS_SHA256", ""), int(os.environ.get("NAOME_FACTORY_APPROVALS_BYTES", "0")), parsed_policy)
    else:
        compressed = base64.b64decode(encoded, validate=True)
        import io
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
            bundle = stream.read(LIMIT + 1)
        if len(bundle) > LIMIT:
            reject("resource", "inline approval bundle decompression exceeds bound; use immutable external evidence reference")
    parse_json(bundle)
    atomic_write(destination / "policy.json", policy)
    atomic_write(destination / "bundle.json", bundle)
    return {"status": "materialized", "policy_sha256": sha256(policy), "bundle_sha256": sha256(bundle)}


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("check", "pre-push", "install-hooks", "promote"):
        sub = commands.add_parser(name)
        for flag in ("repo", "policy", "bundle"):
            sub.add_argument("--" + flag, required=True)
        if name == "check":
            sub.add_argument("--mode", choices=("candidate", "commit", "publish", "audit"), required=True)
            sub.add_argument("--tree", help="immutable commit ID in publish/audit mode")
        elif name == "pre-push":
            sub.add_argument("--remote-url", required=True)
        elif name == "install-hooks":
            sub.add_argument("--evaluator", required=True)
        else:
            sub.add_argument("--destination", required=True)
    sub = commands.add_parser("uninstall-hooks")
    sub.add_argument("--repo", required=True)
    sub = commands.add_parser("identity")
    sub.add_argument("--repo", required=True)
    sub.add_argument("--mode", choices=("candidate", "commit"), default="candidate")
    sub = commands.add_parser("ci-materialize")
    sub.add_argument("--directory", required=True)
    sub = commands.add_parser("recover-promotion")
    sub.add_argument("--destination", required=True)
    sub.add_argument("--policy", required=True)
    return result


def main():
    args = parser().parse_args()
    try:
        handlers = {"check": check, "pre-push": pre_push, "install-hooks": install_hooks, "uninstall-hooks": uninstall_hooks, "identity": export_identity, "ci-materialize": ci_materialize, "promote": promote, "recover-promotion": recover_promotion}
        result = handlers[args.command](args)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Rejection as error:
        print(json.dumps({"status": "rejected", "code": error.code, "detail": str(error)}, sort_keys=True), file=sys.stderr)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.TimeoutExpired) as error:
        print(json.dumps({"status": "rejected", "code": "invalid_input", "detail": str(error)}, sort_keys=True), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
