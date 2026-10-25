"""Small GitHub API boundary; no shell interpolation or mutation retries."""

import json
import os
import re
import urllib.error
import urllib.request

from policy import REPOSITORY


class GitHub:
    def request(self, path, *, method="GET", body=None, missing=False, upload=None):
        url = f"https://api.github.com/repos/{REPOSITORY}{path}"
        # GitHub does not grant Administration:read to GITHUB_TOKEN. Use a
        # separate read-only credential only for release policy and the full
        # ruleset policy (including bypass actors, hidden from ordinary readers).
        policy_read = path == "/immutable-releases" or re.fullmatch(r"/rulesets/[0-9]+", path)
        if policy_read and method != "GET":
            raise ValueError("release tooling cannot mutate repository protections")
        token_name = "RELEASE_POLICY_TOKEN" if policy_read else "GH_TOKEN"
        token = os.environ.get(token_name)
        if not token:
            raise ValueError(f"missing {token_name}; RELEASE_POLICY_TOKEN requires a fine-grained token restricted to {REPOSITORY} with Administration:read and Metadata:read")
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                   "Authorization": f"Bearer {token}"}
        if upload is not None:
            url = f"https://uploads.github.com/repos/{REPOSITORY}{path}"
            data = upload.read_bytes()
            headers["Content-Type"] = "application/octet-stream"
        else:
            data = None if body is None else json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        try:
            with urllib.request.urlopen(urllib.request.Request(url, data, headers, method=method), timeout=60) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if missing and error.code == 404:
                return None
            raise RuntimeError(f"GitHub {method} {path}: HTTP {error.code}") from error

    def get(self, path, *, missing=False):
        return self.request(path, missing=missing)

    def pages(self, path, key=None):
        page = 1
        while True:
            result = self.get(f"{path}{'&' if '?' in path else '?'}per_page=100&page={page}")
            values = result[key] if key else result
            yield from values
            if len(values) < 100:
                break
            page += 1
