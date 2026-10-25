"""Synchronize test readiness without exchanging participant identities or addresses."""
import json
import os
import time
import urllib.request

JOBS = {"Public discovery (ubuntu-24.04)", "Public discovery (macos-15)"}
BUILD = "Build the matching public-network test configuration"


def built(jobs):
    participants = [job for job in jobs if job["name"] in JOBS]
    if {job["name"] for job in participants} != JOBS:
        return False
    ready = True
    for job in participants:
        if job.get("conclusion") not in [None, "success"]:
            raise RuntimeError(f"public participant failed: {job['name']}")
        steps = [step for step in job.get("steps", []) if step["name"] == BUILD]
        if not steps or steps[0]["status"] != "completed":
            ready = False
        elif steps[0]["conclusion"] != "success":
            raise RuntimeError(f"public participant build failed: {job['name']}")
    return ready


def main():
    url = (f"{os.environ['GITHUB_API_URL']}/repos/{os.environ['GITHUB_REPOSITORY']}"
           f"/actions/runs/{os.environ['GITHUB_RUN_ID']}/attempts/{os.environ['GITHUB_RUN_ATTEMPT']}/jobs?per_page=100")
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {os.environ['GH_TOKEN']}",
        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        with urllib.request.urlopen(request, timeout=20) as response:
            result = json.load(response)
        assert result["total_count"] <= 100, "job pagination must not hide participant readiness"
        if built(result["jobs"]):
            print("Both independent hosts built; public discovery may start.")
            return
        time.sleep(5)
    raise TimeoutError("the other physical host did not finish its build within ten minutes")


if __name__ == "__main__":
    main()
