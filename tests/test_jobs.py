"""The worker accepts a scan description and nothing that configures Docker."""

from __future__ import annotations

import pytest

from security_console.jobs import JobError, parse_job


def test_parse_job_drops_host_config() -> None:
    job = parse_job(
        {
            "id": "abc123def456",
            "target": "repo",
            "repo": "https://github.com/org/repo.git",
            "tools": ["semgrep", "trivy"],
            "privileged": True,
            "volumes": {"/": {"bind": "/host", "mode": "rw"}},
            "network_mode": "host",
            "image": "attacker:latest",
            "entrypoint": "/bin/sh",
        }
    )

    assert job == {
        "id": "abc123def456",
        "target": "repo",
        "repo": "https://github.com/org/repo.git",
        "image": "",
        "tools": ["semgrep", "trivy"],
        "requested_sha": "",
    }


def test_parse_job_rejects_socket_paths_and_bad_images() -> None:
    with pytest.raises(JobError):
        parse_job(
            {
                "id": "../etc/passwd",
                "target": "image",
                "image": "nginx:1.27",
                "tools": ["trivy"],
            }
        )
    with pytest.raises(JobError):
        parse_job(
            {
                "id": "abc123def456",
                "target": "image",
                "image": "/var/run/docker.sock",
                "tools": ["trivy"],
            }
        )
    with pytest.raises(JobError):
        parse_job(
            {
                "id": "abc123def456",
                "target": "image",
                "image": "nginx:1.27",
            "tools": ["semgrep"],
        }
    )


def test_parse_job_accepts_only_a_full_sha() -> None:
    sha = "a" * 40
    job = parse_job(
        {
            "id": "abc123def456",
            "target": "repo",
            "repo": "https://github.com/org/repo.git",
            "tools": ["semgrep"],
            "requested_sha": sha.upper(),
        }
    )

    assert job["requested_sha"] == sha
    with pytest.raises(JobError):
        parse_job(
            {
                "id": "abc123def456",
                "target": "repo",
                "repo": "https://github.com/org/repo.git",
                "tools": ["semgrep"],
                "requested_sha": "abc1234",
            }
        )
    with pytest.raises(JobError):
        parse_job(
            {
                "id": "abc123def456",
                "target": "image",
                "image": "nginx:1.27",
                "tools": ["trivy"],
                "requested_sha": sha,
            }
        )
