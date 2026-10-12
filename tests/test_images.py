"""Image names stay inside the Docker reference shape."""

from __future__ import annotations

from security_console.images import image_rows, valid_image_ref


def test_valid_image_ref_accepts_local_and_remote_names() -> None:
    assert valid_image_ref("nginx")
    assert valid_image_ref("nginx:1.27")
    assert valid_image_ref("ghcr.io/org/app:1.2.3")
    assert valid_image_ref("10.1.2.3:5000/team/app:1")
    assert valid_image_ref("registry.example:5000/app:1")
    digest = "a" * 64
    assert valid_image_ref(f"python@sha256:{digest}")
    assert valid_image_ref(f"sha256:{digest}")


def test_valid_image_ref_rejects_metadata_and_loopback_registries() -> None:
    assert not valid_image_ref("169.254.169.254/nginx:1.27")
    assert not valid_image_ref("169.254.169.254:80/nginx:1.27")
    assert not valid_image_ref("127.0.0.1:5000/app:latest")
    assert not valid_image_ref("localhost:5000/app:latest")
    assert not valid_image_ref("metadata.google.internal/nginx:1")
    assert not valid_image_ref("100.100.100.200:443/app:1")
    assert not valid_image_ref("010.0.0.1:5000/app:1")
    assert not valid_image_ref("[::1]/nginx:1")
    assert not valid_image_ref("[::1]:5000/app:latest")
    assert not valid_image_ref("[::ffff:127.0.0.1]/nginx:1")
    assert not valid_image_ref("[::ffff:169.254.169.254]:443/app:1")
    assert not valid_image_ref("[fd00:ec2::254]/nginx:1")
    assert not valid_image_ref("[fe80::1]/nginx:1")


def test_valid_image_ref_rejects_flags_and_paths() -> None:
    assert not valid_image_ref("")
    assert not valid_image_ref("nginx;rm -rf /")
    assert not valid_image_ref("--server")
    assert not valid_image_ref("../etc/passwd")
    assert not valid_image_ref("Nginx:1.27")
    assert not valid_image_ref("nginx latest")


def test_image_rows_skip_untagged_and_keep_newest() -> None:
    rows = image_rows(
        [
            {
                "tags": ["old:1", "<none>:<none>"],
                "id": "sha256:abc",
                "size": 10,
                "created": "2026-01-01T00:00:00Z",
            },
            {
                "tags": ["new:2"],
                "id": "sha256:def",
                "size": 20,
                "created": "2026-02-01T00:00:00Z",
            },
            {
                "tags": ["not a ref"],
                "id": "sha256:bad",
                "size": 1,
                "created": "2026-03-01",
            },
        ]
    )

    assert [row["ref"] for row in rows] == ["new:2", "old:1"]
    assert rows[0]["id"] == "def"
