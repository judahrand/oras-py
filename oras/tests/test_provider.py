__author__ = "Vanessa Sochat"
__copyright__ = "Copyright The ORAS Authors."
__license__ = "Apache-2.0"

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest
import requests

import oras.client
import oras.defaults
import oras.oci
import oras.provider
import oras.utils

here = Path(__file__).resolve().parent

MANIFEST_CONTENT = (
    b'{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",'
    b'"config":{},"layers":[]}'
)


def make_pull_client(monkeypatch, layer, content):
    """Create a registry client whose pull inputs do not require a live registry."""
    client = oras.provider.Registry(insecure=True)
    monkeypatch.setattr(client, "get_container", lambda target: target)
    monkeypatch.setattr(client.auth, "load_configs", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        client,
        "get_manifest",
        lambda container, allowed_media_type: {"layers": [layer]},
    )

    def get_blob(container, digest, *args, **kwargs):
        resp = requests.Response()
        resp.status_code = 200
        resp._content = content
        resp._content_consumed = True
        return resp

    monkeypatch.setattr(client, "get_blob", get_blob)
    return client


def make_manifest_client(monkeypatch, content, digest_header):
    """Create a registry client with a fixed manifest response."""
    client = oras.provider.Registry(hostname="registry.example", insecure=True)
    monkeypatch.setattr(client.auth, "load_configs", lambda *args, **kwargs: None)

    response = requests.Response()
    response.status_code = 200
    response._content = content
    response._content_consumed = True
    if digest_header is not None:
        response.headers["Docker-Content-Digest"] = digest_header
    monkeypatch.setattr(client, "do_request", lambda *args, **kwargs: response)
    return client


def test_digest_string_round_trip():
    original = f"sha256:{hashlib.sha256(b'content').hexdigest()}"

    assert str(oras.oci.Digest(original)) == original


def test_get_manifest_verifies_digest_header(monkeypatch):
    digest = oras.oci.RegisteredDigestAlgorithm.SHA256.digest_for_bytes(
        MANIFEST_CONTENT
    )
    client = make_manifest_client(monkeypatch, MANIFEST_CONTENT, digest.digest)

    manifest = client.get_manifest("registry.example/repository:tag")

    assert manifest == json.loads(MANIFEST_CONTENT)


def test_get_manifest_rejects_digest_header_mismatch(monkeypatch):
    expected_digest = oras.oci.RegisteredDigestAlgorithm.SHA256.digest_for_bytes(
        b"different content"
    )
    client = make_manifest_client(monkeypatch, MANIFEST_CONTENT, expected_digest.digest)

    with pytest.raises(ValueError, match="Downloaded manifest digest mismatch:"):
        client.get_manifest("registry.example/repository:tag")


def test_get_manifest_fails_without_header(monkeypatch):
    digest = oras.oci.RegisteredDigestAlgorithm.SHA256.digest_for_bytes(
        MANIFEST_CONTENT
    )
    client = make_manifest_client(monkeypatch, MANIFEST_CONTENT, None)

    with pytest.raises(
        ValueError, match="Expected to find Docker-Content-Digest header."
    ):
        client.get_manifest(f"registry.example/repository@{digest}")


def test_get_manifest_rejects_digest_reference_mismatch(monkeypatch):
    actual_digest = oras.oci.RegisteredDigestAlgorithm.SHA256.digest_for_bytes(
        MANIFEST_CONTENT
    ).digest
    expected_digest = oras.oci.RegisteredDigestAlgorithm.SHA256.digest_for_bytes(
        b"different content"
    ).digest
    client = make_manifest_client(monkeypatch, MANIFEST_CONTENT, actual_digest)

    with pytest.raises(ValueError, match="Downloaded manifest digest mismatch"):
        client.get_manifest(f"registry.example/repository@{expected_digest}")


def test_get_manifest_verifies_reference_and_canonical_header(monkeypatch):
    requested_digest = oras.oci.RegisteredDigestAlgorithm.SHA256.digest_for_bytes(
        MANIFEST_CONTENT
    )
    canonical_digest = oras.oci.RegisteredDigestAlgorithm.SHA512.digest_for_bytes(
        MANIFEST_CONTENT
    )
    client = make_manifest_client(
        monkeypatch, MANIFEST_CONTENT, canonical_digest.digest
    )

    manifest = client.get_manifest(f"registry.example/repository@{requested_digest}")
    assert manifest == json.loads(MANIFEST_CONTENT)


@pytest.mark.parametrize(
    "digest_header",
    ["sha256:not!hex", f"sha384:{'a' * 96}"],
)
def test_get_manifest_rejects_invalid_digest_header(monkeypatch, digest_header):
    client = make_manifest_client(monkeypatch, MANIFEST_CONTENT, digest_header)

    with pytest.raises(ValueError):
        client.get_manifest("registry.example/repository:tag")


@pytest.mark.parametrize("algorithm", ["sha256", "sha512"])
def test_pull_validates_registered_digest(monkeypatch, tmp_path, algorithm):
    content = b"verified content"
    digest = f"{algorithm}:{hashlib.new(algorithm, content).hexdigest()}"
    layer = {
        "mediaType": oras.defaults.default_blob_media_type,
        "size": len(content),
        "digest": digest,
        "annotations": {oras.defaults.annotation_title: "artifact.txt"},
    }
    client = make_pull_client(monkeypatch, layer, content)

    files = client.pull("registry.example/repository:tag", outdir=str(tmp_path))

    outfile = tmp_path / "artifact.txt"
    assert files == [str(outfile)]
    assert outfile.read_bytes() == content


def test_pull_rejects_digest_mismatch_without_replacing_file(monkeypatch, tmp_path):
    expected_content = b"expected content"
    downloaded_content = b"corrupt! content"
    digest = f"sha256:{hashlib.sha256(expected_content).hexdigest()}"
    layer = {
        "mediaType": oras.defaults.default_blob_media_type,
        "size": len(downloaded_content),
        "digest": digest,
        "annotations": {oras.defaults.annotation_title: "artifact.txt"},
    }
    client = make_pull_client(monkeypatch, layer, downloaded_content)
    outfile = tmp_path / "artifact.txt"
    outfile.write_bytes(b"existing content")

    with pytest.raises(ValueError) as error:
        client.pull("registry.example/repository:tag", outdir=str(tmp_path))

    actual_digest = f"sha256:{hashlib.sha256(downloaded_content).hexdigest()}"
    assert str(error.value) == (
        f"Downloaded blob digest mismatch: expected {digest}, got {actual_digest}."
    )
    assert outfile.read_bytes() == b"existing content"
    assert not list(tmp_path.glob(".oras-*"))


def test_pull_rejects_size_mismatch(monkeypatch, tmp_path):
    content = b"content"
    digest = f"sha256:{hashlib.sha256(content).hexdigest()}"
    layer = {
        "mediaType": oras.defaults.default_blob_media_type,
        "size": len(content) + 1,
        "digest": digest,
        "annotations": {oras.defaults.annotation_title: "artifact.txt"},
    }
    client = make_pull_client(monkeypatch, layer, content)

    with pytest.raises(ValueError, match="Downloaded blob size mismatch"):
        client.pull("registry.example/repository:tag", outdir=str(tmp_path))

    assert not (tmp_path / "artifact.txt").exists()
    assert not list(tmp_path.glob(".oras-*"))


def test_pull_validates_directory_before_extraction(monkeypatch, tmp_path):
    expected_content = b"expected archive"
    downloaded_content = b"corrupted archive"
    digest = f"sha256:{hashlib.sha256(expected_content).hexdigest()}"
    layer = {
        "mediaType": oras.defaults.default_blob_dir_media_type,
        "size": len(downloaded_content),
        "digest": digest,
        "annotations": {oras.defaults.annotation_title: "artifact"},
    }
    client = make_pull_client(monkeypatch, layer, downloaded_content)
    extracted = False

    def extract_targz(*args, **kwargs):
        nonlocal extracted
        extracted = True

    monkeypatch.setattr(oras.utils, "extract_targz", extract_targz)

    with pytest.raises(ValueError, match="Downloaded blob digest mismatch"):
        client.pull("registry.example/repository:tag", outdir=str(tmp_path))

    assert not extracted
    assert not (tmp_path / "artifact").exists()
    assert not list(tmp_path.glob(".oras-*"))


@pytest.mark.parametrize(
    ("digest", "error"),
    [
        ("sha256+b64u:YWJj", "Unsupported OCI digest algorithm"),
        (f"sha384:{'a' * 96}", "Unsupported OCI digest algorithm"),
        (f"sha256:{'a' * 63}", "Invalid sha256 digest encoding"),
        ("sha256:not!hex", "Invalid OCI digest"),
        ("sha256:", "Invalid OCI digest"),
        (f"SHA256:{'a' * 64}", "Invalid OCI digest"),
    ],
)
def test_pull_rejects_invalid_digest_encoding(monkeypatch, tmp_path, digest, error):
    layer = {
        "mediaType": oras.defaults.default_blob_media_type,
        "size": 0,
        "digest": digest,
        "annotations": {oras.defaults.annotation_title: "artifact.txt"},
    }
    client = make_pull_client(monkeypatch, layer, b"")

    with pytest.raises(ValueError, match=error):
        client.pull("registry.example/repository:tag", outdir=str(tmp_path))

    assert not (tmp_path / "artifact.txt").exists()


@pytest.mark.with_auth(False)
def test_annotated_registry_push(tmp_path, registry, credentials, target):
    """
    Basic tests for oras push with annotations
    """

    # Direct access to registry functions
    remote = oras.provider.Registry(hostname=registry, insecure=True)
    client = oras.client.OrasClient(hostname=registry, insecure=True)
    artifact = os.path.join(here, "artifact.txt")

    assert os.path.exists(artifact)

    # Custom manifest annotations
    annots = {"holiday": "Halloween", "candy": "chocolate"}
    res = client.push(files=[artifact], target=target, manifest_annotations=annots)
    assert res.status_code in [200, 201]

    # Get the manifest
    manifest = remote.get_manifest(target)
    assert "annotations" in manifest
    for k, v in annots.items():
        assert k in manifest["annotations"]
        assert manifest["annotations"][k] == v

    # Annotations from file with $manifest
    annotation_file = os.path.join(here, "annotations.json")
    file_annots = oras.utils.read_json(annotation_file)
    assert "$manifest" in file_annots
    res = client.push(files=[artifact], target=target, annotation_file=annotation_file)
    assert res.status_code in [200, 201]
    manifest = remote.get_manifest(target)

    assert "annotations" in manifest
    for k, v in file_annots["$manifest"].items():
        assert k in manifest["annotations"]
        assert manifest["annotations"][k] == v

    # File that doesn't exist
    annotation_file = os.path.join(here, "annotations-nope.json")
    with pytest.raises(FileNotFoundError):
        res = client.push(
            files=[artifact], target=target, annotation_file=annotation_file
        )


@pytest.mark.with_auth(False)
def test_file_contains_column(tmp_path, registry, credentials, target):
    """
    Test for file containing column symbol
    """
    client = oras.client.OrasClient(hostname=registry, insecure=True)
    artifact = os.path.join(here, "artifact.txt")
    assert os.path.exists(artifact)

    # file containing `:`
    try:
        contains_column = here / "some:file"
        with open(contains_column, "w") as f:
            f.write("hello world some:file")

        res = client.push(files=[contains_column], target=target)
        assert res.status_code in [200, 201]

        files = client.pull(target, outdir=tmp_path / "download")
        download = str(tmp_path / "download/some:file")
        assert download in files
        assert oras.utils.get_file_hash(
            str(contains_column)
        ) == oras.utils.get_file_hash(download)
    finally:
        contains_column.unlink()

    # file containing `:` as prefix, pushed with type
    try:
        contains_column = here / ":somefile"
        with open(contains_column, "w") as f:
            f.write("hello world :somefile")

        res = client.push(files=[f"{contains_column}:text/plain"], target=target)
        assert res.status_code in [200, 201]

        files = client.pull(target, outdir=tmp_path / "download")
        download = str(tmp_path / "download/:somefile")
        assert download in files
        assert oras.utils.get_file_hash(
            str(contains_column)
        ) == oras.utils.get_file_hash(download)
    finally:
        contains_column.unlink()

    # error: file does not exist
    with pytest.raises(FileNotFoundError):
        client.push(files=[".doesnotexist"], target=target)

    with pytest.raises(FileNotFoundError):
        client.push(files=[":doesnotexist"], target=target)

    with pytest.raises(FileNotFoundError, match=r".*does:not:exists .*"):
        client.push(files=["does:not:exists:text/plain"], target=target)

    with pytest.raises(FileNotFoundError, match=r".*does:not:exists .*"):
        client.push(files=["does:not:exists:text/plain+ext"], target=target)


@pytest.mark.with_auth(False)
def test_chunked_push(tmp_path, registry, credentials, target):
    """
    Basic tests for oras chunked push
    """
    # Direct access to registry functions
    client = oras.client.OrasClient(hostname=registry, insecure=True)
    artifact = os.path.join(here, "artifact.txt")

    assert os.path.exists(artifact)

    res = client.push(files=[artifact], target=target, do_chunked=True)
    assert res.status_code in [200, 201, 202]

    files = client.pull(target, outdir=tmp_path)
    assert str(tmp_path / "artifact.txt") in files
    assert oras.utils.get_file_hash(artifact) == oras.utils.get_file_hash(files[0])

    # large file upload
    base_size = oras.defaults.default_chunksize * 1024  # 16GB
    tmp_chunked = here / "chunked"
    try:
        subprocess.run(
            [
                "dd",
                "if=/dev/null",
                f"of={tmp_chunked}",
                "bs=1",
                "count=0",
                f"seek={base_size}",
            ],
        )

        res = client.push(
            files=[tmp_chunked],
            target=target,
            do_chunked=True,
        )
        assert res.status_code in [200, 201, 202]

        files = client.pull(target, outdir=tmp_path / "download")
        download = str(tmp_path / "download/chunked")
        assert download in files
        assert oras.utils.get_file_hash(str(tmp_chunked)) == oras.utils.get_file_hash(
            download
        )
    finally:
        tmp_chunked.unlink()

    # File that doesn't exist
    with pytest.raises(FileNotFoundError):
        res = client.push(files=[tmp_path / "none"], target=target)


def test_parse_manifest(registry):
    """
    Test parse manifest function.

    Parse manifest function has additional logic for Windows - this isn't included in
    these tests as they don't usually run on Windows.
    """
    testref = "path/to/config:application/vnd.oci.image.config.v1+json"
    remote = oras.provider.Registry(hostname=registry, insecure=True)
    ref, content_type = remote._parse_manifest_ref(testref)
    assert ref == "path/to/config"
    assert content_type == "application/vnd.oci.image.config.v1+json"

    testref = "/dev/null:application/vnd.oci.image.manifest.v1+json"
    ref, content_type = remote._parse_manifest_ref(testref)
    assert ref == "/dev/null"
    assert content_type == "application/vnd.oci.image.manifest.v1+json"

    testref = "/dev/null"
    ref, content_type = remote._parse_manifest_ref(testref)
    assert ref == "/dev/null"
    assert content_type == oras.defaults.unknown_config_media_type

    testref = "path/to/config.json"
    ref, content_type = remote._parse_manifest_ref(testref)
    assert ref == "path/to/config.json"
    assert content_type == oras.defaults.unknown_config_media_type


def test_sanitize_path():
    HOME_DIR = str(Path.home())
    assert str(oras.utils.sanitize_path(HOME_DIR, HOME_DIR)) == f"{HOME_DIR}"
    assert (
        str(oras.utils.sanitize_path(HOME_DIR, os.path.join(HOME_DIR, "username")))
        == f"{HOME_DIR}/username"
    )
    assert (
        str(oras.utils.sanitize_path(HOME_DIR, os.path.join(HOME_DIR, ".", "username")))
        == f"{HOME_DIR}/username"
    )

    with pytest.raises(Exception) as e:
        assert oras.utils.sanitize_path(HOME_DIR, os.path.join(HOME_DIR, ".."))
    assert (
        str(e.value)
        == f"Filename {Path(os.path.join(HOME_DIR, '..')).resolve()} is not in {HOME_DIR} directory"
    )

    assert oras.utils.sanitize_path("", "") == str(Path(".").resolve())
    assert oras.utils.sanitize_path("/opt", os.path.join("/opt", "image_name")) == str(
        Path("/opt/image_name").resolve()
    )
    assert oras.utils.sanitize_path("/../../", "/") == str(Path("/").resolve())
    assert oras.utils.sanitize_path(
        Path(os.getcwd()).parent.absolute(), os.path.join(os.getcwd(), "..")
    ) == str(Path("..").resolve())

    with pytest.raises(Exception) as e:
        assert oras.utils.sanitize_path(
            Path(os.getcwd()).parent.absolute(), os.path.join(os.getcwd(), "..", "..")
        ) != str(Path("../..").resolve())
    assert (
        str(e.value)
        == f"Filename {Path(os.path.join(os.getcwd(), '..', '..')).resolve()} is not in {Path('../').resolve()} directory"
    )
