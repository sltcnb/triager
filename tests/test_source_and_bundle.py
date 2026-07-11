"""Source primitives, end-to-end collection, and bundle schema conformance."""

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sources import build_source  # noqa: E402
from utils import contracts  # noqa: E402
from utils.manifest import CollectionManifest  # noqa: E402
from collectors.orchestrator import HarvesterCollection  # noqa: E402
from utils.bundle import BundleWriter  # noqa: E402


def _fake_windows_tree():
    src = tempfile.mkdtemp()
    etc = os.path.join(src, "Windows", "System32", "drivers", "etc")
    os.makedirs(etc)
    with open(os.path.join(etc, "hosts"), "w") as fh:
        fh.write("127.0.0.1 localhost")
    return src


def test_live_source_primitives():
    src = _fake_windows_tree()
    s = build_source(src)
    assert s.exists("Windows/System32/drivers/etc/hosts")
    assert s.is_file("Windows/System32/drivers/etc/hosts")
    assert s.file_size("Windows/System32/drivers/etc/hosts") == 19
    dst = tempfile.mkdtemp()
    ok, err = s.extract("Windows/System32/drivers/etc/hosts", os.path.join(dst, "c"))
    assert ok and err is None


def test_end_to_end_bundle_is_schema_valid():
    src = _fake_windows_tree()
    out = tempfile.mkdtemp()
    cfg = {"level": "small", "hash_collected": True, "categories": ["network"]}
    man = CollectionManifest(out, "small")
    coll = HarvesterCollection(
        cfg, src, out, "small", man, ["network"],
        source=build_source(src), threads=1, hostname="T", os_name="windows",
        session_id="sess1",
    )
    coll.start()
    coll.collect()
    result = coll.finalize()
    assert len(result.artifacts) == 1
    # manifest conforms to the vendored contract
    contracts.validate_bundle_manifest(result.to_manifest())

    # content-addressed bundle materializes correctly
    bdir = os.path.join(out, "bundle")
    BundleWriter(out, bdir).write(result, validate=True)
    manifest = json.load(open(os.path.join(bdir, "manifest.json")))
    art = manifest["artifacts"][0]
    blob = os.path.join(bdir, "blobs", art["sha256"])
    assert os.path.exists(blob)
    assert os.path.getsize(blob) == art["size"]
    assert os.path.exists(os.path.join(bdir, "events.jsonl"))
    assert os.path.exists(os.path.join(bdir, "bundle.sha256"))


def test_invalid_manifest_rejected():
    try:
        contracts.validate_bundle_manifest({"os": "bogus"})
    except contracts.ContractValidationError:
        return
    raise AssertionError("invalid manifest was not rejected")


if __name__ == "__main__":
    test_live_source_primitives()
    test_end_to_end_bundle_is_schema_valid()
    test_invalid_manifest_rejected()
    print("PASS source + bundle")
