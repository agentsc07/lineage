from datetime import datetime, timedelta, timezone

import httpx
import pytest

from lineage.inspect import package_osv, package_provenance as pp
from lineage.inspect._text import damerau_levenshtein
from lineage.schemas.policy import PolicyPack

NOW = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def policy(policy_path):
    return PolicyPack.from_yaml(policy_path)


def meta(age_hours=24 * 30, repo="https://github.com/BerriAI/litellm", author="Krrish", provenance=None):
    m = {
        "info": {"name": "litellm", "project_urls": {"Source": repo}, "author": author},
        "urls": [{"upload_time_iso_8601": (NOW - timedelta(hours=age_hours)).isoformat()}],
    }
    if provenance:
        m["provenance"] = {"repository": provenance}
    return m


def ids(fs):
    return {f.id for f in fs}


# --- distance
def test_damerau_levenshtein():
    assert damerau_levenshtein("ca", "abc") == 2 and damerau_levenshtein("ab", "ba") == 1
    assert damerau_levenshtein("requests", "reqeusts") == 1
    assert damerau_levenshtein("abcdef", "uvwxyz", 2) == 3


# --- provenance
def test_established_package_is_clean(policy):
    assert pp.scan("litellm", "1.106.0", meta(), policy, now=NOW) == []


def test_litellm_case_flags_cooldown_and_lookalike_repo(policy):
    m = meta(age_hours=2, repo="https://github.com/BerriAI/litellm", provenance="https://github.com/Berri-AI/litellm")
    fs = {f.id: f for f in pp.scan("litellm", "1.107.0", m, policy, now=NOW)}
    assert fs["PKG.PROV.COOLDOWN"].severity == "high"
    assert fs["PKG.PROV.LOOKALIKE_REPO"].severity == "critical"


def test_repo_change_versus_previous_version(policy):
    prev = meta()
    cur = meta(repo="https://github.com/someone-else/litellm")
    assert "PKG.PROV.REPO_MISMATCH" in ids(pp.scan("litellm", "2", cur, policy, previous_metadata=prev, now=NOW))


def test_maintainer_change(policy):
    fs = pp.scan("litellm", "2", meta(author="mallory"), policy, previous_metadata=meta(), now=NOW)
    assert "PKG.PROV.MAINTAINER_CHANGED" in ids(fs)


def test_typosquats(policy):
    assert pp.lookalikes("requests") == []  # popular itself
    assert pp.lookalikes("reqeusts")[0][0] == "requests"
    assert pp.lookalikes("python_dateutil") == [] or pp.normalise("python_dateutil") in pp.top_packages()
    fs = pp.scan("reqeusts", "1", {"info": {}}, policy)
    assert [f.id for f in fs] == ["PKG.PROV.LOOKALIKE_NAME"] and fs[0].severity == "high"


def test_unrelated_name_is_not_flagged():
    assert pp.lookalikes("zzqx-internal-tooling") == []


# --- OSV
def osv_client(payload, calls):
    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=payload)
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_osv_vuln_and_malicious(tmp_path):
    calls = []
    payload = {"vulns": [
        {"id": "GHSA-xxxx", "summary": "bad parsing", "database_specific": {"severity": "HIGH"}},
        {"id": "MAL-2026-1", "summary": "Malicious code in evilpkg"},
    ]}
    fs = package_osv.scan("evilpkg", "1.0", cache_dir=tmp_path, client=osv_client(payload, calls))
    assert [f.id for f in fs] == ["PKG.OSV.MALICIOUS", "PKG.OSV.VULN"]
    assert fs[0].severity == "critical" and fs[1].severity == "high"
    assert fs[0].evidence[0].ref == "https://osv.dev/vulnerability/MAL-2026-1"


def test_osv_cache_hits_and_ttl(tmp_path):
    calls = []
    c = osv_client({"vulns": []}, calls)
    package_osv.scan("x", "1", cache_dir=tmp_path, client=c)
    package_osv.scan("x", "1", cache_dir=tmp_path, client=c)
    assert len(calls) == 1
    package_osv.scan("x", "1", cache_dir=tmp_path, client=c, ttl=0)
    assert len(calls) == 2


def test_osv_offline_falls_back(tmp_path):
    def boom(request):
        raise httpx.ConnectError("offline")
    c = httpx.Client(transport=httpx.MockTransport(boom))
    fs = package_osv.scan("x", "1", cache_dir=tmp_path, client=c)
    assert [f.id for f in fs] == ["PKG.OSV.UNAVAILABLE"] and fs[0].severity == "info" and fs[0].score == 0
    # stale cache is used when offline
    package_osv.scan("x", "1", cache_dir=tmp_path, client=osv_client({"vulns": [{"id": "MAL-1"}]}, []))
    assert package_osv.scan("x", "1", cache_dir=tmp_path, client=c, ttl=0)[0].id == "PKG.OSV.MALICIOUS"


def test_osv_placeholder_version_is_not_queried(tmp_path):
    calls = []
    fs = package_osv.scan("litellm", "0.0.0", cache_dir=tmp_path, client=osv_client({"vulns": [{"id": "GHSA-1"}]}, calls))
    assert [f.id for f in fs] == ["PKG.OSV.VERSION_UNKNOWN"] and calls == []


def test_osv_offline_switch(tmp_path, monkeypatch):
    monkeypatch.setenv("LINEAGE_OFFLINE", "1")
    assert [f.id for f in package_osv.scan("x", "1.0", cache_dir=tmp_path)] == ["PKG.OSV.UNAVAILABLE"]
