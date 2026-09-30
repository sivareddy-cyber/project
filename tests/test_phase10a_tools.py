"""
Comprehensive security, scope, and regression tests for Phase 10A Passive Tool Adapters (R4 Remediation).
"""

from __future__ import annotations

import datetime
import json
import logging
import pytest

from ctf_mentor.domain.models import AuthorizedScope
from ctf_mentor.tools import (
    CrtShAdapter,
    CrtShInput,
    CredentialNotFoundError,
    EnvCredentialProvider,
    EvidenceCandidate,
    ExecutionClass,
    GitHubCodeSearchAdapter,
    GitHubSearchInput,
    RateLimitExceededError,
    ConcurrencyLimitExceededError,
    RateLimitPolicy,
    RedirectSecurityError,
    ResponseSizeExceededError,
    SSRFProtectionError,
    SecretStr,
    SecureNetworkWrapper,
    ShodanAdapter,
    ShodanInput,
    StaticToolRegistry,
    ToolAdapter,
    ToolCache,
    ToolInputSchema,
    ToolResult,
    UnknownToolError,
    VirusTotalAdapter,
    VirusTotalInput,
    WaybackAdapter,
    WaybackInput,
    normalize_tool_result,
)
from ctf_mentor.tools.network import is_forbidden_ip, resolve_and_validate_host


@pytest.fixture
def sample_scope():
    return AuthorizedScope(
        scope_id="scope-123",
        challenge_id="challenge-abc",
        scheme="https",
        hostname="target.com",
        port=443,
        allowed_path_patterns=["/*"],
        allowed_methods=["GET"],
        exclusions=[],
        query_restrictions={"allowed_domains": ["target.com", "sub.target.com"]},
        environment_id="env-ctf",
        challenge_relationship="primary_target",
        created_at=datetime.datetime.now(datetime.timezone.utc),
        metadata={
            "allowed_domains": ["target.com", "sub.target.com"],
            "allowed_subjects": ["target.com", "target_user"],
            "allowed_artifacts": ["artifact.txt", "44d88612fea8a8f36de82e1278abb02f"],
        },
    )


# ============================================================================
# MOCKED HTTP 200 SUCCESS-PATH EXECUTION TESTS FOR ALL 5 ADAPTERS
# ============================================================================


def test_crtsh_success_path_execution(sample_scope, monkeypatch):
    adapter = CrtShAdapter()
    inp = adapter.validate_input({"domain": "target.com"})

    def mock_request(self, url, method="GET", headers=None, body=None, context_key="global"):
        assert "crt.sh" in url
        return 200, {}, json.dumps([{"name_value": "sub1.target.com", "id": 101}]).encode("utf-8")

    import ctf_mentor.tools.adapters.crtsh as crt_mod
    monkeypatch.setattr(crt_mod.SecureNetworkWrapper, "request", mock_request)

    res = adapter.execute(inp, sample_scope)
    assert res.error_status is None
    assert res.tool_id == "crt_sh"
    assert res.authorized_target == "target.com"
    assert len(res.normalized_observations) == 1
    assert res.normalized_observations[0].trust == "UNTRUSTED"
    assert "sub1.target.com" in res.normalized_observations[0].observation
    assert res.provenance.get("domain") == "target.com"


def test_wayback_success_path_execution(sample_scope, monkeypatch):
    adapter = WaybackAdapter()
    inp = adapter.validate_input({"domain": "target.com", "limit": 5})

    def mock_request(self, url, method="GET", headers=None, body=None, context_key="global"):
        assert "web.archive.org" in url
        data = [
            ["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"],
            ["k1", "20230101", "https://target.com/index.html", "text/html", "200", "d1", "100"],
        ]
        return 200, {}, json.dumps(data).encode("utf-8")

    import ctf_mentor.tools.adapters.wayback as wb_mod
    monkeypatch.setattr(wb_mod.SecureNetworkWrapper, "request", mock_request)

    res = adapter.execute(inp, sample_scope)
    assert res.error_status is None
    assert res.tool_id == "wayback"
    assert res.authorized_target == "target.com"
    assert len(res.normalized_observations) == 1
    assert res.normalized_observations[0].trust == "UNTRUSTED"
    assert "https://target.com/index.html" in res.normalized_observations[0].observation


def test_shodan_success_path_execution(sample_scope, monkeypatch):
    test_key = "REAL_TEST_SHODAN_SECRET_KEY_77777"
    provider = EnvCredentialProvider(overrides={"shodan_api_key": test_key})
    adapter = ShodanAdapter()
    inp = adapter.validate_input({"domain": "target.com"})

    def mock_request(self, url, method="GET", headers=None, body=None, context_key="global"):
        assert "api.shodan.io" in url
        # Assert API key is passed via HTTP header, NOT in URL query params
        assert test_key not in url
        assert headers is not None and headers.get("key") == test_key
        data = {"subdomains": ["api"], "data": [{"subdomain": "api", "value": "1.1.1.1", "type": "A"}]}
        return 200, {}, json.dumps(data).encode("utf-8")

    import ctf_mentor.tools.adapters.shodan as sh_mod
    monkeypatch.setattr(sh_mod.SecureNetworkWrapper, "request", mock_request)

    res = adapter.execute(inp, sample_scope, credential_provider=provider)
    assert res.error_status is None
    assert res.tool_id == "shodan"
    assert len(res.normalized_observations) == 2
    assert res.normalized_observations[0].trust == "UNTRUSTED"
    assert res.provenance.get("source_url") == "https://api.shodan.io/dns/domain/target.com"

    # Verify API key is absent from result, provenance, and output
    assert test_key not in str(res)
    assert test_key not in str(res.provenance)


def test_virustotal_success_path_execution(sample_scope, monkeypatch):
    test_key = "REAL_TEST_VT_SECRET_KEY_88888"
    provider = EnvCredentialProvider(overrides={"virustotal_api_key": test_key})
    adapter = VirusTotalAdapter()

    def mock_request(self, url, method="GET", headers=None, body=None, context_key="global"):
        assert "virustotal.com" in url
        assert headers is not None and headers.get("x-apikey") == test_key
        data = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 65}}}}
        return 200, {}, json.dumps(data).encode("utf-8")

    import ctf_mentor.tools.adapters.virustotal as vt_mod
    monkeypatch.setattr(vt_mod.SecureNetworkWrapper, "request", mock_request)

    # 1. DOMAIN_TARGET execute path
    inp_domain = adapter.validate_input({"target_value": "target.com", "target_type": "DOMAIN_TARGET"})
    res_domain = adapter.execute(inp_domain, sample_scope, credential_provider=provider)
    assert res_domain.error_status is None
    assert res_domain.tool_id == "virustotal"
    assert len(res_domain.normalized_observations) == 1
    assert res_domain.normalized_observations[0].trust == "UNTRUSTED"

    # 2. METADATA_TARGET execute path (tests urllib.parse.quote cleanly)
    inp_meta = adapter.validate_input({"target_value": "44d88612fea8a8f36de82e1278abb02f", "target_type": "METADATA_TARGET"})
    res_meta = adapter.execute(inp_meta, sample_scope, credential_provider=provider)
    assert res_meta.error_status is None
    assert res_meta.authorized_target == "44d88612fea8a8f36de82e1278abb02f"


def test_github_success_path_execution(sample_scope, monkeypatch):
    adapter = GitHubCodeSearchAdapter()
    inp = adapter.validate_input({"query": "target.com"})

    def mock_request(self, url, method="GET", headers=None, body=None, context_key="global"):
        assert "api.github.com" in url
        data = {"items": [{"name": "c.py", "path": "src/c.py", "html_url": "https://github.com/o/r/src/c.py", "repository": {"full_name": "o/r"}}]}
        return 200, {}, json.dumps(data).encode("utf-8")

    import ctf_mentor.tools.adapters.github as gh_mod
    monkeypatch.setattr(gh_mod.SecureNetworkWrapper, "request", mock_request)

    res = adapter.execute(inp, sample_scope)
    assert res.error_status is None
    assert res.tool_id == "github_code_search"
    assert len(res.normalized_observations) == 1
    assert res.normalized_observations[0].trust == "UNTRUSTED"


# ============================================================================
# FINDING 1 REGRESSION TESTS — SHODAN SECRET LEAKAGE THROUGH REDIRECT LOGS
# ============================================================================


def test_shodan_secret_not_in_redirect_logs_or_urls(sample_scope, caplog):
    test_secret = "SUPER_SECRET_SHODAN_KEY_99999"
    provider = EnvCredentialProvider(overrides={"shodan_api_key": test_secret})
    adapter = ShodanAdapter()

    redirect_count = 0

    def mock_transport(url, headers):
        nonlocal redirect_count
        assert test_secret not in url
        assert headers.get("key") == test_secret

        if redirect_count == 0:
            redirect_count += 1
            return 302, {"location": "https://api.shodan.io/dns/domain/target.com/page2"}, b""
        return 200, {}, json.dumps({"subdomains": ["sub1"]}).encode("utf-8")

    wrapper = SecureNetworkWrapper(
        allowed_destinations=adapter.network_destinations,
        transport_mock=mock_transport,
    )

    with caplog.at_level(logging.DEBUG):
        inp = ShodanInput(domain="target.com")
        status, resp_headers, resp_bytes = wrapper.request("https://api.shodan.io/dns/domain/target.com", headers={"key": test_secret}, context_key="shodan")
        assert status == 200

    assert test_secret not in caplog.text


# ============================================================================
# FINDING 2 REGRESSION TESTS — GITHUB QUERY / AUTHORIZATION BINDING
# ============================================================================


def test_github_query_target_subject_binding_through_execute(sample_scope, monkeypatch):
    adapter = GitHubCodeSearchAdapter()

    # 1. query="target.com", target_subject="target.com" -> ACCEPT
    inp1 = adapter.validate_input({"query": "target.com", "target_subject": "target.com"})
    assert adapter.validate_scope(inp1.query, sample_scope) is True

    # 2. query="target.com", target_subject="target.com." -> ACCEPT (normalized match)
    inp2 = adapter.validate_input({"query": "target.com", "target_subject": "target.com."})
    assert adapter.validate_scope(inp2.query, sample_scope) is True

    # 3. query="target.com something", target_subject="target.com" -> REJECT (no substring binding)
    with pytest.raises(ValueError, match="does not strictly match"):
        adapter.validate_input({"query": "target.com something", "target_subject": "target.com"})

    # 4. query="target.com.evil.com", target_subject="target.com" -> REJECT
    with pytest.raises(ValueError, match="does not strictly match"):
        adapter.validate_input({"query": "target.com.evil.com", "target_subject": "target.com"})

    # 5. query="unrelated", target_subject="target.com" -> REJECT
    with pytest.raises(ValueError, match="does not strictly match"):
        adapter.validate_input({"query": "unrelated", "target_subject": "target.com"})

    # Full execute-path checks:
    def mock_request(self, url, method="GET", headers=None, body=None, context_key="global"):
        return 200, {}, json.dumps({"items": []}).encode("utf-8")

    import ctf_mentor.tools.adapters.github as gh_mod
    monkeypatch.setattr(gh_mod.SecureNetworkWrapper, "request", mock_request)

    # Authorized query execution -> SUCCEEDS
    valid_inp = adapter.validate_input({"query": "target.com"})
    res = adapter.execute(valid_inp, sample_scope)
    assert res.error_status is None
    assert res.authorized_target == "target.com"

    # Unrelated query -> REJECTED at execute()
    unrelated_inp = GitHubSearchInput(query="unrelated_secret_text")
    with pytest.raises(ValueError, match="out of authorized scope"):
        adapter.execute(unrelated_inp, sample_scope)

    # Malicious query -> REJECTED at execute()
    malicious_inp = GitHubSearchInput(query="SELECT * FROM users WHERE 1=1")
    with pytest.raises(ValueError, match="out of authorized scope"):
        adapter.execute(malicious_inp, sample_scope)

    # Lookalike domain query -> REJECTED at execute()
    lookalike_inp = GitHubSearchInput(query="target.com.evil.com")
    with pytest.raises(ValueError, match="out of authorized scope"):
        adapter.execute(lookalike_inp, sample_scope)


# ============================================================================
# FINDING 3 REGRESSION TESTS — VIRUSTOTAL INPUT HARDENING
# ============================================================================


def test_virustotal_path_traversal_and_malformed_inputs_rejected():
    adapter = VirusTotalAdapter()

    # Traversal inputs -> REJECTED
    traversal_cases = [
        "../../etc/passwd",
        "../target.com",
        "target.com/evil",
        "target.com\\evil",
    ]
    for case in traversal_cases:
        with pytest.raises(ValueError, match="Path traversal or slashes not permitted"):
            adapter.validate_input({"target_value": case, "target_type": "DOMAIN_TARGET"})

    # Malformed / injection inputs -> REJECTED
    malformed_cases = [
        "https://target.com",
        "target.com?x=y",
        "target.com#fragment",
        "invalid_domain_name!",
    ]
    for case in malformed_cases:
        with pytest.raises(ValueError):
            adapter.validate_input({"target_value": case, "target_type": "DOMAIN_TARGET"})


def test_virustotal_valid_inputs_accepted(sample_scope):
    adapter = VirusTotalAdapter()

    # Valid domain -> ACCEPTED
    inp1 = adapter.validate_input({"target_value": "target.com", "target_type": "DOMAIN_TARGET"})
    assert inp1.target_value == "target.com"

    # Valid hash / metadata target -> ACCEPTED
    inp2 = adapter.validate_input({"target_value": "44d88612fea8a8f36de82e1278abb02f", "target_type": "METADATA_TARGET"})
    assert inp2.target_value == "44d88612fea8a8f36de82e1278abb02f"


# ============================================================================
# A. ToolAdapter Contract & Basic Validation
# ============================================================================


def test_tool_adapter_contract_crtsh():
    adapter = CrtShAdapter()
    assert adapter.tool_id == "crt_sh"
    assert adapter.execution_class == ExecutionClass.PASSIVE_NETWORK
    assert "DOMAIN_TARGET" in adapter.allowed_target_types
    assert adapter.requires_credentials is False
    assert adapter.network_destinations == ["crt.sh"]


def test_typed_input_validation_crtsh():
    adapter = CrtShAdapter()
    inp = adapter.validate_input({"domain": "target.com"})
    assert isinstance(inp, CrtShInput)
    assert inp.domain == "target.com"

    with pytest.raises(ValueError, match="Unexpected argument keys"):
        adapter.validate_input({"domain": "target.com", "extra_param": "evil"})

    with pytest.raises(ValueError, match="Invalid domain format"):
        adapter.validate_input({"domain": "invalid_domain_name!!!"})


def test_typed_input_validation_wayback():
    adapter = WaybackAdapter()
    inp = adapter.validate_input({"domain": "target.com", "limit": 20})
    assert isinstance(inp, WaybackInput)
    assert inp.limit == 20

    with pytest.raises(ValueError):
        adapter.validate_input({"domain": "target.com", "limit": 9999})


def test_typed_input_validation_shodan():
    adapter = ShodanAdapter()
    inp = adapter.validate_input({"domain": "target.com"})
    assert isinstance(inp, ShodanInput)

    with pytest.raises(ValueError):
        adapter.validate_input({"domain": ""})


# ============================================================================
# B. Static Registry, C. Unknown Tool Rejection, D. Duplicate Tool IDs
# ============================================================================


def test_static_registry_lookup():
    registry = StaticToolRegistry()
    assert "crt_sh" in registry.list_tools()
    assert "wayback" in registry.list_tools()
    assert "shodan" in registry.list_tools()
    assert "virustotal" in registry.list_tools()
    assert "github_code_search" in registry.list_tools()

    adapter = registry.get("crt_sh")
    assert isinstance(adapter, CrtShAdapter)


def test_unknown_tool_rejection():
    registry = StaticToolRegistry()
    assert registry.get("unknown_tool") is None
    with pytest.raises(UnknownToolError):
        registry.get_or_raise("unknown_tool")


def test_duplicate_tool_id_registration():
    registry = StaticToolRegistry()
    with pytest.raises(ValueError, match="Duplicate tool_id"):
        registry.register(CrtShAdapter())


# ============================================================================
# CONCURRENCY ENFORCEMENT & EXACT DESTINATION ALLOWLIST
# ============================================================================


def test_concurrency_enforcement():
    def mock_transport(url, headers):
        return 200, {}, b"OK"

    policy = RateLimitPolicy(max_concurrent=2, max_requests_per_window=100)
    wrapper = SecureNetworkWrapper(
        allowed_destinations=["target.com"],
        rate_limit_policy=policy,
        transport_mock=mock_transport,
    )

    context = "test_concurrent_ctx_r4"
    from ctf_mentor.tools.network import _global_concurrency_tracker

    assert _global_concurrency_tracker.acquire(context, 2) is True
    assert _global_concurrency_tracker.acquire(context, 2) is True

    with pytest.raises(ConcurrencyLimitExceededError):
        wrapper.request("https://target.com/3", context_key=context)

    _global_concurrency_tracker.release(context)
    status, _, _ = wrapper.request("https://target.com/4", context_key=context)
    assert status == 200
    _global_concurrency_tracker.release(context)


def test_destination_allowlist_exact_matching():
    def mock_transport(url, headers):
        return 200, {}, b"OK"

    wrapper = SecureNetworkWrapper(
        allowed_destinations=["allowed.example.com"],
        transport_mock=mock_transport,
    )

    status, _, _ = wrapper.request("https://allowed.example.com/api")
    assert status == 200

    with pytest.raises(RedirectSecurityError, match="not in exact authorized network allowlist"):
        wrapper.request("https://sub.allowed.example.com/api")


# ============================================================================
# SSRF, LOCALHOST, CLOUD METADATA
# ============================================================================


def test_ssrf_forbidden_ip_detection():
    assert is_forbidden_ip("10.0.0.1") is True
    assert is_forbidden_ip("172.16.0.1") is True
    assert is_forbidden_ip("192.168.1.100") is True
    assert is_forbidden_ip("127.0.0.1") is True
    assert is_forbidden_ip("169.254.169.254") is True
    assert is_forbidden_ip("93.184.216.34") is False


def test_ssrf_forbidden_hostname_resolution():
    wrapper = SecureNetworkWrapper(allowed_destinations=["localhost", "169.254.169.254"])
    with pytest.raises(SSRFProtectionError):
        wrapper.request("https://localhost/api")


# ============================================================================
# CREDENTIAL ISOLATION & UNTRUSTED EVIDENCE TRUST
# ============================================================================


def test_secret_str_redaction():
    secret = SecretStr("super_secret_shodan_key_12345")
    assert str(secret) == "***REDACTED***"
    assert repr(secret) == "SecretStr('***REDACTED***')"
    assert secret.get_secret_value() == "super_secret_shodan_key_12345"


def test_all_adapters_produce_untrusted_evidence(sample_scope):
    crt = CrtShAdapter().normalize([{"name_value": "sub.target.com"}], {"domain": "target.com"})
    assert crt[0].trust == "UNTRUSTED"

    way = WaybackAdapter().normalize([["h"], ["k", "ts", "https://target.com/a"]], {"domain": "target.com"})
    assert way[0].trust == "UNTRUSTED"

    sho = ShodanAdapter().normalize({"subdomains": ["api"]}, {"domain": "target.com"})
    assert sho[0].trust == "UNTRUSTED"

    vt = VirusTotalAdapter().normalize({"data": {"attributes": {"last_analysis_stats": {"harmless": 5}}}}, {"target_value": "target.com"})
    assert vt[0].trust == "UNTRUSTED"

    gh = GitHubCodeSearchAdapter().normalize({"items": [{"name": "a", "path": "p", "html_url": "u", "repository": {"full_name": "r"}}]}, {"target_subject": "target.com"})
    assert gh[0].trust == "UNTRUSTED"
