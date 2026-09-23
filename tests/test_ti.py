import json
import sys
import time
import urllib.request
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

import pytest

from phishscope.cli import main
from phishscope.models import Confidence, Finding, FindingCategory, Severity
from phishscope.ti import IOCType, TICache, TIOrchestrator, TIResult, TIStatus, VirusTotalProvider


@pytest.fixture
def vt_provider():
    with patch.dict("os.environ", {"PHISHSCOPE_VT_API_KEY": "fake_key"}):
        return VirusTotalProvider()

@pytest.fixture
def mock_response():
    return MockHTTPResponse(json.dumps({
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 5,
                    "suspicious": 1,
                    "harmless": 50,
                    "undetected": 10,
                    "timeout": 2
                }
            }
        }
    }).encode("utf-8"))

@pytest.fixture
def mock_clean_response():
    return MockHTTPResponse(json.dumps({
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 60,
                    "undetected": 10
                }
            }
        }
    }).encode("utf-8"))

def _f(evidence):
    return Finding(
        id="1", name="N", category=FindingCategory.URL,
        severity=Severity.LOW, confidence=Confidence.LOW,
        evidence=evidence, description="Desc", source="body"
    )

def test_vt_valid_malicious(vt_provider, mock_response):
    with patch.object(urllib.request, "urlopen", return_value=mock_response):

        res = vt_provider.lookup(IOCType.URL, "http://evil.com")
        assert res.status == TIStatus.LOOKUP_SUCCESS
        assert res.malicious == 5
        assert res.suspicious == 1
        assert res.timeout == 2
        assert res.total_engines == 68
        assert res.cache_hit is False

def test_vt_stats_validation(vt_provider):
    mock_res = MockHTTPResponse(json.dumps({
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": -5,
                    "suspicious": "high",
                    "harmless": 50,
                    "timeout": 1,
                    "unexpected": 999
                }
            }
        }
    }).encode("utf-8"))
    with patch.object(urllib.request, "urlopen", return_value=mock_res):

        res = vt_provider.lookup(IOCType.URL, "http://evil.com")
        assert res.malicious == 0
        assert res.suspicious == 0
        assert res.harmless == 50
        assert res.undetected == 0
        assert res.timeout == 1
        assert res.total_engines == 51

def test_vt_valid_clean(vt_provider, mock_clean_response):
    with patch.object(urllib.request, "urlopen", return_value=mock_clean_response):

        res = vt_provider.lookup(IOCType.URL, "http://google.com")
        assert res.status == TIStatus.LOOKUP_SUCCESS
        assert res.malicious == 0

def _raise_http_error(code):
    return HTTPError(url="", code=code, msg="", hdrs={}, fp=None)

def test_vt_404(vt_provider):
    with patch.object(urllib.request, "urlopen", side_effect=_raise_http_error(404)):
        res = vt_provider.lookup(IOCType.URL, "http://unknown.com")
        assert res.status == TIStatus.NO_RESULT

def test_vt_429(vt_provider):
    with patch.object(urllib.request, "urlopen", side_effect=_raise_http_error(429)):
        res = vt_provider.lookup(IOCType.URL, "http://unknown.com")
        assert res.status == TIStatus.RATE_LIMITED

def test_vt_5xx(vt_provider):
    with patch.object(urllib.request, "urlopen", side_effect=_raise_http_error(500)):
        res = vt_provider.lookup(IOCType.URL, "http://unknown.com")
        assert res.status == TIStatus.PROVIDER_ERROR

def test_vt_timeout(vt_provider):
    with patch.object(urllib.request, "urlopen", side_effect=URLError(TimeoutError())):
        res = vt_provider.lookup(IOCType.URL, "http://unknown.com")
        assert res.status == TIStatus.TIMEOUT

def test_vt_invalid_json(vt_provider):
    mock_res = MockHTTPResponse(b"{invalid_json")
    with patch.object(urllib.request, "urlopen", return_value=mock_res):

        res = vt_provider.lookup(IOCType.URL, "http://unknown.com")
        assert res.status == TIStatus.INVALID_RESPONSE

def test_vt_malformed_response(vt_provider):
    mock_res = MockHTTPResponse(b'{"data": {}}')
    with patch.object(urllib.request, "urlopen", return_value=mock_res):

        res = vt_provider.lookup(IOCType.URL, "http://unknown.com")
        assert res.status == TIStatus.INVALID_RESPONSE

def test_missing_api_key():
    with patch.dict("os.environ", {}, clear=True):
        provider = VirusTotalProvider()
        res = provider.lookup(IOCType.URL, "http://unknown.com")
        assert res.status == TIStatus.NOT_CONFIGURED

def test_orchestrator_not_enabled():
    orc = TIOrchestrator(enable_ti=False)
    findings = [_f("Defanged URL: hxxp://evil.com")]
    email = MagicMock()
    email.attachments = []
    res = orc.run(findings, email)
    # URL and DOMAIN extracted
    assert len(res) == 2
    assert res[0].status == TIStatus.NOT_ENABLED

def test_cache_privacy_and_hit(tmp_path):
    cache_file = tmp_path / "cache.json"
    cache = TICache(cache_file)

    res = TIResult(
        IOCType.URL, "http://test.com", "VirusTotal",
        TIStatus.NO_RESULT, time.time()
    )
    cache.set(res)

    # Verify raw IOC not in file
    content = cache_file.read_text()
    assert "http://test.com" not in content
    assert "ioc_value" not in content

    # Miss
    assert cache.get("VirusTotal", IOCType.URL, "http://unknown.com") is None

    # Hit
    cached = cache.get("VirusTotal", IOCType.URL, "http://test.com")
    assert cached is not None
    assert cached.status == TIStatus.NO_RESULT
    assert cached.cache_hit is True

def test_expired_cache(tmp_path):
    cache_file = tmp_path / "cache.json"
    cache = TICache(cache_file, ttl_seconds=1)
    res = TIResult(
        IOCType.URL, "http://test.com", "VirusTotal",
        TIStatus.LOOKUP_SUCCESS, time.time() - 5
    )
    cache.set(res)
    assert cache.get("VirusTotal", IOCType.URL, "http://test.com") is None

def test_duplicate_ioc_dedup():
    orc = TIOrchestrator()
    findings = [
        _f("Defanged URL: hxxp://EVIL.com."),
        _f("Defanged URL: hxxp://evil[.]com")
    ]
    email = MagicMock()
    email.attachments = []
    iocs = orc.extract_and_normalize(findings, email)

    # We get two URLs (http://EVIL.com. and http://evil.com) and one deduplicated DOMAIN
    assert len(iocs) == 3
    assert (IOCType.DOMAIN, "evil.com") in iocs

def test_ipv4_validation():
    orc = TIOrchestrator()
    assert orc._normalize_ipv4("1.2.3.4") == "1.2.3.4"
    assert orc._normalize_ipv4("999.999.1.1") is None
    assert orc._normalize_ipv4("1.2.3") is None

def test_ip_based_url():
    orc = TIOrchestrator()
    findings = [_f("Defanged URL: hxxp://192[.]168[.]1[.]10/login?a=1")]
    email = MagicMock()
    email.attachments = []
    iocs = orc.extract_and_normalize(findings, email)

    # Should yield exactly URL and IPv4, NO DOMAIN
    assert len(iocs) == 2
    assert (IOCType.URL, "http://192.168.1.10/login?a=1") in iocs
    assert (IOCType.IPV4, "192.168.1.10") in iocs

def test_url_normalization_preserves_query():
    orc = TIOrchestrator()
    assert orc._normalize_url("hxxps://evil[.]com/path?q=1#frag") == "https://evil.com/path?q=1#frag"

def test_corrupt_cache(tmp_path):
    cache_file = tmp_path / "cache.json"
    cache_file.write_text("{corrupt json")
    cache = TICache(cache_file)
    assert cache.get("VirusTotal", IOCType.URL, "http://test.com") is None

def test_ti_does_not_modify_score(vt_provider, mock_response, tmp_path):
    eml_file = tmp_path / "test.eml"
    eml_file.write_text("From: a@b.com\r\n\r\nhttp://192.168.1.100/login")

    test_args_1 = ["phishscope", "analyze", str(eml_file), "--json"]
    with patch.object(sys, "argv", test_args_1):
        with patch("phishscope.cli.json.dumps") as mock_json_dumps:
            main()
            call_args = mock_json_dumps.call_args[0][0]
            score_no_ti = call_args["risk_score"]
            risk_no_ti = call_args["risk_level"]

    test_args_2 = ["phishscope", "analyze", str(eml_file), "--json", "--enable-ti"]
    with patch.object(sys, "argv", test_args_2):
        with patch("phishscope.cli.json.dumps") as mock_json_dumps:
            with patch.dict("os.environ", {"PHISHSCOPE_VT_API_KEY": "fake_key"}):
                def make_mock_response(*args, **kwargs):
                    return MockHTTPResponse(
                        json.dumps({
                            "data": {
                                "attributes": {
                                    "last_analysis_stats": {
                                        "malicious": 5,
                                        "suspicious": 1,
                                        "harmless": 50,
                                        "undetected": 10,
                                        "timeout": 2
                                    }
                                }
                            }
                        }).encode()
                    )

                with patch.object(
                    urllib.request, "urlopen", side_effect=make_mock_response
                ):
                    main()
                    call_args = mock_json_dumps.call_args[0][0]
                    score_ti = call_args["risk_score"]
                    risk_ti = call_args["risk_level"]
                    ti_block = call_args["threat_intelligence"]

    assert score_no_ti == score_ti
    assert risk_no_ti == risk_ti
    assert len(ti_block) == 2

    # Deterministic sorting in Orchestrator means IPV4 comes before URL
    assert ti_block[0]["status"] == TIStatus.LOOKUP_SUCCESS.value
    assert ti_block[1]["status"] == TIStatus.LOOKUP_SUCCESS.value

def test_domain_normalization_cases():
    orc = TIOrchestrator()

    # Uppercase to lowercase
    findings1 = [_f("Defanged URL: hxxps://EVIL.COM")]
    iocs1 = orc.extract_and_normalize(findings1, MagicMock(attachments=[]))
    assert (IOCType.DOMAIN, "evil.com") in iocs1

    # Trailing dot removed
    findings2 = [_f("Defanged URL: hxxps://evil.com.")]
    iocs2 = orc.extract_and_normalize(findings2, MagicMock(attachments=[]))
    assert (IOCType.DOMAIN, "evil.com") in iocs2

    # Duplicates deduplicated
    findings3 = [_f("Defanged URL: hxxps://EVIL.COM"), _f("Defanged URL: hxxps://evil.com.")]
    iocs3 = orc.extract_and_normalize(findings3, MagicMock(attachments=[]))
    doms = [ioc for ioc in iocs3 if ioc[0] == IOCType.DOMAIN]
    assert len(doms) == 1
    assert doms[0] == (IOCType.DOMAIN, "evil.com")

    # Malformed hostname
    findings4 = [_f("Defanged URL: hxxps://.bad.com/")]
    iocs4 = orc.extract_and_normalize(findings4, MagicMock(attachments=[]))
    doms4 = [ioc for ioc in iocs4 if ioc[0] == IOCType.DOMAIN]
    assert len(doms4) == 0

    # IP hostname -> IPV4 only
    findings5 = [_f("Defanged URL: hxxps://1.2.3.4")]
    iocs5 = orc.extract_and_normalize(findings5, MagicMock(attachments=[]))
    assert (IOCType.IPV4, "1.2.3.4") in iocs5
    doms5 = [ioc for ioc in iocs5 if ioc[0] == IOCType.DOMAIN]
    assert len(doms5) == 0

    # Non-http/https scheme
    findings6 = [_f("Defanged URL: ftp://example.com/")]
    iocs6 = orc.extract_and_normalize(findings6, MagicMock(attachments=[]))
    urls6 = [ioc for ioc in iocs6 if ioc[0] == IOCType.URL]
    assert len(urls6) == 0



class MockHTTPResponse:
    def __init__(self, data):
        self.data = data
    def read(self):
        return self.data
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
