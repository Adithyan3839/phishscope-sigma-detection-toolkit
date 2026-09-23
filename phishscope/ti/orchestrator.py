import ipaddress
import re
from urllib.parse import urlparse

from phishscope.models import Finding, FindingCategory, ParsedEmail

from .cache import TICache
from .models import IOCType, TIResult, TIStatus
from .virustotal import VirusTotalProvider


class TIOrchestrator:
    def __init__(self, enable_ti: bool = False, cache: TICache | None = None):
        self.enable_ti = enable_ti
        self.cache = cache or TICache()
        self.provider = VirusTotalProvider()

    def _normalize_ipv4(self, val: str) -> str | None:
        try:
            # We strictly validate using ipaddress
            parsed = ipaddress.IPv4Address(val)
            return str(parsed)
        except ValueError:
            return None

    def _normalize_sha256(self, val: str) -> str | None:
        val = val.lower().strip()
        if re.match(r"^[a-f0-9]{64}$", val):
            return val
        return None

    def _normalize_domain(self, val: str) -> str | None:
        val = val.lower().strip()
        val = val.rstrip(".")
        if not val or " " in val or len(val) > 255:
            return None

        # Basic domain validation (alphanumeric and hyphens, no empty labels)
        labels = val.split(".")
        if len(labels) < 2:
            return None

        for label in labels:
            if not label or len(label) > 63:
                return None
            if not re.match(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", label):
                return None
        return val

    def _normalize_url(self, val: str) -> str | None:
        # Undefang
        val = val.replace("[.]", ".")
        # Strictly handle hxxp and hxxps -> http and https
        if val.lower().startswith("hxxp://"):
            val = "http://" + val[7:]
        elif val.lower().startswith("hxxps://"):
            val = "https://" + val[8:]

        # Strictly accept only http:// and https:// (not starts_with("http") which matches "httpfoo://")
        try:
            parsed = urlparse(val)
            if parsed.scheme not in ("http", "https"):
                return None
            if not parsed.netloc:
                return None
        except Exception:
            return None

        return val

    def extract_and_normalize(
        self, findings: list[Finding], email: ParsedEmail
    ) -> set[tuple[IOCType, str]]:
        iocs = set()

        for f in findings:
            if f.category == FindingCategory.URL:
                match = re.search(r"Defanged URL: (\S+)", f.evidence)
                if match:
                    norm_url = self._normalize_url(match.group(1))
                    if norm_url:
                        iocs.add((IOCType.URL, norm_url))

                        # Extract Domain or IPv4 from URL
                        try:
                            parsed = urlparse(norm_url)
                            host = parsed.hostname
                            if host:
                                host = host.lower().rstrip(".")
                                ipv4 = self._normalize_ipv4(host)
                                if ipv4:
                                    iocs.add((IOCType.IPV4, ipv4))
                                else:
                                    dom = self._normalize_domain(host)
                                    if dom:
                                        iocs.add((IOCType.DOMAIN, dom))
                        except Exception:
                            pass

                # Also try IP from Hostname: (...)
                match_ip = re.search(r"Hostname: (\d+\.\d+\.\d+\.\d+)", f.evidence)
                if match_ip:
                    norm_ip = self._normalize_ipv4(match_ip.group(1))
                    if norm_ip:
                        iocs.add((IOCType.IPV4, norm_ip))

        for att in email.attachments:
            if att.sha256:
                norm_hash = self._normalize_sha256(att.sha256)
                if norm_hash:
                    iocs.add((IOCType.SHA256, norm_hash))

        return iocs

    def run(self, findings: list[Finding], email: ParsedEmail) -> list[TIResult]:
        iocs = self.extract_and_normalize(findings, email)
        results = []

        for ioc_type, ioc_value in iocs:
            if not self.enable_ti:
                results.append(TIResult(
                    ioc_type=ioc_type,
                    ioc_value=ioc_value,
                    provider_name=self.provider.name,
                    status=TIStatus.NOT_ENABLED,
                    timestamp=0.0
                ))
                continue

            if not self.provider.is_configured():
                results.append(TIResult(
                    ioc_type=ioc_type,
                    ioc_value=ioc_value,
                    provider_name=self.provider.name,
                    status=TIStatus.NOT_CONFIGURED,
                    timestamp=0.0
                ))
                continue

            cached = self.cache.get(self.provider.name, ioc_type, ioc_value)
            if cached:
                results.append(cached)
                continue

            try:
                res = self.provider.lookup(ioc_type, ioc_value)
                self.cache.set(res)
                results.append(res)
            except Exception:
                results.append(TIResult(
                    ioc_type=ioc_type,
                    ioc_value=ioc_value,
                    provider_name=self.provider.name,
                    status=TIStatus.PROVIDER_ERROR,
                    timestamp=0.0
                ))

        # We will sort the results to ensure deterministic ordering (helps with testing)
        return sorted(results, key=lambda r: (r.ioc_type.value, r.ioc_value))
