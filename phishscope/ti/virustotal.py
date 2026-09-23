import base64
import json
import os
import time
import urllib.error
import urllib.request
from urllib.error import HTTPError, URLError

from .models import IOCType, TIResult, TIStatus
from .provider import TIProvider


class VirusTotalProvider(TIProvider):
    def __init__(self):
        self.api_key = os.environ.get("PHISHSCOPE_VT_API_KEY", "").strip()
        self.base_url = "https://www.virustotal.com/api/v3"

    @property
    def name(self) -> str:
        return "VirusTotal"

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def _get_url_id(self, url: str) -> str:
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def _parse_stat(self, stats: dict, key: str) -> int:
        val = stats.get(key)
        if val is None:
            return 0
        if isinstance(val, int) and val >= 0:
            return val
        return 0

    def lookup(self, ioc_type: IOCType, ioc_value: str) -> TIResult:
        if not self.is_configured():
            return self._build_result(ioc_type, ioc_value, TIStatus.NOT_CONFIGURED)

        endpoint = ""
        identifier = ioc_value

        if ioc_type == IOCType.IPV4:
            endpoint = f"/ip_addresses/{identifier}"
        elif ioc_type == IOCType.DOMAIN:
            endpoint = f"/domains/{identifier}"
        elif ioc_type == IOCType.SHA256:
            endpoint = f"/files/{identifier}"
        elif ioc_type == IOCType.URL:
            identifier = self._get_url_id(ioc_value)
            endpoint = f"/urls/{identifier}"
        else:
            return self._build_result(ioc_type, ioc_value, TIStatus.INVALID_IOC)

        req = urllib.request.Request(self.base_url + endpoint)
        req.add_header("x-apikey", self.api_key)

        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                body = response.read()
                data = json.loads(body)

                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})

                if not stats:
                    return self._build_result(ioc_type, ioc_value, TIStatus.INVALID_RESPONSE)

                malicious = self._parse_stat(stats, "malicious")
                suspicious = self._parse_stat(stats, "suspicious")
                harmless = self._parse_stat(stats, "harmless")
                timeout = self._parse_stat(stats, "timeout")
                undetected = self._parse_stat(stats, "undetected")

                total = malicious + suspicious + harmless + timeout + undetected

                return self._build_result(
                    ioc_type,
                    ioc_value,
                    TIStatus.LOOKUP_SUCCESS,
                    malicious=malicious,
                    suspicious=suspicious,
                    harmless=harmless,
                    timeout=timeout,
                    undetected=undetected,
                    total_engines=total
                )

        except HTTPError as e:
            if e.code == 404:
                return self._build_result(ioc_type, ioc_value, TIStatus.NO_RESULT)
            elif e.code == 429:
                return self._build_result(ioc_type, ioc_value, TIStatus.RATE_LIMITED)
            elif 400 <= e.code < 500:
                return self._build_result(ioc_type, ioc_value, TIStatus.PROVIDER_ERROR)
            else:
                return self._build_result(ioc_type, ioc_value, TIStatus.PROVIDER_ERROR)
        except URLError as e:
            if isinstance(e.reason, TimeoutError):
                return self._build_result(ioc_type, ioc_value, TIStatus.TIMEOUT)
            return self._build_result(ioc_type, ioc_value, TIStatus.PROVIDER_ERROR)
        except json.JSONDecodeError:
            return self._build_result(ioc_type, ioc_value, TIStatus.INVALID_RESPONSE)
        except Exception:
            return self._build_result(ioc_type, ioc_value, TIStatus.PROVIDER_ERROR)

    def _build_result(
        self, ioc_type: IOCType, ioc_value: str, status: TIStatus, **kwargs
    ) -> TIResult:
        return TIResult(
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            provider_name=self.name,
            status=status,
            timestamp=time.time(),
            **kwargs
        )
