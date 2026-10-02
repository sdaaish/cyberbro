import json
import logging
from typing import Any

import requests

from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)

# Emojis prefixed to each result link label, mirroring the per-engine icon
# convention used in templates/index.html (engineIcons).
_IOC_EMOJI = "🧷"
_NOTE_EMOJI = "📝"


class DFIRIrisEngine(BaseEngine):
    @property
    def name(self):
        return "dfir_iris"

    @property
    def supported_types(self) -> ObservableType:
        return (
            ObservableType.IPV4
            | ObservableType.IPV6
            | ObservableType.MD5
            | ObservableType.SHA1
            | ObservableType.SHA256
            | ObservableType.BOGON
            | ObservableType.FQDN
            | ObservableType.URL
        )

    def _auth_headers(self) -> dict[str, str]:
        """Build the Authorization/Content-Type headers shared by both API versions."""
        return {
            "Authorization": "Bearer " + self.secrets.dfir_iris_api_key,
            "Content-Type": "application/json",
        }

    @staticmethod
    def _make_link(url: str, case_id: int, emoji: str) -> dict[str, str]:
        """Build a link entry with a bling label (emoji + CaseID) alongside its URL."""
        return {"url": url, "label": f"{emoji} CaseID: {case_id}"}

    @staticmethod
    def _dedupe_links(links: list[dict[str, str]]) -> list[dict[str, str]]:
        """Deduplicate link entries by URL, keeping a stable URL-sorted order."""
        unique_by_url = {link["url"]: link for link in links}
        return [unique_by_url[url] for url in sorted(unique_by_url)]

    # ------------------------------------------------------------------
    # Legacy API support (DFIR-IRIS v2.0.5 up to v2.4.29)
    # ------------------------------------------------------------------

    def _build_search_body(self, observable: Observable, search_type: str) -> dict[str, str]:
        """Build the request body for a DFIR-IRIS search, applying the same selective
        wildcard pattern used for both ioc and notes searches."""
        match observable.type:
            case (
                ObservableType.IPV4
                | ObservableType.IPV6
                | ObservableType.MD5
                | ObservableType.SHA1
                | ObservableType.SHA256
                | ObservableType.BOGON
            ):
                return {"search_value": f"%{observable.value}", "search_type": search_type}
            case ObservableType.FQDN | ObservableType.URL:
                return {"search_value": f"{observable.value}%", "search_type": search_type}
            case _:
                return {"search_value": f"{observable.value}", "search_type": search_type}

    def _query_legacy(self, dfir_iris_url: str, body: dict[str, str]) -> Any:
        """Send a search request to the legacy DFIR-IRIS API (up to v2.4.29) and
        return the parsed JSON response."""
        url = f"{dfir_iris_url}/search"
        params: dict[str, int] = {"cid": 1}
        payload = json.dumps(body)
        response = requests.post(
            url,
            params=params,
            headers=self._auth_headers(),
            data=payload,
            proxies=self.proxies,
            verify=self.ssl_verify,
            timeout=5,
        )
        response.raise_for_status()
        return response.json()

    @staticmethod
    def _extract_case_ids(data: Any) -> list[int]:
        """Extract the case_ids from a legacy DFIR-IRIS search response, if any."""
        if not data or "data" not in data or not data["data"]:
            return []
        return [i["case_id"] for i in data["data"]]

    def _analyze_legacy(self, observable: Observable, dfir_iris_url: str) -> dict[str, Any] | None:
        """Query the legacy DFIR-IRIS API (v2.0.5 up to v2.4.29), which exposes a
        single POST /search endpoint per search type (ioc, notes)."""
        try:
            ioc_body = self._build_search_body(observable, "ioc")
            ioc_data = self._query_legacy(dfir_iris_url, ioc_body)
        except Exception as e:
            logger.error(
                "Error querying DFIR-IRIS for '%s': %s", observable.value, e, exc_info=True
            )
            return None

        ioc_links = [
            self._make_link(f"{dfir_iris_url}/case/ioc?cid={case_id}", case_id, _IOC_EMOJI)
            for case_id in self._extract_case_ids(ioc_data)
        ]

        notes_links: list[dict[str, str]] = []
        if self.secrets.dfir_iris_search_notes:
            try:
                notes_body = self._build_search_body(observable, "notes")
                notes_data = self._query_legacy(dfir_iris_url, notes_body)
                notes_links = [
                    self._make_link(
                        f"{dfir_iris_url}/case/notes?cid={case_id}", case_id, _NOTE_EMOJI
                    )
                    for case_id in self._extract_case_ids(notes_data)
                ]
            except Exception as e:
                logger.warning(
                    "Error querying DFIR-IRIS notes for '%s': %s",
                    observable.value,
                    e,
                    exc_info=True,
                )

        if not ioc_links and not notes_links:
            return None

        unique_links = self._dedupe_links(ioc_links + notes_links)
        return {"reports": len(unique_links), "links": unique_links}

    # ------------------------------------------------------------------
    # New API support (DFIR-IRIS v3.0.0+)
    # ------------------------------------------------------------------

    def _query_v3(self, dfir_iris_url: str, observable: Observable, types: str) -> Any:
        """Send a search request to the new DFIR-IRIS v3.0.0 API (GET /api/v2/search)
        and return the parsed JSON response."""
        url = f"{dfir_iris_url}/api/v2/search"
        params = {"value": observable.value, "types": types}
        response = requests.get(
            url,
            params=params,
            headers=self._auth_headers(),
            proxies=self.proxies,
            verify=self.ssl_verify,
            timeout=5,
        )
        response.raise_for_status()
        return response.json()

    @staticmethod
    def _extract_results_by_type(data: Any, result_type: str) -> list[dict[str, Any]]:
        """Extract the result entries for a given result type (ioc, notes) from a
        DFIR-IRIS v3.0.0 search response, if any."""
        if not data or "data" not in data or not data["data"]:
            return []
        return [i for i in data["data"] if i.get("type") == result_type]

    def _analyze_v3(self, observable: Observable, dfir_iris_url: str) -> dict[str, Any] | None:
        """Query the new DFIR-IRIS v3.0.0 API, which exposes a single GET
        /api/v2/search endpoint returning both ioc and notes results at once."""
        types = "ioc,notes" if self.secrets.dfir_iris_search_notes else "ioc"
        try:
            data = self._query_v3(dfir_iris_url, observable, types)
        except Exception as e:
            logger.error(
                "Error querying DFIR-IRIS for '%s': %s", observable.value, e, exc_info=True
            )
            return None

        ioc_links = [
            self._make_link(
                f"{dfir_iris_url}/case/{result['case_id']}/iocs/{result['ioc_id']}",
                result["case_id"],
                _IOC_EMOJI,
            )
            for result in self._extract_results_by_type(data, "ioc")
        ]
        notes_links = [
            self._make_link(
                f"{dfir_iris_url}/case/{result['case_id']}/notes/{result['note_id']}",
                result["case_id"],
                _NOTE_EMOJI,
            )
            for result in self._extract_results_by_type(data, "notes")
        ]

        if not ioc_links and not notes_links:
            return None

        unique_links = self._dedupe_links(ioc_links + notes_links)
        return {"reports": len(unique_links), "links": unique_links}

    # ------------------------------------------------------------------

    def analyze(self, observable: Observable) -> dict[str, Any] | None:
        dfir_iris_url = self.secrets.dfir_iris_url

        if self.secrets.dfir_iris_v3:
            return self._analyze_v3(observable, dfir_iris_url)
        return self._analyze_legacy(observable, dfir_iris_url)

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {"dfir_iris_total_count": None, "dfir_iris_link": None}

        links_str = ", ".join(link["url"] for link in analysis_result.get("links", []))
        return {
            "dfir_iris_total_count": analysis_result.get("reports"),
            "dfir_iris_link": links_str if links_str else None,
        }
