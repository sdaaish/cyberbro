import logging
import urllib.parse
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "FQDN",
    "IPv4",
    "IPv6",
    "MD5",
    "SHA1",
    "SHA256",
    "URL",
]


def get_api_endpoint(observable: str, observable_type: str) -> str | None:
    # Map observable type to Reversing Labs SPectre Analyze endpoint
    endpoint_map = {
        "IPv4": f"/api/network-threat-intel/ip/{observable}/report/",
        "IPv6": f"/api/network-threat-intel/ip/{observable}/report/",
        "FQDN": f"/api/network-threat-intel/domain/{observable}/",
        "URL": f"/api/network-threat-intel/url/?url={urllib.parse.quote_plus(observable)}",
        "MD5": f"/api/v2/samples/{observable}/classification/?av_scanners=1",
        "SHA1": f"/api/v2/samples/{observable}/classification/?av_scanners=1",
        "SHA256": f"/api/v2/samples/{observable}/classification/?av_scanners=1",
    }

    return endpoint_map.get(observable_type)


def get_ui_endpoint(observable: str, observable_type: str) -> str | None:
    # Map observable type to Reversing Labs Spectre Analyze endpoint
    endpoint_map = {
        "IPv4": f"/ip/{observable}/analysis/ip/",
        "IPv6": f"/ip/{observable}/analysis/ip/",
        "FQDN": f"/domain/{observable}/analysis/domain/",
        "URL": f"/url/{urllib.parse.quote_plus(observable)}/analysis/url/",
        "MD5": f"/{observable}/",
        "SHA1": f"/{observable}/",
        "SHA256": f"/{observable}/",
    }

    return endpoint_map.get(observable_type)


def query_rl_analyze(
    observable: str,
    observable_type: str,
    rl_analyze_api_key: str,
    rl_analyze_url: str,
    proxies: dict[str, str],
    ssl_verify: bool = True,
) -> Optional[dict[str, Any]]:
    """
    Queries the Reversing Labs API for information about a given observable (IP, domain, URL, or file hash).

    Args:
        observable (str): The IoC to query (IPv4, IPv6, domain, URL, or file hash).
        observable_type (str): What type of IOC, (IPv4, IPv6, FQDN, MD5, SHA1, SHA256, URL)
        rl_analyze_api_key (str): Reversing Labs Spectre Analyze API key.
        rl_analyze_url (str): Reversing Labs Spectre Analyze url.
        proxies (dict): Dictionary of proxies.
        ssl_verify (bool): Whether to verify SSL certificates.

    Returns:
        dict: A dictionary with number of cases with the indicator, and the case id links, for example:
            {
                "reports": 3,
                "links": ["https://rl_analyze_url/case/ioc?cid=3","https://rl_analyze_url/case/ioc?cid=4"]
            }
        None: If any error occurs.
    """

    endpoint = get_api_endpoint(observable, observable_type)

    try:
        url = f"{rl_analyze_url}{endpoint}"
        headers = {
            "Authorization": f"Token {rl_analyze_api_key}",
            "accept": "application/json",
        }

        response = requests.get(url, headers=headers, proxies=None, verify=ssl_verify, timeout=5)
        response.raise_for_status()

        data = response.json()
        return parse_rl_response(data, observable, observable_type, rl_analyze_url)

    except Exception as e:
        logger.error("Error querying Reversing Labs for '%s': %s", observable, e, exc_info=True)

    return None


def parse_rl_response(result: dict, observable: str, observable_type: str, url: str):
    top_threats: list[str] = []
    if observable_type in ["IPv4", "IPv6", "FQDN"]:
        top_threats.extend(result.get("top_threats"))
        malicious_files: int = result["downloaded_files_statistics"]["malicious"]
        malicious: int = result["third_party_reputations"]["statistics"]["malicious"]
        suspicious: int = result["third_party_reputations"]["statistics"]["suspicious"]
        total: int = result["third_party_reputations"]["statistics"]["total"]

        if observable_type in ["IPv4", "IPv6"]:
            link: str = url + get_ui_endpoint(result["requested_ip"], observable_type)
        elif observable_type in ["FQDN"]:
            link: str = url + get_ui_endpoint(result["requested_domain"], observable_type)
        elif observable_type in ["URL"]:
            link: str = url + get_ui_endpoint(result["requested_url"], observable_type)

        if total > 0:
            return {
                "reports": total,
                "malicious": malicious,
                "suspicious": suspicious,
                "files": malicious_files,
                "threats": top_threats,
                "link": link,
            }
    elif observable_type in ["URL"]:
        top_threats.append(result.get("threat_name"))
        top_threats.extend(result.get("categories"))
        malicious_files: int = 0
        malicious: int = result["third_party_reputations"]["statistics"]["malicious"]
        suspicious: int = result["third_party_reputations"]["statistics"]["suspicious"]
        total: int = result["third_party_reputations"]["statistics"]["total"]
        link: str = url + get_ui_endpoint(observable, observable_type)
        if total > 0:
            return {
                "reports": total,
                "malicious": malicious,
                "suspicious": suspicious,
                "files": malicious_files,
                "threats": top_threats,
                "link": link,
            }

    elif observable_type in ["MD5", "SHA1", "SHA256"]:
        top_threats.append(result.get("threat_status"))
        top_threats.append(result.get("threat_name"))
        if result.get("threat_status") == "KNOWN" and result.get("threat_level") == 0:
            malicious: int = 0
            suspicious: int = result.get("threat_level")
        elif (result.get("threat_status") == "SUSPICIOUS" and result.get("threat_level") > 0) or (
            result.get("threat_status") == "MALICIOUS" and result.get("threat_level") > 0
        ):
            malicious: int = result.get("threat_level")
            suspicious: int = result.get("threat_level")
        else:
            malicious: int = 0
            suspicious: int = 0

        if "av_scanners" in result:
            total: int = result["av_scanners"]["scanner_count"]
            link: str = url + get_ui_endpoint(observable, observable_type)

            return {
                "reports": total,
                "malicious": malicious,
                "suspicious": suspicious,
                "files": 0,
                "threats": top_threats,
                "link": link,
            }

    return {}
