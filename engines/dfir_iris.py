import logging
from typing import Any, Optional

from dfir_iris_client.case import Case
from dfir_iris_client.global_search import global_search_ioc
from dfir_iris_client.session import ClientSession

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


def query_dfir_iris(
    observable: str,
    proxies: dict[str, str],
    api_key: str,
    dfir_iris_url: str,
    ssl_verify: bool = True,
) -> Optional[dict[str, Any]]:
    """
    Queries the DFIR-IRIS API for information about a given observable (IP, domain, URL, or file hash).
    DFIR-IRIS search supports all observable types.

    Args:
        observable (str): The IoC to query (IPv4, IPv6, domain, URL, or file hash).
        api_key (str): DFIR_IRIS API key.
        proxies (dict): Dictionary of proxies.

    Returns:
        dict: A dictionary with "cases" (list), "count" (int).
        None: If an error occurs or API key is missing.
    """
    try:
        if not api_key:
            logger.error("DFIR IRIS API key is required")
            return None

        # Ensure the URL is properly formatted
        dfir_iris_url = dfir_iris_url.rstrip("/")

        session = ClientSession(apikey=api_key, host=dfir_iris_url, ssl_verify=ssl_verify)

        # Initialize the case instance with the session
        case = Case(session=session)

        # Fetch the case from its ID. Let's use the initial demo case and improve it
        if not case.case_id_exists(cid=1):
            # This should never happen, the server refuses to delete this case for consistency
            raise Exception("Case ID 1 not found !")

        # Attribute the cid to the case instance
        case.set_cid(cid=1)

        response = global_search_ioc(session, observable)
        data = response.as_json()
        status = data.get("status")
        if status == "success":
            case_data = data.get("data")
            case_findings = []

            for case in case_data:
                cid = case.get("case_id")
                link = f"{dfir_iris_url}/case?cid={cid}" if cid else None
                case_findings.append(link)

            unique_cases = list(set(case_findings))
            count = len(unique_cases)

        return {"cases": unique_cases, "count": count}

    except Exception as e:
        logger.error("Error querying Dfir_Iris for '%s': %s", observable, e, exc_info=True)

    return None
