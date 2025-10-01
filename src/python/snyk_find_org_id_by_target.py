

import logging
import os
import sys
import time
from argparse import ArgumentParser
from typing import Any, NamedTuple, TypeAlias
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ORG FINDER")

API_VERSION = "2024-10-15"

DEFAULT_GROUP = ""
DEFAULT_ORG = ""
DEFAULT_WORKERS = 4

SNYK_TOKEN_POOL = os.getenv("SNYK_TOKEN_POOL") or os.getenv("SNYK_TOKEN")
if SNYK_TOKEN_POOL is not None:
    TOKEN_LIST = SNYK_TOKEN_POOL.split(",")
    logger.info("Token pool has %s tokens", len(TOKEN_LIST))
else:
    logger.error("Could not find Snyk API tokens in the environment")
    sys.exit(1)

Asset: TypeAlias = dict(str, Any)


class Organization:
    """DataClass for Org"""
    def __init__(self, org_data: dict[str, Any]):
        self.id: str= org_data["id"]
        self.name: str = org_data["attributes"]["name"]

class SnykTokenManager: 
    """Maintains and auto-rotates through a list of Snyk tokens each time a client is created."""


    def __init__(self, tokens: list[str] = TOKEN_LIST, tries=5):
        """Args:
        tokens: The Snyk tokens to use.
        tries: The number of tries the clients should make before failing.
        """
        self.tokens = tokens
        self.tries = tries
        self.idx = 0

    def next_token(self) -> str:
        """Gets the current token, then cycles."""
        token = self.tokens[self.idx % len(self.tokens)]
        self.idx += 1
        return token



class _Arguments(NamedTuple):
    """Command line argument values"""

    group_id: str
    target_name: str
    allow_fallback: bool


def _parse_args() -> _Arguments:
    """Parse command line arguments"""
    parser = ArgumentParser(description="Identify assets in Snyk Group.")
    parser.add_argument("target_name", help="Target (repo) to filter by.")
    parser.add_argument(
        "--group-id",
        "-g",
        help="ID of the Snyk group to query (currently unused).",
        default=DEFAULT_GROUP,
        )
        parser.add_argument(
            "--allow-fallback",
            "-f",
            action="store_true",
            help="Fallback to the default org if the target is not found in Snyk.",
        )

        args = parser.parse_args()
        arguments = _Arguments(**vars(args))

        logger.debug("Arguments: %s", arguments)
        return arguments


# This function is also in DEOS tools, but Im including it here so this script
# can be used completely standalone
def _build_repo_url(repo_name: str, fallback_org="vasukotha2") -> str:
    """Given a repo name, build the GitHub URL for it.Intelligently determines 
    whether it needs to supply an org. If repo is already a URL, returns it
    without validation."""
    if repo_name.startswith("https://"):
        return repo_name.replace("https://www.","https://")
    
    if "/" not in repo_name:
        repo_name = fallback_org + "/" + repo_name
    return f"https://github.com/{repo_name}"


def add_url_params(url: str, params: dict[str, Any]) -> str:
    """Add parameters to a URL. If the parameter already exists, overwrite it."""
    url_parts = list(urlparse(url))

    # Extract existing query parameters and update with new ones
    query = dict(parse_qs(url_parts[4]))
    query.update(params)

    # Re-encode the query parameters
    url_parts[4] = urlencode(query, doseq=True)

    #Reconstruct the full URL
    return urlunparse(url_parts)


def fetch_repo_data(repo: str, group_id: str, client_manager: SnykTokenManager, max_attempts=5) -> list[Asset]:
    """Fetch data from the assets API."""
    query = {
        "query": {
            "attributes": {
                "operator": "and",
                "values": [
                    {"attribute": "type", "operator": "equal", "values": ["repository"]},
                    {"attribute": "repository_url", "operator": "equal", "values": [_build_repo_url(repo)]},
                ],
            }
        }    
    }
    url = f"https://api.snyk.io/rest/groups/{group_id}/assets/search"
    backoff=2
    attempt=1

    while True:
        headers = {"Accept": "application/json", "Authorization": client_manager.next_token()}
        r = requests.post(url, headers=headers, params={"version": "2024-10-15"}, json=query, timeout=60)
        if r.status_code == 429:
            if attempt >=max_attempts:
                raise ValueError("Rate-limited. Max retries exceeded.")

                logging.warning("Rate-limited. Retrying in %s seconds.", backoff)
                time.sleep(backoff)
                backoff *= 2
                attempt += 1
            else:
                break

    r.raise_for_status()
    data = r.json()

    return data["data"]


def get(client_manager: SnykTokenManager, url: str, *args, max_attempts=5, **kwargs) -> requests.Response:
    """Perform a GET request on the Snyk API, backing off if rate-limited."""
    params = kwargs.pop("params", {})
    if "?" not in url:
        if "version" not in params:
            params["version"] = API_VERSION
        if "limit" not in params:
            params["limit"] = 100
    else:
        params = None
    
    backoff = 2
    attempt = 1
    while True:
        headers = {"Accept": "application/json", "Authorization": client_manager.next_token()}
        r = requests.get(url, headers=headers, params=params, timeout=60, *args, **kwargs)
        if r.status_code == 429:
            if attempt == max_attempts:
                raise ValueError("Rate-limited. Max attempts exceeded.")
            
            logging.warning("Rate-limited. Retrying in %s", backoff)
            time.sleep(backoff)
            backoff *= 2
            attempt += 1
        else:
            return r


def get_data(client_manager: SnykTokenManager, url: str, *args, **kwargs) -> list[dict[str, Any]]:
    """Get paginated data."""
    results = []
    while url:
        r = get(client_manager, url, *args, **kwargs)
        data = r.json()
        if not "data" in data:
            logging.error(data)
        results.extend(data.get("data", []))

        links = data.get("links", {})
        url = links.get("next")
        if url and not url.startswith("https://"):
            url = "https://api.snyk.io" + url
    
    return results


def fetch_organizations(repo: str, group_id: str, client_manager: SnykTokenManager) -> list[Organization] | None:
    """A more specialized version of fetch_organizations() that only returns orgs
    where the repo has an SCM integration. This is necessary due to the assets
    API returning orgs where CI targets are present."""
    assets = fetch_repo_data(repo, group_id, client_manager)
    if not assets:
        return None
    if len(assets) > 1:
        raise ValueError(f"{len(assets)} matches found. Please narrow your search.")

    repo_asset = assets[0]
    repo_orgs = [Organization(o) for o in repo_asset["relationships"].get("organization", {}).get("data", [])]


    if not repo_orgs:
        return []
    
    # The will give us multiple orgs if the project has an SCM integration in one
    # org and a monitor target in another. We need to fetch the related projects
    # and filter out those with a "test_surface" of "cli"
    project_link = repo_asset["relationships"]["projects"]["links"]["related"]
    url = f"https://api.snyk.io{project_link}"
    url = add_url_params(url, {"limit": 100})
    related_projects = get_data(client_manager, url)

    scm_org_ids = {
        p["attributes"]["organization_id"] for p in related_projects if p["attributes"]["test_surface"] != "cli"
    }
    scm_orgs = [o for o in repo_orgs if o.id in scm_org_ids]

    return scm_orgs


def get_best_org(orgs: list[Organization]) -> Organization:
    """Selects the "best" org from a list.
    Returns: The first org without "unassigned" in its name, or the first org.
    Raises: ValueError if the lsit is empty."""
    if not orgs:
        raise ValueError("orgs cannot be empty.")
    try:
        org = next(o for o in orgs if "unassigned" not in o.name.lower() and "default" not in o.name.lower())
        return org
    except StopIteration:
        return orgs[0]


def main():
    """Fetch and print the Snyk org ID for the target."""
    args = _parse_args()
    client_man = SnykTokenManager()
    found = fetch_organizations(args.target_name, args.group_id, client_man)
    if not found:
        logger.error("REPO NOT FOUND: %s", args.target_name)
        if not args.allow_fallback:
            sys.exit(1)
        logger.info("Using default org.")
        print(DEFAULT_ORG)
        sys.exit(0)
    
    if len(found) > 1:
        logger.warning("%s orgs found.", len(found))
        if not args.allow_fallback:
            sys.exit(1)
        
    for org in found:
        logger.info(org.name)
    
    selected = get_best_org(found)
    print(selected.id)



    
