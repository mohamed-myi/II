"""GitHub GraphQL API client with cost aware rate limiting"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from .rate_limiter import CostAwareLimiter

logger = logging.getLogger(__name__)

GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"


class GitHubAPIError(Exception):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class GitHubRateLimitError(GitHubAPIError):
    def __init__(self, reset_at: int | None = None):
        super().__init__("GitHub API rate limit exceeded", status_code=403)
        self.reset_at = reset_at


class GitHubAuthError(GitHubAPIError):
    def __init__(self):
        super().__init__("GitHub authentication failed", status_code=401)


@dataclass
class RateLimitInfo:
    remaining: int
    limit: int
    reset_at: int
    used: int


@dataclass
class QueryCostInfo:
    cost: int
    remaining: int
    limit: int
    reset_at: int
    node_count: int


class GitHubGraphQLClient:
    """Accepts optional CostAwareLimiter to coordinate quota usage across instances"""

    MAX_RETRIES: int = 3
    RETRY_DELAY_SECONDS: float = 1.0
    TIMEOUT_SECONDS: float = 30.0

    RATE_LIMIT_FRAGMENT: str = """
        rateLimit {
            cost
            remaining
            limit
            resetAt
            nodeCount
        }
    """

    def __init__(self, token: str, limiter: CostAwareLimiter | None = None):
        if not token:
            raise ValueError("GitHub token is required")

        self._token = token
        self._limiter = limiter
        self._header_rate_limit: RateLimitInfo | None = None
        self._query_cost: QueryCostInfo | None = None
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> GitHubGraphQLClient:
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.TIMEOUT_SECONDS),
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
            },
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    def _ensure_rate_limit_fragment(self, query: str) -> str:
        """Auto injects rateLimit fragment for cost tracking if caller omits it"""
        if "rateLimit" in query:
            return query
        
        # Find the last '}' and insert rateLimit before it
        last_brace = query.rfind("}")
        if last_brace == -1:
            return query  # Malformed query, let GitHub return the error
        
        return query[:last_brace] + self.RATE_LIMIT_FRAGMENT + query[last_brace:]

    async def execute_query(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
        estimated_cost: int = 1,
    ) -> dict[str, Any]:
        """Retries on transient failures; waits for quota if limiter is present"""
        if not self._client:
            raise RuntimeError("Client not initialized; use async context manager")

        query = self._ensure_rate_limit_fragment(query)

        if self._limiter:
            await self._limiter.wait_until_affordable(estimated_cost)

        payload = {"query": query}
        if variables:
            payload["variables"] = variables

        last_error: Exception | None = None

        for attempt in range(self.MAX_RETRIES):
            try:
                response = await self._client.post(GITHUB_GRAPHQL_URL, json=payload)
                self._update_header_rate_limit(response)

                if response.status_code == 401:
                    raise GitHubAuthError()

                if response.status_code == 403:
                    if self._query_cost and self._query_cost.remaining == 0:
                        raise GitHubRateLimitError(reset_at=self._query_cost.reset_at)
                    if self._header_rate_limit and self._header_rate_limit.remaining == 0:
                        raise GitHubRateLimitError(reset_at=self._header_rate_limit.reset_at)
                    raise GitHubAPIError("Forbidden", status_code=403)

                if response.status_code >= 500:
                    last_error = GitHubAPIError(
                        f"Server error: {response.status_code}",
                        status_code=response.status_code,
                    )
                    await asyncio.sleep(self.RETRY_DELAY_SECONDS * (attempt + 1))
                    continue

                response.raise_for_status()
                full_response = response.json()

                self._update_query_cost(full_response)

                if self._limiter and self._query_cost:
                    await self._limiter.set_remaining_from_response(
                        self._query_cost.remaining,
                        self._query_cost.reset_at,
                    )

                if "errors" in full_response:
                    error_messages = [e.get("message", "Unknown") for e in full_response["errors"]]
                    raise GitHubAPIError(f"GraphQL errors: {'; '.join(error_messages)}")

                return full_response.get("data", {})

            except httpx.TimeoutException as e:
                last_error = GitHubAPIError(f"Request timeout: {e}")
                await asyncio.sleep(self.RETRY_DELAY_SECONDS * (attempt + 1))
            except httpx.RequestError as e:
                last_error = GitHubAPIError(f"Request failed: {e}")
                await asyncio.sleep(self.RETRY_DELAY_SECONDS * (attempt + 1))

        raise last_error or GitHubAPIError("Max retries exceeded")

    async def execute_query_with_cost(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
        estimated_cost: int = 1,
    ) -> tuple[dict[str, Any], QueryCostInfo | None]:
        data = await self.execute_query(query, variables, estimated_cost)
        return data, self._query_cost

    def _update_header_rate_limit(self, response: httpx.Response) -> None:
        try:
            remaining = response.headers.get("x-ratelimit-remaining")
            limit = response.headers.get("x-ratelimit-limit")
            reset_at = response.headers.get("x-ratelimit-reset")
            used = response.headers.get("x-ratelimit-used")

            if all([remaining, limit, reset_at, used]):
                self._header_rate_limit = RateLimitInfo(
                    remaining=int(remaining),
                    limit=int(limit),
                    reset_at=int(reset_at),
                    used=int(used),
                )
        except (ValueError, TypeError):
            pass

    def _update_query_cost(self, response: dict[str, Any]) -> None:
        """Checks data,rateLimit then falls back to extensions,rateLimit"""
        try:
            data = response.get("data", {})
            rate_limit = data.get("rateLimit") or response.get("extensions", {}).get("rateLimit")

            if not rate_limit:
                return

            reset_at = self._parse_reset_at(rate_limit.get("resetAt", ""))

            self._query_cost = QueryCostInfo(
                cost=int(rate_limit.get("cost", 0)),
                remaining=int(rate_limit.get("remaining", 5000)),
                limit=int(rate_limit.get("limit", 5000)),
                reset_at=reset_at,
                node_count=int(rate_limit.get("nodeCount", 0)),
            )

            logger.debug(
                f"Query cost: {self._query_cost.cost} points, "
                f"{self._query_cost.remaining}/{self._query_cost.limit} remaining"
            )
        except (ValueError, TypeError, KeyError) as e:
            logger.warning(f"Failed to parse query cost: {e}")

    def _parse_reset_at(self, reset_at_str: str) -> int:
        if not reset_at_str:
            return 0
        try:
            dt = datetime.fromisoformat(reset_at_str.replace("Z", "+00:00"))
            return int(dt.timestamp())
        except (ValueError, AttributeError, TypeError):
            logger.warning(f"Unexpected resetAt format: {reset_at_str!r}")
            return 0

    def get_rate_limit_remaining(self) -> int | None:
        """Prefers query cost over header based remaining"""
        if self._query_cost:
            return self._query_cost.remaining
        if self._header_rate_limit:
            return self._header_rate_limit.remaining
        return None

    def get_last_query_cost(self) -> int | None:
        return self._query_cost.cost if self._query_cost else None

    def get_query_cost_info(self) -> QueryCostInfo | None:
        return self._query_cost

    def get_header_rate_limit_info(self) -> RateLimitInfo | None:
        return self._header_rate_limit

    async def verify_authentication(self) -> str:
        query = """
            query {
                viewer { login }
            }
        """
        data = await self.execute_query(query)
        return data.get("viewer", {}).get("login", "")
