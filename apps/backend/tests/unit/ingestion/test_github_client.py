"""Unit tests for GitHub GraphQL client"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from src.ingestion.github_client import (
    GitHubAPIError,
    GitHubRateLimitError,
    GitHubAuthError,
    GitHubGraphQLClient,
    RateLimitInfo,
    QueryCostInfo,
)


@pytest.fixture
def mock_httpx_client():
    mock_client = AsyncMock()
    mock_client.post = AsyncMock()
    mock_client.aclose = AsyncMock()
    mock_client.is_closed = True
    return mock_client


class TestGitHubExceptions:

    def test_api_error_preserves_status_code(self):
        error = GitHubAPIError("Server error", status_code=500)
        assert error.status_code == 500
        assert "Server error" in str(error)

    def test_rate_limit_error_captures_reset_timestamp(self):
        reset_ts = 1704067200
        error = GitHubRateLimitError(reset_at=reset_ts)
        assert error.reset_at == reset_ts
        assert error.status_code == 403

    def test_auth_error_defaults_to_401(self):
        error = GitHubAuthError()
        assert error.status_code == 401
        assert "authentication" in str(error).lower()


class TestGitHubClientInit:

    def test_empty_token_raises_value_error(self):
        with pytest.raises(ValueError, match="required"):
            GitHubGraphQLClient(token="")

    def test_valid_token_initializes_without_limiter(self):
        client = GitHubGraphQLClient(token="ghp_valid_token")
        assert client._token == "ghp_valid_token"
        assert client._limiter is None


class TestEnsureRateLimitFragment:

    @pytest.fixture
    def client(self):
        return GitHubGraphQLClient(token="test_token")

    def test_appends_fragment_when_missing(self, client):
        query = "query { viewer { login } }"
        result = client._ensure_rate_limit_fragment(query)
        assert "rateLimit" in result
        assert result.endswith("}")
        assert "cost" in result
        assert "remaining" in result

    def test_preserves_query_when_fragment_present(self, client):
        query = "query { viewer { login } rateLimit { cost } }"
        result = client._ensure_rate_limit_fragment(query)
        assert result == query

    def test_returns_unchanged_on_malformed_query(self, client):
        query = "query { viewer { login "
        result = client._ensure_rate_limit_fragment(query)
        assert result == query


class TestParseResetAt:

    @pytest.fixture
    def client(self):
        return GitHubGraphQLClient(token="test_token")

    def test_parses_iso_datetime_with_z_suffix(self, client):
        result = client._parse_reset_at("2024-01-01T12:00:00Z")
        assert result == 1704110400

    def test_parses_iso_datetime_with_offset(self, client):
        result = client._parse_reset_at("2024-01-01T12:00:00+00:00")
        assert result == 1704110400

    def test_returns_zero_for_empty_string(self, client):
        assert client._parse_reset_at("") == 0

    def test_returns_zero_for_malformed_datetime(self, client):
        assert client._parse_reset_at("not-a-date") == 0
        assert client._parse_reset_at("2024/01/01") == 0


class TestUpdateHeaderRateLimit:

    @pytest.fixture
    def client(self):
        return GitHubGraphQLClient(token="test_token")

    def test_extracts_all_header_fields(self, client):
        response = MagicMock()
        response.headers = {
            "x-ratelimit-remaining": "4500",
            "x-ratelimit-limit": "5000",
            "x-ratelimit-reset": "1704067200",
            "x-ratelimit-used": "500",
        }

        client._update_header_rate_limit(response)

        assert client._header_rate_limit is not None
        assert client._header_rate_limit.remaining == 4500
        assert client._header_rate_limit.limit == 5000
        assert client._header_rate_limit.reset_at == 1704067200
        assert client._header_rate_limit.used == 500

    def test_ignores_missing_headers(self, client):
        response = MagicMock()
        response.headers = {"x-ratelimit-remaining": "4500"}

        client._update_header_rate_limit(response)
        assert client._header_rate_limit is None

    def test_ignores_non_integer_headers(self, client):
        response = MagicMock()
        response.headers = {
            "x-ratelimit-remaining": "not_a_number",
            "x-ratelimit-limit": "5000",
            "x-ratelimit-reset": "1704067200",
            "x-ratelimit-used": "500",
        }

        client._update_header_rate_limit(response)
        assert client._header_rate_limit is None


class TestUpdateQueryCost:

    @pytest.fixture
    def client(self):
        return GitHubGraphQLClient(token="test_token")

    def test_parses_rate_limit_from_data(self, client):
        response = {
            "data": {
                "rateLimit": {
                    "cost": 1,
                    "remaining": 4999,
                    "limit": 5000,
                    "resetAt": "2024-01-01T12:00:00Z",
                    "nodeCount": 10,
                }
            }
        }

        client._update_query_cost(response)

        assert client._query_cost is not None
        assert client._query_cost.cost == 1
        assert client._query_cost.remaining == 4999
        assert client._query_cost.node_count == 10

    def test_parses_rate_limit_from_extensions(self, client):
        response = {
            "data": {},
            "extensions": {
                "rateLimit": {
                    "cost": 2,
                    "remaining": 4998,
                    "limit": 5000,
                    "resetAt": "2024-01-01T12:00:00Z",
                    "nodeCount": 5,
                }
            },
        }

        client._update_query_cost(response)

        assert client._query_cost is not None
        assert client._query_cost.cost == 2

    def test_handles_missing_rate_limit(self, client):
        response = {"data": {"viewer": {"login": "testuser"}}}

        client._update_query_cost(response)
        assert client._query_cost is None

    def test_handles_malformed_cost_values(self, client):
        response = {
            "data": {
                "rateLimit": {
                    "cost": "not_an_int",
                    "remaining": 4999,
                    "limit": 5000,
                    "resetAt": "2024-01-01T12:00:00Z",
                    "nodeCount": 10,
                }
            }
        }

        client._update_query_cost(response)
        assert client._query_cost is None


class TestExecuteQuery:

    @pytest.fixture
    def mock_response(self):
        response = MagicMock()
        response.status_code = 200
        response.headers = {}
        response.json.return_value = {
            "data": {
                "viewer": {"login": "testuser"},
                "rateLimit": {
                    "cost": 1,
                    "remaining": 4999,
                    "limit": 5000,
                    "resetAt": "2024-01-01T12:00:00Z",
                    "nodeCount": 1,
                },
            }
        }
        response.raise_for_status = MagicMock()
        return response

    async def test_raises_runtime_error_without_context_manager(self):
        client = GitHubGraphQLClient(token="test_token")
        with pytest.raises(RuntimeError, match="not initialized"):
            await client.execute_query("query { viewer { login } }")

    async def test_401_raises_auth_error(self, mock_httpx_client):
        client = GitHubGraphQLClient(token="test_token")
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.headers = {}
        mock_httpx_client.post.return_value = mock_response

        with patch("httpx.AsyncClient", return_value=mock_httpx_client):
            async with client:
                with pytest.raises(GitHubAuthError):
                    await client.execute_query("query { viewer { login } }")

    async def test_403_with_zero_remaining_raises_rate_limit_error(self, mock_httpx_client):
        client = GitHubGraphQLClient(token="test_token")
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.headers = {}
        mock_httpx_client.post.return_value = mock_response

        with patch("httpx.AsyncClient", return_value=mock_httpx_client):
            async with client:
                # Pre-set query cost with zero remaining
                client._query_cost = QueryCostInfo(
                    cost=1, remaining=0, limit=5000, reset_at=1704067200, node_count=1
                )

                with pytest.raises(GitHubRateLimitError) as exc:
                    await client.execute_query("query { viewer { login } }")
                assert exc.value.reset_at == 1704067200

    async def test_403_with_zero_header_remaining_raises_rate_limit_error(self, mock_httpx_client):
        client = GitHubGraphQLClient(token="test_token")
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.headers = {}
        mock_httpx_client.post.return_value = mock_response

        with patch("httpx.AsyncClient", return_value=mock_httpx_client):
            async with client:
                # Pre-set header rate limit with zero remaining
                client._header_rate_limit = RateLimitInfo(
                    remaining=0, limit=5000, reset_at=1704067200, used=5000
                )

                with pytest.raises(GitHubRateLimitError) as exc:
                    await client.execute_query("query { viewer { login } }")
                assert exc.value.reset_at == 1704067200

    async def test_403_without_quota_info_raises_generic_api_error(self, mock_httpx_client):
        client = GitHubGraphQLClient(token="test_token")
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.headers = {}
        mock_httpx_client.post.return_value = mock_response

        with patch("httpx.AsyncClient", return_value=mock_httpx_client):
            async with client:
                with pytest.raises(GitHubAPIError) as exc:
                    await client.execute_query("query { viewer { login } }")
                assert exc.value.status_code == 403

    async def test_5xx_retries_with_exponential_backoff(self, mock_httpx_client):
        client = GitHubGraphQLClient(token="test_token")
        mock_500 = MagicMock()
        mock_500.status_code = 500
        mock_500.headers = {}

        mock_200 = MagicMock()
        mock_200.status_code = 200
        mock_200.headers = {}
        mock_200.json.return_value = {"data": {"viewer": {"login": "test"}}}
        mock_200.raise_for_status = MagicMock()

        mock_httpx_client.post.side_effect = [mock_500, mock_500, mock_200]

        with patch("httpx.AsyncClient", return_value=mock_httpx_client):
            with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
                async with client:
                    result = await client.execute_query("query { viewer { login } }")

                    assert result == {"viewer": {"login": "test"}}
                    assert mock_sleep.call_count == 2
                    mock_sleep.assert_any_call(1.0)
                    mock_sleep.assert_any_call(2.0)

    async def test_graphql_errors_in_response_raise_api_error(self, mock_httpx_client, mock_response):
        client = GitHubGraphQLClient(token="test_token")
        mock_response.json.return_value = {
            "data": {},
            "errors": [{"message": "Field 'foo' not found"}],
        }
        mock_httpx_client.post.return_value = mock_response

        with patch("httpx.AsyncClient", return_value=mock_httpx_client):
            async with client:
                with pytest.raises(GitHubAPIError) as exc:
                    await client.execute_query("query { foo }")
                assert "Field 'foo' not found" in str(exc.value)

    async def test_timeout_retries_then_fails(self, mock_httpx_client):
        client = GitHubGraphQLClient(token="test_token")
        mock_httpx_client.post.side_effect = httpx.TimeoutException("Connection timed out")

        with patch("httpx.AsyncClient", return_value=mock_httpx_client):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                async with client:
                    with pytest.raises(GitHubAPIError) as exc:
                        await client.execute_query("query { viewer { login } }")
                    assert "timeout" in str(exc.value).lower()

    async def test_request_error_retries_then_fails(self, mock_httpx_client):
        client = GitHubGraphQLClient(token="test_token")
        mock_httpx_client.post.side_effect = httpx.RequestError("Connection refused")

        with patch("httpx.AsyncClient", return_value=mock_httpx_client):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                async with client:
                    with pytest.raises(GitHubAPIError) as exc:
                        await client.execute_query("query { viewer { login } }")
                    assert "failed" in str(exc.value).lower()

    async def test_max_retries_exceeded_raises_last_error(self, mock_httpx_client):
        client = GitHubGraphQLClient(token="test_token")
        mock_500 = MagicMock()
        mock_500.status_code = 503
        mock_500.headers = {}
        mock_httpx_client.post.return_value = mock_500

        with patch("httpx.AsyncClient", return_value=mock_httpx_client):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                async with client:
                    with pytest.raises(GitHubAPIError) as exc:
                        await client.execute_query("query { viewer { login } }")
                    assert exc.value.status_code == 503

    async def test_successful_query_returns_data(self, mock_httpx_client, mock_response):
        client = GitHubGraphQLClient(token="test_token")
        mock_httpx_client.post.return_value = mock_response

        with patch("httpx.AsyncClient", return_value=mock_httpx_client):
            async with client:
                result = await client.execute_query("query { viewer { login } }")

                assert result["viewer"]["login"] == "testuser"
                assert client._query_cost is not None
                assert client._query_cost.cost == 1

    async def test_limiter_wait_called_before_request(self, mock_httpx_client, mock_response):
        mock_limiter = AsyncMock()
        mock_limiter.wait_until_affordable = AsyncMock()
        mock_limiter.set_remaining_from_response = AsyncMock()

        client = GitHubGraphQLClient(token="test_token", limiter=mock_limiter)
        mock_httpx_client.post.return_value = mock_response

        with patch("httpx.AsyncClient", return_value=mock_httpx_client):
            async with client:
                await client.execute_query(
                    "query { viewer { login } }", estimated_cost=5
                )

                mock_limiter.wait_until_affordable.assert_called_once_with(5)

    async def test_limiter_updated_after_response(self, mock_httpx_client, mock_response):
        mock_limiter = AsyncMock()
        mock_limiter.wait_until_affordable = AsyncMock()
        mock_limiter.set_remaining_from_response = AsyncMock()

        client = GitHubGraphQLClient(token="test_token", limiter=mock_limiter)
        mock_httpx_client.post.return_value = mock_response

        with patch("httpx.AsyncClient", return_value=mock_httpx_client):
            async with client:
                await client.execute_query("query { viewer { login } }")

                mock_limiter.set_remaining_from_response.assert_called_once()
                call_args = mock_limiter.set_remaining_from_response.call_args[0]
                assert call_args[0] == 4999  # remaining


class TestExecuteQueryWithCost:

    async def test_returns_data_and_cost_tuple(self, mock_httpx_client):
        client = GitHubGraphQLClient(token="test_token")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.json.return_value = {
            "data": {
                "viewer": {"login": "testuser"},
                "rateLimit": {
                    "cost": 1,
                    "remaining": 4999,
                    "limit": 5000,
                    "resetAt": "2024-01-01T12:00:00Z",
                    "nodeCount": 1,
                },
            }
        }
        mock_response.raise_for_status = MagicMock()
        mock_httpx_client.post.return_value = mock_response

        with patch("httpx.AsyncClient", return_value=mock_httpx_client):
            async with client:
                data, cost_info = await client.execute_query_with_cost(
                    "query { viewer { login } }"
                )

                assert data["viewer"]["login"] == "testuser"
                assert cost_info is not None
                assert cost_info.cost == 1

    async def test_cost_is_none_when_not_present(self, mock_httpx_client):
        client = GitHubGraphQLClient(token="test_token")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.json.return_value = {"data": {"viewer": {"login": "testuser"}}}
        mock_response.raise_for_status = MagicMock()
        mock_httpx_client.post.return_value = mock_response

        with patch("httpx.AsyncClient", return_value=mock_httpx_client):
            async with client:
                data, cost_info = await client.execute_query_with_cost(
                    "query { viewer { login } }"
                )

                assert data["viewer"]["login"] == "testuser"
                assert cost_info is None


class TestRateLimitGetters:

    def test_get_remaining_prefers_query_cost_over_headers(self):
        client = GitHubGraphQLClient(token="test_token")
        client._query_cost = QueryCostInfo(
            cost=1, remaining=4000, limit=5000, reset_at=0, node_count=1
        )
        client._header_rate_limit = RateLimitInfo(
            remaining=4500, limit=5000, reset_at=0, used=500
        )

        assert client.get_rate_limit_remaining() == 4000

    def test_get_remaining_falls_back_to_headers(self):
        client = GitHubGraphQLClient(token="test_token")
        client._header_rate_limit = RateLimitInfo(
            remaining=4500, limit=5000, reset_at=0, used=500
        )

        assert client.get_rate_limit_remaining() == 4500

    def test_get_remaining_returns_none_initially(self):
        client = GitHubGraphQLClient(token="test_token")
        assert client.get_rate_limit_remaining() is None

    def test_get_last_query_cost_returns_cost(self):
        client = GitHubGraphQLClient(token="test_token")
        client._query_cost = QueryCostInfo(
            cost=5, remaining=4995, limit=5000, reset_at=0, node_count=10
        )

        assert client.get_last_query_cost() == 5

    def test_get_last_query_cost_returns_none_initially(self):
        client = GitHubGraphQLClient(token="test_token")
        assert client.get_last_query_cost() is None

    def test_get_query_cost_info_returns_full_info(self):
        client = GitHubGraphQLClient(token="test_token")
        cost_info = QueryCostInfo(
            cost=5, remaining=4995, limit=5000, reset_at=1704067200, node_count=10
        )
        client._query_cost = cost_info

        assert client.get_query_cost_info() == cost_info

    def test_get_header_rate_limit_info_returns_info(self):
        client = GitHubGraphQLClient(token="test_token")
        header_info = RateLimitInfo(remaining=4500, limit=5000, reset_at=0, used=500)
        client._header_rate_limit = header_info

        assert client.get_header_rate_limit_info() == header_info


class TestContextManager:

    async def test_aenter_creates_httpx_client(self, mock_httpx_client):
        client = GitHubGraphQLClient(token="test_token")
        assert client._client is None

        with patch("httpx.AsyncClient", return_value=mock_httpx_client):
            async with client:
                assert client._client is not None

    async def test_aexit_closes_client(self, mock_httpx_client):
        client = GitHubGraphQLClient(token="test_token")

        with patch("httpx.AsyncClient", return_value=mock_httpx_client):
            async with client:
                pass

        assert client._client is None
        mock_httpx_client.aclose.assert_called_once()

    async def test_aexit_handles_already_none_client(self, mock_httpx_client):
        client = GitHubGraphQLClient(token="test_token")

        with patch("httpx.AsyncClient", return_value=mock_httpx_client):
            async with client:
                client._client = None

        assert client._client is None

