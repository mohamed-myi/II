"""Integration tests for GitHubGraphQLClient against live API"""

import os
import time
import pytest

from src.ingestion.github_client import (
    GitHubGraphQLClient,
    GitHubAuthError,
)
from src.ingestion.rate_limiter import InMemoryCostLimiter


pytestmark = pytest.mark.skipif(
    not os.getenv("GIT_TOKEN"),
    reason="GIT_TOKEN environment variable not set"
)


class TestLiveGitHubAuthentication:

    @pytest.fixture
    def token(self):
        return os.getenv("GIT_TOKEN")

    @pytest.mark.asyncio
    async def test_verify_authentication_returns_username(self, token):
        async with GitHubGraphQLClient(token) as client:
            username = await client.verify_authentication()

            assert username != ""
            assert len(username) > 0
            print(f"Authenticated as: {username}")

    @pytest.mark.asyncio
    async def test_invalid_token_raises_auth_error(self):
        async with GitHubGraphQLClient("ghp_invalidtoken123456789") as client:
            with pytest.raises(GitHubAuthError):
                await client.verify_authentication()


class TestLiveCostTracking:

    @pytest.fixture
    def token(self):
        return os.getenv("GIT_TOKEN")

    @pytest.mark.asyncio
    async def test_simple_query_has_cost_of_1(self, token):
        async with GitHubGraphQLClient(token) as client:
            query = """
                query {
                    viewer { login }
                    rateLimit { cost remaining limit resetAt nodeCount }
                }
            """
            data, cost_info = await client.execute_query_with_cost(query)

            assert cost_info is not None, "Expected cost_info to be populated"
            assert cost_info.cost == 1, f"Expected simple query cost to be 1, got {cost_info.cost}"
            assert cost_info.remaining > 0, f"Expected remaining > 0, got {cost_info.remaining}"
            assert cost_info.limit > 0, f"Expected limit to be a positive integer, got {cost_info.limit}"
            current_time = time.time()
            assert cost_info.reset_at > current_time, (
                f"Expected reset_at ({cost_info.reset_at}) to be in the future (current: {current_time})"
            )
            print(f"Cost: {cost_info.cost}, Remaining: {cost_info.remaining}")

    @pytest.mark.asyncio
    async def test_complex_query_tracks_resource_usage(self, token):
        async with GitHubGraphQLClient(token) as client:
            query = """
                query {
                    search(query: "language:python stars:>10000", type: REPOSITORY, first: 10) {
                        nodes {
                            ... on Repository {
                                name
                                issues(first: 20) {
                                    totalCount
                                }
                            }
                        }
                    }
                    rateLimit { cost remaining limit resetAt nodeCount }
                }
            """
            data, cost_info = await client.execute_query_with_cost(query)

            assert cost_info is not None
            
            assert cost_info.node_count > 10, (
                f"Expected nested query to visit many nodes, got {cost_info.node_count}"
            )

            assert cost_info.cost >= 1
            
            assert cost_info.remaining < cost_info.limit
            assert cost_info.reset_at is not None

    @pytest.mark.asyncio
    async def test_remaining_decreases_after_query(self, token):
        async with GitHubGraphQLClient(token) as client:
            query = """
                query { viewer { login } rateLimit { cost remaining limit resetAt nodeCount } }
            """

            _, cost_info_1 = await client.execute_query_with_cost(query)
            remaining_after_first = cost_info_1.remaining

            _, cost_info_2 = await client.execute_query_with_cost(query)
            remaining_after_second = cost_info_2.remaining

            # Use <= to handle external token noise
            expected_max_remaining = remaining_after_first - cost_info_2.cost
            assert remaining_after_second <= expected_max_remaining, (
                f"Expected remaining {remaining_after_second} to be <= {expected_max_remaining} "
                f"(first: {remaining_after_first}, cost: {cost_info_2.cost})"
            )


class TestLiveCostLimiterIntegration:

    @pytest.fixture
    def token(self):
        return os.getenv("GIT_TOKEN")

    @pytest.mark.asyncio
    async def test_limiter_syncs_with_api_response(self, token):
        limiter = InMemoryCostLimiter()

        async with GitHubGraphQLClient(token) as client:
            query = """
                query { viewer { login } rateLimit { cost remaining limit resetAt nodeCount } }
            """
            _, cost_info = await client.execute_query_with_cost(query)

            await limiter.set_remaining_from_response(
                remaining=cost_info.remaining,
                reset_at=cost_info.reset_at
            )

            assert await limiter.get_remaining_points() == cost_info.remaining

    @pytest.mark.asyncio
    async def test_limiter_tracks_costs_accurately(self, token):
        limiter = InMemoryCostLimiter()

        async with GitHubGraphQLClient(token) as client:
            query = """
                query { viewer { login } rateLimit { cost remaining limit resetAt nodeCount } }
            """

            _, cost_info = await client.execute_query_with_cost(query)
            await limiter.record_cost(cost_info.cost)

            assert limiter.get_total_cost_recorded() == cost_info.cost


class TestLiveRateLimitInfo:

    @pytest.fixture
    def token(self):
        return os.getenv("GIT_TOKEN")

    @pytest.mark.asyncio
    async def test_rate_limit_remaining_updates(self, token):
        async with GitHubGraphQLClient(token) as client:
            assert client.get_rate_limit_remaining() is None

            await client.verify_authentication()

            remaining = client.get_rate_limit_remaining()
            assert remaining is not None
            assert remaining > 0, f"Expected remaining > 0, got {remaining}"

    @pytest.mark.asyncio
    async def test_query_cost_info_populated(self, token):
        async with GitHubGraphQLClient(token) as client:
            await client.verify_authentication()

            cost_info = client.get_query_cost_info()
            assert cost_info is not None, "Expected cost_info to be populated after authentication"
            assert cost_info.cost >= 1, f"Expected cost >= 1, got {cost_info.cost}"
            assert cost_info.limit > 0, f"Expected limit to be a positive integer, got {cost_info.limit}"
            current_time = time.time()
            assert cost_info.reset_at > current_time, (
                f"Expected reset_at ({cost_info.reset_at}) to be in the future (current: {current_time})"
            )
