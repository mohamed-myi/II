"""
Service for fetching and processing GitHub profile data for recommendations.
Extracts languages, topics, and repo descriptions from starred and contributed repos.

For async processing via Cloud Tasks:
  - initiate_github_fetch() validates connection and enqueues task; returns immediately
  - execute_github_fetch() does the actual fetching and embedding (called by worker)
  - fetch_github_profile() is the synchronous version for testing or fallback
"""
import logging
from collections import Counter
from datetime import datetime, timezone, timedelta
from uuid import UUID

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from models.profiles import UserProfile
from src.ingestion.github_client import (
    GitHubGraphQLClient,
    GitHubAPIError,
    GitHubAuthError,
    GitHubRateLimitError,
)
from src.services.linked_account_service import (
    get_valid_access_token,
    LinkedAccountNotFoundError,
    LinkedAccountRevokedError,
)
from src.services.profile_embedding_service import calculate_combined_vector
from src.services.vector_generation import generate_github_vector_with_retry
from src.services.onboarding_service import mark_onboarding_in_progress
from src.services.cloud_tasks_service import enqueue_github_task

logger = logging.getLogger(__name__)


from src.core.errors import GitHubNotConnectedError, RefreshRateLimitError


REFRESH_COOLDOWN_SECONDS = 3600  # 1 hour


STARRED_REPOS_QUERY = """
query StarredRepos($login: String!, $first: Int!, $after: String) {
  user(login: $login) {
    starredRepositories(first: $first, after: $after) {
      totalCount
      nodes {
        name
        primaryLanguage { name }
        languages(first: 10) { nodes { name } }
        repositoryTopics(first: 10) { nodes { topic { name } } }
        description
      }
      pageInfo { hasNextPage endCursor }
    }
  }
}
"""

CONTRIBUTED_REPOS_QUERY = """
query ContributedRepos($login: String!, $first: Int!) {
  user(login: $login) {
    repositoriesContributedTo(first: $first, contributionTypes: [COMMIT]) {
      totalCount
      nodes {
        name
        primaryLanguage { name }
        languages(first: 10) { nodes { name } }
        repositoryTopics(first: 10) { nodes { topic { name } } }
        description
      }
    }
  }
}
"""


async def _get_or_create_profile(
    db: AsyncSession,
    user_id: UUID,
) -> UserProfile:
    """Local version to avoid circular import with profile_service."""
    statement = select(UserProfile).where(UserProfile.user_id == user_id)
    result = await db.exec(statement)
    profile = result.first()
    
    if profile is not None:
        return profile
    
    profile = UserProfile(
        user_id=user_id,
        min_heat_threshold=0.6,
        is_calculating=False,
        onboarding_status="not_started",
    )
    
    db.add(profile)
    await db.commit()
    await db.refresh(profile)
    return profile


async def _fetch_starred_repos(
    client: GitHubGraphQLClient,
    username: str,
    max_repos: int = 100,
) -> tuple[int, list[dict]]:
    """Fetches starred repos with pagination; returns (total_count, repos)."""
    repos = []
    cursor = None
    page_size = min(50, max_repos)
    
    while len(repos) < max_repos:
        variables = {
            "login": username,
            "first": page_size,
            "after": cursor,
        }
        
        data = await client.execute_query(
            STARRED_REPOS_QUERY,
            variables=variables,
            estimated_cost=1,
        )
        
        user_data = data.get("user")
        if not user_data:
            break
            
        starred = user_data.get("starredRepositories", {})
        total_count = starred.get("totalCount", 0)
        nodes = starred.get("nodes", [])
        
        repos.extend(nodes)
        
        page_info = starred.get("pageInfo", {})
        if not page_info.get("hasNextPage"):
            break
        cursor = page_info.get("endCursor")
    
    return (
        data.get("user", {}).get("starredRepositories", {}).get("totalCount", len(repos)),
        repos[:max_repos]
    )


async def _fetch_contributed_repos(
    client: GitHubGraphQLClient,
    username: str,
    max_repos: int = 50,
) -> tuple[int, list[dict]]:
    """Fetches repos where user has commits; returns (total_count, repos)."""
    variables = {
        "login": username,
        "first": min(50, max_repos),
    }
    
    data = await client.execute_query(
        CONTRIBUTED_REPOS_QUERY,
        variables=variables,
        estimated_cost=1,
    )
    
    user_data = data.get("user")
    if not user_data:
        return 0, []
    
    contributed = user_data.get("repositoriesContributedTo", {})
    total_count = contributed.get("totalCount", 0)
    nodes = contributed.get("nodes", [])
    
    return total_count, nodes[:max_repos]


def _extract_languages_from_repos(repos: list[dict]) -> list[str]:
    """Extracts all languages from repo nodes."""
    languages = []
    for repo in repos:
        if not repo:
            continue
        primary = repo.get("primaryLanguage")
        if primary and primary.get("name"):
            languages.append(primary["name"])
        
        languages_data = repo.get("languages")
        if languages_data is None:
            continue
        lang_nodes = languages_data.get("nodes") or []
        for lang in lang_nodes:
            if lang and lang.get("name"):
                languages.append(lang["name"])
    
    return languages


def _extract_topics_from_repos(repos: list[dict]) -> list[str]:
    """Extracts all topics from repo nodes."""
    topics = []
    for repo in repos:
        if not repo:
            continue
        topics_data = repo.get("repositoryTopics")
        if topics_data is None:
            continue
        topic_nodes = topics_data.get("nodes") or []
        for topic_node in topic_nodes:
            if not topic_node:
                continue
            topic = topic_node.get("topic")
            if topic and topic.get("name"):
                topics.append(topic["name"])
    
    return topics


def _extract_descriptions_from_repos(repos: list[dict], max_count: int = 5) -> list[str]:
    """Extracts non-empty descriptions from repos."""
    descriptions = []
    for repo in repos:
        if not repo:
            continue
        desc = repo.get("description")
        if desc and desc.strip():
            descriptions.append(desc.strip())
            if len(descriptions) >= max_count:
                break
    return descriptions


def extract_languages(
    starred_repos: list[dict],
    contributed_repos: list[dict],
) -> list[str]:
    """
    Merges languages from starred and contributed repos.
    Contributed repos are weighted 2x to reflect active engagement.
    Returns deduplicated list sorted by frequency.
    """
    counter: Counter = Counter()
    
    starred_langs = _extract_languages_from_repos(starred_repos)
    for lang in starred_langs:
        counter[lang] += 1
    
    contributed_langs = _extract_languages_from_repos(contributed_repos)
    for lang in contributed_langs:
        counter[lang] += 2  
    
    sorted_langs = sorted(counter.keys(), key=lambda x: (-counter[x], x))
    return sorted_langs


def extract_topics(
    starred_repos: list[dict],
    contributed_repos: list[dict],
) -> list[str]:
    """
    Merges topics from starred and contributed repos.
    Returns deduplicated list sorted by frequency.
    """
    counter: Counter = Counter()
    
    starred_topics = _extract_topics_from_repos(starred_repos)
    for topic in starred_topics:
        counter[topic] += 1
    
    contributed_topics = _extract_topics_from_repos(contributed_repos)
    for topic in contributed_topics:
        counter[topic] += 2  # 2x weight
    
    sorted_topics = sorted(counter.keys(), key=lambda x: (-counter[x], x))
    return sorted_topics


def format_github_text(
    languages: list[str],
    topics: list[str],
    descriptions: list[str],
) -> str:
    """
    Formats GitHub data into text for embedding.
    Format: "{languages}. {topics}. {descriptions}"
    """
    parts = []
    
    if languages:
        parts.append(", ".join(languages[:10]))
    
    if topics:
        parts.append(", ".join(topics[:15]))
    
    if descriptions:
        parts.append(" ".join(descriptions[:5]))
    
    return ". ".join(parts)


def check_minimal_data(
    starred_count: int,
    contributed_count: int,
) -> str | None:
    """
    Returns warning message if data is below threshold per PROFILE.md lines 229 to 236.
    Threshold: fewer than 3 public repos AND fewer than 5 starred repos.
    """
    if contributed_count < 3 and starred_count < 5:
        return (
            "We found limited public activity on your GitHub profile. "
            "For better recommendations, consider adding manual input."
        )
    return None


def check_refresh_allowed(
    last_fetched_at: datetime | None,
) -> int | None:
    """
    Returns None if refresh is allowed; seconds remaining otherwise.
    """
    if last_fetched_at is None:
        return None
    
    now = datetime.now(timezone.utc)
    if last_fetched_at.tzinfo is None:
        last_fetched_at = last_fetched_at.replace(tzinfo=timezone.utc)
    
    elapsed = (now - last_fetched_at).total_seconds()
    if elapsed >= REFRESH_COOLDOWN_SECONDS:
        return None
    
    return int(REFRESH_COOLDOWN_SECONDS - elapsed)


async def generate_github_vector(
    languages: list[str],
    topics: list[str],
    descriptions: list[str],
) -> list[float] | None:
    """Generates 768-dim embedding from GitHub profile data with retry support."""
    text = format_github_text(languages, topics, descriptions)
    
    if not text:
        logger.warning("Cannot generate GitHub vector: no text content")
        return None
    
    logger.info(f"Generating GitHub vector for text length {len(text)}")
    vector = await generate_github_vector_with_retry(text)
    
    if vector is None:
        logger.warning("GitHub vector generation failed after retries")
        return None
    
    return vector


async def initiate_github_fetch(
    db: AsyncSession,
    user_id: UUID,
    is_refresh: bool = False,
) -> dict:
    """
    Validates GitHub connection and enqueues Cloud Task for async processing.
    Returns immediately with job_id and status 'processing'.
    """
    profile = await _get_or_create_profile(db, user_id)
    
    if is_refresh and profile.github_fetched_at:
        seconds_remaining = check_refresh_allowed(profile.github_fetched_at)
        if seconds_remaining is not None:
            raise RefreshRateLimitError(seconds_remaining)
    
    try:
        await get_valid_access_token(db, user_id, "github")
    except LinkedAccountNotFoundError:
        raise GitHubNotConnectedError(
            "No GitHub account connected. Please connect GitHub first at /auth/connect/github"
        )
    except LinkedAccountRevokedError:
        raise GitHubNotConnectedError(
            "Please reconnect your GitHub account"
        )
    
    await mark_onboarding_in_progress(db, profile)
    
    profile.is_calculating = True
    await db.commit()
    
    job_id = await enqueue_github_task(user_id)
    
    logger.info(f"GitHub fetch initiated for user {user_id}, job_id {job_id}")
    
    return {
        "job_id": job_id,
        "status": "processing",
        "message": "GitHub profile fetch started. Processing in background.",
    }


async def execute_github_fetch(
    db: AsyncSession,
    user_id: UUID,
) -> dict:
    """
    Executes full GitHub fetch and embedding. Called by worker.
    Does not check refresh rate limit (already validated in initiate).
    """
    profile = await _get_or_create_profile(db, user_id)
    
    try:
        access_token = await get_valid_access_token(db, user_id, "github")
    except (LinkedAccountNotFoundError, LinkedAccountRevokedError) as e:
        profile.is_calculating = False
        await db.commit()
        raise GitHubNotConnectedError(str(e))
    
    async with GitHubGraphQLClient(access_token) as client:
        try:
            username = await client.verify_authentication()
        except GitHubAuthError:
            profile.is_calculating = False
            await db.commit()
            raise GitHubNotConnectedError("Please reconnect your GitHub account")
        
        if not username:
            profile.is_calculating = False
            await db.commit()
            raise GitHubNotConnectedError("Could not retrieve GitHub username")
        
        starred_count, starred_repos = await _fetch_starred_repos(client, username)
        contributed_count, contributed_repos = await _fetch_contributed_repos(client, username)
    
    languages = extract_languages(starred_repos, contributed_repos)
    topics = extract_topics(starred_repos, contributed_repos)
    
    descriptions = _extract_descriptions_from_repos(contributed_repos, max_count=3)
    descriptions.extend(_extract_descriptions_from_repos(starred_repos, max_count=2))
    
    minimal_warning = check_minimal_data(starred_count, contributed_count)
    
    profile.github_username = username
    profile.github_languages = languages[:20] if languages else []
    profile.github_topics = topics[:30] if topics else []
    profile.github_data = {
        "starred_count": starred_count,
        "contributed_count": contributed_count,
        "starred_repos": [r.get("name") for r in starred_repos[:20] if r],
        "contributed_repos": [r.get("name") for r in contributed_repos[:20] if r],
    }
    profile.github_fetched_at = datetime.now(timezone.utc)
    await db.commit()
    
    try:
        logger.info(f"Generating GitHub vector for user {user_id}")
        github_vector = await generate_github_vector(languages, topics, descriptions)
        profile.github_vector = github_vector
        
        combined = await calculate_combined_vector(
            intent_vector=profile.intent_vector,
            resume_vector=profile.resume_vector,
            github_vector=github_vector,
        )
        profile.combined_vector = combined
        logger.info(f"GitHub vector generated for user {user_id}")
    finally:
        profile.is_calculating = False
    
    await db.commit()
    await db.refresh(profile)
    
    return {
        "status": "ready",
        "username": username,
        "starred_count": starred_count,
        "contributed_repos": contributed_count,
        "languages": profile.github_languages or [],
        "topics": profile.github_topics or [],
        "vector_status": "ready" if profile.github_vector else None,
        "fetched_at": profile.github_fetched_at.isoformat() if profile.github_fetched_at else None,
        "minimal_data_warning": minimal_warning,
    }


async def fetch_github_profile(
    db: AsyncSession,
    user_id: UUID,
    is_refresh: bool = False,
) -> dict:
    """
    Synchronous version: Full GitHub fetch and embedding in one call.
    Used for testing or as fallback when Cloud Tasks is unavailable.
    """
    profile = await _get_or_create_profile(db, user_id)
    
    if is_refresh and profile.github_fetched_at:
        seconds_remaining = check_refresh_allowed(profile.github_fetched_at)
        if seconds_remaining is not None:
            raise RefreshRateLimitError(seconds_remaining)
    
    # Get GitHub access token from linked accounts
    try:
        access_token = await get_valid_access_token(db, user_id, "github")
    except LinkedAccountNotFoundError:
        raise GitHubNotConnectedError(
            "No GitHub account connected. Please connect GitHub first at /auth/connect/github"
        )
    except LinkedAccountRevokedError:
        raise GitHubNotConnectedError(
            "Please reconnect your GitHub account"
        )
    
    async with GitHubGraphQLClient(access_token) as client:
        try:
            username = await client.verify_authentication()
        except GitHubAuthError:
            raise GitHubNotConnectedError(
                "Please reconnect your GitHub account"
            )
        
        if not username:
            raise GitHubNotConnectedError(
                "Could not retrieve GitHub username. Please reconnect."
            )
        
        # Fetch starred and contributed repos
        starred_count, starred_repos = await _fetch_starred_repos(client, username)
        contributed_count, contributed_repos = await _fetch_contributed_repos(client, username)
    
    # Extract languages and topics
    languages = extract_languages(starred_repos, contributed_repos)
    topics = extract_topics(starred_repos, contributed_repos)
    
    descriptions = _extract_descriptions_from_repos(contributed_repos, max_count=3)
    descriptions.extend(_extract_descriptions_from_repos(starred_repos, max_count=2))
    
    minimal_warning = check_minimal_data(starred_count, contributed_count)
    
    await mark_onboarding_in_progress(db, profile)
    
    # Update profile with fetched data
    profile.github_username = username
    profile.github_languages = languages[:20] if languages else []
    profile.github_topics = topics[:30] if topics else []
    profile.github_data = {
        "starred_count": starred_count,
        "contributed_count": contributed_count,
        "starred_repos": [r.get("name") for r in starred_repos[:20] if r],
        "contributed_repos": [r.get("name") for r in contributed_repos[:20] if r],
    }
    profile.github_fetched_at = datetime.now(timezone.utc)
    profile.is_calculating = True
    await db.commit()
    
    # Generate GitHub vector
    try:
        logger.info(f"Generating GitHub vector for user {user_id}")
        github_vector = await generate_github_vector(languages, topics, descriptions)
        profile.github_vector = github_vector
        
        # Recalculate combined vector
        combined = await calculate_combined_vector(
            intent_vector=profile.intent_vector,
            resume_vector=profile.resume_vector,
            github_vector=github_vector,
        )
        profile.combined_vector = combined
        logger.info(f"GitHub vector generated for user {user_id}")
    finally:
        profile.is_calculating = False
    
    await db.commit()
    await db.refresh(profile)
    
    return {
        "status": "ready",
        "username": username,
        "starred_count": starred_count,
        "contributed_repos": contributed_count,
        "languages": profile.github_languages or [],
        "topics": profile.github_topics or [],
        "vector_status": "ready" if profile.github_vector else None,
        "fetched_at": profile.github_fetched_at.isoformat() if profile.github_fetched_at else None,
        "minimal_data_warning": minimal_warning,
    }


async def get_github_data(
    db: AsyncSession,
    user_id: UUID,
) -> dict | None:
    """Returns stored GitHub profile data or None if not populated."""
    profile = await _get_or_create_profile(db, user_id)
    
    if profile.github_username is None:
        return None
    
    github_data = profile.github_data or {}
    
    return {
        "status": "ready",
        "username": profile.github_username,
        "starred_count": github_data.get("starred_count", 0),
        "contributed_repos": github_data.get("contributed_count", 0),
        "languages": profile.github_languages or [],
        "topics": profile.github_topics or [],
        "vector_status": "ready" if profile.github_vector else None,
        "fetched_at": profile.github_fetched_at.isoformat() if profile.github_fetched_at else None,
    }


async def delete_github(
    db: AsyncSession,
    user_id: UUID,
) -> bool:
    """Clears GitHub data and recalculates combined vector."""
    profile = await _get_or_create_profile(db, user_id)
    
    if profile.github_username is None:
        return False
    
    profile.is_calculating = True
    await db.commit()
    
    try:
        profile.github_username = None
        profile.github_languages = None
        profile.github_topics = None
        profile.github_data = None
        profile.github_fetched_at = None
        profile.github_vector = None
        
        logger.info(f"Recalculating combined vector after GitHub deletion for user {user_id}")
        combined = await calculate_combined_vector(
            intent_vector=profile.intent_vector,
            resume_vector=profile.resume_vector,
            github_vector=None,
        )
        profile.combined_vector = combined
    finally:
        profile.is_calculating = False
    
    await db.commit()
    await db.refresh(profile)
    return True


__all__ = [
    "REFRESH_COOLDOWN_SECONDS",
    "extract_languages",
    "extract_topics",
    "format_github_text",
    "check_minimal_data",
    "check_refresh_allowed",
    "generate_github_vector",
    "initiate_github_fetch",
    "execute_github_fetch",
    "fetch_github_profile",
    "get_github_data",
    "delete_github",
]

