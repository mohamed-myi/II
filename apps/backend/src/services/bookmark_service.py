"""Bookmark service. All queries filter by user_id to enforce authorization."""
import logging
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import delete, func
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

import sys
from pathlib import Path

db_models_path = Path(__file__).resolve().parent.parent.parent.parent.parent / "packages" / "database" / "src"
if str(db_models_path) not in sys.path:
    sys.path.insert(0, str(db_models_path))

from models.persistence import BookmarkedIssue, PersonalNote

from src.core.errors import BookmarkAlreadyExistsError

logger = logging.getLogger(__name__)

DEFAULT_PAGE_SIZE: int = 20
MAX_PAGE_SIZE: int = 50


async def create_bookmark(
    db: AsyncSession,
    user_id: UUID,
    issue_node_id: str,
    github_url: str,
    title_snapshot: str,
    body_snapshot: str,
) -> BookmarkedIssue:
    existing_stmt = select(BookmarkedIssue).where(
        BookmarkedIssue.user_id == user_id,
        BookmarkedIssue.issue_node_id == issue_node_id,
    )
    result = await db.exec(existing_stmt)
    if result.first() is not None:
        raise BookmarkAlreadyExistsError()

    bookmark = BookmarkedIssue(
        user_id=user_id,
        issue_node_id=issue_node_id,
        github_url=github_url,
        title_snapshot=title_snapshot,
        body_snapshot=body_snapshot,
        is_resolved=False,
    )

    db.add(bookmark)
    await db.commit()
    await db.refresh(bookmark)

    logger.info(f"Created bookmark {bookmark.id} for user {user_id}")
    return bookmark


async def list_bookmarks(
    db: AsyncSession,
    user_id: UUID,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> tuple[list[BookmarkedIssue], int, bool]:
    if page < 1:
        page = 1
    if page_size < 1:
        page_size = DEFAULT_PAGE_SIZE
    if page_size > MAX_PAGE_SIZE:
        page_size = MAX_PAGE_SIZE

    offset = (page - 1) * page_size

    count_stmt = select(func.count()).select_from(BookmarkedIssue).where(
        BookmarkedIssue.user_id == user_id
    )
    count_result = await db.exec(count_stmt)
    total = count_result.one()

    list_stmt = (
        select(BookmarkedIssue)
        .where(BookmarkedIssue.user_id == user_id)
        .order_by(BookmarkedIssue.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    result = await db.exec(list_stmt)
    bookmarks = list(result.all())

    has_more = (offset + len(bookmarks)) < total

    return bookmarks, total, has_more


async def get_bookmark(
    db: AsyncSession,
    user_id: UUID,
    bookmark_id: UUID,
) -> BookmarkedIssue | None:
    stmt = select(BookmarkedIssue).where(
        BookmarkedIssue.id == bookmark_id,
        BookmarkedIssue.user_id == user_id,
    )
    result = await db.exec(stmt)
    return result.first()


async def get_bookmark_with_notes_count(
    db: AsyncSession,
    user_id: UUID,
    bookmark_id: UUID,
) -> tuple[BookmarkedIssue | None, int]:
    bookmark = await get_bookmark(db, user_id, bookmark_id)
    if bookmark is None:
        return None, 0

    count_stmt = select(func.count()).select_from(PersonalNote).where(
        PersonalNote.bookmark_id == bookmark_id
    )
    count_result = await db.exec(count_stmt)
    notes_count = count_result.one()

    return bookmark, notes_count


async def update_bookmark(
    db: AsyncSession,
    user_id: UUID,
    bookmark_id: UUID,
    is_resolved: bool,
) -> BookmarkedIssue | None:
    bookmark = await get_bookmark(db, user_id, bookmark_id)
    if bookmark is None:
        return None

    bookmark.is_resolved = is_resolved

    await db.commit()
    await db.refresh(bookmark)

    logger.info(f"Updated bookmark {bookmark_id} is_resolved={is_resolved}")
    return bookmark


async def delete_bookmark(
    db: AsyncSession,
    user_id: UUID,
    bookmark_id: UUID,
) -> bool:
    """Cascade deletes associated notes before removing bookmark."""
    bookmark = await get_bookmark(db, user_id, bookmark_id)
    if bookmark is None:
        return False

    delete_notes_stmt = delete(PersonalNote).where(
        PersonalNote.bookmark_id == bookmark_id
    )
    await db.exec(delete_notes_stmt)

    await db.delete(bookmark)
    await db.commit()

    logger.info(f"Deleted bookmark {bookmark_id} and associated notes for user {user_id}")
    return True


async def create_note(
    db: AsyncSession,
    user_id: UUID,
    bookmark_id: UUID,
    content: str,
) -> PersonalNote | None:
    bookmark = await get_bookmark(db, user_id, bookmark_id)
    if bookmark is None:
        return None

    note = PersonalNote(
        bookmark_id=bookmark_id,
        content=content,
    )

    db.add(note)
    await db.commit()
    await db.refresh(note)

    logger.info(f"Created note {note.id} on bookmark {bookmark_id}")
    return note


async def list_notes(
    db: AsyncSession,
    user_id: UUID,
    bookmark_id: UUID,
) -> list[PersonalNote] | None:
    bookmark = await get_bookmark(db, user_id, bookmark_id)
    if bookmark is None:
        return None

    stmt = (
        select(PersonalNote)
        .where(PersonalNote.bookmark_id == bookmark_id)
        .order_by(PersonalNote.updated_at.desc())
    )
    result = await db.exec(stmt)
    return list(result.all())


async def get_note_with_ownership_check(
    db: AsyncSession,
    user_id: UUID,
    note_id: UUID,
) -> PersonalNote | None:
    """Verifies ownership via join to parent bookmark."""
    stmt = (
        select(PersonalNote)
        .join(BookmarkedIssue, PersonalNote.bookmark_id == BookmarkedIssue.id)
        .where(
            PersonalNote.id == note_id,
            BookmarkedIssue.user_id == user_id,
        )
    )
    result = await db.exec(stmt)
    return result.first()


async def update_note(
    db: AsyncSession,
    user_id: UUID,
    note_id: UUID,
    content: str,
) -> PersonalNote | None:
    note = await get_note_with_ownership_check(db, user_id, note_id)
    if note is None:
        return None

    note.content = content
    note.updated_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(note)

    logger.info(f"Updated note {note_id}")
    return note


async def delete_note(
    db: AsyncSession,
    user_id: UUID,
    note_id: UUID,
) -> bool:
    note = await get_note_with_ownership_check(db, user_id, note_id)
    if note is None:
        return False

    await db.delete(note)
    await db.commit()

    logger.info(f"Deleted note {note_id}")
    return True


async def get_notes_count_for_bookmark(
    db: AsyncSession,
    bookmark_id: UUID,
) -> int:
    stmt = select(func.count()).select_from(PersonalNote).where(
        PersonalNote.bookmark_id == bookmark_id
    )
    result = await db.exec(stmt)
    return result.one()


__all__ = [
    "create_bookmark",
    "list_bookmarks",
    "get_bookmark",
    "get_bookmark_with_notes_count",
    "update_bookmark",
    "delete_bookmark",
    "create_note",
    "list_notes",
    "update_note",
    "delete_note",
    "get_notes_count_for_bookmark",
    "DEFAULT_PAGE_SIZE",
    "MAX_PAGE_SIZE",
]

