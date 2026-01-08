"""Bookmarks and Notes API routes."""
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlmodel.ext.asyncio.session import AsyncSession

from src.api.dependencies import get_db
from src.middleware.auth import require_auth
from src.services.bookmark_service import (
    create_bookmark as create_bookmark_service,
    list_bookmarks as list_bookmarks_service,
    get_bookmark_with_notes_count,
    update_bookmark as update_bookmark_service,
    delete_bookmark as delete_bookmark_service,
    create_note as create_note_service,
    list_notes as list_notes_service,
    update_note as update_note_service,
    delete_note as delete_note_service,
    get_notes_count_for_bookmark,
    DEFAULT_PAGE_SIZE,
)
from src.core.errors import (
    BookmarkAlreadyExistsError,
)
from models.identity import User, Session


router = APIRouter()


class BookmarkCreateInput(BaseModel):
    issue_node_id: str = Field(..., min_length=1)
    github_url: str = Field(..., pattern=r"^https://github\.com/.+")
    title_snapshot: str = Field(..., min_length=1, max_length=500)
    body_snapshot: str = Field(..., max_length=5000)


class BookmarkUpdateInput(BaseModel):
    is_resolved: bool


class NoteCreateInput(BaseModel):
    content: str = Field(..., min_length=1, max_length=5000)


class NoteUpdateInput(BaseModel):
    content: str = Field(..., min_length=1, max_length=5000)


class BookmarkOutput(BaseModel):
    id: str
    issue_node_id: str
    github_url: str
    title_snapshot: str
    body_snapshot: str
    is_resolved: bool
    created_at: str
    notes_count: int


class BookmarkListOutput(BaseModel):
    results: list[BookmarkOutput]
    total: int
    page: int
    page_size: int
    has_more: bool


class NoteOutput(BaseModel):
    id: str
    bookmark_id: str
    content: str
    updated_at: str


class NoteListOutput(BaseModel):
    results: list[NoteOutput]


@router.post("", response_model=BookmarkOutput, status_code=201)
async def create_bookmark(
    body: BookmarkCreateInput,
    auth: tuple[User, Session] = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
) -> BookmarkOutput:
    user, _ = auth

    try:
        bookmark = await create_bookmark_service(
            db=db,
            user_id=user.id,
            issue_node_id=body.issue_node_id,
            github_url=body.github_url,
            title_snapshot=body.title_snapshot,
            body_snapshot=body.body_snapshot,
        )
    except BookmarkAlreadyExistsError as e:
        raise HTTPException(status_code=409, detail=e.user_message)

    return BookmarkOutput(
        id=str(bookmark.id),
        issue_node_id=bookmark.issue_node_id,
        github_url=bookmark.github_url,
        title_snapshot=bookmark.title_snapshot,
        body_snapshot=bookmark.body_snapshot,
        is_resolved=bookmark.is_resolved,
        created_at=bookmark.created_at.isoformat(),
        notes_count=0,
    )


@router.get("", response_model=BookmarkListOutput)
async def list_bookmarks(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=50),
    auth: tuple[User, Session] = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
) -> BookmarkListOutput:
    user, _ = auth

    bookmarks, total, has_more = await list_bookmarks_service(
        db=db,
        user_id=user.id,
        page=page,
        page_size=page_size,
    )

    results = []
    for bookmark in bookmarks:
        notes_count = await get_notes_count_for_bookmark(db, bookmark.id)
        results.append(BookmarkOutput(
            id=str(bookmark.id),
            issue_node_id=bookmark.issue_node_id,
            github_url=bookmark.github_url,
            title_snapshot=bookmark.title_snapshot,
            body_snapshot=bookmark.body_snapshot,
            is_resolved=bookmark.is_resolved,
            created_at=bookmark.created_at.isoformat(),
            notes_count=notes_count,
        ))

    return BookmarkListOutput(
        results=results,
        total=total,
        page=page,
        page_size=page_size,
        has_more=has_more,
    )


@router.get("/{bookmark_id}", response_model=BookmarkOutput)
async def get_bookmark(
    bookmark_id: UUID,
    auth: tuple[User, Session] = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
) -> BookmarkOutput:
    user, _ = auth

    bookmark, notes_count = await get_bookmark_with_notes_count(
        db=db,
        user_id=user.id,
        bookmark_id=bookmark_id,
    )

    if bookmark is None:
        raise HTTPException(status_code=404, detail="Bookmark not found")

    return BookmarkOutput(
        id=str(bookmark.id),
        issue_node_id=bookmark.issue_node_id,
        github_url=bookmark.github_url,
        title_snapshot=bookmark.title_snapshot,
        body_snapshot=bookmark.body_snapshot,
        is_resolved=bookmark.is_resolved,
        created_at=bookmark.created_at.isoformat(),
        notes_count=notes_count,
    )


@router.patch("/{bookmark_id}", response_model=BookmarkOutput)
async def update_bookmark(
    bookmark_id: UUID,
    body: BookmarkUpdateInput,
    auth: tuple[User, Session] = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
) -> BookmarkOutput:
    user, _ = auth

    bookmark = await update_bookmark_service(
        db=db,
        user_id=user.id,
        bookmark_id=bookmark_id,
        is_resolved=body.is_resolved,
    )

    if bookmark is None:
        raise HTTPException(status_code=404, detail="Bookmark not found")

    notes_count = await get_notes_count_for_bookmark(db, bookmark.id)

    return BookmarkOutput(
        id=str(bookmark.id),
        issue_node_id=bookmark.issue_node_id,
        github_url=bookmark.github_url,
        title_snapshot=bookmark.title_snapshot,
        body_snapshot=bookmark.body_snapshot,
        is_resolved=bookmark.is_resolved,
        created_at=bookmark.created_at.isoformat(),
        notes_count=notes_count,
    )


@router.delete("/{bookmark_id}")
async def delete_bookmark(
    bookmark_id: UUID,
    auth: tuple[User, Session] = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
) -> dict:
    user, _ = auth

    was_deleted = await delete_bookmark_service(
        db=db,
        user_id=user.id,
        bookmark_id=bookmark_id,
    )

    if not was_deleted:
        raise HTTPException(status_code=404, detail="Bookmark not found")

    return {"deleted": True, "message": "Bookmark and notes deleted"}


@router.post("/{bookmark_id}/notes", response_model=NoteOutput, status_code=201)
async def create_note(
    bookmark_id: UUID,
    body: NoteCreateInput,
    auth: tuple[User, Session] = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
) -> NoteOutput:
    user, _ = auth

    note = await create_note_service(
        db=db,
        user_id=user.id,
        bookmark_id=bookmark_id,
        content=body.content,
    )

    if note is None:
        raise HTTPException(status_code=404, detail="Bookmark not found")

    return NoteOutput(
        id=str(note.id),
        bookmark_id=str(note.bookmark_id),
        content=note.content,
        updated_at=note.updated_at.isoformat(),
    )


@router.get("/{bookmark_id}/notes", response_model=NoteListOutput)
async def list_notes(
    bookmark_id: UUID,
    auth: tuple[User, Session] = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
) -> NoteListOutput:
    user, _ = auth

    notes = await list_notes_service(
        db=db,
        user_id=user.id,
        bookmark_id=bookmark_id,
    )

    if notes is None:
        raise HTTPException(status_code=404, detail="Bookmark not found")

    results = [
        NoteOutput(
            id=str(note.id),
            bookmark_id=str(note.bookmark_id),
            content=note.content,
            updated_at=note.updated_at.isoformat(),
        )
        for note in notes
    ]

    return NoteListOutput(results=results)


@router.patch("/notes/{note_id}", response_model=NoteOutput)
async def update_note(
    note_id: UUID,
    body: NoteUpdateInput,
    auth: tuple[User, Session] = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
) -> NoteOutput:
    user, _ = auth

    note = await update_note_service(
        db=db,
        user_id=user.id,
        note_id=note_id,
        content=body.content,
    )

    if note is None:
        raise HTTPException(status_code=404, detail="Note not found")

    return NoteOutput(
        id=str(note.id),
        bookmark_id=str(note.bookmark_id),
        content=note.content,
        updated_at=note.updated_at.isoformat(),
    )


@router.delete("/notes/{note_id}")
async def delete_note(
    note_id: UUID,
    auth: tuple[User, Session] = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
) -> dict:
    user, _ = auth

    was_deleted = await delete_note_service(
        db=db,
        user_id=user.id,
        note_id=note_id,
    )

    if not was_deleted:
        raise HTTPException(status_code=404, detail="Note not found")

    return {"deleted": True, "message": "Note deleted"}

