"""Integration tests for bookmarks and notes API routes."""
import pytest
from datetime import datetime, timezone
from uuid import uuid4
from unittest.mock import patch, MagicMock, AsyncMock

from fastapi.testclient import TestClient

from src.main import app
from src.middleware.auth import require_auth
from src.middleware.rate_limit import reset_rate_limiter, reset_rate_limiter_instance


@pytest.fixture(autouse=True)
def reset_rate_limit():
    reset_rate_limiter()
    reset_rate_limiter_instance()
    yield
    reset_rate_limiter()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def mock_user():
    user = MagicMock()
    user.id = uuid4()
    user.email = "test@example.com"
    return user


@pytest.fixture
def mock_session(mock_user):
    session = MagicMock()
    session.id = uuid4()
    session.user_id = mock_user.id
    return session


@pytest.fixture
def authenticated_client(client, mock_user, mock_session):
    def mock_require_auth():
        return (mock_user, mock_session)

    app.dependency_overrides[require_auth] = mock_require_auth
    yield client
    app.dependency_overrides.clear()


@pytest.fixture
def mock_bookmark():
    bookmark = MagicMock()
    bookmark.id = uuid4()
    bookmark.issue_node_id = "I_abc123"
    bookmark.github_url = "https://github.com/org/repo/issues/1"
    bookmark.title_snapshot = "Bug title"
    bookmark.body_snapshot = "Bug body description"
    bookmark.is_resolved = False
    bookmark.created_at = datetime.now(timezone.utc)
    return bookmark


@pytest.fixture
def mock_note(mock_bookmark):
    note = MagicMock()
    note.id = uuid4()
    note.bookmark_id = mock_bookmark.id
    note.content = "My note content"
    note.updated_at = datetime.now(timezone.utc)
    return note


class TestAuthRequired:
    """Verifies authentication middleware is applied to all bookmark routes."""

    @pytest.mark.parametrize("method,path,body", [
        ("post", "/bookmarks", {"issue_node_id": "I_123", "github_url": "https://github.com/o/r/issues/1", "title_snapshot": "T", "body_snapshot": "B"}),
        ("get", "/bookmarks", None),
        ("get", f"/bookmarks/{uuid4()}", None),
        ("patch", f"/bookmarks/{uuid4()}", {"is_resolved": True}),
        ("delete", f"/bookmarks/{uuid4()}", None),
        ("post", f"/bookmarks/{uuid4()}/notes", {"content": "Note"}),
        ("get", f"/bookmarks/{uuid4()}/notes", None),
        ("patch", f"/bookmarks/notes/{uuid4()}", {"content": "Updated"}),
        ("delete", f"/bookmarks/notes/{uuid4()}", None),
    ])
    def test_returns_401_without_auth(self, client, method, path, body):
        if body:
            response = getattr(client, method)(path, json=body)
        else:
            response = getattr(client, method)(path)
        assert response.status_code == 401


class TestBookmarkValidation:
    """Tests input validation for bookmark endpoints."""

    def test_rejects_invalid_github_url_pattern(self, authenticated_client):
        response = authenticated_client.post("/bookmarks", json={
            "issue_node_id": "I_abc123",
            "github_url": "https://gitlab.com/org/repo/issues/1",
            "title_snapshot": "Title",
            "body_snapshot": "Body",
        })
        assert response.status_code == 422

    def test_rejects_empty_issue_node_id(self, authenticated_client):
        response = authenticated_client.post("/bookmarks", json={
            "issue_node_id": "",
            "github_url": "https://github.com/org/repo/issues/1",
            "title_snapshot": "Title",
            "body_snapshot": "Body",
        })
        assert response.status_code == 422

    def test_rejects_title_over_max_length(self, authenticated_client):
        response = authenticated_client.post("/bookmarks", json={
            "issue_node_id": "I_abc123",
            "github_url": "https://github.com/org/repo/issues/1",
            "title_snapshot": "x" * 501,
            "body_snapshot": "Body",
        })
        assert response.status_code == 422

    def test_rejects_body_over_max_length(self, authenticated_client):
        response = authenticated_client.post("/bookmarks", json={
            "issue_node_id": "I_abc123",
            "github_url": "https://github.com/org/repo/issues/1",
            "title_snapshot": "Title",
            "body_snapshot": "x" * 5001,
        })
        assert response.status_code == 422


class TestBookmarkCRUD:
    """Tests bookmark CRUD operations."""

    def test_create_bookmark_returns_201(self, authenticated_client, mock_bookmark):
        with patch("src.api.routes.bookmarks.create_bookmark_service", new_callable=AsyncMock) as mock_create:
            mock_create.return_value = mock_bookmark

            response = authenticated_client.post("/bookmarks", json={
                "issue_node_id": "I_abc123",
                "github_url": "https://github.com/org/repo/issues/1",
                "title_snapshot": "Bug title",
                "body_snapshot": "Bug body",
            })

            assert response.status_code == 201
            data = response.json()
            assert data["issue_node_id"] == "I_abc123"
            assert data["is_resolved"] is False
            assert data["notes_count"] == 0

    def test_create_duplicate_bookmark_returns_409(self, authenticated_client):
        from src.core.errors import BookmarkAlreadyExistsError

        with patch("src.api.routes.bookmarks.create_bookmark_service", new_callable=AsyncMock) as mock_create:
            mock_create.side_effect = BookmarkAlreadyExistsError()

            response = authenticated_client.post("/bookmarks", json={
                "issue_node_id": "I_abc123",
                "github_url": "https://github.com/org/repo/issues/1",
                "title_snapshot": "Title",
                "body_snapshot": "Body",
            })

            assert response.status_code == 409

    def test_list_bookmarks_returns_paginated_results(self, authenticated_client, mock_bookmark):
        with patch("src.api.routes.bookmarks.list_bookmarks_service", new_callable=AsyncMock) as mock_list:
            with patch("src.api.routes.bookmarks.get_notes_count_for_bookmark", new_callable=AsyncMock) as mock_count:
                mock_list.return_value = ([mock_bookmark], 1, False)
                mock_count.return_value = 2

                response = authenticated_client.get("/bookmarks?page=1&page_size=20")

                assert response.status_code == 200
                data = response.json()
                assert data["total"] == 1
                assert data["page"] == 1
                assert data["has_more"] is False
                assert len(data["results"]) == 1
                assert data["results"][0]["notes_count"] == 2

    def test_list_bookmarks_empty_returns_200(self, authenticated_client):
        with patch("src.api.routes.bookmarks.list_bookmarks_service", new_callable=AsyncMock) as mock_list:
            mock_list.return_value = ([], 0, False)

            response = authenticated_client.get("/bookmarks")

            assert response.status_code == 200
            data = response.json()
            assert data["results"] == []
            assert data["total"] == 0

    def test_get_bookmark_returns_bookmark_with_notes_count(self, authenticated_client, mock_bookmark):
        with patch("src.api.routes.bookmarks.get_bookmark_with_notes_count", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = (mock_bookmark, 3)

            response = authenticated_client.get(f"/bookmarks/{mock_bookmark.id}")

            assert response.status_code == 200
            data = response.json()
            assert data["id"] == str(mock_bookmark.id)
            assert data["notes_count"] == 3

    def test_get_bookmark_not_found_returns_404(self, authenticated_client):
        with patch("src.api.routes.bookmarks.get_bookmark_with_notes_count", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = (None, 0)

            response = authenticated_client.get(f"/bookmarks/{uuid4()}")

            assert response.status_code == 404

    def test_update_bookmark_is_resolved(self, authenticated_client, mock_bookmark):
        with patch("src.api.routes.bookmarks.update_bookmark_service", new_callable=AsyncMock) as mock_update:
            with patch("src.api.routes.bookmarks.get_notes_count_for_bookmark", new_callable=AsyncMock) as mock_count:
                mock_bookmark.is_resolved = True
                mock_update.return_value = mock_bookmark
                mock_count.return_value = 0

                response = authenticated_client.patch(
                    f"/bookmarks/{mock_bookmark.id}",
                    json={"is_resolved": True}
                )

                assert response.status_code == 200
                data = response.json()
                assert data["is_resolved"] is True

    def test_update_bookmark_not_found_returns_404(self, authenticated_client):
        with patch("src.api.routes.bookmarks.update_bookmark_service", new_callable=AsyncMock) as mock_update:
            mock_update.return_value = None

            response = authenticated_client.patch(
                f"/bookmarks/{uuid4()}",
                json={"is_resolved": True}
            )

            assert response.status_code == 404

    def test_delete_bookmark_returns_success(self, authenticated_client, mock_bookmark):
        with patch("src.api.routes.bookmarks.delete_bookmark_service", new_callable=AsyncMock) as mock_delete:
            mock_delete.return_value = True

            response = authenticated_client.delete(f"/bookmarks/{mock_bookmark.id}")

            assert response.status_code == 200
            data = response.json()
            assert data["deleted"] is True

    def test_delete_bookmark_not_found_returns_404(self, authenticated_client):
        with patch("src.api.routes.bookmarks.delete_bookmark_service", new_callable=AsyncMock) as mock_delete:
            mock_delete.return_value = False

            response = authenticated_client.delete(f"/bookmarks/{uuid4()}")

            assert response.status_code == 404


class TestNoteCRUD:
    """Tests note CRUD operations."""

    def test_create_note_returns_201(self, authenticated_client, mock_bookmark, mock_note):
        with patch("src.api.routes.bookmarks.create_note_service", new_callable=AsyncMock) as mock_create:
            mock_create.return_value = mock_note

            response = authenticated_client.post(
                f"/bookmarks/{mock_bookmark.id}/notes",
                json={"content": "My note content"}
            )

            assert response.status_code == 201
            data = response.json()
            assert data["content"] == "My note content"

    def test_create_note_bookmark_not_found_returns_404(self, authenticated_client):
        with patch("src.api.routes.bookmarks.create_note_service", new_callable=AsyncMock) as mock_create:
            mock_create.return_value = None

            response = authenticated_client.post(
                f"/bookmarks/{uuid4()}/notes",
                json={"content": "Note content"}
            )

            assert response.status_code == 404

    def test_list_notes_returns_notes(self, authenticated_client, mock_bookmark, mock_note):
        with patch("src.api.routes.bookmarks.list_notes_service", new_callable=AsyncMock) as mock_list:
            mock_list.return_value = [mock_note]

            response = authenticated_client.get(f"/bookmarks/{mock_bookmark.id}/notes")

            assert response.status_code == 200
            data = response.json()
            assert len(data["results"]) == 1
            assert data["results"][0]["content"] == "My note content"

    def test_list_notes_bookmark_not_found_returns_404(self, authenticated_client):
        with patch("src.api.routes.bookmarks.list_notes_service", new_callable=AsyncMock) as mock_list:
            mock_list.return_value = None

            response = authenticated_client.get(f"/bookmarks/{uuid4()}/notes")

            assert response.status_code == 404

    def test_update_note_returns_updated_note(self, authenticated_client, mock_note):
        with patch("src.api.routes.bookmarks.update_note_service", new_callable=AsyncMock) as mock_update:
            mock_note.content = "Updated content"
            mock_update.return_value = mock_note

            response = authenticated_client.patch(
                f"/bookmarks/notes/{mock_note.id}",
                json={"content": "Updated content"}
            )

            assert response.status_code == 200
            data = response.json()
            assert data["content"] == "Updated content"

    def test_update_note_not_found_returns_404(self, authenticated_client):
        with patch("src.api.routes.bookmarks.update_note_service", new_callable=AsyncMock) as mock_update:
            mock_update.return_value = None

            response = authenticated_client.patch(
                f"/bookmarks/notes/{uuid4()}",
                json={"content": "New content"}
            )

            assert response.status_code == 404

    def test_delete_note_returns_success(self, authenticated_client, mock_note):
        with patch("src.api.routes.bookmarks.delete_note_service", new_callable=AsyncMock) as mock_delete:
            mock_delete.return_value = True

            response = authenticated_client.delete(f"/bookmarks/notes/{mock_note.id}")

            assert response.status_code == 200
            data = response.json()
            assert data["deleted"] is True

    def test_delete_note_not_found_returns_404(self, authenticated_client):
        with patch("src.api.routes.bookmarks.delete_note_service", new_callable=AsyncMock) as mock_delete:
            mock_delete.return_value = False

            response = authenticated_client.delete(f"/bookmarks/notes/{uuid4()}")

            assert response.status_code == 404


class TestNoteValidation:
    """Tests input validation for note endpoints."""

    def test_rejects_empty_note_content(self, authenticated_client, mock_bookmark):
        response = authenticated_client.post(
            f"/bookmarks/{mock_bookmark.id}/notes",
            json={"content": ""}
        )
        assert response.status_code == 422

    def test_rejects_note_content_over_max_length(self, authenticated_client, mock_bookmark):
        response = authenticated_client.post(
            f"/bookmarks/{mock_bookmark.id}/notes",
            json={"content": "x" * 5001}
        )
        assert response.status_code == 422


class TestPagination:
    """Tests pagination parameters for list endpoints."""

    def test_page_defaults_to_1(self, authenticated_client):
        with patch("src.api.routes.bookmarks.list_bookmarks_service", new_callable=AsyncMock) as mock_list:
            mock_list.return_value = ([], 0, False)

            response = authenticated_client.get("/bookmarks")

            assert response.status_code == 200
            data = response.json()
            assert data["page"] == 1

    def test_page_size_defaults_to_20(self, authenticated_client):
        with patch("src.api.routes.bookmarks.list_bookmarks_service", new_callable=AsyncMock) as mock_list:
            mock_list.return_value = ([], 0, False)

            response = authenticated_client.get("/bookmarks")

            assert response.status_code == 200
            data = response.json()
            assert data["page_size"] == 20

    def test_page_size_clamped_to_50(self, authenticated_client):
        with patch("src.api.routes.bookmarks.list_bookmarks_service", new_callable=AsyncMock) as mock_list:
            mock_list.return_value = ([], 0, False)

            response = authenticated_client.get("/bookmarks?page_size=100")

            assert response.status_code == 422

    def test_page_minimum_is_1(self, authenticated_client):
        response = authenticated_client.get("/bookmarks?page=0")
        assert response.status_code == 422

    def test_custom_pagination_parameters(self, authenticated_client):
        with patch("src.api.routes.bookmarks.list_bookmarks_service", new_callable=AsyncMock) as mock_list:
            mock_list.return_value = ([], 0, False)

            response = authenticated_client.get("/bookmarks?page=2&page_size=10")

            assert response.status_code == 200
            data = response.json()
            assert data["page"] == 2
            assert data["page_size"] == 10


class TestUserIsolation:
    """Tests that users can only access their own bookmarks."""

    def test_get_bookmark_owned_by_other_user_returns_404(self, authenticated_client):
        with patch("src.api.routes.bookmarks.get_bookmark_with_notes_count", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = (None, 0)

            response = authenticated_client.get(f"/bookmarks/{uuid4()}")

            assert response.status_code == 404

    def test_delete_bookmark_owned_by_other_user_returns_404(self, authenticated_client):
        with patch("src.api.routes.bookmarks.delete_bookmark_service", new_callable=AsyncMock) as mock_delete:
            mock_delete.return_value = False

            response = authenticated_client.delete(f"/bookmarks/{uuid4()}")

            assert response.status_code == 404

    def test_update_note_owned_by_other_user_returns_404(self, authenticated_client):
        with patch("src.api.routes.bookmarks.update_note_service", new_callable=AsyncMock) as mock_update:
            mock_update.return_value = None

            response = authenticated_client.patch(
                f"/bookmarks/notes/{uuid4()}",
                json={"content": "Trying to update"}
            )

            assert response.status_code == 404

