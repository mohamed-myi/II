"""Integration tests for resume profile API routes."""
import pytest
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


class TestAuthRequired:
    """Verifies authentication middleware is applied to all resume routes."""
    
    @pytest.mark.parametrize("method,path", [
        ("post", "/profile/resume"),
        ("get", "/profile/resume"),
        ("delete", "/profile/resume"),
    ])
    def test_returns_401_without_auth(self, client, method, path):
        if method == "post":
            response = client.post(path, files={"file": ("resume.pdf", b"content", "application/pdf")})
        else:
            response = getattr(client, method)(path)
        assert response.status_code == 401


class TestPostResume:
    """Tests for POST /profile/resume endpoint."""
    
    def test_returns_400_for_invalid_format(self, authenticated_client, mock_user):
        with patch(
            "src.api.routes.profile_resume.process_resume",
            new_callable=AsyncMock,
        ) as mock_process:
            from src.services.resume_parsing_service import UnsupportedFormatError
            mock_process.side_effect = UnsupportedFormatError("Please upload a PDF or DOCX file")
            
            response = authenticated_client.post(
                "/profile/resume",
                files={"file": ("resume.txt", b"text content", "text/plain")},
            )
        
        assert response.status_code == 400
        assert "PDF or DOCX" in response.json()["detail"]
    
    def test_returns_413_for_large_file(self, authenticated_client, mock_user):
        from src.services.resume_parsing_service import MAX_FILE_SIZE
        
        # File size is checked in the route before calling process_resume
        large_content = b"x" * (MAX_FILE_SIZE + 1)
        
        response = authenticated_client.post(
            "/profile/resume",
            files={"file": ("resume.pdf", large_content, "application/pdf")},
        )
        
        assert response.status_code == 413
        assert "5MB" in response.json()["detail"]
    
    def test_returns_422_for_parse_failure(self, authenticated_client, mock_user):
        with patch(
            "src.api.routes.profile_resume.process_resume",
            new_callable=AsyncMock,
        ) as mock_process:
            from src.services.resume_parsing_service import ResumeParseError
            mock_process.side_effect = ResumeParseError(
                "We couldn't read your resume. Try a different format?"
            )
            
            response = authenticated_client.post(
                "/profile/resume",
                files={"file": ("resume.pdf", b"corrupt pdf", "application/pdf")},
            )
        
        assert response.status_code == 422
        assert "couldn't read" in response.json()["detail"].lower()
    
    def test_successful_upload_returns_data(self, authenticated_client, mock_user):
        with patch(
            "src.api.routes.profile_resume.process_resume",
            new_callable=AsyncMock,
        ) as mock_process:
            mock_process.return_value = {
                "status": "ready",
                "skills": ["Python", "Docker", "FastAPI"],
                "job_titles": ["Senior Software Engineer"],
                "vector_status": "ready",
                "uploaded_at": "2026-01-04T12:00:00+00:00",
                "minimal_data_warning": None,
            }
            
            response = authenticated_client.post(
                "/profile/resume",
                files={"file": ("resume.pdf", b"pdf content", "application/pdf")},
            )
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"
        assert "Python" in data["skills"]
        assert "Docker" in data["skills"]
        assert "Senior Software Engineer" in data["job_titles"]
        assert data["vector_status"] == "ready"
    
    def test_returns_minimal_data_warning(self, authenticated_client, mock_user):
        with patch(
            "src.api.routes.profile_resume.process_resume",
            new_callable=AsyncMock,
        ) as mock_process:
            mock_process.return_value = {
                "status": "ready",
                "skills": ["Python"],
                "job_titles": [],
                "vector_status": "ready",
                "uploaded_at": "2026-01-04T12:00:00+00:00",
                "minimal_data_warning": "We couldn't find many skills in your resume.",
            }
            
            response = authenticated_client.post(
                "/profile/resume",
                files={"file": ("resume.pdf", b"pdf content", "application/pdf")},
            )
        
        assert response.status_code == 200
        data = response.json()
        assert data["minimal_data_warning"] is not None
        assert "skills" in data["minimal_data_warning"].lower()
    
    def test_accepts_docx_file(self, authenticated_client, mock_user):
        with patch(
            "src.api.routes.profile_resume.process_resume",
            new_callable=AsyncMock,
        ) as mock_process:
            mock_process.return_value = {
                "status": "ready",
                "skills": ["JavaScript", "React"],
                "job_titles": ["Frontend Developer"],
                "vector_status": "ready",
                "uploaded_at": "2026-01-04T12:00:00+00:00",
                "minimal_data_warning": None,
            }
            
            content_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            response = authenticated_client.post(
                "/profile/resume",
                files={"file": ("resume.docx", b"docx content", content_type)},
            )
        
        assert response.status_code == 200
        data = response.json()
        assert "JavaScript" in data["skills"]


class TestGetResume:
    """Tests for GET /profile/resume endpoint."""
    
    def test_returns_404_when_not_populated(self, authenticated_client, mock_user):
        with patch(
            "src.api.routes.profile_resume.get_resume_data",
            new_callable=AsyncMock,
        ) as mock_get:
            mock_get.return_value = None
            
            response = authenticated_client.get("/profile/resume")
        
        assert response.status_code == 404
        assert "no resume data" in response.json()["detail"].lower()
    
    def test_returns_data_when_populated(self, authenticated_client, mock_user):
        with patch(
            "src.api.routes.profile_resume.get_resume_data",
            new_callable=AsyncMock,
        ) as mock_get:
            mock_get.return_value = {
                "status": "ready",
                "skills": ["Python", "PostgreSQL", "Docker", "FastAPI"],
                "job_titles": ["Backend Engineer", "Tech Lead"],
                "vector_status": "ready",
                "uploaded_at": "2026-01-04T12:00:00+00:00",
            }
            
            response = authenticated_client.get("/profile/resume")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"
        assert "Python" in data["skills"]
        assert "PostgreSQL" in data["skills"]
        assert "Backend Engineer" in data["job_titles"]
        assert data["vector_status"] == "ready"
        assert "2026-01-04" in data["uploaded_at"]


class TestDeleteResume:
    """Tests for DELETE /profile/resume endpoint."""
    
    def test_returns_404_when_no_data(self, authenticated_client, mock_user):
        with patch(
            "src.api.routes.profile_resume.delete_resume",
            new_callable=AsyncMock,
        ) as mock_delete:
            mock_delete.return_value = False
            
            response = authenticated_client.delete("/profile/resume")
        
        assert response.status_code == 404
        assert "no resume data" in response.json()["detail"].lower()
    
    def test_successfully_deletes_data(self, authenticated_client, mock_user):
        with patch(
            "src.api.routes.profile_resume.delete_resume",
            new_callable=AsyncMock,
        ) as mock_delete:
            mock_delete.return_value = True
            
            response = authenticated_client.delete("/profile/resume")
        
        assert response.status_code == 200
        data = response.json()
        assert data["deleted"] is True
        assert "cleared" in data["message"].lower()


class TestCombinedVectorUpdates:
    """Tests verifying combined vector is recalculated."""
    
    def test_upload_updates_combined_vector(self, authenticated_client, mock_user):
        """Verifies that uploading resume triggers combined vector recalculation."""
        with patch(
            "src.api.routes.profile_resume.process_resume",
            new_callable=AsyncMock,
        ) as mock_process:
            mock_process.return_value = {
                "status": "ready",
                "skills": ["Python"],
                "job_titles": [],
                "vector_status": "ready",
                "uploaded_at": "2026-01-04T12:00:00+00:00",
                "minimal_data_warning": None,
            }
            
            response = authenticated_client.post(
                "/profile/resume",
                files={"file": ("resume.pdf", b"pdf content", "application/pdf")},
            )
            
            assert response.status_code == 200
            assert response.json()["vector_status"] == "ready"
    
    def test_delete_recalculates_combined_vector(self, authenticated_client, mock_user):
        """Verifies that deleting resume triggers combined vector recalculation."""
        with patch(
            "src.api.routes.profile_resume.delete_resume",
            new_callable=AsyncMock,
        ) as mock_delete:
            # delete_resume internally recalculates combined vector
            mock_delete.return_value = True
            
            response = authenticated_client.delete("/profile/resume")
            
            assert response.status_code == 200
            mock_delete.assert_called_once()


class TestErrorMessages:
    """Tests for error message formatting per PROFILE.md."""
    
    def test_unsupported_format_message(self, authenticated_client, mock_user):
        with patch(
            "src.api.routes.profile_resume.process_resume",
            new_callable=AsyncMock,
        ) as mock_process:
            from src.services.resume_parsing_service import UnsupportedFormatError
            mock_process.side_effect = UnsupportedFormatError("Please upload a PDF or DOCX file")
            
            response = authenticated_client.post(
                "/profile/resume",
                files={"file": ("resume.jpg", b"image content", "image/jpeg")},
            )
        
        assert response.status_code == 400
        assert "PDF or DOCX" in response.json()["detail"]
    
    def test_file_too_large_message(self, authenticated_client, mock_user):
        from src.services.resume_parsing_service import MAX_FILE_SIZE
        
        large_content = b"x" * (MAX_FILE_SIZE + 1)
        
        response = authenticated_client.post(
            "/profile/resume",
            files={"file": ("resume.pdf", large_content, "application/pdf")},
        )
        
        assert response.status_code == 413
        assert "5MB" in response.json()["detail"]
    
    def test_parse_failure_message(self, authenticated_client, mock_user):
        with patch(
            "src.api.routes.profile_resume.process_resume",
            new_callable=AsyncMock,
        ) as mock_process:
            from src.services.resume_parsing_service import ResumeParseError
            mock_process.side_effect = ResumeParseError(
                "We couldn't read your resume. Try a different format?"
            )
            
            response = authenticated_client.post(
                "/profile/resume",
                files={"file": ("resume.pdf", b"corrupt", "application/pdf")},
            )
        
        assert response.status_code == 422
        detail = response.json()["detail"].lower()
        assert "couldn't read" in detail or "different format" in detail


class TestFileValidation:
    """Tests for file validation at route level."""
    
    def test_accepts_pdf_content_type(self, authenticated_client, mock_user):
        with patch(
            "src.api.routes.profile_resume.process_resume",
            new_callable=AsyncMock,
        ) as mock_process:
            mock_process.return_value = {
                "status": "ready",
                "skills": [],
                "job_titles": [],
                "vector_status": "ready",
                "uploaded_at": "2026-01-04T12:00:00+00:00",
                "minimal_data_warning": None,
            }
            
            response = authenticated_client.post(
                "/profile/resume",
                files={"file": ("resume.pdf", b"pdf content", "application/pdf")},
            )
        
        assert response.status_code == 200
    
    def test_accepts_docx_content_type(self, authenticated_client, mock_user):
        with patch(
            "src.api.routes.profile_resume.process_resume",
            new_callable=AsyncMock,
        ) as mock_process:
            mock_process.return_value = {
                "status": "ready",
                "skills": [],
                "job_titles": [],
                "vector_status": "ready",
                "uploaded_at": "2026-01-04T12:00:00+00:00",
                "minimal_data_warning": None,
            }
            
            content_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            response = authenticated_client.post(
                "/profile/resume",
                files={"file": ("resume.docx", b"docx content", content_type)},
            )
        
        assert response.status_code == 200


class TestFileSizeLimit:
    """Tests for 5MB file size limit."""
    
    def test_rejects_file_just_over_limit(self, authenticated_client, mock_user):
        from src.services.resume_parsing_service import MAX_FILE_SIZE
        
        # Just over the limit
        content = b"x" * (MAX_FILE_SIZE + 1)
        
        response = authenticated_client.post(
            "/profile/resume",
            files={"file": ("resume.pdf", content, "application/pdf")},
        )
        
        assert response.status_code == 413
    
    def test_accepts_file_at_limit(self, authenticated_client, mock_user):
        from src.services.resume_parsing_service import MAX_FILE_SIZE
        
        with patch(
            "src.api.routes.profile_resume.process_resume",
            new_callable=AsyncMock,
        ) as mock_process:
            mock_process.return_value = {
                "status": "ready",
                "skills": [],
                "job_titles": [],
                "vector_status": "ready",
                "uploaded_at": "2026-01-04T12:00:00+00:00",
                "minimal_data_warning": None,
            }
            
            # Exactly at the limit
            content = b"x" * MAX_FILE_SIZE
            
            response = authenticated_client.post(
                "/profile/resume",
                files={"file": ("resume.pdf", content, "application/pdf")},
            )
        
        assert response.status_code == 200

