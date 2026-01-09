"""Unit tests for embed worker endpoints."""
import pytest
from uuid import uuid4
from unittest.mock import patch, MagicMock, AsyncMock

import sys
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent.parent.parent.parent
database_src = project_root / "packages" / "database" / "src"
if str(database_src) not in sys.path:
    sys.path.insert(0, str(database_src))


class TestHealthEndpoint:
    """Tests for health check endpoint."""
    
    def test_health_returns_ok(self):
        from src.workers.embed_worker import app
        from fastapi.testclient import TestClient
        
        client = TestClient(app)
        response = client.get("/health")
        
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
        assert response.json()["service"] == "embed-worker"


class TestCloudTasksVerification:
    """Tests for Cloud Tasks token verification."""
    
    def test_accepts_request_in_development(self):
        """Development mode should accept all requests."""
        with patch("src.workers.embed_worker.settings") as mock_settings:
            mock_settings.environment = "development"
            
            from src.workers.embed_worker import _verify_cloud_tasks_token
            
            result = _verify_cloud_tasks_token(None)
            assert result is True
    
    def test_accepts_request_with_cloud_tasks_header(self):
        """Requests with Cloud Tasks header should be accepted."""
        with patch("src.workers.embed_worker.settings") as mock_settings:
            mock_settings.environment = "production"
            
            from src.workers.embed_worker import _verify_cloud_tasks_token
            
            result = _verify_cloud_tasks_token("task-name-123")
            assert result is True
    
    def test_rejects_request_without_header_in_production(self):
        """Production requests without header should be rejected."""
        with patch("src.workers.embed_worker.settings") as mock_settings:
            mock_settings.environment = "production"
            
            from src.workers.embed_worker import _verify_cloud_tasks_token
            
            result = _verify_cloud_tasks_token(None)
            assert result is False


class TestResumeEmbedEndpoint:
    """Tests for POST /tasks/embed/resume endpoint."""
    
    def test_returns_403_without_auth_in_production(self):
        from src.workers.embed_worker import app
        from fastapi.testclient import TestClient
        
        with patch("src.workers.embed_worker.settings") as mock_settings:
            mock_settings.environment = "production"
            
            client = TestClient(app)
            response = client.post(
                "/tasks/embed/resume",
                json={
                    "job_id": "job-123",
                    "user_id": str(uuid4()),
                    "markdown_text": "Test markdown content",
                },
            )
        
            assert response.status_code == 403
    
    def test_accepts_request_with_cloud_tasks_header(self):
        from src.workers.embed_worker import app
        from fastapi.testclient import TestClient
        
        user_id = uuid4()
        mock_profile = MagicMock()
        mock_profile.intent_vector = None
        mock_profile.github_vector = None
        
        with patch("src.workers.embed_worker.settings") as mock_settings, \
             patch("src.workers.embed_worker.embed_query", new_callable=AsyncMock) as mock_embed, \
             patch("src.workers.embed_worker.async_session_factory") as mock_session_factory, \
             patch("src.workers.embed_worker._get_profile", new_callable=AsyncMock) as mock_get_profile, \
             patch("src.workers.embed_worker.calculate_combined_vector", new_callable=AsyncMock) as mock_calc:
            
            mock_settings.environment = "production"
            mock_embed.return_value = [0.1] * 768
            mock_get_profile.return_value = mock_profile
            mock_calc.return_value = [0.1] * 768
            
            mock_db = AsyncMock()
            mock_session_factory.return_value.__aenter__.return_value = mock_db
            
            client = TestClient(app)
            response = client.post(
                "/tasks/embed/resume",
                json={
                    "job_id": "job-123",
                    "user_id": str(user_id),
                    "markdown_text": "Test markdown content",
                },
                headers={"X-CloudTasks-TaskName": "task-123"},
            )
        
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "completed"


class TestGitHubEmbedEndpoint:
    """Tests for POST /tasks/embed/github endpoint."""
    
    def test_returns_403_without_auth_in_production(self):
        from src.workers.embed_worker import app
        from fastapi.testclient import TestClient
        
        with patch("src.workers.embed_worker.settings") as mock_settings:
            mock_settings.environment = "production"
            
            client = TestClient(app)
            response = client.post(
                "/tasks/embed/github",
                json={
                    "job_id": "job-456",
                    "user_id": str(uuid4()),
                    "formatted_text": "Python, Go, web development",
                },
            )
        
            assert response.status_code == 403


class TestProfileNotFound:
    """Tests for handling deleted profiles."""
    
    def test_returns_abandoned_when_profile_not_found(self):
        from src.workers.embed_worker import app
        from fastapi.testclient import TestClient
        
        user_id = uuid4()
        
        with patch("src.workers.embed_worker.settings") as mock_settings, \
             patch("src.workers.embed_worker.embed_query", new_callable=AsyncMock) as mock_embed, \
             patch("src.workers.embed_worker.async_session_factory") as mock_session_factory, \
             patch("src.workers.embed_worker._get_profile", new_callable=AsyncMock) as mock_get_profile:
            
            mock_settings.environment = "development"
            mock_embed.return_value = [0.1] * 768
            mock_get_profile.return_value = None
            
            mock_db = AsyncMock()
            mock_session_factory.return_value.__aenter__.return_value = mock_db
            
            client = TestClient(app)
            response = client.post(
                "/tasks/embed/resume",
                json={
                    "job_id": "job-orphan",
                    "user_id": str(user_id),
                    "markdown_text": "Test content",
                },
            )
        
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "abandoned"
            assert data["reason"] == "profile_not_found"

