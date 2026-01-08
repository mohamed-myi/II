"""Unit tests for Cloud Tasks service."""
import sys
from pathlib import Path
from uuid import uuid4

project_root = Path(__file__).resolve().parent.parent.parent.parent.parent
database_src = project_root / "packages" / "database" / "src"
if str(database_src) not in sys.path:
    sys.path.insert(0, str(database_src))


class TestCloudTasksClientMockMode:
    """Tests for Cloud Tasks client in mock mode."""
    
    async def test_enqueue_resume_task_returns_job_id(self):
        from src.services.cloud_tasks_service import (
            get_cloud_tasks_client,
            reset_client_for_testing,
        )
        
        reset_client_for_testing()
        client = get_cloud_tasks_client()
        
        user_id = uuid4()
        
        job_id = await client.enqueue_resume_task(
            user_id=user_id,
            file_bytes=b"test pdf content",
            filename="resume.pdf",
            content_type="application/pdf",
        )
        
        assert job_id is not None
        assert isinstance(job_id, str)
        assert len(job_id) > 0
        
        reset_client_for_testing()
    
    async def test_enqueue_github_task_returns_job_id(self):
        from src.services.cloud_tasks_service import (
            get_cloud_tasks_client,
            reset_client_for_testing,
        )
        
        reset_client_for_testing()
        client = get_cloud_tasks_client()
        
        user_id = uuid4()
        
        job_id = await client.enqueue_github_task(user_id=user_id)
        
        assert job_id is not None
        assert isinstance(job_id, str)
        assert len(job_id) > 0
        
        reset_client_for_testing()
    
    async def test_mock_tasks_are_stored(self):
        from src.services.cloud_tasks_service import (
            get_cloud_tasks_client,
            reset_client_for_testing,
        )
        
        reset_client_for_testing()
        client = get_cloud_tasks_client()
        
        user_id = uuid4()
        
        await client.enqueue_resume_task(
            user_id=user_id,
            file_bytes=b"content",
            filename="test.pdf",
        )
        
        mock_tasks = client.get_mock_tasks()
        
        assert len(mock_tasks) == 1
        
        task_name = list(mock_tasks.keys())[0]
        assert str(user_id) in task_name
        assert "resume" in task_name
        
        reset_client_for_testing()
    
    async def test_cancel_user_tasks_removes_all_user_tasks(self):
        from src.services.cloud_tasks_service import (
            get_cloud_tasks_client,
            reset_client_for_testing,
        )
        
        reset_client_for_testing()
        client = get_cloud_tasks_client()
        
        user_id_1 = uuid4()
        user_id_2 = uuid4()
        
        await client.enqueue_resume_task(user_id=user_id_1, file_bytes=b"a", filename="a.pdf")
        await client.enqueue_github_task(user_id=user_id_1)
        await client.enqueue_resume_task(user_id=user_id_2, file_bytes=b"b", filename="b.pdf")
        
        assert len(client.get_mock_tasks()) == 3
        
        cancelled = await client.cancel_user_tasks(user_id_1)
        
        assert cancelled == 2
        
        remaining = client.get_mock_tasks()
        assert len(remaining) == 1
        
        task_name = list(remaining.keys())[0]
        assert str(user_id_2) in task_name
        
        reset_client_for_testing()
    
    async def test_cancel_user_tasks_returns_zero_when_no_tasks(self):
        from src.services.cloud_tasks_service import (
            get_cloud_tasks_client,
            reset_client_for_testing,
        )
        
        reset_client_for_testing()
        client = get_cloud_tasks_client()
        
        user_id = uuid4()
        
        cancelled = await client.cancel_user_tasks(user_id)
        
        assert cancelled == 0
        
        reset_client_for_testing()
    
    async def test_clear_mock_tasks(self):
        from src.services.cloud_tasks_service import (
            get_cloud_tasks_client,
            reset_client_for_testing,
        )
        
        reset_client_for_testing()
        client = get_cloud_tasks_client()
        
        user_id = uuid4()
        await client.enqueue_resume_task(user_id=user_id, file_bytes=b"x", filename="x.pdf")
        
        assert len(client.get_mock_tasks()) == 1
        
        client.clear_mock_tasks()
        
        assert len(client.get_mock_tasks()) == 0
        
        reset_client_for_testing()


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""
    
    async def test_enqueue_resume_task_function(self):
        from src.services.cloud_tasks_service import (
            enqueue_resume_task,
            reset_client_for_testing,
        )
        
        reset_client_for_testing()
        
        user_id = uuid4()
        job_id = await enqueue_resume_task(
            user_id=user_id,
            file_bytes=b"content",
            filename="test.pdf",
        )
        
        assert job_id is not None
        
        reset_client_for_testing()
    
    async def test_enqueue_github_task_function(self):
        from src.services.cloud_tasks_service import (
            enqueue_github_task,
            reset_client_for_testing,
        )
        
        reset_client_for_testing()
        
        user_id = uuid4()
        job_id = await enqueue_github_task(user_id=user_id)
        
        assert job_id is not None
        
        reset_client_for_testing()
    
    async def test_cancel_user_tasks_function(self):
        from src.services.cloud_tasks_service import (
            enqueue_resume_task,
            cancel_user_tasks,
            reset_client_for_testing,
        )
        
        reset_client_for_testing()
        
        user_id = uuid4()
        await enqueue_resume_task(user_id=user_id, file_bytes=b"x", filename="x.pdf")
        
        cancelled = await cancel_user_tasks(user_id)
        
        assert cancelled == 1
        
        reset_client_for_testing()


class TestTaskPayloads:
    """Tests for task payload structure."""
    
    async def test_resume_task_payload_contains_required_fields(self):
        from src.services.cloud_tasks_service import (
            get_cloud_tasks_client,
            reset_client_for_testing,
        )
        
        reset_client_for_testing()
        client = get_cloud_tasks_client()
        
        user_id = uuid4()
        
        await client.enqueue_resume_task(
            user_id=user_id,
            file_bytes=b"pdf content here",
            filename="resume.pdf",
            content_type="application/pdf",
        )
        
        mock_tasks = client.get_mock_tasks()
        task = list(mock_tasks.values())[0]
        payload = task["payload"]
        
        assert "job_id" in payload
        assert "user_id" in payload
        assert "filename" in payload
        assert "content_type" in payload
        assert "file_bytes_b64" in payload
        assert "created_at" in payload
        
        assert payload["user_id"] == str(user_id)
        assert payload["filename"] == "resume.pdf"
        assert payload["content_type"] == "application/pdf"
        
        reset_client_for_testing()
    
    async def test_github_task_payload_contains_required_fields(self):
        from src.services.cloud_tasks_service import (
            get_cloud_tasks_client,
            reset_client_for_testing,
        )
        
        reset_client_for_testing()
        client = get_cloud_tasks_client()
        
        user_id = uuid4()
        
        await client.enqueue_github_task(user_id=user_id)
        
        mock_tasks = client.get_mock_tasks()
        task = list(mock_tasks.values())[0]
        payload = task["payload"]
        
        assert "job_id" in payload
        assert "user_id" in payload
        assert "created_at" in payload
        
        assert payload["user_id"] == str(user_id)
        
        reset_client_for_testing()

