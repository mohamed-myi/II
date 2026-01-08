"""
Cloud Tasks service for async profile processing jobs.
Wraps GCP Cloud Tasks API with mock mode for local development and testing.
"""
import base64
import json
import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from src.core.config import get_settings

logger = logging.getLogger(__name__)


class CloudTasksClient:
    """
    Client for enqueueing and managing Cloud Tasks.
    Supports mock mode for local development where tasks are not actually created.
    """
    
    def __init__(self):
        self._settings = get_settings()
        self._mock_mode = self._settings.environment == "development" or not self._settings.gcp_project
        self._mock_tasks: dict[str, dict] = {}
        self._client = None
        
        if not self._mock_mode:
            try:
                from google.cloud import tasks_v2
                self._client = tasks_v2.CloudTasksClient()
                logger.info("Cloud Tasks client initialized for production")
            except ImportError:
                logger.warning("google-cloud-tasks not installed; using mock mode")
                self._mock_mode = True
        else:
            logger.info("Cloud Tasks client initialized in mock mode")
    
    def _get_queue_path(self) -> str:
        """Returns the fully qualified queue path."""
        return f"projects/{self._settings.gcp_project}/locations/{self._settings.gcp_region}/queues/{self._settings.cloud_tasks_queue}"
    
    def _create_task_name(self, user_id: UUID, job_type: str) -> str:
        """Creates a task name with user_id prefix for filtering."""
        task_id = f"{user_id}-{job_type}-{uuid4().hex[:8]}"
        return f"{self._get_queue_path()}/tasks/{task_id}"
    
    async def enqueue_resume_task(
        self,
        user_id: UUID,
        file_bytes: bytes,
        filename: str,
        content_type: Optional[str] = None,
    ) -> str:
        """
        Enqueues a resume parsing task.
        File bytes are base64 encoded in the task payload.
        Returns job_id for tracking.
        """
        job_id = str(uuid4())
        task_name = self._create_task_name(user_id, "resume")
        
        payload = {
            "job_id": job_id,
            "user_id": str(user_id),
            "filename": filename,
            "content_type": content_type,
            "file_bytes_b64": base64.b64encode(file_bytes).decode("utf-8"),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        
        if self._mock_mode:
            self._mock_tasks[task_name] = {
                "payload": payload,
                "status": "pending",
            }
            logger.info(f"Mock task enqueued: {task_name} for resume parsing")
            return job_id
        
        from google.cloud import tasks_v2
        from google.protobuf import timestamp_pb2
        
        task = tasks_v2.Task(
            name=task_name,
            http_request=tasks_v2.HttpRequest(
                http_method=tasks_v2.HttpMethod.POST,
                url=f"{self._settings.resume_worker_url}/tasks/resume/parse",
                headers={"Content-Type": "application/json"},
                body=json.dumps(payload).encode(),
                oidc_token=tasks_v2.OidcToken(
                    service_account_email=f"{self._settings.gcp_project}@appspot.gserviceaccount.com",
                ),
            ),
        )
        
        self._client.create_task(
            parent=self._get_queue_path(),
            task=task,
        )
        
        logger.info(f"Cloud Task created: {task_name} for resume parsing")
        return job_id
    
    async def enqueue_github_task(
        self,
        user_id: UUID,
    ) -> str:
        """
        Enqueues a GitHub profile fetch task.
        Returns job_id for tracking.
        """
        job_id = str(uuid4())
        task_name = self._create_task_name(user_id, "github")
        
        payload = {
            "job_id": job_id,
            "user_id": str(user_id),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        
        if self._mock_mode:
            self._mock_tasks[task_name] = {
                "payload": payload,
                "status": "pending",
            }
            logger.info(f"Mock task enqueued: {task_name} for GitHub fetch")
            return job_id
        
        from google.cloud import tasks_v2
        
        task = tasks_v2.Task(
            name=task_name,
            http_request=tasks_v2.HttpRequest(
                http_method=tasks_v2.HttpMethod.POST,
                url=f"{self._settings.embed_worker_url}/tasks/github/fetch",
                headers={"Content-Type": "application/json"},
                body=json.dumps(payload).encode(),
                oidc_token=tasks_v2.OidcToken(
                    service_account_email=f"{self._settings.gcp_project}@appspot.gserviceaccount.com",
                ),
            ),
        )
        
        self._client.create_task(
            parent=self._get_queue_path(),
            task=task,
        )
        
        logger.info(f"Cloud Task created: {task_name} for GitHub fetch")
        return job_id
    
    async def cancel_user_tasks(self, user_id: UUID) -> int:
        """
        Cancels all pending tasks for a user.
        Used when profile is deleted to prevent orphaned job updates.
        Returns count of cancelled tasks.
        """
        user_prefix = str(user_id)
        cancelled_count = 0
        
        if self._mock_mode:
            tasks_to_remove = [
                name for name in self._mock_tasks
                if user_prefix in name
            ]
            for task_name in tasks_to_remove:
                del self._mock_tasks[task_name]
                cancelled_count += 1
            
            logger.info(f"Mock: Cancelled {cancelled_count} tasks for user {user_id}")
            return cancelled_count
        
        from google.api_core import exceptions as gcp_exceptions
        
        try:
            tasks = self._client.list_tasks(parent=self._get_queue_path())
            
            for task in tasks:
                if user_prefix in task.name:
                    try:
                        self._client.delete_task(name=task.name)
                        cancelled_count += 1
                    except gcp_exceptions.NotFound:
                        pass
            
            logger.info(f"Cancelled {cancelled_count} Cloud Tasks for user {user_id}")
            
        except Exception as e:
            logger.warning(f"Error cancelling tasks for user {user_id}: {e}")
        
        return cancelled_count
    
    def get_mock_tasks(self) -> dict[str, dict]:
        """Returns mock tasks for testing. Only available in mock mode."""
        if not self._mock_mode:
            raise RuntimeError("get_mock_tasks only available in mock mode")
        return self._mock_tasks.copy()
    
    def clear_mock_tasks(self) -> None:
        """Clears mock tasks for testing. Only available in mock mode."""
        if not self._mock_mode:
            raise RuntimeError("clear_mock_tasks only available in mock mode")
        self._mock_tasks.clear()


_client_instance: Optional[CloudTasksClient] = None


def get_cloud_tasks_client() -> CloudTasksClient:
    """Returns singleton Cloud Tasks client."""
    global _client_instance
    
    if _client_instance is None:
        _client_instance = CloudTasksClient()
    
    return _client_instance


async def enqueue_resume_task(
    user_id: UUID,
    file_bytes: bytes,
    filename: str,
    content_type: Optional[str] = None,
) -> str:
    """Convenience function for enqueueing resume tasks."""
    client = get_cloud_tasks_client()
    return await client.enqueue_resume_task(user_id, file_bytes, filename, content_type)


async def enqueue_github_task(user_id: UUID) -> str:
    """Convenience function for enqueueing GitHub tasks."""
    client = get_cloud_tasks_client()
    return await client.enqueue_github_task(user_id)


async def cancel_user_tasks(user_id: UUID) -> int:
    """Convenience function for cancelling user tasks."""
    client = get_cloud_tasks_client()
    return await client.cancel_user_tasks(user_id)


def reset_client_for_testing() -> None:
    """Resets the singleton client for testing."""
    global _client_instance
    _client_instance = None


__all__ = [
    "CloudTasksClient",
    "get_cloud_tasks_client",
    "enqueue_resume_task",
    "enqueue_github_task",
    "cancel_user_tasks",
    "reset_client_for_testing",
]

