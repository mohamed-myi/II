from datetime import datetime, timezone
from typing import Literal, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field

from src.middleware.auth import require_auth
from models.identity import User, Session
from src.services.recommendation_event_service import (
    RecommendationEvent,
    get_recommendation_batch_context,
    enqueue_recommendation_events,
)


router = APIRouter()


class RecommendationEventInput(BaseModel):
    event_id: UUID
    event_type: Literal["impression", "click"]
    issue_node_id: str = Field(..., min_length=1, max_length=200)
    position: int = Field(..., ge=1)
    surface: str = Field(default="feed", min_length=1, max_length=50)
    occurred_at: Optional[datetime] = None
    metadata: Optional[dict] = None


class RecommendationEventsRequest(BaseModel):
    recommendation_batch_id: UUID
    events: list[RecommendationEventInput] = Field(..., min_length=1, max_length=200)


@router.post("/events", status_code=204)
async def log_recommendation_events(
    body: RecommendationEventsRequest,
    auth: tuple[User, Session] = Depends(require_auth),
) -> Response:
    user, _ = auth

    context = await get_recommendation_batch_context(body.recommendation_batch_id)
    if context is None:
        raise HTTPException(status_code=404, detail="Unknown or expired recommendation_batch_id")

    now = datetime.now(timezone.utc)
    events: list[RecommendationEvent] = []

    for ev in body.events:
        created_at = ev.occurred_at or now
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)

        events.append(
            RecommendationEvent(
                event_id=ev.event_id,
                recommendation_batch_id=body.recommendation_batch_id,
                event_type=ev.event_type,
                issue_node_id=ev.issue_node_id,
                position=ev.position,
                surface=ev.surface,
                created_at=created_at,
                metadata=ev.metadata,
            )
        )

    try:
        await enqueue_recommendation_events(
            user_id=user.id,
            context=context,
            events=events,
        )
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Redis unavailable")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid event for recommendation batch")

    return Response(status_code=204)


