from fastapi import APIRouter, Depends, Header, HTTPException
from sqlmodel.ext.asyncio.session import AsyncSession

from src.api.dependencies import get_db
from src.core.config import get_settings
from src.services.recommendation_event_service import flush_recommendation_event_queue_once


router = APIRouter()


@router.post("/recommendations/flush")
async def flush_recommendation_events(
    x_reco_flush_secret: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
) -> dict:
    settings = get_settings()

    if not settings.reco_flush_secret:
        raise HTTPException(status_code=503, detail="Flush secret not configured")

    if x_reco_flush_secret != settings.reco_flush_secret:
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        result = await flush_recommendation_event_queue_once(
            db=db,
            batch_size=settings.reco_events_flush_batch_size,
        )
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Redis unavailable")

    return result


