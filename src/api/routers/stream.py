"""SSE streaming router."""

import json
from collections.abc import Generator

from fastapi import APIRouter, HTTPException
from starlette.responses import StreamingResponse

from src.api.dependencies import job_queues
from src.utils.logging_config import get_logger

logger = get_logger(__name__)
router = APIRouter()

_HEARTBEAT_SECONDS = 15.0


@router.get("/{job_id}")
def stream_job_status(job_id: str) -> StreamingResponse:
    """Stream job status updates via Server-Sent Events.

    Every client replays the event log from the start, then tails new
    events, so late joiners and reconnects see the full pipeline history.
    """
    if not job_queues.has(job_id):
        raise HTTPException(status_code=404, detail="Job not found")
    stream = job_queues.get(job_id)

    def event_generator() -> Generator[str, None, None]:
        index = 0
        try:
            while True:
                events, index, closed = stream.wait(index, timeout=_HEARTBEAT_SECONDS)
                for event in events:
                    yield f"data: {json.dumps(event)}\n\n"
                if closed:
                    yield f"data: {json.dumps({'type': 'complete'})}\n\n"
                    return
                if not events:
                    yield ": heartbeat\n\n"
        except GeneratorExit:
            logger.info("SSE client disconnected for job %s", job_id)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
