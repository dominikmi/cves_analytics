"""SSE streaming router."""

import json
from collections.abc import Generator
from queue import Empty, Queue
from typing import Any

from fastapi import APIRouter, HTTPException
from starlette.responses import StreamingResponse

from src.api.dependencies import job_queues
from src.utils.logging_config import get_logger

logger = get_logger(__name__)
router = APIRouter()


@router.get("/{job_id}")
def stream_job_status(job_id: str) -> StreamingResponse:
    """Stream job status updates via Server-Sent Events."""
    queue: Queue[Any] | None = (
        job_queues.get(job_id) if job_queues.has(job_id) else None
    )
    if queue is None:
        raise HTTPException(status_code=404, detail="Job not found")

    def event_generator() -> Generator[str, None, None]:
        try:
            while True:
                try:
                    message = queue.get(timeout=1)
                    if message is None:
                        yield f"data: {json.dumps({'type': 'complete'})}\n\n"
                        break
                    yield f"data: {json.dumps(message)}\n\n"
                except Empty:
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
