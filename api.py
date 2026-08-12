import threading
import uuid

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from investigator import verify_profiles


app = FastAPI(
    title="AI OSINT System API",
    description="IRONCLAD Cyber Intelligence OSINT Platform",
    version="1.0"
)


# CORS - Allow Frontend Connection
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# In-memory job store: job_id -> job state dict.
# Fine for a single local dev instance. If this API is ever run
# with multiple worker processes, this must move to something
# shared (Redis, a DB, etc), since each worker would otherwise
# have its own separate copy of JOBS.
JOBS = {}
JOBS_LOCK = threading.Lock()


# Request Model
class ScanRequest(BaseModel):
    target: str


def _record_progress(job_id, percent, description):
    """Store every progress event so polling cannot skip fast tools."""

    percent = max(0, min(int(percent), 100))
    event = {
        "percent": percent,
        "description": str(description),
    }

    with JOBS_LOCK:
        job = JOBS[job_id]
        job["percent"] = percent
        job["description"] = event["description"]

        events = job.setdefault("events", [])
        if not events or events[-1] != event:
            events.append(event)



# Home Route
@app.get("/")
def home():

    return {
        "status": "online",
        "message": "IRONCLAD AI OSINT API Running"
    }



def _run_scan_job(job_id: str, target: str):
    """
    Runs the (slow, blocking) OSINT scan in a background thread and
    writes live progress into JOBS[job_id] as each engine finishes,
    using investigator.verify_profiles's progress_callback hook.
    """

    def on_progress(percent, description):
        _record_progress(job_id, percent, description)

    try:
        result = verify_profiles(target, progress_callback=on_progress)

        with JOBS_LOCK:
            JOBS[job_id]["results"] = result
        _record_progress(job_id, 100, "Investigation completed")
        with JOBS_LOCK:
            JOBS[job_id]["done"] = True

    except Exception as exc:
        with JOBS_LOCK:
            JOBS[job_id]["error"] = str(exc)
            percent = JOBS[job_id]["percent"]
        _record_progress(job_id, percent, "Investigation failed")
        with JOBS_LOCK:
            JOBS[job_id]["done"] = True



# Start a scan - returns immediately with a job_id.
# The actual scan runs in the background; poll /status/{job_id}
# to watch real progress and fetch the final result.
@app.post("/scan")
def scan(request: ScanRequest):

    job_id = str(uuid.uuid4())

    with JOBS_LOCK:
        JOBS[job_id] = {
            "target": request.target,
            "percent": 0,
            "description": "Starting OSINT Scan...",
            "done": False,
            "results": None,
            "error": None,
            "events": [],
        }

    thread = threading.Thread(
        target=_run_scan_job,
        args=(job_id, request.target),
        daemon=True
    )
    thread.start()

    return {"job_id": job_id}



# Poll this while a scan is running to get real, live progress.
@app.get("/status/{job_id}")
def status(job_id: str):

    with JOBS_LOCK:
        job = JOBS.get(job_id)

        if job is not None:
            # Return a stable progress snapshot while the scan thread appends
            # events. The frontend can safely consume every unseen event.
            job = {
                **job,
                "events": [dict(event) for event in job.get("events", [])],
            }

    if job is None:
        return {"error": "Invalid or expired job_id"}

    return job
