"""Celery: scheduled and on-demand scans with retries (FND-07)."""

import os

from celery import Celery
from celery.schedules import crontab

from app.config import get_settings
from app.logging import configure_logging

configure_logging()

celery = Celery("brandintel", broker=get_settings().redis_url, backend=get_settings().redis_url,
                include=["app.workers.tasks"])


celery.conf.update(
    task_always_eager=os.environ.get("CELERY_TASK_ALWAYS_EAGER") == "1",
    task_eager_propagates=True,
    task_default_queue="default",
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_time_limit=60 * 60,
    task_soft_time_limit=55 * 60,
    result_expires=24 * 3600,
    # Unfinished tasks are redelivered after this; keep it above the task time limit to avoid double runs
    broker_transport_options={"visibility_timeout": 2 * 3600},
    timezone="UTC",
    beat_schedule={
        # Daily discovery for every active brand and every module (TYP-12, OBJ-01)
        "daily-full-scan": {"task": "app.workers.tasks.schedule_all", "schedule": crontab(hour=2, minute=0)},
        # Re-check known live / email-enabled domains more often, they change fastest
        "domain-recheck": {"task": "app.workers.tasks.schedule_all",
                           "schedule": crontab(minute=30, hour="*/6"), "kwargs": {"runners": ["domains"]}},
        # Email intake (D-28): reporting mailbox every 5 min, DMARC reports hourly, posture daily
        "poll-reporting-mailbox": {"task": "app.workers.tasks.poll_mailbox", "schedule": crontab(minute="*/5")},
        "poll-dmarc-mailbox": {"task": "app.workers.tasks.poll_dmarc", "schedule": crontab(minute=15)},
        "email-posture": {"task": "app.workers.tasks.schedule_all",
                          "schedule": crontab(hour=3, minute=0), "kwargs": {"runners": ["email_posture"]}},
    },
)
