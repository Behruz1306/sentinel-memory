"""Security event logging — AWS CloudWatch with a local fallback.

Breaches and access decisions are logged here. If boto3 + AWS credentials are
present, events go to a CloudWatch Logs stream; otherwise they go to a local
JSONL file and colored stderr so the demo always shows the red alert.

Env:
  SENTINEL_CLOUDWATCH=1                enable CloudWatch (default: auto if boto3+creds)
  SENTINEL_LOG_GROUP=/sentinel/security
  AWS_REGION / AWS_DEFAULT_REGION
"""

from __future__ import annotations

import json
import os
import sys
import time

_RED = "\033[91m"
_YEL = "\033[93m"
_DIM = "\033[2m"
_X = "\033[0m"

_LOCAL_LOG = os.path.join(os.path.dirname(__file__), "..", "..", "security_events.jsonl")


class SecurityLogger:
    def __init__(self):
        self._cw = None
        self._group = os.getenv("SENTINEL_LOG_GROUP", "/sentinel/security")
        self._stream = "session-" + time.strftime("%Y%m%d")
        self._init_cloudwatch()

    def _init_cloudwatch(self):
        if os.getenv("SENTINEL_CLOUDWATCH", "auto") == "0":
            return
        try:
            import boto3  # optional dependency

            region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
            self._cw = boto3.client("logs", region_name=region) if region else boto3.client("logs")
            self._ensure_stream()
        except Exception:
            self._cw = None  # no creds / no boto3 -> local fallback

    def _ensure_stream(self):
        if not self._cw:
            return
        try:
            self._cw.create_log_group(logGroupName=self._group)
        except Exception:
            pass
        try:
            self._cw.create_log_stream(logGroupName=self._group, logStreamName=self._stream)
        except Exception:
            pass

    @property
    def sink(self) -> str:
        return "AWS CloudWatch" if self._cw else "local (security_events.jsonl)"

    def _emit(self, event: dict):
        event = {"ts": int(time.time() * 1000), **event}
        # CloudWatch
        if self._cw:
            try:
                self._cw.put_log_events(
                    logGroupName=self._group,
                    logStreamName=self._stream,
                    logEvents=[{"timestamp": event["ts"], "message": json.dumps(event)}],
                )
            except Exception:
                pass
        # Local JSONL fallback (always written for auditability)
        try:
            with open(os.path.abspath(_LOCAL_LOG), "a") as f:
                f.write(json.dumps(event) + "\n")
        except Exception:
            pass

    def breach(self, message: str, **fields):
        self._emit({"level": "RED_ALERT", "message": message, **fields})
        sys.stderr.write(f"{_RED}🚨 RED ALERT [{self.sink}] {message}{_X}\n")
        if fields:
            sys.stderr.write(f"{_DIM}   {json.dumps(fields)}{_X}\n")

    def warn(self, message: str, **fields):
        self._emit({"level": "WARN", "message": message, **fields})
        sys.stderr.write(f"{_YEL}⚠️  {message}{_X}\n")

    def info(self, message: str, **fields):
        self._emit({"level": "INFO", "message": message, **fields})


# module-level singleton
security_log = SecurityLogger()
