"""Serialize policy editing across GUI workers and background publishers."""
import asyncio
import fcntl
import time
from contextlib import contextmanager
from fastapi import HTTPException, Request
from app.config import DATA_ROOT

PATH = DATA_ROOT/'policy-edit.lock'


@contextmanager
def policy_edit_lock():
    PATH.parent.mkdir(parents=True,exist_ok=True)
    with PATH.open('a+') as stream:
        fcntl.flock(stream.fileno(),fcntl.LOCK_EX)
        try:yield
        finally:fcntl.flock(stream.fileno(),fcntl.LOCK_UN)


async def policy_guard(request:Request):
    if request.method not in ('POST','PUT','PATCH','DELETE'):
        yield
        return
    PATH.parent.mkdir(parents=True,exist_ok=True)
    with PATH.open('a+') as stream:
        deadline=time.monotonic()+30
        while True:
            try:
                fcntl.flock(stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic()>=deadline:
                    raise HTTPException(503,'Another policy change is running. Retry shortly.',headers={'Retry-After':'5'})
                await asyncio.sleep(.05)
        try:yield
        finally:fcntl.flock(stream.fileno(),fcntl.LOCK_UN)
