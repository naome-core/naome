"""Registered outcomes for local and public test evidence."""
from enum import IntEnum


class FixtureResult(IntEnum):
    PASS = 0x003F_0001
    FAIL = 0x003F_0002
    RUNNING = 0x003F_0003
