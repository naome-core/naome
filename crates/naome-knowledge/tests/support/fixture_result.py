"""Registered outcomes for local and public test evidence."""
from enum import IntEnum


class FixtureResult(IntEnum):
    PASS = 0x003F_0001
    FAIL = 0x003F_0002
    RUNNING = 0x003F_0003


class ResourceProfile(IntEnum):
    DYNAMIC = 0x004C_0001
    HEAVY = 0x004C_0002
    LIGHT = 0x004C_0003
    CUSTOM = 0x004C_0004
