"""Launch the relay fixture in the process integration test executable."""

import os


def relay_process(config):
    env = os.environ.copy()
    env["NAOME_RELAY_FIXTURE_CONFIG"] = str(config)
    return [env["NAOME_RELAY_TEST_EXECUTABLE"], "--exact", "relay_fixture_process", "--ignored", "--nocapture"], env
