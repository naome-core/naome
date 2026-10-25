"""Developer-build process evidence from the live owner's bounded log."""


def latest(node):
    return next((event for event in reversed(node.logs())
                 if event.get("event") == "resource_observation"
                 and event["snapshot"]["pid"] == node.process["pid"]), None)
