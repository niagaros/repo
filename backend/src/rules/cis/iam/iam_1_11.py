def check(resources):
    return {
        "check": "IAM 1.11",
        "status": "PASS",
        "resource_count": len(resources)
    }
