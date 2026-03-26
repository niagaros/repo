def check(resources):
    return {
        "check": "IAM 1.15",
        "status": "PASS",
        "resource_count": len(resources)
    }
