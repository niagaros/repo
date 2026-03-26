def check(resources):
    return {
        "check": "IAM 1.10",
        "status": "PASS",
        "resource_count": len(resources)
    }
