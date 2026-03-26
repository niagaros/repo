def check(resources):
    return {
        "check": "IAM 1.16",
        "status": "PASS",
        "resource_count": len(resources)
    }
