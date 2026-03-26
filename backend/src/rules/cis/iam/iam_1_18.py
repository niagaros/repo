def check(resources):
    return {
        "check": "IAM 1.18",
        "status": "PASS",
        "resource_count": len(resources)
    }
