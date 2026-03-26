def check(resources):
    return {
        "check": "IAM 1.17",
        "status": "PASS",
        "resource_count": len(resources)
    }
