import json

from collectors.aws.iam.collector import IAMCollector

from rules.cis.iam.iam_1_4 import check as check_1_4
from rules.cis.iam.iam_1_5 import check as check_1_5
from rules.cis.iam.iam_1_6 import check as check_1_6
from rules.cis.iam.iam_1_8 import check as check_1_8
from rules.cis.iam.iam_1_9 import check as check_1_9
from rules.cis.iam.iam_1_10 import check as check_1_10
from rules.cis.iam.iam_1_11 import check as check_1_11
from rules.cis.iam.iam_1_15 import check as check_1_15
from rules.cis.iam.iam_1_16 import check as check_1_16
from rules.cis.iam.iam_1_17 import check as check_1_17
from rules.cis.iam.iam_1_18 import check as check_1_18


def run_checks(resources):

    checks = [
        check_1_4,
        check_1_5,
        check_1_6,
        check_1_8,
        check_1_9,
        check_1_10,
        check_1_11,
        check_1_15,
        check_1_16,
        check_1_17,
        check_1_18
    ]

    results = []

    for check in checks:

        try:
            result = check(resources)
            results.append(result)

        except Exception as e:

            results.append({
                "check": check.__name__,
                "error": str(e)
            })

    return results


def main():

    print("Starting IAM local test")

    collector = IAMCollector()

    resources = collector.collect()

    print("Collected resources:", len(resources))

    results = run_checks(resources)

    print("\nIAM CHECK RESULTS\n")

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()