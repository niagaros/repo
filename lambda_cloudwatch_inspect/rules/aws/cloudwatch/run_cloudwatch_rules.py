import json
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from cloudwatch_1 import CloudWatch1Check
from cloudwatch_2 import CloudWatch2Check
from cloudwatch_3 import CloudWatch3Check
from cloudwatch_4 import CloudWatch4Check
from cloudwatch_5 import CloudWatch5Check
from cloudwatch_6 import CloudWatch6Check
from cloudwatch_7 import CloudWatch7Check
from cloudwatch_8 import CloudWatch8Check
from cloudwatch_9 import CloudWatch9Check
from cloudwatch_10 import CloudWatch10Check
from cloudwatch_11 import CloudWatch11Check
from cloudwatch_12 import CloudWatch12Check
from cloudwatch_13 import CloudWatch13Check
from cloudwatch_14 import CloudWatch14Check

SNAPSHOT_PATH = r"C:\Users\danii\OneDrive - HvA\Stage Niagaros\repo\out\cloudwatch-snapshot-115462458880-eu-north-1.json"

with open(SNAPSHOT_PATH) as f:
    snapshot = json.load(f)

for Check in [
    CloudWatch1Check, CloudWatch2Check, CloudWatch3Check,
    CloudWatch4Check, CloudWatch5Check, CloudWatch6Check,
    CloudWatch7Check, CloudWatch8Check, CloudWatch9Check,
    CloudWatch10Check, CloudWatch11Check, CloudWatch12Check,
    CloudWatch13Check, CloudWatch14Check]:
    result = Check().evaluate(snapshot)
    print(json.dumps(result.to_dict(), indent=2))
    print()