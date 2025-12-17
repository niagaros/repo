# Niagaros Internal Assessment – AWS Region Usage (Client: Domits)

**Author:** Robin van Dijk  
**Department:** Cloud Security Engineering  
**Date:** 2025-12-03  
**Confidentiality:** Internal Use Only

---

## 1. Purpose
This document summarizes the assessment of **Domits’ AWS regions** to identify active resources, unused regions, and potential areas for optimization or risk reduction.

---

## 2. What Was Done
- Scanned **all AWS regions** for resources using a **read-only AWS CLI script**.
- Checked for the following resource types:
  - **Compute:** EC2, Lambda, ECS, EKS, Auto Scaling Groups
  - **Networking:** VPCs, Subnets, Security Groups, NAT/Internet Gateways, Endpoints
  - **Databases:** RDS, Aurora, DynamoDB, Elasticache, OpenSearch
  - **Application Services:** Amplify, Cognito, API Gateway, AppSync, CloudFormation
  - **Observability:** CloudWatch logs, EventBridge rules, SNS/SQS
  - **Storage:** S3 Buckets (global)
- Collated results per region and identified which regions contain significant resources.

---

## 3. Why It Was Done
- AWS accounts often accumulate resources in multiple regions, which increases:
  - **Cost** (unused services, logs, and endpoints)
  - **Attack surface** (unused but accessible resources)
  - **Audit complexity**  
- Limiting active regions to **1–2 approved regions** reduces risk and simplifies cloud management.
- Provides **baseline data** for the CSPM prototype to detect regional misconfigurations and unused resources.

---

## 4. How It Was Done
- **AWS CLI** commands were executed for all regions to list resources.
- Only **read-only operations** were performed (`describe`/`list` commands).
- Regions with **>0 important resources** (compute, databases, application services) were flagged.
- Global resources like **S3** and **IAM** were checked separately.
- Results were summarized in a table.

```bash
# Scan all AWS regions for important resources
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  echo "==============================="
  echo "Checking region: $region"
  echo "==============================="

  # Compute
  ec2=$(aws ec2 describe-instances --region $region --query 'Reservations[].Instances[]' --output text | wc -l)
  asg=$(aws autoscaling describe-auto-scaling-groups --region $region --query 'AutoScalingGroups' --output text | wc -l)
  lambda=$(aws lambda list-functions --region $region --query 'Functions' --output text | wc -l)
  ecs=$(aws ecs list-clusters --region $region --query 'clusterArns' --output text | wc -l)
  eks=$(aws eks list-clusters --region $region --query 'clusters' --output text | wc -l)

  # Networking
  vpcs=$(aws ec2 describe-vpcs --region $region --query 'Vpcs' --output text | wc -l)
  subnets=$(aws ec2 describe-subnets --region $region --query 'Subnets' --output text | wc -l)
  sg=$(aws ec2 describe-security-groups --region $region --query 'SecurityGroups' --output text | wc -l)
  nat=$(aws ec2 describe-nat-gateways --region $region --query 'NatGateways' --output text | wc -l)
  igw=$(aws ec2 describe-internet-gateways --region $region --query 'InternetGateways' --output text | wc -l)
  vpce=$(aws ec2 describe-vpc-endpoints --region $region --query 'VpcEndpoints' --output text | wc -l)
  eip=$(aws ec2 describe-addresses --region $region --query 'Addresses' --output text | wc -l)

  # Storage & Databases
  ebs=$(aws ec2 describe-volumes --region $region --query 'Volumes' --output text | wc -l)
  dynamodb=$(aws dynamodb list-tables --region $region --query 'TableNames' --output text | wc -l)
  rds=$(aws rds describe-db-instances --region $region --query 'DBInstances' --output text | wc -l)
  aurora=$(aws rds describe-db-clusters --region $region --query 'DBClusters' --output text | wc -l)
  elasticache=$(aws elasticache describe-cache-clusters --region $region --query 'CacheClusters' --output text | wc -l)
  opensearch=$(aws opensearch list-domain-names --region $region --query 'DomainNames' --output text | wc -l)

  # Identity
  cognito_pools=$(aws cognito-idp list-user-pools --region $region --max-results 60 --query 'UserPools' --output text | wc -l)
  cognito_identities=$(aws cognito-identity list-identity-pools --region $region --max-results 60 --query 'IdentityPools' --output text | wc -l)

  # Application Services
  amplify=$(aws amplify list-apps --region $region --query 'apps' --output text | wc -l)
  apigw=$(aws apigateway get-rest-apis --region $region --query 'items' --output text | wc -l)
  apigw2=$(aws apigatewayv2 get-apis --region $region --query 'Items' --output text | wc -l)
  appsync=$(aws appsync list-graphql-apis --region $region --query 'graphqlApis' --output text | wc -l)
  cfn=$(aws cloudformation list-stacks --region $region --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE --query 'StackSummaries' --output text | wc -l)

  # Observability
  logs=$(aws logs describe-log-groups --region $region --query 'logGroups' --output text | wc -l)
  eventbridge=$(aws events list-rules --region $region --query 'Rules' --output text | wc -l)
  sns=$(aws sns list-topics --region $region --query 'Topics' --output text | wc -l)
  sqs=$(aws sqs list-queues --region $region --query 'QueueUrls' --output text | wc -l)

  echo "Compute: EC2=$ec2 ASG=$asg Lambda=$lambda ECS=$ecs EKS=$eks"
  echo "Network: VPC=$vpcs Subnets=$subnets SG=$sg NAT=$nat IGW=$igw VPCe=$vpce EIP=$eip"
  echo "Storage/DB: EBS=$ebs DynamoDB=$dynamodb RDS=$rds Aurora=$aurora Elasticache=$elasticache OpenSearch=$opensearch"
  echo "Identity: CognitoUserPools=$cognito_pools IdentityPools=$cognito_identities"
  echo "Application: Amplify=$amplify APIGW=$apigw/$apigw2 AppSync=$appsync CFN=$cfn"
  echo "Observability: Logs=$logs EventBridge=$eventbridge SNS=$sns SQS=$sqs"
  echo "---------------------------------------------------------------"
done

# Global check for S3
aws s3api list-buckets --query 'Buckets[].Name'



## 5. Recommendations
1. **Keep only approved regions active:**  
   - eu-north-1 (primary workloads)  
   - us-east-1 (AWS global services)
2. **Double check region**
   - eu-west-1 (Has open AWS and cloudformation)
2. **Disable all other regions** to reduce cost and security risk.
3. **Implement recurring region audits** via CSPM:
   - Weekly scan
   - Alert for new or unexpected regions
4. Optional: Clean up unused resources (EBS volumes, CloudWatch logs, default VPC endpoints).

---

## 6. Conclusion

After performing a full resource inventory across all AWS regions using automated scanning and manual verification, the following conclusions were reached:

- **Only two regions contain active and relevant resources:**  
  **eu-north-1** and **us-east-1**.  
  These regions host the operational workloads such as Lambda functions, API Gateway, Cognito, Amplify, CloudFormation, and logging services.

- **The region eu-west-1 required additional verification** because a CloudFormation stack (`amplify-domits-dev-a219c`) was detected.  
  After further inspection, this stack was identified as an unused **development Amplify environment**, with no active deployments, domains, or linked services.  
  It was confirmed safe to disable.

- **All remaining regions contained only empty network defaults** (VPC, Subnets, Security Groups) and no compute, database, identity, or application services.  
  These regions were validated as unused and have been **safely disabled** to reduce cost, attack surface, and operational complexity.

**Outcome:**  
The AWS environment now operates exclusively in **eu-north-1** and **us-east-1**, with all other regions disabled for security and cost optimization.

