```bash
# AMP 작업 공간 생성
# aws amp create-workspace --alias amazon-q-prometheus-workspace --region us-east-1
aws amp create-workspace --alias amazon-q-prometheus-workspace --region us-west-2
```

```bash
### AMG role 생성
# 1. 신뢰 정책 파일 생성
cat > grafana-trust-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "grafana.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

# 2. 권한 정책 파일 생성 (CloudWatch, Prometheus 등 기본 데이터 소스에 대한 접근 권한)
cat > grafana-permissions-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudwatch:DescribeAlarmsForMetric",
        "cloudwatch:DescribeAlarmHistory",
        "cloudwatch:DescribeAlarms",
        "cloudwatch:ListMetrics",
        "cloudwatch:GetMetricStatistics",
        "cloudwatch:GetMetricData",
        "logs:StartQuery",
        "logs:StopQuery",
        "logs:GetQueryResults",
        "logs:GetLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "ec2:DescribeTags",
        "ec2:DescribeInstances",
        "ec2:DescribeRegions",
        "tag:GetResources",
        "aps:QueryMetrics",
        "aps:GetLabels",
        "aps:GetSeries",
        "aps:GetMetricMetadata"
      ],
      "Resource": "*"
    }
  ]
}
EOF

# 3. IAM 역할 생성
aws iam create-role \
  --role-name GrafanaWorkspaceRole \
  --assume-role-policy-document file://grafana-trust-policy.json

# 4. 권한 정책을 역할에 연결
aws iam create-policy \
  --policy-name GrafanaWorkspacePolicy \
  --policy-document file://grafana-permissions-policy.json

# 5. 생성된 정책 ARN 가져오기 (리전과 계정 ID에 따라 다름)
POLICY_ARN=$(aws iam list-policies --query 'Policies[?PolicyName==`GrafanaWorkspacePolicy`].Arn' --output text)

# 6. 정책을 역할에 연결
aws iam attach-role-policy \
  --role-name GrafanaWorkspaceRole \
  --policy-arn $POLICY_ARN

# 7. 역할 ARN 출력 (이 ARN을 Grafana 워크스페이스 생성 시 사용)
aws iam get-role --role-name GrafanaWorkspaceRole --query 'Role.Arn' --output text

### AMG 작업 공간 생성
### 성공 (SAML)
aws grafana create-workspace \
  --workspace-name amazon-q-grafana-workspace \
  --authentication-providers SAML \
  --permission-type SERVICE_MANAGED \
  --account-access-type CURRENT_ACCOUNT \
  --workspace-role-arn arn:aws:iam::888191491481:role/GrafanaWorkspaceRole \
  --region us-west-2


### AWS_SSO 활성화
활성화 권한 문제로 제한적

### AWS SSO
aws grafana create-workspace \
  --workspace-name amazon-q-grafana-workspace-1 \
  --authentication-providers AWS_SSO \
  --permission-type SERVICE_MANAGED \
  --account-access-type CURRENT_ACCOUNT \
  --workspace-role-arn arn:aws:iam::888191491481:role/GrafanaWorkspaceRole \
  --region us-west-2
```
