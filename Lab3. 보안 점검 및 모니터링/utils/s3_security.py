import boto3
from botocore.exceptions import ClientError

def get_s3_security_issues(session):
    """S3 버킷의 보안 이슈를 스캔합니다."""
    s3_client = session.client('s3')
    s3_control = session.client('s3control')
    
    try:
        # 계정 ID 가져오기
        sts_client = session.client('sts')
        account_id = sts_client.get_caller_identity()["Account"]
    except Exception as e:
        print(f"계정 ID 가져오기 실패: {e}")
        account_id = None
    
    issues = []
    
    try:
        # 모든 버킷 목록 가져오기
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            bucket_issues = []
            
            # 1. 퍼블릭 액세스 설정 확인
            try:
                public_access = s3_client.get_public_access_block(Bucket=bucket_name)
                block_config = public_access.get('PublicAccessBlockConfiguration', {})
                
                if not all([
                    block_config.get('BlockPublicAcls', False),
                    block_config.get('BlockPublicPolicy', False),
                    block_config.get('IgnorePublicAcls', False),
                    block_config.get('RestrictPublicBuckets', False)
                ]):
                    bucket_issues.append({
                        'issue_type': 'PUBLIC_ACCESS_SETTINGS',
                        'severity': 'HIGH',
                        'description': '버킷의 퍼블릭 액세스 차단 설정이 완전히 활성화되지 않았습니다.'
                    })
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    bucket_issues.append({
                        'issue_type': 'PUBLIC_ACCESS_SETTINGS',
                        'severity': 'HIGH',
                        'description': '버킷에 퍼블릭 액세스 차단 설정이 구성되지 않았습니다.'
                    })
                else:
                    print(f"버킷 {bucket_name}의 퍼블릭 액세스 설정 확인 실패: {e}")
            
            # 2. 버킷 정책 확인
            try:
                policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                # 여기서 정책 분석 로직을 추가할 수 있습니다
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    print(f"버킷 {bucket_name}의 정책 확인 실패: {e}")
            
            # 3. 버킷 암호화 확인
            try:
                encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
            except ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    bucket_issues.append({
                        'issue_type': 'ENCRYPTION',
                        'severity': 'MEDIUM',
                        'description': '버킷에 기본 암호화가 구성되지 않았습니다.'
                    })
                else:
                    print(f"버킷 {bucket_name}의 암호화 설정 확인 실패: {e}")
            
            # 4. 버킷 버전 관리 확인
            try:
                versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                if versioning.get('Status') != 'Enabled':
                    bucket_issues.append({
                        'issue_type': 'VERSIONING',
                        'severity': 'LOW',
                        'description': '버킷에 버전 관리가 활성화되지 않았습니다.'
                    })
            except ClientError as e:
                print(f"버킷 {bucket_name}의 버전 관리 설정 확인 실패: {e}")
            
            # 5. 로깅 설정 확인
            try:
                logging = s3_client.get_bucket_logging(Bucket=bucket_name)
                if 'LoggingEnabled' not in logging:
                    bucket_issues.append({
                        'issue_type': 'LOGGING',
                        'severity': 'LOW',
                        'description': '버킷에 액세스 로깅이 활성화되지 않았습니다.'
                    })
            except ClientError as e:
                print(f"버킷 {bucket_name}의 로깅 설정 확인 실패: {e}")
            
            # 이슈가 있는 경우 추가
            if bucket_issues:
                for issue in bucket_issues:
                    issues.append({
                        'resource_type': 'S3_BUCKET',
                        'resource_id': bucket_name,
                        'title': f"S3 버킷 보안 이슈: {issue['issue_type']}",
                        'severity': issue['severity'],
                        'description': issue['description'],
                        'created_at': bucket['CreationDate'].strftime('%Y-%m-%d %H:%M:%S') if 'CreationDate' in bucket else 'N/A'
                    })
        
        # 계정 수준 퍼블릭 액세스 설정 확인
        if account_id:
            try:
                account_public_access = s3_control.get_public_access_block(AccountId=account_id)
                account_block_config = account_public_access.get('PublicAccessBlockConfiguration', {})
                
                if not all([
                    account_block_config.get('BlockPublicAcls', False),
                    account_block_config.get('BlockPublicPolicy', False),
                    account_block_config.get('IgnorePublicAcls', False),
                    account_block_config.get('RestrictPublicBuckets', False)
                ]):
                    issues.append({
                        'resource_type': 'S3_ACCOUNT_SETTINGS',
                        'resource_id': account_id,
                        'title': 'S3 계정 수준 퍼블릭 액세스 설정 이슈',
                        'severity': 'HIGH',
                        'description': '계정 수준의 S3 퍼블릭 액세스 차단 설정이 완전히 활성화되지 않았습니다.',
                        'created_at': 'N/A'
                    })
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    issues.append({
                        'resource_type': 'S3_ACCOUNT_SETTINGS',
                        'resource_id': account_id,
                        'title': 'S3 계정 수준 퍼블릭 액세스 설정 누락',
                        'severity': 'HIGH',
                        'description': '계정 수준의 S3 퍼블릭 액세스 차단 설정이 구성되지 않았습니다.',
                        'created_at': 'N/A'
                    })
                else:
                    print(f"계정 수준 퍼블릭 액세스 설정 확인 실패: {e}")
    
    except Exception as e:
        print(f"S3 보안 이슈 스캔 중 오류 발생: {e}")
    
    return issues
