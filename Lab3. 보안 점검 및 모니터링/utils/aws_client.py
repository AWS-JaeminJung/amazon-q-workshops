import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timedelta

def create_aws_session(use_profile=False, profile_name=None, access_key=None, secret_key=None, region="ap-northeast-2"):
    """Create AWS session based on provided credentials or instance profile"""
    if use_profile and profile_name:
        return boto3.Session(profile_name=profile_name, region_name=region)
    elif access_key and secret_key:
        return boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
    else:
        # 인스턴스 프로파일 사용 (자동 인증)
        return boto3.Session(region_name=region)

def get_iam_info(session):
    """Get IAM account information with error handling"""
    iam = session.client('iam')
    result = {
        'account_summary': {},
        'users': [],
        'roles': [],
        'groups': [],
        'policies': [],
        'users_without_mfa': []
    }
    
    # Get account summary
    try:
        account_summary = iam.get_account_summary()
        result['account_summary'] = account_summary.get('SummaryMap', {})
    except Exception as e:
        print(f"계정 요약 정보 가져오기 실패: {e}")
    
    # Get users
    try:
        users = iam.list_users().get('Users', [])
        result['users'] = users
        
        # Find users without MFA
        for user in users:
            try:
                mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])
                if not mfa_devices.get('MFADevices'):
                    result['users_without_mfa'].append(user['UserName'])
            except Exception as e:
                print(f"MFA 정보 가져오기 실패 (사용자: {user['UserName']}): {e}")
    except Exception as e:
        print(f"사용자 정보 가져오기 실패: {e}")
    
    # Get roles
    try:
        result['roles'] = iam.list_roles().get('Roles', [])
    except Exception as e:
        print(f"역할 정보 가져오기 실패: {e}")
    
    # Get groups
    try:
        result['groups'] = iam.list_groups().get('Groups', [])
    except Exception as e:
        print(f"그룹 정보 가져오기 실패: {e}")
    
    # Get policies
    try:
        result['policies'] = iam.list_policies(Scope='Local').get('Policies', [])
    except Exception as e:
        print(f"정책 정보 가져오기 실패: {e}")
    
    return result

def get_cloudtrail_events(session, days=7):
    """Get CloudTrail events for the specified number of days"""
    cloudtrail = session.client('cloudtrail')
    
    try:
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Get events
        events = []
        response = cloudtrail.lookup_events(
            StartTime=start_date,
            EndTime=end_date
        )
        events.extend(response.get('Events', []))
        
        # Get additional pages if available
        while 'NextToken' in response and len(events) < 100:
            response = cloudtrail.lookup_events(
                NextToken=response['NextToken'],
                StartTime=start_date,
                EndTime=end_date
            )
            events.extend(response.get('Events', []))
        
        return events
    except Exception as e:
        print(f"CloudTrail 이벤트 가져오기 실패: {e}")
        return []
