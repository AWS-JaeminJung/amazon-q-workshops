import streamlit as st
import pandas as pd
from datetime import datetime
from utils.aws_client import create_aws_session, get_iam_info, get_cloudtrail_events
from utils.s3_security import get_s3_security_issues
from utils.waf_security import get_waf_security_issues
from utils.guardduty_security import get_guardduty_findings, format_guardduty_findings, get_guardduty_status

# Page configuration
st.set_page_config(page_title="AWS Security Dashboard", page_icon="🔒", layout="wide")

# Load CSS
with open('styles/main.css') as f:
    st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

# Initialize session state variables
if 'scan_completed' not in st.session_state:
    st.session_state.scan_completed = False
if 'account_id' not in st.session_state:
    st.session_state.account_id = ""
if 'access_key' not in st.session_state:
    st.session_state.access_key = ""
if 'secret_key' not in st.session_state:
    st.session_state.secret_key = ""
if 'aws_region' not in st.session_state:
    st.session_state.aws_region = "ap-northeast-2"
if 'validated' not in st.session_state:
    st.session_state.validated = False
if 'use_instance_profile' not in st.session_state:
    st.session_state.use_instance_profile = False
if 's3_issues' not in st.session_state:
    st.session_state.s3_issues = []
if 'waf_issues' not in st.session_state:
    st.session_state.waf_issues = []
if 'guardduty_findings' not in st.session_state:
    st.session_state.guardduty_findings = []
if 'guardduty_status' not in st.session_state:
    st.session_state.guardduty_status = {'status': 'UNKNOWN', 'message': '아직 스캔되지 않음'}

# Sidebar
with st.sidebar:
    st.markdown("<h1 style='margin-top:0; font-size:1.5rem; color:#FF9900;'>AWS Security Dashboard</h1>", unsafe_allow_html=True)
    
    # Account information
    st.markdown("<p class='account-info-text'>계정 정보</p>", unsafe_allow_html=True)
    
    # 인스턴스 프로파일 사용 옵션 추가
    use_instance_profile = st.checkbox("인스턴스 프로파일 사용", value=st.session_state.use_instance_profile)
    st.session_state.use_instance_profile = use_instance_profile
    
    if not st.session_state.validated:
        if use_instance_profile:
            # 인스턴스 프로파일 사용 시 리전만 선택
            aws_region = st.selectbox("AWS 리전", ["ap-northeast-2", "us-east-1", "us-west-2"], key="input_aws_region")
            
            login_col1, login_col2 = st.columns(2)
            with login_col1:
                validate_button = st.button("인스턴스 프로파일 검증", use_container_width=True)
            with login_col2:
                scan_button = st.button("보안 스캔 시작", use_container_width=True)
                
            if validate_button:
                try:
                    # 인스턴스 프로파일로 세션 생성
                    session = create_aws_session(use_profile=False, profile_name=None, access_key=None, secret_key=None, region=aws_region)
                    # 계정 ID 가져오기
                    sts_client = session.client('sts')
                    account_id = sts_client.get_caller_identity()["Account"]
                    
                    # 세션 상태에 저장
                    st.session_state.account_id = account_id
                    st.session_state.aws_region = aws_region
                    st.session_state.use_instance_profile = True
                    st.session_state.validated = True
                    st.rerun()
                except Exception as e:
                    st.error(f"인스턴스 프로파일 검증 실패: {e}")
        else:
            # 기존 방식 - 계정 정보 직접 입력
            account_id = st.text_input("AWS 계정 ID", placeholder="123456789012", key="input_account_id")
            access_key = st.text_input("AWS Access Key ID", type="password", key="input_access_key")
            secret_key = st.text_input("AWS Secret Access Key", type="password", key="input_secret_key")
            aws_region = st.selectbox("AWS 리전", ["ap-northeast-2", "us-east-1", "us-west-2"], key="input_aws_region")
            
            login_col1, login_col2 = st.columns(2)
            with login_col1:
                validate_button = st.button("계정 검증", use_container_width=True)
            with login_col2:
                scan_button = st.button("보안 스캔 시작", use_container_width=True)
                
            if validate_button:
                if not account_id:
                    st.error("AWS 계정 ID를 입력해주세요.")
                elif not access_key or not secret_key:
                    st.error("AWS Access Key와 Secret Key를 모두 입력해주세요.")
                else:
                    # 세션 상태에 계정 정보 저장
                    st.session_state.account_id = account_id
                    st.session_state.aws_region = aws_region
                    st.session_state.access_key = access_key
                    st.session_state.secret_key = secret_key
                    st.session_state.validated = True
                    st.rerun()
    else:
        # 검증된 상태일 때 계정 정보 표시
        st.success(f"계정 ID: {st.session_state.account_id}")
        if not st.session_state.use_instance_profile:
            st.info("Access Key: ********")
        st.info(f"리전: {st.session_state.aws_region}")
        st.info(f"인증 방식: {'인스턴스 프로파일' if st.session_state.use_instance_profile else '액세스 키'}")
        
        reset_col1, reset_col2 = st.columns(2)
        with reset_col1:
            reset_button = st.button("계정 초기화", use_container_width=True)
        with reset_col2:
            scan_button = st.button("보안 스캔 시작", use_container_width=True)
            
        if reset_button:
            st.session_state.validated = False
            st.rerun()

# Main content
st.markdown('<h1 class="dashboard-title">AWS Security Dashboard</h1>', unsafe_allow_html=True)
st.markdown(f'<p class="last-scan">마지막 스캔: {datetime.now().strftime("%Y년 %m월 %d일 %H:%M")}</p>', unsafe_allow_html=True)

# Tabs
tabs = st.tabs(["👥 IAM 계정 현황", "📜 CloudTrail 로그", "⚠️ 발견 사항", "📝 권장 조치"])

# Scan button handler
if scan_button:
    try:
        with st.spinner("AWS 계정 정보를 가져오는 중입니다..."):
            # 인스턴스 프로파일 또는 입력된 자격 증명으로 세션 생성
            if st.session_state.use_instance_profile:
                aws_region = st.session_state.get("aws_region", "ap-northeast-2")
                session = create_aws_session(use_profile=False, profile_name=None, access_key=None, secret_key=None, region=aws_region)
            else:
                # 계정 검증 상태에 따라 계정 정보 가져오기
                if not st.session_state.validated:
                    account_id = st.session_state.get("input_account_id", "")
                    aws_region = st.session_state.get("input_aws_region", "ap-northeast-2")
                    access_key = st.session_state.get("input_access_key", "")
                    secret_key = st.session_state.get("input_secret_key", "")
                    
                    if not account_id:
                        st.sidebar.error("AWS 계정 ID를 입력해주세요.")
                        raise ValueError("AWS 계정 ID가 필요합니다.")
                    elif not access_key or not secret_key:
                        st.sidebar.error("AWS Access Key와 Secret Key를 모두 입력해주세요.")
                        raise ValueError("AWS 자격 증명이 필요합니다.")
                else:
                    account_id = st.session_state.account_id
                    aws_region = st.session_state.aws_region
                    access_key = st.session_state.access_key
                    secret_key = st.session_state.secret_key
                
                session = create_aws_session(use_profile=False, profile_name=None, access_key=access_key, secret_key=secret_key, region=aws_region)
            
            # Get IAM information
            iam_info = get_iam_info(session)
            st.session_state.iam_info = iam_info
            
            # Get CloudTrail events
            cloudtrail_events = get_cloudtrail_events(session)
            st.session_state.cloudtrail_events = cloudtrail_events
            
            # Get S3 security issues
            try:
                s3_issues = get_s3_security_issues(session)
                st.session_state.s3_issues = s3_issues
            except Exception as e:
                st.session_state.s3_issues = []
                print(f"S3 보안 이슈 스캔 실패: {e}")
            
            # Get WAF security issues
            try:
                waf_issues = get_waf_security_issues(session)
                st.session_state.waf_issues = waf_issues
            except Exception as e:
                st.session_state.waf_issues = []
                print(f"WAF 보안 이슈 스캔 실패: {e}")
            
            # Get GuardDuty findings
            try:
                guardduty_findings = get_guardduty_findings(session)
                st.session_state.guardduty_findings = format_guardduty_findings(guardduty_findings)
                
                # GuardDuty 상태 확인
                guardduty_status = get_guardduty_status(session)
                st.session_state.guardduty_status = guardduty_status
            except Exception as e:
                st.session_state.guardduty_findings = []
                st.session_state.guardduty_status = {'status': 'ERROR', 'message': str(e)}
                print(f"GuardDuty 정보 가져오기 실패: {e}")
            
            # Set scan completed flag
            st.session_state.scan_completed = True
            
            # Show success message
            st.sidebar.success(f"AWS 계정 정보를 성공적으로 가져왔습니다.")
            st.sidebar.info(f"사용자: {len(iam_info['users'])}명, 역할: {len(iam_info['roles'])}개, 그룹: {len(iam_info['groups'])}개")
            if 'users_without_mfa' in iam_info and iam_info['users_without_mfa']:
                st.sidebar.warning(f"MFA가 없는 사용자: {len(iam_info['users_without_mfa'])}명")
    
    except Exception as e:
        st.sidebar.error(f"오류 발생: {e}")

# IAM Account Status tab
with tabs[0]:
    st.markdown('<div class="card"><div class="card-header">IAM 계정 현황</div><div class="card-content">', unsafe_allow_html=True)
    if not st.session_state.scan_completed:
        st.info("보안 스캔을 시작하여 IAM 계정 정보를 가져오세요.")
    else:
        iam_info = st.session_state.iam_info
        
        # Users Card
        st.markdown('<div class="card"><div class="card-header">IAM 사용자</div><div class="card-content">', unsafe_allow_html=True)
        if iam_info['users']:
            users_data = [{
                '사용자 이름': user['UserName'],
                '생성일': user['CreateDate'].strftime('%Y-%m-%d'),
                'MFA 활성화': '✅' if user.get('MFADevices') else '❌'
            } for user in iam_info['users']]
            st.dataframe(pd.DataFrame(users_data), use_container_width=True)
        else:
            st.info("IAM 사용자가 없습니다.")
        st.markdown('</div></div>', unsafe_allow_html=True)
        
        # Roles Card
        st.markdown('<div class="card"><div class="card-header">IAM 역할</div><div class="card-content">', unsafe_allow_html=True)
        if iam_info['roles']:
            roles_data = [{
                '역할 이름': role['RoleName'],
                '생성일': role['CreateDate'].strftime('%Y-%m-%d'),
                '신뢰 관계': role.get('AssumeRolePolicyDocument', {}).get('Statement', [{}])[0].get('Principal', {}).get('Service', 'N/A')
            } for role in iam_info['roles']]
            st.dataframe(pd.DataFrame(roles_data), use_container_width=True)
        else:
            st.info("IAM 역할이 없습니다.")
        st.markdown('</div></div>', unsafe_allow_html=True)
        
        # Groups Card
        st.markdown('<div class="card"><div class="card-header">IAM 그룹</div><div class="card-content">', unsafe_allow_html=True)
        if iam_info['groups']:
            groups_data = [{
                '그룹 이름': group['GroupName'],
                '생성일': group['CreateDate'].strftime('%Y-%m-%d'),
                '사용자 수': len(group.get('Users', []))
            } for group in iam_info['groups']]
            st.dataframe(pd.DataFrame(groups_data), use_container_width=True)
        else:
            st.info("IAM 그룹이 없습니다.")
        st.markdown('</div></div>', unsafe_allow_html=True)
    st.markdown('</div></div>', unsafe_allow_html=True)

# CloudTrail Logs tab
with tabs[1]:
    st.markdown('<div class="card"><div class="card-header">CloudTrail 로그</div><div class="card-content">', unsafe_allow_html=True)
    if not st.session_state.scan_completed:
        st.info("보안 스캔을 시작하여 CloudTrail 로그를 가져오세요.")
    else:
        events = st.session_state.cloudtrail_events
        if events:
            event_data = [{
                '시간': event.get('EventTime').strftime('%Y-%m-%d %H:%M:%S'),
                '이벤트 이름': event.get('EventName'),
                '사용자': event.get('Username', 'N/A'),
                '소스 IP': event.get('SourceIPAddress', 'N/A')
            } for event in events]
            
            df = pd.DataFrame(event_data)
            st.dataframe(df, use_container_width=True)
            
            # CSV download
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="CSV로 다운로드",
                data=csv,
                file_name=f"cloudtrail_logs_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv"
            )
        else:
            st.warning("CloudTrail 이벤트가 없습니다.")
    st.markdown('</div></div>', unsafe_allow_html=True)

# Findings tab
with tabs[2]:
    st.markdown('<div class="card"><div class="card-header">발견 사항</div><div class="card-content">', unsafe_allow_html=True)
    if not st.session_state.scan_completed:
        st.info("보안 스캔을 시작하여 보안 위협 정보를 가져오세요.")
    else:
        # S3, WAF, GuardDuty 탭 생성
        security_tabs = st.tabs(["S3 버킷", "WAF", "GuardDuty"])
        
        # S3 탭
        with security_tabs[0]:
            if hasattr(st.session_state, 's3_issues') and st.session_state.s3_issues:
                issues = st.session_state.s3_issues
                st.write(f"총 {len(issues)}개의 S3 보안 이슈가 발견되었습니다.")
                
                # 심각도별 필터링
                severity_options = ["모두 보기", "HIGH", "MEDIUM", "LOW"]
                selected_severity = st.selectbox("심각도 필터", severity_options, key="s3_severity")
                
                if selected_severity != "모두 보기":
                    filtered_issues = [f for f in issues if f.get('severity') == selected_severity]
                else:
                    filtered_issues = issues
                
                if filtered_issues:
                    for issue in filtered_issues:
                        severity_class = "severity-high" if issue.get('severity') == "HIGH" else \
                                        "severity-medium" if issue.get('severity') == "MEDIUM" else "severity-low"
                        
                        st.markdown(f"""
                        <div class="finding-item {severity_class}">
                            <h3 style="color: #000000;">{issue.get('title', 'N/A')}</h3>
                            <p style="color: #000000;"><strong style="color: #000000;">심각도:</strong> {issue.get('severity', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">리소스:</strong> {issue.get('resource_type', 'N/A')} - {issue.get('resource_id', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">설명:</strong> {issue.get('description', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">발견 시간:</strong> {issue.get('created_at', 'N/A')}</p>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.info(f"{selected_severity} 심각도의 S3 보안 이슈가 없습니다.")
            else:
                st.info("S3 보안 이슈가 발견되지 않았습니다.")
        
        # WAF 탭
        with security_tabs[1]:
            if hasattr(st.session_state, 'waf_issues') and st.session_state.waf_issues:
                issues = st.session_state.waf_issues
                st.write(f"총 {len(issues)}개의 WAF 보안 이슈가 발견되었습니다.")
                
                # 심각도별 필터링
                severity_options = ["모두 보기", "HIGH", "MEDIUM", "LOW"]
                selected_severity = st.selectbox("심각도 필터", severity_options, key="waf_severity")
                
                if selected_severity != "모두 보기":
                    filtered_issues = [f for f in issues if f.get('severity') == selected_severity]
                else:
                    filtered_issues = issues
                
                if filtered_issues:
                    for issue in filtered_issues:
                        severity_class = "severity-high" if issue.get('severity') == "HIGH" else \
                                        "severity-medium" if issue.get('severity') == "MEDIUM" else "severity-low"
                        
                        st.markdown(f"""
                        <div class="finding-item {severity_class}">
                            <h3 style="color: #000000;">{issue.get('title', 'N/A')}</h3>
                            <p style="color: #000000;"><strong style="color: #000000;">심각도:</strong> {issue.get('severity', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">리소스:</strong> {issue.get('resource_type', 'N/A')} - {issue.get('resource_id', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">설명:</strong> {issue.get('description', 'N/A')}</p>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.info(f"{selected_severity} 심각도의 WAF 보안 이슈가 없습니다.")
            else:
                st.info("WAF 보안 이슈가 발견되지 않았습니다.")
        
        # GuardDuty 탭
        with security_tabs[2]:
            # GuardDuty 상태 표시
            status = st.session_state.guardduty_status if hasattr(st.session_state, 'guardduty_status') else {'status': 'UNKNOWN', 'message': '알 수 없음'}
            
            status_class = "status-active" if status['status'] == 'ACTIVE' else \
                          "status-warning" if status['status'] == 'PARTIALLY_ACTIVE' else \
                          "status-error" if status['status'] in ['DISABLED', 'NOT_CONFIGURED'] else "status-warning"
            
            st.markdown(f"""
            <div class="status-indicator {status_class}" style="color: #000000;">
                <strong style="color: #000000;">GuardDuty 상태:</strong> {status['status']} - {status['message']}
            </div>
            """, unsafe_allow_html=True)
            
            if hasattr(st.session_state, 'guardduty_findings') and st.session_state.guardduty_findings:
                findings = st.session_state.guardduty_findings
                st.write(f"총 {len(findings)}개의 GuardDuty 위협이 발견되었습니다.")
                
                # 심각도별 필터링
                severity_options = ["모두 보기", "높음 (7-10)", "중간 (4-7)", "낮음 (0-4)"]
                selected_severity = st.selectbox("심각도 필터", severity_options, key="gd_severity")
                
                if selected_severity == "높음 (7-10)":
                    filtered_findings = [f for f in findings if f.get('심각도', 0) > 7]
                elif selected_severity == "중간 (4-7)":
                    filtered_findings = [f for f in findings if 4 < f.get('심각도', 0) <= 7]
                elif selected_severity == "낮음 (0-4)":
                    filtered_findings = [f for f in findings if f.get('심각도', 0) <= 4]
                else:
                    filtered_findings = findings
                
                if filtered_findings:
                    for finding in filtered_findings:
                        severity_value = finding.get('심각도', 0)
                        severity_class = "severity-high" if severity_value > 7 else \
                                        "severity-medium" if severity_value > 4 else "severity-low"
                        
                        st.markdown(f"""
                        <div class="finding-item {severity_class}">
                            <h3 style="color: #000000;">{finding.get('제목', 'N/A')}</h3>
                            <p style="color: #000000;"><strong style="color: #000000;">심각도:</strong> {finding.get('심각도', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">유형:</strong> {finding.get('유형', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">리소스:</strong> {finding.get('리소스 유형', 'N/A')} - {finding.get('리소스 ID', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">설명:</strong> {finding.get('설명', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">발견 시간:</strong> {finding.get('발견 시간', 'N/A')}</p>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.info(f"{selected_severity} 심각도의 GuardDuty 위협이 없습니다.")
            else:
                if status['status'] in ['ACTIVE', 'PARTIALLY_ACTIVE']:
                    st.info("GuardDuty 위협이 발견되지 않았습니다.")
                else:
                    st.warning("GuardDuty가 활성화되지 않았거나 구성되지 않았습니다. AWS 콘솔에서 GuardDuty를 활성화하세요.")
                    
                    # GuardDuty 활성화 방법 안내
                    with st.expander("GuardDuty 활성화 방법"):
                        st.markdown("""
                        1. AWS 콘솔에 로그인합니다.
                        2. GuardDuty 서비스로 이동합니다.
                        3. '시작하기' 또는 'GuardDuty 활성화' 버튼을 클릭합니다.
                        4. 설정을 검토하고 '활성화'를 클릭합니다.
                        
                        GuardDuty는 30일 무료 평가판을 제공하며, 이후에는 사용량에 따라 요금이 부과됩니다.
                        """)
    st.markdown('</div></div>', unsafe_allow_html=True)

# Recommendations tab
with tabs[3]:
    st.markdown('<div class="card"><div class="card-header">권장 조치</div><div class="card-content">', unsafe_allow_html=True)
    if not st.session_state.scan_completed:
        st.info("보안 스캔을 시작하여 권장 조치를 확인하세요.")
    else:
        # 권장 조치 목록
        recommendations = []
        
        # IAM 관련 권장 조치
        iam_info = st.session_state.iam_info if hasattr(st.session_state, 'iam_info') else {}
        
        # MFA가 없는 사용자 확인
        if 'users_without_mfa' in iam_info and iam_info['users_without_mfa']:
            recommendations.append({
                'title': 'MFA가 없는 사용자 발견',
                'description': f"{len(iam_info['users_without_mfa'])}명의 사용자가 MFA를 사용하지 않고 있습니다. 모든 IAM 사용자에게 MFA를 활성화하는 것이 좋습니다.",
                'severity': 'HIGH',
                'action': 'AWS 콘솔에서 IAM > 사용자로 이동하여 MFA 디바이스를 등록하세요.',
                'affected_resources': iam_info['users_without_mfa']
            })
        
        # S3 관련 권장 조치
        if hasattr(st.session_state, 's3_issues') and st.session_state.s3_issues:
            high_issues = [i for i in st.session_state.s3_issues if i.get('severity') == 'HIGH']
            if high_issues:
                recommendations.append({
                    'title': 'S3 버킷 보안 취약점 발견',
                    'description': f"{len(high_issues)}개의 심각한 S3 버킷 보안 취약점이 발견되었습니다. 즉시 조치가 필요합니다.",
                    'severity': 'HIGH',
                    'action': '발견 사항 탭에서 자세한 내용을 확인하고 조치하세요.',
                    'affected_resources': [i.get('resource_id', 'N/A') for i in high_issues]
                })
        
        # WAF 관련 권장 조치
        if hasattr(st.session_state, 'waf_issues') and st.session_state.waf_issues:
            high_issues = [i for i in st.session_state.waf_issues if i.get('severity') == 'HIGH']
            if high_issues:
                recommendations.append({
                    'title': 'WAF 보안 구성 이슈 발견',
                    'description': f"{len(high_issues)}개의 심각한 WAF 보안 구성 이슈가 발견되었습니다. 웹 애플리케이션이 적절히 보호되지 않을 수 있습니다.",
                    'severity': 'HIGH',
                    'action': '발견 사항 탭에서 자세한 내용을 확인하고 WAF 규칙을 추가하세요.',
                    'affected_resources': [i.get('resource_id', 'N/A') for i in high_issues]
                })
        
        # GuardDuty 관련 권장 조치
        if hasattr(st.session_state, 'guardduty_findings') and st.session_state.guardduty_findings:
            high_findings = [f for f in st.session_state.guardduty_findings if f.get('심각도', 0) > 7]
            if high_findings:
                recommendations.append({
                    'title': 'GuardDuty에서 심각한 위협 발견',
                    'description': f"{len(high_findings)}개의 심각한 보안 위협이 GuardDuty에서 발견되었습니다. 즉시 조치가 필요합니다.",
                    'severity': 'CRITICAL',
                    'action': '발견 사항 탭에서 자세한 내용을 확인하고 조치하세요.',
                    'affected_resources': [f.get('리소스 ID', 'N/A') for f in high_findings]
                })
        
        # 권장 조치 표시
        if recommendations:
            for rec in recommendations:
                severity_class = "severity-high" if rec['severity'] in ["CRITICAL", "HIGH"] else \
                                "severity-medium" if rec['severity'] == "MEDIUM" else "severity-low"
                
                st.markdown(f"""
                <div class="finding-item {severity_class}">
                    <h3 style="color: #000000;">{rec['title']}</h3>
                    <p style="color: #000000;"><strong style="color: #000000;">심각도:</strong> {rec['severity']}</p>
                    <p style="color: #000000;"><strong style="color: #000000;">설명:</strong> {rec['description']}</p>
                    <p style="color: #000000;"><strong style="color: #000000;">권장 조치:</strong> {rec['action']}</p>
                    <p style="color: #000000;"><strong style="color: #000000;">영향 받는 리소스:</strong> {', '.join(rec['affected_resources'][:5])}{'...' if len(rec['affected_resources']) > 5 else ''}</p>
                </div>
                """, unsafe_allow_html=True)
                
                # Amazon Q에게 조치 방법 물어보기 버튼
                if st.button(f"Amazon Q에게 '{rec['title']}' 조치 방법 물어보기", key=f"ask_q_{recommendations.index(rec)}"):
                    st.markdown("<h4 style='color: #000000;'>Amazon Q 해결 가이드</h4>", unsafe_allow_html=True)
                    
                    # 위협 유형에 따른 해결 가이드 제공
                    if "MFA" in rec['title']:
                        st.markdown("""
                        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #FF9900; color: #000000;">
                            <h5 style="color: #000000;">MFA가 없는 사용자 문제 해결 가이드</h5>
                            <p style="color: #000000;"><strong>문제:</strong> MFA(다중 인증)가 활성화되지 않은 IAM 사용자가 있습니다. 이는 계정 보안에 취약점을 만들 수 있습니다.</p>
                            
                            <h6 style="color: #000000;">해결 단계:</h6>
                            <ol style="color: #000000;">
                                <li>AWS 콘솔에 로그인하고 IAM 서비스로 이동합니다.</li>
                                <li>왼쪽 메뉴에서 '사용자'를 선택합니다.</li>
                                <li>MFA가 없는 사용자를 선택합니다.</li>
                                <li>'보안 자격 증명' 탭을 클릭합니다.</li>
                                <li>'할당된 MFA 디바이스' 섹션에서 'MFA 디바이스 관리'를 클릭합니다.</li>
                                <li>'가상 MFA 디바이스'를 선택하고 '계속'을 클릭합니다.</li>
                                <li>QR 코드를 스캔하거나 비밀 키를 입력하여 모바일 앱(예: Google Authenticator)에 MFA를 설정합니다.</li>
                                <li>모바일 앱에서 생성된 두 개의 연속 MFA 코드를 입력합니다.</li>
                                <li>'MFA 할당'을 클릭하여 설정을 완료합니다.</li>
                            </ol>
                            
                            <h6 style="color: #000000;">AWS CLI를 사용한 방법:</h6>
                            <pre style="background-color: #f1f1f1; padding: 10px; color: #000000;">
# 가상 MFA 디바이스 생성
aws iam create-virtual-mfa-device --virtual-mfa-device-name MyMFA --outfile /tmp/QRCode.png --bootstrap-method QRCodePNG

# MFA 디바이스를 사용자에게 할당 (두 개의 연속 코드 필요)
aws iam enable-mfa-device --user-name USERNAME --serial-number arn:aws:iam::ACCOUNT-ID:mfa/MyMFA --authentication-code-1 CODE1 --authentication-code-2 CODE2
                            </pre>
                            
                            <h6 style="color: #000000;">모범 사례:</h6>
                            <ul style="color: #000000;">
                                <li>모든 IAM 사용자, 특히 관리자 권한이 있는 사용자에게 MFA를 활성화하세요.</li>
                                <li>MFA 없이 중요한 작업을 수행할 수 없도록 IAM 정책을 구성하세요.</li>
                                <li>정기적으로 MFA 상태를 감사하고 모니터링하세요.</li>
                            </ul>
                            
                            <p style="color: #000000;"><strong>참고 문서:</strong> <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html" target="_blank">AWS IAM 사용 설명서: MFA 사용</a></p>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    elif "S3 버킷" in rec['title']:
                        st.markdown("""
                        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #FF9900; color: #000000;">
                            <h5 style="color: #000000;">S3 버킷 보안 취약점 해결 가이드</h5>
                            <p style="color: #000000;"><strong>문제:</strong> 일부 S3 버킷에 보안 취약점이 발견되었습니다. 이는 데이터 유출 위험을 초래할 수 있습니다.</p>
                            
                            <h6 style="color: #000000;">해결 단계:</h6>
                            <ol style="color: #000000;">
                                <li>AWS 콘솔에 로그인하고 S3 서비스로 이동합니다.</li>
                                <li>취약한 버킷을 선택합니다.</li>
                                <li>'권한' 탭을 클릭합니다.</li>
                                <li>'퍼블릭 액세스 차단' 설정을 확인하고 필요한 경우 '편집'을 클릭하여 모든 퍼블릭 액세스를 차단합니다.</li>
                                <li>버킷 정책을 검토하고 불필요한 퍼블릭 액세스 권한을 제거합니다.</li>
                                <li>ACL(액세스 제어 목록)을 검토하고 필요하지 않은 권한을 제거합니다.</li>
                                <li>버킷 암호화 설정을 확인하고 서버 측 암호화를 활성화합니다.</li>
                            </ol>
                            
                            <h6 style="color: #000000;">AWS CLI를 사용한 방법:</h6>
                            <pre style="background-color: #f1f1f1; padding: 10px; color: #000000;">
# 버킷의 퍼블릭 액세스 차단 설정
aws s3api put-public-access-block --bucket BUCKET_NAME --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# 버킷 암호화 활성화
aws s3api put-bucket-encryption --bucket BUCKET_NAME --server-side-encryption-configuration '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}'
                            </pre>
                            
                            <h6 style="color: #000000;">모범 사례:</h6>
                            <ul style="color: #000000;">
                                <li>모든 S3 버킷에 대해 기본적으로 퍼블릭 액세스를 차단하세요.</li>
                                <li>최소 권한 원칙을 따라 필요한 권한만 부여하세요.</li>
                                <li>모든 버킷에 서버 측 암호화를 활성화하세요.</li>
                                <li>버킷 정책과 IAM 정책을 정기적으로 검토하세요.</li>
                                <li>S3 액세스 로깅을 활성화하여 모든 액세스를 모니터링하세요.</li>
                            </ul>
                            
                            <p style="color: #000000;"><strong>참고 문서:</strong> <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html" target="_blank">Amazon S3 보안 모범 사례</a></p>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    elif "WAF" in rec['title']:
                        st.markdown("""
                        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #FF9900; color: #000000;">
                            <h5 style="color: #000000;">WAF 보안 구성 이슈 해결 가이드</h5>
                            <p style="color: #000000;"><strong>문제:</strong> WAF(웹 애플리케이션 방화벽) 구성에 보안 이슈가 발견되었습니다. 이로 인해 웹 애플리케이션이 공격에 취약할 수 있습니다.</p>
                            
                            <h6 style="color: #000000;">해결 단계:</h6>
                            <ol style="color: #000000;">
                                <li>AWS 콘솔에 로그인하고 WAF & Shield 서비스로 이동합니다.</li>
                                <li>'웹 ACL'을 선택하고 문제가 있는 웹 ACL을 클릭합니다.</li>
                                <li>'규칙' 탭을 검토하고 필요한 보호 규칙이 활성화되어 있는지 확인합니다.</li>
                                <li>AWS 관리형 규칙 그룹(예: 핵심 규칙 세트, SQL 인젝션, XSS 방지)을 추가합니다.</li>
                                <li>속도 기반 규칙을 추가하여 DDoS 공격을 방지합니다.</li>
                                <li>IP 기반 차단 규칙을 검토하고 필요한 경우 업데이트합니다.</li>
                                <li>로깅을 활성화하여 모든 WAF 이벤트를 모니터링합니다.</li>
                            </ol>
                            
                            <h6 style="color: #000000;">AWS CLI를 사용한 방법:</h6>
                            <pre style="background-color: #f1f1f1; padding: 10px; color: #000000;">
# AWS 관리형 규칙 그룹 추가
aws wafv2 update-web-acl --name MY_WEB_ACL --scope REGIONAL --id WEB_ACL_ID --lock-token LOCK_TOKEN --rules '[{
    "Name": "AWS-AWSManagedRulesCommonRuleSet",
    "Priority": 0,
    "Statement": {
        "ManagedRuleGroupStatement": {
            "VendorName": "AWS",
            "Name": "AWSManagedRulesCommonRuleSet"
        }
    },
    "OverrideAction": {
        "None": {}
    },
    "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "AWS-AWSManagedRulesCommonRuleSet"
    }
}]'
                            </pre>
                            
                            <h6 style="color: #000000;">모범 사례:</h6>
                            <ul style="color: #000000;">
                                <li>OWASP Top 10 취약점을 방어하는 규칙을 구성하세요.</li>
                                <li>속도 기반 규칙을 사용하여 과도한 요청을 차단하세요.</li>
                                <li>지리적 제한을 설정하여 불필요한 지역에서의 액세스를 차단하세요.</li>
                                <li>로깅을 활성화하고 정기적으로 로그를 검토하세요.</li>
                                <li>WAF 규칙을 정기적으로 테스트하고 업데이트하세요.</li>
                            </ul>
                            
                            <p style="color: #000000;"><strong>참고 문서:</strong> <a href="https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html" target="_blank">AWS WAF 개발자 가이드</a></p>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    elif "GuardDuty" in rec['title']:
                        st.markdown("""
                        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #FF9900; color: #000000;">
                            <h5 style="color: #000000;">GuardDuty 위협 해결 가이드</h5>
                            <p style="color: #000000;"><strong>문제:</strong> GuardDuty에서 심각한 보안 위협이 감지되었습니다. 이는 계정이나 리소스가 공격받고 있음을 나타낼 수 있습니다.</p>
                            
                            <h6 style="color: #000000;">해결 단계:</h6>
                            <ol style="color: #000000;">
                                <li>AWS 콘솔에 로그인하고 GuardDuty 서비스로 이동합니다.</li>
                                <li>'결과' 페이지에서 심각한 위협을 확인합니다.</li>
                                <li>각 위협의 세부 정보를 검토하여 영향받은 리소스와 위협 유형을 파악합니다.</li>
                                <li>위협 유형에 따라 적절한 조치를 취합니다:
                                    <ul>
                                        <li><strong>무단 액세스:</strong> 관련 IAM 자격 증명을 교체하고 권한을 검토합니다.</li>
                                        <li><strong>악성 IP 통신:</strong> 보안 그룹 및 NACL을 업데이트하여 해당 IP를 차단합니다.</li>
                                        <li><strong>암호화폐 채굴:</strong> 영향받은 인스턴스를 격리하고 조사합니다.</li>
                                        <li><strong>데이터 유출:</strong> 관련 S3 버킷의 권한을 검토하고 제한합니다.</li>
                                    </ul>
                                </li>
                                <li>영향받은 리소스를 격리하거나 종료하여 추가 피해를 방지합니다.</li>
                                <li>보안 그룹, IAM 정책, 네트워크 ACL 등을 검토하고 강화합니다.</li>
                                <li>사고 대응 계획에 따라 추가 조사를 수행합니다.</li>
                            </ol>
                            
                            <h6 style="color: #000000;">AWS CLI를 사용한 방법:</h6>
                            <pre style="background-color: #f1f1f1; padding: 10px; color: #000000;">
# GuardDuty 결과 세부 정보 가져오기
aws guardduty get-findings --detector-id DETECTOR_ID --finding-ids FINDING_ID

# 악성 IP를 차단하는 보안 그룹 규칙 추가
aws ec2 revoke-security-group-ingress --group-id SECURITY_GROUP_ID --protocol all --cidr MALICIOUS_IP/32

# 의심스러운 IAM 사용자 액세스 키 비활성화
aws iam update-access-key --access-key-id ACCESS_KEY_ID --status Inactive --user-name USER_NAME
                            </pre>
                            
                            <h6 style="color: #000000;">모범 사례:</h6>
                            <ul style="color: #000000;">
                                <li>GuardDuty 결과에 대한 자동 알림을 설정하세요.</li>
                                <li>정기적으로 GuardDuty 결과를 검토하세요.</li>
                                <li>사고 대응 계획을 수립하고 정기적으로 테스트하세요.</li>
                                <li>최소 권한 원칙을 따라 IAM 권한을 구성하세요.</li>
                                <li>VPC 흐름 로그와 CloudTrail을 활성화하여 모든 활동을 모니터링하세요.</li>
                            </ul>
                            
                            <p style="color: #000000;"><strong>참고 문서:</strong> <a href="https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html" target="_blank">AWS GuardDuty 결과 이해 및 대응</a></p>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    else:
                        st.markdown("""
                        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #FF9900; color: #000000;">
                            <h5 style="color: #000000;">일반 보안 권장 사항</h5>
                            <p style="color: #000000;"><strong>문제:</strong> 보안 취약점이 발견되었습니다. 이는 AWS 환경의 보안 상태에 영향을 미칠 수 있습니다.</p>
                            
                            <h6 style="color: #000000;">일반적인 보안 강화 단계:</h6>
                            <ol style="color: #000000;">
                                <li>모든 IAM 사용자에 대해 MFA를 활성화하세요.</li>
                                <li>루트 사용자 액세스 키를 삭제하고 루트 사용자에 MFA를 설정하세요.</li>
                                <li>최소 권한 원칙에 따라 IAM 정책을 검토하고 업데이트하세요.</li>
                                <li>모든 S3 버킷에 대해 퍼블릭 액세스를 차단하세요.</li>
                                <li>중요한 데이터에 대해 암호화를 활성화하세요.</li>
                                <li>보안 그룹 규칙을 검토하고 불필요한 포트를 닫으세요.</li>
                                <li>CloudTrail, VPC 흐름 로그, S3 액세스 로깅 등 모니터링을 활성화하세요.</li>
                                <li>AWS Config를 사용하여 리소스 구성을 지속적으로 모니터링하세요.</li>
                                <li>Security Hub를 활성화하여 보안 모범 사례를 확인하세요.</li>
                            </ol>
                            
                            <h6 style="color: #000000;">AWS CLI를 사용한 보안 점검:</h6>
                            <pre style="background-color: #f1f1f1; padding: 10px; color: #000000;">
# IAM 사용자 목록 및 MFA 상태 확인
aws iam list-users | jq -r '.Users[].UserName' | while read user; do
  aws iam list-mfa-devices --user-name $user | jq -r '.MFADevices | length'
done

# 퍼블릭 S3 버킷 확인
aws s3api list-buckets --query 'Buckets[].Name' --output text | while read bucket; do
  aws s3api get-bucket-policy-status --bucket $bucket --query 'PolicyStatus.IsPublic' 2>/dev/null || echo "No policy"
done
                            </pre>
                            
                            <h6 style="color: #000000;">AWS 보안 모범 사례:</h6>
                            <ul style="color: #000000;">
                                <li>정기적인 보안 평가 및 취약점 스캔을 수행하세요.</li>
                                <li>패치 관리 프로세스를 구현하여 시스템을 최신 상태로 유지하세요.</li>
                                <li>인프라를 코드로 관리하여 일관된 보안 구성을 유지하세요.</li>
                                <li>보안 이벤트에 대한 자동 알림 및 대응 메커니즘을 구현하세요.</li>
                                <li>정기적으로 보안 교육을 실시하여 팀의 보안 인식을 높이세요.</li>
                            </ul>
                            
                            <p style="color: #000000;"><strong>참고 문서:</strong> <a href="https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html" target="_blank">AWS Well-Architected Framework - 보안 기둥</a></p>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    # 추가 조치 버튼
                    st.markdown("<p style='color: #000000;'>이 가이드가 도움이 되셨나요?</p>", unsafe_allow_html=True)
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button("더 자세한 정보 필요", key=f"more_info_{recommendations.index(rec)}"):
                            st.markdown("<p style='color: #000000;'>더 자세한 정보는 AWS 공식 문서를 참조하세요.</p>", unsafe_allow_html=True)
                    with col2:
                        if st.button("문제 해결됨", key=f"resolved_{recommendations.index(rec)}"):
                            st.success("문제 해결을 완료했습니다! 다음 보안 스캔에서 이 문제가 해결되었는지 확인하세요.")
        else:
            st.success("모든 보안 검사를 통과했습니다! 현재 권장 조치가 없습니다.")
    st.markdown('</div></div>', unsafe_allow_html=True)

# Footer
st.markdown('<p style="text-align: center; color: #666666; font-size: 0.8rem; margin-top: 30px;">AWS 운영자를 위한 보안 대시보드 | Amazon Q 핸즈온 워크샵</p>', unsafe_allow_html=True)
