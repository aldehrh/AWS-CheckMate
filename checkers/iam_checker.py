# 루트(Root) 계정의 일상적 사용
import boto3
import csv
import io
from datetime import datetime, timezone
from botocore.stub import Stubber  # Boto3의 가상 응답을 만들어주는 도구

def check_root_usage():
    # 1. 실제 Boto3 IAM 클라이언트를 생성합니다.
    # (원래는 인증 키가 없으면 에러가 나지만, stub을 쓰기 위해 가짜 리전정보만 줍니다)
    iam = boto3.client('iam', region_name='us-east-1', aws_access_key_id='mock', aws_secret_access_key='mock')

    # ------------------------------------------------------------------
    # [테스트용 가짜 데이터 설정] AWS 서버가 줄법한 실제 CSV 결과물입니다.
    mock_csv_content = """user,arn,user_creation_time,password_enabled,password_last_used,access_key_1_active,access_key_1_last_used_date,access_key_2_active,access_key_2_last_used_date
<root_account>,arn:aws:iam::123456789012:root,2015-10-14T19:31:01+00:00,not_supported,2026-05-10T12:00:00Z,false,N/A,false,N/A
iam_user_01,arn:aws:iam::123456789012:user/iam_user_01,2024-01-01T10:00:00+00:00,true,2026-05-14T01:00:00Z,true,2026-05-14T02:00:00Z,false,N/A
"""
    # Boto3 Stubber를 연결하여 실제 AWS로 안 가고 위 CSV 데이터를 뱉게 만듭니다.
    stubber = Stubber(iam)
    stubber.add_response('generate_credential_report', {'State': 'COMPLETE'})
    stubber.add_response('get_credential_report', {'Content': mock_csv_content.encode('utf-8')})
    stubber.activate()
    # ------------------------------------------------------------------

    print("자격 증명 보고서 생성을 요청합니다...")
    
    # [Boto3 실행] 보고서 생성 요청
    while True:
        report = iam.generate_credential_report()
        if report['State'] == 'COMPLETE':
            break
            
    # [Boto3 실행] 보고서 내용 가져오기
    response = iam.get_credential_report()
    content = response['Content'].decode('utf-8')
    
    # CSV 파싱 및 분석 로직
    reader = csv.DictReader(io.StringIO(content))
    
    root_data = None
    for row in reader:
        if row['user'] == '<root_account>':
            root_data = row
            break
            
    if not root_data:
        print("루트 계정 정보를 찾을 수 없습니다.")
        return

    fields_to_check = [
        'password_last_used',
        'access_key_1_last_used_date',
        'access_key_2_last_used_date'
    ]

    print(f"\n--- 루트 계정 사용 기록 분석 (Boto3 가상 테스트) ---")
    is_regularly_used = False
    now = datetime.now(timezone.utc)

    for field in fields_to_check:
        last_used = root_data.get(field)
        
        if last_used and last_used not in ['N/A', 'not_supported', 'no_information']:
            last_used_dt = datetime.fromisoformat(last_used.replace('Z', '+00:00'))
            days_diff = (now - last_used_dt).days
            
            print(f"[{field}]: {last_used} (약 {days_diff}일 전 사용)")
            
            if days_diff <= 90:
                is_regularly_used = True
        else:
            print(f"[{field}]: 사용 기록 없음 (N/A)")

    print("-" * 30)
    if is_regularly_used:
        print("결과: [취약] 루트 계정이 최근에 사용되었습니다. IAM 사용자를 권장합니다.")
    else:
        print("결과: [양호] 최근 루트 계정 사용 기록이 발견되지 않았습니다.")

if __name__ == "__main__":
    check_root_usage()

# ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ

# 액세스 키의 코드 내 하드코딩
import boto3
from datetime import datetime, timezone
from botocore.stub import Stubber  # Boto3 가상 응답 도구

def check_access_keys(username):
    # 1. 실제 Boto3 IAM 클라이언트 생성 (테스트를 위해 가짜 키 주입)
    iam = boto3.client('iam', region_name='us-east-1', aws_access_key_id='mock', aws_secret_access_key='mock')

    # ------------------------------------------------------------------
    # [테스트용 가짜 데이터 설정] AWS 서버가 줄법한 실제 API 응답 구조입니다.
    # 예시: 하나는 정상적이지만 오래된 키(Active), 하나는 비활성화된 키(Inactive)
    mock_response = {
        'AccessKeyMetadata': [
            {
                'UserName': username,
                'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE',
                'Status': 'Active',
                'CreateDate': datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc) # 생성된 지 오래된 키
            },
            {
                'UserName': username,
                'AccessKeyId': 'AKIAI44QH426EXAMPLE2',
                'Status': 'Inactive',
                'CreateDate': datetime(2026, 4, 15, 9, 30, 0, tzinfo=timezone.utc) # 비활성화된 키
            }
        ],
        'IsTruncated': False
    }

    # Boto3 Stubber를 연결하여 list_access_keys 호출 시 위 데이터를 가로채서 반환하게 만듭니다.
    stubber = Stubber(iam)
    stubber.add_response('list_access_keys', mock_response, {'UserName': username})
    stubber.activate()
    # ------------------------------------------------------------------

    print(f"=== 사용자 [{username}]의 액세스 키 점검을 시작합니다 ===")
    
    # [Boto3 실행] 특정 사용자의 액세스 키 목록 가져오기
    response = iam.list_access_keys(UserName=username)
    access_keys = response.get('AccessKeyMetadata', [])

    if not access_keys:
        print("결과: 생성된 액세스 키가 없습니다. [양호]")
        return

    now = datetime.now(timezone.utc)
    
    # 각 키의 정보(ID, 생성일, 상태) 확인 및 분석
    for key in access_keys:
        key_id = key['AccessKeyId']
        status = key['Status']
        create_date = key['CreateDate']
        
        # 키가 생성된 후 지난 일수 계산
        days_since_creation = (now - create_date).days
        
        print(f"\n[키 ID]: {key_id}")
        print(f"  - 상태(Status): {status}")
        print(f"  - 생성일(CreateDate): {create_date.strftime('%Y-%m-%d')} (약 {days_since_creation}일 전 생성)")

        # 취약점 진단 기준 (보안 모범 사례 적용)
        # 1. 활성화(Active) 상태이면서 생성된 지 90일이 지난 경우 위험 (주기적 로테이션 미준수)
        if status == 'Active' and days_since_creation > 90:
            print(f"  ❌ 결과: [취약] 활성화된 키가 90일 이상 방치되었습니다. 키 교체(Rotation)가 필요합니다.")
        # 2. 비활성화(Inactive) 상태인 경우
        elif status == 'Inactive':
            print(f"  ⚠️ 결과: [주의] 비활성화된 키입니다. 더 이상 쓰지 않는다면 안전을 위해 삭제를 권장합니다.")
        else:
            print(f"  ✅ 결과: [양호] 최근에 생성된 활성 키입니다.")

if __name__ == "__main__":
    # 테스트할 가상의 IAM 사용자 이름 입력
    check_access_keys(username="test_developer")




# ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ

# MFA(다요소 인증) 미설정

import boto3
from unittest.mock import MagicMock

def check_mfa_setup():
    # 1. 실제 Boto3 IAM 클라이언트를 생성합니다.
    iam = boto3.client('iam', region_name='us-east-1', aws_access_key_id='mock', aws_secret_access_key='mock')

    # 2. [테스트 세팅] Boto3 메서드들이 에러 없이 가짜 데이터를 반환하도록 Mock(위장) 처리합니다.
    # 계정에 일반 사용자 2명(charlie, dana)이 있다고 가정합니다.
    iam.list_users = MagicMock(return_value={
        'Users': [
            {'UserName': 'charlie_admin'},
            {'UserName': 'dana_developer'}
        ]
    })

    # 사용자에 따라 각기 다른 MFA 장치 목록을 반환하는 가짜 함수 정의
    def mock_list_mfa_devices(UserName):
        if UserName == 'charlie_admin':
            # charlie는 MFA 기기가 있음
            return {
                'MFADevices': [
                    {
                        'UserName': 'charlie_admin',
                        'SerialNumber': 'arn:aws:iam::123456789012:mfa/charlie_admin'
                    }
                ]
            }
        else:
            # dana는 MFA 기기가 없음 (빈 리스트)
            return {'MFADevices': []}

    iam.list_mfa_devices = MagicMock(side_effect=mock_list_mfa_devices)
    # ------------------------------------------------------------------

    print("=== IAM 사용자 MFA 설정 여부 점검을 시작합니다 ===")
    
    # [Boto3 호출] 전체 사용자 목록 가져오기
    users_response = iam.list_users()
    users = users_response.get('Users', [])

    if not users:
        print("조회된 IAM 사용자가 없습니다.")
        return

    # 사용자별로 루프를 돌며 MFA 상태 체크
    for user in users:
        username = user['UserName']
        
        # [Boto3 호출] 해당 사용자의 MFA 기기 목록 조회
        mfa_response = iam.list_mfa_devices(UserName=username)
        mfa_devices = mfa_response.get('MFADevices', [])
        
        print(f"\n[사용자 ID]: {username}")
        
        # 핵심 로직: MFADevices 목록이 비어있는지([]) 확인
        if not mfa_devices:
            print(f"  ❌ 결과: [취약] MFA(다요소 인증)가 설정되어 있지 않습니다!")
        else:
            print(f"  ✅ 결과: [양호] MFA 기기가 등록되어 있습니다.")

if __name__ == "__main__":
    check_mfa_setup()



# ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ

# 와일드카드(*) 남용(과도한 권한 부여)

