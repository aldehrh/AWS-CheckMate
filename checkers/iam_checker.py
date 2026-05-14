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