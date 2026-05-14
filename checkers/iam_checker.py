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