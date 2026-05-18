import boto3
import json
from botocore.exceptions import ClientError

def check_s3_security_detailed():
    s3 = boto3.client('s3')
    
    print("=== 🛡️ AWS S3 버킷 보안 상세 점검 시작 ===\n")
    
    try:
        response = s3.list_buckets()
        buckets = response.get('Buckets', [])
    except ClientError as e:
        print(f"[오류] 버킷 목록을 불러올 수 없습니다: {e}")
        return

    for bucket in buckets:
        bucket_name = bucket['Name']
        creation_date = bucket['CreationDate']
        print(f"📦 [{bucket_name}] (생성일: {creation_date.strftime('%Y-%m-%d %H:%M:%S')})")
        
        # 2. 퍼블릭 차단 설정 상세 조회
        try:
            pab = s3.get_public_access_block(Bucket=bucket_name)
            config = pab['PublicAccessBlockConfiguration']
            
            bpa = config.get('BlockPublicAcls', False)
            ipa = config.get('IgnorePublicAcls', False)
            bpp = config.get('BlockPublicPolicy', False)
            rpb = config.get('RestrictPublicBuckets', False)
            
            if bpa and ipa and bpp and rpb:
                print("  - [2] 퍼블릭 차단: 안전 🟢 (4개 항목 모두 True)")
            else:
                print("  - [2] 퍼블릭 차단: 취약 🔴 (상세 내역 확인)")
                print(f"      > BlockPublicAcls (새 ACL 퍼블릭 차단) : {'True 🟢' if bpa else 'False 🔴'}")
                print(f"      > IgnorePublicAcls (기존 ACL 퍼블릭 무시) : {'True 🟢' if ipa else 'False 🔴'}")
                print(f"      > BlockPublicPolicy (새 정책 퍼블릭 차단) : {'True 🟢' if bpp else 'False 🔴'}")
                print(f"      > RestrictPublicBuckets (퍼블릭/크로스 계정 액세스 제한) : {'True 🟢' if rpb else 'False 🔴'}")
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                print("  - [2] 퍼블릭 차단: 설정 없음 🔴 (모든 퍼블릭 차단이 꺼져있음)")
            else:
                print(f"  - [2] 퍼블릭 차단 오류: {e}")

        # 3. 버킷 정책 상세 조회
        try:
            policy_resp = s3.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(policy_resp['Policy'])
            statements = policy.get('Statement', [])
            
            vuln_reasons = []
            for idx, stmt in enumerate(statements):
                if stmt.get('Effect') == 'Allow':
                    principal = stmt.get('Principal', '')
                    action = stmt.get('Action', '')
                    
                    if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                        vuln_reasons.append(f"규칙 {idx+1}: 누구나(Principal='*') 접근 가능하도록 허용됨")
                    if action == '*' or (isinstance(action, list) and '*' in action):
                        vuln_reasons.append(f"규칙 {idx+1}: 모든 작업(Action='*')이 허용됨")
                        
            if vuln_reasons:
                print("  - [3] 버킷 정책: 취약 🔴")
                for reason in vuln_reasons:
                    print(f"      > {reason}")
            else:
                print("  - [3] 버킷 정책: 안전 🟢")
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                print("  - [3] 버킷 정책: 정책 없음 🟢 (기본 차단 상태이므로 안전)")
            else:
                print(f"  - [3] 버킷 정책 오류: {e}")

        # 4. 암호화 설정 상세 조회
        try:
            enc = s3.get_bucket_encryption(Bucket=bucket_name)
            rules = enc['ServerSideEncryptionConfiguration']['Rules']
            algo = rules[0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
            
            if algo in ['AES256', 'aws:kms']:
                kms_info = f", KMS Key ID: {rules[0]['ApplyServerSideEncryptionByDefault'].get('KMSMasterKeyID', 'Default')}" if algo == 'aws:kms' else ""
                print(f"  - [4] 암호화: 안전 🟢 ({algo}{kms_info})")
            else:
                print(f"  - [4] 암호화: 취약 🔴 (알 수 없는 알고리즘: {algo})")
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                print("  - [4] 암호화: 설정 없음 🔴 (데이터가 평문으로 저장될 위험)")
            else:
                print(f"  - [4] 암호화 오류: {e}")

        # 5. 버전 관리 상세 조회
        try:
            ver = s3.get_bucket_versioning(Bucket=bucket_name)
            status = ver.get('Status', 'Disabled')
            mfa_delete = ver.get('MFADelete', 'Disabled')
            
            if status == 'Enabled':
                print(f"  - [5] 버전 관리: 안전 🟢 (MFA Delete: {mfa_delete})")
            else:
                print(f"  - [5] 버전 관리: 비활성화 상태 🟡")
                print("      > (권고) 랜섬웨어 및 실수 삭제 대비를 위해 활성화 권장")
        except ClientError as e:
            print(f"  - [5] 버전 관리 오류: {e}")

        # 6. 서버 로깅 상세 조회
        try:
            log = s3.get_bucket_logging(Bucket=bucket_name)
            if 'LoggingEnabled' in log:
                target = log['LoggingEnabled'].get('TargetBucket')
                prefix = log['LoggingEnabled'].get('TargetPrefix', '없음')
                print(f"  - [6] 서버 로깅: 활성화 🟢 (저장 버킷: {target}, 폴더명: {prefix})")
            else:
                print("  - [6] 서버 로깅: 비활성화 상태 🟡")
                print("      > (권고) 침해 사고 발생 시 추적을 위해 로깅 활성화 권장")
        except ClientError as e:
            print(f"  - [6] 서버 로깅 오류: {e}")

        # 7. ACL(접근 제어 목록) 상세 조회
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            grants = acl.get('Grants', [])
            vuln_acls = []
            
            for grant in grants:
                grantee = grant.get('Grantee', {})
                uri = grantee.get('URI', '')
                permission = grant.get('Permission', '')
                
                if uri == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    vuln_acls.append(f"모든 외부 사용자에게 '{permission}' 권한 허용됨")
                elif uri == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers':
                    vuln_acls.append(f"인증된 모든 AWS 계정에게 '{permission}' 권한 허용됨")
                    
            if vuln_acls:
                print("  - [7] ACL 설정: 취약 🔴")
                for vacl in vuln_acls:
                    print(f"      > {vacl}")
            else:
                print("  - [7] ACL 설정: 안전 🟢 (외부 접근 권한 없음)")
        except ClientError as e:
            print(f"  - [7] ACL 설정 오류: {e}")

        print("-" * 65)

if __name__ == "__main__":
    check_s3_security_detailed()