import boto3

# 사용자 액세스 토큰 값 가져오기
def get_configured_region():
    """aws configure에 설정된 기본 리전 값을 가져오는 함수"""
    # 기본 세션 생성 (AWS 자격 증명 및 설정 파일을 자동으로 읽어옴)
    session = boto3.Session()
    
    # 설정된 기본 리전 이름 가져오기
    configured_region = session.region_name
    
    if not configured_region:
        print("⚠️ 설정된 기본 리전(Default region)이 없습니다. 터미널에서 'aws configure'를 확인해주세요.")
        return None
        
    print(f"🔍 [점검 시작] 타겟 리전: {configured_region}\n")
    return configured_region

def check_open_security_groups():
    # 1. 사용자 환경 변수에서 리전 값 동적 할당
    region = get_configured_region()
    
    # 리전 정보가 없으면 검사 중단
    if not region:
        return  
        
    # 2. 동적으로 가져온 리전 변수를 클라이언트에 주입
    ec2 = boto3.client('ec2', region_name=region)
    response = ec2.describe_security_groups()
    
    vulnerable_sgs = []

    # 전체 보안 그룹 순회
    for sg in response.get('SecurityGroups', []):
        sg_id = sg.get('GroupId')
        sg_name = sg.get('GroupName')
        
        # 인바운드 규칙(IpPermissions) 확인
        for permission in sg.get('IpPermissions', []):
            # 허용된 IP 범위(IpRanges) 확인
            for ip_range in permission.get('IpRanges', []):
                # CidrIp 값이 0.0.0.0/0 인지 검사
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    from_port = permission.get('FromPort', 'All')
                    to_port = permission.get('ToPort', 'All')
                    protocol = permission.get('IpProtocol', 'All')
                    
                    vulnerable_sgs.append({
                        'GroupId': sg_id,
                        'GroupName': sg_name,
                        'Protocol': protocol,
                        'PortRange': f"{from_port}~{to_port}"
                    })
                    # 하나의 규칙에서 0.0.0.0/0을 찾았다면, 해당 규칙의 중복 출력을 막기 위해 반복문 탈출
                    break 

    # 결과 출력
    if vulnerable_sgs:
        print(f"⚠️ [경고] 0.0.0.0/0 이 허용된 보안 그룹 발견 ({len(vulnerable_sgs)}건):")
        for v_sg in vulnerable_sgs:
            print(f" - [{v_sg['GroupId']}] {v_sg['GroupName']} (프로토콜: {v_sg['Protocol']}, 포트: {v_sg['PortRange']})")
    else:
        print("✅ 모든 보안 그룹이 안전하게 설정되어 있습니다. (0.0.0.0/0 없음)")

def check_imdsv2_enforcement():

    # region_name은 사용자 변수
    ec2 = boto3.client('ec2', region_name='ap-southeast-2')
    response = ec2.describe_instances()
    
    vulnerable_instances = []

    # 전체 인스턴스 순회
    for reservation in response.get('Reservations', []):
        for instance in reservation.get('Instances', []):
            instance_id = instance.get('InstanceId')
            
            # 인스턴스가 종료(terminated)된 상태라면 검사에서 제외
            if instance.get('State', {}).get('Name') == 'terminated':
                continue
            
            # MetadataOptions 필드 확인
            metadata_options = instance.get('MetadataOptions', {})
            http_tokens = metadata_options.get('HttpTokens')
            
            # HttpTokens가 'required'가 아니면 IMDSv2가 강제되지 않은 상태
            if http_tokens != 'required':
                vulnerable_instances.append({
                    'InstanceId': instance_id,
                    'HttpTokens': http_tokens
                })

    # 결과 출력
    if vulnerable_instances:
        print(f"⚠️ [경고] IMDSv2가 강제되지 않은 인스턴스 발견 ({len(vulnerable_instances)}건):")
        for v_inst in vulnerable_instances:
            print(f" - 인스턴스 ID: {v_inst['InstanceId']} (현재 HttpTokens 상태: {v_inst['HttpTokens']})")
    else:
        print("✅ 모든 인스턴스에 IMDSv2가 정상적으로 강제(required)되어 있습니다.")


def check_ebs_encryption():
    # 1. 사용자 환경 변수에서 리전 값 동적 할당
    region = get_configured_region()
    
    # 리전 정보가 없으면 검사 중단
    if not region:
        return

    # 2. 동적으로 가져온 리전 변수를 클라이언트에 주입
    ec2 = boto3.client('ec2', region_name=region)
    response = ec2.describe_volumes()
    
    unencrypted_volumes = []

    # 전체 볼륨 순회
    for volume in response.get('Volumes', []):
        volume_id = volume.get('VolumeId')
        
        # Encrypted 값 확인 (기본값을 False로 두어 안전하게 체크)
        is_encrypted = volume.get('Encrypted', False)
        
        # 암호화되지 않은(False) 볼륨 필터링
        if not is_encrypted:
            # 추가 정보(볼륨 크기, 상태 등)도 함께 저장
            state = volume.get('State')
            size = volume.get('Size')
            unencrypted_volumes.append({
                'VolumeId': volume_id,
                'State': state,
                'Size': size
            })

    # 결과 출력
    if unencrypted_volumes:
        print(f"⚠️ [경고] 암호화되지 않은 EBS 볼륨 발견 ({len(unencrypted_volumes)}건):")
        for vol in unencrypted_volumes:
            print(f" - 볼륨 ID: {vol['VolumeId']} (상태: {vol['State']}, 크기: {vol['Size']}GB)")
    else:
        print("✅ 모든 EBS 볼륨이 안전하게 암호화되어 있습니다.")

def check_iam_role_assignment():
    # 1. 사용자 환경 변수에서 리전 값 동적 할당
    region = get_configured_region()
    
    # 리전 정보가 없으면 검사 중단
    if not region:
        return

    # 2. 동적으로 가져온 리전 변수를 클라이언트에 주입
    ec2 = boto3.client('ec2', region_name=region)
    response = ec2.describe_instances()
    
    instances_without_role = []

    # 전체 인스턴스 순회
    for reservation in response.get('Reservations', []):
        for instance in reservation.get('Instances', []):
            instance_id = instance.get('InstanceId')
            
            # 이미 종료된(terminated) 인스턴스는 검사에서 제외
            if instance.get('State', {}).get('Name') == 'terminated':
                continue
            
            # IamInstanceProfile 키가 딕셔너리 안에 없는지 확인
            if 'IamInstanceProfile' not in instance:
                # 태그 정보 중 'Name' 값을 찾아두면 식별하기 편합니다.
                instance_name = "이름 없음"
                for tag in instance.get('Tags', []):
                    if tag.get('Key') == 'Name':
                        instance_name = tag.get('Value')
                        break
                        
                instances_without_role.append({
                    'InstanceId': instance_id,
                    'Name': instance_name
                })

    # 결과 출력
    if instances_without_role:
        print(f"⚠️ [경고] IAM 역할이 할당되지 않은 인스턴스 발견 ({len(instances_without_role)}건):")
        print("   (장기 자격 증명(Access Key)이 인스턴스 내부에 하드코딩되어 사용될 위험이 있습니다.)")
        for inst in instances_without_role:
            print(f" - 인스턴스 ID: {inst['InstanceId']} (이름: {inst['Name']})")
    else:
        print("✅ 활성화된 모든 인스턴스에 IAM 역할이 정상적으로 할당되어 있습니다.")

def check_user_data_for_sensitive_info():
    # 1. 사용자 환경 변수에서 리전 값 동적 할당
    region = get_configured_region()
    
    # 리전 정보가 없으면 검사 중단
    if not region:
        return

    # 2. 동적으로 가져온 리전 변수를 클라이언트에 주입
    ec2 = boto3.client('ec2', region_name=region)
    
    # 활성화된 모든 인스턴스 ID 수집
    response = ec2.describe_instances()
    instances_to_check = []
    
    for reservation in response.get('Reservations', []):
        for instance in reservation.get('Instances', []):
            # 종료된 인스턴스는 검사 제외
            if instance.get('State', {}).get('Name') != 'terminated':
                instances_to_check.append(instance.get('InstanceId'))
                
    if not instances_to_check:
        print("검사할 활성 인스턴스가 없습니다.")
        return

    print(f"총 {len(instances_to_check)}개의 인스턴스 User Data를 점검합니다...\n")
    
    # 보안 점검용 민감 키워드 목록 (소문자 기준)
    sensitive_keywords = ['password', 'secret', 'access_key', 'token', 'private_key']
    vulnerable_instances = []

    # 각 인스턴스의 User Data 속성 개별 조회 및 디코딩
    for instance_id in instances_to_check:
        attr_response = ec2.describe_instance_attribute(
            InstanceId=instance_id,
            Attribute='userData'
        )
        
        # UserData 키 안의 Value 값을 가져옴
        user_data_value = attr_response.get('UserData', {}).get('Value')
        
        # UserData가 존재하는 경우만 디코딩 진행
        if user_data_value:
            try:
                # Base64 문자열을 바이트로 변환 후 UTF-8 문자열로 디코딩
                decoded_bytes = base64.b64decode(user_data_value)
                decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                
                # 디코딩된 텍스트 안에 민감 정보 키워드가 있는지 확인
                found_keywords = [kw for kw in sensitive_keywords if kw in decoded_str.lower()]
                
                # 키워드가 발견되거나, 전체 스크립트를 수동 점검하기 위해 저장
                if found_keywords:
                    vulnerable_instances.append({
                        'InstanceId': instance_id,
                        'Keywords': found_keywords,
                        # 전체 코드가 길 수 있으므로 앞 150자만 미리보기로 저장
                        'Snippet': decoded_str.strip()[:150].replace('\n', ' ') + ' ...'
                    })
            except Exception as e:
                print(f"[{instance_id}] 디코딩 오류 발생: {e}")

    # 점검 결과 출력
    if vulnerable_instances:
        print(f"⚠️ [경고] 민감 정보(패스워드, 키 등)가 포함된 것으로 의심되는 User Data 발견 ({len(vulnerable_instances)}건):")
        for inst in vulnerable_instances:
            print(f" - 인스턴스 ID: {inst['InstanceId']}")
            print(f"   의심 키워드: {', '.join(inst['Keywords'])}")
            print(f"   데이터 일부: {inst['Snippet']}\n")
    else:
        print("✅ 점검한 인스턴스의 User Data가 비어있거나, 명시적인 민감 키워드가 발견되지 않았습니다.")

# 리스트1: 인바운드 규칙 확인
check_open_security_groups()
# 리스트2: IMDSv2 강제 여부 확인
check_imdsv2_enforcement()
# 리스트3: EBS 암호화 설정 확인
check_ebs_encryption()
# 리스트4: 인스턴스의 IAM 역할 할당 확인
check_iam_role_assignment()
# 리스트5: 인스턴스 User Data에 민감 정보 포함 여부 확인
check_user_data_for_sensitive_info()

