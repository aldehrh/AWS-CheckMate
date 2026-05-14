"""
Amazon RDS 보안 점검 도구

점검 항목:
  1. 퍼블릭 접근 허용 여부 (PubliclyAccessible)
  2. 기본/약한 DB 계정명 사용 여부 (MasterUsername)
  3. 저장 데이터 암호화 미적용 (StorageEncrypted)
  4. 보안 그룹 과다 개방 (0.0.0.0/0 or ::/0)
  5. 자동 백업 보존 기간 (BackupRetentionPeriod)
  6. SSL/TLS 전송 암호화 강제 여부 (파라미터 그룹)
  7. CloudWatch 로그 및 모니터링 설정 여부
"""

import boto3
import json
from dataclasses import dataclass, field
from typing import Optional


# ──────────────────────────────────────────────
# 상수 정의
# ──────────────────────────────────────────────

# 위험 계정명 목록
WEAK_USERNAMES = {"admin", "root", "postgres", "mysql", "oracle", "sa", "master", "user", "test", "db"}

# 자동 백업 최소 권장 기간 (일)
BACKUP_RETENTION_WARNING = 7   # 경고 기준
BACKUP_RETENTION_OK      = 30  # 권장 기준

# 위험도 상수
HIGH   = "🔴 HIGH"
MEDIUM = "🟡 MEDIUM"
LOW    = "🟢 LOW"


# ──────────────────────────────────────────────
# 데이터 클래스
# ──────────────────────────────────────────────

@dataclass
class CheckResult:
    """개별 점검 항목 결과"""
    check_id:    int
    name:        str
    severity:    str
    status:      str          # "PASS" / "FAIL" / "WARN"
    detail:      str
    remediation: str


@dataclass
class InstanceReport:
    """RDS 인스턴스 전체 보안 점검 결과"""
    instance_id:  str
    engine:       str
    endpoint:     str
    results:      list[CheckResult] = field(default_factory=list)

    @property
    def fail_count(self) -> int:
        return sum(1 for r in self.results if r.status == "FAIL")

    @property
    def warn_count(self) -> int:
        return sum(1 for r in self.results if r.status == "WARN")


# ──────────────────────────────────────────────
# 점검 함수
# ──────────────────────────────────────────────

def check_public_access(db: dict) -> CheckResult:
    """[1] 퍼블릭 접근 허용 여부"""
    publicly_accessible = db.get("PubliclyAccessible", False)

    if publicly_accessible:
        return CheckResult(
            check_id=1,
            name="퍼블릭 접근 허용",
            severity=HIGH,
            status="FAIL",
            detail="PubliclyAccessible = True → 인터넷에서 DB에 직접 접근 가능",
            remediation=(
                "aws rds modify-db-instance "
                f"--db-instance-identifier {db['DBInstanceIdentifier']} "
                "--no-publicly-accessible --apply-immediately"
            ),
        )
    return CheckResult(
        check_id=1,
        name="퍼블릭 접근 허용",
        severity=HIGH,
        status="PASS",
        detail="PubliclyAccessible = False",
        remediation="조치 불필요",
    )


def check_master_username(db: dict) -> CheckResult:
    """[2] 기본/약한 마스터 계정명 사용 여부"""
    username = db.get("MasterUsername", "").lower()
    is_weak  = username in WEAK_USERNAMES

    if is_weak:
        return CheckResult(
            check_id=2,
            name="기본/약한 DB 계정명 사용",
            severity=HIGH,
            status="FAIL",
            detail=f"MasterUsername = '{username}' → 예측 가능한 기본 계정명 사용",
            remediation=(
                "Secrets Manager를 통해 강력한 비밀번호로 교체하고, "
                "애플리케이션별 최소 권한 계정을 별도 생성하세요."
            ),
        )
    return CheckResult(
        check_id=2,
        name="기본/약한 DB 계정명 사용",
        severity=HIGH,
        status="PASS",
        detail=f"MasterUsername = '{username}'",
        remediation="조치 불필요",
    )


def check_storage_encryption(db: dict) -> CheckResult:
    """[3] 저장 데이터 암호화 (Encryption at Rest)"""
    encrypted = db.get("StorageEncrypted", False)
    kms_key   = db.get("KmsKeyId", "")

    if not encrypted:
        return CheckResult(
            check_id=3,
            name="저장 데이터 암호화 미적용",
            severity=HIGH,
            status="FAIL",
            detail="StorageEncrypted = False → 스냅샷·백업·Read Replica 모두 비암호화",
            remediation=(
                "기존 DB는 소급 적용 불가. "
                "암호화 스냅샷 복사 후 새 인스턴스 복원:\n"
                "  aws rds copy-db-snapshot "
                "--source-db-snapshot-identifier <snap> "
                "--target-db-snapshot-identifier <snap-enc> "
                "--kms-key-id alias/aws/rds"
            ),
        )
    return CheckResult(
        check_id=3,
        name="저장 데이터 암호화 미적용",
        severity=HIGH,
        status="PASS",
        detail=f"StorageEncrypted = True, KmsKeyId = {kms_key or 'N/A'}",
        remediation="조치 불필요",
    )


def check_security_groups(db: dict, ec2_client) -> CheckResult:
    """[4] 보안 그룹 인바운드 규칙 과다 개방 (0.0.0.0/0 or ::/0)"""
    sg_ids     = [sg["VpcSecurityGroupId"] for sg in db.get("VpcSecurityGroups", [])]
    open_rules = []

    if sg_ids:
        response = ec2_client.describe_security_groups(GroupIds=sg_ids)
        for sg in response.get("SecurityGroups", []):
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port   = rule.get("ToPort",   0)
                # IPv4 전체 개방
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") in ("0.0.0.0/0",):
                        open_rules.append(
                            f"SG={sg['GroupId']} port={from_port}-{to_port} cidr=0.0.0.0/0"
                        )
                # IPv6 전체 개방
                for ip_range in rule.get("Ipv6Ranges", []):
                    if ip_range.get("CidrIpv6") == "::/0":
                        open_rules.append(
                            f"SG={sg['GroupId']} port={from_port}-{to_port} cidr=::/0"
                        )

    if open_rules:
        return CheckResult(
            check_id=4,
            name="보안 그룹 과다 개방",
            severity=HIGH,
            status="FAIL",
            detail="전체 IP 허용 규칙 발견:\n  " + "\n  ".join(open_rules),
            remediation=(
                "위험 규칙 제거 후 특정 SG 또는 CIDR로 재제한:\n"
                "  aws ec2 revoke-security-group-ingress "
                "--group-id <sg-id> --protocol tcp --port 3306 --cidr 0.0.0.0/0\n"
                "  aws ec2 authorize-security-group-ingress "
                "--group-id <sg-id> --protocol tcp --port 3306 --source-group <app-sg-id>"
            ),
        )
    return CheckResult(
        check_id=4,
        name="보안 그룹 과다 개방",
        severity=HIGH,
        status="PASS",
        detail="0.0.0.0/0 또는 ::/0 허용 규칙 없음",
        remediation="조치 불필요",
    )


def check_backup_retention(db: dict) -> CheckResult:
    """[5] 자동 백업 보존 기간"""
    period = db.get("BackupRetentionPeriod", 0)
    db_id  = db["DBInstanceIdentifier"]

    if period == 0:
        return CheckResult(
            check_id=5,
            name="자동 백업 미설정",
            severity=MEDIUM,
            status="FAIL",
            detail="BackupRetentionPeriod = 0 → 자동 백업 비활성화",
            remediation=(
                f"aws rds modify-db-instance "
                f"--db-instance-identifier {db_id} "
                "--backup-retention-period 30 --apply-immediately"
            ),
        )
    if period < BACKUP_RETENTION_WARNING:
        return CheckResult(
            check_id=5,
            name="자동 백업 보존 기간 부족",
            severity=MEDIUM,
            status="WARN",
            detail=f"BackupRetentionPeriod = {period}일 (권장: 7일 이상, 최적: 30일 이상)",
            remediation=(
                f"aws rds modify-db-instance "
                f"--db-instance-identifier {db_id} "
                "--backup-retention-period 30 --apply-immediately"
            ),
        )
    status  = "PASS" if period >= BACKUP_RETENTION_OK else "WARN"
    message = "양호" if period >= BACKUP_RETENTION_OK else f"{period}일 (30일 이상 권장)"
    return CheckResult(
        check_id=5,
        name="자동 백업 보존 기간",
        severity=MEDIUM,
        status=status,
        detail=f"BackupRetentionPeriod = {period}일 → {message}",
        remediation="조치 불필요" if status == "PASS" else (
            f"aws rds modify-db-instance "
            f"--db-instance-identifier {db_id} "
            "--backup-retention-period 30 --apply-immediately"
        ),
    )


def check_ssl_tls(db: dict, rds_client) -> CheckResult:
    """[6] SSL/TLS 전송 암호화 강제 여부 (파라미터 그룹)"""
    engine     = db.get("Engine", "").lower()
    pg_name    = None

    for pg in db.get("DBParameterGroups", []):
        pg_name = pg.get("DBParameterGroupName")
        break

    if not pg_name:
        return CheckResult(
            check_id=6,
            name="SSL/TLS 전송 암호화",
            severity=MEDIUM,
            status="WARN",
            detail="파라미터 그룹 정보를 확인할 수 없음",
            remediation="커스텀 파라미터 그룹 생성 후 SSL 파라미터 적용 필요",
        )

    # 기본 파라미터 그룹은 수정 불가 → WARN 처리
    if pg_name.startswith("default."):
        return CheckResult(
            check_id=6,
            name="SSL/TLS 전송 암호화",
            severity=MEDIUM,
            status="WARN",
            detail=f"기본 파라미터 그룹({pg_name}) 사용 중 → SSL 강제 설정 불가",
            remediation=(
                "커스텀 파라미터 그룹 생성 후 적용:\n"
                "  MySQL  → require_secure_transport=ON\n"
                "  PostgreSQL → ssl=1, rds.force_ssl=1"
            ),
        )

    # SSL 관련 파라미터 조회
    try:
        if "mysql" in engine or "mariadb" in engine:
            param_name = "require_secure_transport"
        elif "postgres" in engine:
            param_name = "rds.force_ssl"
        else:
            param_name = "ssl"

        resp   = rds_client.describe_db_parameters(
            DBParameterGroupName=pg_name,
            Source="user",
        )
        params = {p["ParameterName"]: p.get("ParameterValue", "") for p in resp.get("Parameters", [])}
        value  = params.get(param_name, "NOT_SET")

        ssl_enabled = value in ("1", "ON", "on", "true", "True")
        if ssl_enabled:
            return CheckResult(
                check_id=6,
                name="SSL/TLS 전송 암호화",
                severity=MEDIUM,
                status="PASS",
                detail=f"파라미터 {param_name} = {value} (강제 적용 중)",
                remediation="조치 불필요",
            )
        return CheckResult(
            check_id=6,
            name="SSL/TLS 전송 암호화",
            severity=MEDIUM,
            status="FAIL",
            detail=f"파라미터 {param_name} = {value} (SSL 미강제 → 평문 연결 허용)",
            remediation=(
                f"aws rds modify-db-parameter-group "
                f"--db-parameter-group-name {pg_name} "
                f"--parameters ParameterName={param_name},"
                "ParameterValue=ON,ApplyMethod=immediate"
            ),
        )
    except Exception as e:
        return CheckResult(
            check_id=6,
            name="SSL/TLS 전송 암호화",
            severity=MEDIUM,
            status="WARN",
            detail=f"파라미터 조회 실패: {e}",
            remediation="IAM 권한(rds:DescribeDBParameters) 확인 필요",
        )


def check_cloudwatch_logs(db: dict) -> CheckResult:
    """[7] CloudWatch 로그 내보내기 설정 여부"""
    enabled_logs = db.get("EnabledCloudwatchLogsExports", [])
    engine       = db.get("Engine", "").lower()
    db_id        = db["DBInstanceIdentifier"]

    # 엔진별 권장 로그 타입
    if "mysql" in engine or "mariadb" in engine:
        recommended = {"audit", "error", "general", "slowquery"}
    elif "postgres" in engine:
        recommended = {"postgresql", "upgrade"}
    else:
        recommended = {"error"}

    enabled_set = set(enabled_logs)
    missing     = recommended - enabled_set

    if not enabled_logs:
        return CheckResult(
            check_id=7,
            name="CloudWatch 로그 미설정",
            severity=MEDIUM,
            status="FAIL",
            detail="EnabledCloudwatchLogsExports = [] → 로그 미전송",
            remediation=(
                f"aws rds modify-db-instance "
                f"--db-instance-identifier {db_id} "
                '--cloudwatch-logs-export-configuration '
                '\'{"EnableLogTypes":["audit","error","general","slowquery"]}\' '
                "--apply-immediately"
            ),
        )
    if missing:
        return CheckResult(
            check_id=7,
            name="CloudWatch 로그 일부 미설정",
            severity=MEDIUM,
            status="WARN",
            detail=f"활성화: {sorted(enabled_set)} | 누락: {sorted(missing)}",
            remediation=(
                f"aws rds modify-db-instance "
                f"--db-instance-identifier {db_id} "
                f'--cloudwatch-logs-export-configuration '
                f'{{"EnableLogTypes":{json.dumps(sorted(recommended))}}} '
                "--apply-immediately"
            ),
        )
    return CheckResult(
        check_id=7,
        name="CloudWatch 로그 설정",
        severity=MEDIUM,
        status="PASS",
        detail=f"활성화된 로그: {sorted(enabled_set)}",
        remediation="조치 불필요",
    )


# ──────────────────────────────────────────────
# 추가 정보 조회 함수
# ──────────────────────────────────────────────

def get_additional_info(db: dict) -> dict:
    """IAM 인증, 삭제 방지, Multi-AZ, 자동 업그레이드 등 추가 항목"""
    return {
        "IAM DB 인증":         db.get("IAMDatabaseAuthenticationEnabled", False),
        "삭제 방지":           db.get("DeletionProtection", False),
        "Multi-AZ":            db.get("MultiAZ", False),
        "마이너 버전 자동 업그레이드": db.get("AutoMinorVersionUpgrade", True),
        "엔진 버전":           db.get("EngineVersion", "N/A"),
    }


# ──────────────────────────────────────────────
# 보고서 출력
# ──────────────────────────────────────────────

def print_report(report: InstanceReport, extra_info: dict) -> None:
    """콘솔 보고서 출력"""
    sep = "=" * 70

    print(f"\n{sep}")
    print(f"  RDS 보안 점검 보고서")
    print(f"  인스턴스: {report.instance_id}")
    print(f"  엔진    : {report.engine}")
    print(f"  엔드포인트: {report.endpoint}")
    print(sep)

    for r in report.results:
        icon = "✅" if r.status == "PASS" else ("⚠️ " if r.status == "WARN" else "❌")
        print(f"\n  [{r.check_id}] {r.name}  {r.severity}")
        print(f"  상태   : {icon} {r.status}")
        print(f"  내용   : {r.detail}")
        if r.status != "PASS":
            print(f"  조치방법 : {r.remediation}")

    # 추가 정보
    print(f"\n{'-' * 70}")
    print("  추가 보안 정보")
    for k, v in extra_info.items():
        flag = "✅" if v else "❌"
        print(f"  {flag}  {k}: {v}")

    # 요약
    print(f"\n{sep}")
    total = len(report.results)
    pass_ = total - report.fail_count - report.warn_count
    print(f"  요약: 전체 {total}개 항목 | PASS {pass_} | WARN {report.warn_count} | FAIL {report.fail_count}")
    if report.fail_count == 0 and report.warn_count == 0:
        print("  종합 판정: ✅ 양호")
    elif report.fail_count == 0:
        print("  종합 판정: ⚠️  일부 개선 권장")
    else:
        print("  종합 판정: ❌ 즉시 조치 필요")
    print(sep)


def export_json(reports: list[InstanceReport], path: str = "rds_security_report.json") -> None:
    """JSON 형식으로 결과 저장"""
    output = []
    for rpt in reports:
        output.append({
            "instance_id": rpt.instance_id,
            "engine":      rpt.engine,
            "endpoint":    rpt.endpoint,
            "fail_count":  rpt.fail_count,
            "warn_count":  rpt.warn_count,
            "results": [
                {
                    "check_id":    r.check_id,
                    "name":        r.name,
                    "severity":    r.severity,
                    "status":      r.status,
                    "detail":      r.detail,
                    "remediation": r.remediation,
                }
                for r in rpt.results
            ],
        })
    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
    print(f"\n  📄 JSON 보고서 저장 완료: {path}")


# ──────────────────────────────────────────────
# 메인 실행
# ──────────────────────────────────────────────

def run_rds_security_check(
    region:      str = "ap-northeast-2",
    export_path: Optional[str] = "rds_security_report.json",
) -> list[InstanceReport]:
    """
    모든 RDS 인스턴스에 대해 보안 점검을 실행하고 결과를 반환합니다.

    Parameters
    ----------
    region      : AWS 리전 (기본값: 서울)
    export_path : JSON 결과 파일 경로 (None이면 저장 안 함)

    Returns
    -------
    list[InstanceReport]
    """
    rds_client = boto3.client("rds", region_name=region)
    ec2_client = boto3.client("ec2", region_name=region)

    print(f"\n🔍 Amazon RDS 보안 점검 시작 (리전: {region})")

    response  = rds_client.describe_db_instances()
    instances = response.get("DBInstances", [])

    if not instances:
        print("  ℹ️  점검할 RDS 인스턴스가 없습니다.")
        return []

    all_reports: list[InstanceReport] = []

    for db in instances:
        db_id    = db["DBInstanceIdentifier"]
        engine   = f"{db.get('Engine','?')} {db.get('EngineVersion','')}"
        endpoint = db.get("Endpoint", {}).get("Address", "N/A")

        report = InstanceReport(
            instance_id=db_id,
            engine=engine,
            endpoint=endpoint,
        )

        # 7개 항목 순차 점검
        report.results.append(check_public_access(db))
        report.results.append(check_master_username(db))
        report.results.append(check_storage_encryption(db))
        report.results.append(check_security_groups(db, ec2_client))
        report.results.append(check_backup_retention(db))
        report.results.append(check_ssl_tls(db, rds_client))
        report.results.append(check_cloudwatch_logs(db))

        extra_info = get_additional_info(db)
        print_report(report, extra_info)

        all_reports.append(report)

    # JSON 내보내기
    if export_path:
        export_json(all_reports, export_path)

    return all_reports


# ──────────────────────────────────────────────
# 실행 진입점
# ──────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Amazon RDS 보안 점검 도구")
    parser.add_argument(
        "--region",
        default="ap-northeast-2",
        help="AWS 리전 (기본값: ap-northeast-2 서울)",
    )
    parser.add_argument(
        "--output",
        default="rds_security_report.json",
        help="JSON 결과 파일 경로 (기본값: rds_security_report.json)",
    )
    args = parser.parse_args()

    run_rds_security_check(region=args.region, export_path=args.output)
