import boto3
from botocore.exceptions import ClientError

def scan_s3_buckets():
    """Scan all S3 buckets for public access misconfigurations"""
    s3 = boto3.client("s3")
    findings = []

    def add_finding(bucket_name, issue, severity):
        findings.append({
            'bucket': bucket_name,
            'issue': issue,
            'severity': severity
        })

    print("Scanning S3 buckets for public access...\n")

    buckets = s3.list_buckets()
    print(f"Found {len(buckets['Buckets'])} buckets to scan\n")

    for bucket in buckets['Buckets']:
        bucket_name = bucket['Name']

        try:
            public_block = s3.get_public_access_block(Bucket=bucket_name)
            config = public_block['PublicAccessBlockConfiguration']

            if not all([
                config.get('BlockPublicAcls'),
                config.get('BlockPublicPolicy'),
                config.get('IgnorePublicAcls'),
                config.get('RestrictPublicBuckets')
            ]):
                add_finding(bucket_name, 'Public access not fully blocked', 'CRITICAL')
                print(f"WARNING: [{bucket_name}] Public access not fully blocked")

        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                add_finding(bucket_name, 'No public access block configured', 'CRITICAL')
                print(f"CRITICAL: [{bucket_name}] No public access block configured")
            else:
                print(f"ERROR: Could not scan {bucket_name}: {str(e)}")

        except Exception as e:
            print(f"ERROR: Could not scan {bucket_name}: {str(e)}")

        try:
            versioning = s3.get_bucket_versioning(Bucket=bucket_name)
            if versioning.get('Status') != 'Enabled':
                add_finding(bucket_name, 'Bucket versioning not enabled', 'MEDIUM')
                print(f"WARNING: [{bucket_name}] Bucket versioning not enabled")
        except ClientError as e:
            print(f"ERROR: Could not check versioning for {bucket_name}: {str(e)}")

        try:
            encryption = s3.get_bucket_encryption(Bucket=bucket_name)
            rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
            if not rules:
                add_finding(bucket_name, 'Default encryption not configured', 'HIGH')
                print(f"WARNING: [{bucket_name}] Default encryption not configured")
            else:
                algo = rules[0].get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm')
                if algo != 'aws:kms':
                    add_finding(bucket_name, 'SSE-KMS not required for default encryption', 'MEDIUM')
                    print(f"WARNING: [{bucket_name}] SSE-KMS not required for default encryption")
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                add_finding(bucket_name, 'Default encryption not configured', 'HIGH')
                print(f"WARNING: [{bucket_name}] Default encryption not configured")
            else:
                print(f"ERROR: Could not check encryption for {bucket_name}: {str(e)}")

        try:
            policy_status = s3.get_bucket_policy_status(Bucket=bucket_name)
            if policy_status.get('PolicyStatus', {}).get('IsPublic'):
                add_finding(bucket_name, 'Bucket policy is public', 'CRITICAL')
                print(f"CRITICAL: [{bucket_name}] Bucket policy is public")
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                print(f"ERROR: Could not check policy status for {bucket_name}: {str(e)}")

        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            public_grants = [
                g for g in acl.get('Grants', [])
                if g.get('Grantee', {}).get('URI') in {
                    'http://acs.amazonaws.com/groups/global/AllUsers',
                    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
                }
            ]
            if public_grants:
                add_finding(bucket_name, 'Bucket ACL allows public access', 'CRITICAL')
                print(f"CRITICAL: [{bucket_name}] Bucket ACL allows public access")
        except ClientError as e:
            print(f"ERROR: Could not check ACL for {bucket_name}: {str(e)}")


            


    print(f"\nScan complete. Found {len(findings)} issues.\n")
    return findings

if __name__ == "__main__":
    scan_s3_buckets()
