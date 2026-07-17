Coventra Health Insurance — Complete Organizational Profile
A fictional medium-sized US healthcare insurance company, used as the reference scenario for the security pipeline.

1. Corporate Identity




Legal name
Coventra Health Insurance, Inc.
Doing business as
Coventra Health
Founded
2008
Industry
Health Insurance (Health and Medical Plans)
NAICS Code
524114 — Direct Health and Medical Insurance Carriers
HQ Address
4400 Coventra Plaza, Columbus, OH 43215, United States
Primary Domain
coventra.com
Member Portal
member.coventra.com
Email Domain
@coventra.com
State of Incorporation
Ohio
Regulatory
HIPAA Covered Entity, NCQA accredited, AM Best rated
Total Employees
64 (in baseline user population)
Members Served
~1.2 million plan members (synthetic — represented by member_NNNNN accounts)


2. Office Locations (Headquarters Detail)
Location
Function
Approximate Headcount
HQ — Columbus, OH
Executive offices, IT, Claims, Compliance, SOC
64
Geographical context
All Okta logins normally show: country=US, state=Ohio, city=Columbus, lat=40.0, lon=-82.9




3. Network Topology
Network Zones (8 segmented zones)
Zone
CIDR
Purpose
IT_Infrastructure
10.0.0.0/8
Firewalls, network gear, SOC infrastructure
Server_VLAN
10.20.0.0/16
Application servers, Splunk, backup
Secure_Data_Zone
10.30.0.0/16
PHI databases, HSM, PAM vault (most restricted)
User_LAN
10.10.0.0/16
Employee workstations
DMZ
172.16.0.0/16
Member portal, API gateway, email gateway, WAF
Cloud_AWS
172.31.0.0/16
AWS-hosted services
Vendor_Access
10.40.0.0/16
EDI servers, vendor connections
Physical_IoT
10.60.0.0/16
Building access, cameras, badge readers

Firewall Estate
Hostname
Serial
Purpose
fw-perimeter-01
PA-VM-001
Internet edge primary (10.0.1.1)
fw-perimeter-02
PA-VM-002
Internet edge secondary (10.0.1.2)
fw-internal-01
PA-VM-003
Internal segmentation (10.0.1.3)


4. Critical Assets Inventory
Secure Data Zone (most regulated — PHI/PII)
Asset Class
Hostname
IP
What it holds
PHI Database (primary)
phi-db-01
10.30.1.10
Member health records, diagnoses, prescriptions
PHI Database (secondary)
phi-db-02
10.30.1.11
Active replica for HA
Member Database (primary)
member-db-01
10.30.2.10
Demographics, eligibility, claims
Member Database (secondary)
member-db-02
10.30.2.11
Active replica
Claims Data Warehouse
claims-dw-01
10.30.3.10
Historical analytics + reporting
Hardware Security Module
hsm-01
10.30.4.10
Encryption keys (KEY-9637-PHI-ENC, KEY-8119-PHI-ENC, etc.)
PAM Vault (CyberArk)
pam-vault-01
10.30.6.10
Privileged credentials for DBs, servers

Server VLAN
Asset Class
Hostname
IP
What it holds
Claims Processing (primary)
claims-proc-01
10.20.1.10
Live claims adjudication
Claims Processing (secondary)
claims-proc-02
10.20.1.11
HA pair
Billing Server
billing-srv-01
10.20.1.20
Premium billing, payments
Provider API
provider-api-01
10.20.1.30
Provider network lookups
Splunk Indexer #1
splunk-idx-01
10.20.3.10
SIEM index
Splunk Indexer #2
splunk-idx-02
10.20.3.11
SIEM index (replica)
Splunk Search Head
splunk-sh-01
10.20.3.20
Analyst query layer
Splunk Heavy Forwarder
splunk-hf-01
10.20.3.30
Log ingestion
Backup (primary)
backup-srv-01
10.20.1.40
Veeam/encrypted backups
Backup (secondary)
backup-srv-02
10.20.1.41
Off-site backup target

User LAN
Asset
Hostname
IP
What it holds
Active Directory (primary)
ad-dc-01
10.10.5.10
Domain controller
Active Directory (secondary)
ad-dc-02
10.10.5.11
DC replica

DMZ (internet-facing)
Asset
Hostname
IP
Public-facing URL
Member Portal (primary)
member-portal-01
172.16.1.10
member.coventra.com
Member Portal (secondary)
member-portal-02
172.16.1.11
HA pair
API Gateway
api-gateway-01
172.16.3.10
api.coventra.com
Email Gateway (Proofpoint)
email-gw-01
172.16.4.10
mail.coventra.com
WAF (Web App Firewall)
waf-01
172.16.0.10
Fronts member portal

Cloud (AWS, us-east-1 / us-east-2)
Asset
Hostname
IP
Purpose
Member Portal DR
ec2-member-portal-dr
172.31.1.10
Disaster recovery
Claims API
ec2-claims-api
172.31.1.20
API in cloud
ETL Worker
ec2-etl-worker
172.31.1.30
Data pipeline jobs
AWS Account ID
123456789012
—
Single account

S3 Buckets
Bucket Name
Contents
Sensitivity
coventra-phi-backup
PHI database backups
HIPAA-protected — highest
coventra-claims-archive
Closed claims archive
HIPAA-protected
coventra-analytics
Aggregated reports
Internal
coventra-audit-logs
Compliance audit trail
Restricted

Vendor Access Zone
Asset
Hostname
IP
Purpose
EDI Server
edi-srv-01
10.40.1.10
Electronic Data Interchange — X12 transactions
CMS API Connector
cms-api-01
10.40.1.20
Centers for Medicare & Medicaid Services integration
Clearinghouse Connector
ch-connector-01
10.40.1.30
Third-party claims clearinghouse


5. Workstation Inventory
Total: ~150 endpoints across 8 departmental subnets
Department
Hostname Pattern
Subnet
Count
Example
Claims
WS-CLM-001 to WS-CLM-024
10.10.1.x
24
WS-CLM-003 → sjohnson_clm
Billing
WS-BIL-001 to WS-BIL-014
10.10.2.x
14
WS-BIL-003 → rdavis_bil
Underwriting
WS-UW-001 to WS-UW-011
10.10.3.x
11
WS-UW-005 → fmartin_uw
Customer Service
WS-CS-001 to WS-CS-019
10.10.4.x
19
WS-CS-005 → cs_rep_02
IT
WS-IT-001 to WS-IT-017
10.10.5.x
17
WS-IT-002 → soc_analyst_02
HR
WS-HR-001 to WS-HR-021
10.10.3.x
21
WS-HR-003 → (shared subnet with UW)
Finance
WS-FIN-001 to WS-FIN-015
10.10.2.x
15
WS-FIN-019 → CFO area
Compliance
WS-COMP-001 to WS-COMP-009
10.10.4.x
9
WS-COMP-007 → hipaa_officer
Total




130




6. Employee Roster (64 personnel)
Executive Leadership (4)
Account
Role
Office
cio_jones
Chief Information Officer
HQ Executive Floor
ciso_patel
Chief Information Security Officer
HQ Executive Floor
cfo_williams
Chief Financial Officer
HQ Executive Floor
vp_operations
VP Operations
HQ Executive Floor

Claims Department (12)
Process and adjudicate member medical claims.
jsmith_clm        mwilliams_clm     agarcia_clm       rthompson_clm
lmartinez_clm     bwhite_clm        ktaylor_clm       sjohnson_clm
dlee_clm          ybrown_clm        cjones_clm        nanderson_clm

Billing Department (7)
Premium billing, collections, payment processing.
pwilson_bil       ehall_bil         omitchell_bil     rdavis_bil
smoore_bil        lharris_bil       cjackson_bil

Underwriting (6)
Risk assessment, policy approval, rate determination.
fmartin_uw        awashington_uw    eroberts_uw       ctaylor_uw
mthompson_uw      kwhite_uw

IT Department (10)
Account
Role
Specialty
sysadmin_ops
Senior Systems Administrator
Linux/Windows infra
netadmin_01
Network Administrator
Firewalls, switches
soc_analyst_01
SOC Analyst Tier 1
Alert triage
soc_analyst_02
SOC Analyst Tier 1
Alert triage
soc_analyst_03
SOC Analyst Tier 2
Incident investigation
devops_jenkins
DevOps Engineer
CI/CD pipeline
dba_oracle_01
DBA — Oracle
PHI databases
dba_mssql_01
DBA — MSSQL
Member databases
cloud_ops_aws
Cloud Operations Engineer
AWS infrastructure
infosec_lead
Information Security Lead
Strategy, audits

Compliance & Risk (4)
Account
Role
hipaa_officer
HIPAA Compliance Officer
audit_mgr_01
Internal Audit Manager
risk_analyst_01
Risk Analyst
compliance_analyst_02
Compliance Analyst

Customer Service (8)
Front-line member support.
cs_rep_01    cs_rep_02    cs_rep_03    cs_rep_04
cs_rep_05    cs_rep_07    cs_rep_08    cs_supervisor

Service Accounts (9)
Non-human automation identities.
Account
Function
svc_claims_etl
Claims data pipeline
svc_backup_agent
Veeam backup runner
svc_splunk_uf
Splunk Universal Forwarder
svc_crowdstrike
CrowdStrike Falcon sensor
svc_nessus_scan
Vulnerability scanner
svc_etl_phi
PHI data ETL
svc_cyberark_pam
CyberArk vault runner (sole authorized HSM actor)
svc_edi_cms
EDI/CMS data exchange
svc_api_gateway
API gateway service

External Vendors (4)
Third-party accounts with restricted access.
Account
Vendor Role
vendor_it_support
Managed IT service provider
vendor_edi_cms
EDI clearinghouse contractor
vendor_clearinghouse
Claims clearinghouse
vendor_outsourced_dev
Outsourced development


7. Data Inventory (PHI / PII)
Tables on phi-db-01 / phi-db-02 — COVENTRA_PHI schema
Table
Sensitivity
Approximate Rows
member_health_records
PHI — highest
~1.2 M
claim_diagnoses
PHI
~4.5 M (multi-claim)
rx_history
PHI — prescription data
~3.1 M
mental_health_records
PHI — extra sensitive (42 CFR Part 2)
~85 K
lab_results
PHI
~2.8 M
prior_auth_records
PHI
~520 K

Tables on member-db-01 / claims-dw-01 — COVENTRA_MEMBERS / CLAIMS_DW
Table
Sensitivity
members
PII
member_eligibility
PII
claims
PII + claim history
claim_status
Operational
claim_lines
Detail line items
claim_payments
Payment information
eob_records
Explanation of Benefits

Members Served
~1.2 million synthetic plan members
Represented in logs as member_NNNNN@coventra.com (5-digit IDs)
Examples seen in attack traffic: member_44769, member_61031, member_22135

8. Security Stack
Layer
Product
Function
Network firewall
Palo Alto NGFW (PAN-OS)
Perimeter + internal segmentation
Endpoint protection
CrowdStrike Falcon
EDR on all workstations and servers
Database monitoring
Imperva DAM SecureSphere
SQL audit and bulk-query detection
Identity provider
Okta
SSO, MFA, account lifecycle
Privileged access
CyberArk Vault
PAM checkout for DB and server access
Cloud audit
AWS CloudTrail
API call logging
Web access
Nginx
Member portal access logs
Email gateway
Proofpoint
BEC and phishing detection
SIEM
Splunk
Central event correlation (the system this pipeline replaces/augments)
WAF
on waf-01
OWASP rule enforcement at the DMZ edge
HSM
on hsm-01
FIPS 140-2 Level 3 key store for PHI encryption


9. Business Context & Risk Profile
Why This Organization Is a High-Value Target
Healthcare PHI sells at premium rates on dark markets ($250-$1000 per record vs. ~$5 for credit card)
HIPAA breach triggers OCR investigation, fines up to $1.5M per violation category per year, and 60-day breach notification to affected members and HHS
State AG enforcement applies in addition to federal HIPAA
HITECH Act requires reporting to HHS Office for Civil Rights
Reputational damage in healthcare insurance is severe — member trust is foundational
Compliance Obligations Coventra Operates Under
HIPAA Privacy Rule (45 CFR Part 164.500-534)
HIPAA Security Rule (45 CFR Part 164.302-318)
HIPAA Breach Notification Rule (45 CFR Part 164.400-414)
42 CFR Part 2 — extra protection for substance abuse / mental health records (note mental_health_records table)
NCQA accreditation requirements for managed care
State insurance regulations — Ohio Department of Insurance
Threat Actor Interest
In the attack scenarios this pipeline detects ("Operation Silent Claim"), the implied threat actor profile:
Nation-state aligned (some attacker IPs geolocate to known threat-source countries: RU, CN, KP, IR, BY, VE)
Targeting executives via BEC (cfo_williams, ciso_patel, vp_operations)
Persistent access via legitimate-looking workstation → PHI DB connections that bypass PAM
C2 infrastructure uses lookalike domains and DNS tunneling
Exfiltration via S3 bulk download + outbound SMTP

10. Daily Operational Baseline
What "a normal day at Coventra" looks like in log volume:
Metric
Value
Total events per day
~810,000
Peak hour volume (business hours 10am-3pm ET)
~70,000 events/hour
Off-hours volume (overnight)
~2,000-5,000 events/hour
Unique active users per day
~64 (entire population active)
Database queries per day
~160,000 (Imperva-logged)
Authentication events per day
~86,000 (Okta)
Email events per day
~2,000 (Proofpoint)
Cloud API calls per day
~30,000 (CloudTrail)
Member portal requests per day
~21,000 (Nginx)


11. Quick-Reference Map
┌────────────────────────────────────────────────────────────────────┐
│                     COVENTRA HEALTH INSURANCE                       │
│                  4400 Coventra Plaza, Columbus OH                   │
│                          coventra.com                               │
├────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  INTERNET                                                           │
│     │                                                               │
│     ▼                                                               │
│  DMZ (172.16.0.0/16)                                                │
│     ├─ waf-01 ──→ member-portal-01/02 (172.16.1.10/11)              │
│     ├─ api-gateway-01 (172.16.3.10)                                 │
│     └─ email-gw-01 (172.16.4.10)  [Proofpoint]                      │
│                                                                     │
│  IT_INFRA (10.0.0.0/8)                                              │
│     ├─ fw-perimeter-01/02 [Palo Alto]                               │
│     └─ fw-internal-01                                               │
│                                                                     │
│  USER_LAN (10.10.0.0/16)                                            │
│     ├─ 130 employee workstations                                    │
│     │   ├─ Claims (WS-CLM-001..024)        10.10.1.x                │
│     │   ├─ Billing/Finance (WS-BIL/FIN)    10.10.2.x                │
│     │   ├─ Underwriting/HR (WS-UW/HR)      10.10.3.x                │
│     │   ├─ Customer Service/Comp           10.10.4.x                │
│     │   └─ IT (WS-IT-001..017)             10.10.5.x                │
│     └─ AD: ad-dc-01/02 (10.10.5.10/11)                              │
│                                                                     │
│  SERVER_VLAN (10.20.0.0/16)                                         │
│     ├─ Claims: claims-proc-01/02 (10.20.1.10/11)                    │
│     ├─ Billing: billing-srv-01 (10.20.1.20)                         │
│     ├─ Splunk: idx-01/02, sh-01, hf-01 (10.20.3.x)                  │
│     └─ Backup: backup-srv-01/02 (10.20.1.40/41)                     │
│                                                                     │
│  SECURE_DATA_ZONE (10.30.0.0/16)  [MOST RESTRICTED]                 │
│     ├─ phi-db-01/02         (10.30.1.10/11)  ← THE CROWN JEWELS     │
│     ├─ member-db-01/02      (10.30.2.10/11)                         │
│     ├─ claims-dw-01         (10.30.3.10)                            │
│     ├─ hsm-01               (10.30.4.10)                            │
│     └─ pam-vault-01         (10.30.6.10)  [CyberArk]                │
│                                                                     │
│  CLOUD_AWS (172.31.0.0/16)                                          │
│     ├─ ec2-member-portal-dr (172.31.1.10)                           │
│     ├─ ec2-claims-api       (172.31.1.20)                           │
│     ├─ ec2-etl-worker       (172.31.1.30)                           │
│     └─ S3: coventra-phi-backup, claims-archive,                     │
│             analytics, audit-logs                                   │
│                                                                     │
│  VENDOR_ACCESS (10.40.0.0/16)                                       │
│     ├─ edi-srv-01      (10.40.1.10)                                 │
│     ├─ cms-api-01      (10.40.1.20)                                 │
│     └─ ch-connector-01 (10.40.1.30)                                 │
│                                                                     │
│  PHYSICAL_IOT (10.60.0.0/16) — building access, cameras             │
│                                                                     │
└────────────────────────────────────────────────────────────────────┘


12. Why This Specific Organization Profile?
The synthetic Coventra organization was designed to be:
Realistic for a mid-size healthcare insurer — 64 employees, ~1.2M members, single HQ, hybrid AWS adoption. Matches profiles of real regional health plans like Medical Mutual of Ohio, Geisinger Health Plan, etc. (without copying any one).


Rich enough to demonstrate every detection rule — needs PHI databases (for bulk_phi_query), HSM (for hsm_wrong_actor), PAM vault (for pam_outside_window), audit log infrastructure (for audit_integrity), executives (for BEC targets), service accounts (for svc_* patterns), and lookalike domains (for bec_phishing).


Small enough that 64 users can be uniquely modeled by UEBA without statistical underfitting — yet large enough that you have meaningful peer groups (12 Claims, 7 Billing, 10 IT, etc.) for fallback profiles.


Geographically anchored to Columbus, OH so impossible-travel detections (Ohio → North Korea) are dramatic and unambiguous in the logs.


Compliance-relevant because HIPAA + 42 CFR Part 2 (mental health records) provide clear stakes for the LLM's risk justification and remediation recommendations.


This is a complete, internally-consistent profile that all the generators, rules, and detection logic reference. Every workstation name, IP, username, and asset that appears in the logs or in the final report traces back to this profile.

