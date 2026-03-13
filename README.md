Lab 02: Block Open Security Groups
Overview
In this lab, I built a policy-as-code control that blocks cloud infrastructure configurations exposing sensitive management ports to the public internet.
Specifically, the policy detects when a security group allows traffic from:
0.0.0.0/0
to sensitive ports such as:
22 (SSH)
3389 (RDP)
These ports are commonly targeted by attackers scanning the internet for vulnerable systems.
Using Rego, Conftest, and Terraform, this lab demonstrates how insecure infrastructure configurations can be automatically detected and blocked before deployment.
What This Lab Demonstrates
By completing this lab I learned how to:
Write security policies using Rego
Test infrastructure configurations using Conftest
Convert Terraform plans to JSON for analysis
Detect insecure network exposure automatically
Troubleshoot real DevSecOps setup issues
Validate both failing and passing configurations
Tools Used
Tool	Purpose
GitHub	Version control
GitHub Codespaces	Browser-based development environment
Terraform	Generates infrastructure configuration plan
Rego	Policy language used by Open Policy Agent
Conftest	Policy testing framework
Lab Architecture
The workflow used in this lab:
Terraform Configuration
        ↓
Terraform Plan
        ↓
Convert Plan → JSON
        ↓
Conftest Policy Test
        ↓
Rego Policy Evaluation
        ↓
PASS or FAIL
This mirrors how DevSecOps pipelines enforce security guardrails before deployment.
Step-by-Step Instructions
Step 1: Create the GitHub Repository
Create a repository named:
no-open-sg
Enable:
Add a README file
Step 2: Create Terraform Configuration
Create a file:
sg.tf
Add:
resource "null_resource" "example" {
  triggers = {
    open_sg = jsonencode({
      name        = "open_sg"
      description = "Allows SSH from anywhere"
      ingress = [{
        from_port   = 22
        to_port     = 22
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
      }]
      egress = [{
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
      }]
    })
  }
}
This simulates a misconfigured security group allowing SSH from anywhere.
Step 3: Create the Policy Folder
Create:
policy/
Inside create:
deny-open-sg.rego
Add:
package main

open_sg = decoded {
  input.resource_changes[_].change.after.triggers["open_sg"] != ""
  json.unmarshal(input.resource_changes[_].change.after.triggers["open_sg"], decoded)
}

deny[msg] {
  ing := open_sg.ingress[_]
  ing.cidr_blocks[_] == "0.0.0.0/0"
  ing.from_port == 22
  msg := "Open SSH access (port 22) to the internet is not allowed."
}

deny[msg] {
  ing := open_sg.ingress[_]
  ing.cidr_blocks[_] == "0.0.0.0/0"
  ing.from_port == 3389
  msg := "Open RDP access (port 3389) to the internet is not allowed."
}
Step 4: Configure Conftest
Create:
conftest.toml
Add:
policy = ["policy"]
Step 5: Open the Repo in Codespaces
Open the repository.
Click:
Code → Codespaces → Create Codespace
Step 6: Install Terraform
Terraform was not installed by default.
Install utilities:
sudo apt update
sudo apt install -y wget unzip
Download Terraform:
wget https://releases.hashicorp.com/terraform/1.14.7/terraform_1.14.7_linux_amd64.zip
Unzip:
unzip terraform_1.14.7_linux_amd64.zip
Move binary:
sudo mv terraform /usr/local/bin/
Verify:
terraform version
Step 7: Install Conftest
wget https://github.com/open-policy-agent/conftest/releases/download/v0.59.0/conftest_0.59.0_Linux_x86_64.tar.gz
tar xzf conftest_0.59.0_Linux_x86_64.tar.gz
sudo mv conftest /usr/local/bin
conftest --version
Step 8: Initialize Terraform
terraform init
Step 9: Generate Terraform Plan
terraform plan -out=tfplan.binary
Step 10: Convert Plan to JSON
terraform show -json tfplan.binary > input.json
Step 11: Test the Policy
conftest test input.json --all-namespaces
Expected result:
FAIL - input.json - main - Open SSH access (port 22) to the internet is not allowed.
Step 12: Fix the Misconfiguration
Update sg.tf:
cidr_blocks = ["0.0.0.0/0"]
to:
cidr_blocks = ["10.0.0.0/16"]
Step 13: Retest
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > input.json
conftest test input.json --all-namespaces
Expected result:
2 tests, 2 passed, 0 failures
Issues Encountered
Terraform Not Installed
Error:
terraform: command not found
Solution: Installed Terraform manually using wget and unzip.
Terraform Package Not Found
Error:
unable to locate package terraform
Solution: Installed Terraform directly from HashiCorp releases.
Conftest Could Not Find Policies
Error:
no policies found in [policy]
Cause: Incorrect file extension.
deny-open-sg.repo
Correct file:
deny-open-sg.rego
Solution:
mv policy/deny-open-sg.repo policy/deny-open-sg.rego
Rego Typo
Error caused by:
denv[msg]
Correct syntax:
deny[msg]
Bash Syntax Error
bash: syntax error near unexpected token '}'
Cause: Policy code pasted into terminal instead of saved to file.
Results
Insecure Configuration
cidr_blocks = ["0.0.0.0/0"]
Result:
FAIL - Open SSH access to the internet is not allowed
Secure Configuration
cidr_blocks = ["10.0.0.0/16"]
Result:
2 tests, 2 passed
Compliance Alignment
Control	Description
AC-4	Information Flow Enforcement
AC-6(9)	Least Privilege for network ports
SC-7	Boundary Protection
SC-7(3)	Deny-by-Default Access
SI-4	Monitoring Unauthorized Communications
Plain English Explanation
This lab prevents a cloud server from being accidentally exposed to the internet. If someone deploys infrastructure that allows public SSH or RDP access, the policy automatically blocks it.
Technical Explanation
Terraform plans are converted to JSON and evaluated using Conftest against a Rego policy that denies insecure ingress rules exposing sensitive management ports.
Outcome
This project demonstrates:
Policy-as-Code implementation
Infrastructure security validation
DevSecOps workflow troubleshooting
Automated guardrails for cloud security
