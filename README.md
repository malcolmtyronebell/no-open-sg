Lab 02: Block Open Security Groups
Overview
In this lab, I built a policy-as-code control that blocks cloud infrastructure configurations that expose sensitive management ports to the public internet.
Specifically, the policy detects when a security group allows traffic from:
0.0.0.0/0
to sensitive ports such as:
22 (SSH)
3389 (RDP)
These ports are commonly targeted by attackers scanning the internet for vulnerable systems.
Using Rego, Conftest, and Terraform, this lab demonstrates how insecure infrastructure configurations can be automatically detected and blocked before deployment.
What This Lab Demonstrates
By completing this lab I learned how to:
• write security policies using Rego
• test infrastructure configurations using Conftest
• convert Terraform plans to JSON for analysis
• detect insecure network exposure automatically
• troubleshoot real DevSecOps setup issues
• validate both failing and passing configurations
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
This is similar to how DevSecOps pipelines enforce security guardrails before deployment.
Step-by-Step Instructions
Step 1: Create the GitHub Repository
Create a new repository named:
no-open-sg
Enable:
Add a README file
Step 2: Create Terraform Configuration
Create a file named:
sg.tf
Add the following Terraform configuration:
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
This simulates a misconfigured security group that allows SSH access from the entire internet.
Step 3: Create Policy Folder
Create a directory:
policy/
Inside that folder create:
deny-open-sg.rego
Add the following policy:
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
This policy denies infrastructure configurations that expose SSH or RDP to the internet.
Step 4: Configure Conftest
Create a file named:
conftest.toml
Add:
policy = ["policy"]
This tells Conftest where to locate policy files.
Step 5: Open the Repo in GitHub Codespaces
Open the repository.
Click:
Code → Codespaces → Create Codespace
This launches a cloud-based development environment.
Step 6: Install Terraform
Terraform was not installed in Codespaces by default.
Install required utilities:
sudo apt update
sudo apt install -y wget unzip
Download Terraform:
wget https://releases.hashicorp.com/terraform/1.14.7/terraform_1.14.7_linux_amd64.zip
Unzip:
unzip terraform_1.14.7_linux_amd64.zip
Move binary:
sudo mv terraform /usr/local/bin/
Verify installation:
terraform version
Step 7: Install Conftest
If Conftest is not installed:
wget https://github.com/open-policy-agent/conftest/releases/download/v0.59.0/conftest_0.59.0_Linux_x86_64.tar.gz
tar xzf conftest_0.59.0_Linux_x86_64.tar.gz
sudo mv conftest /usr/local/bin
conftest --version
Step 8: Initialize Terraform
Run:
terraform init
Terraform will initialize the environment.
Step 9: Generate Terraform Plan
Run:
terraform plan -out=tfplan.binary
This creates a binary Terraform plan.
Step 10: Convert Plan to JSON
Run:
terraform show -json tfplan.binary > input.json
This converts the Terraform plan into JSON format so Conftest can analyze it.
Step 11: Test the Policy
Run:
conftest test input.json --all-namespaces
Expected result:
FAIL - input.json - main - Open SSH access (port 22) to the internet is not allowed.
This confirms the policy successfully detected the insecure configuration.
Step 12: Fix the Misconfiguration
Open sg.tf and change:
cidr_blocks = ["0.0.0.0/0"]
to:
cidr_blocks = ["10.0.0.0/16"]
This restricts access to a private internal network.
Step 13: Retest the Configuration
Run:
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > input.json
conftest test input.json --all-namespaces
Expected result:
2 tests, 2 passed, 0 failures
This confirms the secure configuration passes policy validation.
Issues Encountered and How They Were Fixed
Issue 1: Terraform not installed
Error:
terraform: command not found
Cause:
Terraform was not installed in Codespaces.
Solution:
Installed Terraform manually using wget and unzip.
Issue 2: Unable to locate Terraform package
Error:
unable to locate package terraform
Cause:
Terraform is not included in default Ubuntu repositories.
Solution:
Installed Terraform directly from the HashiCorp release page.
Issue 3: Conftest could not find policies
Error:
no policies found in [policy]
Cause:
The policy file had the wrong extension:
deny-open-sg.repo
instead of:
deny-open-sg.rego
Solution:
Renamed the file:
mv policy/deny-open-sg.repo policy/deny-open-sg.rego
Issue 4: Policy typo
The policy originally contained a typo:
denv[msg]
instead of:
deny[msg]
Correcting the typo fixed the issue.
Issue 5: Bash syntax error
Error:
bash: syntax error near unexpected token '}'
Cause:
Part of the Rego policy was accidentally pasted into the terminal instead of the .rego file.
Solution:
Saved the policy correctly in the file instead of the terminal.
Before and After Results
Insecure Configuration
cidr_blocks = ["0.0.0.0/0"]
Result:
FAIL - Open SSH access to the internet is not allowed
Secure Configuration
cidr_blocks = ["10.0.0.0/16"]
Result:
2 tests, 2 passed
Compliance Mapping
This lab supports several NIST SP 800-53 security principles:
Control	Description
AC-4	Information Flow Enforcement
AC-6(9)	Least Privilege for network ports
SC-7	Boundary Protection
SC-7(3)	Deny-by-default network access
SI-4	Monitoring for unauthorized communication
In Layman's Terms
This lab prevents a cloud server from being accidentally exposed to the entire internet. If someone tries to deploy infrastructure with open SSH access, the policy catches it and blocks it before the system goes live.
Technical Explanation
This lab uses Terraform, Rego, and Conftest to enforce infrastructure security controls. The policy evaluates Terraform plan output and denies configurations that expose management ports to public networks.
Final Outcome
This project demonstrates the ability to:
• implement policy-as-code security controls
• validate infrastructure configurations automatically
• troubleshoot DevSecOps environments
• enforce security guardrails before deployment
