# Lab 02: Block Open Security Groups

## Overview

This lab demonstrates how to prevent cloud infrastructure from exposing sensitive management ports to the public internet using **policy-as-code**.

Specifically, the policy blocks configurations where a security group allows access from:

0.0.0.0/0

to sensitive ports such as:

- **22 (SSH)**
- **3389 (RDP)**

These ports are frequently targeted by attackers scanning for vulnerable systems. Using **Rego**, **Conftest**, and **Terraform**, this lab shows how insecure configurations can be automatically detected and blocked before deployment.

---

# What This Lab Demonstrates

By completing this lab I learned how to:

- Write security policies using **Rego**
- Test infrastructure configurations using **Conftest**
- Convert Terraform plans to JSON for analysis
- Detect insecure network exposure automatically
- Troubleshoot real DevSecOps setup issues
- Validate both failing and passing configurations

---

# Tools Used

| Tool | Purpose |
|-----|------|
| GitHub | Version control |
| GitHub Codespaces | Browser-based development environment |
| Terraform | Generates infrastructure configuration plan |
| Rego | Policy language used by Open Policy Agent |
| Conftest | Policy testing framework |

---

# Lab Architecture

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

This workflow mirrors how **DevSecOps pipelines enforce security guardrails before deployment.**

---

# Step-by-Step Instructions

## Step 1: Create the GitHub Repository

Create a repository named:

```
no-open-sg
```

Enable the option:

```
Add a README file
```

---

## Step 2: Create Terraform Configuration

Create a file named:

```
sg.tf
```

Add the following configuration:

```hcl
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
```

This simulates a **misconfigured security group** allowing SSH access from the entire internet.

---

## Step 3: Create Policy Folder

Create a folder:

```
policy/
```

Inside that folder create:

```
deny-open-sg.rego
```

Add the following policy:

```rego
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
```

---

## Step 4: Configure Conftest

Create a file named:

```
conftest.toml
```

Add:

```toml
policy = ["policy"]
```

---

## Step 5: Open the Repository in GitHub Codespaces

Open the repository.

Click:

```
Code → Codespaces → Create Codespace
```

This launches a cloud-based development environment.

---

## Step 6: Install Terraform

Terraform is not installed by default in Codespaces.

Install required tools:

```bash
sudo apt update
sudo apt install -y wget unzip
```

Download Terraform:

```bash
wget https://releases.hashicorp.com/terraform/1.14.7/terraform_1.14.7_linux_amd64.zip
```

Unzip Terraform:

```bash
unzip terraform_1.14.7_linux_amd64.zip
```

Move the binary:

```bash
sudo mv terraform /usr/local/bin/
```

Verify installation:

```bash
terraform version
```

---

## Step 7: Install Conftest

```bash
wget https://github.com/open-policy-agent/conftest/releases/download/v0.59.0/conftest_0.59.0_Linux_x86_64.tar.gz
tar xzf conftest_0.59.0_Linux_x86_64.tar.gz
sudo mv conftest /usr/local/bin
conftest --version
```

---

## Step 8: Initialize Terraform

```bash
terraform init
```

---

## Step 9: Generate Terraform Plan

```bash
terraform plan -out=tfplan.binary
```

---

## Step 10: Convert Plan to JSON

```bash
terraform show -json tfplan.binary > input.json
```

---

## Step 11: Test the Policy

```bash
conftest test input.json --all-namespaces
```

Expected output:

```
FAIL - input.json - main - Open SSH access (port 22) to the internet is not allowed.
```

This confirms the policy detected the insecure configuration.

---

## Step 12: Fix the Misconfiguration

Update the configuration in `sg.tf`.

Change:

```hcl
cidr_blocks = ["0.0.0.0/0"]
```

to:

```hcl
cidr_blocks = ["10.0.0.0/16"]
```

---

## Step 13: Retest

Run again:

```bash
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > input.json
conftest test input.json --all-namespaces
```

Expected output:

```
2 tests, 2 passed, 0 failures
```

---

# Issues Encountered

### Terraform Not Installed

Error:

```
terraform: command not found
```

Solution: Install Terraform manually using `wget` and `unzip`.

---

### Terraform Package Not Found

Error:

```
unable to locate package terraform
```

Solution: Install Terraform directly from the HashiCorp release page.

---

### Conftest Could Not Find Policies

Error:

```
no policies found in [policy]
```

Cause: incorrect file extension.

```
deny-open-sg.repo
```

Correct file:

```
deny-open-sg.rego
```

Solution:

```
mv policy/deny-open-sg.repo policy/deny-open-sg.rego
```

---

### Rego Policy Typo

Incorrect syntax:

```
denv[msg]
```

Correct syntax:

```
deny[msg]
```

---

### Bash Syntax Error

Error:

```
bash: syntax error near unexpected token '}'
```

Cause: policy code pasted into the terminal instead of the `.rego` file.

---

# Results

### Insecure Configuration

```
cidr_blocks = ["0.0.0.0/0"]
```

Result:

```
FAIL - Open SSH access to the internet is not allowed
```

---

### Secure Configuration

```
cidr_blocks = ["10.0.0.0/16"]
```

Result:

```
2 tests, 2 passed
```

---

# Plain English Explanation

This lab prevents cloud infrastructure from being accidentally exposed to the public internet. If someone attempts to deploy a server with open SSH or RDP access, the policy detects it and blocks the configuration before deployment.

---

# Technical Explanation

Terraform plans are converted to JSON and analyzed using **Conftest** against a **Rego policy** that denies insecure ingress rules exposing sensitive management ports.

---

# Outcome

This project demonstrates:

- Policy-as-Code implementation
- Infrastructure security validation
- DevSecOps workflow troubleshooting
- Automated guardrails for cloud security
