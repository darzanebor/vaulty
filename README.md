### Vaulty is a tool for obtaining credentials/secrets from Hashicorp Vault

#### Environment Variables

##### Global Env Vars
#
| Variable | Default | Example |
| ------ | ------ | ------ |
| VAULT_ADDR | | https://vault.example.com:8200 |
| VAULT_ROLE | | aws_readonly |
| VAULT_TTL | 3600 | 60 |
| VAULT_AUTH | radius or approle or ldap | ldap |
| VAULT_CRED | to stdout | ./credentials |
| VAULT_MOUNT | | secret |
| VAULT_SECRET | | gitlab |
| VAULT_TLS_VER | | True |

##### AppRole Auth
#
| Variable | Default |
| ------ | ------ |
| VAULT_USER | ROLE_ID |
| VAULT_PASS | SECRET_ID |

##### Radius Auth
#
| Variable | Default |
| ------ | ------ |
| VAULT_USER | |
| VAULT_PASS | |

##### Ldap Auth
#
| Variable | Default |
| ------ | ------ |
| VAULT_USER | |
| VAULT_PASS | |

##### How-To
# 

###### 0. Create AWS account which you would use with Vault.
# 
###### 1. Create Policy, arn:aws:iam::*:policy/VaultAdminPolicy (example)
# 
# 
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:*"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "eks:*"
            ],
            "Resource": "*"
        }
    ]
}
```
###### 2. Create Role, arn:aws:iam::*:role/VaultAdmin with attached policy arn:aws:iam::*:policy/VaultAdminPolicy and configure Trusted relationship with account from step 0.
# 
###### 3. Enable Vault Secret Engine with Access_Key and Secret_Key for account from step 0 and nesessary timeouts.
# 
###### 4. Create role default.admin in AWS Secret Engine with type AssumedRole and Role Arn: arn:aws:iam::*:role/VaultAdmin
# 
###### 5. Configure Authentication in Vault with Methods radius, app-role or ldap(tbd) and policy which would grant access to AWS Secrets Engine:
# 
# 
```
# Read and Update aws/sts/*
path "aws/sts/*"
{
  capabilities = ["read","update"]
}
```
#
###### 6. If needed add nesessary mappings to aws-auth config map at EKS cluster
# 
# 
```
---
apiVersion: v1 
kind: ConfigMap 
metadata: 
  name: aws-auth 
  namespace: kube-system 
data: 
  mapRoles: | 
    - rolearn: arn:aws:iam::*:role/VaultAdmin
      username: system:node:vaultadmin
      groups: 
        - system:masters
```
# 
###### 7. Container usage example
```
docker run \
    -e VAULT_AUTH="ldap" \
    -e VAULT_ADDR="https://vault.example.local:8200" \
    -e VAULT_USER="some_user" \
    -e VAULT_PASS="some_password" \
    -e VAULT_ROLE="default.admin" \
    -e VAULT_TTL=60 \
    alphaceti/aws-vaulty:0.1.3
```
# 
###### 8. Gitlab Usage with Env Vars
<div align="center" width="90%">
<img src="./img/Screenshot_from_2021-08-10_18-03-03.png?raw=true" alt="Vault AWS Secret Engine">
<img src="./img/Screenshot_from_2021-08-10_18-05-10.png?raw=true" alt="Vault KV2 Secret">
</div>

