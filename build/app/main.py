#!/usr/bin/env python3
""" Vaulty is a tool for obtaining temporary aws credentials from hashicorp vault """
from datetime import datetime
from os import environ as env
from json import dumps
from jinja2 import Template
import hvac


class Vaulty:
    """Vaulty Class"""

    def gen_data(self, vault_client):
        """ generate aws credentials or get latest secret  from vault"""
        if "aws" in self.vault_mount:
            return vault_client.secrets.aws.generate_credentials(
                name=self.vault_role,
                ttl=self.vault_ttl,
                endpoint="sts",
                mount_point=self.vault_mount,
            )
        return vault_client.secrets.kv.v2.read_secret(
            path=self.vault_secret, mount_point=self.vault_mount
        )

    def get_aws_creds_ldap(self):
        """generate temporary aws credentials, auth method radius"""
        vault_client = hvac.Client(url=self.vault_addr, verify=self.vault_verify)
        vault_client.auth.ldap.login(
            use_token=True,
            username=self.vault_user,
            password=self.vault_pass,
        )
        return self.gen_data(vault_client)

    def get_aws_creds_radius(self):
        """generate temporary aws credentials, auth method radius"""
        vault_client = hvac.Client(url=self.vault_addr, verify=self.vault_verify)
        vault_client.auth.radius.login(
            use_token=True,
            username=self.vault_user,
            password=self.vault_pass,
        )
        return self.gen_data(vault_client)

    def get_aws_creds_approle(self):
        """generate temporary aws credentials, auth method approle"""
        vault_client = hvac.Client(url=self.vault_addr, verify=self.vault_verify)
        vault_client.auth.approle.login(
            use_token=True,
            role_id=self.vault_user,
            secret_id=self.vault_pass,
        )
        return self.gen_data(vault_client)

    def output_credentials(self):
        """update local aws credentials file provided in path or to stdout"""
        if not self.vault_cred:
            print(dumps(self.vault_credentials["data"], sort_keys=True))
        else:
            with open("aws.credentials.jinja2", "r") as file_:
                template = Template(file_.read())
                aws_credentials_output = template.render(
                    access_key=self.vault_credentials["data"]["access_key"],
                    secret_key=self.vault_credentials["data"]["secret_key"],
                    security_token=self.vault_credentials["data"]["security_token"],
                )
            with open(self.vault_cred, "w") as file_:
                file_.write(aws_credentials_output)
            print(
                '{ "type": "credentials", "action":"aws credentials update", '
                + '"message":"credentials update success", "severity": "medium", "date": "'
                + datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                + '", "Lease Duration": "'
                + str(self.vault_credentials["lease_duration"])
                + '" }'
            )

    def get_secrets(self):
        """generate credentials"""
        if self.vault_method == "radius":
            self.vault_credentials = self.get_aws_creds_radius()
        elif self.vault_method == "approle":
            self.vault_credentials = self.get_aws_creds_approle()
        elif self.vault_method == "ldap":
            self.vault_credentials = self.get_aws_creds_ldap()
        if self.vault_credentials:
            self.output_credentials()
        else:
            print(
                '{"type": "credentials", "action":"aws credentials update",'
                + '"message":"credentials update failed, no auth type configured",'
                + '"severity": "medium", "date":"'
                + datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                + '"}'
            )

    def check_empty(self, env_var):
        """ env variables check """
        if env_var == "" or not env_var:
            return False
        return True

    def __init__(self):
        self.vault_addr   = env.get("VAULT_ADDR", "")
        self.vault_user   = env.get("VAULT_USER", "")
        self.vault_pass   = env.get("VAULT_PASS", "")
        self.vault_role   = env.get("VAULT_ROLE", "")
        self.vault_ttl    = env.get("VAULT_TTL", 3600)
        self.vault_method = env.get("VAULT_AUTH")
        self.vault_cred   = (
            env.get("VAULT_CRED")
            if self.check_empty(env.get("VAULT_CRED"))
            else False
        )
        self.vault_mount  = (
            env.get("VAULT_MOUNT")
            if self.check_empty(env.get("VAULT_MOUNT"))
            else "aws"
        )# aws or secret
        self.vault_secret = (
            env.get("VAULT_SECRET")
            if self.check_empty(env.get("VAULT_SECRET"))
            else "gitlab"
         )# secret at mount for example secret/gitlab
        self.vault_verify = (
            env.get("VAULT_TLS_VER")
            if self.check_empty(env.get("VAULT_TLS_VER"))
            else False
        )
        self.vault_credentials = {}


if __name__ == "__main__":
    vaulty = Vaulty()
    vaulty.get_secrets()
