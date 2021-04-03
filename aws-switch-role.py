#!/usr/bin/env python
"""
This script performs a STS Assume Role operation for a role in a target account
It takes in an AWS Account ID, Role Name, and optional clobber flag
It assumes the role and sets credentials for the AWS CLI
"""

import boto3
import sys
import os
import json
import time
import argparse
import re
import ConfigParser

from os.path import expanduser
from datetime import datetime
from dateutil import tz
from botocore.exceptions import ClientError

def assume_role(aws_account_number, role_name, no_clobber):
    """
    Assumes the provided role in an account
    :param aws_account_number: AWS Account Number
    :param role_name: Role to assume in target account
    :param no_clobber: Whether to clobber default credentials or not
    :return: Assumed role session
    """

    # Beginning the assume role process for account
    sts = boto3.client('sts')

    # Get the current partition
    partition = sts.get_caller_identity()['Arn'].split(":")[1]

    # Get the region
    session = boto3.session.Session()
    region = session.region_name

    assumedRoleObject = sts.assume_role(
        RoleArn='arn:{}:iam::{}:role/{}'.format(
            partition,
            aws_account_number,
            role_name
        ),
        RoleSessionName='AssumedRoleSession'
    )

    # Storing STS credentials
    session = boto3.Session(
        aws_access_key_id=assumedRoleObject['Credentials']['AccessKeyId'],
        aws_secret_access_key=assumedRoleObject['Credentials']['SecretAccessKey'],
        aws_session_token=assumedRoleObject['Credentials']['SessionToken']
    )

    # Get account alias
    iam = session.client('iam')
    aliases = iam.list_account_aliases()
    alias = aliases['AccountAliases'][0]

    # Write the AWS STS token into the AWS credential file
    home = expanduser("~")
    awsconfigfile = '{}.aws{}credentials'.format(os.sep,os.sep)
    filename = home + awsconfigfile

    # Read in the existing config file
    config = ConfigParser.RawConfigParser()
    config.read(filename)

    # Set profile based on no_clobber
    if no_clobber:
        profile=aws_account_number
        clobber_message='Run CLI commands using --profile ' + aws_account_number
    else:
        profile='default'
        clobber_message='Credentials have been overwritten for default profile'

    # Put the credentials into a profile specific for the account
    if not config.has_section(profile):
        config.add_section(profile)
    config.set(profile, 'region', region)
    config.set(profile, 'aws_access_key_id', assumedRoleObject['Credentials']['AccessKeyId'])
    config.set(profile, 'aws_secret_access_key', assumedRoleObject['Credentials']['SecretAccessKey'])
    config.set(profile, 'aws_session_token', assumedRoleObject['Credentials']['SessionToken'])

    # Write the updated config file
    with open(filename, 'w+') as configfile:
        config.write(configfile)

    expiration=assumedRoleObject['Credentials']['Expiration']

    print("\nAssumed session for {} ({}) - Temporary credentials expire at {} UTC\n{}\n".format(
        alias,
        aws_account_number,
        expiration,
        clobber_message
    ))

    return session

if __name__ == '__main__':

    # Setup command line arguments
    parser = argparse.ArgumentParser(description='Perform STS Assume Role in another account')
    parser.add_argument('--account_id', type=str, required=True, help="AccountId for target AWS Account")
    parser.add_argument('--role_name', type=str, required=True, help="Role Name to assume in target account")
    parser.add_argument('--no_clobber', action='store_true', required=False, help="Do not clobber default profile")
    args = parser.parse_args()

    # Call assume
    session = assume_role(args.account_id, args.role_name, args.no_clobber)
