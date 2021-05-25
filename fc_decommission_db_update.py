"""
This Module is to Delete Multiple Stacks
Author: Hitachi Vantara
Contributor: Vara
Date: 18-10-2021

1. Decomission of all the foundational components in the target account.
2. Update the IPAM Dynamodb making the CIDR avilable.
"""

import sys
from os import environ
import logging
import argparse
import time
import boto3
import botocore
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

LOGGER = logging.getLogger(__name__)
LOGFORMAT = "%(levelname)s: %(message)s"
LOGGER = logging.getLogger("Delete Stacks")
LOGLEVEL = environ.get("logLevel", "INFO")
logging.basicConfig(format=LOGFORMAT, level=LOGLEVEL)
LOGGER.setLevel(logging.getLevelName(LOGLEVEL))


PARSER = argparse.ArgumentParser(description="This Module decomission the target account")

PARSER.add_argument("-a", "--action", help='stack actions(delete,update)', required=True)
PARSER.add_argument("-r", "--region", type=str, required=True)

ARGS = PARSER.parse_args()

StackRegion = ARGS.region
AccountName = environ['AccountName']
num = environ['num']

def boto3_client(resource_type, region_name, session_name):
    """
    Function to get the aws credentials
    Args:

       resource_type (str): Resource type to initilize (Ex: ec2, s3)
       session_name(obj): contains assume role object
    """
    try:
        if "role_arn" in environ:
            client = boto3.client('sts')
            response = client.assume_role(RoleArn=environ[role_arn],
                                          RoleSessionName=session_name)
            service_client = boto3.client(
                resource_type, region_name=region_name,
                aws_access_key_id=response['Credentials']['AccessKeyId'],
                aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                aws_session_token=response['Credentials']['SessionToken']
                )
        else:
            service_client = boto3.client(resource_type, region_name)
    except Exception as error:
        LOGGER.info("Failed to assume the role for Account:"+str(error))
        raise
    return service_client


def boto3_resource(resource_type, region_name, session_name):
    """
    Function to get the aws credentials
    Args:
       resource_type (str): Resource type to initilize (Ex: ec2, s3)
       session_name(obj): contains assume role object
    """
    try:
        if "role_arn" in environ:
            client = boto3.client('sts')
            response = client.assume_role(RoleArn=environ[role_arn],
                                          RoleSessionName=session_name)
            service_resource = boto3.resource(
                resource_type, region_name=region_name,
                aws_access_key_id=response['Credentials']['AccessKeyId'],
                aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                aws_session_token=response['Credentials']['SessionToken']
                )
        else:
            service_resource = boto3.resource(resource_type, region_name)
    except Exception as error:
        LOGGER.info("Failed to assume the role for Account:"+str(error))
        raise
    return service_resource


def get_vpc_cidr(account_name):
    db_resource = boto3_resource('dynamodb', 'us-east-1', 'dbsen')
    table = db_resource.Table('ACCOUNT-META-DATA')
    db_resource = boto3.resource('dynamodb')
    table = db_resource.Table('ACCOUNT-META-DATA')
    response = table.query(KeyConditionExpression=Key('accountIdentifier').eq(account_name))
    for cidr in response['Items']:
        if cidr['vpcCidr']:
            vpc_cidr = cidr['vpcCidr']
        else:
            vpc_cidr = None
    return vpc_cidr

def stack_exists(region_name, stack_name):
    cft_client = boto3_client('cloudformation', region_name, 'cftlist')
    stacks = cft_client.list_stacks()['StackSummaries']
    for stack in stacks:
        if stack['StackStatus'] == 'DELETE_COMPLETE':
            continue
        if stack_name == stack['StackName']:
            return True
    return False

def deleteconfigkmscloudtrail():
    try:
        stack_deletion_status = []
        ec2 = boto3_client('ec2', StackRegion, 'ec2list')
        regionlist = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
        for region_name in regionlist:
            cft_client = boto3_client('cloudformation', region_name, 'cftlist')
            LOGGER.info("Region Name: "+region_name)
            cloud_kms_stack = ['NVSGIS'+AccountName+num+'-CONFIG', 'NVSGIS'+AccountName+num+'-CLOUDTRAIL', 'NVSGIS'+AccountName+num+'-KMS']
            for stack_name in cloud_kms_stack:
                if stack_exists(region_name, stack_name):
                    cft_client.delete_stack(StackName=stack_name)
                    LOGGER.info("Deleting {}".format(stack_name))

                    waiter = cft_client.get_waiter('stack_delete_complete')
                    waiter_response = waiter.wait(StackName=stack_name)
                    if waiter_response is None:
                        LOGGER.info("Stack "+stack_name+" is deleted successfully")
                        stack_deletion_status.append(True)
                    else:
                        LOGGER.info("Deletion of stack failed")
                        stack_deletion_status.append(False)
                else:
                    LOGGER.info("{} Stack Name does not exist".format(stack_name))
                    stack_deletion_status.append(True)
        return stack_deletion_status
    except ClientError as error:
        LOGGER.info("Error Occure in deleting the stack  {}".format(stack_name))
        return False


def stack_deletion():
    '''
    stack deletion of each foundational component service
    '''
    ###delete stack###
    exsbx_services = ['BILLING-BUDGET', 'BILLING-ALARMS', 'PRIVATE-LINKS', 'CONFIG-RULES', 'S3-LOGS', 'VPC-SECURITYGROUPS', 'VPC-FLOWLOG',
    'VPC-PEERING', 'S3-PLATFORM', 'ORACLE-OPTIONGROUP', 'MYSQL-OPTIONGROUP', 'MSSQL-OPTIONGROUP', 'VPC']
    #EERSTD = ['EC2', 'S3', 'SG', 'IGW', 'VPC']

    try:
        cft_client = boto3_client('cloudformation', StackRegion, 'cftlist')
        stack_deletion_status = []
        for service_name in exsbx_services:
            stack_name = 'NVSGIS'+AccountName+num+'-'+service_name
            LOGGER.info("StackName of"+service_name + stack_name)
            if(service_name == 'VPC'):
                cloudkms_status = deleteconfigkmscloudtrail()
                stack_deletion_status.extend(cloudkms_status)

            if stack_exists(StackRegion, stack_name):
                cft_client.delete_stack(StackName=stack_name)
                LOGGER.info("Deleting {}".format(stack_name))
                waiter = cft_client.get_waiter('stack_delete_complete')
                waiter_response = waiter.wait(StackName=stack_name)
                if waiter_response is None:
                    LOGGER.info("Stack "+stack_name+" is deleted successfully")
                    stack_deletion_status.append(True)
                else:
                    LOGGER.info("Deletion of stack failed")
                    stack_deletion_status.append(False)
            else:
                LOGGER.info("{} Stack Name does not exist".format(stack_name))
                stack_deletion_status.append(True)
        return stack_deletion_status
    except ClientError as error:
        LOGGER.info(error)
        LOGGER.info("Error in {}".format(stack_name))
        return False

def dynamodb_update():
    dynamodb = boto3_resource('dynamodb', 'us-east-1', 'dbsen')
    table = dynamodb.Table('NVSGISRCC-IPAM-TST-V1')
    account_name = AccountName+num
    vpc_cidr = get_vpc_cidr(account_name)
    response = table.update_item(Key={'cidr': vpc_cidr},
        UpdateExpression="SET #vpc_identifier = :v, #ritm = :r, #timestamp = :t",
        ExpressionAttributeValues={':v': "",
            ':r': "", ':t': ""},
        ExpressionAttributeNames={
            "#vpc_identifier": "vpc_identifier",
            "#ritm": "ritm",
            "#timestamp": "timestamp"
        },
        ReturnValues="UPDATED_NEW"
    )
    return response

def main():
    '''
    Main function
    '''
    if ARGS.action == 'delete':
        state = stack_deletion()
    elif ARGS.action == 'update':
        update_response = dynamodb_update()
        LOGGER.info("NVSGISRCC-IPAM-TST-V1 table has been updated successfully")
        LOGGER.info(update_response)
        state = [True]
    return state

if __name__ == '__main__':
    state = main()
    if False in state:
        sys.exit(1)
