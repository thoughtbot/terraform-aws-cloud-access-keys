# Based on the generic template provided by Amazon:
# https://github.com/aws-samples/aws-secrets-manager-rotation-lambdas

import boto3
import json
import logging
import os
import time
import requests


from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """Access key rotation lambda
    Args:
        event (dict): Lambda dictionary of event parameters. These keys must include the following:
            - SecretId: The secret ARN or identifier
            - ClientRequestToken: The ClientRequestToken of the secret version
            - Step: The rotation step (one of createSecret, setSecret, testSecret, or finishSecret)
        context (LambdaContext): The Lambda runtime information
    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist
        ValueError: If the secret is not properly configured for rotation
        KeyError: If the event parameters do not contain the expected keys
    """
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    # Setup the client
    service_client = boto3.client('secretsmanager', endpoint_url=os.environ['SECRETS_MANAGER_ENDPOINT'])

    # Make sure the version is staged correctly
    metadata = service_client.describe_secret(SecretId=arn)
    if not metadata['RotationEnabled']:
        logger.error("Secret %s is not enabled for rotation" % arn)
        raise ValueError("Secret %s is not enabled for rotation" % arn)
    versions = metadata['VersionIdsToStages']
    if token not in versions:
        logger.error("Secret version %s has no stage for rotation of secret %s." % (token, arn))
        raise ValueError("Secret version %s has no stage for rotation of secret %s." % (token, arn))
    if "AWSCURRENT" in versions[token]:
        logger.info("Secret version %s already set as AWSCURRENT for secret %s." % (token, arn))
        return
    elif "AWSPENDING" not in versions[token]:
        logger.error("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))
        raise ValueError("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))

    if step == "createSecret":
        create_secret(service_client, arn, token)

    elif step == "setSecret":
        set_secret(service_client, arn, token)

    elif step == "testSecret":
        test_secret(service_client, arn, token)

    elif step == "finishSecret":
        finish_secret(service_client, arn, token)

    else:
        raise ValueError("Invalid step parameter")


def create_secret(service_client, arn, token):
    """Create the secret
    This method first checks for the existence of a secret for the passed in
    token. If one does not exist, it will generate a new secret and put it with
    the passed in token. The oldest access key will be deleted.
    Args:
        service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist
    """
    username = os.environ['IAM_USERNAME']
    iam = boto3.client('iam')

    # Make sure the current secret exists
    current_secret = get_secret_dict(service_client, arn, "AWSCURRENT")

    # Check to see if we already have a value for this version of the secret
    try:
        # If we do, return it
        service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        logger.info("createSecret: Successfully retrieved secret for %s." % arn)
    except service_client.exceptions.ResourceNotFoundException:
        # Delete any access keys besides the active one
        access_keys = iam.list_access_keys(UserName=username)
        for key in access_keys['AccessKeyMetadata']:
            access_key_id = key['AccessKeyId']
            if access_key_id != current_secret['AWS_ACCESS_KEY_ID']:
                iam.delete_access_key(UserName=username, AccessKeyId=access_key_id)
                logger.info("finishSecret: Deleted previous access key %s for %s" % (access_key_id, arn))

        # Create a new access key
        response = iam.create_access_key(UserName=username)
        logger.info("createSecret: Created access key for %s." % username)
        access_key = response['AccessKey']
        current_secret['AWS_ACCESS_KEY_ID'] = access_key['AccessKeyId']
        current_secret['AWS_SECRET_ACCESS_KEY'] = access_key['SecretAccessKey']

        # generate new terraform team token
        new_tfe_token = generate_terraform_team_token(current_secret['TFE_TOKEN'])
        current_secret['TFE_TOKEN'] = new_tfe_token


        tfe_team_name = os.environ['TFE_TEAM_NAME']
        logger.info(f"createSecret: Generated terraform access token for {tfe_team_name} team"

        # Put the secret
        service_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=json.dumps(current_secret), VersionStages=['AWSPENDING'])
        logger.info("createSecret: Successfully put secret for ARN %s and version %s." % (arn, token))

def set_secret(service_client, arn, token):
    """Set the secret
    You can't generate your own access keys (they are generated by AWS), which
    means the access key already exists and there is nothing to set at this
    stage.
    Args:
        service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    """
    pass


def test_secret(service_client, arn, token):
    """Test the secret
    Validate that the secret value authenticates as the expected user.
    Args:
        service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    """

    # Get the pending version of the secret
    logger.info("testSecret: fetching AWSPENDING stage of version %s for secret %s." % (token, arn))
    pending = get_secret_dict(service_client, arn, "AWSPENDING", token)

    # Attempt to authenticate using the pending access key
    username = check_access_key(pending['AWS_ACCESS_KEY_ID'], pending['AWS_SECRET_ACCESS_KEY'])

    # Attempt to authenticate using the new Tfe Token
    check_terraform_token(pending['TFE_TOKEN'])

    logger.info("testSecret: authenticated successfully using new tfe team token.")

    # Verify that we're authenticated as the expected user
    if username == os.environ['IAM_USERNAME']:
        logger.info("testSecret: authenticated as %s for AWSPENDING stage of version %s for secret %s." % (username, token, arn))
        return
    else:
        logger.error("testSecret: authenticated as %s for AWSPENDING stage of version %s for secret %s." % (username, token, arn))
        raise ValueError("authenticated as %s for AWSPENDING stage of version %s for secret %s." % (username, token, arn))




def check_terraform_token(tfe_token, attempts=5):
    """ Function to test new Terraform team token """

    tfc_workspace_id = os.environ['TFE_WORKSPACE_ID']
    headers = {
    "Authorization" : f"Bearer {tfe_token}",
    "Content-Type" : "application/vnd.api+json"
    }
    var_list_url = f"https://app.terraform.io/api/v2/workspaces/{tfc_workspace_id}/vars"

    try:
        tfe_response = requests.get(var_list_url, headers=headers,data="")
    except Exception as exception:
        logger.error(f"Error occured while raising http request")
        raise ValueError(f"Error occured while raising http request : {exception}")

    if not tfe_response.ok:
        logger.warn(f"Failed to authenticate with new terraform team token; {attempts} attempts remaining")
        if attempts >= 0:
            time.sleep(5)
            return check_terraform_token(tfe_token, attempts - 1)
        else:
            raise ValueError("unable to authenticate using generated terraform team token")



def check_access_key(access_key_id, secret_access_key, attempts=5):
    try:
        caller=boto3.client('sts',
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_access_key).get_caller_identity()
        _prefix, username = caller['Arn'].split('/', 2)
        return username
    except ClientError:
        logger.warn("Failed to authenticate with access key; %d attempts remaining" % (attempts))
        if attempts >= 0:
            time.sleep(5)
            return check_access_key(access_key_id, secret_access_key, attempts - 1)
        else:
            raise ValueError("unable to authenticate using generated access keys")


def generate_terraform_team_token(tfe_token):
    """ Function to generate new terraform team token
    """
    #fetch team id from environment variable
    tfe_team_id = os.environ['TFE_TEAM_ID']

    # set request headers
    headers = {
    "Authorization" : f"Bearer {tfe_token}",
    "Content-Type" : "application/vnd.api+json"
    }
    # send post request to trigger and plan and apply for the Meta workspace
    tfe_team_token_url = f"https://app.terraform.io/api/v2/teams/{tfe_team_id}/authentication-token"
    tfe_response = send_http_request(requests.post, tfe_team_token_url, headers=headers, data="")

    if not tfe_response.ok:
        raise ValueError(f"Failed to generate new terraform team token, reason: {tfe_response.reason}")
    logger.info("Terraform team token generated successfully.")

    return tfe_response.json()['data']['attributes']['token']


def send_http_request(requestMethod, url, headers, payload):
    """Function to send http request, and handle error codes.
    """
    try:
        tfe_response = requestMethod(url, headers=headers,data=payload)
    except Exception as exception:
        logger.error(f"Error occured while raising http request")
        raise ValueError(f"Error occured while raising http request : {exception}")
    if not tfe_response.ok:
        logger.error("Error occured while raising terraform request")
        raise RuntimeError(f"Error received from Terraform API : {tfe_response.reason}, Error Code : {tfe_response.status_code}")
    return tfe_response


def update_terraform_variables(access_key_id, secret_access_key, tfe_token):
    """ Function to update Terraform access keys and raise run request to
    update the Meta workspace with the new access keys
    """
    #fetch workspace id from environment variable
    tfc_workspace_id = os.environ['TFE_WORKSPACE_ID']
    #fetch tfe token from environment variable

    tfe_aws_accesskey_id = ''
    tfe_aws_secret_accesskey_id = ''
    tfe_token_var_id = ''
    tfe_token_env_var_id = ''
    # set request headers
    headers = {
    "Authorization" : f"Bearer {tfe_token}",
    "Content-Type" : "application/vnd.api+json"
    }

    var_list_url = f"https://app.terraform.io/api/v2/workspaces/{tfc_workspace_id}/vars"
    tfe_response = send_http_request(requests.get, var_list_url, headers=headers, data="")

    if not tfe_response.ok:
        raise ValueError(f"Failed to get list of all terraform variables, reason: {tfe_response.reason}")
    logger.info("Retrieved terraform variables successfully.")

    # get the terraform variable ID for aws_accesskey_id and aws_secret_accesskey variables
    for each_tfe_variable in tfe_response.json()['data']:

        if each_tfe_variable['attributes']['key'] == 'aws_accesskey_id' and each_tfe_variable['attributes']['category'] == 'terraform':
            tfe_aws_accesskey_var_id = each_tfe_variable['id']

        if each_tfe_variable['attributes']['key'] == 'aws_secret_accesskey' and each_tfe_variable['attributes']['category'] == 'terraform':
            tfe_aws_secret_accesskey_var_id = each_tfe_variable['id']

        if each_tfe_variable['attributes']['key'] == 'tfe_token' and each_tfe_variable['attributes']['category'] == 'terraform':
            tfe_token_var_id = each_tfe_variable['id']

        if each_tfe_variable['attributes']['key'] == 'TFE_TOKEN' and each_tfe_variable['attributes']['category'] == 'env':
            tfe_token_env_var_id = each_tfe_variable['id']

        if tfe_aws_accesskey_var_id and tfe_aws_secret_accesskey_var_id and tfe_token_var_id and tfe_token_env_var_id:
            break

    # send patch request to update access_key_id value in tarraform variable
    access_key_id_url = f"https://app.terraform.io/api/v2/workspaces/{tfc_workspace_id}/vars/{tfe_aws_accesskey_var_id}"
    payload = {
    "data": {
        "id": tfe_aws_accesskey_var_id,
            "attributes": {
                "value": access_key_id,
            },
        "type":"vars"
        }
    }
    tfe_response = send_http_request(requests.patch, var_list_url, headers=headers, data=json.dumps(payload))
    if not tfe_response.ok:
        raise ValueError(f"Failed to update terraform access key id variable, reason: {tfe_response.reason}")
    logger.info("Terraform access key id variable updated successfully.")

    # send patch request to update access_secret_key value in tarraform variable
    access_secret_id_url = f"https://app.terraform.io/api/v2/workspaces/{tfc_workspace_id}/vars/{tfe_aws_secret_accesskey_id}"
    payload = {
    "data": {
        "id": tfe_aws_secret_accesskey_id,
        "attributes": {
            "value": secret_access_key,
        },
        "type":"vars"
        }
    }
    tfe_response = send_http_request(requests.patch, access_secret_id_url, headers=headers, data=json.dumps(payload))
    if not tfe_response.ok:
        raise ValueError(f"Failed to update terraform access key secret variable, reason: {tfe_response.reason}")
    logger.info("Terraform access key secret variable updated successfully.")

    # send patch request to update tfe_token value in tarraform variable
    tfe_token_var_id_url = f"https://app.terraform.io/api/v2/workspaces/{tfc_workspace_id}/vars/{tfe_token_var_id}"
    payload = {
    "data": {
        "id": tfe_token_var_id,
        "attributes": {
            "value": tfe_token,
        },
        "type":"vars"
        }
    }
    tfe_response = send_http_request(requests.patch, tfe_token_var_id_url, headers=headers, data=json.dumps(payload))
    if not tfe_response.ok:
        raise ValueError(f"Failed to update terraform tfe token variable, reason: {tfe_response.reason}")
    logger.info("Terraform tfe token variable updated successfully.")

    # send patch request to update TFE_TOKEN value in tarraform environment variable
    tfe_token_env_var_id_url = f"https://app.terraform.io/api/v2/workspaces/{tfc_workspace_id}/vars/{tfe_token_env_var_id}"
    payload = {
    "data": {
        "id": tfe_token_env_var_id,
        "attributes": {
            "value": tfe_token,
        },
        "type":"vars"
        }
    }
    tfe_response = send_http_request(requests.patch, tfe_token_env_var_id_url, headers=headers, data=json.dumps(payload))
    if not tfe_response.ok:
        raise ValueError(f"Failed to update terraform tfe env token variable, reason: {tfe_response.reason}")
    logger.info("Terraform tfe env token variable updated successfully.")

    # send post request to trigger and plan and apply for the Terraform workspace
    terraform_run_url = "https://app.terraform.io/api/v2/runs"
    payload = {
      "data": {
        "attributes": {
          "message": "Triggered via AWS Secret Manager (Secret Rotation)"
        },
        "type":"runs",
        "relationships": {
          "workspace": {
            "data": {
              "type": "workspaces",
              "id": tfc_workspace_id
            }
          }
        }
      }
    }
    tfe_response = send_http_request(requests.post, terraform_run_url, headers=headers, data=json.dumps(payload))
    if not tfe_response.ok:
        raise ValueError(f"Failed to trigger plan and apply on terraform workspace, reason: {tfe_response.reason}")
    logger.info("Terraform plan and apply triggered successfully.")


def finish_secret(service_client, arn, token):
    """Finish the secret
    This method finalizes the rotation process by marking the secret version
    passed in as the AWSCURRENT secret.
    Args:
        service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    Raises:
        ResourceNotFoundException: If the secret with the specified arn does not exist
    """
    # First describe the secret to get the current version
    metadata = service_client.describe_secret(SecretId=arn)
    current_version = None
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                logger.info("finishSecret: Version %s already marked as AWSCURRENT for %s" % (version, arn))
                return
            current_version = version
            break

    pending = get_secret_dict(service_client, arn, "AWSPENDING", token)

    # update terraform access keys
    update_terraform_variables(pending['AWS_ACCESS_KEY_ID'], pending['AWS_SECRET_ACCESS_KEY'], pending['TFE_TOKEN'])

    # Finalize by staging the secret version current
    service_client.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=current_version)
    logger.info("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s." % (token, arn))



def get_secret_dict(service_client, arn, stage, token=None):
    """Gets the secret dictionary corresponding for the secret arn, stage, and token
    This helper function gets credentials for the arn and stage passed in and returns the dictionary by parsing the JSON string
    Args:
        service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version, or None if no validation is desired
        stage (string): The stage identifying the secret version
    Returns:
        SecretDictionary: Secret dictionary
    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist
        ValueError: If the secret is not valid JSON
        KeyError: If the secret json does not contain the expected keys
    """
    required_fields = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'TFE_TOKEN']

    # Only do VersionId validation against the stage if a token is passed in
    if token:
        secret = service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage=stage)
    else:
        secret = service_client.get_secret_value(SecretId=arn, VersionStage=stage)
    plaintext = secret['SecretString']
    secret_dict = json.loads(plaintext)

    for field in required_fields:
        if field not in secret_dict:
            raise KeyError("%s key is missing from secret JSON" % field)

    # Parse and return the secret JSON string
    return secret_dict
