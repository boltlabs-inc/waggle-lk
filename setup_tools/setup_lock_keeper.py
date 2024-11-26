import argparse
import base64
import getpass
import json
import os
from dotenv import load_dotenv
import requests

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_der, sigdecode_der
from eth_account.messages import encode_typed_data, _hash_eip191_message
from eth_keyfile import load_keyfile, decode_keyfile_json
from eth_utils.crypto import keccak


# Tenant fields
TENANT_NAME = "Game7"
TENANT_DISPLAY_NAME = "Game7 Tenant"
TENANT_DESCRIPTION = "Game7 purposes"
DEFAULT_ZONE_NAME = "game7_zone"
DEFAULT_ZONE_DESCRIPTION = "Game7 zone"

# Authorizing Entity fields
AUTH_ENTITY_TYPE_NAME = "approver_auth_entity_type"
AUTH_ENTITY_TYPE_DESCRIPTION = "Approver Auth Entity Type"
APPROVER_1_NAME = "approver_1_auth_entity"
APPROVER_1_DESCRIPTION = "Approver 1 to approve waggle claims"
APPROVER_2_NAME = "approver_2_auth_entity"
APPROVER_2_DESCRIPTION = "Approver 2 to approve waggle claims"

# Domain fields
DOMAIN_NAME = "game7_domain"
DOMAIN_DESCRIPTION = "Game7 Domain"
DOMAIN_AUTH_ENTITY_NAME_PREFIX = "game7_auth_entity"
DOMAIN_AUTH_ENTITY_DESCRIPTION = "Game7 entity type to approve claims"

# Policy fields
DOMAIN_POLICY_ADMIN_NAME = "domain_policy_admin"
POLICY_APPROVER_NAME = "policy_approver"
POLICY_APPROVER_DESCRIPTION = "Entity type to approve policies"
POLICY_APPROVER_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEEfw/MOmtobnF36IKi6WcN/sSbP2nrdSE\n3bKZV9X0j+bukH19wqtyp+JC6OiKY5E8LQn5bWM7ihBy2+0Tl0mHVQ==\n-----END PUBLIC KEY-----"
POLICY_NAME = "noop_policy"
APPROVER_POLICY_NAME = "approver_policy"

# Service provider fields
SERVICE_PROVIDER_USERNAME = "game7_service_provider"
SERVICE_PROVIDER_PASSWORD = "password"


def print_header(header):
    print("")
    print("############################################")
    print(f"      {header}")
    print("############################################")


def login(login_url, username, password):
    login_data = {
        "username": username,
        "password": password,
        "grant_type": "password",
    }
    res = requests.post(login_url, data=login_data)
    return res.json().get("access_token")


def login_status_code(login_url, username, password):
    login_data = {
        "username": username,
        "password": password,
        "grant_type": "password",
    }
    res = requests.post(login_url, data=login_data)
    return res.status_code


def get_approvers_private_keys_from_env():
    load_dotenv()
    env_vars = [
        "APPROVER_1_PRIVATE_KEY",
        "APPROVER_2_PRIVATE_KEY",
    ]
    missing_vars = []
    for var in env_vars:
        if var not in os.environ:
            missing_vars.append(var)

    if missing_vars:
        print(f"Missing environment variables: {missing_vars}")
        exit(1)

    return os.getenv("APPROVER_1_PRIVATE_KEY"), os.getenv("APPROVER_2_PRIVATE_KEY")


def private_key_to_pem_public_key(private_key):
    private_key_bytes = bytes.fromhex(private_key)

    private_key = ec.derive_private_key(
        int.from_bytes(private_key_bytes, byteorder="big"),
        ec.SECP256K1(),
        default_backend(),
    )
    public_key = private_key.public_key()

    # Convert the public key to PEM format
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return pem_public_key.decode("utf-8")


def get_mock_sign_request_typed_data():
    message_dict = {
        "domain": {
            "name": "Moonstream Dropper",
            "version": "0.2.0",
            "chainId": "0xaa36a7",
            "verifyingContract": "0x1e01dd2F620014bcA0579bBa7b982d5702fe744c",
        },
        "message": {
            "amount": "3000",
            "blockDeadline": "400000000",
            "claimant": "0x85AFAdD55A1693d227eF97361d56D0a5a6FDa104",
            "dropId": "1",
            "requestID": "279927661987246322371885526670387588087",
        },
        "types": {
            "ClaimPayload": [
                {"name": "dropId", "type": "uint256"},
                {"name": "requestID", "type": "uint256"},
                {"name": "claimant", "type": "address"},
                {"name": "blockDeadline", "type": "uint256"},
                {"name": "amount", "type": "uint256"},
            ],
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
        },
        "primaryType": "ClaimPayload",
    }
    return message_dict


def get_authorizing_data(typed_data, approver_1_private_key, approver_2_private_key):
    # Let's first prepare the typed data to be signed by creating its metadata
    content_hash = encode_typed_data(full_message=typed_data)
    content_hash = _hash_eip191_message(content_hash)
    content_hash = list(content_hash)

    metadata = {
        "order_id": "1",
        "content_hash": content_hash,
        "approval_status": 1,
        "status_reason": "Approved",
    }
    base_64_metadata = base64.b64encode(json.dumps(metadata).encode("utf-8"))
    hashed_metadata = keccak(base_64_metadata)

    # Then we prepare the authorizing data object with signatures from both approvers
    return [
        {
            "authorizing_entity": APPROVER_1_NAME,
            "level": "Domain",
            "metadata": base_64_metadata.decode("utf-8"),
            "metadata_signature": sign_metadata_with_approver(
                approver_1_private_key, hashed_metadata
            ),
        },
        {
            "authorizing_entity": APPROVER_2_NAME,
            "level": "Domain",
            "metadata": base_64_metadata.decode("utf-8"),
            "metadata_signature": sign_metadata_with_approver(
                approver_2_private_key, hashed_metadata
            ),
        },
    ]


def sign_metadata_with_approver(approver_private_key, hashed_metadata):
    # Get the signing key from the approver's private key hex
    private_key_bytes = bytes.fromhex(approver_private_key)
    signing_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)

    # Sign the hashed metadata
    signature = signing_key.sign_digest(hashed_metadata, sigencode=sigencode_der)

    # Decode the signature to ensure that s is in the lower half of the curve
    r, s = sigdecode_der(signature, signing_key.curve.order)
    order = signing_key.curve.order
    if s > order // 2:
        s = order - s

    # Rebuild the canonical signature and encode it into base64
    canonical_signature = sigencode_der(r, s, order)
    signature = base64.b64encode(canonical_signature).decode()

    # Return the base64 encoded signature
    return signature


def setup_lock_keeper(lock_keeper_url, super_admin_password):

    approver_1_private_key, approver_2_private_key = (
        get_approvers_private_keys_from_env()
    )

    print(f"Setting up Lock Keeper at {lock_keeper_url}")

    print_header("Lock Keeper Setup")

    # We first login as super admin to create the tenant
    print("Logging in as Super Admin...")
    super_admin_token = login(
        f"{lock_keeper_url}/login", "super_admin", super_admin_password
    )
    print("Success!")

    print_header("Tenant Setup")

    # We first try logging in with the Tenant, if it succeeds, we skip the tenant creation
    tenant_login_status_code = login_status_code(
        f"{lock_keeper_url}/{TENANT_NAME}/login",
        f"{TENANT_NAME}_Administrator",
        "password",
    )
    if tenant_login_status_code != 200:
        # Creates the tenant
        print("Creating Tenant...")
        req_body = {
            "tenant_name": TENANT_NAME,
            "display_name": TENANT_DISPLAY_NAME,
            "tenant_admin_email": "tenant@test.com",
            "description": TENANT_DESCRIPTION,
            "default_zone_name": DEFAULT_ZONE_NAME,
            "default_zone_description": DEFAULT_ZONE_DESCRIPTION,
            "default_zone_key_servers": [
                "key_server_1",
                "key_server_2",
                "key_server_3",
            ],
        }
        res = requests.post(
            f"{lock_keeper_url}/tenant",
            json=req_body,
            headers={"Authorization": f"Bearer {super_admin_token}"},
        )
        print("Tenant created!")

        print("Updating Tenant Admin roles...")
        # Login with the tenant admin
        tenant_admin_token = login(
            f"{lock_keeper_url}/{TENANT_NAME}/login",
            f"{TENANT_NAME}_Administrator",
            "password",
        )

        # Update the tenant admin roles
        req_body = {
            "username": f"{TENANT_NAME}_Administrator",
            "password": "password",
            "roles": ["Administrator", "AuthorizingAdmin", "Auditor"],
        }
        res = requests.put(
            f"{lock_keeper_url}/user_account",
            json=req_body,
            headers={"Authorization": f"Bearer {tenant_admin_token}"},
        )
        print("Tenant Admin roles updated!")
    else:
        print(f"Tenant '{TENANT_NAME}' already exists!")
        tenant_admin_token = login(
            f"{lock_keeper_url}/{TENANT_NAME}/login",
            f"{TENANT_NAME}_Administrator",
            "password",
        )

    print_header("Domain Setup")

    # We check if the domain exists, if not, we create it
    res = requests.get(
        f"{lock_keeper_url}/domain/{DOMAIN_NAME}",
        headers={"Authorization": f"Bearer {tenant_admin_token}"},
    )
    if res.status_code != 200:
        print("Creating Domain...")
        req_body = {
            "domain_name": DOMAIN_NAME,
            "description": DOMAIN_DESCRIPTION,
            "domain_admin_email": "domain@test.com",
        }
        res = requests.post(
            f"{lock_keeper_url}/domain",
            json=req_body,
            headers={"Authorization": f"Bearer {tenant_admin_token}"},
        )
        print("Domain created!")

        print("Logging in as Domain Admin...")
        domain_admin_token = login(
            f"{lock_keeper_url}/{TENANT_NAME}/{DOMAIN_NAME}/login",
            f"{DOMAIN_NAME}_admin",
            "password",
        )
        print("Success!")

        print("Updating Domain Admin roles...")
        req_body = {
            "username": f"{DOMAIN_NAME}_admin",
            "password": "password",
            "roles": ["DomainAdmin", "AuthorizingAdmin"],
        }
        res = requests.put(
            f"{lock_keeper_url}/user_account",
            json=req_body,
            headers={"Authorization": f"Bearer {domain_admin_token}"},
        )
        print("Domain Admin roles updated!")
    else:
        print(f"Domain '{DOMAIN_NAME}' already exists!")

        print("Logging in as Domain Admin...")
        domain_admin_token = login(
            f"{lock_keeper_url}/{TENANT_NAME}/{DOMAIN_NAME}/login",
            f"{DOMAIN_NAME}_admin",
            "password",
        )
        print("Success!")

    # We first check if the policy admin exists, if not, we create it
    res = requests.get(
        f"{lock_keeper_url}/user_account/{DOMAIN_POLICY_ADMIN_NAME}",
        headers={"Authorization": f"Bearer {domain_admin_token}"},
    )
    if res.status_code != 200:
        print("Creating Domain Policy Admin...")
        req_body = {
            "username": DOMAIN_POLICY_ADMIN_NAME,
            "password": "password",
            "user_type": "api_user",
            "roles": ["DomainAdmin", "DomainPolicyAdmin", "AuthorizingAdmin"],
        }
        res = requests.post(
            f"{lock_keeper_url}/user_account",
            json=req_body,
            headers={"Authorization": f"Bearer {domain_admin_token}"},
        )
        print("Domain Policy Admin created!")
    else:
        print(f"Domain Policy Admin '{DOMAIN_POLICY_ADMIN_NAME}' already exists!")

    print_header("Policy Approver Setup")

    print("Logging in as Policy Admin...")
    domain_policy_admin_token = login(
        f"{lock_keeper_url}/{TENANT_NAME}/{DOMAIN_NAME}/login",
        DOMAIN_POLICY_ADMIN_NAME,
        "password",
    )
    print("Success!")

    print_header("Policy Approver Setup")

    # We first check if the policy approver exists, if not, we create it
    res = requests.get(
        f"{lock_keeper_url}/authorizing_entity/{POLICY_APPROVER_NAME}",
        headers={"Authorization": f"Bearer {domain_policy_admin_token}"},
    )
    if res.status_code != 200:
        print("Creating Policy Approver Authorizing Entity...")
        req_body = {
            "name": POLICY_APPROVER_NAME,
            "description": POLICY_APPROVER_DESCRIPTION,
            "entity_type": "PolicyApprover",
        }
        res = requests.post(
            f"{lock_keeper_url}/authorizing_entity",
            json=req_body,
            headers={"Authorization": f"Bearer {domain_policy_admin_token}"},
        )
        print("Policy Approver created!")

        print("Setting one time passcode for Policy Approver Authorizing Entity...")
        passcode_res = requests.put(
            f"{lock_keeper_url}/authorizing_entity/{POLICY_APPROVER_NAME}/passcode",
            headers={"Authorization": f"Bearer {domain_policy_admin_token}"},
        ).json()
        print("One time passcode set!")

        print("Setting public key for Policy Approver Authorizing Entity...")
        req_body = {
            "name": POLICY_APPROVER_NAME,
            "passcode": passcode_res["passcode"],
            "public_key": POLICY_APPROVER_PUBLIC_KEY,
        }
        upload_path_parameter = passcode_res.get("upload_path_parameter")
        res = requests.put(
            f"{lock_keeper_url}/authorizing_entity/public_key/{upload_path_parameter}",
            json=req_body,
            headers={"Authorization": f"Bearer {domain_policy_admin_token}"},
        )
        print("Public key set!")
    else:
        print(f"Policy Approver '{POLICY_APPROVER_NAME}' already exists!")

    print_header("Authorizing Entity Type Setup")

    # We first try getting the Authorizing Entity Type, if it exists, we skip the creation
    res = requests.get(
        f"{lock_keeper_url}/authorizing_entity/type/{AUTH_ENTITY_TYPE_NAME}",
        headers={"Authorization": f"Bearer {tenant_admin_token}"},
    )
    if res.status_code != 200:
        print("Creating Authorizing Entity Type...")
        req_body = {
            "name": AUTH_ENTITY_TYPE_NAME,
            "description": AUTH_ENTITY_TYPE_DESCRIPTION,
        }
        res = requests.post(
            f"{lock_keeper_url}/authorizing_entity/type",
            json=req_body,
            headers={"Authorization": f"Bearer {tenant_admin_token}"},
        )
        print("Authorizing Entity Type created!")
    else:
        print(f"Authorizing Entity Type '{AUTH_ENTITY_TYPE_NAME}' already exists!")

    print_header("Approvers Authorizing Entity Setup")

    print_header("Approver 1 Setup")
    # We check if the approver 1 exists, if not, we create it
    res = requests.get(
        f"{lock_keeper_url}/authorizing_entity/{APPROVER_1_NAME}",
        headers={"Authorization": f"Bearer {domain_admin_token}"},
    )
    if res.status_code != 200:
        print("Creating Approver 1...")
        req_body = {
            "name": APPROVER_1_NAME,
            "description": APPROVER_1_DESCRIPTION,
            "entity_type": AUTH_ENTITY_TYPE_NAME,
        }
        res = requests.post(
            f"{lock_keeper_url}/authorizing_entity",
            json=req_body,
            headers={"Authorization": f"Bearer {domain_admin_token}"},
        )
        print("Approver 1 created!")

        print("Setting one time passcode for Approver 1...")
        passcode_res = requests.put(
            f"{lock_keeper_url}/authorizing_entity/{APPROVER_1_NAME}/passcode",
            headers={"Authorization": f"Bearer {domain_admin_token}"},
        )
        print("One time passcode set!")

        print("Setting public key for Approver 1...")

        # Convert the private key to a PEM encoded public key
        approver_1_public_key = private_key_to_pem_public_key(approver_1_private_key)
        req_body = {
            "name": APPROVER_1_NAME,
            "passcode": passcode_res.json()["passcode"],
            "public_key": approver_1_public_key,
        }
        upload_path_parameter = passcode_res.json().get("upload_path_parameter")
        res = requests.put(
            f"{lock_keeper_url}/authorizing_entity/public_key/{upload_path_parameter}",
            json=req_body,
            headers={"Authorization": f"Bearer {domain_admin_token}"},
        )
        print(res.text)
        print("Public key set!")
    else:
        print(f"Authorizing Entity '{APPROVER_1_NAME}' already exists!")

    print_header("Approver 2 Setup")
    # We check if the approver 2 exists, if not, we create it
    res = requests.get(
        f"{lock_keeper_url}/authorizing_entity/{APPROVER_2_NAME}",
        headers={"Authorization": f"Bearer {domain_admin_token}"},
    )
    if res.status_code != 200:
        print("Creating Approver 2...")
        req_body = {
            "name": APPROVER_2_NAME,
            "description": APPROVER_2_DESCRIPTION,
            "entity_type": AUTH_ENTITY_TYPE_NAME,
        }
        res = requests.post(
            f"{lock_keeper_url}/authorizing_entity",
            json=req_body,
            headers={"Authorization": f"Bearer {domain_admin_token}"},
        )
        print("Approver 2 created!")

        print("Setting one time passcode for Approver 2...")
        passcode_res = requests.put(
            f"{lock_keeper_url}/authorizing_entity/{APPROVER_2_NAME}/passcode",
            headers={"Authorization": f"Bearer {domain_admin_token}"},
        )
        print("One time passcode set!")

        print("Setting public key for Approver 2...")

        # Convert the private key to a PEM encoded public key
        approver_2_public_key = private_key_to_pem_public_key(approver_2_private_key)

        req_body = {
            "name": APPROVER_2_NAME,
            "passcode": passcode_res.json()["passcode"],
            "public_key": approver_2_public_key,
        }
        upload_path_parameter = passcode_res.json().get("upload_path_parameter")
        res = requests.put(
            f"{lock_keeper_url}/authorizing_entity/public_key/{upload_path_parameter}",
            json=req_body,
            headers={"Authorization": f"Bearer {domain_admin_token}"},
        )
        print(res.text)
        print("Public key set!")
    else:
        print(f"Authorizing Entity '{APPROVER_2_NAME}' already exists!")

    print_header("Noop Policy Setup")

    # We first check if the policy exists, if not, we create it
    res = requests.get(
        f"{lock_keeper_url}/policy/{POLICY_NAME}",
        headers={"Authorization": f"Bearer {domain_policy_admin_token}"},
    )
    if res.status_code != 200:
        print("Creating Tenant Policy...")
        # This is what the noop policy object looks like
        # {
        #     "policy_name": "noop_policy",
        #     "nonce": 1,
        #     "tenant_approvals": {"required": [], "optional": []},
        #     "domain_approvals": {"required": [], "optional": []},
        #     "min_optional_approvals": 0,
        # }
        req_body = {
            "serialized_policy": "eyJwb2xpY3lfbmFtZSI6Im5vb3BfcG9saWN5Iiwibm9uY2UiOjEsInRlbmFudF9hcHByb3ZhbHMiOnsicmVxdWlyZWQiOltdLCJvcHRpb25hbCI6W119LCJtaW5fb3B0aW9uYWxfYXBwcm92YWxzIjowfQ==",
            "signature": "MEUCIQCR8a1yPZAwjouBO2e8doVbzQQ+1ybO1M2K5G2mFF/w6wIgckxm3UHPNzzkEwJeorUxvgj083dPut5Q3U8GMxL5A2Q=",
        }
        res = requests.post(
            f"{lock_keeper_url}/policy",
            json=req_body,
            headers={"Authorization": f"Bearer {domain_policy_admin_token}"},
        )
        print("Tenant Policy created!")
    else:
        print(f"Policy '{POLICY_NAME}' already exists!")

    print_header("Approver Policy Setup")

    # We first check if the approver policy exists, if not, we create it
    res = requests.get(
        f"{lock_keeper_url}/policy/{APPROVER_POLICY_NAME}",
        headers={"Authorization": f"Bearer {domain_policy_admin_token}"},
    )
    if res.status_code != 200:
        print("Creating Approver Policy...")
        # This is what the approver policy object looks like
        # {
        #     "policy_name": "approver_policy",
        #     "nonce": 2,
        #     "domain_approvals": { "required": ["approver_1_auth_entity", "approver_2_auth_entity"], "optional": [] },
        #     "min_optional_approvals": 0
        # }
        req_body = {
            "serialized_policy": "eyJwb2xpY3lfbmFtZSI6ImFwcHJvdmVyX3BvbGljeSIsIm5vbmNlIjoyLCJkb21haW5fYXBwcm92YWxzIjp7InJlcXVpcmVkIjpbImFwcHJvdmVyXzFfYXV0aF9lbnRpdHkiLCJhcHByb3Zlcl8yX2F1dGhfZW50aXR5Il0sIm9wdGlvbmFsIjpbXX0sIm1pbl9vcHRpb25hbF9hcHByb3ZhbHMiOjB9",
            "signature": "MEQCID6uSbQzKREPq1Nf1NuiMwItpBl7rC8tR7HRMFOXudMrAiBjLSBmzlAymw3Rh5u9UTpRy3agoxosBn/zo2UDpuF5/A==",
        }
        res = requests.post(
            f"{lock_keeper_url}/policy",
            json=req_body,
            headers={"Authorization": f"Bearer {domain_policy_admin_token}"},
        )
        print("Approver Policy created!")
    else:
        print(f"Policy '{APPROVER_POLICY_NAME}' already exists!")

    print_header("Service Provider Setup")

    # We first try to login with the service provider, if it fails, we create it
    service_provider_login_status_code = login_status_code(
        f"{lock_keeper_url}/{TENANT_NAME}/login",
        SERVICE_PROVIDER_USERNAME,
        "password",
    )
    if service_provider_login_status_code != 200:
        print("Creating Service Provider...")
        req_body = {
            "username": SERVICE_PROVIDER_USERNAME,
            "password": SERVICE_PROVIDER_PASSWORD,
            "user_type": "api_user",
            "roles": ["ServiceProvider", "Auditor"],
        }
        res = requests.post(
            f"{lock_keeper_url}/user_account",
            json=req_body,
            headers={"Authorization": f"Bearer {tenant_admin_token}"},
        )
        print("Service Provider created!")
    else:
        print(f"Service Provider '{SERVICE_PROVIDER_USERNAME}' already exists!")

    print_header("Roundtrip test")

    # We try creating one key, and signing one transaction before wrapping up the script
    print("Logging in with Service Provider...")
    service_provider_token = login(
        f"{lock_keeper_url}/{TENANT_NAME}/login",
        SERVICE_PROVIDER_USERNAME,
        SERVICE_PROVIDER_PASSWORD,
    )

    print("Generating a Key...")
    req_body = {"domain_name": DOMAIN_NAME}
    res = requests.post(
        f"{lock_keeper_url}/generate",
        json=req_body,
        headers={"Authorization": f"Bearer {service_provider_token}"},
    )
    key_id = res.json().get("key_id")
    print(f"Succesfully generated a key: {key_id}")

    print("Signing typed data with noop policy...")
    typed_data = get_mock_sign_request_typed_data()
    typed_data_json = json.dumps(typed_data)
    base_64_typed_data = base64.b64encode(typed_data_json.encode("utf-8")).decode(
        "utf-8"
    )
    req_body = {
        "typed_data": base_64_typed_data,
        "authorizing_data": [],
        "key_id": key_id,
        "message_type": "Standard",
        "policies": [POLICY_NAME],
    }
    res = requests.post(
        f"{lock_keeper_url}/sign_message",
        json=req_body,
        headers={"Authorization": f"Bearer {service_provider_token}"},
    )
    signature = res.json().get("signature")
    print(f"Message signed! signature: {signature}")

    print("Signing a typed message with approver policy and two pre-approvals...")
    typed_data = get_mock_sign_request_typed_data()
    authorizing_data = get_authorizing_data(
        typed_data, approver_1_private_key, approver_2_private_key
    )

    typed_data_json = json.dumps(typed_data)
    base_64_typed_data = base64.b64encode(typed_data_json.encode("utf-8")).decode(
        "utf-8"
    )
    req_body = {
        "typed_data": base_64_typed_data,
        "authorizing_data": authorizing_data,
        "key_id": key_id,
        "message_type": "Standard",
        "policies": [APPROVER_POLICY_NAME],
    }

    res = requests.post(
        f"{lock_keeper_url}/sign_message",
        json=req_body,
        headers={"Authorization": f"Bearer {service_provider_token}"},
    )
    print(res.text)
    signature = res.json().get("signature")
    print(f"Message signed! signature: {signature}")

    print_header("Setup Complete! :)")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        prog="Setup Lock Keeper",
        description="Setup Lock Keeper with all required entities",
    )

    parser.add_argument("lock_keeper_url", type=str, help="Lock Keeper URL")
    parser.add_argument("super_admin_password", type=str, help="Super Admin Password")

    args = parser.parse_args()

    setup_lock_keeper(args.lock_keeper_url, args.super_admin_password)
