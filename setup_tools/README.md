# Setup Lock Keeper tool

This tool is used to setup a Lock Keeper instance with everything we need to sign claims with Waggle-LK.

It will create the following entities in Lock Keeper;

- A new Tenant with the name `Game7`
- A new Domain with the name `game7_domain`
- A new empty Policy called `noop_policy`
- A new policy that requires an approver called `approver_policy`
    - the approver key used will be the provided as a keystore file created by the waggle tool
- A new Service Provider with the following info:
    - username: `game7_service_provider`
    - password: `password`

And then execute the following steps to ensure that the Lock Keeper instance is ready to sign claims:
- Login into LockKeeper with the newly created Service Provider
- Create a new key pair for the Service Provider
- Sign a message with the new key pair using the noop policy (no approvals required)
- Sign a message with the new key pair using the approver policy (pre-approving the signature)

## Usage

Before using the tool, you need export some required environment variables. Keep in mind that the approvers private key should also be the keys to use when signing the claims in the waggle CLI.

These env vars can also be set in a `.env` file in the `setup_tools` directory. To easily set these env vars, you can use the following command:

```bash
cp .env.example .env
```

Then you can edit the `.env` file and set the values for the following env vars:

| Env var | Description |
| --- | --- |
| `LOCK_KEEPER_URL` | The URL of the Lock Keeper instance |
| `SUPER_ADMIN_PASSWORD` | The password of the super admin user, used to create a new Tenant |
| `APPROVER_1_PRIVATE_KEY` | The private key of the first approver |
| `APPROVER_2_PRIVATE_KEY` | The private key of the second approver |


After that, you then need to setup your virtual environment and install the requirements:

```bash
cd setup_tools
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Then you can run the tool with the following command:

```bash
python3 setup_lock_keeper.py
```