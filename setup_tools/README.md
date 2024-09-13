# Setup Lock Keeper tool

This tool is used to setup a Lock Keeper instance with everything we need to sign claims with Waggle-LK.

It will create the following entities in Lock Keeper;

- A new Tenant with the name `Game7`
- A new Domain with the name `game7_domain`
- A new empty Policy called `noop_policy`
- A new policy that requires an approver called `approver_policy`
    - the approver key used will be the provided as a keystore file created by the tool
- A new Service Provider with the following info:
    - username: `game7_service_provider`
    - password: `password`

## Usage

Before using the tool, you first need to create a virtual env, and install the requirements.

```bash
python3 -m venv venv
source venv/bin/activate
pip install requests
```

Then you can run the tool with the following command:

```bash
python setup_lock_keeper.py LOCK_KEEPER_URL SUPER_ADMIN_PASSWORD
```
