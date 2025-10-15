UNDER CONSTRUCTION, DO NOT USE

(Documentation is a work-in-progress)

# Confidential Script TEE

This projects implements a Trusted Execution Environment (TEE) around [`confidential-script-lib`](https://github.com/joshdoman/confidential-script-lib), with a secure, reproducible, and permissionlessly provisioned master private key.

AWS's Nitro Enclave is currently the only supported TEE. Users first create a KMS key, which provably can only be accessed by an enclave running Confidential Script. By creating an un-deletable KMS key with cross-account access, emulation can be made nearly permissionless.

Builds are made reproducible using Nix and [`nix-enclaver`](https://github.com/joshdoman/nix-enclaver), a nix-compatible fork of [`enclaver`](https://github.com/enclaver-io/enclaver) that produces a proxy architecture for communication into and out of the enclave.

## What is Confidential Script?

Confidential Script facilitates secure, reproducible, and stateless emulation of Bitcoin script.

Under the hood, [`confidential-script-lib`](https://github.com/joshdoman/confidential-script-lib) emulates Bitcoin script by converting valid script-path spends to key-path spends using Taproot. The enclave validates the unlocking conditions and then replaces the witness with a signature that authorizes the transaction, using a deterministically derived private key that only the enclave can access.

This approach enables confidential execution of complex script, including opcodes not yet supported by the Bitcoin protocol. The actual on-chain footprint is a minimal key-path spend, preserving privacy and efficiency.

For more details on how emulation works, see [`confidential-script-lib`](https://github.com/joshdoman/confidential-script-lib).

## Architecture

Read the [architecture docs](docs/architecture.md) for details.

## Usage

1.  **Build** the EIF file with Nix using `nix build`. To target a non-native architecture, use `nix build .x86_64-eif` or `nix build .aarch64-eif`.
2.  **Deploy** the EIF to a Nitro-enabled EC2 instance and run it using [`nix-enclaver`](https://github.com/joshdoman/nix-enclaver).
3.  **Configure** an AWS KMS key with a PCR0 policy that exclusively allows your enclave to call `kms:DeriveSharedSecret` (see [`pcr-policy-stub.json`](https://github.com/joshdoman/confidential-script-tee/blob/main/pcr-policy-stub.json)).
4.  **Setup** the enclave with the KMS key id and a Bitcoin blockhash, which timestamps the creation of the enclave's master private key.
    ```bash
    curl -X POST http://localhost:8000/setup \
      -H "Content-Type: application/json" \
      -d '{
        "key_id": "arn:aws:kms:us-east-1:123456789012:key/your-kms-key-id"
        "blockhash": "0000000000000000000000000000000000000000000000000000000000000000"
      }'
    ```
5.  **Get the Master Public Key**: You can use this key to generate addressess offline and encrypt requests into the enclave.
    ```bash
    curl http://localhost:8000/public-key
    ```
6. **Emulate** your transaction. Use `secure/verify-and-sign` to encrypt requests into and out of the enclave.
    ```bash
    curl -X POST http://localhost:8000/verify-and-sign \
      -H "Content-Type: application/json" \
      -d '{
        "emulated_tx_to": <TRANSACTION_HEX>,
        "actual_spent_outputs": [
            <OUTPUT0_HEX>,
            <OUTPUT1_HEX>,
            ...
            <OUTPUTN_HEX>,
        ],
        "backup_merkle_roots": {
            "0": <OPTIONAL_MERKLE_ROOT_FOR_INPUT_0>,
            "1": <OPTIONAL_MERKLE_ROOT_FOR_INPUT_1>,
            ...
            "N": <OPTIONAL_MERKLE_ROOT_FOR_INPUT_N>,
        }
      }'
    ```

## Security & Trust Model

*   **Confidentiality**: The master private key is born inside the enclave and never leaves it. All operations on the key happen within the secure boundary.
*   **Reproducibility**: Both the EIF image file and key generation is entirely deterministic. The same enclave code + the same KMS key ARN + the same blockhash will *always* result in the same master private key.
*   **Trust-Minimization via Attestation**: Trust is minimized by configuring the AWS KMS key policy with permissions that grant `DeriveSharedSecret` usage **only** to an enclave with a specific cryptographic measurement (the `PCR0` hash). If the policy was set prior to the timestamped blockhash and the policy cannot be changed, no other machine in the world can derive the secret, under the trust assumptions and security guarantees of AWS Nitro and AWS KMS.

## Running Locally

To run this project locally, first enter the Nix development shell:

```
nix develop
```

Set the following environment variables granting access to your KMS key:
```
export AWS_ACCESS_KEY_ID=$(aws configure get aws_access_key_id)
export AWS_SECRET_ACCESS_KEY=$(aws configure get aws_secret_access_key)
export AWS_SESSION_TOKEN=$(aws configure get aws_session_token)
export AWS_DEFAULT_REGION=<your region>
```

Then build the application and run it:
```
cargo build
cargo run
```
