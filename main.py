import json
import argparse
import base64
import boto3
import logging
import os
import sys
import textwrap
from cryptography.fernet import Fernet


# pseudo-code for envelope encryption using aws kms:
#   alice: generates a new data key (to be shared with bob) and encrypts the plaintext.
#       data_key, encrypted_data_key = kms.GenerateDataKey(bob_key_id, cleartext)
#       ciphertext = encrypt(data_key, plaintext)
#   bob: decrypts the ciphertext.
#       data_key = get_data_key(encrypted_data_key)
#       plaintext = decrypt(data_key, cleartext, ciphertext)


def generate_data_key(kms_client, key_id, encryption_context):
    """Generate a data key using KMS"""
    # see https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html
    response = kms_client.generate_data_key(
        KeyId=key_id,
        KeySpec="AES_256",
        EncryptionContext=encryption_context,
    )
    return (
        response["KeyId"],
        base64.b64encode(response["Plaintext"]).decode("utf-8"),
        base64.b64encode(response["CiphertextBlob"]).decode("utf-8"),
    )


def encrypt_message(plaintext_key, message):
    """Encrypt a message using the plaintext data key"""
    f = Fernet(plaintext_key)
    return f.encrypt(message.encode("utf-8"))


def decrypt_data_key(kms_client, ciphertext_key, encryption_context):
    """Decrypt the data key using KMS"""
    # see https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html
    response = kms_client.decrypt(
        CiphertextBlob=base64.b64decode(ciphertext_key),
        EncryptionContext=encryption_context,
    )
    return (
        response["KeyId"],
        base64.b64encode(response["Plaintext"]).decode("utf-8")
    )


def decrypt_message(plaintext_key, encrypted_message):
    """Decrypt a message using the plaintext data key"""
    f = Fernet(plaintext_key)
    return f.decrypt(encrypted_message).decode("utf-8")


def encrypt_main(args):
    from_identity = args.from_identity.upper()
    to_identity = args.to_identity.upper()

    aws_region_name = os.getenv("PLAYGROUND_AWS_REGION")

    from_aws_access_key_id = os.getenv(f"PLAYGROUND_{from_identity}_AWS_ACCESS_KEY_ID")
    from_aws_secret_access_key = os.getenv(
        f"PLAYGROUND_{from_identity}_AWS_SECRET_ACCESS_KEY"
    )

    to_aws_kms_key_alias = os.getenv(f"PLAYGROUND_{to_identity}_AWS_KMS_KEY_ALIAS")

    from_session = boto3.session.Session(
        aws_access_key_id=from_aws_access_key_id,
        aws_secret_access_key=from_aws_secret_access_key,
        region_name=aws_region_name,
    )

    from_kms_client = from_session.client("kms")

    # NB this is sent in cleartext.
    # NB this is verified when decrypting the data key.
    # NB this data can only be trusted when the verification succeeds.
    # NB since the origin does not sign this metadata and message, we cannot
    #    really verify who is sending this.
    # NB KMS will read this metadata.
    metadata = {
        "from": args.from_identity,
        "to": args.to_identity,
    }
    encoded_metadata = base64.b64encode(
        json.dumps(metadata, separators=(",", ":")).encode("utf-8")
    ).decode("utf-8")
    message = args.message
    logging.info(f"Original message: {message}")

    data_key_id, data_key, encrypted_data_key = generate_data_key(
        from_kms_client, to_aws_kms_key_alias, metadata
    )
    logging.info(f"Data key alias: {to_aws_kms_key_alias}")
    logging.info(f"Data key id: {data_key_id}")
    logging.info(f"Data key: {data_key}")
    logging.info(f"Encrypted data key: {encrypted_data_key}")

    encrypted_message = encrypt_message(data_key, message)
    encoded_encrypted_message = base64.b64encode(encrypted_message).decode("utf-8")
    logging.info(f"Encrypted message: {encoded_encrypted_message}")

    # NB we do need to include data_key_id in the envelope. encrypted_data_key
    #    includes it as metadata.
    envelope = {
        "data_key": encrypted_data_key,
        "metadata": encoded_metadata,
        "message": encoded_encrypted_message,
    }
    logging.info(f"Envelope: {envelope}")

    print(json.dumps(envelope))


def decrypt_main(args):
    to_identity = args.to_identity.upper()

    aws_region_name = os.getenv("PLAYGROUND_AWS_REGION")

    to_aws_access_key_id = os.getenv(f"PLAYGROUND_{to_identity}_AWS_ACCESS_KEY_ID")
    to_aws_secret_access_key = os.getenv(
        f"PLAYGROUND_{to_identity}_AWS_SECRET_ACCESS_KEY"
    )

    to_session = boto3.session.Session(
        aws_access_key_id=to_aws_access_key_id,
        aws_secret_access_key=to_aws_secret_access_key,
        region_name=aws_region_name,
    )

    to_kms_client = to_session.client("kms")

    envelope = json.load(sys.stdin)
    logging.info(f"Envelope: {envelope}")

    metadata = json.loads(base64.b64decode(envelope["metadata"]).decode("utf-8"))
    encrypted_data_key = envelope["data_key"]
    encrypted_message = base64.b64decode(envelope["message"])

    data_key_id, data_key = decrypt_data_key(to_kms_client, encrypted_data_key, metadata)
    logging.info(f"Data key id: {data_key_id}")
    logging.info(f"Data key: {data_key}")

    message = decrypt_message(data_key, encrypted_message)

    logging.info(f"Metadata: {metadata}")
    logging.info(f"Message: {message}")
    print(message)


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(
            """\
            aws kms playground.

            this expects the AWS credentials to be available at the following environment variables:

                PLAYGROUND_<IDENTITY>_AWS_ACCESS_KEY_ID
                PLAYGROUND_<IDENTITY>_AWS_SECRET_ACCESS_KEY
                PLAYGROUND_<IDENTITY>_AWS_KMS_KEY_ALIAS

            example:

            %(prog)s -v encrypt \\
                --from alice \\
                --to bob \\
                --message 'Hello Bob, this is a secret message from Alice!' \\
                | %(prog)s -v decrypt \\
                    --to bob
            """
        ),
    )
    parser.add_argument(
        "--verbose",
        "-v",
        default=0,
        action="count",
        help="verbosity level. specify multiple to increase logging.",
    )
    subparsers = parser.add_subparsers(help="sub-command help")
    encrypt_parser = subparsers.add_parser("encrypt", help="encrypt a message.")
    encrypt_parser.add_argument(
        "--from-identity", default="alice", help="identity that is sending the message."
    )
    encrypt_parser.add_argument(
        "--to-identity", default="bob", help="identity that is receiving the message."
    )
    encrypt_parser.add_argument(
        "--message", default="Hello, World!", help="message to encrypt."
    )
    encrypt_parser.set_defaults(sub_command=encrypt_main)
    decrypt_parser = subparsers.add_parser("decrypt", help="decrypt a message.")
    decrypt_parser.add_argument(
        "--to-identity", default="bob", help="identity that is receiving the message."
    )
    decrypt_parser.set_defaults(sub_command=decrypt_main)
    args = parser.parse_args()

    LOGGING_FORMAT = "%(asctime)-15s %(levelname)s %(name)s: %(message)s"
    if args.verbose >= 3:
        logging.basicConfig(level=logging.DEBUG, format=LOGGING_FORMAT)
        from http.client import HTTPConnection

        HTTPConnection.debuglevel = 1
    elif args.verbose >= 2:
        logging.basicConfig(level=logging.DEBUG, format=LOGGING_FORMAT)
    elif args.verbose >= 1:
        logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)

    return args.sub_command(args)


if __name__ == "__main__":
    sys.exit(main())
