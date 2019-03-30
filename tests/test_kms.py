import pytest
from zmon_worker_monitor.builtins.plugins.kms import KmsWrapper

from mock import MagicMock


ciphertext = 'ciphertext1'
plaintext = 'plaintext1'
encryption_context = {
    'aws:s3:arn': 'arn:aws:s3:::bucket_name/file_name'
}
role = 'arn:aws:123456789:role/ROLE'
region = 'my-region'
assume_role_resp = {
    'Credentials': {
        'AccessKeyId': 'key-1',
        'SecretAccessKey': 'secret-key-1',
        'SessionToken': 'session-token-1',
    }
}


def test_kms_decrypt(monkeypatch):
    client_mock = MagicMock()
    client_mock.decrypt.return_value = plaintext
    get_mock = MagicMock()
    get_mock.return_value.json.return_value = {'region': region}
    monkeypatch.setattr('requests.get', get_mock)
    monkeypatch.setattr('boto3.client', lambda x, region_name: client_mock)

    kms = KmsWrapper()
    plaintext_blob = kms.decrypt(ciphertext.encode('utf8'))
    assert plaintext_blob.decode('utf8') == plaintext
    client_mock.decrypt.assert_called_with(CiphertextBlob=ciphertext.encode('utf8'))


def test_kms_decrypt_with_assume_role(monkeypatch):
    client_mock = MagicMock()
    client_mock.assume_role.return_value = assume_role_resp
    client_mock.decrypt.return_value = plaintext
    get_mock = MagicMock()
    get_mock.return_value.json.return_value = {'region': region}
    session_mock = MagicMock()
    session_mock.return_value.client.return_value = client_mock
    monkeypatch.setattr('requests.get', get_mock)
    monkeypatch.setattr('boto3.client', lambda x, region_name: client_mock)
    monkeypatch.setattr('boto3.Session', session_mock)

    kms = KmsWrapper(region=region, assume_role_arn=role)
    plaintext_blob = kms.decrypt(ciphertext.encode('utf8'))
    assert plaintext_blob.decode('utf8') == plaintext
    client_mock.assume_role.assert_called_with(RoleArn=role, RoleSessionName='zmon-woker-session')
    client_mock.decrypt.assert_called_with(CiphertextBlob=ciphertext.encode('utf8'))
    session_mock.assert_called_with(
        aws_access_key_id=assume_role_resp['Credentials']['AccessKeyId'],
        aws_secret_access_key=assume_role_resp['Credentials']['SecretAccessKey'],
        aws_session_token=assume_role_resp['Credentials']['SessionToken'])
    session_mock.return_value.client.assert_called_with('kms', region_name=region)


def test_kms_decrypt_encryption_context(monkeypatch):
    client_mock = MagicMock()
    client_mock.decrypt.return_value = plaintext
    get_mock = MagicMock()
    get_mock.return_value.json.return_value = {'region': region}
    monkeypatch.setattr('requests.get', get_mock)
    monkeypatch.setattr('boto3.client', lambda x, region_name: client_mock)

    kms = KmsWrapper()
    plaintext_blob = kms.decrypt(ciphertext.encode('utf8'), encryption_context)
    assert plaintext_blob.decode('utf8') == plaintext
    client_mock.decrypt.assert_called_with(
        CiphertextBlob=ciphertext.encode('utf8'), EncryptionContext=encryption_context)
