#!/usr/bin/env python
# -*- coding: utf-8 -*-

import boto3
import logging

from zmon_worker_monitor.builtins.plugins.aws_common import get_instance_identity_document
from zmon_worker_monitor.adapters.ifunctionfactory_plugin import IFunctionFactoryPlugin, propartial

logging.getLogger('botocore').setLevel(logging.WARN)

logger = logging.getLogger('zmon-worker.cloudwatch')


class KmsWrapperFactory(IFunctionFactoryPlugin):
    def __init__(self):
        super(KmsWrapperFactory, self).__init__()

    def configure(self, conf):
        return

    def create(self, factory_ctx):
        """
        Automatically called to create the check function's object
        :param factory_ctx: (dict) names available for Function instantiation
        :return: an object that implements a check function
        """
        return propartial(KmsWrapper, region=factory_ctx.get('entity').get('region', None))


class KmsWrapper(object):
    def __init__(self, region=None, assume_role_arn=None):
        if not region:
            region = get_instance_identity_document()['region']
        self.__client = boto3.client('kms', region_name=region)

        if assume_role_arn:
            sts = boto3.client('sts', region_name=region)
            resp = sts.assume_role(RoleArn=assume_role_arn, RoleSessionName='zmon-woker-session')
            session = boto3.Session(aws_access_key_id=resp['Credentials']['AccessKeyId'],
                                    aws_secret_access_key=resp['Credentials']['SecretAccessKey'],
                                    aws_session_token=resp['Credentials']['SessionToken'])
            self.__client = session.client('kms', region_name=region)
            logger.debug('kms wrapper assumed role: {}'.format(assume_role_arn))

    def decrypt(self, ciphertext_blob, encryption_context=None):
        """
        Invokes kms_client.decrypt() of boto3.
        :param ciphertext_blob: (bytes) required, the ciphertext blob to be decrypt.
        :param encryption_context: (dict) optional, encryption_context that was specified when encrypting.
        :return: (bytes) plaintext blob
        """
        kwargs = {'CiphertextBlob': ciphertext_blob}
        if encryption_context:
            logger.debug('encryption_context provided: ', encryption_context)
            kwargs['EncryptionContext'] = encryption_context
        return self.__client.decrypt(**kwargs)
