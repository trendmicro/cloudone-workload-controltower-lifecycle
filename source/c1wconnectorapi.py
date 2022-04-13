import deepsecurity
from deepsecurity.rest import ApiException
import logging
import os

logger = logging.getLogger()


class CloudOneConnector:
    def __init__(self, api_key):
        self.configuration = deepsecurity.Configuration()
        self.configuration.host = f'https://{os.environ["ApiEndpoint"]}/api'
        self.configuration.api_key['api-secret-key'] = api_key
        self.connectorClient = deepsecurity.AWSConnectorsApi(deepsecurity.ApiClient(self.configuration))
        self.apiVersion = 'v1'

    def get_externalid(self):
        connector_settings_client = deepsecurity.AWSConnectorSettingsApi(deepsecurity.ApiClient(self.configuration))
        try:
            connector_settings = connector_settings_client.list_aws_connector_settings(self.apiVersion)
            logger.info('Retrieved external id')
            return connector_settings.external_id
        except ApiException as e:
            logger.info(f"Exception when calling AWSConnectorSettingsApi.list_aws_connector_settings: {e}")
            raise e
        except Exception as e:
            logger.info(e)

    def add_connector(self, aws_cross_account_arn, aws_account_id, aws_account_name):
        if aws_account_name:
            display_name = f"ControlTower - {aws_account_name} - {aws_account_id}"
        else:
            display_name = f"ControlTower - {aws_account_id}"
        aws_connector = deepsecurity.AWSConnector(cross_account_role_arn=aws_cross_account_arn,
                                                  workspaces_enabled="True",
                                                  display_name=display_name)
        logger.info(f'Creating connector for arn: {aws_cross_account_arn}')
        try:
            add_connector_response = self.connectorClient.create_aws_connector(aws_connector, self.apiVersion)
            logger.info('Connector added')
            logger.info(add_connector_response)
        except ApiException as e:
            logger.info(f"Exception when calling AWSConnectorsApi.create_aws_connector: {e}")
        except Exception as e:
            logger.info(e)

    def delete_connector(self, aws_account_id):
        connector_id = self.get_connector_id(aws_account_id)
        try:
            self.connectorClient.delete_aws_connector(connector_id, self.apiVersion)
            logger.info('Connector removed')
        except ApiException as e:
            logger.info(e)
        except Exception as e:
            logger.info(e)

    def get_connector_id(self, aws_account_id):
        search_filter = deepsecurity.SearchFilter(
            search_criteria={"fieldName": "accountId", "stringValue": aws_account_id})
        try:
            connectors = self.connectorClient.search_aws_connectors(self.apiVersion, search_filter=search_filter)
            logger.info(f"Connector ID {connectors.aws_connectors[0].id} found for accountid {aws_account_id}")
            return connectors.aws_connectors[0].id
        except ApiException as e:
            logger.info("An exception occurred when calling AWSConnectorSettingsApi.list_aws_connector_settings: %s\n" % e)
        except Exception as e:
            logger.info(e)
