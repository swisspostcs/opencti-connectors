import os
from pathlib import Path

import yaml
from pycti import get_config_variable


class ConfigConnector:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """

        # Load configuration file
        self.load = self._load_config()
        self._initialize_configurations()

    @staticmethod
    def _load_config() -> dict:
        """
        Load the configuration from the YAML file
        :return: Configuration dictionary
        """
        config_file_path = Path(__file__).parents[1].joinpath("config.yml")
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        return config

    def _initialize_configurations(self) -> None:
        """
        Connector configuration variables
        :return: None
        """
        # OpenCTI configurations

        # Connector extra parameters
        self.misp_api_base_url = get_config_variable(
            "MISP_EXPORTER_API_BASE_URL",
            ["misp_exporter", "api_base_url"],
            self.load,
        )

        self.misp_api_key = get_config_variable(
            "MISP_EXPORTER_API_KEY",
            ["misp_exporter", "api_key"],
            self.load,
        )

        self.misp_distribution_level = get_config_variable(
            "MISP_EXPORTER_DISTRIBUTION_LEVEL",
            ["misp_exporter", "distribution_level"],
            self.load,
            default=0,  # Own organization only
        )

        self.misp_threat_level_id = get_config_variable(
            "MISP_EXPORTER_THREAT_LEVEL_ID",
            ["misp_exporter", "threat_level_id"],
            self.load,
            default=4,  # Undefined
        )

        self.misp_analysis = get_config_variable(
            "MISP_EXPORTER_ANALYSIS",
            ["misp_exporter", "analysis"],
            self.load,
            default=0,  # Initial
        )

        self.misp_tag_prefix = get_config_variable(
            "MISP_EXPORTER_TAG_PREFIX",
            ["misp_exporter", "tag_prefix"],
            self.load,
            default="opencti",
        )
