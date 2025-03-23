import json
from datetime import datetime
from typing import Any

from pycti import OpenCTIConnectorHelper
from pymisp import MISPEvent

from .config_loader import ConfigConnector


class ConnectorMispExporter:
    """
    Specifications of the Stream connector

    This class encapsulates the main actions, expected to be run by any stream connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector has the capability to listen to live streams from the OpenCTI platform.
    It is highly useful for creating connectors that can react and make decisions in real time.
    Actions on OpenCTI will apply the changes to the third-party connected platform
    ---

    Attributes
        - `config (ConfigConnector())`:
            Initialize the connector with necessary configuration environment variables

        - `helper (OpenCTIConnectorHelper(config))`:
            This is the helper to use.
            ALL connectors have to instantiate the connector helper with configurations.
            Doing this will do a lot of operations behind the scene.

    ---

    Best practices
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message

    """

    OPENCTI_TO_MISP_OBSERVABLES_MAPPING = {
        "Autonomous-System": "AS",
        # "Directory" TODO: MISP does not have a directory attribute
        "Email-Addr": "email",
        "Email-Message": "email-body",
        "Email-Mime-Part-Type": "email-mime-boundary",
        # "Artifact" TODO: MISP does not have an artifact attribute
        # "X509-Certificate" TODO: MISP does not have a x509-certificate attribute
        "IPv4-Addr": "ip-dst",  # TODO: ip-src or ip-dst?
        "IPv6-Addr": "ip-dst",  # TODO: ip-src or ip-dst?
        "Mac-Addr": "mac-address",
        "Mutex": "mutex",
        # "Network-Traffic" TODO: MISP does not have a network-traffic attribute (pattern-in-traffic ?)
        "Domain-Name": "domain",
        # "Process" TODO: MISP does not have a process attribute (process-state ?)
        # "Software" TODO: MISP does not have a software attribute (cpe ?)
        "Url": "url",
        "SHA-512": "sha512",
        "SHA-256": "sha256",
        "SHA-1": "sha1",
        "MD5": "md5",
    }

    OPENCTI_NESTED_OBSERVABLES_MAPPING = {
        "File": "hashes",
    }

    def __init__(self, config: ConfigConnector, helper: OpenCTIConnectorHelper):
        """
        Initialize the Connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = config
        self.helper = helper

    def check_stream_id(self) -> None:
        """
        In case of stream_id configuration is missing, raise Value Error
        :return: None
        """
        if (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "ChangeMe"
        ):
            raise ValueError("Missing stream ID, please check your configurations.")

    def _create_event(self, event: MISPEvent) -> None:
        """
        Create a MISP event
        :param event: MISP Event object
        """
        # TODO: Create the event in MISP
        # for retry in range(self.max_retry_count):
        #     try:
        #         response = self.misp.add_event(event)

        #         if response:
        #             event_id = response["Event"]["id"]
        #             self.helper.log_info(
        #                 f"[CREATE] Indicator {internal_id} -> MISP Event {event_id}"
        #             )

        #             # Add an external reference in OpenCTI
        #             external_reference = self.helper.api.external_reference.create(
        #                 source_name="MISP",
        #                 url=f"{self.misp_url}/events/view/{event_id}",
        #                 external_id=str(event_id),
        #                 description="MISP Event",
        #             )

        #             self.helper.api.stix_domain_object.add_external_reference(
        #                 id=internal_id,
        #                 external_reference_id=external_reference["id"],
        #             )

        #             # Publish the event if configured to do so
        #             if self.misp_publish_events:
        #                 self.misp.publish(event_id)

        #             return response
        #         break
        #     except Exception as e:
        #         if retry < self.max_retry_count - 1:
        #             self.helper.log_info(
        #                 f"Retrying create operation in {self.retry_delay} seconds..."
        #             )
        #             time.sleep(self.retry_delay)
        #         else:
        #             raise e

    def _create_indicator(self, data: Any) -> None:
        """
        Create a MISP event from an OpenCTI indicator
        """
        internal_id = self.helper.get_attribute_in_extension("id", data)

        # Create a new MISP event
        event = MISPEvent()
        event.info = data.get("name", "Indicator from OpenCTI")
        event.distribution = self.config.misp_distribution_level
        event.threat_level_id = self.config.misp_threat_level_id
        event.analysis = self.config.misp_analysis

        # Add date
        if "created" in data:
            event.date = datetime.strptime(
                data["created"], "%Y-%m-%dT%H:%M:%S.%fZ"
            ).strftime("%Y-%m-%d")

        # TODO: Add tags for TLP/PAP markings
        # if "objectMarking" in data:
        #    self._add_tlp_markings(event, data["objectMarking"])

        # Add a tag with the OpenCTI ID
        event.add_tag(f"{self.config.misp_tag_prefix}:id={internal_id}")

        # Add tags from OpenCTI labels
        if "labels" in data:
            for label in data["labels"]:
                event.add_tag(label)

        # Parse the indicator pattern and add attributes
        if "pattern" not in data or data.get("pattern_type") != "stix":
            self.helper.connector_logger.debug(
                f"[CREATE] Indicator {internal_id} has no STIX pattern"
            )
            # TODO: Analyze other types of patterns
            return

        observable_values = self.helper.get_attribute_in_extension(
            "observable_values", data
        )
        if not observable_values:
            self.helper.connector_logger.debug(
                f"[CREATE] Indicator {internal_id} has no observables"
            )
            # TODO: Maybe create the event without attributes?
            return

        for observable in observable_values:
            obs_type = observable.get("type")
            description = data.get("description")
            to_ids = self.helper.get_attribute_in_extension("to_ids", data)

            if obs_type in self.OPENCTI_TO_MISP_OBSERVABLES_MAPPING:
                event.add_attribute(
                    type=self.OPENCTI_TO_MISP_OBSERVABLES_MAPPING[obs_type],
                    value=observable["value"],
                    comment=description,
                    to_ids=to_ids,
                )
            elif obs_type in self.OPENCTI_NESTED_OBSERVABLES_MAPPING:
                observables_key = self.OPENCTI_NESTED_OBSERVABLES_MAPPING[obs_type]
                for nested_obs_type, nested_obs_value in observable[
                    observables_key
                ].items():
                    if nested_obs_type in self.OPENCTI_TO_MISP_OBSERVABLES_MAPPING:
                        event.add_attribute(
                            type=self.OPENCTI_TO_MISP_OBSERVABLES_MAPPING[
                                nested_obs_type
                            ],
                            value=nested_obs_value,
                            comment=description,
                            to_ids=to_ids,
                        )
                    else:
                        self.helper.connector_logger.debug(
                            f"[CREATE] Unsupported nested observable type: {nested_obs_type}"
                        )
            else:
                self.helper.connector_logger.debug(
                    f"[CREATE] Unsupported observable type: {obs_type}"
                )
                continue

    def _handle_create(self, data):
        """
        Handle creation
        :param data: Data from the stream
        :return: None
        """
        self.helper.connector_logger.info(f"[CREATE] Processing {data['type']}")

        if data["type"] == "indicator":
            self._create_indicator(data)
        else:
            self.helper.connector_logger.debug(
                f"[CREATE] {data['type']} not implemented"
            )

    def process_message(self, msg) -> None:
        """
        Main process if connector successfully works
        The data passed in the data parameter is a dictionary with the following structure as shown in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations
        :param msg: Message event from stream
        :return: string
        """
        try:
            self.check_stream_id()

            data = json.loads(msg.data)["data"]

            if msg.event == "create":
                self._handle_create(data)

        except Exception as e:
            self.helper.connector_logger.debug(f"Message: {data}")
            raise ValueError(f"Cannot process the message: {str(e)}") from e

        # Performing the main process
        # ===========================
        # === Add your code below ===
        # ===========================

        # Handle update
        if msg.event == "update":
            self.helper.connector_logger.debug("[UPDATE] event not implemented")

        # Handle delete
        if msg.event == "delete":
            self.helper.connector_logger.debug("[DELETE] event not implemented")

        # ===========================
        # === Add your code above ===
        # ===========================

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors messages from the platform
        The connector have the capability to listen a live stream from the platform.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen_stream(message_callback=self.process_message)
