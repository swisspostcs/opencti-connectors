import json
from datetime import datetime
from typing import Any

from misp_stix_converter import ExternalSTIX2toMISPParser
from pycti import OpenCTIConnectorHelper
from pymisp import MISPEvent, PyMISP
from stix2 import Bundle

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

    def __init__(self, config: ConfigConnector, helper: OpenCTIConnectorHelper) -> None:
        """
        Initialize the Connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = config
        self.helper = helper

        # Initialize MISP connection
        self.misp = PyMISP(
            url=self.config.misp_url,
            key=self.config.misp_key,
            ssl=self.config.misp_ssl_verify,
        )

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

    def _create_event_indicator(self, data: Any) -> MISPEvent:
        """
        Create a MISP event from an OpenCTI indicator
        :param data: OpenCTI indicator object
        :return: MISP Event object
        """
        internal_id = self.helper.get_attribute_in_extension("id", data)

        # Parse the indicator pattern and add attributes
        if "pattern" not in data or data.get("pattern_type") != "stix":
            self.helper.connector_logger.debug(
                f"[CREATE] Indicator {internal_id} has no STIX pattern"
            )
            # TODO: Add support for non-STIX patterns ?
            return

        # Convert the STIX pattern to a MISP event
        stix_bundle = Bundle(objects=[data])
        parser = ExternalSTIX2toMISPParser()
        parser.load_stix_bundle(stix_bundle)
        parser.parse_stix_bundle(stix_bundle)

        event = parser.misp_event
        # Replace the event info with the indicator description
        event.info = data.get("description", "OpenCTI Indicator")
        event.distribution = self.config.misp_distribution_level
        event.threat_level_id = self.config.misp_threat_level_id
        event.analysis = self.config.misp_analysis

        # Override created date with the OpenCTI created date
        if "created" in data:
            event.date = datetime.strptime(
                data["created"], "%Y-%m-%dT%H:%M:%S.%fZ"
            ).strftime("%Y-%m-%d")

        # Add tag with the OpenCTI ID
        event.add_tag(f"{self.config.misp_tag_prefix}:id={internal_id}")

        # Add tags from OpenCTI labels
        if "labels" in data:
            for label in data["labels"]:
                event.add_tag(label)

        return event

    def _add_event(self, event: MISPEvent, internal_id: str) -> None:
        """
        Add an event to MISP
        :param event: MISP Event object
        :param internal_id: OpenCTI internal ID
        """
        added = self.misp.add_event(event, pythonify=True)

        # Create an external reference to the MISP event
        external_reference = self.helper.api.external_reference.create(
            source_name="MISP",
            url=f"{self.config.misp_url}/events/view/{added.id}",
            external_id=str(added.id),
            description="MISP Event",
        )

        # Link the reference to the OpenCTI indicator
        self.helper.api.stix_domain_object.add_external_reference(
            id=internal_id,
            external_reference_id=external_reference["id"],
        )

    def _handle_create(self, data: Any) -> None:
        """
        Handle creation
        :param data: Data from the stream
        """
        internal_id = self.helper.get_attribute_in_extension("id", data)
        self.helper.connector_logger.info(
            f"[CREATE] Processing {data['type']} {internal_id}"
        )

        if data["type"] == "indicator":
            event = self._create_event_indicator(data)
            self._add_event(event, internal_id)
            self.helper.connector_logger.info(
                f"[CREATE] Created MISP event for indicator {internal_id}"
            )
        else:
            self.helper.connector_logger.debug(
                f"[CREATE] {data['type']} not implemented"
            )

    def _handle_update(self, data: Any) -> None:
        """
        Handle update
        :param data: Data from the stream
        """
        internal_id = self.helper.get_attribute_in_extension("id", data)
        self.helper.connector_logger.info(
            f"[UPDATE] Processing {data['type']} {internal_id}"
        )

        if data["type"] == "indicator":
            event = self._create_event_indicator(data)

            # Look for the MISP event by the OpenCTI ID
            to_update = self.misp.search(
                tags=f"{self.config.misp_tag_prefix}:id={internal_id}",
                pythonify=True,
            )

            # Update the MISP event if it exists, otherwise create a new one
            if len(to_update):
                event.uuid = to_update[0].uuid  # Keep the same UUID
                self.misp.update_event(event, to_update[0].id, pythonify=True)
                self.helper.connector_logger.info(
                    f"[UPDATE] Updated MISP event for indicator {internal_id}"
                )
            else:
                self._add_event(event, internal_id)
                self.helper.connector_logger.info(
                    f"[UPDATE] Created MISP event for indicator {internal_id}"
                )
        else:
            self.helper.connector_logger.debug(
                f"[UPDATE] {data['type']} not implemented"
            )

    def _handle_delete(self, data: Any) -> None:
        """
        Handle deletion
        :param data: Data from the stream
        """
        internal_id = self.helper.get_attribute_in_extension("id", data)
        self.helper.connector_logger.info(
            f"[DELETE] Processing {data['type']} {internal_id}"
        )

        if data["type"] == "indicator":
            # Look for the MISP event by the OpenCTI ID
            to_delete = self.misp.search(
                tags=f"{self.config.misp_tag_prefix}:id={internal_id}",
                pythonify=True,
            )

            # Delete the MISP event if it exists
            if len(to_delete):
                self.misp.delete_event(to_delete[0])
                self.helper.connector_logger.info(
                    f"[DELETE] Deleted MISP event for indicator {internal_id}"
                )
            else:
                self.helper.connector_logger.debug(
                    f"[DELETE] MISP event for indicator {internal_id} not found"
                )
        else:
            self.helper.connector_logger.debug(
                f"[DELETE] {data['type']} not implemented"
            )

    def process_message(self, msg: Any) -> None:
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

            if msg.event == "update":
                self._handle_update(data)

            if msg.event == "delete":
                self._handle_delete(data)
        except Exception as e:
            raise ValueError("Cannot process the message") from e

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors messages from the platform
        The connector have the capability to listen a live stream from the platform.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen_stream(message_callback=self.process_message)
