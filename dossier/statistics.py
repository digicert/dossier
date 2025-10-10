import collections
import logging

logger = logging.getLogger(__name__)


class Statistics:
    def _initialize(self):
        self.delayed_valid_cert_count = 0
        self.delayed_revoked_cert_count = 0
        self.timely_revoked_cert_count = 0
        self.expired_cert_count = 0
        self.valid_cert_count = 0
        self.final_without_precert = 0
        self.precert_without_final = 0
        self.unknown_cert_type = 0
        self.duplicate_cert_count = 0
        self.total_cert_count = 0
        self.cert_count_by_revocation_reason_code = collections.defaultdict(int)
        self.error_count = 0

    def __init__(self):
        self._initialize()

    def reset(self):
        self._initialize()

    def output(self) -> None:
        logger.info(
            f"Delayed revocation valid certificate pair count: {self.delayed_valid_cert_count}"
        )
        logger.info(
            f"Delayed revocation revoked certificate pair count: {self.delayed_revoked_cert_count}"
        )
        logger.info(
            f"Timely revoked certificate pair count: {self.timely_revoked_cert_count}"
        )
        logger.info(f"Expired certificate pair count: {self.expired_cert_count}")
        logger.info(f"Valid certificate pair count: {self.valid_cert_count}")
        logger.info(
            f"Final certificate without corresponding precertificate count: {self.final_without_precert}"
        )
        logger.info(
            f"Precertificate without corresponding final certificate count: {self.precert_without_final}"
        )
        logger.info(f"Unknown certificate count: {self.unknown_cert_type}")
        logger.info(f"Duplicate certificate count: {self.duplicate_cert_count}")
        logger.info(f"Total certificate count: {self.total_cert_count}")
        revocation_counts_str = ", ".join(
            (f"{k}: {v}" for k, v in self.cert_count_by_revocation_reason_code.items())
        )

        logger.info(
            f"Certificate count by revocation reason code: {revocation_counts_str}"
        )
        logger.info(f"Error count: {self.error_count}")


INSTANCE = Statistics()
