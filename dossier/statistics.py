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

    def __init__(self):
        self._initialize()

    def reset(self):
        self._initialize()

    def output(self) -> None:
        logger.info(f"Delayed valid cert count: {self.delayed_valid_cert_count}")
        logger.info(f"Delayed revoked cert count: {self.delayed_revoked_cert_count}")
        logger.info(f"Timely revoked cert count: {self.timely_revoked_cert_count}")
        logger.info(f"Expired cert count: {self.expired_cert_count}")
        logger.info(f"Valid cert count: {self.valid_cert_count}")
        logger.info(f"Final cert without precert: {self.final_without_precert}")
        logger.info(f"Precert without final cert: {self.precert_without_final}")
        logger.info(f"Unknown cert type: {self.unknown_cert_type}")
        logger.info(f"Duplicate cert count: {self.duplicate_cert_count}")
        logger.info(f"Total cert count: {self.total_cert_count}")
        logger.info(
            f"Cert count by revocation reason code: {self.cert_count_by_revocation_reason_code}"
        )


INSTANCE = Statistics()
