import collections
import io


class Statistics:
    def __init__(self):
        self.certificate_count_by_issuance_year = collections.defaultdict(int)
        self.revoked_count = 0
        self.expired_without_revocation_count = 0
        self.valid_not_revoked_count = 0
        self.final_without_precert = 0
        self.precert_without_final = 0

    def write(self, writer: io.TextIOBase) -> None:
        writer.write(
            f"Certificate count by issuance year: {self.certificate_count_by_issuance_year}\n"
        )
        writer.write(f"Revoked count: {self.revoked_count}\n")
        writer.write(
            f"Expired without revocation count: {self.expired_without_revocation_count}\n"
        )
        writer.write(f"Valid not revoked count: {self.valid_not_revoked_count}\n")
        writer.write(f"Final without precert count: {self.final_without_precert}\n")
        writer.write(
            f"Precert without final cert count: {self.precert_without_final}\n"
        )
        writer.write(
            f"Total cert count: {self.revoked_count + self.expired_without_revocation_count + self.valid_not_revoked_count}"
        )
