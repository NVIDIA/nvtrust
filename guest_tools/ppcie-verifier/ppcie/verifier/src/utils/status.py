#    Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

"""Status for each stage in PPCIE Verifier tool"""

from prettytable import PrettyTable


class Status:
    """
    Status class tracks the completion/failure of each stage in PPCIE Verifier tool
    """

    def __init__(self):
        """
        Initializing all the stages to False initially
        """
        self.table = PrettyTable()
        self.gpu_pre_checks = "Skipped"
        self.switch_pre_checks = "Skipped"
        self.gpu_attestation = "Skipped"
        self.switch_attestation = "Skipped"
        self.topology_checks = "Skipped"
        self.ppcie_successful = False

    def status(self, logger):
        """
        Prints a detailed status for each stage in a tabular format
        """
        self.table.field_names = ["STAGE", "STATUS"]
        self.table.add_row(
            ["GPU Pre-checks", str(self.convert_message(self.gpu_pre_checks)).upper()]
        )
        self.table.add_row(
            [
                "Switch Pre-checks",
                str(self.convert_message(self.switch_pre_checks)).upper(),
            ]
        )
        self.table.add_row(
            ["GPU Attestation", str(self.convert_message(self.gpu_attestation)).upper()]
        )
        self.table.add_row(
            [
                "Switch Attestation",
                str(self.convert_message(self.switch_attestation)).upper(),
            ]
        )
        self.table.add_row(
            ["Topology checks", str(self.convert_message(self.topology_checks)).upper()]
        )
        print(self.table)

    def convert_message(self, stage):
        if stage is True:
            return "Success"
        elif not stage:
            return "Failed"
        return "Skipped"

    def update_stage_status(self, stage, status):
        """
        Updates the status of a specific stage
        """
        setattr(self, stage, status)
