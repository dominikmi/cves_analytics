"""System simulation module for generating realistic system configurations."""

import random
from typing import Any

from faker import Faker

from src.utils.error_handling import error_handler
from src.utils.logging_config import get_logger

logger = get_logger(__name__)

# OS probability weights for different system groups
OS_P_WEIGHTS = {
    "Linux": {"REV": 0.4, "AUX": 0.5, "NBC": 0.7, "INF": 0.8},
    "Windows": {"REV": 0.7, "AUX": 0.6, "NBC": 0.4, "INF": 0.2},
}

# Security feature probability weights by system group and OS
SYSTEM_POSTURE_P_WEIGHTS = {
    "REV_L": {
        "PublicExposure": 0.7,
        "AccessPublic": 0.95,
        "CriticalDataProcess": 0.5,
        "OpenSourceComponents": 0.95,
        "PatchMgmt": 0.8,
        "IncidentMgmt": 0.8,
        "ChangeMgmt": 0.8,
        "StrongAuth": 0.8,
        "AccessControl": 0.8,
        "AppFirewall": 0.8,
        "VulnMgmt": 0.8,
        "DataEnc": 0.5,
        "DataClass": 0.5,
        "DataBackup": 0.7,
        "DataLossPrevention": 0.4,
        "Monitoring": 0.7,
        "Logging": 0.8,
        "NetworkSeg": 0.7,
        "NetworkFirewall": 0.9,
        "SIEM": 0.5,
        "Location": 0.3,
    },
    "AUX_L": {
        "PublicExposure": 0.4,
        "AccessPublic": 0.95,
        "CriticalDataProcess": 0.25,
        "OpenSourceComponents": 0.95,
        "PatchMgmt": 0.6,
        "IncidentMgmt": 0.6,
        "ChangeMgmt": 0.5,
        "StrongAuth": 0.6,
        "AccessControl": 0.8,
        "AppFirewall": 0.5,
        "VulnMgmt": 0.5,
        "DataEnc": 0.5,
        "DataClass": 0.5,
        "DataBackup": 0.2,
        "DataLossPrevention": 0.3,
        "Monitoring": 0.5,
        "Logging": 0.8,
        "NetworkSeg": 0.5,
        "NetworkFirewall": 0.6,
        "SIEM": 0.3,
        "Location": 0.3,
    },
    "NBC_L": {
        "PublicExposure": 0.6,
        "AccessPublic": 0.95,
        "CriticalDataProcess": 0.5,
        "OpenSourceComponents": 0.95,
        "PatchMgmt": 0.3,
        "IncidentMgmt": 0.3,
        "ChangeMgmt": 0.3,
        "StrongAuth": 0.3,
        "AccessControl": 0.5,
        "AppFirewall": 0.2,
        "VulnMgmt": 0.2,
        "DataEnc": 0.2,
        "DataClass": 0.1,
        "DataBackup": 0.1,
        "DataLossPrevention": 0.1,
        "Monitoring": 0.3,
        "Logging": 0.8,
        "NetworkSeg": 0.4,
        "NetworkFirewall": 0.4,
        "SIEM": 0.2,
        "Location": 0.5,
    },
    "INF_L": {
        "PublicExposure": 0.5,
        "AccessPublic": 0.95,
        "CriticalDataProcess": 0.8,
        "OpenSourceComponents": 0.95,
        "PatchMgmt": 0.5,
        "IncidentMgmt": 0.8,
        "ChangeMgmt": 0.8,
        "StrongAuth": 0.3,
        "AccessControl": 0.6,
        "AppFirewall": 0.5,
        "VulnMgmt": 0.4,
        "DataEnc": 0.5,
        "DataClass": 0.2,
        "DataBackup": 0.1,
        "DataLossPrevention": 0.1,
        "Monitoring": 0.9,
        "Logging": 0.9,
        "NetworkSeg": 0.5,
        "NetworkFirewall": 0.7,
        "SIEM": 0.4,
        "Location": 0.5,
    },
    "REV_W": {
        "PublicExposure": 0.5,
        "AccessPublic": 0.95,
        "CriticalDataProcess": 0.9,
        "OpenSourceComponents": 0.1,
        "PatchMgmt": 0.9,
        "IncidentMgmt": 0.8,
        "ChangeMgmt": 0.8,
        "StrongAuth": 0.9,
        "AccessControl": 0.9,
        "AppFirewall": 0.8,
        "VulnMgmt": 0.8,
        "DataEnc": 0.8,
        "DataClass": 0.7,
        "DataBackup": 0.8,
        "DataLossPrevention": 0.6,
        "Monitoring": 0.8,
        "Logging": 0.8,
        "NetworkSeg": 0.8,
        "NetworkFirewall": 0.7,
        "SIEM": 0.8,
        "Location": 0.7,
    },
    "AUX_W": {
        "PublicExposure": 0.5,
        "AccessPublic": 0.95,
        "CriticalDataProcess": 0.9,
        "OpenSourceComponents": 0.1,
        "PatchMgmt": 0.6,
        "IncidentMgmt": 0.6,
        "ChangeMgmt": 0.6,
        "StrongAuth": 0.6,
        "AccessControl": 0.6,
        "AppFirewall": 0.6,
        "VulnMgmt": 0.6,
        "DataEnc": 0.6,
        "DataClass": 0.6,
        "DataBackup": 0.6,
        "DataLossPrevention": 0.6,
        "Monitoring": 0.6,
        "Logging": 0.6,
        "NetworkSeg": 0.6,
        "NetworkFirewall": 0.6,
        "SIEM": 0.6,
        "Location": 0.5,
    },
    "NBC_W": {
        "PublicExposure": 0.5,
        "AccessPublic": 0.95,
        "CriticalDataProcess": 0.9,
        "OpenSourceComponents": 0.1,
        "PatchMgmt": 0.4,
        "IncidentMgmt": 0.4,
        "ChangeMgmt": 0.4,
        "StrongAuth": 0.4,
        "AccessControl": 0.4,
        "AppFirewall": 0.4,
        "VulnMgmt": 0.4,
        "DataEnc": 0.4,
        "DataClass": 0.4,
        "DataBackup": 0.4,
        "DataLossPrevention": 0.4,
        "Monitoring": 0.4,
        "Logging": 0.4,
        "NetworkSeg": 0.4,
        "NetworkFirewall": 0.4,
        "SIEM": 0.4,
        "Location": 0.3,
    },
    "INF_W": {
        "PublicExposure": 0.5,
        "AccessPublic": 0.95,
        "CriticalDataProcess": 0.9,
        "OpenSourceComponents": 0.1,
        "PatchMgmt": 0.8,
        "IncidentMgmt": 0.8,
        "ChangeMgmt": 0.8,
        "StrongAuth": 0.6,
        "AccessControl": 0.9,
        "AppFirewall": 0.5,
        "VulnMgmt": 0.2,
        "DataEnc": 0.2,
        "DataClass": 0.2,
        "DataBackup": 0.2,
        "DataLossPrevention": 0.4,
        "Monitoring": 0.8,
        "Logging": 0.8,
        "NetworkSeg": 0.6,
        "NetworkFirewall": 0.8,
        "SIEM": 0.4,
        "Location": 0.5,
    },
}

# Popular Windows and Linux server versions
WINDOWS_SERVERS = {
    "Windows Server 2019": 0.4,
    "Windows Server 2016 Standard": 0.3,
    "Windows Server 2016 Datacenter": 0.2,
    "Windows Server 2012 R2": 0.1,
}

LINUX_SERVERS = {
    "Ubuntu 22.04": 0.25,
    "OpenSUSE Leap 15.5": 0.2,
    "Red Hat Enterprise Linux 8": 0.2,
    "Oracle Linux 8": 0.15,
    "Fedora 40": 0.1,
    "Debian 10": 0.05,
    "Debian 11": 0.05,
}


@error_handler()
class SimSystem:
    """Generates realistic simulated system configurations."""

    def __init__(
        self,
        os_p_weights: dict[str, dict[str, float]] | None = None,
        sys_p_weights: dict[str, dict[str, float]] | None = None,
        win_svs: dict[str, float] | None = None,
        lin_svs: dict[str, float] | None = None,
    ):
        """
        Initialize the system simulator.

        Args:
            os_p_weights: OS probability weights
            sys_p_weights: System posture probability weights
            win_svs: Windows server versions and weights
            lin_svs: Linux server versions and weights
        """
        self.os_p_weights = os_p_weights or OS_P_WEIGHTS
        self.sys_p_weights = sys_p_weights or SYSTEM_POSTURE_P_WEIGHTS
        self.win_svs = win_svs or WINDOWS_SERVERS
        self.lin_svs = lin_svs or LINUX_SERVERS

        self.system = self.generate_random_system()
        self.hostname = self.system["hostname"]
        self.group = self.system["group"]
        self.os = self.system["os"]
        self.os_ver = self.system["os_ver"]
        self.posture = self.system["posture"]

        logger.debug(f"Generated system: {self}")

    def __str__(self) -> str:
        """Return string representation of the system."""
        return f"System: {self.hostname} - Group: {self.group} - OS: {self.os}"

    def generate_random_system(self) -> dict[str, Any]:
        """
        Randomly generate a system configuration.

        Returns:
            Dictionary with system configuration
        """
        fake = Faker()

        # Select OS
        os_choices = list(self.os_p_weights.keys())
        selected_os = random.choice(os_choices)

        # Select system group based on OS
        groups = list(self.os_p_weights[selected_os].keys())
        weights = list(self.os_p_weights[selected_os].values())
        selected_group = random.choices(groups, weights=weights, k=1)[0]

        # Generate hostname
        prefix = "L" if selected_os == "Linux" else "W"
        hostname = f"{prefix}-{fake.hostname().split('.')[0]}.hal.com"

        # Select OS version
        if selected_os == "Linux":
            os_ver = random.choices(
                list(self.lin_svs.keys()),
                weights=list(self.lin_svs.values()),
                k=1,
            )[0]
        else:
            os_ver = random.choices(
                list(self.win_svs.keys()),
                weights=list(self.win_svs.values()),
                k=1,
            )[0]

        # Generate security posture
        posture_key = f"{selected_group}_{'L' if selected_os == 'Linux' else 'W'}"
        posture = {
            key: random.choices([True, False], weights=[p_weight, 1 - p_weight])[0]
            for key, p_weight in self.sys_p_weights.get(posture_key, {}).items()
        }

        return {
            "hostname": hostname,
            "group": selected_group,
            "os": selected_os,
            "os_ver": os_ver,
            "posture": posture,
        }
