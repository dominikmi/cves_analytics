import pandas as pd
import networkx as nx
from typing import List, Dict, Any, Tuple, Set

# MITRE ATT&CK tactics map based on impact level
mitre_attack_impact_map = {
    "RCE": "Execution",
    "Privilege Escalation": "Privilege Escalation",
    "Auth Bypass": "Initial Access",
    "Lateral Movement": "Lateral Movement"
}

# MITRE ATT&CK tactics map based on CWE identifier (top 25 CWEs)
mitre_attack_cwe_map = {
    "CWE-79": "Execution",  # Cross-Site Scripting (XSS)
    "CWE-89": "Credential Access",  # SQL Injection
    "CWE-287": "Defense Evasion",  # Improper Authentication
    "CWE-502": "Execution",  # Deserialization of Untrusted Data
    "CWE-269": "Privilege Escalation",  # Improper Privilege Management
    "CWE-200": "Discovery",  # Information Exposure
    "CWE-77": "Execution",  # Command Injection
    "CWE-94": "Execution",  # Code Injection
    "CWE-611": "Execution",  # XML External Entities (XXE)
    "CWE-798": "Credential Access",  # Use of Hard-coded Credentials
    "CWE-119": "Execution",  # Buffer Overflow
    "CWE-190": "Privilege Escalation",  # Integer Overflow or Wraparound
    "CWE-284": "Privilege Escalation",  # Improper Access Control
    "CWE-434": "Execution",  # Unrestricted File Upload
    "CWE-732": "Privilege Escalation",  # Incorrect Permission Assignment
    "CWE-601": "Lateral Movement",  # Open Redirect
    "CWE-306": "Defense Evasion",  # Missing Authentication
    "CWE-352": "Initial Access",  # Cross-Site Request Forgery (CSRF)
    "CWE-522": "Credential Access",  # Insufficiently Protected Credentials
    "CWE-125": "Execution",  # Out-of-bounds Read (Memory Disclosure)
    "CWE-918": "Execution",  # Server-Side Request Forgery (SSRF)
    "CWE-640": "Defense Evasion",  # Weak Password Recovery Mechanism
    "CWE-476": "Execution",  # NULL Pointer Dereference
    "CWE-862": "Privilege Escalation",  # Missing Authorization
    "CWE-284": "Privilege Escalation",  # Improper Access Control
    "CWE-287": "Initial Access"  # Improper Authentication
}

class AttackChainAnalyzer:
    """
    Analyzes attack chains by constructing a directed graph of vulnerabilities,
    incorporating CWE relationships and mapping to MITRE ATT&CK phases.
    """
    
    def __init__(self, df: pd.DataFrame) -> None:
        """
        Initializes the attack chain analyzer.
        
        :param df: Pandas DataFrame containing CVE data with 'cve_id', 'impact', 'severity', and 'cwe'.
        """
        self.df = df
        self.attack_graph = nx.DiGraph()
        self.build_graph()

    def map_to_mitre(self, impact: str, cwe: str) -> str:
        """
        Maps CVE impact and CWE to MITRE ATT&CK tactics.
        """
        return mitre_attack_impact_map.get(impact, mitre_attack_impact_map.get(cwe, "Unknown"))

    def build_graph(self) -> None:
        """
        Efficiently builds a directed graph of attack chains using Pandas operations,
        ensuring all severities (Critical, High, Medium, Low) are properly considered.
        """
        impact_order = {
            "Critical": 5,
            "RCE": 4,
            "Privilege Escalation": 3,
            "High": 3,
            "Auth Bypass": 2,
            "Medium": 2,
            "Lateral Movement": 1,
            "Low": 1
        }

        # Add MITRE phase column directly in DataFrame
        self.df["mitre_phase"] = self.df.apply(lambda row: self.map_to_mitre(row["impact"], row["cwe"]), axis=1)

        # Convert DataFrame to dictionary and add nodes in bulk
        nodes_data = self.df.set_index("cve_id")[["impact", "severity", "cwe", "mitre_phase"]].to_dict("index")
        self.attack_graph.add_nodes_from(nodes_data.items())

        # Replace impact categories with numerical order
        impact_df = self.df.replace({"impact": impact_order, "severity": impact_order})

        # Merge DataFrame with itself on CWE, ensuring proper impact hierarchy
        attack_edges = impact_df.merge(
            impact_df, on="cwe", suffixes=("_higher", "_lower")
        ).query("impact_higher > impact_lower & severity_higher > severity_lower & cve_id_higher != cve_id_lower")

        # Add edges in bulk
        self.attack_graph.add_edges_from(attack_edges[["cve_id_higher", "cve_id_lower"]].to_records(index=False))


    def find_unique_chains(self) -> List[Tuple[str, ...]]:
        """
        Identifies unique attack paths from high-impact vulnerabilities to lower ones.
        """
        unique_chains: Set[Tuple[str, ...]] = set()
        for start_node in self.attack_graph.nodes:
            for end_node in self.attack_graph.nodes:
                if start_node != end_node:
                    paths = list(nx.all_simple_paths(self.attack_graph, source=start_node, target=end_node))
                    unique_chains.update(tuple(path) for path in paths)
        return sorted(unique_chains, key=len, reverse=True)
