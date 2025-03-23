"""
Scenario: Phishing Attack Using a Malicious Domain
A security analyst detects a phishing campaign where attackers use a
fake login page hosted on "malicious-login[.]com" to steal credentials.

This simple STIX example demonstrates how a
CTI analyst can classify and document threat
events in a structured format.
By using STIX, organizations can standardize
threat intelligence and enhance their cybersecurity defense.
"""

from stix2 import Indicator, AttackPattern, ThreatActor, Bundle

# Create an indicator for the malicious domain
indicator = Indicator(
    name="Malicious Phishing Domain",
    pattern="[domain-name:value = 'malicious-login.com']",
    pattern_type="stix",
    labels=["malicious-activity"],
    description="This domain is used for phishing attacks."
)

# Define the attack pattern (Phishing)
attack_pattern = AttackPattern(
    name="Spear Phishing via Service",
    description="Attackers send phishing emails with links to a malicious login page."
)

# Define the threat actor
threat_actor = ThreatActor(
    name="APT-PhishGroup",
    description="An advanced phishing group targeting corporate users.",
    roles=["malicious-actor"],
    sophistication="expert"
)

# Bundle all objects together
stix_bundle = Bundle(objects=[indicator, attack_pattern, threat_actor])

# Print the STIX data
print(stix_bundle.serialize(pretty=True))
