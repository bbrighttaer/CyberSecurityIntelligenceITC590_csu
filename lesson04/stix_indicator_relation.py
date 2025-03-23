"""
Scenario:
We will define a malicious URL as an indicator and use
a relationship object to associate it with a threat report.
This will help demonstrate how STIX can be used for threat
response in a cybersecurity context.
"""

from stix2 import Indicator, Relationship, Report
from datetime import datetime

# Define a STIX Indicator for a malicious URL
phishing_indicator = Indicator(
    name="Malicious Phishing URL",
    pattern="[url:value = 'http://malicious-phishing.com']",
    pattern_type="stix",
    description="This URL is associated with a phishing attack campaign.",
    labels=["malicious-activity", "phishing"],
    valid_from=datetime.utcnow()
)

# Define a Threat Report that describes the attack
threat_report = Report(
    name="Phishing Attack Report",
    description="This report contains information about a phishing attack campaign.",
    published=datetime.utcnow(),
    object_refs=[phishing_indicator.id],
    labels=["threat-report", "phishing"]
)

# Create a relationship between the indicator and the report
relationship = Relationship(
    source_ref=phishing_indicator.id,
    target_ref=threat_report.id,
    relationship_type="related-to"
)

# Print STIX objects as JSON
print("=== STIX Indicator ===")
print(phishing_indicator.serialize(pretty=True))

print("\n=== STIX Threat Report ===")
print(threat_report.serialize(pretty=True))

print("\n=== STIX Relationship ===")
print(relationship.serialize(pretty=True))
