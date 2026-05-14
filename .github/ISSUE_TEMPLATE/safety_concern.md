name: Safety or Protocol Concern
description: Report a concern regarding protocol integrity, safety-critical timing, or false signals.
labels: ["safety", "protocol"]
body:
  - type: markdown
    attributes:
      value: |
        **WARNING**: If this is a security vulnerability (e.g. RCE, DoS), please refer to our [Security Policy](SECURITY.md) for private disclosure.
  - type: textarea
    id: concern
    attributes:
      label: Describe the Safety Concern
      description: What specific safety guarantee is at risk? (e.g., Stall Detection Jitter, False Positives, Cryptographic Weakness).
    validations:
      required: true
  - type: textarea
    id: scenario
    attributes:
      label: Deployment Scenario
      description: What kind of system is this affecting? (e.g., Hospital IT, Industrial Controller, Autonomous Vehicle).
  - type: textarea
    id: details
    attributes:
      label: Technical Details
      description: Please provide details on timing, latency measurements, or protocol traces that highlight the concern.
    validations:
      required: true
