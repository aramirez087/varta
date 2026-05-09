name: Bug report
description: Create a report to help us improve
labels: ["bug"]
body:
  - type: markdown
    attributes:
      value: |
        Before reporting, please ensure the bug is not already reported and that it persists in the latest `main` branch.
  - type: textarea
    id: description
    attributes:
      label: Describe the bug
      description: A clear and concise description of what the bug is.
    validations:
      required: true
  - type: textarea
    id: reproduction
    attributes:
      label: Steps to Reproduce
      description: How do we trigger this behavior?
      placeholder: |
        1. Varta::connect(...)
        2. beat(...)
        3. ...
    validations:
      required: true
  - type: textarea
    id: environment
    attributes:
      label: Environment
      description: OS version, Rust version, Hardware (e.g. Apple Silicon, x86_64).
      placeholder: macOS 14.4, Rust 1.77.0, M1 Max
    validations:
      required: true
  - type: textarea
    id: logs
    attributes:
      label: Relevant Log Output
      description: Please provide `varta-watch` output or relevant stack traces.
      render: shell
