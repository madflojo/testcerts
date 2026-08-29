---
on:
  schedule: weekly on friday
  workflow_dispatch:
  steps:
    - name: Select alternating hunter cohort
      id: rotation
      run: |
        week="$(date -u +%V)"
        test "$((10#$week % 2))" -eq 1
  skip-if-match:
    query: 'is:pr is:open in:body "code-hunters-origin"'
    # Default total-open limit. Change only through explicit operator configuration.
    max: 10

if: github.event_name == 'workflow_dispatch' || needs.pre_activation.outputs.rotation_result == 'success'

concurrency:
  group: code-hunters-documentation-hunter
  cancel-in-progress: false

imports:
  - uses: ./documentation-hunter.md
    with:
      allowed-files: ["README.md", "*.go"]
      protected-files: fallback-to-issue
      # Default per-run limit. Change only through explicit operator configuration.
      max-pull-requests-per-run: 5
---

<!-- Generated from hunter.json. Do not edit directly. -->

# Run Documentation Hunter

Run one bounded Documentation Hunter maintenance pass.
