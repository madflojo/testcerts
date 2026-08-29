---
on:
  schedule: weekly on monday
  workflow_dispatch:
  steps:
    - name: Select alternating hunter cohort
      id: rotation
      run: |
        week="$(date -u +%V)"
        test "$((10#$week % 2))" -eq 0
  skip-if-match:
    query: 'is:pr is:open in:body "code-hunters-origin"'
    # Default total-open limit. Change only through explicit operator configuration.
    max: 10

if: github.event_name == 'workflow_dispatch' || needs.pre_activation.outputs.rotation_result == 'success'

concurrency:
  group: code-hunters-bug-hunter
  cancel-in-progress: false

imports:
  - uses: ./bug-hunter.md
    with:
      allowed-files: ["*.go", "go.*", "README.md"]
      protected-files: fallback-to-issue
      # Default per-run limit. Change only through explicit operator configuration.
      max-pull-requests-per-run: 5
---

<!-- Generated from hunter.json. Do not edit directly. -->

# Run Bug Hunter

Run one bounded Bug Hunter maintenance pass.
