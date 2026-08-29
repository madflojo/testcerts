---
on:
  schedule: weekly on sunday
  workflow_dispatch:
  skip-if-match:
    query: 'is:pr is:open in:body "code-hunters-origin"'
    # Default total-open limit. Change only through explicit operator configuration.
    max: 10

concurrency:
  group: code-hunters-testing-hunter
  cancel-in-progress: false

imports:
  - uses: ./testing-hunter.md
    with:
      allowed-files: ["*_test.go", "testdata/**", "*.go", "go.*"]
      protected-files: fallback-to-issue
      # Default per-run limit. Change only through explicit operator configuration.
      max-pull-requests-per-run: 5
---

<!-- Generated from hunter.json. Do not edit directly. -->

# Run Testing Hunter

Run one bounded Testing Hunter maintenance pass.
