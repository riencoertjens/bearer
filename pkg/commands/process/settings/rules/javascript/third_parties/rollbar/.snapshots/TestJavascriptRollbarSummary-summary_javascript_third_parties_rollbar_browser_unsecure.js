critical:
    - rule_dsrid: DSR-1
      rule_display_id: javascript_rollbar
      rule_description: Do not send sensitive data to Rollbar.
      rule_documentation_url: https://curio.sh/reference/rules/javascript_rollbar
      line_number: 1
      filename: pkg/commands/process/settings/rules/javascript/third_parties/rollbar/testdata/browser_unsecure.js
      category_groups:
        - PII
      parent_line_number: 3
      parent_content: Rollbar.critical("Connection error from remote Payments API", user)


--
