"""SOAR Integration Framework — take action, not just score.

Provides a unified interface for automated response actions:
  - CrowdStrike Falcon: Isolate/contain endpoints
  - Okta: Suspend/unsuspend users, clear sessions
  - ServiceNow: Create incident tickets

Each integration is configured per-tenant via API keys stored in
tenant settings. Actions are triggered from case detail or
automatically by high-confidence incident workflows.
"""
