# Azure AD Security

This Powerpipe mod provides security benchmarks for analyzing Azure AD privileged users.

## Benchmarks

- **Azure AD Privileged Users** - Detects privileged users (Tier 0/1 roles) signing in from unmanaged devices

## Usage

```bash
powerpipe benchmark run benchmark.azuread_privileged_users
```

## Requirements

- Steampipe with Azure AD plugin configured and data populated
