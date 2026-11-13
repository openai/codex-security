"""Synthetic internal balance service."""

import os

BALANCES = {
    "acme": 500,
    "beacon": 800,
    "cedar": 1200,
}


def balance_for_account(authorized_tenant_id):
    return {
        "tenant_id": authorized_tenant_id,
        "balance_cents": BALANCES[authorized_tenant_id],
    }


def handler(_event, _context):
    """IAM-only Lambda entry point; tenant comes from deployment configuration."""
    return balance_for_account(os.environ.get("AUTHORIZED_TENANT_ID", "acme"))
