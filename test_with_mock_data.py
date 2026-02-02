#!/usr/bin/env python3
"""
Mock data test script for Azure AD Privileged Users Powerpipe benchmark.

This script tests the SQL query logic locally using SQLite, simulating
the Steampipe Azure AD tables. It validates the recursive CTE for nested
group resolution and the privileged user sign-in detection logic.

Usage:
    python test_with_mock_data.py
"""

import sqlite3
import json
from typing import List, Dict, Any

# Sample Tier 0 role IDs
TIER0_ROLE_IDS = [
    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
    "b24988ac-6180-42a0-ab88-20f7382dd24c",  # Contributor
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
]

# Sample Tier 1 role IDs
TIER1_ROLE_IDS = [
    "f25e0fa2-a7c8-4377-a976-54943a77a395",  # Key Vault Contributor
]


def setup_database(conn: sqlite3.Connection):
    """Create mock tables matching Steampipe schema."""
    cursor = conn.cursor()
    
    # Create azuread_group table
    cursor.execute("""
        CREATE TABLE azuread_group (
            id TEXT PRIMARY KEY,
            display_name TEXT,
            member_ids TEXT  -- JSON array stored as text
        )
    """)
    
    # Create azuread_directory_role table
    cursor.execute("""
        CREATE TABLE azuread_directory_role (
            id TEXT PRIMARY KEY,
            display_name TEXT,
            role_template_id TEXT,
            member_ids TEXT  -- JSON array stored as text
        )
    """)
    
    # Create azuread_sign_in_report table
    cursor.execute("""
        CREATE TABLE azuread_sign_in_report (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            user_principal_name TEXT,
            created_date_time TEXT,
            app_display_name TEXT,
            resource_display_name TEXT,
            ip_address TEXT,
            status TEXT,       -- JSON object stored as text
            device_detail TEXT -- JSON object stored as text
        )
    """)
    
    conn.commit()


def insert_mock_data(conn: sqlite3.Connection):
    """Insert test data covering various scenarios."""
    cursor = conn.cursor()
    
    # === GROUPS ===
    # Group 1: Direct members only
    cursor.execute("""
        INSERT INTO azuread_group (id, display_name, member_ids)
        VALUES ('group-1', 'IT Admins', '["user-1", "user-2"]')
    """)
    
    # Group 2: Nested group (contains group-1)
    cursor.execute("""
        INSERT INTO azuread_group (id, display_name, member_ids)
        VALUES ('group-2', 'All Admins', '["group-1", "user-3"]')
    """)
    
    # Group 3: Deeply nested (level 3)
    cursor.execute("""
        INSERT INTO azuread_group (id, display_name, member_ids)
        VALUES ('group-3', 'Super Admins', '["group-2", "user-4"]')
    """)
    
    # === DIRECTORY ROLES ===
    # Role 1: Global Administrator (Tier 0) - has direct user and nested group
    cursor.execute("""
        INSERT INTO azuread_directory_role (id, display_name, role_template_id, member_ids)
        VALUES ('role-ga', 'Global Administrator', '62e90394-69f5-4237-9190-012177145e10', '["user-admin", "group-3"]')
    """)
    
    # Role 2: Contributor (Tier 0) - direct user only
    cursor.execute("""
        INSERT INTO azuread_directory_role (id, display_name, role_template_id, member_ids)
        VALUES ('role-contrib', 'Contributor', 'b24988ac-6180-42a0-ab88-20f7382dd24c', '["user-contrib"]')
    """)
    
    # Role 3: Key Vault Contributor (Tier 1) - direct user only
    cursor.execute("""
        INSERT INTO azuread_directory_role (id, display_name, role_template_id, member_ids)
        VALUES ('role-kv', 'Key Vault Contributor', 'f25e0fa2-a7c8-4377-a976-54943a77a395', '["user-kv"]')
    """)
    
    # Role 4: Non-privileged role (not in our list)
    cursor.execute("""
        INSERT INTO azuread_directory_role (id, display_name, role_template_id, member_ids)
        VALUES ('role-reader', 'Directory Reader', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', '["user-reader"]')
    """)
    
    # === SIGN-IN REPORTS ===
    # Sign-in 1: Privileged user (Tier 0 user-admin) from UNMANAGED device - SHOULD ALERT
    cursor.execute("""
        INSERT INTO azuread_sign_in_report (id, user_id, user_principal_name, created_date_time, app_display_name, 
            resource_display_name, ip_address, status, device_detail)
        VALUES ('signin-1', 'user-admin', 'admin@example.com', '2024-01-15T10:30:00Z', 'Azure Portal', 
            'Azure Management', '192.168.1.100', '{"errorCode": 0}', 
            '{"isManaged": false, "operatingSystem": "Windows 10", "browser": "Chrome"}')
    """)
    
    # Sign-in 2: Nested privileged user (Tier 0 user-1 found via nesting) from UNMANAGED - SHOULD ALERT
    cursor.execute("""
        INSERT INTO azuread_sign_in_report (id, user_id, user_principal_name, created_date_time, app_display_name, 
            resource_display_name, ip_address, status, device_detail)
        VALUES ('signin-2', 'user-1', 'user1@example.com', '2024-01-15T11:00:00Z', 'Microsoft Graph', 
            'Graph API', '10.0.0.50', '{"errorCode": 0}', 
            '{"isManaged": false, "operatingSystem": "macOS", "browser": "Safari"}')
    """)
    
    # Sign-in 3: Privileged user (Tier 1 user-kv) from UNMANAGED - SHOULD ALERT
    cursor.execute("""
        INSERT INTO azuread_sign_in_report (id, user_id, user_principal_name, created_date_time, app_display_name, 
            resource_display_name, ip_address, status, device_detail)
        VALUES ('signin-kv', 'user-kv', 'kv@example.com', '2024-01-15T11:30:00Z', 'Azure Portal', 
            'Azure Management', '192.168.1.101', '{"errorCode": 0}', 
            '{"isManaged": false, "operatingSystem": "Windows 10", "browser": "Edge"}')
    """)
    
    # Sign-in 4: Privileged user from MANAGED device - SHOULD NOT ALERT
    cursor.execute("""
        INSERT INTO azuread_sign_in_report (id, user_id, user_principal_name, created_date_time, app_display_name, 
            resource_display_name, ip_address, status, device_detail)
        VALUES ('signin-3', 'user-contrib', 'contrib@example.com', '2024-01-15T12:00:00Z', 'Azure Portal', 
            'Azure Management', '192.168.1.200', '{"errorCode": 0}', 
            '{"isManaged": true, "operatingSystem": "Windows 11", "browser": "Edge"}')
    """)
    
    # Sign-in 5: FAILED sign-in (privileged user, unmanaged) - SHOULD NOT ALERT
    cursor.execute("""
        INSERT INTO azuread_sign_in_report (id, user_id, user_principal_name, created_date_time, app_display_name, 
            resource_display_name, ip_address, status, device_detail)
        VALUES ('signin-4', 'user-admin', 'admin@example.com', '2024-01-15T13:00:00Z', 'Azure Portal', 
            'Azure Management', '192.168.1.100', '{"errorCode": 50126}', 
            '{"isManaged": false, "operatingSystem": "Windows 10", "browser": "Chrome"}')
    """)
    
    # Sign-in 6: Non-privileged user from unmanaged device - SHOULD NOT ALERT
    cursor.execute("""
        INSERT INTO azuread_sign_in_report (id, user_id, user_principal_name, created_date_time, app_display_name, 
            resource_display_name, ip_address, status, device_detail)
        VALUES ('signin-5', 'user-reader', 'reader@example.com', '2024-01-15T14:00:00Z', 'Azure Portal', 
            'Azure Management', '192.168.1.50', '{"errorCode": 0}', 
            '{"isManaged": false, "operatingSystem": "Linux", "browser": "Firefox"}')
    """)
    
    conn.commit()


def run_privileged_signin_query(conn: sqlite3.Connection, tier0_ids: List[str], tier1_ids: List[str]) -> List[Dict[str, Any]]:
    """
    Execute the privileged user sign-in detection query.
    
    Uses SQLite's recursive CTE to handle nested group memberships (similar to PostgreSQL).
    Requires separate lists for Tier 0 and Tier 1 roles to assign correct labels.
    """
    cursor = conn.cursor()
    
    tier0_str = ",".join(f"'{rid}'" for rid in tier0_ids)
    tier1_str = ",".join(f"'{rid}'" for rid in tier1_ids)
    
    # SQLite supports recursive CTEs with similar syntax to PostgreSQL
    query = f"""
        WITH RECURSIVE group_members AS (
            -- Base case: direct group members
            SELECT 
                g.id as root_group_id,
                g.id as group_id, 
                json_each.value as member_id, 
                1 as depth
            FROM azuread_group g,
                 json_each(g.member_ids)
            
            UNION ALL
            
            -- Recursive case: nested groups (depth limit 20)
            SELECT 
                gm.root_group_id,
                g.id as group_id,
                json_each.value as member_id, 
                gm.depth + 1
            FROM group_members gm
            JOIN azuread_group g ON g.id = gm.member_id
            CROSS JOIN json_each(g.member_ids)
            WHERE gm.depth < 20
        ),
        -- All users reachable from each root group
        expanded_groups AS (
            SELECT DISTINCT root_group_id, member_id
            FROM group_members
            WHERE member_id NOT LIKE 'group-%'
        ),
        direct_role_members AS (
            -- Get role to member mappings
            SELECT 
                dr.display_name as role_name,
                dr.role_template_id,
                json_each.value as member_id
            FROM azuread_directory_role dr,
                 json_each(dr.member_ids)
            WHERE dr.role_template_id IN ({tier0_str}, {tier1_str})
        ),
        privileged_users AS (
            -- Direct users in roles
            SELECT DISTINCT 
                drm.member_id as user_id, 
                drm.role_name,
                CASE 
                    WHEN drm.role_template_id IN ({tier0_str}) THEN 'Tier 0'
                    ELSE 'Tier 1'
                END as tier
            FROM direct_role_members drm
            WHERE drm.member_id NOT LIKE 'group-%'
            
            UNION
            
            -- Users via groups (expanded)
            SELECT DISTINCT 
                eg.member_id as user_id, 
                drm.role_name,
                CASE 
                    WHEN drm.role_template_id IN ({tier0_str}) THEN 'Tier 0'
                    ELSE 'Tier 1'
                END as tier
            FROM direct_role_members drm
            JOIN expanded_groups eg ON eg.root_group_id = drm.member_id
        )
        SELECT
            s.id as resource,
            'alarm' as status,
            pu.role_name || ' ' || pu.tier || ' ' || s.user_principal_name || ' signed in from ' || s.ip_address || ' (' || COALESCE(json_extract(s.device_detail, '$.operatingSystem'), 'Unknown OS') || ') to ' || s.app_display_name as reason,
            pu.user_id,
            s.user_principal_name,
            pu.tier,
            pu.role_name,
            s.created_date_time,
            s.app_display_name,
            s.resource_display_name,
            s.ip_address,
            json_object(
                'user_principal_name', s.user_principal_name,
                'user_id', pu.user_id,
                'tier', pu.tier,
                'role_name', pu.role_name,
                'sign_in_time', s.created_date_time,
                'app_display_name', s.app_display_name,
                'resource_display_name', s.resource_display_name,
                'ip_address', s.ip_address,
                'operating_system', json_extract(s.device_detail, '$.operatingSystem'),
                'browser', json_extract(s.device_detail, '$.browser')
            ) as dimensions
        FROM azuread_sign_in_report s
        JOIN privileged_users pu ON pu.user_id = s.user_id
        WHERE 
            -- Successful sign-in (error code 0)
            COALESCE(json_extract(s.status, '$.errorCode'), -1) = 0
            -- Device is not managed
            AND COALESCE(json_extract(s.device_detail, '$.isManaged'), 0) = 0
        ORDER BY s.created_date_time DESC
    """
    
    cursor.execute(query)
    columns = [desc[0] for desc in cursor.description]
    results = [dict(zip(columns, row)) for row in cursor.fetchall()]
    return results


def run_tests():
    """Run all test cases and report results."""
    print("=" * 60)
    print("Azure AD Privileged Users - Mock Data Tests")
    print("=" * 60)
    print()
    
    # Create in-memory SQLite database
    conn = sqlite3.connect(":memory:")
    
    try:
        # Setup and populate database
        print("[1/3] Setting up mock database...")
        setup_database(conn)
        print("      ✓ Tables created")
        
        print("[2/3] Inserting test data...")
        insert_mock_data(conn)
        print("      ✓ Test data inserted")
        
        print("[3/3] Running privileged sign-in detection query...")
        results = run_privileged_signin_query(conn, TIER0_ROLE_IDS, TIER1_ROLE_IDS)
        print(f"      ✓ Query completed, found {len(results)} alerts")
        print()
        
        # Validate results
        print("-" * 60)
        print("Test Results:")
        print("-" * 60)
        
        expected_alerts = {"signin-1", "signin-2", "signin-kv"} 
        actual_alerts = {r["resource"] for r in results}
        
        # Test 1: Check expected alerts are found
        test1_pass = expected_alerts <= actual_alerts
        print(f"[TEST 1] Expected privileged users detected (T0+T1): {'PASS ✓' if test1_pass else 'FAIL ✗'}")
        if not test1_pass:
            missing = expected_alerts - actual_alerts
            print(f"         Missing: {missing}")
        
        # Test 2: Check no false positives
        expected_no_alert = {"signin-3", "signin-4", "signin-5"}
        unexpected_alerts = actual_alerts & expected_no_alert
        test2_pass = len(unexpected_alerts) == 0
        print(f"[TEST 2] No false positives: {'PASS ✓' if test2_pass else 'FAIL ✗'}")
        
        # Test 3: Validate enriched fields (Tier, UPN)
        # Parse dimensions column which returns as a string in SQLite mock if using json_object, 
        # or dict if we parse it. sqlite3 in python returns string for JSON types usually.
        
        found_tiers = {}
        found_upns = {}
        
        for r in results:
            dims = json.loads(r["dimensions"]) if isinstance(r["dimensions"], str) else r["dimensions"]
            found_tiers[r["resource"]] = dims.get("tier")
            found_upns[r["resource"]] = dims.get("user_principal_name")
            
        tier_check_pass = (
            found_tiers.get("signin-1") == "Tier 0" and 
            found_tiers.get("signin-2") == "Tier 0" and 
            found_tiers.get("signin-kv") == "Tier 1"
        )
        print(f"[TEST 3] Tier assignment correct (T0 vs T1): {'PASS ✓' if tier_check_pass else 'FAIL ✗'}")
        
        upn_check_pass = (
            found_upns.get("signin-1") == "admin@example.com" and 
            found_upns.get("signin-kv") == "kv@example.com"
        )
        print(f"[TEST 4] UPN data present: {'PASS ✓' if upn_check_pass else 'FAIL ✗'}")

        print()
        print("-" * 60)
        print("Alert Details Sample:")
        print("-" * 60)
        for result in results[:3]:
            dims = json.loads(result["dimensions"]) if isinstance(result["dimensions"], str) else result["dimensions"]
            print(f"  • {dims['user_principal_name']} ({dims['tier']} - {dims['role_name']})")
            print(f"    User ID: {dims['user_id']}")
            print(f"    App: {dims['app_display_name']}")
            print(f"    Device OS: {dims['operating_system']}")
            # Reason is still top-level
            print(f"    Reason: {result['reason']}")
            print()
        
        # Summary
        all_pass = test1_pass and test2_pass and tier_check_pass and upn_check_pass
        print("=" * 60)
        if all_pass:
            print("ALL TESTS PASSED ✓")
        else:
            print("SOME TESTS FAILED ✗")
        print("=" * 60)
        
        return all_pass
        
    finally:
        conn.close()


if __name__ == "__main__":
    import sys
    success = run_tests()
    sys.exit(0 if success else 1)
