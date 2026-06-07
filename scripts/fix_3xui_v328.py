#!/usr/bin/env python3
"""
Fix 3x-ui v3.2.8 database migration issues.

Background:
    3x-ui v3.2.8 changed its database schema:
    - Clients moved from inbounds.settings JSON to standalone `clients` table
    - realitySettings.settings.publicKey flattened to realitySettings.publicKey

    The built-in migration script does NOT copy old client data, leaving
    xray config with clients=null and publicKey missing after upgrade.

Usage:
    scp fix_3xui_v328.py <host>:/tmp/
    ssh <host> 'python3 /tmp/fix_3xui_v328.py'

Then restart x-ui:
    ssh <host> 'systemctl restart x-ui'
"""

import json, sqlite3, shutil, subprocess, sys, os

def fix_database():
    db_path = "/etc/x-ui/x-ui.db"
    if not os.path.exists(db_path):
        print(f"[!] Database not found: {db_path}")
        sys.exit(1)

    backup_path = f"/etc/x-ui/x-ui.db.backup.pre-fix"
    shutil.copy(db_path, backup_path)
    print(f"[+] Database backed up to {backup_path}")

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # 1. Migrate clients from inbounds.settings JSON to clients table
    cur.execute("SELECT id, settings, stream_settings FROM inbounds WHERE protocol='vless'")
    migrated = 0
    for row in cur.fetchall():
        inbound_id, settings_json, stream_json = row
        try:
            settings = json.loads(settings_json)
        except json.JSONDecodeError:
            continue

        for client in settings.get("clients", []):
            email = client.get("email") or f"user_{inbound_id}@local"
            uuid = client.get("id", "")
            flow = client.get("flow", "")
            limit_ip = client.get("limitIp", 0)
            total_gb = client.get("totalGB", 0)
            expiry_time = client.get("expiryTime", 0)
            enable = client.get("enable", True)
            tg_id = client.get("tgId", 0) or 0
            sub_id = client.get("subId", "")
            reset = client.get("reset", 0)

            cur.execute("""
                INSERT OR IGNORE INTO clients
                (email, uuid, flow, limit_ip, total_gb, expiry_time, enable, tg_id, sub_id, reset)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (email, uuid, flow, limit_ip, total_gb, expiry_time, enable, tg_id, sub_id, reset))

            cur.execute("SELECT id FROM clients WHERE email=?", (email,))
            client_row = cur.fetchone()
            if client_row:
                client_id = client_row[0]
                cur.execute("""
                    INSERT OR IGNORE INTO client_inbounds (client_id, inbound_id, flow_override)
                    VALUES (?, ?, ?)
                """, (client_id, inbound_id, flow))
                migrated += 1
                print(f"[+] Migrated client {email} for inbound {inbound_id}")

    # 2. Flatten realitySettings.settings to top-level fields
    cur.execute("SELECT id, stream_settings FROM inbounds WHERE protocol='vless'")
    for row in cur.fetchall():
        inbound_id, stream_json = row
        try:
            stream = json.loads(stream_json)
        except json.JSONDecodeError:
            continue

        reality = stream.get("realitySettings", {})
        if "settings" in reality:
            nested = reality.pop("settings", {})
            reality["publicKey"] = nested.get("publicKey", "")
            reality["fingerprint"] = nested.get("fingerprint", "chrome")
            reality["serverName"] = nested.get("serverName", "")
            reality["spiderX"] = nested.get("spiderX", "/")
            stream["realitySettings"] = reality
            cur.execute("UPDATE inbounds SET stream_settings=? WHERE id=?",
                        (json.dumps(stream), inbound_id))
            print(f"[+] Flattened realitySettings for inbound {inbound_id}")

    conn.commit()
    conn.close()
    print(f"[+] Done. Migrated {migrated} clients.")

def restart_xui():
    subprocess.run(["systemctl", "restart", "x-ui"], check=True)
    print("[+] x-ui restarted.")

def verify():
    import time
    time.sleep(2)
    config_path = "/usr/local/x-ui/bin/config.json"
    if not os.path.exists(config_path):
        print("[verify] xray config not found!")
        return False

    with open(config_path) as f:
        d = json.load(f)
    for i in d.get("inbounds", []):
        if i.get("protocol") == "vless":
            clients = i.get("settings", {}).get("clients")
            pk = i.get("streamSettings", {}).get("realitySettings", {}).get("publicKey", "")
            ok = clients is not None and len(clients) > 0 and bool(pk)
            print(f"[verify] clients: {clients is not None and len(clients)>0}, publicKey: {bool(pk)} -> {'OK' if ok else 'FAIL'}")
            return ok
    print("[verify] No VLESS inbound found!")
    return False

if __name__ == "__main__":
    fix_database()
    restart_xui()
    if verify():
        print("\n✅ All fixed!")
        sys.exit(0)
    else:
        print("\n❌ Verification failed! Check /usr/local/x-ui/bin/config.json")
        sys.exit(1)
