#!/usr/bin/env python3

import os
import sys
import json
import uuid
import base64
import urllib.parse
import requests
import time


# ============================================================
# CONFIG
# ============================================================

BASE = os.environ.get(
    "BASE",
    "https://core.todayvpn.app/api/v1"
).rstrip("/")

SERVERS_OUT = "today.json"
VLESS_OUT = "today.txt"
SYNC_OUT = "sync.json"

OS_TYPE = "Android"
OS_VERSION = "16"
APP_VERSION = "1.0.0"
APP_BUILD = 1
DEVICE_MODEL = "RMX3709"


# ============================================================
# SESSION
# ============================================================

session = requests.Session()

session.headers.update({
    "Accept": "application/json",
    "Content-Type": "application/json",
})


# ============================================================
# DEVICE SYNC
# ============================================================

def sync_device():

    device_uuid = str(uuid.uuid4())

    print("[+] Device UUID:")
    print("    {}".format(device_uuid))

    body = {
        "OsType": OS_TYPE,
        "OsVersion": OS_VERSION,
        "AppVersion": APP_VERSION,
        "AppBuild": APP_BUILD,
        "DeviceUuid": device_uuid,
        "DeviceModel": DEVICE_MODEL,
    }

    print()
    print("[+] Device sync...")

    r = session.post(
        BASE + "/devices/sync",
        json=body,
        timeout=20,
    )

    print("    HTTP {}".format(r.status_code))

    r.raise_for_status()

    data = r.json()

    # Сохраняем полный ответ sync
    with open(SYNC_OUT, "w", encoding="utf-8") as f:
        json.dump(
            data,
            f,
            ensure_ascii=False,
            indent=2
        )

    if not data.get("success", True):
        raise RuntimeError(
            "Device sync failed: {}".format(
                data.get("error") or data.get("message")
            )
        )

    payload = data.get("data") or {}

    # Основной вариант, который у нас уже использовался:
    token = payload.get("accessToken")

    # На случай другого имени поля
    if not token:
        token = payload.get("token")

    if not token:
        token = data.get("accessToken")

    if not token:
        raise RuntimeError(
            "accessToken not found in /devices/sync response"
        )

    print("[+] Access token received")
    print("    length: {}".format(len(token)))

    return token, device_uuid


# ============================================================
# AUTH
# ============================================================

def set_token(token):

    session.headers.update({
        "Authorization": "Bearer " + token
    })


# ============================================================
# GET SERVERS
# ============================================================

def get_servers():

    print()
    print("[+] Getting servers...")

    r = session.get(
        BASE + "/servers",
        timeout=20,
    )

    print("    HTTP {}".format(r.status_code))

    r.raise_for_status()

    data = r.json()

    if not data.get("success", True):
        raise RuntimeError(
            "GET /servers failed: {}".format(
                data.get("error") or data.get("message")
            )
        )

    servers = (
        data
        .get("data", {})
        .get("servers", [])
    )

    print("[+] Found {} servers".format(len(servers)))

    return data, servers


# ============================================================
# BASE64 V2RAY CONFIG
# ============================================================

def decode_v2ray_config(encoded):

    encoded = encoded.strip()

    # base64 padding
    encoded += "=" * (-len(encoded) % 4)

    raw = base64.b64decode(encoded)

    return json.loads(
        raw.decode("utf-8")
    )


# ============================================================
# VLESS URI
# ============================================================

def get_vless_from_config(cfg, server_name):

    outbounds = cfg.get("outbounds", [])

    vless = None

    for outbound in outbounds:

        if outbound.get("protocol") == "vless":
            vless = outbound
            break

    if not vless:
        raise ValueError(
            "VLESS outbound not found"
        )

    settings = vless.get(
        "settings",
        {}
    )

    vnext = settings.get(
        "vnext",
        []
    )

    if not vnext:
        raise ValueError(
            "vnext is empty"
        )

    node = vnext[0]

    host = node.get("address")
    port = node.get("port")

    users = node.get(
        "users",
        []
    )

    if not users:
        raise ValueError(
            "VLESS users is empty"
        )

    user = users[0]

    user_uuid = user.get("id")

    encryption = user.get(
        "encryption",
        "none"
    )

    flow = user.get("flow")

    stream = vless.get(
        "streamSettings",
        {}
    )

    network = stream.get(
        "network",
        "tcp"
    )

    security = stream.get(
        "security"
    )

    reality = stream.get(
        "realitySettings",
        {}
    )

    sni = reality.get(
        "serverName"
    )

    fingerprint = reality.get(
        "fingerprint"
    )

    public_key = reality.get(
        "publicKey"
    )

    short_id = reality.get(
        "shortId"
    )

    if not host:
        raise ValueError("host missing")

    if not port:
        raise ValueError("port missing")

    if not user_uuid:
        raise ValueError("UUID missing")

    params = {
        "encryption": encryption
    }

    if flow:
        params["flow"] = flow

    if security:
        params["security"] = security

    if network:
        params["type"] = network

    if sni:
        params["sni"] = sni

    if fingerprint:
        params["fp"] = fingerprint

    if public_key:
        params["pbk"] = public_key

    if short_id:
        params["sid"] = short_id

    query = urllib.parse.urlencode(
        params
    )

    fragment = urllib.parse.quote(
        server_name,
        safe=""
    )

    return (
        "vless://"
        + user_uuid
        + "@"
        + str(host)
        + ":"
        + str(port)
        + "?"
        + query
        + "#"
        + fragment
    )


# ============================================================
# CONNECT
# ============================================================

def connect_server(server):

    sid = server["id"]

    name = server.get(
        "name",
        sid
    )

    country_id = server.get(
        "countryId"
    )

    location_id = server.get(
        "locationId"
    )

    inbounds = server.get(
        "inbounds"
    ) or []

    if inbounds:

        inbound = inbounds[0]

        protocol = (
            inbound.get("protocol")
            or "vless"
        )

        port = (
            inbound.get("port")
            or server.get("port")
        )

    else:

        protocol = "vless"

        port = server.get(
            "port"
        )

    body = {
        "serverId": sid,
        "countryId": country_id,
        "locationId": location_id,
        "protocol": protocol,
        "port": port,
    }

    r = session.post(
        BASE + "/vpn/connect",
        json=body,
        timeout=20,
    )

    r.raise_for_status()

    return r.json()


# ============================================================
# MAIN
# ============================================================

def main():

    print("========================================")
    print(" TodayVPN → VLESS extractor")
    print("========================================")

    # --------------------------------------------------------
    # 1. DEVICE SYNC
    # --------------------------------------------------------

    token, device_uuid = sync_device()

    set_token(token)

    # --------------------------------------------------------
    # 2. SERVERS
    # --------------------------------------------------------

    servers_raw, servers = get_servers()

    result_servers = []
    result_vless = []

    successful = 0
    failed = 0

    # --------------------------------------------------------
    # 3. CONNECT EACH SERVER
    # --------------------------------------------------------

    for index, server in enumerate(
        servers,
        1
    ):

        sid = server["id"]

        name = server.get(
            "name",
            sid
        )

        country = server.get(
            "countryCode",
            ""
        )

        print()
        print(
            "[{}/{}] {} [{}]".format(
                index,
                len(servers),
                name,
                country
            )
        )

        print(
            "    requested: {} ({})".format(
                name,
                sid
            )
        )

        try:

            response = connect_server(
                server
            )

            data = (
                response.get("data")
                or {}
            )

            error = data.get(
                "error"
            )

            if error:

                print(
                    "    [-] {}".format(
                        error
                    )
                )

                failed += 1
                continue

            selected = (
                data.get(
                    "selectedServer"
                )
                or {}
            )

            selected_id = selected.get(
                "id"
            )

            print(
                "    selected:  {} ({})".format(
                    selected.get("name"),
                    selected_id
                )
            )

            # ------------------------------------------------
            # IMPORTANT:
            # backend must return requested server
            # ------------------------------------------------

            if selected_id != sid:

                print(
                    "    [!] WARNING: backend selected another server"
                )

                failed += 1
                continue

            config = (
                data.get("config")
                or {}
            )

            encoded = config.get(
                "v2RayConfig"
            )

            if not encoded:

                print(
                    "    [-] no v2RayConfig"
                )

                failed += 1
                continue

            # ------------------------------------------------
            # Decode
            # ------------------------------------------------

            v2cfg = decode_v2ray_config(
                encoded
            )

            # ------------------------------------------------
            # Build VLESS
            # ------------------------------------------------

            uri = get_vless_from_config(
                v2cfg,
                name
            )

            host = config.get(
                "serverHost"
            )

            port = config.get(
                "serverPort"
            )

            print(
                "    endpoint:  {}:{}".format(
                    host,
                    port
                )
            )

            print(
                "    [+] {}".format(
                    uri
                )
            )

            # ------------------------------------------------
            # Extract useful metadata
            # ------------------------------------------------

            vless_outbound = None

            for outbound in v2cfg.get(
                "outbounds",
                []
            ):

                if outbound.get(
                    "protocol"
                ) == "vless":

                    vless_outbound = outbound
                    break

            metadata = {}

            if vless_outbound:

                settings = vless_outbound.get(
                    "settings",
                    {}
                )

                vnext = settings.get(
                    "vnext",
                    []
                )

                if vnext:

                    node = vnext[0]

                    users = node.get(
                        "users",
                        []
                    )

                    if users:

                        user = users[0]

                        metadata["uuid"] = user.get(
                            "id"
                        )

                        metadata["flow"] = user.get(
                            "flow"
                        )

                        metadata["encryption"] = user.get(
                            "encryption"
                        )

                stream = vless_outbound.get(
                    "streamSettings",
                    {}
                )

                metadata["network"] = stream.get(
                    "network"
                )

                metadata["security"] = stream.get(
                    "security"
                )

                reality = stream.get(
                    "realitySettings",
                    {}
                )

                metadata["sni"] = reality.get(
                    "serverName"
                )

                metadata["fingerprint"] = reality.get(
                    "fingerprint"
                )

                metadata["publicKey"] = reality.get(
                    "publicKey"
                )

                metadata["shortId"] = reality.get(
                    "shortId"
                )

            # ------------------------------------------------
            # Save
            # ------------------------------------------------

            result_servers.append({

                "id": sid,

                "name": name,

                "countryCode": country,

                "countryName": server.get(
                    "countryName"
                ),

                "locationName": server.get(
                    "locationName"
                ),

                "host": host,

                "port": port,

                "protocol": config.get(
                    "protocol"
                ),

                "configVariant": data.get(
                    "configVariant"
                ),

                "uuid": metadata.get(
                    "uuid"
                ),

                "flow": metadata.get(
                    "flow"
                ),

                "encryption": metadata.get(
                    "encryption"
                ),

                "network": metadata.get(
                    "network"
                ),

                "security": metadata.get(
                    "security"
                ),

                "sni": metadata.get(
                    "sni"
                ),

                "fingerprint": metadata.get(
                    "fingerprint"
                ),

                "publicKey": metadata.get(
                    "publicKey"
                ),

                "shortId": metadata.get(
                    "shortId"
                ),

                "vless": uri,

                "selectedServer": selected,

                "v2RayConfig": encoded,

            })

            result_vless.append(
                uri
            )

            successful += 1

        except Exception as e:

            print(
                "    [!] ERROR: {}".format(
                    e
                )
            )

            failed += 1

        time.sleep(0.3)

    # ========================================================
    # OUTPUT servers.json
    # ========================================================

    output = {
        "deviceUuid": device_uuid,
        "generatedAt": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime()
        ),
        "successful": successful,
        "failed": failed,
        "total": len(servers),
        "servers": result_servers
    }

    with open(
        SERVERS_OUT,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            output,
            f,
            ensure_ascii=False,
            indent=2
        )

    # ========================================================
    # OUTPUT vless.txt
    # ========================================================

    with open(
        VLESS_OUT,
        "w",
        encoding="utf-8"
    ) as f:

        for uri in result_vless:

            f.write(
                uri + "\n"
            )

    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print("========================================")
    print(
        "[+] Successful: {}".format(
            successful
        )
    )
    print(
        "[+] Failed: {}".format(
            failed
        )
    )
    print(
        "[+] Total: {}".format(
            len(servers)
        )
    )
    print(
        "[+] {}".format(
            SERVERS_OUT
        )
    )
    print(
        "[+] {}".format(
            VLESS_OUT
        )
    )
    print(
        "[+] {}".format(
            SYNC_OUT
        )
    )
    print("========================================")


if __name__ == "__main__":
    main()
