import base64
import shlex
import socket
import time
from dataclasses import dataclass, field
from typing import Callable

from lists_store import GoodIpRecord


RegionEnv = Callable[[str, str], str]


@dataclass
class OpenStackConfig:
    auth_url: str
    project_id: str = ""
    project_name: str = ""
    username: str = ""
    password: str = ""
    user_domain_name: str = "Default"
    project_domain_name: str = "Default"
    interface: str = "public"
    identity_api_version: str = "3"
    compute_api_version: str = "2.72"
    connect_retries: int = 2
    api_timeout: int = 30


@dataclass
class SelectelCloudConfig:
    floating_network_id: str = ""
    floating_network_name: str = ""
    provision_origin_ip: str = ""
    provision_vless_template: str = ""
    provision_preemptible_regions: list[str] = field(default_factory=list)
    provision_server_name_prefix: str = "selectel-finder"
    provision_image_id: str = ""
    provision_image_name: str = "Ubuntu 24.04 LTS 64-bit"
    provision_flavor_id: str = ""
    provision_flavor_name: str = ""
    provision_require_local_disk: bool = True
    provision_network_id: str = ""
    provision_network_name: str = ""
    provision_security_group: str = "selectel-finder-proxy"
    provision_key_name: str = ""
    provision_availability_zone: str = ""
    provision_auto_flavor_fallback: bool = True
    provision_max_flavor_attempts: int = 10
    provision_server_wait_seconds: int = 300
    provision_setup_wait_seconds: int = 120
    provision_tcp_check_enabled: bool = True
    provision_tcp_check_timeout: int = 5
    provision_tcp_check_retries: int = 6
    region_env: RegionEnv | None = None


def _openstack():
    import openstack

    return openstack


def get_connection(config: OpenStackConfig, region: str):
    return _openstack().connection.Connection(
        auth_url=config.auth_url,
        project_id=config.project_id or None,
        project_name=None if config.project_id else config.project_name or None,
        username=config.username,
        password=config.password,
        user_domain_name=config.user_domain_name,
        project_domain_name=config.project_domain_name,
        region_name=region,
        interface=config.interface,
        identity_api_version=config.identity_api_version,
        compute_api_version=config.compute_api_version,
        connect_retries=config.connect_retries,
        api_timeout=config.api_timeout,
    )


def close_connection(conn):
    if not conn:
        return
    try:
        close = getattr(conn, "close", None)
        if callable(close):
            close()
            return
        session = getattr(conn, "session", None) or getattr(conn, "_session", None)
        session_close = getattr(session, "close", None)
        if callable(session_close):
            session_close()
    except Exception:
        pass


def _region_env(config: SelectelCloudConfig, name: str, region: str) -> str:
    if not config.region_env:
        return ""
    return config.region_env(name, region)


def _provision_region_env(config: SelectelCloudConfig, name: str, region: str) -> str:
    return _region_env(config, f"PROVISION_{name}", region)


def get_floating_network(conn, region: str, config: SelectelCloudConfig):
    network_id = _region_env(config, "FLOATING_NETWORK_ID", region) or config.floating_network_id
    network_name = _region_env(config, "FLOATING_NETWORK_NAME", region) or config.floating_network_name

    if network_id:
        return conn.network.get_network(network_id)

    if network_name:
        network = conn.network.find_network(network_name, ignore_missing=True)
        if not network:
            raise RuntimeError(f"External network '{network_name}' not found in {region}")
        return network

    networks = list(conn.network.networks(is_router_external=True))
    if not networks:
        raise RuntimeError(f"No external networks found in {region}")

    if len(networks) > 1:
        found = ", ".join(
            f"{getattr(network, 'name', '<no-name>')} ({network.id})"
            for network in networks
        )
        raise RuntimeError(
            f"Multiple external networks found in {region}; set FLOATING_NETWORK_ID "
            f"or FLOATING_NETWORK_NAME in .env. Found: {found}"
        )

    return networks[0]


def create_floating_ip(region: str, auth_config: OpenStackConfig, cloud_config: SelectelCloudConfig):
    conn = get_connection(auth_config, region)
    try:
        network = get_floating_network(conn, region, cloud_config)
        ip = conn.network.create_ip(floating_network_id=network.id)
        return conn, ip.id, ip.floating_ip_address
    except Exception:
        close_connection(conn)
        raise


def delete_floating_ip(conn, ip_id) -> bool:
    try:
        conn.network.delete_ip(ip_id, ignore_missing=True)
        return True
    except Exception as e:
        print(f"⚠️ Ошибка удаления IP {ip_id}: {e}", flush=True)
        return False


def saved_ip_active(record: GoodIpRecord, auth_config: OpenStackConfig) -> bool:
    conn = None
    try:
        conn = get_connection(auth_config, record.region)

        if record.ip_id:
            ip = conn.network.find_ip(record.ip_id, ignore_missing=True)
            return bool(ip and getattr(ip, "floating_ip_address", "") == record.ip)

        for ip in conn.network.ips():
            if getattr(ip, "floating_ip_address", "") == record.ip:
                return True

        return False
    except Exception as e:
        print(f"⚠️ Не удалось проверить сохраненный IP {record.ip}: {e}", flush=True)
        return True
    finally:
        close_connection(conn)


def find_floating_ip(conn, address: str):
    for ip in conn.network.ips():
        if getattr(ip, "floating_ip_address", "") == address:
            return ip
    return None


def delete_floating_ip_address(conn, address: str, ip_id: str = "") -> bool:
    """Delete a Floating IP by address, falling back to the saved id."""
    target = ""
    ip_obj = None
    lookup_failed = False
    if address:
        try:
            ip_obj = find_floating_ip(conn, address)
            target = getattr(ip_obj, "id", "") if ip_obj else ""
        except Exception as e:
            lookup_failed = True
            print(f"⚠️ Не удалось найти Floating IP по адресу {address}: {e}", flush=True)

    if not target and ip_id:
        target = ip_id
        try:
            ip_obj = conn.network.find_ip(ip_id, ignore_missing=True)
        except Exception:
            pass

    if not target:
        return not lookup_failed

    if ip_obj and getattr(ip_obj, "port_id", None):
        try:
            conn.network.update_ip(ip_obj, port_id=None)
            print(f"✅ Floating IP отвязан перед удалением: {address or target}", flush=True)
        except Exception as e:
            print(f"⚠️ Не удалось отвязать Floating IP перед удалением {address or target}: {e}", flush=True)

    if not delete_floating_ip(conn, target):
        return False

    if address and not lookup_failed:
        try:
            remaining = find_floating_ip(conn, address)
            if not remaining:
                return True
            remaining_id = getattr(remaining, "id", "")
            if remaining_id and remaining_id != target:
                return delete_floating_ip(conn, remaining_id)
            print(f"⚠️ Floating IP {address} всё ещё найден после удаления id={target}", flush=True)
            return False
        except Exception as e:
            print(f"⚠️ Не удалось проверить удаление Floating IP {address}: {e}", flush=True)

    return True


def get_server_ports(conn, server_id: str):
    return list(conn.network.ports(device_id=server_id))


def attach_floating_ip_to_server(conn, server, floating_ip_address: str):
    server_id = getattr(server, "id", "")
    if not server_id:
        raise RuntimeError("Server has no id, cannot attach floating IP")

    ports = get_server_ports(conn, server_id)
    if not ports:
        raise RuntimeError(f"No Neutron ports found for server {server_id}")

    port = ports[0]
    floating_ip = find_floating_ip(conn, floating_ip_address)
    if not floating_ip:
        raise RuntimeError(f"Floating IP not found: {floating_ip_address}")

    conn.network.update_ip(floating_ip, port_id=port.id)
    print(f"✅ Floating IP привязан через Neutron: {floating_ip_address} -> port {port.id}", flush=True)


def detach_floating_ip_from_server(conn, floating_ip_address: str):
    floating_ip = find_floating_ip(conn, floating_ip_address)
    if not floating_ip:
        return

    if getattr(floating_ip, "port_id", None):
        conn.network.update_ip(floating_ip, port_id=None)
        print(f"✅ Floating IP отвязан через Neutron: {floating_ip_address}", flush=True)


def get_provision_image(conn, region: str, config: SelectelCloudConfig):
    image_id = _provision_region_env(config, "IMAGE_ID", region) or config.provision_image_id
    image_name = _provision_region_env(config, "IMAGE_NAME", region) or config.provision_image_name

    if image_id:
        image = conn.image.find_image(image_id, ignore_missing=True)
        if image:
            return image
        raise RuntimeError(f"Ubuntu image id not found in {region}: {image_id}")

    if image_name:
        image = conn.image.find_image(image_name, ignore_missing=True)
        if image:
            return image

    images = [
        image
        for image in conn.image.images()
        if getattr(image, "status", "") == "active"
        and "ubuntu" in (getattr(image, "name", "") or "").lower()
    ]

    preferred = ["ubuntu 24.04 lts 64-bit", "ubuntu 22.04 lts 64-bit", "ubuntu 20.04 lts 64-bit"]
    for expected_name in preferred:
        for image in images:
            if (getattr(image, "name", "") or "").lower() == expected_name:
                return image

    if images:
        images.sort(key=lambda image: getattr(image, "name", "") or "")
        return images[0]

    raise RuntimeError(f"No active Ubuntu image found in {region}")


def flavor_sort_key(flavor):
    return (
        getattr(flavor, "vcpus", 10**9) or 10**9,
        getattr(flavor, "ram", 10**9) or 10**9,
        getattr(flavor, "disk", 10**9) or 10**9,
        str(getattr(flavor, "name", "")),
    )


def get_candidate_flavors(conn, region: str, config: SelectelCloudConfig):
    flavor_id = _provision_region_env(config, "FLAVOR_ID", region) or config.provision_flavor_id
    flavor_name = _provision_region_env(config, "FLAVOR_NAME", region) or config.provision_flavor_name
    selected_flavor = None

    if flavor_id:
        selected_flavor = conn.compute.find_flavor(flavor_id, ignore_missing=True)
        if not selected_flavor:
            raise RuntimeError(f"Flavor id not found in {region}: {flavor_id}")

    if flavor_name and not selected_flavor:
        selected_flavor = conn.compute.find_flavor(flavor_name, ignore_missing=True)
        if not selected_flavor:
            raise RuntimeError(f"Flavor not found in {region}: {flavor_name}")

    flavors = list(conn.compute.flavors())
    if config.provision_require_local_disk:
        flavors = [flavor for flavor in flavors if (getattr(flavor, "disk", 0) or 0) > 0]

    if selected_flavor:
        selected_id = getattr(selected_flavor, "id", "")
        rest = [flavor for flavor in flavors if getattr(flavor, "id", "") != selected_id]
        rest.sort(key=flavor_sort_key)
        flavors = [selected_flavor] + (rest if config.provision_auto_flavor_fallback else [])
    else:
        flavors.sort(key=flavor_sort_key)

    if not flavors:
        raise RuntimeError(f"No suitable flavors found in {region}")

    max_attempts = max(1, int(config.provision_max_flavor_attempts or 1))
    return flavors[:max_attempts]


def get_provision_network(conn, region: str, config: SelectelCloudConfig):
    network_id = _provision_region_env(config, "NETWORK_ID", region) or config.provision_network_id
    network_name = _provision_region_env(config, "NETWORK_NAME", region) or config.provision_network_name

    if network_id:
        network = conn.network.find_network(network_id, ignore_missing=True)
        if network:
            return network
        raise RuntimeError(f"Network id not found in {region}: {network_id}")

    if network_name:
        network = conn.network.find_network(network_name, ignore_missing=True)
        if network:
            return network
        raise RuntimeError(f"Network not found in {region}: {network_name}")

    networks = [
        network
        for network in conn.network.networks()
        if not getattr(network, "is_router_external", False)
    ]

    if not networks:
        raise RuntimeError(f"No private network found in {region}; set PROVISION_NETWORK_ID")

    networks.sort(key=lambda network: getattr(network, "name", "") or "")
    return networks[0]


def get_explicit_provision_availability_zone(region: str, config: SelectelCloudConfig):
    return _provision_region_env(config, "AVAILABILITY_ZONE", region) or config.provision_availability_zone


def ensure_security_group(conn, config: SelectelCloudConfig):
    security_group = conn.network.find_security_group(config.provision_security_group, ignore_missing=True)
    if not security_group:
        security_group = conn.network.create_security_group(
            name=config.provision_security_group,
            description="Selectel finder temporary VLESS test access",
        )

    for rule in conn.network.security_group_rules(security_group_id=security_group.id):
        if (
            getattr(rule, "direction", "") == "ingress"
            and str(getattr(rule, "protocol", "")).lower() == "tcp"
            and getattr(rule, "port_range_min", None) == 443
            and getattr(rule, "port_range_max", None) == 443
            and getattr(rule, "remote_ip_prefix", None) in (None, "0.0.0.0/0")
        ):
            return security_group

    try:
        conn.network.create_security_group_rule(
            security_group_id=security_group.id,
            direction="ingress",
            ethertype="IPv4",
            protocol="tcp",
            port_range_min=443,
            port_range_max=443,
            remote_ip_prefix="0.0.0.0/0",
        )
    except Exception as e:
        print(f"⚠️ Не удалось создать security group rule TCP/443: {e}", flush=True)

    return security_group


def make_cloud_init_script(config: SelectelCloudConfig) -> str:
    return (
        "#!/bin/bash\n"
        "set -euxo pipefail\n"
        "export DEBIAN_FRONTEND=noninteractive\n"
        "apt-get update\n"
        "apt-get install -y curl\n"
        "cd /root\n"
        "curl -fsSLO https://raw.githubusercontent.com/denpiligrim/3dp-manager/main/forwarding_install.sh\n"
        f"export ORIGIN_IP={shlex.quote(config.provision_origin_ip)}\n"
        "sudo -E bash forwarding_install.sh\n"
    )


def make_vless_key(ip: str, config: SelectelCloudConfig) -> str:
    return (
        config.provision_vless_template
        .replace("{Белый IP}", ip)
        .replace("{WHITE_IP}", ip)
        .replace("{IP}", ip)
        .replace("{ip}", ip)
    )


def validate_provision_config(config: SelectelCloudConfig):
    missing = []

    if not config.provision_origin_ip:
        missing.append("PROVISION_ORIGIN_IP")
    if not config.provision_vless_template:
        missing.append("PROVISION_VLESS_TEMPLATE")
    elif not any(token in config.provision_vless_template for token in ("{WHITE_IP}", "{Белый IP}", "{IP}", "{ip}")):
        raise RuntimeError("PROVISION_VLESS_TEMPLATE must contain {WHITE_IP}")

    if missing:
        raise RuntimeError(f"Missing provisioning settings: {', '.join(missing)}")


def tcp_connect_ok(host: str, port: int = 443, timeout: int = 5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_for_tcp_port(host: str, config: SelectelCloudConfig, port: int = 443) -> bool:
    if not config.provision_tcp_check_enabled:
        return True
    retries = max(1, int(config.provision_tcp_check_retries or 1))
    timeout = max(1, int(config.provision_tcp_check_timeout or 1))
    for attempt in range(1, retries + 1):
        if tcp_connect_ok(host, port=port, timeout=timeout):
            print(f"✅ TCP/{port} открыт на {host}", flush=True)
            return True
        print(f"⏳ TCP/{port} пока закрыт на {host}, попытка {attempt}/{retries}", flush=True)
        if attempt < retries:
            time.sleep(5)
    return False


def create_test_server(conn, record: GoodIpRecord, config: SelectelCloudConfig):
    region = record.region
    preemptible = region in config.provision_preemptible_regions

    image = get_provision_image(conn, region, config)
    flavors = get_candidate_flavors(conn, region, config)
    network = get_provision_network(conn, region, config)
    security_group = ensure_security_group(conn, config)
    availability_zone = get_explicit_provision_availability_zone(region, config)
    user_data = base64.b64encode(make_cloud_init_script(config).encode("utf-8")).decode("ascii")

    base_attrs = {
        "image_id": image.id,
        "networks": [{"uuid": network.id}],
        "security_groups": [{"name": security_group.name}],
        "user_data": user_data,
        "metadata": {"selectel_finder_ip": record.ip},
    }

    if availability_zone:
        base_attrs["availability_zone"] = availability_zone
    if config.provision_key_name:
        base_attrs["key_name"] = config.provision_key_name
    if preemptible:
        base_attrs["tags"] = ["preemptible"]

    last_error = None

    for index, flavor in enumerate(flavors, 1):
        server = None
        server_name = (
            f"{config.provision_server_name_prefix}-{region}-{record.ip.replace('.', '-')}-"
            f"{int(time.time())}-{index}"
        )
        attrs = dict(base_attrs)
        attrs["name"] = server_name
        attrs["flavor_id"] = flavor.id

        print(
            f"🚀 Пробую сервер {server_name}: region={region}, "
            f"image={getattr(image, 'name', image.id)}, "
            f"flavor={getattr(flavor, 'name', flavor.id)}, "
            f"network={getattr(network, 'name', network.id)}, "
            f"preemptible={preemptible}, "
            f"availability_zone={availability_zone or 'auto'}, "
            f"attempt={index}/{len(flavors)}",
            flush=True,
        )

        try:
            server = conn.compute.create_server(**attrs)
            server = conn.compute.wait_for_server(server, wait=config.provision_server_wait_seconds)
            attach_floating_ip_to_server(conn, server, record.ip)

            print(
                f"✅ Сервер создан: {server_name}, "
                f"flavor={getattr(flavor, 'name', flavor.id)}",
                flush=True,
            )

            setup_wait = max(0, int(config.provision_setup_wait_seconds or 0))
            if setup_wait:
                time.sleep(setup_wait)

            return server

        except Exception as e:
            last_error = e
            flavor_name = getattr(flavor, "name", flavor.id)
            print(f"⚠️ Flavor не подошёл {flavor_name}: {e}", flush=True)

            if server:
                try:
                    cleanup_test_server(conn, getattr(server, "id", ""), record.ip)
                except Exception as cleanup_error:
                    print(f"⚠️ Cleanup после неудачной попытки не удался: {cleanup_error}", flush=True)

            continue

    raise RuntimeError(
        f"Не удалось создать сервер в {region} после {len(flavors)} попыток. "
        f"Последняя ошибка: {last_error}"
    )


def cleanup_test_server(conn, server_id: str, ip: str):
    if not server_id:
        return

    try:
        server = conn.compute.find_server(server_id, ignore_missing=True)
        if not server:
            return
        try:
            detach_floating_ip_from_server(conn, ip)
        except Exception as e:
            print(f"⚠️ Не удалось отвязать floating IP {ip}: {e}", flush=True)
        conn.compute.delete_server(server, ignore_missing=True)
        try:
            conn.compute.wait_for_delete(server, wait=120)
        except Exception as e:
            print(f"⚠️ Не дождался удаления сервера {server_id}: {e}", flush=True)
    except Exception as e:
        print(f"⚠️ Ошибка удаления временного сервера {server_id}: {e}", flush=True)
