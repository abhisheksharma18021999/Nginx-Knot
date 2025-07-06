import sys
import os
import json
import subprocess
import logging
import argparse


# === Logging Configuration ===
LOG_FILE = "/var/log/nginx_knot.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# === Configuration Paths ===
UPSTREAM_DIR = "/etc/nginx/upstreams"
LOCATION_DIR = "/etc/nginx/locations"

DEFAULT_PROXY_TIMEOUTS = {
    "proxy_connect_timeout": "3s",
    "proxy_send_timeout": "5s",
    "proxy_read_timeout": "20s",
}


def process_config(data):
    logging.info("[Starting to process request %s ]", data)

    ensure_dirs()
    ms_list = data["ms"]
    check_exists = data.get("check_config_already_exits", False)
    validate_flag = data.get("validate_nginx", False)
    reload_flag = data.get("reload_nginx", False)

    for service in ms_list:
        name = service["upstream_name"]
        upstream_path = os.path.join(UPSTREAM_DIR, f"{name}.conf")
        location_path = os.path.join(LOCATION_DIR, f"{name}.conf")

        if service["action"].lower() == "delete":
            delete_configs(name)
            continue

        if check_exists and os.path.exists(upstream_path):
            logging.info(f"[Update] Already exists: {upstream_path}")

        upstream_config = generate_upstream(service)
        location_config = generate_location(service)

        with open(upstream_path, "w") as f:
            f.write(upstream_config)
        logging.info(f"[Created] Upstream: {upstream_path}")

        with open(location_path, "w") as f:
            f.write(location_config)
        logging.info(f"[Created] Location: {location_path}")

    if validate_flag and not validate_nginx():
        logging.error("[Aborting]: NGINX validation failed.")
        return

    if reload_flag and not reload_nginx():
        logging.error("[Aborting]: NGINX reload failed.")

    logging.info("[ ****[NGINX-KNOT SUCCESSFULLY EXECUTED]**** ]")


def ensure_dirs():
    for path in [UPSTREAM_DIR, LOCATION_DIR]:
        os.makedirs(path, exist_ok=True)
        logging.info(f"[Ensured] config directory exists: {path}")


def generate_upstream(service):
    upstream_name = service["upstream_name"]
    upstream_ips = service["upstream_ips"].split(",")

    upstream_block = [f"upstream {upstream_name} {{", "    least_conn;"]
    for ip in upstream_ips:
        host, port = ip.strip().split(":")
        if not port.isdigit() or not (1 <= int(port) <= 65535):
            raise ValueError(f"Invalid port: {port} for IP {ip}")
        upstream_block.append(f"    server {host}:{port};")
    upstream_block.append("}")

    return "\n".join(upstream_block)


def generate_location(service):
    upstream_name = service["upstream_name"]
    location_path = service["path"]
    proxy_config = service.get("proxy_config", {})

    timeouts = {
        key: proxy_config.get(key, DEFAULT_PROXY_TIMEOUTS[key])
        for key in DEFAULT_PROXY_TIMEOUTS
    }

    return f"""
location ~* {location_path} {{
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Server $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_pass http://{upstream_name};
    proxy_set_header X-Real-IP $remote_addr;
    proxy_connect_timeout {timeouts["proxy_connect_timeout"]};
    proxy_send_timeout {timeouts["proxy_send_timeout"]};
    proxy_read_timeout {timeouts["proxy_read_timeout"]};
    error_page 502 503 504 = @fallback;
}}""".strip()


def validate_nginx():
    result = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    if result.returncode == 0:
        logging.info("[NGINX] config is valid.")
        return True
    logging.error(f"[NGINX] config is invalid:\n{result.stderr}")
    return False


def reload_nginx():
    result = subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, text=True)
    if result.returncode == 0:
        logging.info("[NGINX] reloaded successfully.")
        return True
    logging.error(f"[Failed] to reload NGINX:\n{result.stderr}")
    return False

def delete_configs(upstream_name):
    upstream_path = os.path.join(UPSTREAM_DIR, f"{upstream_name}.conf")
    location_path = os.path.join(LOCATION_DIR, f"{upstream_name}.conf")
    for path in [upstream_path, location_path]:
        if os.path.exists(path):
            os.remove(path)
            logging.info(f"[Deleted] config removed: {path}")
        else:
            logging.warning(f"[Not Found] Config not found (skip delete): {path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NGINX Configurator")
    parser.add_argument("--delete", help="Name the upstream to delete from /etc/nginx/upstreams dir", required=False)
    parser.add_argument("--file", help="Path to JSON config to add in /etc/nginx/upstreams and /etc/nginx/locations", required=False, default="fleet_route_config.json")
    args = parser.parse_args()

    try:
        logging.info("[ ****[NGINX KNOT INITIATED]**** ]")

        if args.delete:
            ensure_dirs()
            delete_configs(args.delete)
            sys.exit(0)

        with open(args.file) as f:
            data = json.load(f)
        process_config(data)

    except Exception as e:
        logging.exception(f"Unhandled exception: {e}")