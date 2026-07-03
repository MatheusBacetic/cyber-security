import json
import os
import re
import time
from datetime import datetime, timezone

SOURCE_LOG = os.path.join("logs", "alerts.log")
OUTPUT_LOG = os.path.join("logs", "wazuh-ad-monitor.jsonl")

EVENT_MAP = {
    "Usuário criado": "account_created",
    "Usuário adicionado a grupo": "group_member_added",
    "Usuário alterado": "account_modified",
    "Conta bloqueada": "account_locked",
}


def field(block, label):
    match = re.search(
        rf"^{re.escape(label)}:\s*(.+)$",
        block,
        re.MULTILINE,
    )
    return match.group(1).strip() if match else "-"


def first_available_field(block, labels):
    for label in labels:
        value = field(block, label)
        if value != "-":
            return value
    return "-"


def export_alert(block):
    event_id = field(block, "Event ID")
    event_name = field(block, "Evento")
    severity = field(block, "Severidade")
    event_time = field(block, "Horário")

    record = {
        "integration": "ad-security-monitor",
        "schema_version": "1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "monitor_event_time": event_time,
        "event_id": int(event_id) if event_id.isdigit() else None,
        "event_name": event_name,
        "event_type": EVENT_MAP.get(event_name, "ad_security_alert"),
        "severity": severity,
        "target_user": first_available_field(
            block,
            ["Usuário criado", "Alvo"],
        ),
        "group": field(block, "Grupo"),
        "actor": first_available_field(
            block,
            ["Criado por", "Alterado por"],
        ),
        "raw_alert": block.strip(),
    }

    with open(OUTPUT_LOG, "a", encoding="utf-8") as output:
        output.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(
        f"[+] Exportado: Event ID {record['event_id']} "
        f"({record['event_name']})"
    )


def main():
    os.makedirs("logs", exist_ok=True)

    if not os.path.exists(SOURCE_LOG):
        print(f"[!] Arquivo de origem não encontrado: {SOURCE_LOG}")
        return

    with open(SOURCE_LOG, "r", encoding="utf-8", errors="replace") as source:
        source.seek(0, os.SEEK_END)
        position = source.tell()

    print("[+] Wazuh exporter iniciado")
    print(f"[+] Aguardando novos alertas em: {SOURCE_LOG}")

    while True:
        with open(SOURCE_LOG, "r", encoding="utf-8", errors="replace") as source:
            source.seek(position)
            content = source.read()
            position = source.tell()

        blocks = re.findall(
            r"========== AD SECURITY ALERT ==========(.*?)=======================================",
            content,
            re.DOTALL,
        )

        for body in blocks:
            export_alert("========== AD SECURITY ALERT ==========" + body)

        time.sleep(1)


if __name__ == "__main__":
    main()