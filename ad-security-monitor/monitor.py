import time
import os
import win32evtlog
from colorama import Fore, Style, init
from collections import defaultdict
from datetime import datetime, timedelta

init()

SERVER = "localhost"
LOG_TYPE = "Security"
LOG_FILE = "logs/alerts.log"

WINDOW_SECONDS = 60
FAILED_LOGON_THRESHOLD = 5
MASS_MODIFICATION_THRESHOLD = 3
LOCKOUT_THRESHOLD = 3

failed_logons = defaultdict(list)
user_modifications = defaultdict(list)
lockouts = []

PRIVILEGED_GROUPS = [
    "Domain Admins",
    "Administrators",
    "Enterprise Admins",
    "Schema Admins",
    "GG_RH_ADMINS",
    "GG_TI_Admins",
    "GG_Backup_Operators",
]

MONITORED_EVENTS = {
    4625: {"name": "Falha de logon", "severity": "HIGH", "color": Fore.YELLOW},
    4720: {"name": "Usuário criado", "severity": "HIGH", "color": Fore.YELLOW},
    4728: {"name": "Usuário adicionado a grupo", "severity": "CRITICAL", "color": Fore.RED},
    4738: {"name": "Usuário alterado", "severity": "MEDIUM", "color": Fore.CYAN},
    4740: {"name": "Conta bloqueada", "severity": "CRITICAL", "color": Fore.RED},
}


def save_alert(message):
    os.makedirs("logs", exist_ok=True)

    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(message + "\n")


def get_value(strings, index):
    try:
        value = strings[index]
        return value if value else "-"
    except IndexError:
        return "-"


def raise_behavior_alert(title, details):
    alert = (
        "\n========== POSSÍVEL ATAQUE ==========\n"
        f"[CRITICAL] {title}\n"
        f"{details}\n"
        "=====================================\n"
    )

    print(Fore.RED + alert + Style.RESET_ALL)
    save_alert(alert)


def detect_lockout_wave():
    now = datetime.now()
    lockouts.append(now)

    recent = [
        t for t in lockouts
        if now - t <= timedelta(seconds=120)
    ]

    if len(recent) >= LOCKOUT_THRESHOLD:
        raise_behavior_alert(
            "Possível password spraying",
            f"Bloqueios recentes: {len(recent)}\nJanela: 120s"
        )


def detect_mass_user_modification(actor):
    now = datetime.now()

    user_modifications[actor].append(now)

    user_modifications[actor] = [
        t for t in user_modifications[actor]
        if now - t <= timedelta(seconds=60)
    ]

    if len(user_modifications[actor]) >= MASS_MODIFICATION_THRESHOLD:
        raise_behavior_alert(
            "Possível alteração em massa de usuários",
            f"Operador: {actor}\nAlterações: {len(user_modifications[actor])}\nJanela: 60s"
        )


def detect_failed_logon_burst(event):
    if event.EventID != 4625:
        return

    strings = event.StringInserts or []

    account = get_value(strings, 5)
    source_ip = get_value(strings, 19)
    key = f"{account}:{source_ip}"

    now = datetime.now()

    failed_logons[key].append(now)

    failed_logons[key] = [
        t for t in failed_logons[key]
        if now - t <= timedelta(seconds=WINDOW_SECONDS)
    ]

    if len(failed_logons[key]) >= FAILED_LOGON_THRESHOLD:
        raise_behavior_alert(
            "Muitas falhas de logon em curto período",
            f"Conta: {account}\nIP origem: {source_ip}\nTentativas: {len(failed_logons[key])}\nJanela: {WINDOW_SECONDS}s"
        )


def detect_privilege_escalation(group, actor):
    normalized_group = group.lower()

    for privileged_group in PRIVILEGED_GROUPS:
        if privileged_group.lower() == normalized_group:
            raise_behavior_alert(
                "Possível escalada de privilégio",
                f"Grupo privilegiado: {group}\nExecutado por: {actor}"
            )


def parse_event(event):
    event_id = event.EventID
    strings = event.StringInserts or []

    if event_id == 4738:
        target_user = get_value(strings, 1)
        target_domain = get_value(strings, 2)
        actor_user = get_value(strings, 5)
        actor_domain = get_value(strings, 6)

        detect_mass_user_modification(actor_user)

        return (
            f"Alvo: {target_domain}\\{target_user}\n"
            f"Alterado por: {actor_domain}\\{actor_user}"
        )

    if event_id == 4740:
        target_user = get_value(strings, 0)
        caller_computer = get_value(strings, 1)

        detect_lockout_wave()

        return (
            f"Conta bloqueada: {target_user}\n"
            f"Origem: {caller_computer}"
        )

    if event_id == 4720:
        target_user = get_value(strings, 0)
        actor_user = get_value(strings, 4)

        return (
            f"Usuário criado: {target_user}\n"
            f"Criado por: {actor_user}"
        )

    if event_id == 4728:
        member = get_value(strings, 0)
        group = get_value(strings, 2)
        actor = get_value(strings, 6)

        detect_privilege_escalation(group, actor)

        return (
            f"Usuário adicionado: {member}\n"
            f"Grupo: {group}\n"
            f"Executado por: {actor}"
        )

    if event_id == 4625:
        account = get_value(strings, 5)
        workstation = get_value(strings, 13)
        source_ip = get_value(strings, 19)

        return (
            f"Conta: {account}\n"
            f"Workstation: {workstation}\n"
            f"IP origem: {source_ip}"
        )

    return "Evento monitorado detectado."


def print_alert(event):
    event_id = event.EventID
    info = MONITORED_EVENTS[event_id]

    details = parse_event(event)

    alert = (
        "\n========== AD SECURITY ALERT ==========\n"
        f"Severidade: {info['severity']}\n"
        f"Evento: {info['name']}\n"
        f"Event ID: {event_id}\n"
        f"Horário: {event.TimeGenerated}\n"
        f"{details}\n"
        "=======================================\n"
    )

    print(info["color"] + alert + Style.RESET_ALL)
    save_alert(alert)
    detect_failed_logon_burst(event)


def main():
    print("[+] AD Security Monitor iniciado")
    print("[+] Monitorando eventos: 4625, 4720, 4728, 4738, 4740")

    last_record = 0

    while True:
        handle = win32evtlog.OpenEventLog(SERVER, LOG_TYPE)

        flags = (
            win32evtlog.EVENTLOG_BACKWARDS_READ
            | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        )

        events = win32evtlog.ReadEventLog(handle, flags, 0)

        new_events = []

        for event in events:
            if event.EventID in MONITORED_EVENTS and event.RecordNumber > last_record:
                new_events.append(event)

        new_events.sort(key=lambda e: e.RecordNumber)

        for event in new_events:
            print_alert(event)

        if new_events:
            last_record = max(e.RecordNumber for e in new_events)

        time.sleep(5)


if __name__ == "__main__":
    main()