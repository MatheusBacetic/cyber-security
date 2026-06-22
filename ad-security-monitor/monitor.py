import os
import re
import subprocess
import queue
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

import win32evtlog
from colorama import Fore, Style, init

init()

SERVER = "localhost"
LOG_TYPE = "Security"
LOG_FILE = "logs/alerts.log"

WINDOW_SECONDS = 60
FAILED_LOGON_THRESHOLD = 5
MASS_MODIFICATION_THRESHOLD = 3
LOCKOUT_THRESHOLD = 3

KERBEROAST_THRESHOLD = 5
KERBEROAST_WINDOW = 60

LDAP_ENUM_THRESHOLD = 1
LDAP_ENUM_WINDOW = 60

LDAP_QUERY_THRESHOLD = 10
LDAP_QUERY_WINDOW = 60
LOGON_SESSION_TTL = 8 * 60 * 60
SUSPICIOUS_ACTIVITY_WINDOW = 120
SUSPICIOUS_ACTIVITY_MIN_SIGNALS = 3
SUSPICIOUS_ACTIVITY_ALERT_COOLDOWN = 300

RISK_SCORE_THRESHOLD = 100
RISK_SCORE_WINDOW = 300
RISK_EVENT_SCORES = {
    4625: 10,
    4740: 25,
    4738: 30,
    4662: 15,
    4728: 100,
}

AUTO_RESPONSE_ENABLED = True
DRY_RUN = True

failed_logons = defaultdict(list)
user_modifications = defaultdict(list)
lockouts = []
ldap_enum_tracker = defaultdict(list)
ldap_queries = defaultdict(list)
kerberos_tickets = defaultdict(list)
logon_sessions = {}
suspicious_activity = defaultdict(list)
suspicious_activity_last_alert = {}
risk_score_events = defaultdict(list)
risk_incidents_active = set()

SERVICE_ACCOUNTS = {
    "svc_web",
    "svc_backup",
    "svc_monitor",
}

# Enderecos que representam o proprio controlador de dominio. Outros enderecos
# podem ser informados separados por virgula em AD_MONITOR_DC_ADDRESSES.
DC_CLIENT_ADDRESSES = {
    "-",
    "::1",
    "127.0.0.1",
    "10.0.0.10",
    *(
        address.strip()
        for address in os.getenv("AD_MONITOR_DC_ADDRESSES", "").split(",")
        if address.strip()
    ),
}

DEBUG = os.getenv("AD_MONITOR_DEBUG", "0").lower() not in {"0", "false", "no"}
BACKFILL_EVENTS = max(0, int(os.getenv("AD_MONITOR_BACKFILL_EVENTS", "0")))
SUBSCRIPTION_QUERY = "*[System[(EventID=4624 or EventID=4625 or EventID=4662 or EventID=4720 or EventID=4728 or EventID=4738 or EventID=4740 or EventID=4768 or EventID=4769 or EventID=4798 or EventID=4799 or EventID=5140 or EventID=5145)]]"


@dataclass
class EventRecord:
    EventID: int
    RecordNumber: int
    TimeGenerated: str
    StringInserts: list = field(default_factory=list)
    Data: dict = field(default_factory=dict)

PRIVILEGED_GROUPS = [
    "Domain Admins",
    "Administrators",
    "Enterprise Admins",
    "Schema Admins",
    "GG_RH_ADMINS",
    "GG_TI_Admins",
    "GG_Backup_Operators",
]

PROTECTED_ACCOUNTS = [
    "Administrator",
    "cyber.admin",
    "svc_web",
    "svc_backup",
    "svc_monitor",
]

MONITORED_EVENTS = {
    4624: {"name": "Logon bem-sucedido", "severity": "LOW", "color": Fore.GREEN},
    4625: {"name": "Falha de logon", "severity": "HIGH", "color": Fore.YELLOW},
    4662: {"name": "Directory Service Access", "severity": "HIGH", "color": Fore.YELLOW},
    4720: {"name": "Usuário criado", "severity": "HIGH", "color": Fore.YELLOW},
    4728: {"name": "Usuário adicionado a grupo", "severity": "CRITICAL", "color": Fore.RED},
    4738: {"name": "Usuário alterado", "severity": "MEDIUM", "color": Fore.CYAN},
    4740: {"name": "Conta bloqueada", "severity": "CRITICAL", "color": Fore.RED},
    4768: {"name": "Kerberos TGT Request", "severity": "LOW", "color": Fore.GREEN},
    4769: {"name": "Kerberos Service Ticket Request", "severity": "MEDIUM", "color": Fore.CYAN},
    4798: {"name": "Enumeracao de grupos locais", "severity": "HIGH", "color": Fore.YELLOW},
    4799: {"name": "Enumeracao de grupo local", "severity": "HIGH", "color": Fore.YELLOW},
    5140: {"name": "Acesso a compartilhamento de rede", "severity": "MEDIUM", "color": Fore.CYAN},
    5145: {"name": "Verificacao detalhada de compartilhamento", "severity": "HIGH", "color": Fore.YELLOW},
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


def normalize_ad_identity(value):
    if not value or value == "-":
        return "-"

    match = re.search(r"CN=([^,]+)", value)
    if match:
        return match.group(1)

    return value


def resolve_sam_account_name(identity):
    identity = normalize_ad_identity(identity)

    if identity == "-":
        return "-"

    try:
        cmd = [
            "powershell",
            "-Command",
            (
                "Import-Module ActiveDirectory;"
                "$u = Get-ADUser -LDAPFilter \"(cn={0})\";"
                "if ($u) { $u.SamAccountName }"
            ).format(identity)
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )

        sam = result.stdout.strip()

        if sam:
            return sam

        return identity

    except Exception as e:
        print(f"[ERROR] Falha ao resolver SamAccountName: {e}")
        return identity


def raise_behavior_alert(title, details):
    alert = (
        "\n========== POSSÍVEL ATAQUE ==========\n"
        f"[CRITICAL] {title}\n"
        f"{details}\n"
        "=====================================\n"
    )

    print(Fore.RED + alert + Style.RESET_ALL, flush=True)
    save_alert(alert)


def get_risk_account(event):
    strings = event.StringInserts or []
    data = getattr(event, "Data", {})
    fallbacks = {
        4625: 5,
        4662: 1,
        4728: 6,
        4738: 5,
        4740: 0,
    }

    if event.EventID in {4625, 4740}:
        field_name = "TargetUserName"
    else:
        field_name = "SubjectUserName"

    return data.get(field_name, get_value(strings, fallbacks[event.EventID]))


def raise_risk_incident(account, score):
    incident = (
        "\n========== INCIDENT ==========\n"
        f"Usuário: {account}\n"
        f"Risk Score: {score}\n"
        "Status: CRITICAL\n"
        "==============================\n"
    )
    print(Fore.RED + Style.BRIGHT + incident + Style.RESET_ALL, flush=True)
    save_alert(incident)


def update_risk_score(event):
    points = RISK_EVENT_SCORES.get(event.EventID)
    if points is None:
        return

    account = get_risk_account(event)
    if not account or account == "-":
        return

    normalized_account = account.lower()
    ignored_accounts = {
        "system",
        "local service",
        "network service",
        "anonymous logon",
    }
    if account.endswith("$") or normalized_account in ignored_accounts:
        return

    now = get_event_time(event)
    risk_score_events[normalized_account] = [
        item
        for item in risk_score_events[normalized_account]
        if timedelta(0) <= now - item[0] <= timedelta(seconds=RISK_SCORE_WINDOW)
    ]
    risk_score_events[normalized_account].append((now, points, event.EventID))
    score = sum(item[1] for item in risk_score_events[normalized_account])

    if DEBUG:
        print(
            "[DEBUG][RISK_SCORE] "
            f"account={account!r} event_id={event.EventID} "
            f"points=+{points} score={score}"
        )

    if score < RISK_SCORE_THRESHOLD:
        risk_incidents_active.discard(normalized_account)
        return

    if normalized_account not in risk_incidents_active:
        raise_risk_incident(account, score)
        risk_incidents_active.add(normalized_account)


def detect_lockout_wave():
    now = datetime.now()
    lockouts.append(now)
    lockouts[:] = [t for t in lockouts if now - t <= timedelta(seconds=120)]

    if len(lockouts) >= LOCKOUT_THRESHOLD:
        raise_behavior_alert(
            "Possivel password spraying",
            f"Bloqueios recentes: {len(lockouts)}\nJanela: 120s",
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
            "Possivel alteracao em massa de usuarios",
            (
                f"Operador: {actor}\n"
                f"Alteracoes: {len(user_modifications[actor])}\n"
                "Janela: 60s"
            ),
        )


def disable_ad_account(username):
    username = resolve_sam_account_name(username)

    if username == "-" or username in PROTECTED_ACCOUNTS:
        response = (
            "\n========== AUTO RESPONSE ==========\n"
            "[SKIPPED] Conta protegida ou inválida\n"
            f"Conta: {username}\n"
            "===================================\n"
        )
        print(Fore.MAGENTA + response + Style.RESET_ALL)
        save_alert(response)
        return

    if DRY_RUN:
        response = (
            "\n========== AUTO RESPONSE ==========\n"
            "[DRY-RUN] Conta seria desabilitada\n"
            f"Conta: {username}\n"
            "===================================\n"
        )
        print(Fore.MAGENTA + response + Style.RESET_ALL)
        save_alert(response)
        return

    cmd = [
        "powershell",
        "-Command",
        (
            "$u = Get-ADUser -Filter \"Name -eq '{0}' -or SamAccountName -eq '{0}'\";"
            "if ($u) { Disable-ADAccount -Identity $u.SamAccountName }"
        ).format(username)
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        response = (
            "\n========== AUTO RESPONSE ==========\n"
            "[ACTION] Conta desabilitada automaticamente\n"
            f"Conta: {username}\n"
            "===================================\n"
        )
    else:
        response = (
            "\n========== AUTO RESPONSE ERROR ==========\n"
            "[ERROR] Falha ao desabilitar conta\n"
            f"Conta: {username}\n"
            f"Erro: {result.stderr}\n"
            "=========================================\n"
        )

    print(Fore.MAGENTA + response + Style.RESET_ALL)
    save_alert(response)


def quarantine_ad_account(username):
    username = resolve_sam_account_name(username)

    if username == "-" or username in PROTECTED_ACCOUNTS:
        response = (
            "\n========== AUTO QUARANTINE ==========\n"
            "[SKIPPED] Conta protegida ou inválida\n"
            f"Conta: {username}\n"
            "=====================================\n"
        )
        print(Fore.MAGENTA + response + Style.RESET_ALL)
        save_alert(response)
        return

    if DRY_RUN:
        response = (
            "\n========== AUTO QUARANTINE ==========\n"
            "[DRY-RUN] Conta seria colocada em quarentena\n"
            f"Conta: {username}\n"
            "Ações: remover grupos privilegiados, mover OU, desabilitar\n"
            "=====================================\n"
        )
        print(Fore.MAGENTA + response + Style.RESET_ALL)
        save_alert(response)
        return

    cmd = [
        "powershell",
        "-Command",
        (
            "Import-Module ActiveDirectory;"
            f"$u = Get-ADUser -Identity '{username}';"
            "$privGroups = @('Domain Admins','Administrators','Enterprise Admins','Schema Admins',"
            "'GG_RH_ADMINS','GG_TI_Admins','GG_Backup_Operators');"
            "foreach ($g in $privGroups) {"
            "try { Remove-ADGroupMember -Identity $g -Members $u -Confirm:$false -ErrorAction SilentlyContinue } catch {}"
            "};"
            "Move-ADObject -Identity $u.DistinguishedName -TargetPath 'OU=Quarantine,DC=TREINO,DC=LOCAL';"
            "Disable-ADAccount -Identity $u.SamAccountName;"
        )
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        response = (
            "\n========== AUTO QUARANTINE ==========\n"
            "[ACTION] Conta isolada automaticamente\n"
            f"Conta: {username}\n"
            "=====================================\n"
        )
    else:
        response = (
            "\n========== AUTO QUARANTINE ERROR ==========\n"
            "[ERROR] Falha ao isolar conta\n"
            f"Conta: {username}\n"
            f"Erro: {result.stderr}\n"
            "===========================================\n"
        )

    print(Fore.MAGENTA + response + Style.RESET_ALL)
    save_alert(response)


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
            (
                f"Conta: {account}\n"
                f"IP origem: {source_ip}\n"
                f"Tentativas: {len(failed_logons[key])}\n"
                f"Janela: {WINDOW_SECONDS}s"
            )
        )


def detect_ldap_enumeration(event):
    if event.EventID != 4624:
        return

    strings = event.StringInserts or []

    # XML da API moderna fornece nomes estaveis; os indices ficam apenas como
    # fallback para registros legados lidos por ReadEventLog.
    data = getattr(event, "Data", {})
    account = data.get("TargetUserName", get_value(strings, 5))
    logon_type = data.get("LogonType", get_value(strings, 8))
    workstation = data.get("WorkstationName", get_value(strings, 11))
    source_ip = data.get("IpAddress", get_value(strings, 18))

    if DEBUG:
        print(
            "[DEBUG][4624][PIPELINE] "
            f"record={event.RecordNumber} account={account!r} "
            f"logon_type={logon_type!r} workstation={workstation!r} "
            f"source_ip={source_ip!r}"
        )

    if logon_type != "3":
        return

    if account.endswith("$"):
        return

    if source_ip in ["::1", "127.0.0.1", "10.0.0.10", "-"]:
        return

    if source_ip.startswith("fe80:"):
        return

    key = f"{account}:{source_ip}"
    now = datetime.now()

    ldap_enum_tracker[key].append(now)

    ldap_enum_tracker[key] = [
        t for t in ldap_enum_tracker[key]
        if now - t <= timedelta(seconds=LDAP_ENUM_WINDOW)
    ]

    if len(ldap_enum_tracker[key]) >= LDAP_ENUM_THRESHOLD:
        raise_behavior_alert(
            "Possível enumeração LDAP / reconhecimento de AD",
            (
                f"Conta: {account}\n"
                f"Workstation: {workstation}\n"
                f"IP origem: {source_ip}\n"
                f"Logons tipo 3: {len(ldap_enum_tracker[key])}\n"
                f"Janela: {LDAP_ENUM_WINDOW}s"
            )
        )


def detect_directory_enumeration(event):
    if event.EventID != 4662:
        return

    strings = event.StringInserts or []

    actor = get_value(strings, 1)
    domain = get_value(strings, 2)

    if actor.endswith("$"):
        return

    key = f"{domain}\\{actor}"
    now = datetime.now()

    ldap_queries[key].append(now)

    ldap_queries[key] = [
        t for t in ldap_queries[key]
        if now - t <= timedelta(seconds=LDAP_QUERY_WINDOW)
    ]

    if len(ldap_queries[key]) >= LDAP_QUERY_THRESHOLD:
        raise_behavior_alert(
            "Possível enumeração LDAP / atividade suspeita no AD",
            (
                f"Usuário: {key}\n"
                f"Eventos 4662: {len(ldap_queries[key])}\n"
                f"Janela: {LDAP_QUERY_WINDOW}s"
            )
        )


def normalize_client_address(address):
    """Normaliza o endereco registrado pelo Kerberos (inclusive IPv4-mapped IPv6)."""
    if not address:
        return "-"

    address = address.strip()
    if address.lower().startswith("::ffff:"):
        return address[7:]
    return address


def format_kerberos_encryption_type(value):
    encryption_types = {
        "0x1": "DES-CBC-CRC (0x1)",
        "0x3": "DES-CBC-MD5 (0x3)",
        "0x11": "AES128-CTS-HMAC-SHA1-96 (0x11)",
        "0x12": "AES256-CTS-HMAC-SHA1-96 (0x12)",
        "0x17": "RC4-HMAC (0x17)",
        "0x18": "RC4-HMAC-EXP (0x18)",
    }
    return encryption_types.get(value.lower(), value)


def get_event_time(event):
    """Retorna o horario do evento para que o backfill preserve a janela real."""
    try:
        value = event.TimeGenerated.replace("Z", "+00:00")
        return datetime.fromisoformat(value).replace(tzinfo=None)
    except (AttributeError, TypeError, ValueError):
        return datetime.now()


def track_network_logon(event):
    """Correlaciona o Logon ID de uma sessao de rede com seu IP de origem."""
    if event.EventID != 4624:
        return

    strings = event.StringInserts or []
    data = getattr(event, "Data", {})
    account = data.get("TargetUserName", get_value(strings, 5))
    logon_id = data.get("TargetLogonId", get_value(strings, 7)).lower()
    logon_type = data.get("LogonType", get_value(strings, 8))
    workstation = data.get("WorkstationName", get_value(strings, 11))
    source_ip = normalize_client_address(
        data.get("IpAddress", get_value(strings, 18))
    )

    if logon_type != "3" or account.endswith("$"):
        return
    if logon_id in {"", "-", "0x0"}:
        return
    if source_ip.lower() in {address.lower() for address in DC_CLIENT_ADDRESSES}:
        return
    if source_ip.lower().startswith("fe80:"):
        return

    now = get_event_time(event)
    logon_sessions[logon_id] = {
        "account": account,
        "ip": source_ip,
        "workstation": workstation,
        "time": now,
    }

    expired = [
        session_id
        for session_id, session in logon_sessions.items()
        if now - session["time"] > timedelta(seconds=LOGON_SESSION_TTL)
    ]
    for session_id in expired:
        logon_sessions.pop(session_id, None)

    if DEBUG:
        print(
            "[DEBUG][4624][SESSION] "
            f"logon_id={logon_id!r} account={account!r} "
            f"source_ip={source_ip!r}"
        )


def raise_suspicious_activity_alert(account, source_ip, events, signals):
    event_ids = sorted({event_id for _, _, event_id, _ in events})
    evidence = list(dict.fromkeys(detail for _, _, _, detail in events))[-10:]
    alert = (
        "\n############################################################\n"
        "#              ATIVIDADE SUSPEITA DETECTADA               #\n"
        "############################################################\n"
        "[CRITICAL] Possivel enumeracao ou reconhecimento do Active Directory\n"
        f"Conta: {account}\n"
        f"IP origem: {source_ip}\n"
        f"Sinais correlacionados: {', '.join(sorted(signals))}\n"
        f"Event IDs: {', '.join(str(event_id) for event_id in event_ids)}\n"
        f"Eventos na janela: {len(events)}\n"
        f"Janela: {SUSPICIOUS_ACTIVITY_WINDOW}s\n\n"
        "Evidencias:\n"
        + "\n".join(f"- {item}" for item in evidence)
        + "\n############################################################\n"
    )
    print(Fore.RED + Style.BRIGHT + alert + Style.RESET_ALL, flush=True)
    save_alert(alert)


def record_suspicious_activity_signal(account, source_ip, signal, event, detail):
    if not account or account == "-" or account.endswith("$"):
        return
    source_ip = normalize_client_address(source_ip)
    if source_ip.lower() in {address.lower() for address in DC_CLIENT_ADDRESSES}:
        return

    now = get_event_time(event)
    normalized_account = account.split("\\")[-1].lower()
    key = f"{normalized_account}:{source_ip.lower()}"
    suspicious_activity[key].append((now, signal, event.EventID, detail))
    suspicious_activity[key] = [
        item
        for item in suspicious_activity[key]
        if timedelta(0) <= now - item[0] <= timedelta(seconds=SUSPICIOUS_ACTIVITY_WINDOW)
    ]

    events = suspicious_activity[key]
    signals = {item[1] for item in events}
    ldap_count = sum(1 for item in events if item[1] == "LDAP")
    combined_detection = "LDAP" in signals and len(signals) >= SUSPICIOUS_ACTIVITY_MIN_SIGNALS
    volume_detection = ldap_count >= LDAP_QUERY_THRESHOLD
    last_alert = suspicious_activity_last_alert.get(key)
    cooldown_complete = (
        last_alert is None
        or now - last_alert >= timedelta(seconds=SUSPICIOUS_ACTIVITY_ALERT_COOLDOWN)
    )

    if DEBUG:
        print(
            "[DEBUG][SUSPICIOUS_ACTIVITY][CORRELATION] "
            f"account={account!r} ip={source_ip!r} signals={sorted(signals)!r} "
            f"events={len(events)} ldap_events={ldap_count}"
        )

    if cooldown_complete and (combined_detection or volume_detection):
        raise_suspicious_activity_alert(account, source_ip, events, signals)
        suspicious_activity_last_alert[key] = now


def detect_suspicious_activity_events(event):
    if event.EventID not in {4768, 4769, 4798, 4799, 5140, 5145}:
        return

    strings = event.StringInserts or []
    data = getattr(event, "Data", {})

    if event.EventID == 4768:
        account = data.get("TargetUserName", get_value(strings, 0))
        source_ip = data.get("IpAddress", get_value(strings, 9))
        record_suspicious_activity_signal(account, source_ip, "KERBEROS_TGT", event, "4768: solicitacao de TGT")
        return

    if event.EventID == 4769:
        account, service, _, source_ip = get_kerberos_event_fields(event)
        record_suspicious_activity_signal(account, source_ip, "KERBEROS_TGS", event, f"4769: TGS para {service}")
        return

    account = data.get("SubjectUserName", get_value(strings, 1))
    logon_id = data.get("SubjectLogonId", get_value(strings, 3)).lower()
    session = logon_sessions.get(logon_id)
    source_ip = data.get("IpAddress", session["ip"] if session else "-")

    if event.EventID in {5140, 5145}:
        share = data.get("ShareName", "-")
        relative_target = data.get("RelativeTargetName", "-")
        record_suspicious_activity_signal(
            account, source_ip, "SMB", event,
            f"{event.EventID}: {share} / {relative_target}",
        )
    else:
        target = data.get("TargetUserName", "-")
        record_suspicious_activity_signal(
            account, source_ip, "GROUP_ENUM", event,
            f"{event.EventID}: enumeracao relacionada a {target}",
        )


def detect_correlated_directory_enumeration(event):
    """Associa o 4662 ao IP do 4624 por meio do Logon ID."""
    if event.EventID != 4662:
        return

    strings = event.StringInserts or []
    data = getattr(event, "Data", {})
    actor = data.get("SubjectUserName", get_value(strings, 1))
    domain = data.get("SubjectDomainName", get_value(strings, 2))
    logon_id = data.get("SubjectLogonId", get_value(strings, 3)).lower()

    if actor.endswith("$"):
        return

    session = logon_sessions.get(logon_id)
    if session is None:
        if DEBUG:
            print(
                "[DEBUG][4662][NO_SESSION] "
                f"record={event.RecordNumber} account={domain}\\{actor} "
                f"logon_id={logon_id!r}"
            )
        return

    source_ip = session["ip"]
    account = f"{domain}\\{actor}"
    key = f"{account}:{source_ip}"
    now = get_event_time(event)

    ldap_queries[key].append(now)
    ldap_queries[key] = [
        timestamp
        for timestamp in ldap_queries[key]
        if timedelta(0) <= now - timestamp <= timedelta(seconds=LDAP_QUERY_WINDOW)
    ]
    event_count = len(ldap_queries[key])

    if DEBUG:
        print(
            "[DEBUG][4662][CORRELATED] "
            f"logon_id={logon_id!r} account={account!r} "
            f"source_ip={source_ip!r} events={event_count}"
        )

    record_suspicious_activity_signal(
        account,
        source_ip,
        "LDAP",
        event,
        f"4662: acesso a objeto do diretorio ({event_count} na janela)",
    )


def get_kerberos_event_fields(event):
    """Extrai os campos estaveis do XML do evento 4769, com fallback legado."""
    strings = event.StringInserts or []
    data = getattr(event, "Data", {})

    account = data.get("TargetUserName", get_value(strings, 0))
    service = data.get("ServiceName", get_value(strings, 2))
    encryption_type = data.get("TicketEncryptionType", get_value(strings, 5))
    client_address = normalize_client_address(
        data.get("IpAddress", get_value(strings, 6))
    )

    return account, service, encryption_type, client_address


def detect_suspicious_service_account_activity(account, tickets, services):
    normalized_account = account.lower()
    ticket_count = len(tickets)

    if normalized_account not in SERVICE_ACCOUNTS:
        return

    if DEBUG:
        print(
            "[DEBUG][4769][SERVICE_ACCOUNT] "
            f"account={account!r} tickets={ticket_count} "
            f"threshold={KERBEROAST_THRESHOLD}"
        )

    if ticket_count == KERBEROAST_THRESHOLD:
        raise_behavior_alert(
            "Atividade suspeita em Service Account",
            (
                f"Conta: {account}\n"
                f"Tickets: {ticket_count}\n"
                f"Janela: {KERBEROAST_WINDOW}s\n\n"
                "Servicos:\n"
                + "\n".join(services)
            ),
        )


def detect_kerberoasting(event):
    if event.EventID != 4769:
        return

    account, service, encryption_type, client_address = get_kerberos_event_fields(event)
    normalized_account = account.lower()

    if DEBUG:
        print(
            "[DEBUG][4769][PIPELINE] "
            f"record={event.RecordNumber} account={account!r} service={service!r} "
            f"client_address={client_address!r} "
            f"encryption_type={encryption_type!r}"
        )

    if account == "-" or account.endswith("$"):
        if DEBUG:
            print(f"[DEBUG][4769][IGNORED] machine_or_invalid_account={account!r}")
        return

    if client_address.lower() in {address.lower() for address in DC_CLIENT_ADDRESSES}:
        if DEBUG:
            print(f"[DEBUG][4769][IGNORED] dc_client_address={client_address!r}")
        return

    now = get_event_time(event)
    kerberos_tickets[normalized_account].append((now, service))
    kerberos_tickets[normalized_account] = [
        ticket
        for ticket in kerberos_tickets[normalized_account]
        if now - ticket[0] <= timedelta(seconds=KERBEROAST_WINDOW)
    ]

    tickets = kerberos_tickets[normalized_account]
    ticket_count = len(tickets)
    services = list(dict.fromkeys(ticket[1] for ticket in tickets))

    if DEBUG:
        print(
            "[DEBUG][4769][TRACKER] "
            f"account={account!r} tickets={ticket_count} "
            f"window={KERBEROAST_WINDOW}s services={services!r}"
        )

    # Dispara uma vez quando o limiar e cruzado. Uma nova janela volta a
    # permitir o alerta, sem inundar o log a cada TGS subsequente.
    if ticket_count == KERBEROAST_THRESHOLD:
        raise_behavior_alert(
            "Possivel Kerberoasting",
            (
                f"Conta: {account}\n"
                f"Tickets solicitados: {ticket_count}\n"
                f"Janela: {KERBEROAST_WINDOW}s\n\n"
                "Servicos:\n"
                + "\n".join(services)
            ),
        )

    detect_suspicious_service_account_activity(account, tickets, services)


def detect_privilege_escalation(group, actor, member):
    normalized_group = normalize_ad_identity(group).lower()
    normalized_member = resolve_sam_account_name(member)

    for privileged_group in PRIVILEGED_GROUPS:
        if privileged_group.lower() == normalized_group:
            raise_behavior_alert(
                "Possível escalada de privilégio",
                (
                    f"Grupo privilegiado: {normalize_ad_identity(group)}\n"
                    f"Executado por: {actor}\n"
                    f"Usuário adicionado: {normalized_member}"
                )
            )

            if AUTO_RESPONSE_ENABLED:
                quarantine_ad_account(normalized_member)


def parse_event(event):
    event_id = event.EventID
    strings = event.StringInserts or []

    if event_id == 4624:
        data = getattr(event, "Data", {})
        account = data.get("TargetUserName", get_value(strings, 5))
        logon_type = data.get("LogonType", get_value(strings, 8))
        workstation = data.get("WorkstationName", get_value(strings, 11))
        source_ip = data.get("IpAddress", get_value(strings, 18))

        return (
            f"Conta: {account}\n"
            f"Tipo de logon: {logon_type}\n"
            f"Workstation: {workstation}\n"
            f"IP origem: {source_ip}"
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

    if event_id == 4662:
        actor = get_value(strings, 1)
        domain = get_value(strings, 2)
        object_type = get_value(strings, 5)
        object_name = get_value(strings, 6)
        access_mask = get_value(strings, 10)

        return (
            f"Usuário: {domain}\\{actor}\n"
            f"Object Type: {object_type}\n"
            f"Object Name: {object_name}\n"
            f"Access Mask: {access_mask}"
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

        detect_privilege_escalation(group, actor, member)

        return (
            f"Usuário adicionado: {resolve_sam_account_name(member)}\n"
            f"Grupo: {normalize_ad_identity(group)}\n"
            f"Executado por: {actor}"
        )

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

    if event_id == 4769:
        account, service, encryption_type, client_address = get_kerberos_event_fields(event)

        return (
            f"Conta: {account}\n"
            f"Service Name: {service}\n"
            f"Client Address: {client_address}\n"
            f"Encryption Type: {format_kerberos_encryption_type(encryption_type)}"
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

    print(info["color"] + alert + Style.RESET_ALL, flush=True)
    save_alert(alert)

    detect_failed_logon_burst(event)
    detect_ldap_enumeration(event)
    detect_correlated_directory_enumeration(event)
    detect_kerberoasting(event)
    detect_suspicious_activity_events(event)
    update_risk_score(event)


def event_from_xml(xml_text):
    """Converte XML do Windows Event Log em um objeto usado pelos detectores."""
    root = ET.fromstring(xml_text)
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    system = root.find("e:System", ns)
    event_data = root.find("e:EventData", ns)

    event_id = int(system.findtext("e:EventID", default="0", namespaces=ns))
    record_id = int(system.findtext("e:EventRecordID", default="0", namespaces=ns))
    time_node = system.find("e:TimeCreated", ns)
    generated = time_node.get("SystemTime", "-") if time_node is not None else "-"

    values = []
    named = {}
    if event_data is not None:
        for item in event_data.findall("e:Data", ns):
            value = item.text or "-"
            values.append(value)
            if item.get("Name"):
                named[item.get("Name")] = value

    return EventRecord(event_id, record_id, generated, values, named)


def render_event(event_handle):
    return event_from_xml(
        win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
    )


def close_evt_handle(handle):
    """Fecha PyEVT_HANDLE sem depender de win32evtlog.EvtClose.

    Algumas versoes do pywin32 nao exportam EvtClose; nelas o fechamento e
    fornecido pelo proprio objeto de handle (ou ocorre ao liberar o objeto).
    """
    if handle is None:
        return

    close_method = getattr(handle, "Close", None) or getattr(handle, "close", None)
    if close_method is not None:
        close_method()


def enqueue_backfill(event_queue):
    """Carrega um historico curto; a assinatura ja esta ativa, portanto nao ha gap."""
    flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
    result_set = win32evtlog.EvtQuery(LOG_TYPE, flags, SUBSCRIPTION_QUERY)
    loaded = []

    try:
        while len(loaded) < BACKFILL_EVENTS:
            handles = win32evtlog.EvtNext(result_set, min(64, BACKFILL_EVENTS - len(loaded)))
            if not handles:
                break
            for handle in handles:
                try:
                    loaded.append(render_event(handle))
                finally:
                    close_evt_handle(handle)
    finally:
        close_evt_handle(result_set)

    for event in reversed(loaded):
        event_queue.put(event)

    print(f"[+] Backfill concluido: {len(loaded)} eventos monitorados")


def get_latest_security_record_id():
    """Captura o watermark atual sem processar eventos historicos."""
    flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
    result_set = win32evtlog.EvtQuery(LOG_TYPE, flags, "*")
    try:
        handles = win32evtlog.EvtNext(result_set, 1)
        if not handles:
            return 0
        try:
            return render_event(handles[0]).RecordNumber
        finally:
            close_evt_handle(handles[0])
    finally:
        close_evt_handle(result_set)


def poll_security_events(after_record_id):
    """Le eventos posteriores ao watermark; fallback confiavel ao callback."""
    flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection
    query = f"*[System[EventRecordID > {int(after_record_id)}]]"
    result_set = win32evtlog.EvtQuery(LOG_TYPE, flags, query)
    events = []
    latest_record_id = after_record_id

    try:
        while True:
            handles = win32evtlog.EvtNext(result_set, 64)
            if not handles:
                break
            for handle in handles:
                try:
                    event = render_event(handle)
                    latest_record_id = max(latest_record_id, event.RecordNumber)
                    if event.EventID in MONITORED_EVENTS:
                        events.append(event)
                finally:
                    close_evt_handle(handle)
    finally:
        close_evt_handle(result_set)

    return events, latest_record_id


def main():
    print("[+] AD Security Monitor iniciado (Windows Event Log API moderna)")
    print("[+] Alertas visiveis: 4625, 4720, 4728, 4738, 4740, 4769")
    print("[+] Telemetria de atividade suspeita: 4624, 4662, 4768, 4798, 4799, 5140, 5145")
    print("[+] Modo ao vivo ativo: callback + polling incremental", flush=True)

    event_queue = queue.Queue()
    callback_errors = queue.Queue()

    def subscription_callback(action, context, event_handle):
        try:
            if action == win32evtlog.EvtSubscribeActionDeliver:
                event_queue.put(render_event(event_handle))
            elif action == win32evtlog.EvtSubscribeActionError:
                callback_errors.put(event_handle)
        except Exception as exc:
            callback_errors.put(exc)

    try:
        subscription = win32evtlog.EvtSubscribe(
            LOG_TYPE,
            win32evtlog.EvtSubscribeToFutureEvents,
            Query=SUBSCRIPTION_QUERY,
            Callback=subscription_callback,
        )
    except Exception as exc:
        subscription = None
        print(f"[WARNING] Callback indisponivel; usando polling: {exc}", flush=True)

    # A assinatura e criada antes do backfill. Eventos gerados durante a consulta
    # entram na fila e sao deduplicados pelo EventRecordID.
    if BACKFILL_EVENTS > 0:
        enqueue_backfill(event_queue)
    last_record_id = get_latest_security_record_id()
    print(f"[+] Watermark do Security Log: {last_record_id}", flush=True)
    seen_records = set()
    seen_order = []

    try:
        while True:
            while not callback_errors.empty():
                error = callback_errors.get()
                print(f"[WARNING] Falha no callback; polling continua ativo: {error}", flush=True)

            try:
                event = event_queue.get(timeout=1)
            except queue.Empty:
                polled_events, last_record_id = poll_security_events(last_record_id)
                for polled_event in polled_events:
                    event_queue.put(polled_event)
                continue

            last_record_id = max(last_record_id, event.RecordNumber)

            if event.RecordNumber in seen_records:
                continue

            seen_records.add(event.RecordNumber)
            seen_order.append(event.RecordNumber)
            # Deduplicacao limitada evita crescimento infinito sem criar gaps.
            deduplication_limit = max(2000, BACKFILL_EVENTS * 2)
            if len(seen_order) > deduplication_limit:
                old = seen_order.pop(0)
                seen_records.discard(old)

            if event.EventID == 4624:
                track_network_logon(event)
            elif event.EventID == 4662:
                detect_correlated_directory_enumeration(event)
                update_risk_score(event)
            elif event.EventID in {4768, 4798, 4799, 5140, 5145}:
                detect_suspicious_activity_events(event)
            elif event.EventID in MONITORED_EVENTS:
                print_alert(event)
    except KeyboardInterrupt:
        print("\n[+] Monitor encerrado")
    finally:
        close_evt_handle(subscription)


if __name__ == "__main__":
    main()
