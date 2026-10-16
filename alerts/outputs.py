from models import Alert


def format_alert(alert: Alert) -> str:
    return (
        f"[{alert.severity.upper()}] {alert.timestamp} "
        f"{alert.rule} desde {alert.src_ip}: {alert.description}"
    )


def console_output(alert: Alert) -> None:
    print(format_alert(alert))


def file_output(alert: Alert, path: str = "alerts.log") -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(format_alert(alert) + "\n")