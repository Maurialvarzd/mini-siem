from collectors.ssh import collect
from storage.db import connect, insert_events, fetch_events, insert_alerts
from rules.brute_force import BruteForceRule
from alerts.outputs import console_output, file_output
from alerts.email_notifier import email_output
conn = connect()

nuevos = insert_events(conn, collect("sample_logs/auth_sample.log"))
print(f"Eventos nuevos guardados: {nuevos}")

rules = [BruteForceRule(threshold=3, window_seconds=60)]
notifiers = [console_output, file_output, email_output]

events = fetch_events(conn)

detected = []
for rule in rules:
    detected.extend(rule.evaluate(events))

new_alerts = insert_alerts(conn, detected)

if not new_alerts:
    print("Sin alertas nuevas.")
for alert in new_alerts:
    for notify in notifiers:
        notify(alert)

conn.close()