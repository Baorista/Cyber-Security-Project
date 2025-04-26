import classify_attack
import stat_ioc
import parse_logs

logs = parse_logs.parse_log_file('/opt/honeypot/http_honeypot/logs/access.log')
classi = classify_attack.classify_attacks(logs)
statc = stat_ioc.extract_stat_from_logs(logs)
stat_ioc.save_report_to_json(statc,classi)