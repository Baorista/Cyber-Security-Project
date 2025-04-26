import matplotlib.pyplot as plt
import json
from collections import Counter

REPORT_PATH = '/opt/honeypot/http_honeypot/logs/report.json'

def load_report(path = REPORT_PATH):
	with open(path, 'r') as f:
		return json.load(f)
def plot_attack_types(attacks):
	attack_counts = {k: len(v) for k,v in attacks.items()}

	plt.figure(figsize=(10,6))
	bars = plt.bar(attack_counts.keys(), attack_counts.values(),color = 'skyblue')
	plt.title('Number of Attacks by Type')
	plt.ylabel('Number of Events')
	plt.xticks(rotation = 45)
	plt.tight_layout()
	for bar in bars:
		height = bar.get_height()
		plt.text(bar.get_x() + bar.get_width()/2, height, str(height), ha='center', va='bottom')
	plt.savefig('/opt/honeypot/http_honeypot/logs/attack_types.png')
	plt.close()
def plot_top_ips(attacks):
	ip_counter = Counter()

	for attack_list in attacks.values():
		for log in attack_list:
			ip_counter[log['ip']]+=1
	most_common_ips = ip_counter.most_common(10)

	if not most_common_ips:
		print("No IP data available.")
		return 
	ips, counts = zip(*most_common_ips)

	plt.figure(figsize=(10,6))
	bars = plt.bar(ips,counts,color='salmon')
	plt.title('Top 10 IP Addresses by Number of Attacks')
	plt.ylabel('Number of Events')
	plt.xticks(rotation=45)
	plt.tight_layout()
	for bar in bars:
		height = bar.get_height()
		plt.text(bar.get_x() + bar.get_width()/2, height, str(height), ha='center', va='bottom')
	plt.savefig('/opt/honeypot/http_honeypot/logs/top_ips.png')
	plt.close()
def plot_top_forwared_ip(attacks):
	fi_counter = Counter()

	for attack_list in attacks.values():
		for log in attack_list:
			fi_counter[log['forwarded_for']]+=1
		most_common_fi = fi_counter.most_common(10)

		if not most_common_fi:
			print("NO Fowared IP data available.")
			return
	fi, counts = zip(*most_common_fi)

	plt.figure(figsize=(10,6))
	bars = plt.bar(fi,counts, color='violet')
	plt.title('Top 10 Forwared IP by Number of Attacks')
	plt.ylabel('Number of Events')
	plt.xticks(rotation=45)
	plt.tight_layout()
	for bar in bars:
		height = bar.get_height()
		plt.text(bar.get_x()+bar.get_width()/2, height, str(height), ha='center', va='bottom')
	plt.savefig('/opt/honeypot/http_honeypot/logs/top_fi.png')
	plt.close()
def plot_top_endpoints(attacks):
	endpoint_counter = Counter()
	for attack_list in attacks.values():
		for log in attack_list:
			endpoint_counter[log['endpoint']] +=1
	most_common_endpoints = endpoint_counter.most_common(10)
	if not most_common_endpoints:
		print("No Endpoint data available.")
		return
	endpoints,counts = zip(*most_common_endpoints)
	plt.figure(figsize=(10,6))
	bars = plt.bar(endpoints, counts, color='lightgreen')
	plt.title('Top 10 Endpoints Accessed')
	plt.ylabel('Number of Accesses')
	plt.xticks(rotation=45)
	plt.tight_layout()
	for bar in bars:
		height = bar.get_height()
		plt.text(bar.get_x() + bar.get_width()/2, height, str(height), ha='center', va='bottom')
	plt.savefig('/opt/honeypot/http_honeypot/logs/top_endpoints.png')
	plt.close()
if __name__ == "__main__":
    report = load_report()
    attacks = report['attacks']
    plot_top_forwared_ip(attacks)
    plot_attack_types(attacks)
    plot_top_ips(attacks)
    plot_top_endpoints(attacks)