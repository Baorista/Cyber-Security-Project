import re
from collections import Counter, defaultdict
from datetime import datetime
import pprint

LOG_PATTERN = re.compile(
	r"\[(?P<timestamp>.*?)\] IP: (?P<ip>.*?) \| Forwarded-For: (?P<forwarded_for>.*?) \| UA: (?P<ua>.*?) \| Method: (?P<method>.*?) \| Endpoint: (?P<endpoint>.*?) \| (?P<message>.*)"
)

def parse_log_file(log_path):
	logs = []
	with open(log_path, 'r') as f:
		for line in f:
			match = LOG_PATTERN.match(line.strip())
			if match:
				log_data = match.groupdict()
				log_data['datetime'] = datetime.strptime(log_data['timestamp'], '%Y-%m-%d %H:%M:%S')
				logs.append(log_data)
	return logs