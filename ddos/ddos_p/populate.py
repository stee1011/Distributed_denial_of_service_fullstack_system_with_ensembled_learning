import os
import django
import random
import uuid
from django.utils import timezone
from faker import Faker

# ✅ Initialize Django (BEFORE importing models)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ddos_p.settings")  # Change to your project name
django.setup()

# ✅ Now import models AFTER Django setup
from ddos_a.models import DatasetInfo, AttackType, NetworkFlow

# Initialize Faker
fake = Faker()

# Create DatasetInfo
dataset = DatasetInfo.objects.create(
    name="DDoS Dataset Sample",
    source="Generated",
    description="A sample dataset for testing.",
)

# Create Attack Types
attack_types = [
    {"name": "SYN Flood", "description": "SYN flood attack", "severity_level": 3},
    {"name": "UDP Flood", "description": "UDP flood attack", "severity_level": 2},
    {"name": "ICMP Flood", "description": "ICMP flood attack", "severity_level": 2},
    {"name": "HTTP Flood", "description": "HTTP request flood attack", "severity_level": 4},
]
attack_type_objects = [AttackType.objects.create(**attack) for attack in attack_types]

# Generate 50 network flows
flows = []
for _ in range(1000):
    src_ip = fake.ipv4()
    dst_ip = fake.ipv4()
    flow = NetworkFlow(
        flow_id=uuid.uuid4(),
        timestamp=timezone.now(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=random.randint(1024, 65535),
        dst_port=random.randint(80, 443),
        protocol=random.choice(["TCP", "UDP", "ICMP"]),
        duration=round(random.uniform(0.1, 10.0), 2),
        bytes_sent=random.randint(100, 50000),
        bytes_received=random.randint(100, 50000),
        packets_sent=random.randint(1, 1000),
        packets_received=random.randint(1, 1000),
        packet_size_min=round(random.uniform(40.0, 1500.0), 2),
        packet_size_max=round(random.uniform(40.0, 1500.0), 2),
        packet_size_mean=round(random.uniform(40.0, 1500.0), 2),
        packet_size_std=round(random.uniform(0.5, 50.0), 2),
        iat_min=round(random.uniform(0.001, 0.5), 6),
        iat_max=round(random.uniform(0.5, 5.0), 6),
        iat_mean=round(random.uniform(0.1, 2.0), 6),
        iat_std=round(random.uniform(0.01, 1.0), 6),
        tcp_flags=random.choice(["SYN", "ACK", "FIN", "PSH", None]),
        flow_iat_min=round(random.uniform(0.001, 0.5), 6),
        flow_iat_max=round(random.uniform(0.5, 5.0), 6),
        flow_iat_mean=round(random.uniform(0.1, 2.0), 6),
        flow_iat_std=round(random.uniform(0.01, 1.0), 6),
        is_fwd=random.choice([True, False]),
        fwd_packets=random.randint(1, 500),
        bwd_packets=random.randint(1, 500),
        fwd_bytes=random.randint(100, 50000),
        bwd_bytes=random.randint(100, 50000),
        dataset=dataset
    )
    flows.append(flow)

# Bulk insert for efficiency
NetworkFlow.objects.bulk_create(flows)

print("Successfully inserted 50 sample network flow records.")
