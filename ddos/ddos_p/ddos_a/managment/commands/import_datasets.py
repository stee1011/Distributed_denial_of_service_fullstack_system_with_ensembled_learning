
from django.core.management.base import BaseCommand
from django.utils import timezone
from detection.models import DatasetInfo, NetworkFlow, AttackType
import pandas as pd
import ipaddress
import uuid
import os
from datetime import datetime
from tqdm import tqdm

class Command(BaseCommand):
    help = 'Import DDoS dataset from CSV file'

    def add_arguments(self, parser):
        parser.add_argument('--file', type=str, required=True, help='Path to the CSV file')
        parser.add_argument('--name', type=str, required=True, help='Dataset name')
        parser.add_argument('--source', type=str, required=True, help='Dataset source')
        parser.add_argument('--description', type=str, default='', help='Dataset description')
        parser.add_argument('--batch-size', type=int, default=1000, help='Batch size for bulk import')

    def handle(self, *args, **options):
        file_path = options['file']
        dataset_name = options['name']
        batch_size = options['batch_size']
        
        if not os.path.exists(file_path):
            self.stderr.write(self.style.ERROR(f'File {file_path} does not exist'))
            return
        
        # Create dataset info
        dataset, created = DatasetInfo.objects.get_or_create(
            name=dataset_name,
            defaults={
                'source': options['source'],
                'description': options['description'],
                'date_added': timezone.now()
            }
        )
        
        if not created:
            self.stdout.write(self.style.WARNING(f'Dataset {dataset_name} already exists. Appending data.'))
        
        # Load and process CSV file
        self.stdout.write(self.style.SUCCESS(f'Importing data from {file_path}'))
        
        # Read the CSV file in chunks to handle large datasets
        chunk_iterator = pd.read_csv(file_path, chunksize=batch_size)
        total_flows = 0
        
        for chunk in tqdm(chunk_iterator, desc="Processing data chunks"):
            flows_to_create = []
            
            for _, row in chunk.iterrows():
                # Map CSV columns to model fields
                # Note: This mapping needs to be adjusted based on your specific dataset format
                try:
                    # Handle different field names based on dataset format
                    src_ip = row.get('src_ip', row.get('source_ip', row.get('srcip', '0.0.0.0')))
                    dst_ip = row.get('dst_ip', row.get('destination_ip', row.get('dstip', '0.0.0.0')))
                    
                    # Validate IP addresses
                    try:
                        ipaddress.ip_address(src_ip)
                        ipaddress.ip_address(dst_ip)
                    except ValueError:
                        continue
                    
                    # Create flow object
                    flow = NetworkFlow(
                        flow_id=uuid.uuid4(),
                        timestamp=self._parse_timestamp(row),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=int(row.get('src_port', row.get('source_port', row.get('sport', 0)))),
                        dst_port=int(row.get('dst_port', row.get('destination_port', row.get('dport', 0)))),
                        protocol=row.get('protocol', row.get('proto', 'UNKNOWN')),
                        
                        # Flow statistics
                        duration=float(row.get('duration', row.get('flow_duration', 0))),
                        bytes_sent=int(row.get('bytes_sent', row.get('tot_fwd_pkts', 0))),
                        bytes_received=int(row.get('bytes_received', row.get('tot_bwd_pkts', 0))),
                        packets_sent=int(row.get('packets_sent', row.get('totlen_fwd_pkts', 0))),
                        packets_received=int(row.get('packets_received', row.get('totlen_bwd_pkts', 0))),
                        
                        # Packet statistics
                        packet_size_min=float(row.get('packet_size_min', row.get('min_pkt_len', 0))),
                        packet_size_max=float(row.get('packet_size_max', row.get('max_pkt_len', 0))),
                        packet_size_mean=float(row.get('packet_size_mean', row.get('mean_pkt_len', 0))),
                        packet_size_std=float(row.get('packet_size_std', row.get('std_pkt_len', 0))),
                        
                        # Inter-arrival time statistics
                        iat_min=float(row.get('iat_min', row.get('min_iat', 0))),
                        iat_max=float(row.get('iat_max', row.get('max_iat', 0))),
                        iat_mean=float(row.get('iat_mean', row.get('mean_iat', 0))),
                        iat_std=float(row.get('iat_std', row.get('std_iat', 0))),
                        
                        # TCP flags
                        tcp_flags=row.get('tcp_flags', row.get('flags', '')),
                        
                        # Flow features
                        flow_iat_min=float(row.get('flow_iat_min', row.get('fwd_iat_min', 0))),
                        flow_iat_max=float(row.get('flow_iat_max', row.get('fwd_iat_max', 0))),
                        flow_iat_mean=float(row.get('flow_iat_mean', row.get('fwd_iat_mean', 0))),
                        flow_iat_std=float(row.get('flow_iat_std', row.get('fwd_iat_std', 0))),
                        
                        # Direction
                        is_fwd=bool(row.get('is_fwd', 1)),
                        
                        # Additional features
                        fwd_packets=int(row.get('fwd_packets', row.get('tot_fwd_pkts', 0))),
                        bwd_packets=int(row.get('bwd_packets', row.get('tot_bwd_pkts', 0))),
                        fwd_bytes=int(row.get('fwd_bytes', row.get('totlen_fwd_pkts', 0))),
                        bwd_bytes=int(row.get('bwd_bytes', row.get('totlen_bwd_pkts', 0))),
                        
                        # Link to dataset
                        dataset=dataset
                    )
                    
                    flows_to_create.append(flow)
                except Exception as e:
                    self.stderr.write(f"Error processing row: {e}")
                    continue
            
            # Bulk create flows
            if flows_to_create:
                NetworkFlow.objects.bulk_create(flows_to_create)
                total_flows += len(flows_to_create)
                self.stdout.write(f"Imported {len(flows_to_create)} flows")
        
        self.stdout.write(self.style.SUCCESS(f'Successfully imported {total_flows} flows from {dataset_name}'))
    
    def _parse_timestamp(self, row):
        """Parse timestamp from various possible formats in the dataset"""
        for field in ['timestamp', 'time', 'datetime', 'flow_start', 'start_time']:
            if field in row:
                try:
                    # Try parsing as Unix timestamp
                    if isinstance(row[field], (int, float)):
                        return datetime.fromtimestamp(row[field])
                    # Try parsing as ISO format
                    return datetime.fromisoformat(row[field])
                except (ValueError, TypeError):
                    try:
                        # Try common date formats
                        for fmt in ['%Y-%m-%d %H:%M:%S', '%Y/%m/%d %H:%M:%S', '%d/%m/%Y %H:%M:%S']:
                            try:
                                return datetime.strptime(row[field], fmt)
                            except ValueError:
                                continue
                    except:
                        pass
        
        # Default to current time if parsing fails
        return timezone.now()