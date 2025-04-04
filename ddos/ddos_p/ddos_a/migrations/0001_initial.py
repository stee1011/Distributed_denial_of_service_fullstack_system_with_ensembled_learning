# Generated by Django 5.1.7 on 2025-03-15 10:16

import django.db.models.deletion
import django.utils.timezone
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AttackType',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('description', models.TextField()),
                ('severity_level', models.IntegerField(choices=[(1, 'Low'), (2, 'Medium'), (3, 'High'), (4, 'Critical')])),
            ],
        ),
        migrations.CreateModel(
            name='BenignTrafficProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('is_active', models.BooleanField(default=True)),
                ('avg_flow_duration', models.FloatField()),
                ('avg_bytes_per_flow', models.FloatField()),
                ('avg_packets_per_flow', models.FloatField()),
                ('avg_packet_size', models.FloatField()),
                ('avg_iat', models.FloatField(help_text='Average inter-arrival time')),
                ('protocol_distribution', models.JSONField(default=dict)),
                ('port_distribution', models.JSONField(default=dict)),
                ('time_of_day_pattern', models.JSONField(default=dict)),
                ('day_of_week_pattern', models.JSONField(default=dict)),
            ],
        ),
        migrations.CreateModel(
            name='ConfigSetting',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('key', models.CharField(max_length=100, unique=True)),
                ('value', models.JSONField()),
                ('description', models.TextField()),
                ('last_updated', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='DatasetInfo',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('source', models.CharField(max_length=255)),
                ('description', models.TextField()),
                ('date_added', models.DateTimeField(default=django.utils.timezone.now)),
            ],
        ),
        migrations.CreateModel(
            name='DetectionModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('version', models.CharField(max_length=50)),
                ('algorithm', models.CharField(max_length=100)),
                ('description', models.TextField()),
                ('creation_date', models.DateTimeField(default=django.utils.timezone.now)),
                ('is_active', models.BooleanField(default=False)),
                ('model_file_path', models.CharField(max_length=255)),
                ('performance_metrics', models.JSONField(default=dict, help_text='Performance metrics (accuracy, precision, recall, F1)')),
                ('trained_on', models.ManyToManyField(related_name='models', to='ddos_a.datasetinfo')),
            ],
        ),
        migrations.CreateModel(
            name='DetectionResult',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('is_attack', models.BooleanField(default=False)),
                ('confidence', models.FloatField(help_text='Confidence score of the detection (0-1)')),
                ('detection_time', models.DateTimeField(default=django.utils.timezone.now)),
                ('top_features', models.JSONField(default=dict, help_text='Top features that contributed to the detection')),
                ('classification_scores', models.JSONField(default=dict, help_text='Raw classification scores')),
                ('attack_type', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='ddos_a.attacktype')),
            ],
        ),
        migrations.CreateModel(
            name='Alert',
            fields=[
                ('alert_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('timestamp', models.DateTimeField(default=django.utils.timezone.now)),
                ('severity', models.IntegerField(choices=[(1, 'Low'), (2, 'Medium'), (3, 'High'), (4, 'Critical')])),
                ('message', models.TextField()),
                ('is_acknowledged', models.BooleanField(default=False)),
                ('acknowledged_at', models.DateTimeField(blank=True, null=True)),
                ('acknowledged_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
                ('detection', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='alerts', to='ddos_a.detectionresult')),
            ],
        ),
        migrations.CreateModel(
            name='FeatureImportance',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('feature_name', models.CharField(max_length=100)),
                ('importance_score', models.FloatField()),
                ('model', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='feature_importances', to='ddos_a.detectionmodel')),
            ],
            options={
                'ordering': ['-importance_score'],
            },
        ),
        migrations.CreateModel(
            name='NetworkFlow',
            fields=[
                ('flow_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('timestamp', models.DateTimeField(default=django.utils.timezone.now)),
                ('src_ip', models.GenericIPAddressField()),
                ('dst_ip', models.GenericIPAddressField()),
                ('src_port', models.IntegerField()),
                ('dst_port', models.IntegerField()),
                ('protocol', models.CharField(max_length=10)),
                ('duration', models.FloatField(help_text='Flow duration in seconds')),
                ('bytes_sent', models.BigIntegerField()),
                ('bytes_received', models.BigIntegerField()),
                ('packets_sent', models.IntegerField()),
                ('packets_received', models.IntegerField()),
                ('packet_size_min', models.FloatField()),
                ('packet_size_max', models.FloatField()),
                ('packet_size_mean', models.FloatField()),
                ('packet_size_std', models.FloatField()),
                ('iat_min', models.FloatField(help_text='Minimum inter-arrival time')),
                ('iat_max', models.FloatField(help_text='Maximum inter-arrival time')),
                ('iat_mean', models.FloatField(help_text='Mean inter-arrival time')),
                ('iat_std', models.FloatField(help_text='Standard deviation of inter-arrival time')),
                ('tcp_flags', models.CharField(blank=True, max_length=50, null=True)),
                ('flow_iat_min', models.FloatField(help_text='Minimum inter-arrival time of flows')),
                ('flow_iat_max', models.FloatField(help_text='Maximum inter-arrival time of flows')),
                ('flow_iat_mean', models.FloatField(help_text='Mean inter-arrival time of flows')),
                ('flow_iat_std', models.FloatField(help_text='Standard deviation of inter-arrival time of flows')),
                ('is_fwd', models.BooleanField(help_text='Is the flow in the forward direction')),
                ('fwd_packets', models.IntegerField(help_text='Number of packets in forward direction')),
                ('bwd_packets', models.IntegerField(help_text='Number of packets in backward direction')),
                ('fwd_bytes', models.BigIntegerField(help_text='Number of bytes in forward direction')),
                ('bwd_bytes', models.BigIntegerField(help_text='Number of bytes in backward direction')),
                ('dataset', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='flows', to='ddos_a.datasetinfo')),
            ],
        ),
        migrations.AddField(
            model_name='detectionresult',
            name='flow',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='detection', to='ddos_a.networkflow'),
        ),
        migrations.CreateModel(
            name='TrafficStatistics',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(default=django.utils.timezone.now)),
                ('time_period', models.CharField(choices=[('1min', '1 Minute'), ('5min', '5 Minutes'), ('15min', '15 Minutes'), ('1hour', '1 Hour'), ('1day', '1 Day')], max_length=20)),
                ('total_flows', models.IntegerField()),
                ('total_bytes', models.BigIntegerField()),
                ('total_packets', models.BigIntegerField()),
                ('avg_flow_duration', models.FloatField()),
                ('attack_flows', models.IntegerField()),
                ('attack_percentage', models.FloatField()),
            ],
            options={
                'indexes': [models.Index(fields=['timestamp'], name='ddos_a_traf_timesta_ba8c56_idx'), models.Index(fields=['time_period'], name='ddos_a_traf_time_pe_74bc47_idx')],
            },
        ),
        migrations.AddIndex(
            model_name='networkflow',
            index=models.Index(fields=['src_ip', 'dst_ip'], name='ddos_a_netw_src_ip_51acb0_idx'),
        ),
        migrations.AddIndex(
            model_name='networkflow',
            index=models.Index(fields=['timestamp'], name='ddos_a_netw_timesta_626849_idx'),
        ),
        migrations.AddIndex(
            model_name='networkflow',
            index=models.Index(fields=['protocol'], name='ddos_a_netw_protoco_549287_idx'),
        ),
    ]
