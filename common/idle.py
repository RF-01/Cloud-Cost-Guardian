"""EC2 idle rules shared by the scanner (detection) and the remediation Lambda (re-check), design §8.2.

Thresholds are the initial values decided by the team (design §24). Only GetMetricStatistics is used
(free API allowance); never GetMetricData (always billed).
"""

# --- EC2 idle thresholds, per hour, scaled to the detection window -----------------------------------
CPU_AVG_PERCENT = 5.0  # CPU average below this is "low"
CPU_MAX_PERCENT = 20.0  # CPU maximum at or above this is a spike (periodic)
NETWORK_BYTES_PER_HOUR = 2 * 1024 * 1024  # NetworkIn + NetworkOut, 2 MB per hour
# VolumeReadOps + VolumeWriteOps over all attached volumes: 3,600 per hour = 1 op/s on average. Idle hosts still
# write logs and run timers (~0.5 op/s; 100/hour flagged a freshly booted, idle AL2023 instance as underused in the
# Nov 22 live test), while disk-heavy workloads run at tens to hundreds of ops/s.
DISK_OPS_PER_HOUR = 3600

METRIC_PERIOD_SECONDS = 300  # basic monitoring granularity

DEFAULT_DETECTION_WINDOW_MINUTES = 30  # demo value; the real tool uses e.g. 1440


def _datapoints(cloudwatch, namespace, metric, dim_name, dim_value, start, end, statistics):
    return cloudwatch.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric,
        Dimensions=[{"Name": dim_name, "Value": dim_value}],
        StartTime=start,
        EndTime=end,
        Period=METRIC_PERIOD_SECONDS,
        Statistics=statistics,
    ).get("Datapoints", [])


def _sum(cloudwatch, namespace, metric, dim_name, dim_value, start, end):
    return sum(p.get("Sum", 0.0) for p in _datapoints(cloudwatch, namespace, metric, dim_name, dim_value,
                                                       start, end, ["Sum"]))


def instance_signals(cloudwatch, instance_id, volume_ids, start, end):
    """Signals over [start, end]: cpuAvg / cpuMax (percent, None if no CPU data), networkBytes, diskOps."""
    cpu = _datapoints(cloudwatch, "AWS/EC2", "CPUUtilization", "InstanceId", instance_id, start, end,
                      ["Average", "Maximum"])
    if cpu:
        cpu_avg = sum(p["Average"] for p in cpu) / len(cpu)
        cpu_max = max(p["Maximum"] for p in cpu)
    else:
        cpu_avg = cpu_max = None
    network = sum(_sum(cloudwatch, "AWS/EC2", m, "InstanceId", instance_id, start, end)
                  for m in ("NetworkIn", "NetworkOut"))
    disk = sum(_sum(cloudwatch, "AWS/EBS", m, "VolumeId", vol, start, end)
               for vol in volume_ids for m in ("VolumeReadOps", "VolumeWriteOps"))
    return {"cpuAvg": cpu_avg, "cpuMax": cpu_max, "networkBytes": network, "diskOps": disk}


def classify(signals, window_minutes):
    """idle | underused | periodic, or None (active, or no CPU data to judge).

    idle      = CPU avg and max, network and disk all low
    periodic  = CPU avg, network and disk low, but CPU max >= threshold (spikes)
    underused = CPU avg low, but network or disk above the threshold
    """
    if signals["cpuAvg"] is None:
        return None
    hours = window_minutes / 60
    cpu_avg_low = signals["cpuAvg"] < CPU_AVG_PERCENT
    cpu_max_low = signals["cpuMax"] < CPU_MAX_PERCENT
    network_low = signals["networkBytes"] < NETWORK_BYTES_PER_HOUR * hours
    disk_low = signals["diskOps"] < DISK_OPS_PER_HOUR * hours
    if not cpu_avg_low:
        return None
    if network_low and disk_low:
        return "idle" if cpu_max_low else "periodic"
    return "underused"
