"""EC2 activity signals and classification (design §8.2).

Only GetMetricStatistics is used (free API allowance); never GetMetricData (always billed).
"""

from scanner import config


def _datapoints(cloudwatch, namespace, metric, dim_name, dim_value, start, end, statistics):
    return cloudwatch.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric,
        Dimensions=[{"Name": dim_name, "Value": dim_value}],
        StartTime=start,
        EndTime=end,
        Period=config.METRIC_PERIOD_SECONDS,
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
    cpu_avg_low = signals["cpuAvg"] < config.CPU_AVG_PERCENT
    cpu_max_low = signals["cpuMax"] < config.CPU_MAX_PERCENT
    network_low = signals["networkBytes"] < config.NETWORK_BYTES_PER_HOUR * hours
    disk_low = signals["diskOps"] < config.DISK_OPS_PER_HOUR * hours
    if not cpu_avg_low:
        return None
    if network_low and disk_low:
        return "idle" if cpu_max_low else "periodic"
    return "underused"
