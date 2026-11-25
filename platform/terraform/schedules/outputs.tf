output "schedule_names" {
  description = "Schedule names keyed by job (scan, daily-cost, daily-summary, digest when wired)"
  value       = { for k, s in aws_scheduler_schedule.this : k => s.name }
}

output "schedule_group_name" {
  value = aws_scheduler_schedule_group.this.name
}
