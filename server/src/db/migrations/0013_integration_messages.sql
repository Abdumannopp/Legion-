-- Alerts into chat and ticket systems (Slack, Jira …): a new kind of outbox job, delivered with the same
-- retries, backoff and dead letters as mail. recipient holds the connection id; payload the message.
ALTER TABLE notification_outbox DROP CONSTRAINT IF EXISTS notification_outbox_kind_check;
ALTER TABLE notification_outbox ADD CONSTRAINT notification_outbox_kind_check
  CHECK (kind IN ('alert_email', 'realtime_alert', 'protection_email', 'integration_message'));
