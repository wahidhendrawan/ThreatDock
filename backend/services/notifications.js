const axios = require('axios');

/*
 * Notification Service
 *
 * This service provides functionality to send alert notifications to an
 * external system such as Slack.  Notifications are triggered after
 * all sources have been fetched and stored.  Only alerts meeting the
 * configured severity threshold are sent.
 *
 * To enable Slack notifications, set `SLACK_WEBHOOK_URL` in your
 * environment.  Optionally set `NOTIFY_THRESHOLD` to one of
 * "Critical", "High", "Medium" or "Low".  Alerts with severity
 * equal to or above this threshold will trigger a notification.
 */

const severityOrder = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
  Unknown: 0
};

async function sendSlackNotifications(alerts) {
  const webhook = process.env.SLACK_WEBHOOK_URL;
  if (!webhook) {
    return;
  }
  const threshold = process.env.NOTIFY_THRESHOLD || 'High';
  const thresholdValue = severityOrder[threshold] || 1;
  const messages = alerts.filter(a => severityOrder[a.severity] >= thresholdValue);
  if (messages.length === 0) return;
  try {
    for (const alert of messages) {
      const payload = {
        text: `\u26a0\uFE0F New ${alert.severity} alert from ${alert.source}: ${alert.title} \n${alert.url}`
      };
      await axios.post(webhook, payload);
    }
  } catch (err) {
    console.error('Failed to send Slack notification:', err.message);
  }
}

module.exports = { sendSlackNotifications };