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
 * environment. To enable n8n webhooks, set `N8N_WEBHOOK_URL`.
 * To enable Telegram notifications, set `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`.
 * To enable MS Teams notifications, set `TEAMS_WEBHOOK_URL`.
 * Optionally set `NOTIFY_THRESHOLD` to one of
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

function parseNotificationRules() {
  try {
    const rules = JSON.parse(process.env.NOTIFICATION_RULES || '[]');
    return Array.isArray(rules) ? rules.filter(rule => rule && rule.enabled !== false) : [];
  } catch {
    return [];
  }
}

function matchesRule(alert, rule, channel) {
  if (rule.channel && rule.channel !== 'all' && rule.channel !== channel) return false;
  const minSeverity = rule.severity || process.env.NOTIFY_THRESHOLD || 'High';
  if ((severityOrder[alert.severity] || 0) < (severityOrder[minSeverity] || 1)) return false;
  if (rule.source && String(alert.source || '') !== String(rule.source)) return false;
  if (rule.status && String(alert.status || '') !== String(rule.status)) return false;
  if (rule.priority && String(alert.priority || '') !== String(rule.priority)) return false;
  if (rule.contains) {
    const haystack = `${alert.title || ''} ${alert.externalId || ''} ${alert.url || ''}`.toLowerCase();
    if (!haystack.includes(String(rule.contains).toLowerCase())) return false;
  }
  return true;
}

function selectAlerts(alerts, channel) {
  const rules = parseNotificationRules();
  if (rules.length > 0) {
    return alerts.filter(alert => rules.some(rule => matchesRule(alert, rule, channel)));
  }
  const threshold = process.env.NOTIFY_THRESHOLD || 'High';
  const thresholdValue = severityOrder[threshold] || 1;
  return alerts.filter(a => severityOrder[a.severity] >= thresholdValue);
}

async function sendSlackNotifications(alerts) {
  const webhook = process.env.SLACK_WEBHOOK_URL;
  if (!webhook) {
    return;
  }
  const messages = selectAlerts(alerts, 'slack');
  if (messages.length === 0) return;
  try {
    for (const alert of messages) {
      const payload = {
        text: `\u26a0\uFE0F New ${alert.severity} alert from ${alert.source}: ${alert.title} \n${alert.url}`
      };
      await axios.post(webhook, payload, { timeout: 10000 });
    }
  } catch (err) {
    console.error('Failed to send Slack notification:', err.message);
  }
}

async function sendN8nWebhook(alerts) {
  const webhook = process.env.N8N_WEBHOOK_URL;
  if (!webhook) {
    return;
  }
  const messages = selectAlerts(alerts, 'n8n');
  if (messages.length === 0) return;
  try {
    // Send array of alerts to n8n webhook
    await axios.post(webhook, { alerts: messages }, { timeout: 10000 });
  } catch (err) {
    console.error('Failed to send n8n webhook:', err.message);
  }
}

async function sendTelegramNotifications(alerts) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) {
    return;
  }
  const messages = selectAlerts(alerts, 'telegram');
  if (messages.length === 0) return;
  try {
    for (const alert of messages) {
      const text = `⚠️ *New ${alert.severity} alert from ${alert.source}*\n${alert.title}\n[Link](${alert.url})`;
      await axios.post(`https://api.telegram.org/bot${token}/sendMessage`, {
        chat_id: chatId,
        text: text,
        parse_mode: 'Markdown'
      }, { timeout: 10000 });
    }
  } catch (err) {
    console.error('Failed to send Telegram notification:', err.message);
  }
}

async function sendTeamsWebhook(alerts) {
  const webhook = process.env.TEAMS_WEBHOOK_URL;
  if (!webhook) {
    return;
  }
  const messages = selectAlerts(alerts, 'teams');
  if (messages.length === 0) return;
  try {
    for (const alert of messages) {
      const payload = {
        text: `⚠️ **New ${alert.severity} alert from ${alert.source}**\n\n${alert.title}\n\n[Link](${alert.url})`
      };
      await axios.post(webhook, payload, { timeout: 10000 });
    }
  } catch (err) {
    console.error('Failed to send Teams webhook:', err.message);
  }
}

module.exports = { sendSlackNotifications, sendN8nWebhook, sendTelegramNotifications, sendTeamsWebhook };
