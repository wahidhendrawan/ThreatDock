/**
 * Notification tests: severity threshold, rule matching, channel selection, webhook delivery.
 */

jest.mock('../services/outboundHttp', () => ({
  outboundHttp: {
    post: jest.fn()
  }
}));

const { outboundHttp } = require('../services/outboundHttp');
const { sendSlackNotifications, sendN8nWebhook, sendTelegramNotifications, sendTeamsWebhook } = require('../services/notifications');

describe('Notifications', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetAllMocks();
    outboundHttp.post.mockResolvedValue({ status: 200 });
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  const criticalAlert = { severity: 'Critical', source: 'NVD', title: 'CVE-2024-1234', url: 'https://nvd.nist.gov/1234' };
  const highAlert = { severity: 'High', source: 'CISA', title: 'Ransomware Campaign', url: 'https://cisa.gov/alert' };
  const mediumAlert = { severity: 'Medium', source: 'OTX', title: 'Phishing IOC', url: 'https://otx.alienvault.com' };
  const lowAlert = { severity: 'Low', source: 'RSS', title: 'Blog Post', url: 'https://blog.example.com' };

  describe('Slack notifications', () => {
    it('does nothing when SLACK_WEBHOOK_URL is not set', async () => {
      delete process.env.SLACK_WEBHOOK_URL;
      await sendSlackNotifications([criticalAlert]);
      expect(outboundHttp.post).not.toHaveBeenCalled();
    });

    it('sends alerts meeting the default threshold (High)', async () => {
      process.env.SLACK_WEBHOOK_URL = 'https://hooks.slack.com/test';
      await sendSlackNotifications([criticalAlert, highAlert, mediumAlert, lowAlert]);
      expect(outboundHttp.post).toHaveBeenCalledTimes(2);
      const calls = outboundHttp.post.mock.calls;
      expect(calls[0][1].text).toContain('Critical');
      expect(calls[1][1].text).toContain('High');
    });

    it('respects custom NOTIFY_THRESHOLD', async () => {
      process.env.SLACK_WEBHOOK_URL = 'https://hooks.slack.com/test';
      process.env.NOTIFY_THRESHOLD = 'Medium';
      await sendSlackNotifications([criticalAlert, highAlert, mediumAlert, lowAlert]);
      expect(outboundHttp.post).toHaveBeenCalledTimes(3);
    });

    it('swallows delivery errors', async () => {
      process.env.SLACK_WEBHOOK_URL = 'https://hooks.slack.com/test';
      outboundHttp.post.mockRejectedValue(new Error('network down'));
      await expect(sendSlackNotifications([criticalAlert])).resolves.toBeUndefined();
    });
  });

  describe('n8n webhook', () => {
    it('does nothing when N8N_WEBHOOK_URL is not set', async () => {
      delete process.env.N8N_WEBHOOK_URL;
      await sendN8nWebhook([criticalAlert]);
      expect(outboundHttp.post).not.toHaveBeenCalled();
    });

    it('sends alerts as a batch array', async () => {
      process.env.N8N_WEBHOOK_URL = 'https://n8n.example.com/webhook';
      await sendN8nWebhook([criticalAlert, highAlert]);
      expect(outboundHttp.post).toHaveBeenCalledTimes(1);
      const payload = outboundHttp.post.mock.calls[0][1];
      expect(payload.alerts).toHaveLength(2);
    });

    it('swallows delivery errors', async () => {
      process.env.N8N_WEBHOOK_URL = 'https://n8n.example.com/webhook';
      outboundHttp.post.mockRejectedValue(new Error('timeout'));
      await expect(sendN8nWebhook([criticalAlert])).resolves.toBeUndefined();
    });
  });

  describe('Telegram notifications', () => {
    it('does nothing when token or chat_id is missing', async () => {
      delete process.env.TELEGRAM_BOT_TOKEN;
      delete process.env.TELEGRAM_CHAT_ID;
      await sendTelegramNotifications([criticalAlert]);
      expect(outboundHttp.post).not.toHaveBeenCalled();
    });

    it('sends messages when both token and chat_id are set', async () => {
      process.env.TELEGRAM_BOT_TOKEN = 'bot-token';
      process.env.TELEGRAM_CHAT_ID = '12345';
      await sendTelegramNotifications([criticalAlert, highAlert]);
      expect(outboundHttp.post).toHaveBeenCalledTimes(2);
      const url = outboundHttp.post.mock.calls[0][0];
      expect(url).toContain('bot-token');
      const payload = outboundHttp.post.mock.calls[0][1];
      expect(payload.chat_id).toBe('12345');
      expect(payload.text).toContain('Critical');
    });

    it('swallows delivery errors', async () => {
      process.env.TELEGRAM_BOT_TOKEN = 'bot-token';
      process.env.TELEGRAM_CHAT_ID = '12345';
      outboundHttp.post.mockRejectedValue(new Error('bot blocked'));
      await expect(sendTelegramNotifications([criticalAlert])).resolves.toBeUndefined();
    });
  });

  describe('Teams webhook', () => {
    it('does nothing when TEAMS_WEBHOOK_URL is not set', async () => {
      delete process.env.TEAMS_WEBHOOK_URL;
      await sendTeamsWebhook([criticalAlert]);
      expect(outboundHttp.post).not.toHaveBeenCalled();
    });

    it('sends messages when webhook is configured', async () => {
      process.env.TEAMS_WEBHOOK_URL = 'https://outlook.office.com/webhook/test';
      await sendTeamsWebhook([criticalAlert]);
      expect(outboundHttp.post).toHaveBeenCalledTimes(1);
      const payload = outboundHttp.post.mock.calls[0][1];
      expect(payload.text).toContain('Critical');
    });

    it('swallows delivery errors', async () => {
      process.env.TEAMS_WEBHOOK_URL = 'https://outlook.office.com/webhook/test';
      outboundHttp.post.mockRejectedValue(new Error('webhook expired'));
      await expect(sendTeamsWebhook([criticalAlert])).resolves.toBeUndefined();
    });
  });

  describe('Notification rules', () => {
    it('filters alerts by custom rules (severity + source)', async () => {
      process.env.SLACK_WEBHOOK_URL = 'https://hooks.slack.com/test';
      process.env.NOTIFICATION_RULES = JSON.stringify([
        { channel: 'slack', severity: 'Critical', source: 'NVD' }
      ]);
      await sendSlackNotifications([criticalAlert, highAlert]);
      expect(outboundHttp.post).toHaveBeenCalledTimes(1);
      expect(outboundHttp.post.mock.calls[0][1].text).toContain('NVD');
    });

    it('filters alerts by contains keyword', async () => {
      process.env.SLACK_WEBHOOK_URL = 'https://hooks.slack.com/test';
      process.env.NOTIFICATION_RULES = JSON.stringify([
        { channel: 'slack', contains: 'CVE' }
      ]);
      await sendSlackNotifications([criticalAlert, highAlert]);
      expect(outboundHttp.post).toHaveBeenCalledTimes(1);
      expect(outboundHttp.post.mock.calls[0][1].text).toContain('CVE-2024-1234');
    });

    it('applies rules to the correct channel only', async () => {
      process.env.SLACK_WEBHOOK_URL = 'https://hooks.slack.com/test';
      process.env.N8N_WEBHOOK_URL = 'https://n8n.example.com/webhook';
      process.env.NOTIFICATION_RULES = JSON.stringify([
        { channel: 'slack', source: 'NVD' },
        { channel: 'n8n', source: 'CISA' }
      ]);

      await sendSlackNotifications([criticalAlert, highAlert]);
      expect(outboundHttp.post).toHaveBeenCalledTimes(1);
      expect(outboundHttp.post.mock.calls[0][1].text).toContain('NVD');

      outboundHttp.post.mockClear();
      await sendN8nWebhook([criticalAlert, highAlert]);
      expect(outboundHttp.post).toHaveBeenCalledTimes(1);
      expect(outboundHttp.post.mock.calls[0][1].alerts).toHaveLength(1);
      expect(outboundHttp.post.mock.calls[0][1].alerts[0].source).toBe('CISA');
    });

    it('falls back to threshold when rules are empty', async () => {
      process.env.SLACK_WEBHOOK_URL = 'https://hooks.slack.com/test';
      process.env.NOTIFICATION_RULES = '[]';
      process.env.NOTIFY_THRESHOLD = 'Medium';
      await sendSlackNotifications([criticalAlert, highAlert, mediumAlert, lowAlert]);
      expect(outboundHttp.post).toHaveBeenCalledTimes(3);
    });

    it('ignores disabled rules', async () => {
      process.env.SLACK_WEBHOOK_URL = 'https://hooks.slack.com/test';
      process.env.NOTIFICATION_RULES = JSON.stringify([
        { channel: 'slack', source: 'NVD', enabled: false },
        { channel: 'slack', source: 'CISA' }
      ]);
      await sendSlackNotifications([criticalAlert, highAlert]);
      expect(outboundHttp.post).toHaveBeenCalledTimes(1);
      expect(outboundHttp.post.mock.calls[0][1].text).toContain('CISA');
    });
  });
});
