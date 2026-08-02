/**
 * OpenAPI 3.0 specification for ThreatDock API
 */
const swaggerSpec = {
  openapi: '3.0.0',
  info: {
    title: 'ThreatDock API',
    version: '1.0.0',
    description: 'Centralized Threat Intelligence Platform API — manage alerts, assets, intel operations, and more.'
  },
  servers: [{ url: '/', description: 'ThreatDock API' }],
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT'
      }
    },
    schemas: {
      Alert: {
        type: 'object',
        properties: {
          id: { type: 'integer' },
          source: { type: 'string' },
          externalId: { type: 'string' },
          title: { type: 'string' },
          severity: { type: 'string', enum: ['Critical', 'High', 'Medium', 'Low', 'Unknown'] },
          date: { type: 'string' },
          url: { type: 'string' },
          status: { type: 'string', enum: ['Open', 'In Progress', 'Resolved', 'False Positive', 'Accepted Risk'] },
          attack_phase: { type: 'string' },
          assignee: { type: 'string' },
          priority: { type: 'string', enum: ['P1', 'P2', 'P3', 'P4'] },
          tags: { type: 'string' },
          case_summary: { type: 'string' }
        }
      },
      PaginatedResponse: {
        type: 'object',
        properties: {
          data: { type: 'array', items: { type: 'object' } },
          total: { type: 'integer' },
          page: { type: 'integer' },
          limit: { type: 'integer' }
        }
      },
      Error: {
        type: 'object',
        properties: {
          error: { type: 'string' }
        }
      }
    }
  },
  paths: {
    '/': {
      get: {
        summary: 'Health check',
        tags: ['System'],
        responses: { '200': { description: 'Server is running' } }
      }
    },
    '/api/alerts': {
      get: {
        summary: 'List alerts',
        tags: ['Alerts'],
        security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
          { name: 'limit', in: 'query', schema: { type: 'integer', default: 100, maximum: 500 } },
          { name: 'severity', in: 'query', schema: { type: 'string' } },
          { name: 'source', in: 'query', schema: { type: 'string' } },
          { name: 'status', in: 'query', schema: { type: 'string' } },
          { name: 'start', in: 'query', schema: { type: 'string', format: 'date' } },
          { name: 'end', in: 'query', schema: { type: 'string', format: 'date' } },
          { name: 'search', in: 'query', schema: { type: 'string' } }
        ],
        responses: {
          '200': { description: 'List of alerts (paginated or full)', content: { 'application/json': { schema: { $ref: '#/components/schemas/PaginatedResponse' } } } },
          '401': { description: 'Unauthorized' }
        }
      }
    },
    '/api/alerts/{id}': {
      patch: {
        summary: 'Update alert',
        tags: ['Alerts'],
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        requestBody: {
          content: { 'application/json': { schema: { type: 'object', properties: { status: { type: 'string' }, assignee: { type: 'string' }, priority: { type: 'string' }, case_summary: { type: 'string' }, tags: { type: 'string' } } } } }
        },
        responses: { '200': { description: 'Updated alert' } }
      }
    },
    '/api/assets': {
      get: {
        summary: 'List assets',
        tags: ['Assets'],
        security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
          { name: 'limit', in: 'query', schema: { type: 'integer', default: 100 } }
        ],
        responses: { '200': { description: 'List of assets' } }
      },
      post: {
        summary: 'Create asset',
        tags: ['Assets'],
        security: [{ bearerAuth: [] }],
        requestBody: { content: { 'application/json': { schema: { type: 'object' } } } },
        responses: { '200': { description: 'Asset created' } }
      }
    },
    '/api/intelligence/indicators': {
      get: {
        summary: 'List indicators',
        tags: ['Intelligence'],
        security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'page', in: 'query', schema: { type: 'integer' } },
          { name: 'limit', in: 'query', schema: { type: 'integer' } },
          { name: 'type', in: 'query', schema: { type: 'string' } },
          { name: 'source', in: 'query', schema: { type: 'string' } },
          { name: 'search', in: 'query', schema: { type: 'string' } }
        ],
        responses: { '200': { description: 'List of indicators' } }
      }
    },
    '/api/intelligence/correlations': {
      get: {
        summary: 'List correlated findings',
        tags: ['Intelligence'],
        security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'page', in: 'query', schema: { type: 'integer' } },
          { name: 'limit', in: 'query', schema: { type: 'integer' } }
        ],
        responses: { '200': { description: 'List of correlations' } }
      }
    },
    '/api/intelligence/stats': {
      get: {
        summary: 'Intel statistics',
        tags: ['Intelligence'],
        security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'Indicator and correlation counts' } }
      }
    },
    '/api/intelligence/correlations/rebuild': {
      post: {
        summary: 'Rebuild correlations',
        tags: ['Intelligence'],
        security: [{ bearerAuth: [] }],
        responses: { '202': { description: 'Rebuild started' } }
      }
    },
    '/api/intelligence/cve-enrichment/refresh': {
      post: {
        summary: 'Refresh CVE enrichment (KEV/EPSS)',
        tags: ['Intelligence'],
        security: [{ bearerAuth: [] }],
        responses: { '202': { description: 'Refresh started' } }
      }
    },
    '/api/ingestion/health': {
      get: {
        summary: 'Source health status',
        tags: ['Ingestion'],
        security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'Source health metrics' } }
      }
    },
    '/api/ingestion/runs': {
      get: {
        summary: 'Ingestion run history',
        tags: ['Ingestion'],
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'limit', in: 'query', schema: { type: 'integer', default: 100 } }],
        responses: { '200': { description: 'List of ingestion runs' } }
      }
    },
    '/api/ingestion/fetch': {
      post: {
        summary: 'Trigger manual source fetch',
        tags: ['Ingestion'],
        security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'Fetch started' } }
      }
    },
    '/auth/local-login': {
      post: {
        summary: 'Local login',
        tags: ['Authentication'],
        requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { username: { type: 'string' }, password: { type: 'string' } } } } } },
        responses: { '200': { description: 'Login result' } }
      }
    },
    '/api/users': {
      get: {
        summary: 'List users',
        tags: ['Users'],
        security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'List of users' } }
      }
    },
    '/api/settings': {
      get: {
        summary: 'Get settings',
        tags: ['Settings'],
        security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'Settings object' } }
      },
      put: {
        summary: 'Update settings',
        tags: ['Settings'],
        security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'Settings updated' } }
      }
    },
    '/api/notify': {
      post: {
        summary: 'Send push notification to all WebSocket clients',
        tags: ['System'],
        requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { title: { type: 'string' }, body: { type: 'string' }, severity: { type: 'string' } } } } } },
        responses: { '200': { description: 'Notification sent' } }
      }
    },
    '/healthz': {
      get: {
        summary: 'Liveness probe',
        tags: ['System'],
        responses: { '200': { description: 'Service is alive' } }
      }
    },
    '/readyz': {
      get: {
        summary: 'Readiness probe',
        tags: ['System'],
        responses: {
          '200': { description: 'Service is ready to accept traffic' },
          '503': { description: 'Service unavailable (database down or long-running fetch)' }
        }
      }
    },
    '/metrics': {
      get: {
        summary: 'Prometheus metrics',
        tags: ['System'],
        responses: { '200': { description: 'Prometheus-format metrics', content: { 'text/plain': { schema: { type: 'string' } } } } }
      }
    },
    '/api/alerts/{id}/comments': {
      get: {
        summary: 'List comments for an alert',
        tags: ['Alerts'],
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: { '200': { description: 'List of comments' } }
      },
      post: {
        summary: 'Add comment to an alert',
        tags: ['Alerts'],
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'] } } } },
        responses: { '201': { description: 'Comment created' } }
      }
    },
    '/api/alerts/{id}/comments/{commentId}': {
      delete: {
        summary: 'Delete a comment',
        tags: ['Alerts'],
        security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'id', in: 'path', required: true, schema: { type: 'integer' } },
          { name: 'commentId', in: 'path', required: true, schema: { type: 'integer' } }
        ],
        responses: { '200': { description: 'Comment deleted' } }
      }
    },
    '/api/alerts/{id}/history': {
      get: {
        summary: 'Get alert change history',
        tags: ['Alerts'],
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: { '200': { description: 'List of historical changes' } }
      }
    },
    '/api/assets/{id}': {
      patch: {
        summary: 'Update an asset',
        tags: ['Assets'],
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        requestBody: { content: { 'application/json': { schema: { type: 'object' } } } },
        responses: { '200': { description: 'Asset updated' } }
      },
      delete: {
        summary: 'Delete an asset',
        tags: ['Assets'],
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: { '200': { description: 'Asset deleted' } }
      }
    },
    '/api/assets/scan': {
      post: {
        summary: 'Trigger asset vulnerability scan',
        tags: ['Assets'],
        security: [{ bearerAuth: [] }],
        responses: { '202': { description: 'Scan started' } }
      }
    },
    '/api/vendors': {
      get: {
        summary: 'List vendors',
        tags: ['Vendors'],
        security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'List of vendors' } }
      },
      post: {
        summary: 'Create vendor',
        tags: ['Vendors'],
        security: [{ bearerAuth: [] }],
        requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { name: { type: 'string' }, contact_email: { type: 'string' }, risk_tier: { type: 'string' } } } } } },
        responses: { '201': { description: 'Vendor created' } }
      }
    },
    '/api/vendors/{id}': {
      patch: {
        summary: 'Update vendor',
        tags: ['Vendors'],
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        requestBody: { content: { 'application/json': { schema: { type: 'object' } } } },
        responses: { '200': { description: 'Vendor updated' } }
      },
      delete: {
        summary: 'Delete vendor',
        tags: ['Vendors'],
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: { '200': { description: 'Vendor deleted' } }
      }
    },
    '/api/vendors/{id}/assess': {
      post: {
        summary: 'Record vendor risk assessment',
        tags: ['Vendors'],
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { risk_score: { type: 'number' }, notes: { type: 'string' } } } } } },
        responses: { '200': { description: 'Assessment recorded' } }
      }
    },
    '/api/dns-impersonation/scan': {
      post: {
        summary: 'Scan for DNS impersonation threats',
        tags: ['DNS Impersonation'],
        security: [{ bearerAuth: [] }],
        requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { domain: { type: 'string' } }, required: ['domain'] } } } },
        responses: { '200': { description: 'Scan results' } }
      }
    },
    '/api/hunt': {
      get: {
        summary: 'List threat hunting queries',
        tags: ['Threat Hunting'],
        security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'List of saved queries' } }
      },
      post: {
        summary: 'Create threat hunting query',
        tags: ['Threat Hunting'],
        security: [{ bearerAuth: [] }],
        requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { name: { type: 'string' }, query: { type: 'string' } } } } } },
        responses: { '201': { description: 'Query created' } }
      }
    },
    '/api/hunt/list/simple': {
      get: {
        summary: 'Simple list of threat hunting queries',
        tags: ['Threat Hunting'],
        security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'Simplified query list' } }
      }
    },
    '/api/osint/findings': {
      get: {
        summary: 'List OSINT findings',
        tags: ['OSINT'],
        security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'List of OSINT findings' } }
      }
    },
    '/api/osint/digital-risk/search': {
      post: {
        summary: 'Search for digital risk indicators',
        tags: ['OSINT'],
        security: [{ bearerAuth: [] }],
        requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { query: { type: 'string' } } } } } },
        responses: { '200': { description: 'Digital risk search results' } }
      }
    },
    '/api/osint/brand/search': {
      post: {
        summary: 'Search for brand exposure',
        tags: ['OSINT'],
        security: [{ bearerAuth: [] }],
        requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { brand: { type: 'string' } } } } } },
        responses: { '200': { description: 'Brand exposure results' } }
      }
    },
    '/api/ingestion/audit': {
      get: {
        summary: 'Ingestion audit log',
        tags: ['Ingestion'],
        security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'Audit log entries' } }
      }
    },
    '/api/ingestion/circuit-breaker': {
      get: {
        summary: 'Circuit breaker status for all sources',
        tags: ['Ingestion'],
        security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'Circuit breaker states' } }
      }
    },
    '/api/ingestion/circuit-breaker/reset': {
      post: {
        summary: 'Reset circuit breaker for a source',
        tags: ['Ingestion'],
        security: [{ bearerAuth: [] }],
        requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { source: { type: 'string' } } } } } },
        responses: { '200': { description: 'Circuit breaker reset' } }
      }
    },
    '/api/ingestion/dlq': {
      get: {
        summary: 'List dead-letter queue entries',
        tags: ['Ingestion'],
        security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'DLQ entries' } }
      }
    },
    '/api/ingestion/dlq/stats': {
      get: {
        summary: 'Dead-letter queue statistics',
        tags: ['Ingestion'],
        security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'DLQ statistics' } }
      }
    },
    '/api/ingestion/dlq/{id}/resolve': {
      post: {
        summary: 'Resolve a dead-letter queue entry',
        tags: ['Ingestion'],
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: { '200': { description: 'Entry resolved' } }
      }
    },
    '/api/intelligence/indicators/export': {
      get: {
        summary: 'Export indicators (CSV/JSON)',
        tags: ['Intelligence'],
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'format', in: 'query', schema: { type: 'string', enum: ['csv', 'json'] } }],
        responses: { '200': { description: 'Exported indicators' } }
      }
    },
    '/api/intelligence/cve-enrichment': {
      get: {
        summary: 'List CVE enrichment data (KEV/EPSS)',
        tags: ['Intelligence'],
        security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'CVE enrichment data' } }
      }
    },
    '/api/intelligence/risk-rules': {
      get: {
        summary: 'Get risk scoring rules',
        tags: ['Intelligence'],
        security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'Risk rules configuration' } }
      },
      put: {
        summary: 'Update risk scoring rules',
        tags: ['Intelligence'],
        security: [{ bearerAuth: [] }],
        requestBody: { content: { 'application/json': { schema: { type: 'object' } } } },
        responses: { '200': { description: 'Risk rules updated' } }
      }
    },
    '/api/settings/history': {
      get: {
        summary: 'Get settings change history',
        tags: ['Settings'],
        security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'Settings history' } }
      }
    },
    '/api/users/{id}': {
      patch: {
        summary: 'Update user',
        tags: ['Users'],
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        requestBody: { content: { 'application/json': { schema: { type: 'object' } } } },
        responses: { '200': { description: 'User updated' } }
      },
      delete: {
        summary: 'Delete user',
        tags: ['Users'],
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: { '200': { description: 'User deleted' } }
      }
    },
    '/api/users/{id}/role': {
      patch: {
        summary: 'Update user role',
        tags: ['Users'],
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { role: { type: 'string', enum: ['admin', 'editor', 'viewer'] } } } } } },
        responses: { '200': { description: 'Role updated' } }
      }
    },
    '/api/users/{id}/mfa/setup': {
      post: {
        summary: 'Generate MFA setup for user',
        tags: ['Users'],
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: { '200': { description: 'MFA setup data (QR code)' } }
      }
    },
    '/api/users/{id}/mfa/enable': {
      post: {
        summary: 'Enable MFA after verification',
        tags: ['Users'],
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { token: { type: 'string' } } } } } },
        responses: { '200': { description: 'MFA enabled' } }
      }
    },
    '/api/users/{id}/mfa': {
      delete: {
        summary: 'Disable MFA for user',
        tags: ['Users'],
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: { '200': { description: 'MFA disabled' } }
      }
    },
    '/auth/config': {
      get: {
        summary: 'Get authentication configuration',
        tags: ['Authentication'],
        responses: { '200': { description: 'Auth config (OAuth enabled, providers)' } }
      }
    },
    '/auth/login': {
      get: {
        summary: 'Initiate OAuth login',
        tags: ['Authentication'],
        responses: { '302': { description: 'Redirect to OAuth provider' } }
      }
    },
    '/auth/callback': {
      post: {
        summary: 'OAuth callback handler',
        tags: ['Authentication'],
        responses: { '200': { description: 'OAuth login result' } }
      }
    },
    '/auth/setup-mfa': {
      post: {
        summary: 'Setup MFA during login flow',
        tags: ['Authentication'],
        responses: { '200': { description: 'MFA setup data' } }
      }
    },
    '/auth/verify-mfa': {
      post: {
        summary: 'Verify MFA token during login',
        tags: ['Authentication'],
        requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { token: { type: 'string' } } } } } },
        responses: { '200': { description: 'MFA verification result' } }
      }
    },
    '/auth/logout': {
      post: {
        summary: 'Logout and invalidate session',
        tags: ['Authentication'],
        responses: { '200': { description: 'Logout successful' } }
      }
    }
  }
};

module.exports = swaggerSpec;
