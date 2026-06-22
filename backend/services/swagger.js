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
    }
  }
};

module.exports = swaggerSpec;
