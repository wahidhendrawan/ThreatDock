import http from 'k6/http';
import { check, sleep } from 'k6';

const baseUrl = __ENV.BASE_URL || 'http://127.0.0.1:5002';
const authToken = __ENV.AUTH_TOKEN;
const headers = authToken ? { Authorization: `Bearer ${authToken}` } : {};

export const options = {
  scenarios: {
    read_api: {
      executor: 'constant-vus',
      vus: Number(__ENV.VUS || 10),
      duration: __ENV.DURATION || '30s'
    }
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<500']
  }
};

function expectOk(response, name) {
  check(response, { [`${name} is successful`]: (result) => result.status >= 200 && result.status < 300 });
}

export default function () {
  expectOk(http.get(`${baseUrl}/healthz`), 'liveness');
  expectOk(http.get(`${baseUrl}/api/docs.json`), 'OpenAPI specification');

  if (authToken) {
    expectOk(http.get(`${baseUrl}/api/alerts?limit=25`, { headers }), 'alerts list');
    expectOk(http.get(`${baseUrl}/api/assets?limit=25`, { headers }), 'assets list');
    expectOk(http.get(`${baseUrl}/api/intelligence/correlations?limit=25`, { headers }), 'correlations list');
  }

  sleep(1);
}
