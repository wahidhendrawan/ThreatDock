import { render, screen, waitFor } from '@testing-library/react';
import Stats from './Stats';

jest.mock('recharts', () => {
  const React = require('react');
  const Component = ({ children }) => <div>{children}</div>;
  return {
    ResponsiveContainer: Component,
    BarChart: Component,
    Bar: Component,
    LineChart: Component,
    Line: Component,
    XAxis: Component,
    YAxis: Component,
    CartesianGrid: Component,
    Tooltip: Component,
    Cell: Component,
    PieChart: Component,
    Pie: Component
  };
});

function jsonResponse(data) {
  return Promise.resolve({ ok: true, status: 200, json: async () => data });
}

test('computes operational KPIs from alerts and enrichment data', async () => {
  global.fetch = jest.fn((url) => {
    if (url === '/api/ingestion/health') return jsonResponse([{ source: 'NVD', status: 'Success', last_count: 3 }]);
    if (url === '/api/intelligence/correlations') return jsonResponse([{ id: 1, title: 'Related CVEs', severity: 'High', score: 8, confidence: 90 }]);
    if (url === '/api/osint/findings?category=brand-exposure') return jsonResponse([]);
    throw new Error(`Unexpected request: ${url}`);
  });

  render(
    <Stats
      authData={{ token: 'token' }}
      alerts={[
        { id: 1, source: 'NVD', severity: 'Critical', status: 'Open', date: '2026-08-01' },
        { id: 2, source: 'NVD', severity: 'High', status: 'In Progress', date: '2026-08-01' },
        { id: 3, source: 'OTX', severity: 'Low', status: 'Resolved', date: '2026-08-02' }
      ]}
    />
  );

  await waitFor(() => expect(screen.getByText('Intelligence Signals').parentElement).toHaveTextContent('1'));
  expect(screen.getByText('Ingested Alerts').parentElement).toHaveTextContent('3');
  expect(screen.getByText('Active Threats').parentElement).toHaveTextContent('2');
  expect(screen.getByText('Resolution Rate').parentElement).toHaveTextContent('33%');
});
