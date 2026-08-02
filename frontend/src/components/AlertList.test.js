import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import AlertList from './AlertList';

function jsonResponse(data) {
  return Promise.resolve({ ok: true, status: 200, json: async () => data });
}

test('renders a useful empty state', async () => {
  global.fetch = jest.fn(() => jsonResponse([]));
  render(<AlertList alerts={[]} authData={{ token: 'token' }} />);
  expect(screen.getByText('No alerts found matching your criteria.')).toBeInTheDocument();
  await waitFor(() => expect(global.fetch).toHaveBeenCalledWith('/api/users/list/simple', expect.anything()));
});

test('expands an alert and propagates triage status changes', async () => {
  const user = userEvent.setup();
  const onStatusChange = jest.fn();
  global.fetch = jest.fn((url) => {
    if (url === '/api/users/list/simple') return jsonResponse(['analyst']);
    if (url === '/api/alerts/alert-1/comments') return jsonResponse([]);
    throw new Error(`Unexpected request: ${url}`);
  });

  render(
    <AlertList
      alerts={[{
        id: 'alert-1',
        source: 'NVD',
        severity: 'Critical',
        priority: 'P1',
        status: 'Open',
        title: 'Critical remote execution vulnerability',
        externalId: 'CVE-2026-0001',
        date: '2026-08-01T10:00:00Z'
      }]}
      authData={{ token: 'token' }}
      onStatusChange={onStatusChange}
      onAlertUpdate={jest.fn()}
    />
  );

  await user.click(screen.getByText('Critical remote execution vulnerability'));
  expect(await screen.findByText('Case Management')).toBeInTheDocument();
  await user.selectOptions(screen.getByLabelText('Current Status'), 'In Progress');

  expect(onStatusChange).toHaveBeenCalledWith('alert-1', 'In Progress');
});
