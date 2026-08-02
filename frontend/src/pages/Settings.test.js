import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Settings from './Settings';

function jsonResponse(data, status = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: async () => data
  });
}

test('loads masked secrets and submits updated settings with authorization', async () => {
  const user = userEvent.setup();
  const initialSettings = {
    MFA_REQUIRED: 'true',
    ANALYST_MFA_REQUIRED: 'false',
    SSO_ENABLED: 'false',
    OIDC_CLIENT_SECRET: '[redacted]',
    GITHUB_TOKEN: '[redacted]',
    MONITORED_BRANDS: '[]'
  };

  global.fetch = jest.fn((url, options = {}) => {
    if (url === '/api/settings' && !options.method) return jsonResponse(initialSettings);
    if (url === '/api/users') return jsonResponse([]);
    if (url === '/api/settings' && options.method === 'PUT') return jsonResponse({ ok: true });
    throw new Error(`Unexpected request: ${options.method || 'GET'} ${url}`);
  });

  render(<Settings authData={{ token: 'secure-token' }} />);
  expect(await screen.findByRole('heading', { name: 'Settings & Management' })).toBeInTheDocument();

  await user.click(screen.getByRole('button', { name: 'Threat Intelligence APIs' }));
  const githubToken = screen.getByLabelText('GitHub Token');
  expect(githubToken).toHaveAttribute('type', 'password');
  expect(githubToken).toHaveValue('[redacted]');

  // Select all text and replace with new value
  await user.click(githubToken);
  await user.keyboard('{Control>}a{/Control}');
  await user.keyboard('new-token');
  
  // Wait for the input to reflect the new value in the DOM
  await waitFor(() => {
    const updated = screen.getByLabelText('GitHub Token');
    expect(updated).toHaveValue('new-token');
  }, { timeout: 2000 });
  
  await user.click(screen.getByRole('button', { name: 'Save Configuration' }));

  await waitFor(() => expect(screen.getByText(/Settings saved successfully/)).toBeInTheDocument());
  const putCall = global.fetch.mock.calls.find(([, options]) => options?.method === 'PUT');
  expect(putCall[1].headers.Authorization).toBe('Bearer secure-token');
  expect(JSON.parse(putCall[1].body).GITHUB_TOKEN).toBe('new-token');
});
