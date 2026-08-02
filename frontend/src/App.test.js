import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import App from './App';

jest.mock('react-router-dom', () => ({
  BrowserRouter: ({ children }) => <>{children}</>,
  Routes: ({ children }) => <>{children}</>,
  Route: () => null,
  Navigate: () => null,
  NavLink: ({ children }) => <a href="/">{children}</a>,
  Outlet: () => null,
  useLocation: () => ({ pathname: '/' })
}));

jest.mock('./socket', () => ({
  on: jest.fn(() => jest.fn()),
  disconnect: jest.fn()
}));

function jsonResponse(data, status = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: async () => data
  });
}

describe('App authentication', () => {
  test('renders the local login form when no session exists', async () => {
    global.fetch = jest.fn(() => jsonResponse({ ssoEnabled: false }));

    render(<App />);

    expect(screen.getByRole('heading', { name: 'ThreatDock' })).toBeInTheDocument();
    expect(screen.getByLabelText('Username')).toBeInTheDocument();
    expect(screen.getByLabelText('Password')).toHaveAttribute('type', 'password');
    expect(screen.getByRole('button', { name: 'Sign In' })).toBeInTheDocument();
    await waitFor(() => expect(global.fetch).toHaveBeenCalledWith('/auth/config'));
  });

  test('shows an authentication error for rejected credentials', async () => {
    const user = userEvent.setup();
    global.fetch = jest.fn((url) => {
      if (url === '/auth/config') return jsonResponse({ ssoEnabled: false });
      if (url === '/auth/local-login') return jsonResponse({ error: 'Unauthorized' }, 401);
      throw new Error(`Unexpected request: ${url}`);
    });

    render(<App />);
    await user.type(screen.getByLabelText('Username'), 'analyst');
    await user.type(screen.getByLabelText('Password'), 'wrong-password');
    await user.click(screen.getByRole('button', { name: 'Sign In' }));

    expect(await screen.findByText('Invalid username or password.')).toBeInTheDocument();
  });
});
