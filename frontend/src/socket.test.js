import { io } from 'socket.io-client';
import ws from './socket';

jest.mock('socket.io-client', () => ({ io: jest.fn() }));

test('sends the current access token in the Socket.IO handshake', () => {
  io.mockReturnValue({ on: jest.fn(), off: jest.fn(), connect: jest.fn(), connected: false });
  localStorage.setItem('threatdock_token', 'access-token-1');
  ws.on('alerts:updated', () => {});

  const { auth } = io.mock.calls[0][0];
  const cb = jest.fn();
  auth(cb);
  expect(cb).toHaveBeenCalledWith({ token: 'access-token-1' });
});
