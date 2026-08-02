
const {
  normalizeRole,
  normalizeRoles,
  rolesFromUser,
  rankOfRole,
  highestRank,
  hasAtLeast,
  requireRole,
  ROLE_RANK
} = require('../services/identity');

describe('Identity Service', () => {
  describe('normalizeRole', () => {
    it('should normalize known roles and aliases', () => {
      expect(normalizeRole('admin')).toBe('admin');
      expect(normalizeRole(' administrator ')).toBe('admin');
      expect(normalizeRole('Analyst')).toBe('editor');
      expect(normalizeRole('read-only')).toBe('viewer');
      expect(normalizeRole('super_admin')).toBe('super_admin');
    });

    it('should return null for unknown roles', () => {
      expect(normalizeRole('unknown_role')).toBeNull();
      expect(normalizeRole(null)).toBeNull();
      expect(normalizeRole(undefined)).toBeNull();
      expect(normalizeRole('')).toBeNull();
    });
  });

  describe('normalizeRoles', () => {
    it('should normalize roles from an array', () => {
      expect(normalizeRoles(['admin', 'Analyst', 'viewer', 'unknown'])).toEqual(['admin', 'editor', 'viewer']);
    });

    it('should handle duplicates', () => {
      expect(normalizeRoles(['admin', 'administrator'])).toEqual(['admin']);
    });

    it('should normalize roles from a comma-separated string', () => {
      expect(normalizeRoles('admin, analyst, viewer')).toEqual(['admin', 'editor', 'viewer']);
    });

    it('should normalize roles from a JSON string array', () => {
      expect(normalizeRoles('["admin", "analyst", "viewer"]')).toEqual(['admin', 'editor', 'viewer']);
    });

    it('should return an empty array for invalid input', () => {
      expect(normalizeRoles(null)).toEqual([]);
      expect(normalizeRoles(undefined)).toEqual([]);
      expect(normalizeRoles('')).toEqual([]);
      expect(normalizeRoles('{}')).toEqual([]);
    });
  });

  describe('rolesFromUser', () => {
    it('should extract roles from user.roles (array)', () => {
      const user = { roles: ['admin', 'editor'] };
      expect(rolesFromUser(user)).toEqual(['admin', 'editor']);
    });

    it('should extract roles from user.roles (JSON string)', () => {
      const user = { roles: '["admin", "viewer"]' };
      expect(rolesFromUser(user)).toEqual(['admin', 'viewer']);
    });

    it('should fall back to user.role (string)', () => {
      const user = { role: 'Analyst' };
      expect(rolesFromUser(user)).toEqual(['editor']);
    });

    it('should prefer user.roles over user.role', () => {
      const user = { roles: ['admin'], role: 'viewer' };
      expect(rolesFromUser(user)).toEqual(['admin']);
    });

    it('should return empty array if no roles found', () => {
      const user = { name: 'test' };
      expect(rolesFromUser(user)).toEqual([]);
    });
  });

  describe('rankOfRole', () => {
    it('should return the correct rank for a role', () => {
      expect(rankOfRole('viewer')).toBe(ROLE_RANK.viewer);
      expect(rankOfRole('editor')).toBe(ROLE_RANK.editor);
      expect(rankOfRole('admin')).toBe(ROLE_RANK.admin);
      expect(rankOfRole('super_admin')).toBe(ROLE_RANK.super_admin);
      expect(rankOfRole('Analyst')).toBe(ROLE_RANK.editor);
    });

    it('should return -1 for an unknown role', () => {
      expect(rankOfRole('unknown')).toBe(-1);
    });
  });

  describe('highestRank', () => {
    it('should return the highest rank from a list of roles', () => {
      expect(highestRank(['viewer', 'admin', 'editor'])).toBe(ROLE_RANK.admin);
    });

    it('should return -1 for an empty list of roles', () => {
      expect(highestRank([])).toBe(-1);
    });
  });

  describe('hasAtLeast', () => {
    it('should return true if roles meet the required rank', () => {
      expect(hasAtLeast(['admin'], 'editor')).toBe(true);
      expect(hasAtLeast(['admin'], 'admin')).toBe(true);
    });

    it('should return false if roles do not meet the required rank', () => {
      expect(hasAtLeast(['editor'], 'admin')).toBe(false);
    });

    it('should handle aliases correctly', () => {
      expect(hasAtLeast(['Analyst'], 'viewer')).toBe(true);
    });
  });

  describe('requireRole middleware', () => {
    let mockReq, mockRes, mockNext;

    beforeEach(() => {
      mockReq = { user: null };
      mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };
      mockNext = jest.fn();
    });

    it('should call next() if user has the required role', () => {
      mockReq.user = { roles: ['admin'] };
      const middleware = requireRole('editor');
      middleware(mockReq, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalled();
    });

    it('should send 403 if user does not have the required role', () => {
      mockReq.user = { roles: ['viewer'] };
      const middleware = requireRole('admin');
      middleware(mockReq, mockRes, mockNext);
      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Requires admin role' });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should send 401 if user is not authenticated', () => {
      const middleware = requireRole('viewer');
      middleware(mockReq, mockRes, mockNext);
      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Authentication required' });
      expect(mockNext).not.toHaveBeenCalled();
    });
  });
});
