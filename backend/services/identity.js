'use strict';

const VALID_ROLES = ['viewer', 'editor', 'admin', 'super_admin'];
const ROLE_RANK = Object.freeze({
  viewer: 0,
  editor: 1,
  admin: 2,
  super_admin: 3
});
const DEFAULT_ROLE = 'viewer';

const ROLE_ALIASES = Object.freeze({
  viewer: 'viewer',
  reader: 'viewer',
  read_only: 'viewer',
  'read-only': 'viewer',
  readonly: 'viewer',
  auditor: 'viewer',
  guest: 'viewer',

  editor: 'editor',
  analyst: 'editor',
  operator: 'editor',
  member: 'editor',
  user: 'editor',
  responder: 'editor',

  admin: 'admin',
  administrator: 'admin',
  owner: 'admin',

  super_admin: 'super_admin',
  'super-admin': 'super_admin',
  superadmin: 'super_admin',
  superuser: 'super_admin',
  root: 'super_admin'
});

function normalizeRole(role) {
  if (role === undefined || role === null) return null;
  const key = String(role).trim().toLowerCase().replace(/\s+/g, '_');
  if (!key) return null;
  return ROLE_ALIASES[key] || null;
}

function normalizeRoles(input) {
  let values = [];
  if (Array.isArray(input)) {
    values = input;
  } else if (typeof input === 'string') {
    const trimmed = input.trim();
    if (!trimmed) return [];
    if (trimmed.startsWith('[')) {
      try {
        const parsed = JSON.parse(trimmed);
        values = Array.isArray(parsed) ? parsed : [];
      } catch {
        values = [];
      }
    } else {
      values = trimmed.split(',');
    }
  } else if (input && typeof input === 'object') {
    if (input.roles !== undefined) return normalizeRoles(input.roles);
    if (input.role !== undefined) values = [input.role];
  }

  return [...new Set(values.map(normalizeRole).filter(Boolean))];
}

function rolesFromUser(user) {
  if (!user) return [];
  const roles = normalizeRoles(user.roles);
  return roles.length ? roles : normalizeRoles(user.role);
}

function rankOfRole(role) {
  const canonical = normalizeRole(role);
  return canonical === null ? -1 : ROLE_RANK[canonical];
}

function highestRank(roles) {
  const normalized = normalizeRoles(roles);
  if (!normalized.length) return -1;
  return normalized.reduce((highest, role) => Math.max(highest, ROLE_RANK[role]), -1);
}

function hasAtLeast(roles, required) {
  const requiredRole = normalizeRole(required);
  if (!requiredRole) return false;
  return highestRank(roles) >= ROLE_RANK[requiredRole];
}

function requireRole(required) {
  const requiredRole = normalizeRole(required);
  if (!requiredRole) throw new TypeError(`Unknown required role: ${required}`);

  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    if (!hasAtLeast(rolesFromUser(req.user), requiredRole)) {
      return res.status(403).json({ error: `Requires ${requiredRole} role` });
    }
    return next();
  };
}

module.exports = {
  VALID_ROLES,
  ROLE_ALIASES,
  ROLE_RANK,
  DEFAULT_ROLE,
  normalizeRole,
  normalizeRoles,
  rolesFromUser,
  rankOfRole,
  highestRank,
  hasAtLeast,
  requireRole
};
