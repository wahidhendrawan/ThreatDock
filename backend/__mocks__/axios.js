module.exports = {
  get: () => Promise.resolve({ data: {} }),
  post: () => Promise.resolve({ data: {} }),
  create: () => ({ get: () => Promise.resolve({ data: {} }), post: () => Promise.resolve({ data: {} }) }),
  default: { get: () => Promise.resolve({ data: {} }), post: () => Promise.resolve({ data: {} }) }
};
