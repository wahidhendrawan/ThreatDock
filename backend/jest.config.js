module.exports = {
  testEnvironment: 'node',
  moduleNameMapper: {
    '^axios$': '<rootDir>/__mocks__/axios.js'
  },
  transform: {
    '^.+\\.js$': ['babel-jest', {
      presets: [['@babel/preset-env', { targets: { node: 'current' } }]]
    }]
  },
  transformIgnorePatterns: [
    '/node_modules/(?!jose)/'
  ]
};
