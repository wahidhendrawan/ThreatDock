import '@testing-library/jest-dom';

afterEach(() => {
  localStorage.clear();
  jest.restoreAllMocks();
});
