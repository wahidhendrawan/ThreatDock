import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Filters from './Filters';

test('propagates filter changes to the owning page', async () => {
  const user = userEvent.setup();
  const handlers = {
    setSeverity: jest.fn(),
    setSource: jest.fn(),
    setStatus: jest.fn(),
    setAttackPhase: jest.fn(),
    setStartDate: jest.fn(),
    setEndDate: jest.fn()
  };

  render(
    <Filters
      severity=""
      source=""
      status=""
      attackPhase=""
      startDate=""
      endDate=""
      {...handlers}
    />
  );

  await user.selectOptions(screen.getByLabelText('Severity'), 'Critical');
  await user.selectOptions(screen.getByLabelText('Status'), 'In Progress');
  await user.type(screen.getByLabelText('Start Date'), '2026-08-01');

  expect(handlers.setSeverity).toHaveBeenCalledWith('Critical');
  expect(handlers.setStatus).toHaveBeenCalledWith('In Progress');
  expect(handlers.setStartDate).toHaveBeenLastCalledWith('2026-08-01');
});
