const { CircuitBreaker, CircuitBreakerError, STATES } = require('../services/circuitBreaker');

describe('CircuitBreaker', () => {
  let cb;

  beforeEach(() => {
    cb = new CircuitBreaker({
      failureThreshold: 3,
      cooldownMs: 100,
      successThreshold: 1,
      timeout: 500
    });
  });

  describe('initial state', () => {
    it('starts in CLOSED state for new sources', () => {
      const circuit = cb.getCircuit('TestSource');
      expect(circuit.state).toBe(STATES.CLOSED);
      expect(circuit.failures).toBe(0);
      expect(circuit.successes).toBe(0);
    });

    it('getStatus returns empty array when no sources have been used', () => {
      const status = cb.getStatus();
      expect(status).toEqual([]);
    });
  });

  describe('success handling', () => {
    it('allows requests in CLOSED state', async () => {
      const result = await cb.execute('TestSource', async () => 'success');
      expect(result).toBe('success');
    });

    it('resets failure count on success', async () => {
      const circuit = cb.getCircuit('TestSource');
      circuit.failures = 2;

      await cb.execute('TestSource', async () => 'ok');

      expect(circuit.failures).toBe(0);
      expect(circuit.lastSuccess).toBeTruthy();
    });
  });

  describe('failure handling', () => {
    it('increments failure count on error', async () => {
      await expect(cb.execute('TestSource', async () => {
        throw new Error('fail');
      })).rejects.toThrow('fail');

      const circuit = cb.getCircuit('TestSource');
      expect(circuit.failures).toBe(1);
      expect(circuit.state).toBe(STATES.CLOSED);
    });

    it('opens circuit after reaching failure threshold', async () => {
      for (let i = 0; i < 3; i++) {
        await cb.execute('TestSource', async () => {
          throw new Error(`fail ${i}`);
        }).catch(() => {});
      }

      const circuit = cb.getCircuit('TestSource');
      expect(circuit.state).toBe(STATES.OPEN);
      expect(circuit.failures).toBe(3);
    });

    it('throws CircuitBreakerError when circuit is OPEN', async () => {
      // Force circuit to OPEN
      for (let i = 0; i < 3; i++) {
        await cb.execute('TestSource', async () => {
          throw new Error('fail');
        }).catch(() => {});
      }

      await expect(cb.execute('TestSource', async () => 'should not run'))
        .rejects.toThrow(CircuitBreakerError);
    });
  });

  describe('HALF_OPEN state', () => {
    it('transitions to HALF_OPEN after cooldown expires', async () => {
      // Open the circuit
      for (let i = 0; i < 3; i++) {
        await cb.execute('TestSource', async () => {
          throw new Error('fail');
        }).catch(() => {});
      }

      expect(cb.getCircuit('TestSource').state).toBe(STATES.OPEN);

      // Wait for cooldown
      await new Promise(r => setTimeout(r, 150));

      // Next check should transition to HALF_OPEN
      await cb.checkState('TestSource');
      expect(cb.getCircuit('TestSource').state).toBe(STATES.HALF_OPEN);
    });

    it('closes circuit on success in HALF_OPEN state', async () => {
      const circuit = cb.getCircuit('TestSource');
      circuit.state = STATES.HALF_OPEN;
      circuit.successes = 0;

      await cb.execute('TestSource', async () => 'recovered');

      expect(circuit.state).toBe(STATES.CLOSED);
    });

    it('reopens circuit on failure in HALF_OPEN state', async () => {
      const circuit = cb.getCircuit('TestSource');
      circuit.state = STATES.HALF_OPEN;
      circuit.successes = 0;

      await cb.execute('TestSource', async () => {
        throw new Error('still failing');
      }).catch(() => {});

      expect(circuit.state).toBe(STATES.OPEN);
    });
  });

  describe('timeout handling', () => {
    it('times out slow operations', async () => {
      await expect(cb.execute('TestSource', async () => {
        await new Promise(r => setTimeout(r, 1000));
        return 'too slow';
      })).rejects.toThrow(/timed out/);
    });
  });

  describe('reset', () => {
    it('manually resets circuit to CLOSED', async () => {
      // Open the circuit
      for (let i = 0; i < 3; i++) {
        await cb.execute('TestSource', async () => {
          throw new Error('fail');
        }).catch(() => {});
      }

      expect(cb.getCircuit('TestSource').state).toBe(STATES.OPEN);

      cb.reset('TestSource');

      const circuit = cb.getCircuit('TestSource');
      expect(circuit.state).toBe(STATES.CLOSED);
      expect(circuit.failures).toBe(0);
      expect(circuit.successes).toBe(0);
    });
  });

  describe('getStatus', () => {
    it('returns status for all tracked sources', async () => {
      await cb.execute('Source1', async () => 'ok');
      await cb.execute('Source2', async () => {
        throw new Error('fail');
      }).catch(() => {});

      const status = cb.getStatus();

      expect(status).toHaveLength(2);
      expect(status.find(s => s.source === 'Source1').state).toBe(STATES.CLOSED);
      expect(status.find(s => s.source === 'Source2').failures).toBe(1);
    });

    it('includes nextAttempt for OPEN circuits', async () => {
      for (let i = 0; i < 3; i++) {
        await cb.execute('TestSource', async () => {
          throw new Error('fail');
        }).catch(() => {});
      }

      const status = cb.getStatus();
      const testStatus = status.find(s => s.source === 'TestSource');

      expect(testStatus.state).toBe(STATES.OPEN);
      expect(testStatus.nextAttempt).toBeTruthy();
    });
  });
});

describe('CircuitBreakerError', () => {
  it('includes source and nextAttempt', () => {
    const nextAttempt = new Date();
    const error = new CircuitBreakerError('TestSource', nextAttempt);

    expect(error.name).toBe('CircuitBreakerError');
    expect(error.code).toBe('ERR_CIRCUIT_OPEN');
    expect(error.source).toBe('TestSource');
    expect(error.nextAttempt).toBe(nextAttempt);
    expect(error.reason).toBe('open');
  });

  it('supports custom reason', () => {
    const error = new CircuitBreakerError('TestSource', new Date(), 'probe_in_progress');
    expect(error.reason).toBe('probe_in_progress');
    expect(error.message).toContain('recovery probe');
  });
});
