/**
 * Circuit breaker for feed adapters — prevents repeated calls to failing sources.
 * 
 * States:
 * - CLOSED: Normal operation, requests pass through
 * - OPEN: Source is failing, requests are blocked
 * - HALF_OPEN: Testing if source recovered, limited requests allowed
 * 
 * Thresholds:
 * - Opens after 3 consecutive failures
 * - Half-open after 5 minutes cooldown
 * - Closes after 1 successful call in half-open state
 */

const STATES = {
  CLOSED: 'CLOSED',
  OPEN: 'OPEN',
  HALF_OPEN: 'HALF_OPEN'
};

const DEFAULT_CONFIG = {
  failureThreshold: 3,        // Failures before opening circuit
  cooldownMs: 5 * 60 * 1000,  // 5 minutes before trying half-open
  successThreshold: 1,         // Successes in half-open to close circuit
  timeout: 60000               // Per-request timeout (60s)
};

class CircuitBreakerError extends Error {
  constructor(source, nextAttempt, reason = 'open') {
    const message = reason === 'probe_in_progress'
      ? `Circuit breaker recovery probe already running for ${source}.`
      : `Circuit breaker OPEN for ${source}. Next attempt at ${nextAttempt.toISOString()}`;
    super(message);
    this.name = 'CircuitBreakerError';
    this.code = 'ERR_CIRCUIT_OPEN';
    this.source = source;
    this.nextAttempt = nextAttempt;
    this.reason = reason;
  }
}

class CircuitBreaker {
  constructor(config = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    // Map<source, { state, failures, successes, lastFailure, lastSuccess }>
    this.circuits = new Map();
  }

  getCircuit(source) {
    if (!this.circuits.has(source)) {
      this.circuits.set(source, {
        state: STATES.CLOSED,
        failures: 0,
        successes: 0,
        lastFailure: null,
        lastSuccess: null
      });
    }
    return this.circuits.get(source);
  }

  /**
   * Check if source is allowed to execute
   * @param {string} source - Feed source name
   * @throws {CircuitBreakerError} if circuit is OPEN and cooldown not elapsed
   */
  async checkState(source) {
    const circuit = this.getCircuit(source);
    const now = Date.now();

    if (circuit.state === STATES.OPEN) {
      const cooldownExpired = circuit.lastFailure && (now - circuit.lastFailure) >= this.config.cooldownMs;
      
      if (cooldownExpired) {
        // Attempt half-open: allow one request to test recovery
        circuit.state = STATES.HALF_OPEN;
        circuit.successes = 0;
        console.log(`[CircuitBreaker] ${source}: OPEN → HALF_OPEN (cooldown elapsed)`);
      } else {
        const nextAttempt = new Date(circuit.lastFailure + this.config.cooldownMs);
        throw new CircuitBreakerError(source, nextAttempt);
      }
    }
  }

  /**
   * Record successful execution
   * @param {string} source - Feed source name
   */
  recordSuccess(source) {
    const circuit = this.getCircuit(source);
    const now = Date.now();

    circuit.lastSuccess = now;
    circuit.failures = 0;
    circuit.successes += 1;

    if (circuit.state === STATES.HALF_OPEN) {
      if (circuit.successes >= this.config.successThreshold) {
        circuit.state = STATES.CLOSED;
        console.log(`[CircuitBreaker] ${source}: HALF_OPEN → CLOSED (success threshold met)`);
      }
    } else if (circuit.state === STATES.OPEN) {
      // Direct transition from OPEN to CLOSED on success
      circuit.state = STATES.CLOSED;
      console.log(`[CircuitBreaker] ${source}: OPEN → CLOSED (recovered)`);
    }
  }

  /**
   * Record failed execution
   * @param {string} source - Feed source name
   * @param {Error} error - The error that occurred
   */
  recordFailure(source, error) {
    const circuit = this.getCircuit(source);
    const now = Date.now();

    circuit.lastFailure = now;
    circuit.failures += 1;
    circuit.successes = 0;

    if (circuit.state === STATES.HALF_OPEN) {
      // Failed during testing — reopen circuit immediately
      circuit.state = STATES.OPEN;
      console.warn(`[CircuitBreaker] ${source}: HALF_OPEN → OPEN (test failed: ${error.message})`);
    } else if (circuit.state === STATES.CLOSED && circuit.failures >= this.config.failureThreshold) {
      // Exceeded failure threshold — open circuit
      circuit.state = STATES.OPEN;
      console.warn(`[CircuitBreaker] ${source}: CLOSED → OPEN (${circuit.failures} consecutive failures)`);
    }
  }

  /**
   * Execute function with circuit breaker protection
   * @param {string} source - Feed source name
   * @param {Function} fn - Async function to execute
   * @returns {Promise<any>} Result from function
   */
  async execute(source, fn) {
    await this.checkState(source);

    let timeoutId;
    const timeoutPromise = new Promise((_, reject) => {
      timeoutId = setTimeout(() => {
        reject(new Error(`${source} timed out after ${this.config.timeout}ms`));
      }, this.config.timeout);
    });

    try {
      const result = await Promise.race([fn(), timeoutPromise]);
      this.recordSuccess(source);
      return result;
    } catch (err) {
      this.recordFailure(source, err);
      throw err;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Get status of all circuits
   * @returns {Array<object>} Circuit status for each source
   */
  getStatus() {
    const status = [];
    for (const [source, circuit] of this.circuits) {
      status.push({
        source,
        state: circuit.state,
        failures: circuit.failures,
        successes: circuit.successes,
        lastFailure: circuit.lastFailure ? new Date(circuit.lastFailure).toISOString() : null,
        lastSuccess: circuit.lastSuccess ? new Date(circuit.lastSuccess).toISOString() : null,
        nextAttempt: circuit.state === STATES.OPEN && circuit.lastFailure
          ? new Date(circuit.lastFailure + this.config.cooldownMs).toISOString()
          : null
      });
    }
    return status;
  }

  /**
   * Manually reset a circuit to CLOSED state
   * @param {string} source - Feed source name
   */
  reset(source) {
    const circuit = this.getCircuit(source);
    circuit.state = STATES.CLOSED;
    circuit.failures = 0;
    circuit.successes = 0;
    console.log(`[CircuitBreaker] ${source}: manually reset to CLOSED`);
  }
}

// Singleton instance
const circuitBreaker = new CircuitBreaker();

module.exports = {
  CircuitBreaker,
  CircuitBreakerError,
  circuitBreaker,
  STATES
};
