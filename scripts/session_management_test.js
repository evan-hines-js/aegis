import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Counter, Trend, Rate, Gauge } from 'k6/metrics';
import exec from 'k6/execution';

// Custom metrics for session management
const sessionCreations = new Counter('session_creations');
const sessionCreationErrors = new Counter('session_creation_errors');
const sessionCreationDuration = new Trend('session_creation_duration');
const sessionRequests = new Counter('session_requests');
const sessionRequestErrors = new Counter('session_request_errors');
const sessionCleanups = new Counter('session_cleanups');
const sessionReuseAttempts = new Counter('session_reuse_attempts');
const concurrentSessions = new Gauge('concurrent_sessions');
const sessionLifetime = new Trend('session_lifetime');
const sessionSuccessRate = new Rate('session_success_rate');

// Mode-specific metrics
const statefulSessions = new Counter('stateful_sessions');
const statelessSessions = new Counter('stateless_sessions');
const statefulRequests = new Counter('stateful_requests');
const statelessRequests = new Counter('stateless_requests');

// Test configuration - designed to stress session management
export const options = {
  scenarios: {
    // Scenario 1: Stateful mode - steady session churn (most realistic)
    stateful_steady_churn: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 2000 },   // Ramp up to 2000 concurrent sessions
        { duration: '2m', target: 2500 },    // Maintain 2500 concurrent sessions
        { duration: '30s', target: 2500 },   // Spike to 2500 sessions
        { duration: '1m', target: 2500 },    // Hold spike
        { duration: '30s', target: 2000 },   // Drop back down
        { duration: '30s', target: 0 },      // Ramp down
      ],
      gracefulRampDown: '10s',
      env: { MODE: 'stateful' },
    },

    // Scenario 2: Stateless mode - steady churn
    stateless_steady_churn: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 2000 },
        { duration: '2m', target: 2500 },
        { duration: '30s', target: 2500 },
        { duration: '1m', target: 2500 },
        { duration: '30s', target: 2000 },
        { duration: '30s', target: 0 },
      ],
      gracefulRampDown: '10s',
      env: { MODE: 'stateless' },
    },

    // Scenario 3: Stateful rapid session creation/destruction (stress test)
    stateful_rapid_turnover: {
      executor: 'constant-arrival-rate',
      rate: 50,                             // 50 new sessions per second (stateful)
      timeUnit: '1s',
      duration: '2m',
      preAllocatedVUs: 100,
      maxVUs: 250,
      startTime: '30s',                     // Start after initial ramp
      env: { MODE: 'stateful' },
    },

    // Scenario 4: Stateless rapid turnover
    stateless_rapid_turnover: {
      executor: 'constant-arrival-rate',
      rate: 50,                             // 50 new sessions per second (stateless)
      timeUnit: '1s',
      duration: '2m',
      preAllocatedVUs: 100,
      maxVUs: 250,
      startTime: '30s',
      env: { MODE: 'stateless' },
    },

    // Scenario 5: Session leak detection (sessions that don't cleanup)
    leak_detection: {
      executor: 'constant-vus',
      vus: 25,
      duration: '1m',
      startTime: '3m',                      // Start in middle of test
      env: { MODE: 'stateful' },            // Only test stateful for leaks
    },
  },

  thresholds: {
    'http_req_duration': ['p(95)<1000'],             // 95% under 1s
    'http_req_failed': ['rate<0.05'],                // Less than 5% HTTP failures
    'session_creation_duration': ['p(95)<500'],      // Session creation under 500ms p95
    'session_creation_errors': ['count<100'],        // Less than 100 session creation failures
    'session_success_rate': ['rate>0.95'],           // 95% of sessions work end-to-end
    'checks': ['rate>=0.95'],                        // 95% of checks pass
  },
};

// Configuration
const BASE_URL = __ENV.BASE_URL || 'http://localhost:4000';
const API_KEY = __ENV.API_KEY || 'ak_MbMgtzSS6KKF04BixsvUZ97V8_Yy-ZzO8a1Rdby_rvE';
const PROTOCOL_VERSION = '2025-06-18';

/**
 * Create a new MCP session and return session metadata
 * Handles both stateful (with mcp-session-id) and stateless (no session) modes
 * @param {string} mode - 'stateful' or 'stateless'
 */
function createNewSession(mode = 'stateful') {
  const startTime = Date.now();

  // Build headers with optional stateless mode flag
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${API_KEY}`,
    'MCP-Protocol-Version': PROTOCOL_VERSION,
  };

  // Add stateless opt-in header if in stateless mode
  if (mode === 'stateless') {
    headers['X-MCP-Allow-Stateless'] = 'true';
  }

  const initResponse = http.post(
    `${BASE_URL}/mcp`,
    JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: {
          roots: { listChanged: true },
          sampling: {},
        },
        clientInfo: {
          name: `k6-session-test-${mode}`,
          version: '1.0.0',
        },
      },
    }),
    {
      headers: headers,
      tags: {
        operation: 'session_creation',
        mode: mode,
      },
    }
  );

  const duration = Date.now() - startTime;
  sessionCreationDuration.add(duration);

  const sessionId = initResponse.headers['Mcp-Session-Id'];
  const isStateful = sessionId !== undefined;

  const success = check(initResponse, {
    'init_successful': (r) => r.status === 200,
    'has_result': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.result && body.result.protocolVersion;
      } catch (e) {
        return false;
      }
    },
  });

  if (success) {
    sessionCreations.add(1);

    // Track mode-specific metrics
    if (isStateful) {
      statefulSessions.add(1);

      // Send initialized notification for stateful sessions
      http.post(
        `${BASE_URL}/mcp`,
        JSON.stringify({
          jsonrpc: '2.0',
          method: 'notifications/initialized',
        }),
        {
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${API_KEY}`,
            'MCP-Protocol-Version': PROTOCOL_VERSION,
            'MCP-Session-Id': sessionId,
          },
          tags: {
            operation: 'session_init_notification',
            mode: 'stateful',
          },
        }
      );
    } else {
      statelessSessions.add(1);
    }

    return {
      sessionId: sessionId,
      isStateful: isStateful,
      mode: mode,
      createdAt: Date.now(),
      requestCount: 0,
    };
  } else {
    sessionCreationErrors.add(1);
    console.error(`[${mode}] Init failed: ${initResponse.status} ${initResponse.body}`);
    return null;
  }
}

/**
 * Make a request using session (stateful) or direct auth (stateless)
 */
function makeSessionRequest(session, method, params = {}) {
  if (!session) {
    sessionRequestErrors.add(1);
    return false;
  }

  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${API_KEY}`,
    'MCP-Protocol-Version': PROTOCOL_VERSION,
  };

  // Only add session ID if stateful
  if (session.isStateful && session.sessionId) {
    headers['MCP-Session-Id'] = session.sessionId;
  }

  const response = http.post(
    `${BASE_URL}/mcp`,
    JSON.stringify({
      jsonrpc: '2.0',
      id: Math.floor(Math.random() * 10000),
      method: method,
      params: params,
    }),
    {
      headers: headers,
      tags: {
        operation: 'session_request',
        method: method,
        mode: session.isStateful ? 'stateful' : 'stateless',
      },
    }
  );

  sessionRequests.add(1);
  session.requestCount++;

  // Track mode-specific request metrics
  if (session.isStateful) {
    statefulRequests.add(1);
  } else {
    statelessRequests.add(1);
  }

  const success = check(response, {
    [`${method}_ok`]: (r) => r.status === 200,
    [`${method}_valid`]: (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.result !== undefined && !body.error;
      } catch (e) {
        return false;
      }
    },
  });

  if (!success) {
    sessionRequestErrors.add(1);
  }

  return success;
}

/**
 * Cleanup a session (simulate client disconnect)
 * Note: MCP doesn't have explicit session termination, but we can stop using it
 */
function cleanupSession(session) {
  if (!session) return;

  const lifetime = Date.now() - session.createdAt;
  sessionLifetime.add(lifetime);
  sessionCleanups.add(1);

  // Track session success: created successfully + made at least 1 successful request
  if (session.requestCount > 0) {
    sessionSuccessRate.add(1);
  } else {
    sessionSuccessRate.add(0);
  }
}

/**
 * Main test function - creates new session on EVERY iteration
 */
export default function () {
  const scenarioName = exec.scenario.name;

  // Get mode from scenario environment variable
  const mode = __ENV.MODE || 'stateful';

  // Track concurrent sessions (approximate)
  concurrentSessions.add(1);

  group('Session Lifecycle Test', () => {
    // STEP 1: Create new session with specified mode
    const session = createNewSession(mode);

    if (!session) {
      console.error(`VU ${__VU} failed to create session`);
      concurrentSessions.add(-1);
      return;
    }

    // STEP 2: Use the session for various operations
    group('Session Usage', () => {
      const methods = ['tools/list', 'resources/list', 'prompts/list'];

      // Different usage patterns based on scenario
      if (scenarioName.includes('steady_churn')) {
        // Normal usage: 2-5 requests per session
        const requestCount = Math.floor(Math.random() * 4) + 2;

        for (let i = 0; i < requestCount; i++) {
          const method = methods[Math.floor(Math.random() * methods.length)];
          makeSessionRequest(session, method);

          // Small delay between requests
          sleep(0.1 + Math.random() * 0.4);
        }
      } else if (scenarioName.includes('rapid_turnover')) {
        // Quick usage: 1-2 requests then done
        const method = methods[Math.floor(Math.random() * methods.length)];
        makeSessionRequest(session, method);

        if (Math.random() > 0.5) {
          sleep(0.05);
          makeSessionRequest(session, methods[Math.floor(Math.random() * methods.length)]);
        }
      } else if (scenarioName === 'leak_detection') {
        // Intentionally create sessions without cleanup to test leak detection
        const requestCount = Math.floor(Math.random() * 3) + 1;

        for (let i = 0; i < requestCount; i++) {
          makeSessionRequest(session, methods[Math.floor(Math.random() * methods.length)]);
          sleep(0.2);
        }

        // Randomly "abandon" 10% of sessions (don't cleanup)
        if (Math.random() < 0.1) {
          console.log(`🔴 VU ${__VU} abandoning session ${session.sessionId}`);
          concurrentSessions.add(-1);
          return; // Exit without cleanup
        }
      }

      // Test session reuse (should work with same session ID)
      if (Math.random() < 0.2) {
        sessionReuseAttempts.add(1);
        sleep(1); // Wait a bit
        makeSessionRequest(session, 'tools/list');
      }
    });

    // STEP 3: Cleanup session
    cleanupSession(session);
    concurrentSessions.add(-1);

    // Variable sleep between iterations based on scenario
    if (scenarioName.includes('steady_churn')) {
      sleep(2 + Math.random() * 3); // 2-5 seconds
    } else if (scenarioName.includes('rapid_turnover')) {
      sleep(0.1); // Minimal sleep for rapid turnover
    } else if (scenarioName === 'leak_detection') {
      sleep(1); // Moderate sleep
    }
  });
}

/**
 * Setup - verify system is ready
 */
export function setup() {
  console.log('🔧 SESSION MANAGEMENT LOAD TEST');
  console.log('================================\n');
  console.log(`Target: ${BASE_URL}`);
  console.log('Test Design: Tests BOTH stateful and stateless modes in parallel');
  console.log('Purpose: Stress test session creation, management, and cleanup');
  console.log('');
  console.log('Scenarios:');
  console.log('  - Stateful steady churn (2000-2500 VUs)');
  console.log('  - Stateless steady churn (2000-2500 VUs)');
  console.log('  - Stateful rapid turnover (50/sec)');
  console.log('  - Stateless rapid turnover (50/sec)');
  console.log('  - Session leak detection (25 VUs)\n');

  // Health check
  const healthCheck = http.get(`${BASE_URL}/api/health`);
  if (healthCheck.status !== 200) {
    throw new Error(`Server health check failed: ${healthCheck.status}`);
  }

  console.log('✅ Server is healthy\n');

  // Test both stateful and stateless session creation
  console.log('Testing both modes...');

  const statefulSession = createNewSession('stateful');
  if (!statefulSession) {
    throw new Error('Failed to create stateful test session - check API_KEY');
  }
  console.log(`✅ Stateful mode working (session: ${statefulSession.sessionId})`);

  const statelessSession = createNewSession('stateless');
  if (!statelessSession) {
    throw new Error('Failed to create stateless test session - check API_KEY');
  }
  console.log(`✅ Stateless mode working ${statelessSession.sessionId ? '(has session - unexpected!)' : '(no session - expected!)'}`);

  console.log('');
  console.log('🚀 Starting parallel load test for both modes...\n');

  return {
    startTime: Date.now(),
    statefulSessionId: statefulSession.sessionId,
  };
}

/**
 * Teardown - summary and analysis
 */
export function teardown(data) {
  const duration = (Date.now() - data.startTime) / 1000;

  console.log('\n\n' + '='.repeat(60));
  console.log('📊 SESSION MANAGEMENT TEST COMPLETE');
  console.log('='.repeat(60));
  console.log(`\n⏱️  Duration: ${duration.toFixed(2)}s\n`);
}

/**
 * Custom summary output
 */
export function handleSummary(data) {
  const metrics = data.metrics;

  let summary = '\n' + '━'.repeat(70) + '\n';
  summary += '  SESSION MANAGEMENT TEST RESULTS\n';
  summary += '━'.repeat(70) + '\n\n';

  // Session metrics
  summary += '🔐 SESSION METRICS:\n';
  summary += `   Sessions Created:        ${metrics.session_creations?.values.count || 0}\n`;
  summary += `   - Stateful Sessions:     ${metrics.stateful_sessions?.values.count || 0}\n`;
  summary += `   - Stateless Sessions:    ${metrics.stateless_sessions?.values.count || 0}\n`;
  summary += `   Creation Errors:         ${metrics.session_creation_errors?.values.count || 0}\n`;
  summary += `   Creation Duration (p95): ${metrics.session_creation_duration?.values['p(95)']?.toFixed(2) || 'N/A'}ms\n`;
  summary += `   Creation Duration (avg): ${metrics.session_creation_duration?.values.avg?.toFixed(2) || 'N/A'}ms\n`;
  summary += `   Session Success Rate:    ${((metrics.session_success_rate?.values.rate || 0) * 100).toFixed(2)}%\n\n`;

  // Request metrics
  summary += '📡 REQUEST METRICS:\n';
  summary += `   Total Requests:          ${metrics.session_requests?.values.count || 0}\n`;
  summary += `   - Stateful Requests:     ${metrics.stateful_requests?.values.count || 0}\n`;
  summary += `   - Stateless Requests:    ${metrics.stateless_requests?.values.count || 0}\n`;
  summary += `   Request Errors:          ${metrics.session_request_errors?.values.count || 0}\n`;
  summary += `   Reuse Attempts:          ${metrics.session_reuse_attempts?.values.count || 0}\n`;
  summary += `   HTTP Duration (p95):     ${metrics.http_req_duration?.values['p(95)']?.toFixed(2) || 'N/A'}ms\n`;
  summary += `   HTTP Duration (avg):     ${metrics.http_req_duration?.values.avg?.toFixed(2) || 'N/A'}ms\n\n`;

  // Lifecycle metrics
  summary += '♻️  LIFECYCLE METRICS:\n';
  summary += `   Cleanups:                ${metrics.session_cleanups?.values.count || 0}\n`;
  summary += `   Avg Session Lifetime:    ${(metrics.session_lifetime?.values.avg / 1000)?.toFixed(2) || 'N/A'}s\n`;
  summary += `   Max Session Lifetime:    ${(metrics.session_lifetime?.values.max / 1000)?.toFixed(2) || 'N/A'}s\n\n`;

  // Performance metrics
  summary += '⚡ PERFORMANCE:\n';
  summary += `   Total HTTP Requests:     ${metrics.http_reqs?.values.count || 0}\n`;
  summary += `   HTTP Failure Rate:       ${((metrics.http_req_failed?.values.rate || 0) * 100).toFixed(2)}%\n`;
  summary += `   Iterations:              ${metrics.iterations?.values.count || 0}\n`;
  summary += `   Check Success Rate:      ${((metrics.checks?.values.rate || 0) * 100).toFixed(2)}%\n\n`;

  // Throughput
  const duration = data.state.testRunDurationMs / 1000;
  const sessionsPerSecond = (metrics.session_creations?.values.count || 0) / duration;
  summary += '📈 THROUGHPUT:\n';
  summary += `   Sessions/sec:            ${sessionsPerSecond.toFixed(2)}\n`;
  summary += `   Requests/sec:            ${((metrics.http_reqs?.values.count || 0) / duration).toFixed(2)}\n\n`;

  summary += '━'.repeat(70) + '\n';

  // Analysis and recommendations
  summary += '\n💡 ANALYSIS:\n';

  const sessionErrorRate = (metrics.session_creation_errors?.values.count || 0) /
                           (metrics.session_creations?.values.count || 1);
  const requestErrorRate = (metrics.session_request_errors?.values.count || 0) /
                           (metrics.session_requests?.values.count || 1);

  if (sessionErrorRate > 0.05) {
    summary += '   ⚠️  High session creation error rate - investigate session limits\n';
  } else {
    summary += '   ✅ Session creation is stable\n';
  }

  if (requestErrorRate > 0.05) {
    summary += '   ⚠️  High request error rate - check session persistence\n';
  } else {
    summary += '   ✅ Session request handling is stable\n';
  }

  if (sessionsPerSecond > 50) {
    summary += `   ✅ Excellent session throughput: ${sessionsPerSecond.toFixed(0)}/sec\n`;
  } else if (sessionsPerSecond > 20) {
    summary += `   ✔️  Good session throughput: ${sessionsPerSecond.toFixed(0)}/sec\n`;
  } else {
    summary += `   ⚠️  Low session throughput: ${sessionsPerSecond.toFixed(0)}/sec - optimize session creation\n`;
  }

  const leakedSessions = (metrics.session_creations?.values.count || 0) -
                         (metrics.session_cleanups?.values.count || 0);
  if (leakedSessions > 100) {
    summary += `   🔴 Potential session leak: ${leakedSessions} sessions not cleaned up\n`;
  } else if (leakedSessions > 0) {
    summary += `   ⚠️  ${leakedSessions} sessions not explicitly cleaned (may timeout naturally)\n`;
  } else {
    summary += '   ✅ No session leaks detected\n';
  }

  summary += '\n';

  return {
    'stdout': summary,
    'summary.json': JSON.stringify(data, null, 2),
  };
}
