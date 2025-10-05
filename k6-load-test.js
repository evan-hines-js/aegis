import http from 'k6/http';
import { check, sleep } from 'k6';

// Configure k6 to not mark 400 (validation errors) and 429 (rate limits) as failures
http.setResponseCallback(http.expectedStatuses(200, 400, 429));

export let options = {
  stages: [
    // Morning ramp-up (simulate business start)
    { duration: '10s', target: 2000 },

    // Business hours sustained load
    { duration: '1s', target: 2000 },
    { duration: '1s', target: 2000  },

    { duration: '1s', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<2500'], // 95% of requests under 5s
    checks: ['rate>=1'],               // 2000% of checks must pass (no failures allowed)
  },
  // Enable HTTP/2 for better performance
  insecureSkipTLSVerify: true,
  noConnectionReuse: false,
};
const BASE_URL = 'http://127.0.0.1:4000/tidewave';
//const BASE_URL = 'http://192.168.1.25:8000';
// Use the API key from our recent test, or set via environment variable
const API_KEY = __ENV.API_KEY || 'ak_x9t0IaCYdYP7eWMiz94LcO1WgfSl_rFcGLlCA9GQW8Q';

// Setup function runs once at the beginning of the test
export function setup() {
  console.log('🚀 Initializing MCP session for 12-hour load test...');

  // Try MCP initialize (requires authentication)
  let initResponse = http.post(`${BASE_URL}/mcp`, JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2025-06-18',
      capabilities: {
        tools: {}
      },
      clientInfo: {
        name: 'k6-12h-load-test-client',
        version: '1.0.0'
      }
    }
  }), {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `${API_KEY}`
    },
  });

  // Check initialize response
  const initSuccess = check(initResponse, {
    'setup: initialize status is 200': (r) => r.status === 200,
    'setup: initialize has result': (r) => JSON.parse(r.body).result !== undefined,
  });

  if (!initSuccess) {
    console.error('❌ Failed to initialize MCP session');
    throw new Error('Setup failed: could not initialize MCP session');
  }

  // Extract session ID from initialize response
  const sessionId = initResponse.headers['Mcp-Session-Id'];
  const sessionData = {
    sessionId: sessionId,
    apiKey: API_KEY,
    baseUrl: BASE_URL
  };

  console.log(`✅ MCP session initialized successfully. Session ID: ${sessionId || 'none'}`);
  return sessionData;
}

// Main test function uses the session data from setup
export default function (sessionData) {
  const sessionHeaders = {
    'Content-Type': 'application/json',
    'Authorization': `${sessionData.apiKey}`
  };

  // Add session ID header if present
  if (sessionData.sessionId) {
    sessionHeaders['Mcp-Session-Id'] = sessionData.sessionId;
  }

  // Log progress periodically (every 2000th user, every 10th iteration)
  if (__VU % 2000 === 0 && __ITER % 10 === 0) {
    console.log(`Progress: VU ${__VU}, Iteration ${__ITER}, Time: ${new Date().toISOString()}`);
  }

  // Test tools/list
  let toolsResponse = http.post(`${sessionData.baseUrl}/mcp`, JSON.stringify({
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/list',
    params: {}
  }), {
    headers: sessionHeaders,
  });

  // Log first 2000 failures only to avoid spam
  const shouldLog = __ITER < 10;

  const toolsListCheck = check(toolsResponse, {
    'tools/list status is 200': (r) => {
      const passed = r.status === 200;
      if (!passed && shouldLog) {
        console.error(`❌ VU${__VU} iter${__ITER}: tools/list failed - status=${r.status}, error=${r.error}, error_code=${r.error_code}, body=${r.body?.substring(0, 200)}`);
      }
      return passed;
    },
    'tools/list has tools': (r) => {
      try {
        return JSON.parse(r.body).result?.tools !== undefined;
      } catch (e) {
        if (shouldLog) {
          console.error(`❌ VU${__VU} iter${__ITER}: tools/list parse failed - ${e}, body=${r.body?.substring(0, 200)}`);
        }
        return false;
      }
    },
  });

  // If tools/list succeeded, call 1-3 random tools
  if (toolsListCheck && toolsResponse.status === 200) {
    try {
      const toolsData = JSON.parse(toolsResponse.body);
      const tools = toolsData.result?.tools || [];

      if (tools.length > 0) {
        // Randomly select 1-3 tools to call
        const numToolsToCall = Math.floor(Math.random() * 3) + 1; // 1, 2, or 3
        const selectedTools = tools.slice(0, Math.min(numToolsToCall, tools.length));

        // Call each selected tool with minimal arguments
        selectedTools.forEach((tool, index) => {
          const toolCallResponse = http.post(`${sessionData.baseUrl}/mcp`, JSON.stringify({
            jsonrpc: '2.0',
            id: 2000 + index, // Unique ID for each tool call
            method: 'tools/call',
            params: {
              name: tool.name,
              arguments: {} // Empty arguments - tools should handle this gracefully
            }
          }), {
            headers: sessionHeaders,
          });

          check(toolCallResponse, {
            [`tool_call_${tool.name.replace(/[^a-zA-Z0-9_]/g, '_')}_status_ok`]: (r) =>
              r.status === 200 || r.status === 400, // Accept 400 for missing args
            [`tool_call_${tool.name.replace(/[^a-zA-Z0-9_]/g, '_')}_has_response`]: (r) => {
              try {
                const body = JSON.parse(r.body);
                return body.result !== undefined || body.error !== undefined;
              } catch {
                return false;
              }
            }
          });
        });
      }
    } catch (error) {
      console.error('Failed to parse tools response or call tools:', error);
    }
  }

  // Simulate enterprise user patterns
  const userType = Math.random();
  
  if (userType < 0.005) {
    // 0.5% RARE BURST USERS - Simulate sudden heavy load spikes
    console.log(`💥 RARE BURST: VU ${__VU} creating traffic spike at ${new Date().toISOString()}`);
    
    const burstCalls = Math.floor(Math.random() * 8) + 5; // 5-12 rapid calls
    for (let i = 0; i < burstCalls; i++) {
      // Very rapid calls with minimal delay
      sleep(Math.random() * 0.5); // 0-500ms between calls
      
      let burstResponse = http.post(`${sessionData.baseUrl}/mcp`, JSON.stringify({
        jsonrpc: '2.0',
        id: 400 + i,
        method: 'tools/list',
        params: {}
      }), {
        headers: sessionHeaders,
      });

      check(burstResponse, {
        'rare_burst_call_ok': (r) => r.status === 200 || r.status === 429, // Allow rate limiting
      });
      
      // Sometimes make tool calls during burst too
      if (i % 2 === 0 && burstResponse.status === 200) {
        try {
          const toolsData = JSON.parse(burstResponse.body);
          const tools = toolsData.result?.tools || [];
          if (tools.length > 0) {
            const randomTool = tools[Math.floor(Math.random() * tools.length)];
            
            let burstToolCall = http.post(`${sessionData.baseUrl}/mcp`, JSON.stringify({
              jsonrpc: '2.0',
              id: 500 + i,
              method: 'tools/call',
              params: {
                name: randomTool.name,
                arguments: {}
              }
            }), {
              headers: sessionHeaders,
            });

            check(burstToolCall, {
              'rare_burst_tool_call_ok': (r) => r.status === 200 || r.status === 400 || r.status === 429,
            });
          }
        } catch (error) {
          // Ignore parsing errors during burst
        }
      }
    }
  } else if (userType < 0.02) {
    // 1.5% "thundering herd" - Simulate cache invalidation scenarios
    const herdSize = Math.floor(Math.random() * 4) + 3; // 3-6 rapid identical calls
    for (let i = 0; i < herdSize; i++) {
      let herdResponse = http.post(`${sessionData.baseUrl}/mcp`, JSON.stringify({
        jsonrpc: '2.0',
        id: 600 + i,
        method: 'tools/list',
        params: {}
      }), {
        headers: sessionHeaders,
      });

      check(herdResponse, {
        'thundering_herd_ok': (r) => r.status === 200,
      });
      
      sleep(0.01 + Math.random() * 0.1); // Very tight timing to stress cache
    }
  } else if (userType < 0.1) {
    // 8% "power users" - make additional rapid calls
    const extraCalls = Math.floor(Math.random() * 3) + 1;
    for (let i = 0; i < extraCalls; i++) {
      sleep(0.5 + Math.random() * 2); // Short delay between rapid calls
      
      // Make another tools/list call (power users often refresh)
      let extraToolsResponse = http.post(`${sessionData.baseUrl}/mcp`, JSON.stringify({
        jsonrpc: '2.0',
        id: 200 + i,
        method: 'tools/list',
        params: {}
      }), {
        headers: sessionHeaders,
      });

      check(extraToolsResponse, {
        'power_user_tools_list_ok': (r) => r.status === 200,
      });
    }
  } else if (userType < 0.2) {
    // 10% "batch users" - simulate automated/scripted usage
    sleep(1); // Slight delay then burst
    
    // Make multiple quick calls
    for (let i = 0; i < 2; i++) {
      let batchResponse = http.post(`${sessionData.baseUrl}/mcp`, JSON.stringify({
        jsonrpc: '2.0',
        id: 300 + i,
        method: 'tools/list',
        params: {}
      }), {
        headers: sessionHeaders,
      });

      check(batchResponse, {
        'batch_user_call_ok': (r) => r.status === 200,
      });
      
      sleep(0.1); // Very short delay between batch calls
    }
  }

  // Variable sleep based on simulated "time of day" and user type
  let baseSleep = Math.random() * 15;
  
  // Adjust sleep based on current stage (simulate day/night patterns)
  const currentTime = new Date();
  const testStartTime = new Date(currentTime.getTime() - (__ITER * 15 * 20000)); // Rough estimate
  const hoursSinceStart = (currentTime - testStartTime) / (20000 * 60 * 60);
  
  // Longer sleeps during "night" hours (hours 8-12 of test)
  if (hoursSinceStart >= 8 && hoursSinceStart <= 12) {
    baseSleep = baseSleep * 2; // Slower activity at night
  }

  sleep(baseSleep);
}

// Note: Removed handleSummary function to preserve default k6 console output
// If you need to save detailed metrics, you can add --out json=results.json to your k6 command

// Teardown function runs once at the end of the test
export function teardown(sessionData) {
  console.log('🧹 Cleaning up 12-hour MCP load test...');

  if (sessionData && sessionData.sessionId) {
    console.log(`✅ 12-hour test completed successfully. Session ID: ${sessionData.sessionId}`);
  } else {
    console.log('✅ 12-hour load test completed (no session ID)');
  }
  
  console.log('📊 Check summary_12h.json for detailed performance metrics');
}
