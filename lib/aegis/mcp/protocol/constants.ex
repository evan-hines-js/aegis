defmodule Aegis.MCP.Constants do
  @moduledoc """
  Centralized constants and configuration values for the MCP implementation.

  This module consolidates magic numbers, timeouts, and other configuration
  values to improve maintainability and consistency.
  """

  # Protocol and server information
  @default_protocol_version "2025-03-26"
  @supported_protocol_versions ["2025-03-26", "2025-06-18"]
  @server_name "Aegis MCP Hub"
  @server_version "1.0.0"

  # Timeouts and intervals (in milliseconds)
  @thirty_seconds 30_000
  @five_seconds 5_000
  @sixty_seconds 60_000
  @five_minutes 300_000

  @default_poll_interval @thirty_seconds
  @session_timeout_hours 24
  @session_cleanup_interval_hours 1
  @session_db_update_threshold @five_minutes
  @session_heartbeat_update_threshold @thirty_seconds
  @sse_heartbeat_interval @thirty_seconds
  @sse_reconnect_delay @five_seconds
  @sse_heartbeat_timeout @sixty_seconds
  @cache_staleness_threshold @five_minutes
  @sse_connection_timeout @five_minutes

  # Security constants
  @session_id_bytes 32

  # Rate limiting constants (requests per minute)
  # 1 minute window with Token Bucket algorithm for burst handling
  @rate_limit_window 60_000
  @default_rate_limit 500
  @tool_calls_rate_limit 300
  @list_operations_rate_limit 1_000
  @resource_reads_rate_limit 2_000
  @server_info_rate_limit 2_000
  @sse_streams_rate_limit 100
  @session_deletion_rate_limit 100

  # HTTP status codes
  @status_ok 200
  @status_accepted 202
  @status_bad_request 400
  @status_unauthorized 401
  @status_not_found 404
  @status_method_not_allowed 405

  # MCP notification methods
  @connected_method "notifications/connected"
  @heartbeat_method "notifications/heartbeat"

  # PubSub topics
  @tools_changed_topic "mcp:tools_changed"
  @resources_changed_topic "mcp:resources_changed"
  @prompts_changed_topic "mcp:prompts_changed"
  @all_changes_topic "mcp:all_changes"
  @session_topic_prefix "mcp:session:"
  @usage_topic "mcp:usage"

  # ETS table names
  @server_capabilities_table :server_capabilities
  @server_registry_table :server_registry
  @client_cache_table :client_cache
  @permission_cache_table :mcp_permission_cache
  @analytics_counters_table :analytics_counters

  # HTTP headers
  @protocol_version_header "mcp-protocol-version"
  @session_id_header "mcp-session-id"
  @last_event_id_header "last-event-id"

  # Content types
  @json_content_type "application/json"
  @sse_content_type "text/event-stream"

  # SSE event types
  @sse_connected_event "connected"
  @sse_notification_event "notification"
  @sse_heartbeat_event "heartbeat"
  @sse_session_event "session"
  @sse_response_event "response"

  # Cache control
  @sse_cache_control "no-cache"
  @sse_connection_type "keep-alive"

  # Keep frequently used getters that provide convenience
  def default_poll_interval, do: @default_poll_interval
  def session_timeout, do: :timer.hours(@session_timeout_hours)
  def session_cleanup_interval, do: :timer.hours(@session_cleanup_interval_hours)
  def sse_heartbeat_interval, do: @sse_heartbeat_interval
  def sse_reconnect_delay, do: @sse_reconnect_delay
  def sse_heartbeat_timeout, do: @sse_heartbeat_timeout
  def cache_staleness_threshold, do: @cache_staleness_threshold
  def session_db_update_threshold, do: @session_db_update_threshold
  def session_heartbeat_update_threshold, do: @session_heartbeat_update_threshold
  def sse_connection_timeout, do: @sse_connection_timeout

  # Security constants
  def session_id_bytes, do: @session_id_bytes

  # Rate limiting constants
  def rate_limit_window, do: @rate_limit_window
  def default_rate_limit, do: {@default_rate_limit, @rate_limit_window}
  def tool_calls_rate_limit, do: {@tool_calls_rate_limit, @rate_limit_window}
  def list_operations_rate_limit, do: {@list_operations_rate_limit, @rate_limit_window}
  def resource_reads_rate_limit, do: {@resource_reads_rate_limit, @rate_limit_window}
  def server_info_rate_limit, do: {@server_info_rate_limit, @rate_limit_window}
  def sse_streams_rate_limit, do: {@sse_streams_rate_limit, @rate_limit_window}
  def session_deletion_rate_limit, do: {@session_deletion_rate_limit, @rate_limit_window}

  # HTTP status codes
  def status_ok, do: @status_ok
  def status_accepted, do: @status_accepted
  def status_bad_request, do: @status_bad_request
  def status_unauthorized, do: @status_unauthorized
  def status_not_found, do: @status_not_found
  def status_method_not_allowed, do: @status_method_not_allowed

  def connected_method, do: @connected_method
  def heartbeat_method, do: @heartbeat_method

  def all_changes_topic, do: @all_changes_topic
  def usage_topic, do: @usage_topic
  def session_topic(session_id), do: @session_topic_prefix <> session_id

  def server_capabilities_table, do: @server_capabilities_table
  def server_registry_table, do: @server_registry_table
  def client_cache_table, do: @client_cache_table
  def permission_cache_table, do: @permission_cache_table
  def analytics_counters_table, do: @analytics_counters_table

  def session_id_header, do: @session_id_header
  def protocol_version_header, do: @protocol_version_header

  def json_content_type, do: @json_content_type
  def sse_content_type, do: @sse_content_type
  def sse_cache_control, do: @sse_cache_control
  def sse_connection_type, do: @sse_connection_type

  def sse_connected_event, do: @sse_connected_event
  def sse_notification_event, do: @sse_notification_event
  def sse_heartbeat_event, do: @sse_heartbeat_event
  def sse_session_event, do: @sse_session_event
  def sse_response_event, do: @sse_response_event

  # Direct access for some constants that aren't frequently called
  def default_protocol_version, do: @default_protocol_version
  def supported_protocol_versions, do: @supported_protocol_versions
  def server_name, do: @server_name
  def server_version, do: @server_version
  def last_event_id_header, do: @last_event_id_header

  # Helper function to get server info map
  def server_info do
    %{
      name: @server_name,
      version: @server_version
    }
  end

  # Helper function to get method to topic mapping
  def method_to_topic(method) do
    case method do
      "notifications/tools/list_changed" -> @tools_changed_topic
      "notifications/resources/list_changed" -> @resources_changed_topic
      "notifications/prompts/list_changed" -> @prompts_changed_topic
      _ -> @all_changes_topic
    end
  end

  # Helper function to check if a method is a list change notification
  def list_change_method?(method) do
    method in [
      "notifications/tools/list_changed",
      "notifications/resources/list_changed",
      "notifications/prompts/list_changed"
    ]
  end
end
