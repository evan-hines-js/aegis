defmodule Aegis.MCP.RequestHelpers do
  @moduledoc """
  Shared utilities for processing MCP requests.
  """

  @doc """
  Adds request ID and _meta to response if present in params.

  This is required by the JSON-RPC specification - if a request has an ID,
  the response must include the same ID. Also forwards _meta for progress tracking.
  """
  @spec add_request_id_if_present(map(), map()) :: map()
  def add_request_id_if_present(response, params) do
    response
    |> maybe_add_field(:id, params, "id")
    |> maybe_add_field(:_meta, params, "_meta")
  end

  defp maybe_add_field(response, field, params, param_key) do
    case Map.get(params, param_key) do
      nil -> response
      value -> Map.put(response, field, value)
    end
  end
end
