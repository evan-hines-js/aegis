defmodule Aegis.MCP.Ranking do
  @moduledoc """
  Smart ranking for MCP tools, resources, and prompts based on usage analytics.

  Implements a simple weighted scoring algorithm:
  - Personal usage count: 60% weight
  - Recency factor: 30% weight
  - Global popularity: 10% weight

  Falls back gracefully to unranked results if analytics are unavailable.
  """

  require Logger

  alias Aegis.MCP.Analytics

  # Recency thresholds (in seconds)
  @one_day 86_400
  @one_week 604_800

  @doc """
  Sort items by usage statistics for a given client.

  Items are sorted by relevance score (highest first). Falls back to
  original order if analytics are unavailable or if there's an error.

  ## Parameters
  - `items`: List of tools/resources/prompts to rank
  - `client_id`: Client ID for personalized ranking

  ## Returns
  - Sorted list of items (or original list on error)
  """
  @spec sort_by_usage(Enumerable.t(), String.t()) :: list()
  def sort_by_usage(items, client_id) when is_binary(client_id) do
    start_time = System.monotonic_time()

    try do
      # Convert stream to list for scoring
      items_list = Enum.to_list(items)

      # Get client usage data once (cached in ETS)
      client_usage = Analytics.get_client_usage(client_id)

      # Sort by score (highest first)
      sorted_items =
        items_list
        |> Enum.map(fn item ->
          score = calculate_item_score(item, client_usage)
          {item, score}
        end)
        |> Enum.sort_by(fn {_item, score} -> score end, :desc)
        |> Enum.map(fn {item, _score} -> item end)

      duration = System.monotonic_time() - start_time

      :telemetry.execute(
        [:aegis, :ranking, :calculated],
        %{duration: duration, item_count: length(items_list)},
        %{client_id: client_id}
      )

      sorted_items
    rescue
      error ->
        Logger.warning("Ranking error, falling back to unsorted: #{inspect(error)}")

        :telemetry.execute(
          [:aegis, :ranking, :fallback],
          %{},
          %{client_id: client_id, error: inspect(error)}
        )

        # Return items as-is on any error
        Enum.to_list(items)
    end
  end

  def sort_by_usage(items, _client_id) do
    # No client_id, return items as-is
    Enum.to_list(items)
  end

  @doc """
  Calculate relevance score for a single item.

  ## Scoring formula:
  ```
  score = (personal_usage_count * 0.6) +
          (recency_factor * 0.3) +
          (global_popularity * 0.1)
  ```

  Where:
  - `personal_usage_count`: How many times this client used the item
  - `recency_factor`: 10 if used within 24h, 5 if within 7d, 0 otherwise
  - `global_popularity`: Total usage count across all clients (normalized)
  """
  @spec calculate_item_score(map(), map()) :: float()
  def calculate_item_score(item, client_usage) do
    tool_identifier = extract_tool_identifier(item)

    # Get personal usage stats
    {personal_count, recency_score} =
      case Map.get(client_usage, tool_identifier) do
        {count, last_used_timestamp} ->
          {count, calculate_recency_score(last_used_timestamp)}

        nil ->
          {0, 0}
      end

    # Get global popularity (fallback to 0 if not found)
    global_count = Analytics.get_global_usage(tool_identifier)

    # Weighted score calculation
    personal_usage_score = personal_count * 0.6
    recency_contribution = recency_score * 0.3
    global_popularity_score = global_count * 0.1

    personal_usage_score + recency_contribution + global_popularity_score
  end

  # Private helper functions

  # Extract tool identifier from item (handles both atom and string keys)
  defp extract_tool_identifier(%{name: name}) when is_binary(name), do: name
  defp extract_tool_identifier(%{"name" => name}) when is_binary(name), do: name
  defp extract_tool_identifier(%{uri: uri}) when is_binary(uri), do: uri
  defp extract_tool_identifier(%{"uri" => uri}) when is_binary(uri), do: uri

  defp extract_tool_identifier(item) do
    # Fallback: use inspect as identifier (will have 0 usage)
    Logger.debug("Could not extract identifier from item: #{inspect(item)}")
    inspect(item)
  end

  # Calculate recency score based on last usage timestamp
  defp calculate_recency_score(last_used_timestamp) when is_integer(last_used_timestamp) do
    now = System.system_time(:second)
    seconds_since_use = now - last_used_timestamp

    cond do
      seconds_since_use <= @one_day -> 10
      seconds_since_use <= @one_week -> 5
      true -> 0
    end
  end

  defp calculate_recency_score(_), do: 0
end
