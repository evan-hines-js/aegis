defmodule Aegis.MCP.Namespace do
  @moduledoc """
  Utilities for namespacing tools, resources, and prompts with server names.

  Handles prefixing and parsing of namespaced identifiers to route
  requests to the appropriate backend servers.
  """

  @separator "__"

  @doc "Namespace a tool with its server name"
  def namespace_tool(tool, server_name) do
    Map.update!(tool, "name", &"#{server_name}#{@separator}#{&1}")
  end

  @doc "Namespace a resource with its server name"
  def namespace_resource(resource, server_name) do
    Map.update!(resource, "uri", &add_server_query_param(&1, server_name))
  end

  @doc "Namespace a resource template with its server name"
  def namespace_resource_template(template, server_name) do
    Map.update!(template, "uriTemplate", &add_server_query_param(&1, server_name))
  end

  @doc "Namespace a prompt with its server name"
  def namespace_prompt(prompt, server_name) do
    Map.update!(prompt, "name", &"#{server_name}#{@separator}#{&1}")
  end

  @doc "Parse a namespaced tool or prompt name"
  def parse_namespaced_tool(namespaced_name) do
    case String.split(namespaced_name, @separator, parts: 2) do
      [server_name, tool_name] when server_name != "" and tool_name != "" ->
        {:ok, server_name, tool_name}

      _ ->
        {:error, :invalid_format}
    end
  end

  @doc "Parse a namespaced URI"
  def parse_namespaced_uri(namespaced_uri) do
    case URI.parse(namespaced_uri) do
      %URI{query: query} when is_binary(query) ->
        case URI.decode_query(query) do
          %{"server" => server_name} when server_name != "" ->
            original_uri = remove_server_query_param(namespaced_uri, server_name)
            {:ok, server_name, original_uri}

          _ ->
            {:error, :invalid_format}
        end

      _ ->
        {:error, :invalid_format}
    end
  end

  @doc "Find a server by name in the cache"
  def find_server_by_name(name) do
    alias Aegis.Cache

    cache_key = {:server, name}

    case Cache.get(:mcp_meta_cache, cache_key) do
      {:ok, server_info} when not is_nil(server_info) ->
        {:ok,
         %{
           name: name,
           endpoint: server_info.endpoint,
           auth_type: Map.get(server_info, :auth_type, :none),
           api_key: Map.get(server_info, :api_key),
           oauth_client_id: Map.get(server_info, :oauth_client_id),
           oauth_client_secret: Map.get(server_info, :oauth_client_secret),
           oauth_token_url: Map.get(server_info, :oauth_token_url),
           oauth_scopes: Map.get(server_info, :oauth_scopes, [])
         }}

      _ ->
        {:error, :not_found}
    end
  end

  # Universal ID functions - these work with the MCP namespace formats

  @doc """
  Create an ID for a tool using MCP namespace format.

  Returns the namespaced tool name.
  """
  @spec create_tool_id(String.t(), String.t()) :: String.t()
  def create_tool_id(server_name, tool_name) do
    "#{server_name}#{@separator}#{tool_name}"
  end

  @doc """
  Create an ID for a resource using MCP namespace format.

  Returns the namespaced URI with server query parameter.
  """
  @spec create_resource_id(String.t(), String.t()) :: String.t()
  def create_resource_id(server_name, resource_uri) do
    add_server_query_param(resource_uri, server_name)
  end

  @doc """
  Create an ID for a prompt using MCP namespace format.

  Returns the namespaced prompt name.
  """
  @spec create_prompt_id(String.t(), String.t()) :: String.t()
  def create_prompt_id(server_name, prompt_name) do
    "#{server_name}#{@separator}#{prompt_name}"
  end

  @doc """
  Parse any item ID (tool, resource, or prompt) back to server and item name.

  Handles both __ separators and query parameters automatically.

  ## Examples

      iex> parse_id("server__tool_name")
      {:ok, "server", "tool_name"}

      iex> parse_id("file:///path/to/file?server=myserver")
      {:ok, "myserver", "file:///path/to/file"}
  """
  @spec parse_id(String.t()) :: {:ok, String.t(), String.t()} | {:error, :invalid_format}
  def parse_id(item_id) do
    # Try resource format first (query parameter)
    case parse_namespaced_uri(item_id) do
      {:ok, server_name, item_name} ->
        {:ok, server_name, item_name}

      {:error, :invalid_format} ->
        # Try tool/prompt format (__)
        case String.split(item_id, @separator, parts: 2) do
          [server_name, item_name] when server_name != "" and item_name != "" ->
            {:ok, server_name, item_name}

          _ ->
            {:error, :invalid_format}
        end
    end
  end

  # Private helper functions for query parameter approach

  defp add_server_query_param(uri, server_name) do
    case URI.parse(uri) do
      %URI{query: nil} = parsed_uri ->
        %{parsed_uri | query: "server=#{URI.encode(server_name)}"}
        |> URI.to_string()

      %URI{query: existing_query} = parsed_uri ->
        query_params = URI.decode_query(existing_query)
        new_query_params = Map.put(query_params, "server", server_name)
        new_query = URI.encode_query(new_query_params)

        %{parsed_uri | query: new_query}
        |> URI.to_string()
    end
  end

  defp remove_server_query_param(namespaced_uri, server_name) do
    case URI.parse(namespaced_uri) do
      %URI{query: query} = parsed_uri when is_binary(query) ->
        query_params = URI.decode_query(query)
        remaining_params = Map.delete(query_params, "server")

        case map_size(remaining_params) do
          0 ->
            # No other query params, remove query entirely
            %{parsed_uri | query: nil}
            |> URI.to_string()

          _ ->
            # Other params exist, keep them
            new_query = URI.encode_query(remaining_params)

            %{parsed_uri | query: new_query}
            |> URI.to_string()
        end

      # Fallback for malformed URIs
      _ ->
        namespaced_uri
        |> String.replace("?server=#{URI.encode(server_name)}", "")
        |> String.replace("&server=#{URI.encode(server_name)}", "")
    end
  end
end
