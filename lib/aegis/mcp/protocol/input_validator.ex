defmodule Aegis.MCP.InputValidator do
  @moduledoc """
  Input validation for MCP requests across protocol versions.

  Validates request parameters to prevent:
  - Injection attacks via malformed input
  - DoS attacks via oversized payloads
  - Type confusion attacks
  - Protocol violations

  Supports multiple MCP protocol versions through configurable validation rules.
  """

  # Maximum sizes to prevent DoS
  @max_string_length 10_000
  @max_uri_length 2_000
  @max_arguments_count 100
  @max_arguments_depth 10
  # 100KB
  @max_total_arguments_size 100_000

  @type validation_result :: :ok | {:error, String.t()}

  @doc """
  Validate tools/call request parameters.

  MCP Spec:
  ```typescript
  interface CallToolRequest {
    method: "tools/call";
    params: {
      name: string;
      arguments?: { [key: string]: unknown };
    };
  }
  ```
  """
  @spec validate_tool_call(map()) :: validation_result()
  def validate_tool_call(%{"params" => params}) do
    with :ok <- validate_required_field(params, "name", "string"),
         :ok <- validate_string_length(params["name"], @max_string_length, "name") do
      validate_optional_arguments(params)
    end
  end

  def validate_tool_call(_params) do
    {:error, "Missing 'params' object"}
  end

  @doc """
  Validate resources/read request parameters.

  MCP Spec:
  ```typescript
  interface ReadResourceRequest {
    method: "resources/read";
    params: {
      uri: string; // @format uri
    };
  }
  ```
  """
  @spec validate_resource_read(map()) :: validation_result()
  def validate_resource_read(%{"params" => params}) do
    with :ok <- validate_required_field(params, "uri", "string"),
         :ok <- validate_string_length(params["uri"], @max_uri_length, "uri") do
      validate_uri_format(params["uri"])
    end
  end

  def validate_resource_read(_params) do
    {:error, "Missing 'params' object"}
  end

  @doc """
  Validate prompts/get request parameters.

  MCP Spec:
  ```typescript
  interface GetPromptRequest {
    method: "prompts/get";
    params: {
      name: string;
      arguments?: { [key: string]: string };
    };
  }
  ```
  """
  @spec validate_prompt_get(map()) :: validation_result()
  def validate_prompt_get(%{"params" => params}) do
    with :ok <- validate_required_field(params, "name", "string"),
         :ok <- validate_string_length(params["name"], @max_string_length, "name") do
      validate_optional_prompt_arguments(params)
    end
  end

  def validate_prompt_get(_params) do
    {:error, "Missing 'params' object"}
  end

  # Private validation helpers

  # Validate required field exists and has correct type
  defp validate_required_field(params, field_name, expected_type) do
    case Map.get(params, field_name) do
      nil ->
        {:error, "Missing required field: '#{field_name}'"}

      value ->
        if correct_type?(value, expected_type) do
          :ok
        else
          {:error, "Field '#{field_name}' must be a #{expected_type}, got: #{type_of(value)}"}
        end
    end
  end

  # Validate string length
  defp validate_string_length(value, max_length, field_name) when is_binary(value) do
    if String.length(value) <= max_length do
      :ok
    else
      {:error,
       "Field '#{field_name}' exceeds maximum length of #{max_length} characters (got: #{String.length(value)})"}
    end
  end

  defp validate_string_length(_, _, _), do: :ok

  # Validate URI format (basic check)
  defp validate_uri_format(uri) when is_binary(uri) do
    # Basic URI validation - check for valid characters and structure
    # MCP uses namespaced URIs like "server_name://path"
    cond do
      String.contains?(uri, ["\n", "\r", "\0"]) ->
        {:error, "URI contains invalid control characters"}

      String.trim(uri) == "" ->
        {:error, "URI cannot be empty or whitespace only"}

      true ->
        :ok
    end
  end

  # Validate optional arguments field for tools/call
  defp validate_optional_arguments(params) do
    case Map.get(params, "arguments") do
      nil ->
        :ok

      arguments when is_map(arguments) ->
        with :ok <- validate_arguments_count(arguments),
             :ok <- validate_arguments_depth(arguments, 0) do
          validate_arguments_size(arguments)
        end

      _other ->
        {:error, "Field 'arguments' must be an object/map"}
    end
  end

  # Validate optional arguments field for prompts/get (must be string values)
  defp validate_optional_prompt_arguments(params) do
    case Map.get(params, "arguments") do
      nil ->
        :ok

      arguments when is_map(arguments) ->
        with :ok <- validate_arguments_count(arguments),
             :ok <- validate_prompt_arguments_are_strings(arguments) do
          validate_arguments_size(arguments)
        end

      _other ->
        {:error, "Field 'arguments' must be an object/map"}
    end
  end

  # Validate number of arguments (prevent DoS via many keys)
  defp validate_arguments_count(arguments) when is_map(arguments) do
    count = map_size(arguments)

    if count <= @max_arguments_count do
      :ok
    else
      {:error, "Too many arguments: #{count} (maximum allowed: #{@max_arguments_count})"}
    end
  end

  # Validate arguments depth (prevent stack overflow)
  defp validate_arguments_depth(_value, depth) when depth > @max_arguments_depth do
    {:error,
     "Arguments nested too deeply: #{depth} levels (maximum allowed: #{@max_arguments_depth})"}
  end

  defp validate_arguments_depth(map, depth) when is_map(map) do
    Enum.reduce_while(map, :ok, fn {_key, value}, :ok ->
      case validate_arguments_depth(value, depth + 1) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp validate_arguments_depth(list, depth) when is_list(list) do
    Enum.reduce_while(list, :ok, fn value, :ok ->
      case validate_arguments_depth(value, depth + 1) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp validate_arguments_depth(_primitive, _depth), do: :ok

  # Validate total arguments size (prevent DoS via large payloads)
  defp validate_arguments_size(arguments) do
    # Estimate size by encoding to JSON
    size = arguments |> Jason.encode!() |> byte_size()

    if size <= @max_total_arguments_size do
      :ok
    else
      {:error,
       "Arguments payload too large: #{size} bytes (maximum allowed: #{@max_total_arguments_size} bytes)"}
    end
  end

  # Validate that prompt arguments are all strings
  defp validate_prompt_arguments_are_strings(arguments) when is_map(arguments) do
    non_string_keys =
      arguments
      |> Enum.filter(fn {_key, value} -> not is_binary(value) end)
      |> Enum.map(fn {key, _value} -> key end)

    if Enum.empty?(non_string_keys) do
      :ok
    else
      {:error,
       "Prompt arguments must be strings. Invalid keys: #{Enum.join(non_string_keys, ", ")}"}
    end
  end

  # Type checking helpers
  defp correct_type?(value, "string"), do: is_binary(value)
  defp correct_type?(_value, _type), do: false

  defp type_of(value) when is_binary(value), do: "string"
  defp type_of(value) when is_number(value), do: "number"
  defp type_of(value) when is_boolean(value), do: "boolean"
  defp type_of(value) when is_map(value), do: "object"
  defp type_of(value) when is_list(value), do: "array"
  defp type_of(nil), do: "null"
  defp type_of(_), do: "unknown"
end
