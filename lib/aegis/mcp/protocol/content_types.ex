defmodule Aegis.MCP.ContentTypes do
  @moduledoc """
  Centralized content type definitions and mappings for MCP operations.

  Provides consistent mappings between content types, their required capabilities,
  and their corresponding MCP methods.
  """

  @type content_type :: :tools | :resources | :prompts | :resource_templates

  @content_type_mappings %{
    tools: %{
      capability: "tools",
      method: "tools/list",
      result_key: "tools"
    },
    resources: %{
      capability: "resources",
      method: "resources/list",
      result_key: "resources"
    },
    prompts: %{
      capability: "prompts",
      method: "prompts/list",
      result_key: "prompts"
    },
    resource_templates: %{
      # Same as resources
      capability: "resources",
      method: "resources/templates/list",
      result_key: "resourceTemplates"
    }
  }

  @doc """
  Returns all supported content types.
  """
  @spec all_content_types() :: [content_type()]
  def all_content_types do
    Map.keys(@content_type_mappings)
  end

  @doc """
  Returns the capability required for a content type.
  """
  @spec content_type_to_capability(content_type()) :: String.t()
  def content_type_to_capability(content_type) do
    @content_type_mappings
    |> Map.fetch!(content_type)
    |> Map.fetch!(:capability)
  end

  @doc """
  Returns the MCP method and result key for a content type.
  """
  @spec content_type_to_method_and_key(content_type()) :: {String.t(), String.t()}
  def content_type_to_method_and_key(content_type) do
    mapping = Map.fetch!(@content_type_mappings, content_type)
    {mapping.method, mapping.result_key}
  end

  @doc """
  Returns content types that require a specific capability.
  """
  @spec content_types_for_capability(String.t()) :: [content_type()]
  def content_types_for_capability(capability) do
    @content_type_mappings
    |> Enum.filter(fn {_content_type, mapping} ->
      mapping.capability == capability
    end)
    |> Enum.map(fn {content_type, _mapping} -> content_type end)
  end

  @doc """
  Returns content types supported by a server based on its capabilities.
  """
  @spec supported_content_types_for_server(function()) :: [content_type()]
  def supported_content_types_for_server(capability_check_fn) do
    @content_type_mappings
    |> Enum.filter(fn {_content_type, mapping} ->
      capability_check_fn.(mapping.capability)
    end)
    |> Enum.map(fn {content_type, _mapping} -> content_type end)
  end
end
