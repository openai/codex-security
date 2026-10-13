export const syntheticModelCatalog = {
  models: [
    {
      slug: "synthetic-catalog-model",
      display_name: "Synthetic model",
      description: "Synthetic catalog fixture",
      default_reasoning_level: "low",
      supported_reasoning_levels: [
        {
          effort: "low",
          description: "Synthetic reasoning option",
        },
        {
          effort: "medium",
          description: "Synthetic reasoning option",
        },
        {
          effort: "high",
          description: "Synthetic reasoning option",
        },
        {
          effort: "xhigh",
          description: "Synthetic reasoning option",
        },
        {
          effort: "max",
          description: "Synthetic reasoning option",
        },
        {
          effort: "ultra",
          description: "Synthetic reasoning option",
        },
      ],
      shell_type: "shell_command",
      visibility: "list",
      minimal_client_version: "0.153.0",
      supported_in_api: true,
      availability_nux: null,
      priority: 2,
      model_messages: null,
      context_window: 272000,
      max_context_window: 872000,
      default_reasoning_summary: "none",
      support_verbosity: true,
      default_verbosity: "low",
      apply_patch_tool_type: "freeform",
      input_modalities: ["text", "image"],
      truncation_policy: {
        mode: "tokens",
        limit: 10000,
      },
      supports_parallel_tool_calls: true,
      supports_reasoning_summaries: true,
      supports_reasoning_summary_parameter: true,
      experimental_supported_tools: [],
      base_instructions: "Synthetic local configuration fixture.",
    },
  ],
};
