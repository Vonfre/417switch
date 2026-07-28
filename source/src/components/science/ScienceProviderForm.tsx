import { useCallback, useEffect, useMemo, useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { Download, Loader2 } from "lucide-react";
import { useForm } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

import { BasicFormFields } from "@/components/providers/forms/BasicFormFields";
import type {
  ProviderFormProps,
  ProviderFormValues,
} from "@/components/providers/forms/ProviderForm";
import { ModelInputWithFetch } from "@/components/providers/forms/shared";
import { Button } from "@/components/ui/button";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import {
  fetchModelsForConfig,
  showFetchModelsError,
  type FetchedModel,
} from "@/lib/api/model-fetch";
import { providerSchema, type ProviderFormData } from "@/lib/schemas/provider";
import { cn } from "@/lib/utils";
import type { ClaudeApiFormat, ProviderMeta } from "@/types";

type ScienceApiFormat = Extract<
  ClaudeApiFormat,
  "anthropic" | "openai_chat" | "openai_responses"
>;

type ScienceProviderFormProps = Omit<ProviderFormProps, "appId">;

interface ScienceTemplate {
  id: ScienceApiFormat;
  title: string;
  description: string;
  baseHint: string;
  icon: string;
  iconColor: string;
}

const SCIENCE_TEMPLATES: ScienceTemplate[] = [
  {
    id: "openai_responses",
    title: "自定义 OpenAI Responses",
    description: "OpenAI Responses 兼容接口，自动补 /responses 与 /models。",
    baseHint: "例如 https://api.example.com/v1",
    icon: "openai",
    iconColor: "#0F766E",
  },
  {
    id: "openai_chat",
    title: "自定义 OpenAI",
    description: "OpenAI Chat Completions 兼容接口，自动补 /chat/completions。",
    baseHint: "例如 https://api.example.com/v1",
    icon: "openai",
    iconColor: "#2563EB",
  },
  {
    id: "anthropic",
    title: "自定义 Anthropic",
    description: "Anthropic Messages 兼容接口，自动补 /v1/messages。",
    baseHint: "例如 https://api.example.com",
    icon: "claude",
    iconColor: "#D97757",
  },
];

const envString = (
  config: Record<string, unknown> | undefined,
  key: string,
): string => {
  const env = config?.env;
  if (!env || typeof env !== "object" || Array.isArray(env)) return "";
  const value = (env as Record<string, unknown>)[key];
  return typeof value === "string" ? value : "";
};

export function ScienceProviderForm({
  submitLabel,
  onSubmit,
  onCancel,
  onSubmittingChange,
  initialData,
  showButtons = true,
}: ScienceProviderFormProps) {
  const { t } = useTranslation();
  const initialConfig = initialData?.settingsConfig;
  const initialDefaultModel =
    envString(initialConfig, "ANTHROPIC_MODEL") ||
    envString(initialConfig, "ANTHROPIC_DEFAULT_SONNET_MODEL");
  const initialApiFormat = (
    initialData?.meta?.apiFormat === "openai_chat" ||
    initialData?.meta?.apiFormat === "anthropic"
      ? initialData.meta.apiFormat
      : "openai_responses"
  ) as ScienceApiFormat;

  const [apiFormat, setApiFormat] =
    useState<ScienceApiFormat>(initialApiFormat);
  const [baseUrl, setBaseUrl] = useState(
    envString(initialConfig, "ANTHROPIC_BASE_URL"),
  );
  const [apiKey, setApiKey] = useState(
    envString(initialConfig, "ANTHROPIC_AUTH_TOKEN") ||
      envString(initialConfig, "ANTHROPIC_API_KEY"),
  );
  const [defaultModel, setDefaultModel] = useState(initialDefaultModel);
  const [qualityModel, setQualityModel] = useState(
    envString(initialConfig, "ANTHROPIC_DEFAULT_OPUS_MODEL") ||
      initialDefaultModel,
  );
  const [fastModel, setFastModel] = useState(
    envString(initialConfig, "ANTHROPIC_DEFAULT_HAIKU_MODEL") ||
      initialDefaultModel,
  );
  const [fableModel, setFableModel] = useState(
    envString(initialConfig, "ANTHROPIC_DEFAULT_FABLE_MODEL") ||
      envString(initialConfig, "ANTHROPIC_DEFAULT_OPUS_MODEL") ||
      initialDefaultModel,
  );
  const [fetchedModels, setFetchedModels] = useState<FetchedModel[]>([]);
  const [isFetchingModels, setIsFetchingModels] = useState(false);

  const form = useForm<ProviderFormData>({
    resolver: zodResolver(providerSchema),
    defaultValues: {
      name: initialData?.name ?? "",
      websiteUrl: initialData?.websiteUrl ?? "",
      notes: initialData?.notes ?? "",
      settingsConfig: JSON.stringify(initialConfig ?? { env: {} }, null, 2),
      icon: initialData?.icon ?? "openai",
      iconColor: initialData?.iconColor ?? "#0F766E",
    },
    mode: "onSubmit",
  });
  const { isSubmitting } = form.formState;

  useEffect(() => {
    onSubmittingChange?.(isSubmitting);
  }, [isSubmitting, onSubmittingChange]);

  const activeTemplate = useMemo(
    () =>
      SCIENCE_TEMPLATES.find((template) => template.id === apiFormat) ??
      SCIENCE_TEMPLATES[0],
    [apiFormat],
  );

  const handleTemplateChange = (template: ScienceTemplate) => {
    setApiFormat(template.id);
    if (!initialData && !form.getValues("name").trim()) {
      form.setValue("name", template.title);
    }
    if (!initialData) {
      form.setValue("icon", template.icon);
      form.setValue("iconColor", template.iconColor);
    }
  };

  const handleFetchModels = useCallback(async () => {
    if (!baseUrl.trim() || !apiKey.trim()) {
      showFetchModelsError(null, t, {
        hasApiKey: Boolean(apiKey.trim()),
        hasBaseUrl: Boolean(baseUrl.trim()),
      });
      return;
    }

    setIsFetchingModels(true);
    try {
      const models = await fetchModelsForConfig(
        baseUrl.trim(),
        apiKey.trim(),
        false,
      );
      setFetchedModels(models);
      if (models.length === 0) {
        toast.info(t("providerForm.fetchModelsEmpty"));
      } else {
        toast.success(
          t("providerForm.fetchModelsSuccess", { count: models.length }),
        );
      }
    } catch (error) {
      console.warn("[ScienceModelFetch] Failed:", error);
      showFetchModelsError(error, t);
    } finally {
      setIsFetchingModels(false);
    }
  }, [apiKey, baseUrl, t]);

  const buildSettingsConfig = () => {
    const config = structuredClone(initialConfig ?? {}) as Record<
      string,
      unknown
    >;
    const existingEnv =
      config.env && typeof config.env === "object" && !Array.isArray(config.env)
        ? (config.env as Record<string, unknown>)
        : {};
    const env: Record<string, unknown> = { ...existingEnv };

    env.ANTHROPIC_BASE_URL = baseUrl.trim();
    env.ANTHROPIC_AUTH_TOKEN = apiKey.trim();
    delete env.ANTHROPIC_API_KEY;
    env.ANTHROPIC_MODEL = defaultModel.trim();
    env.ANTHROPIC_DEFAULT_SONNET_MODEL = defaultModel.trim();
    env.ANTHROPIC_DEFAULT_OPUS_MODEL =
      qualityModel.trim() || defaultModel.trim();
    env.ANTHROPIC_DEFAULT_HAIKU_MODEL = fastModel.trim() || defaultModel.trim();
    env.ANTHROPIC_DEFAULT_FABLE_MODEL =
      fableModel.trim() || qualityModel.trim() || defaultModel.trim();
    config.env = env;
    return config;
  };

  const handleSubmit = async (values: ProviderFormData) => {
    if (
      !values.name.trim() ||
      !baseUrl.trim() ||
      !apiKey.trim() ||
      !defaultModel.trim()
    ) {
      toast.error(
        t("science.providerForm.required", {
          defaultValue: "请填写供应商名称、base_url、API Key 和默认模型。",
        }),
      );
      return;
    }

    const config = buildSettingsConfig();
    const meta: ProviderMeta = {
      ...(initialData?.meta ?? {}),
      apiFormat,
      apiKeyField: "ANTHROPIC_AUTH_TOKEN",
      isFullUrl: false,
      endpointAutoSelect: false,
      providerType: "science_custom",
    };
    const payload: ProviderFormValues = {
      ...values,
      name: values.name.trim(),
      websiteUrl: values.websiteUrl?.trim() ?? "",
      notes: values.notes?.trim() ?? "",
      settingsConfig: JSON.stringify(config, null, 2),
      presetCategory: initialData?.category ?? "custom",
      meta,
    };
    await onSubmit(payload);
  };

  const renderModel = (
    id: string,
    label: string,
    value: string,
    onChange: (value: string) => void,
    required = false,
  ) => (
    <FormItem>
      <FormLabel htmlFor={id}>
        {label}
        {required && <span className="ml-1 text-destructive">*</span>}
      </FormLabel>
      <ModelInputWithFetch
        id={id}
        value={value}
        onChange={onChange}
        placeholder="gpt-5.6-sol"
        fetchedModels={fetchedModels}
        isLoading={isFetchingModels}
      />
    </FormItem>
  );

  return (
    <Form {...form}>
      <form
        id="provider-form"
        onSubmit={form.handleSubmit(handleSubmit)}
        className="space-y-6 glass rounded-xl border border-white/10 p-6"
      >
        <div className="space-y-3">
          <div>
            <h3 className="text-sm font-semibold">
              {t("science.providerForm.source", {
                defaultValue: "Claude Science API 来源",
              })}
            </h3>
            <p className="mt-1 text-xs text-muted-foreground">
              {t("science.providerForm.sourceHint", {
                defaultValue:
                  "配置逻辑与 CSSwitch 一致；OpenAI 兼容地址填写 base root，417Switch 自动拼接实际请求路径。",
              })}
            </p>
          </div>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
            {SCIENCE_TEMPLATES.map((template) => {
              const selected = template.id === apiFormat;
              return (
                <button
                  key={template.id}
                  type="button"
                  onClick={() => handleTemplateChange(template)}
                  className={cn(
                    "rounded-xl border p-4 text-left transition-colors",
                    selected
                      ? "border-primary bg-primary/5 ring-1 ring-primary/30"
                      : "border-border hover:border-primary/40 hover:bg-muted/40",
                  )}
                >
                  <span className="block text-sm font-medium">
                    {template.title}
                  </span>
                  <span className="mt-1 block text-xs leading-relaxed text-muted-foreground">
                    {template.description}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        <BasicFormFields form={form} />

        <div className="space-y-2">
          <FormLabel htmlFor="science-base-url">
            base_url<span className="ml-1 text-destructive">*</span>
          </FormLabel>
          <Input
            id="science-base-url"
            value={baseUrl}
            onChange={(event) => setBaseUrl(event.target.value)}
            placeholder={activeTemplate.baseHint}
            autoComplete="off"
          />
          <p className="text-xs text-muted-foreground">
            {activeTemplate.description}
          </p>
        </div>

        <div className="space-y-2">
          <FormLabel htmlFor="science-api-key">
            API Key<span className="ml-1 text-destructive">*</span>
          </FormLabel>
          <Input
            id="science-api-key"
            type="password"
            value={apiKey}
            onChange={(event) => setApiKey(event.target.value)}
            placeholder="sk-..."
            autoComplete="new-password"
          />
        </div>

        <div className="space-y-3 border-t pt-5">
          <div className="flex items-center justify-between gap-3">
            <div>
              <FormLabel>
                {t("science.providerForm.models", {
                  defaultValue: "模型配置",
                })}
              </FormLabel>
              <p className="mt-1 text-xs text-muted-foreground">
                {t("science.providerForm.modelsHint", {
                  defaultValue:
                    "模型获取只提供候选项；最终保存的是下方四个输入框中明确选择的模型 ID。",
                })}
              </p>
            </div>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={handleFetchModels}
              disabled={isFetchingModels}
              className="shrink-0 gap-1.5"
            >
              {isFetchingModels ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Download className="h-4 w-4" />
              )}
              {t("providerForm.fetchModels")}
            </Button>
          </div>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            {renderModel(
              "science-default-model",
              t("science.providerForm.defaultModel", {
                defaultValue: "默认模型",
              }),
              defaultModel,
              setDefaultModel,
              true,
            )}
            {renderModel(
              "science-quality-model",
              t("science.providerForm.qualityModel", {
                defaultValue: "高质量模型",
              }),
              qualityModel,
              setQualityModel,
            )}
            {renderModel(
              "science-fast-model",
              t("science.providerForm.fastModel", {
                defaultValue: "快速模型",
              }),
              fastModel,
              setFastModel,
            )}
            {renderModel(
              "science-fable-model",
              t("science.providerForm.fableModel", {
                defaultValue: "Fable 模型",
              }),
              fableModel,
              setFableModel,
            )}
          </div>
        </div>

        <FormField
          control={form.control}
          name="settingsConfig"
          render={() => (
            <FormItem className="hidden">
              <FormControl>
                <input type="hidden" />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        {showButtons && (
          <div className="flex justify-end gap-2">
            <Button variant="outline" type="button" onClick={onCancel}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" disabled={isSubmitting}>
              {submitLabel}
            </Button>
          </div>
        )}
      </form>
    </Form>
  );
}
