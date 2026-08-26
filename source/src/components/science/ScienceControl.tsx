import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink, Loader2, Play, Square } from "lucide-react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { scienceApi } from "@/lib/api";
import { extractErrorMessage } from "@/utils/errorUtils";

import { isScienceControlPending } from "./scienceControlState";

const scienceKey = ["scienceStatus"] as const;

export function ScienceControl() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const refresh = () => queryClient.invalidateQueries({ queryKey: scienceKey });

  const startMutation = useMutation({
    mutationFn: scienceApi.start,
    onSuccess: (result) => {
      toast.success(
        t("science.started", {
          provider: result.providerName,
          defaultValue: `Claude Science 已启动，当前使用 ${result.providerName}`,
        }),
      );
      refresh();
    },
    onError: (error) =>
      toast.error(
        t("science.startFailed", {
          detail: extractErrorMessage(error),
          defaultValue: `启动 Claude Science 失败：${extractErrorMessage(error)}`,
        }),
      ),
  });

  const { data: status, isLoading } = useQuery({
    queryKey: scienceKey,
    queryFn: scienceApi.getStatus,
    refetchInterval: (query) =>
      startMutation.isPending || query.state.data?.running ? 3000 : 15000,
    placeholderData: (previous) => previous,
  });

  const stopMutation = useMutation({
    mutationFn: scienceApi.stop,
    onSuccess: () => {
      toast.success(
        t("science.stopped", { defaultValue: "Claude Science 已停止" }),
      );
      refresh();
    },
    onError: (error) =>
      toast.error(
        t("science.stopFailed", {
          detail: extractErrorMessage(error),
          defaultValue: `停止 Claude Science 失败：${extractErrorMessage(error)}`,
        }),
      ),
  });

  const openMutation = useMutation({
    mutationFn: scienceApi.open,
    onError: (error) =>
      toast.error(
        t("science.openFailed", {
          detail: extractErrorMessage(error),
          defaultValue: `打开 Claude Science 失败：${extractErrorMessage(error)}`,
        }),
      ),
  });

  const pending = isScienceControlPending({
    isLoading,
    isStarting: startMutation.isPending,
    isRunning: Boolean(status?.running),
    isStopping: stopMutation.isPending,
    isOpening: openMutation.isPending,
  });
  const unavailable = status && (!status.supported || !status.installed);
  const title = status?.running
    ? t("science.runningTitle", {
        provider: status.providerName ?? "Claude Provider",
        version: status.runtimeVersion ?? "",
        defaultValue: `Claude Science 运行中 · ${status.providerName ?? "Claude Provider"} · ${status.runtimeVersion ?? ""}`,
      })
    : (status?.message ??
      t("science.startTitle", {
        provider: status?.providerName ?? "Claude Provider",
        defaultValue: `使用当前 ${status?.providerName ?? "Claude Provider"} 启动 Claude Science`,
      }));

  return (
    <div className="flex items-center gap-1 rounded-xl bg-muted p-1">
      <Button
        variant="ghost"
        size="sm"
        disabled={pending || Boolean(unavailable)}
        onClick={() =>
          status?.running ? openMutation.mutate() : startMutation.mutate()
        }
        className="h-8 gap-1.5 px-3 text-muted-foreground hover:bg-background/50 hover:text-foreground"
        title={title}
      >
        {pending ? (
          <Loader2 className="h-4 w-4 animate-spin" />
        ) : status?.running ? (
          <ExternalLink className="h-4 w-4" />
        ) : (
          <Play className="h-4 w-4" />
        )}
        {status?.running
          ? t("science.open", { defaultValue: "打开 Science" })
          : t("science.start", { defaultValue: "启动 Science" })}
      </Button>
      {status?.running && (
        <Button
          variant="ghost"
          size="sm"
          disabled={pending}
          onClick={() => stopMutation.mutate()}
          className="h-8 w-7 px-1 text-muted-foreground hover:bg-background/50 hover:text-red-500"
          title={t("science.stop", { defaultValue: "停止 Claude Science" })}
        >
          <Square className="h-3.5 w-3.5" />
        </Button>
      )}
    </div>
  );
}
