import { Loader2, Radio } from "lucide-react";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";
import { Switch } from "@/components/ui/switch";
import { useProxyStatus } from "@/hooks/useProxyStatus";
import { scienceApi } from "@/lib/api";
import { cn } from "@/lib/utils";

interface ClaudeDesktopRouteToggleProps {
  className?: string;
}

export function ClaudeDesktopRouteToggle({
  className,
}: ClaudeDesktopRouteToggleProps) {
  const { t } = useTranslation();
  const {
    isRunning,
    status,
    takeoverStatus,
    startProxyServer,
    stopProxyServer,
    isStarting,
    isStoppingServer,
  } = useProxyStatus();

  const isBusy = isStarting || isStoppingServer;
  const activeTakeoverApps = [
    takeoverStatus?.claude && "Claude Code",
    takeoverStatus?.codex && "Codex",
    takeoverStatus?.gemini && "Gemini CLI",
    takeoverStatus?.grokbuild && "Grok Build",
  ].filter((value): value is string => Boolean(value));
  const otherTakeoverActive = activeTakeoverApps.length > 0;
  const routeAddress = status?.address ?? "127.0.0.1";
  const routePort = status?.port ?? 41721;

  const handleToggle = async (checked: boolean) => {
    try {
      if (checked) {
        await startProxyServer();
        return;
      }

      const scienceStatus = await scienceApi.getStatus();
      if (scienceStatus.running || scienceStatus.healthy) {
        toast.warning(
          t("claudeDesktop.route.stopBlockedByScience", {
            defaultValue:
              "共享本地路由正在供 Claude Science 使用，Claude Desktop 路由也已经可用，无需重复开启。这不是路由冲突；如需关闭服务，请先停止 Claude Science。",
          }),
          { duration: 5000 },
        );
        return;
      }

      if (otherTakeoverActive) {
        toast.warning(
          t("claudeDesktop.route.stopBlockedByTakeover", {
            apps: activeTakeoverApps.join("、"),
            defaultValue: `417Switch 的 ${activeTakeoverApps.join("、")} 接管正在使用共享本地路由；这不是 CCSwitch 进程冲突。请先关闭对应应用接管，再停止路由。`,
          }),
          { duration: 5000 },
        );
        return;
      }

      await stopProxyServer();
    } catch (error) {
      console.error("[ClaudeDesktopRouteToggle] Toggle route failed:", error);
    }
  };

  const tooltipText = isRunning
    ? t("claudeDesktop.route.tooltip.active", {
        address: routeAddress,
        port: routePort,
        defaultValue: `Claude Desktop 本地路由已开启 - ${routeAddress}:${routePort}`,
      })
    : t("claudeDesktop.route.tooltip.inactive", {
        address: routeAddress,
        port: routePort,
        defaultValue: `开启 Claude Desktop 本地路由，用于需要模型映射或格式转换的供应商。当前配置地址：${routeAddress}:${routePort}`,
      });

  return (
    <div
      className={cn(
        "flex items-center gap-1 px-1.5 h-8 rounded-lg bg-muted/50 transition-all",
        className,
      )}
      title={tooltipText}
    >
      {isBusy ? (
        <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
      ) : (
        <Radio
          className={cn(
            "h-4 w-4 transition-colors",
            isRunning
              ? "text-emerald-500 status-heartbeat"
              : "text-muted-foreground",
          )}
        />
      )}
      <Switch
        checked={isRunning}
        onCheckedChange={handleToggle}
        disabled={isBusy}
      />
    </div>
  );
}
