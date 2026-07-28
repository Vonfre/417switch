import { invoke } from "@tauri-apps/api/core";

export interface ScienceStatus {
  supported: boolean;
  installed: boolean;
  running: boolean;
  healthy: boolean;
  port: number;
  providerName?: string;
  runtimeSource?: string;
  runtimeVersion?: string;
  message?: string;
}

export interface ScienceStartResult {
  url: string;
  providerName: string;
  runtimeSource: string;
  runtimeVersion: string;
}

export const scienceApi = {
  getStatus(): Promise<ScienceStatus> {
    return invoke("get_science_status");
  },
  start(): Promise<ScienceStartResult> {
    return invoke("start_science");
  },
  stop(): Promise<void> {
    return invoke("stop_science");
  },
  open(): Promise<string> {
    return invoke("open_science");
  },
};
