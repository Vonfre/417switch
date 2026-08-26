import { describe, expect, it } from "vitest";

import { isScienceControlPending } from "@/components/science/scienceControlState";

describe("isScienceControlPending", () => {
  it("releases the loading state once Science is independently confirmed running", () => {
    expect(
      isScienceControlPending({
        isLoading: false,
        isStarting: true,
        isRunning: true,
        isStopping: false,
        isOpening: false,
      }),
    ).toBe(false);
  });

  it("keeps the loading state while startup is pending and Science is not ready", () => {
    expect(
      isScienceControlPending({
        isLoading: false,
        isStarting: true,
        isRunning: false,
        isStopping: false,
        isOpening: false,
      }),
    ).toBe(true);
  });
});
