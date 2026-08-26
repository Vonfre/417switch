export interface ScienceControlPendingState {
  isLoading: boolean;
  isStarting: boolean;
  isRunning: boolean;
  isStopping: boolean;
  isOpening: boolean;
}

export function isScienceControlPending({
  isLoading,
  isStarting,
  isRunning,
  isStopping,
  isOpening,
}: ScienceControlPendingState): boolean {
  return isLoading || (isStarting && !isRunning) || isStopping || isOpening;
}
