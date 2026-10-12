/** State of the reporter's decrypted file list ("Your files").
 *
 * A refresh (after any action, "Check for updates" or new evidence) re-lists
 * the files but keeps the previous list on screen: replacing it with a loading
 * message would unmount each row, and unmounting a download row cancels its
 * in-progress download (EvidenceDownloadButton). Only the first listing shows
 * a loading state, and a failed refresh keeps the list with a short notice. */
export type OwnerFileListState<F> =
  | { kind: "loading" }
  | { kind: "error" }
  | { kind: "ready"; files: F[]; refreshing: boolean; refreshFailed: boolean };

export type OwnerFileListEvent<F> =
  | { type: "start" }
  | { type: "loaded"; files: F[] }
  | { type: "failed" };

export function ownerFileListReducer<F>(state: OwnerFileListState<F>, event: OwnerFileListEvent<F>): OwnerFileListState<F> {
  switch (event.type) {
    case "start":
      return state.kind === "ready" ? { ...state, refreshing: true, refreshFailed: false } : { kind: "loading" };
    case "loaded":
      return { kind: "ready", files: event.files, refreshing: false, refreshFailed: false };
    case "failed":
      return state.kind === "ready" ? { ...state, refreshing: false, refreshFailed: true } : { kind: "error" };
  }
}
