"use client";

/**
 * The context that carries `useEncryptorState()`'s return value down to the
 * tab modules that used to be inline closures inside `EncryptorTool()`:
 * `secret-form.tsx`, `recovery-tab.tsx` and `shares-dialog.tsx`. A context
 * rather than threading each of those ~140 values through as props — the
 * parent already builds the one object every render, so this is the same
 * data reaching the same places at the same time, just not spelled out as a
 * prop list.
 */
import { createContext, useContext } from "react";
import type { useEncryptorState } from "./use-encryptor-state";

export type EncryptorContextValue = ReturnType<typeof useEncryptorState>;

export const EncryptorContext = createContext<EncryptorContextValue | null>(null);

export function useEncryptorContext(): EncryptorContextValue {
  const ctx = useContext(EncryptorContext);
  if (!ctx) {
    throw new Error("useEncryptorContext() must be used within EncryptorContext.Provider");
  }
  return ctx;
}
