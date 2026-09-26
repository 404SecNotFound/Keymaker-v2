"use client";

/**
 * The Encryptor tool's entry point and shell: the Tabs/sidebar/footer chrome
 * that was always the outermost layer of this file, now composing the tab
 * modules under `src/components/encryptor/` instead of rendering everything
 * inline.
 *
 * This file used to be one 6,459-line component. The state, effects and
 * handlers every tab reads or writes now live in
 * `encryptor/use-encryptor-state.ts`, reached here through one hook call and
 * handed down through `EncryptorContext` (`encryptor/context.tsx`) so the
 * tab modules do not each need a 140-item prop list. The Encrypt and Decrypt
 * tabs turned out to be one shared form rather than two — see
 * `encryptor/secret-form.tsx`'s header for why it is one module, not two —
 * and the Recovery page, the Workspace home page, the "save these shares"
 * dialog and the recovery-kit dialog each became their own module under the
 * same directory. Nothing here changes behaviour: every string, id,
 * `data-testid`, and handler is the one that was already here, moved rather
 * than rewritten.
 */
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { CommandBar } from "@/components/command-bar";
import { CameraScanDialog } from "@/components/camera-scan";
import { ContainerInspector } from "@/components/container-inspector";
import { DiceEntropyTool } from "@/components/dice-entropy-tool";
import { DocsGuide } from "@/components/docs-guide";
import { AudioStegoTool } from "@/components/audio-stego-tool";
import { PaperVault } from "@/components/paper-vault";
import { Search, Lock, Heart, ScrollText, LifeBuoy } from "lucide-react";
import { KEYM2_VERSION } from "@/lib/keym-v2";
import { EncryptorContext } from "./encryptor/context";
import { useEncryptorState } from "./encryptor/use-encryptor-state";
import { SecretForm } from "./encryptor/secret-form";
import { WorkspaceTab } from "./encryptor/workspace-tab";
import { RecoveryTab } from "./encryptor/recovery-tab";
import { SharesDialog } from "./encryptor/shares-dialog";
import { RecoveryKitDialog } from "./encryptor/recovery-kit-dialog";
import { BASE_PATH, KEYMAKER_REPO, APP_VERSION, IS_RELEASE_BUILD, DOORS } from "./encryptor/shared";

export function EncryptorTool() {
  const state = useEncryptorState();
  const {
    mode, workspacePage, compactNavigation, isLoading, qrScanBusy,
    isApplePlatform, setIsCommandBarOpen, isCommandBarOpen, navItems,
    pageCopy, activePage, navigateWorkspace, currentDoor, openDoor,
    openInheritance, inspectorPlan, sealedPeek, decryptPeek,
    commandBarCommands, paperVault, cameraOpen, setCameraOpen,
    handleQrImageFiles, setIsRecoveryOpen,
  } = state;

  return (
    <EncryptorContext.Provider value={state}>
    <Tabs value={activePage} onValueChange={navigateWorkspace} orientation={compactNavigation ? "horizontal" : "vertical"} className="km-app flex min-h-screen flex-col">
      <header className="km-topbar">
        <div className="km-brand">
          <img src={`${BASE_PATH}/logo.svg`} alt="Keymaker" width={24} height={24} />
          <span>Keymaker</span>
          <span className="km-brand-divider" aria-hidden="true" />
          <span className="km-topbar-context">Secure workspace</span>
        </div>
        <button
          type="button"
          onClick={() => setIsCommandBarOpen(true)}
          aria-label="Open the command menu"
          data-testid="command-bar-hint"
          className="km-command"
        >
          <Search className="h-4 w-4" aria-hidden="true" />
          <span>Search commands</span>
          <kbd>{isApplePlatform ? "⌘" : "Ctrl"} K</kbd>
        </button>
      </header>
      <div className="km-shell">
        <aside className="km-sidebar" aria-label="Workspace navigation">
          <p className="km-nav-label">WORKSPACE</p>
          <TabsList className="km-navigation" aria-label="Workspace views">
            {navItems.map(({ id, label, icon: Icon }) => (
              <TabsTrigger
                key={id}
                value={id}
                disabled={(id === "workspace" || id === "recovery" || id === "docs") && (isLoading || qrScanBusy)}
                className="km-nav-item"
              >
                <Icon className="h-4 w-4" aria-hidden="true" />
                {label}
              </TabsTrigger>
            ))}
          </TabsList>
          <div className="km-sidebar-foot">
            <Lock className="h-4 w-4" aria-hidden="true" />
            <div><p>Local by design</p><span>Encryption runs in your browser.</span></div>
          </div>
        </aside>
        <div className="km-main">
          <div className="km-page-heading">
            <p className="km-breadcrumb">Workspace <span aria-hidden="true">/</span> {pageCopy[activePage][0]}</p>
            <h1>{pageCopy[activePage][0]}</h1>
            <p>{pageCopy[activePage][1]}</p>
          </div>

          <WorkspaceTab />
          <RecoveryTab />
          <TabsContent value="docs" className="mt-0" tabIndex={-1}>
            <DocsGuide onNavigate={navigateWorkspace} assetBase={BASE_PATH} />
          </TabsContent>

          <div hidden={workspacePage !== "workbench"}>
            {(mode === "encrypt" || mode === "decrypt") && (
              <div className="km-intents" role="group" aria-label="Start with" data-testid="intent-doors">
                {DOORS.map(({ id, icon: Icon, title }) => (
                  <button key={id} type="button" onClick={() => openDoor(id)} aria-pressed={currentDoor === id} data-testid={`door-${id}`}>
                    <Icon className="h-4 w-4" aria-hidden="true" />{title}
                  </button>
                ))}
              </div>
            )}
            <div className={mode === "tools" || mode === "audio" ? "km-utility-panel" : "km-workbench"}>
              <section className="km-editor">
                <TabsContent value="encrypt" className="mt-0" tabIndex={-1}><SecretForm mode="encrypt" /></TabsContent>
                <TabsContent value="decrypt" className="mt-0" tabIndex={-1}><SecretForm mode="decrypt" /></TabsContent>
                <TabsContent value="audio" className="mt-0" tabIndex={-1}><AudioStegoTool /></TabsContent>
                <TabsContent value="tools" className="mt-0" tabIndex={-1} forceMount hidden={mode !== "tools" || workspacePage !== "workbench"}><DiceEntropyTool /></TabsContent>
              </section>
              {workspacePage === "workbench" && (mode === "encrypt" || mode === "decrypt") && (
                <ContainerInspector mode={mode} plan={inspectorPlan} peek={mode === "encrypt" ? sealedPeek : decryptPeek} sealing={isLoading && mode === "encrypt"} className="km-inspector" />
              )}
            </div>
            {(mode === "encrypt" || mode === "decrypt") && (
              <button type="button" onClick={openInheritance} data-testid="inheritance-open" className="km-inheritance-link">
                <ScrollText className="h-3.5 w-3.5" aria-hidden="true" />Planning for someone to inherit this? Set up an inheritance plan.
              </button>
            )}
          </div>
        </div>
      </div>

      {/* ---- FOOTER ---- */}
      <footer className="w-full border-t border-border">
        <div className="mx-auto flex max-w-5xl flex-col items-center gap-2 px-4 py-5 text-xs text-muted-foreground sm:flex-row sm:justify-between sm:px-6">
          <div className="flex items-center gap-1.5">
            <Heart className="h-3.5 w-3.5 text-subtle-foreground" />
            <span>
              Keymaker is a fork of{' '}
              <a href="https://github.com/seQRets/ittybitz" target="_blank" rel="noopener noreferrer" className="text-foreground underline underline-offset-4 decoration-1">
                IttyBitz
              </a>{' '}
              by seQRets (GPL-3).
            </span>
          </div>
          {/*
            U8. These two are standalone footer controls, not links inside a
            sentence, so WCAG 2.5.8's inline exception does not cover them and
            16px tall is simply too small to hit. `py-1.5` takes both past 24px;
            the negative margin keeps the footer's own spacing where it was.
          */}
          <div className="-my-1.5 flex items-center gap-3">
            <button
              type="button"
              onClick={() => setIsRecoveryOpen(true)}
              className="flex cursor-pointer items-center gap-1.5 py-1.5 text-foreground hover:underline"
            >
              <LifeBuoy className="h-3.5 w-3.5" />
              Recovery kit
            </button>
            <a href={KEYMAKER_REPO} target="_blank" rel="noopener noreferrer" className="py-1.5 hover:underline">GitHub</a>
            {/*
              6.3. The signed manifest and the reproducible build had existed
              for a while and were reachable only from a document in the repo —
              the one place someone worried about the *served* bundle has no
              particular reason to look.

              `.html` rather than a bare `/verify`: the export emits verify.html
              beside a verify/ directory of router payloads, so the
              extensionless path resolves to a directory with no index and 404s.
            */}
            <a href={`${BASE_PATH}/verify.html`} className="py-1.5 hover:underline">
              Verify this build
            </a>
            {/*
              6.1. Two numbers, stated separately and on purpose.

              The app version comes from package.json at build time, so there is
              no second literal to drift from it. The format version is what a
              *container* is, and moves only when the format does — §9 of the v2
              design says that is now frozen.

              Both appear because this is the line someone reads out when a file
              will not open, and "v2" alone does not say whether they mean the
              app or the file.
            */}
            <span>
              Keymaker v{APP_VERSION}
              {/*
                Only on a rolling build. A release says nothing extra, because
                there the version is the whole truth; a development build has
                to admit it is ahead of the tag it is naming. The verify page
                carries the commit, which is what turns this from a caveat into
                something actionable.
              */}
              {!IS_RELEASE_BUILD && (
                <span className="text-subtle-foreground">-dev</span>
              )}
              {/* Read from the constant, not typed out. This said "writes KEYM
                  v2" for as long as the app had been writing v3 — a footer
                  whose whole purpose is to tell someone which format they are
                  holding, telling them the wrong one. A literal here is a
                  claim that has to be remembered; a constant is one that
                  cannot go stale. */}
              <span className="text-subtle-foreground">
                {` · writes KEYM v${KEYM2_VERSION}`}
              </span>
            </span>
          </div>
        </div>
      </footer>

      {/*
        The recovery kit.

        Everything else in this app is about the container being safe. This is
        about it being *openable* — years from now, by someone who did not
        choose this tool, when the website is gone. Both files are served from
        this origin and precached by the service worker, so this dialog works
        offline and travels with the app rather than pointing at a repository
        the user may never find.
      */}
      {/*
        §4.6. The share set, shown exactly once.

        `onOpenChange` only ever closes — there is no reopening this, because
        there is nothing left to reopen it from: the share secret was discarded
        inside the worker the moment the slot was wrapped, so these strings are
        the only copies that will ever exist. That is a property of the format,
        not a limitation of this dialog, and the copy says so plainly rather
        than letting someone discover it by closing the window.
      */}
      <CommandBar
        open={isCommandBarOpen}
        onOpenChange={setIsCommandBarOpen}
        commands={commandBarCommands}
      />
      <SharesDialog />
      {/*
        4.2. The paper vault sheet. Hidden on screen by `.paper-vault` in
        globals.css and made the only visible element inside `@media print`, so
        it does not need to sit at the document root to print cleanly.
      */}
      {paperVault ? (
        <PaperVault
          container={paperVault.container}
          parts={paperVault.parts}
          tooLarge={paperVault.tooLarge}
          shares={paperVault.shares}
          threshold={paperVault.threshold}
          sharesNeedPassword={paperVault.sharesNeedPassword}
          setCodes={paperVault.setCodes}
          stripBackupPart={paperVault.stripBackupPart}
          printedOn={paperVault.printedOn}
          rehearsal={paperVault.rehearsal}
        />
      ) : null}

      {/*
        The live camera scanner. Its codes take the scanned-image path, so a
        strip read by the camera lands in the shares box and a container
        symbol in the container box, exactly as a photo of either would.
      */}
      <CameraScanDialog
        open={cameraOpen}
        onOpenChange={setCameraOpen}
        onDone={(codes) => void handleQrImageFiles([], codes)}
      />

      <RecoveryKitDialog />
    </Tabs>
    </EncryptorContext.Provider>
  );
}
