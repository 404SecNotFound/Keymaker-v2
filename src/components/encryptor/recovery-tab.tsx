"use client";

/**
 * The Recovery workspace page: the current session's backup, a way to test
 * it, and a way to check a printout. Moved verbatim out of
 * `encryptor-tool.tsx`'s `TabsContent value="recovery"` block.
 */
import { Download, Printer, ShieldCheck, KeyRound, QrCode, TriangleAlert, CheckCircle2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { TabsContent } from "@/components/ui/tabs";
import { BASE_PATH, formatBytes } from "./shared";
import { useEncryptorContext } from "./context";

export function RecoveryTab() {
  const {
    mode, receipt, rehearsal, downloadContainer, printPaperVault,
    handleModeChange, returnToBackupTest, printoutInputRef, checkPrintout,
    printoutBusy, printoutFindings, setIsRecoveryOpen, openInheritance,
  } = useEncryptorContext();

  return (
    <TabsContent value="recovery" className="mt-0" tabIndex={-1}>
      <div className="km-recovery-grid">
        <section className="km-form-section" aria-labelledby="recovery-current-title">
          <div className="km-section-heading"><span className="km-section-number">01</span><h2 id="recovery-current-title">Current backup</h2></div>
          {mode === "encrypt" && receipt ? (
            <>
              <p className="text-sm text-foreground">Container created · {formatBytes(receipt.bytes)}</p>
              <p className="mt-2 text-[13px] leading-relaxed text-muted-foreground">{receipt.cipher} · {receipt.kdf}</p>
              <dl className="km-recovery-facts">
                <div><dt>Recovery shares</dt><dd>{receipt.shares ? `${receipt.shares.threshold} of ${receipt.shares.count} needed` : "Not included"}</dd></div>
                <div><dt>Saved copy</dt><dd>{receipt.onScreen ? "Not saved yet. It is on screen: download it or print the paper backup" : "Downloaded when encryption finished. Check your downloads folder"}</dd></div>
                <div><dt>Recovery test</dt><dd>{rehearsal.kind === "ok" ? `Rehearsed on ${rehearsal.on}${rehearsal.strips.length > 0 ? ` with strips ${rehearsal.strips.join(" and ")}` : ""}` : "Not tested yet in this session"}</dd></div>
              </dl>
              {receipt.onScreen ? (
                <div className="km-action-row">
                  <Button onClick={downloadContainer}><Download className="h-4 w-4" />Download container</Button>
                  <Button variant="outline" onClick={() => void printPaperVault()}><Printer className="h-4 w-4" />Paper backup</Button>
                </div>
              ) : <p className="km-help">The file download was requested when encryption finished. Keymaker kept only its header; load your saved file to test it.</p>}
            </>
          ) : (
            <>
              <p className="text-[13px] leading-relaxed text-muted-foreground">No newly created backup in this session. Encrypt content to prepare a paper backup, or test a container you have already saved.</p>
              <Button className="mt-5" onClick={() => handleModeChange("encrypt")}>Go to Encrypt</Button>
            </>
          )}
        </section>
        <section className="km-form-section" aria-labelledby="recovery-test-title">
          <div className="km-section-heading"><span className="km-section-number">02</span><h2 id="recovery-test-title">Test a way back in</h2></div>
          <p className="text-[13px] leading-relaxed text-muted-foreground">Verification checks whether your backup opens. It does not display or download the decrypted contents.</p>
          <div className="km-recovery-options">
            <Button variant="outline" onClick={() => returnToBackupTest(false)}><ShieldCheck className="h-4 w-4" />Verify with password</Button>
            <Button variant="outline" onClick={() => returnToBackupTest(true)}><KeyRound className="h-4 w-4" />Verify with recovery shares</Button>
          </div>
          <p className="km-help">Test each method you plan to rely on. A successful password test does not prove that your shares work.</p>
          {/*
            "Check this printout": the step before a rehearsal. It needs
            no password and no strips beyond the one in the photo, and
            it opens nothing, so it can be run on every sheet the moment
            it comes out of the printer.
          */}
          <div className="km-printout-check" data-testid="printout-check">
            <h3 id="printout-check-title" className="text-[13px] font-medium text-foreground">Check a printout</h3>
            <p className="km-help">
              Photograph printed recovery strips or container symbols, one at a time or a whole sheet at once. Keymaker confirms each code reads back intact
              {mode === "encrypt" && receipt
                ? " and belongs to the backup created in this session."
                : ". There is no backup from this session to compare it with, so it cannot say which backup it belongs to."}{" "}
              Nothing is opened and no password is needed.
            </p>
            <input
              ref={printoutInputRef}
              id="printout-check-input"
              type="file"
              accept="image/png,image/jpeg,image/webp"
              multiple
              className="hidden"
              aria-labelledby="printout-check-title"
              onChange={(e) => {
                const files = Array.from(e.target.files ?? []);
                e.target.value = "";
                void checkPrintout(files);
              }}
            />
            <Button variant="outline" disabled={printoutBusy} onClick={() => printoutInputRef.current?.click()}>
              <QrCode className="h-4 w-4" />
              {printoutBusy ? "Reading photos…" : "Choose photos of the printout"}
            </Button>
            {printoutFindings ? (
              <ul className="km-printout-results" data-testid="printout-results" aria-live="polite">
                {printoutFindings.map((r, i) => (
                  <li key={`${i}-${r.file}`} data-problem={r.problem ? "true" : "false"}>
                    {r.problem ? (
                      <TriangleAlert className="h-4 w-4 text-warning" aria-hidden="true" />
                    ) : (
                      <CheckCircle2 className="h-4 w-4 text-success" aria-hidden="true" />
                    )}
                    <span>
                      <span className="km-printout-file">{r.file}</span> {r.text}
                    </span>
                  </li>
                ))}
              </ul>
            ) : null}
          </div>
        </section>
        <figure className="km-art km-art-wide">
          <img src={`${BASE_PATH}/art-key-shards.webp`} alt="A key broken into three shards on separate plates, hairline paths leading back to a keyhole, a folded printed sheet beside one shard" width={2100} height={900} loading="lazy" decoding="async" />
        </figure>
        <section className="km-form-section km-recovery-reference" aria-labelledby="recovery-offline-title">
          <div><h2 id="recovery-offline-title">Recovery without this app</h2><p>The standalone recovery kit and an inheritance plan help you prepare for someone else opening your backup.</p></div>
          <div className="km-action-row">
            <Button variant="outline" onClick={() => setIsRecoveryOpen(true)}>Open recovery kit</Button>
            <Button variant="outline" onClick={openInheritance}>Set up inheritance</Button>
          </div>
        </section>
      </div>
    </TabsContent>
  );
}
