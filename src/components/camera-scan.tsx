"use client";

import { useEffect, useRef, useState } from "react";
import { Camera } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { decodeAllQrInFrame } from "@/lib/qr-decode";
import { cameraProgress, describeCameraProgress } from "@/lib/camera-progress";

/**
 * Live camera scanning for a printed backup.
 *
 * Photographing each strip and choosing the files is five steps per strip.
 * Holding the strips up to a camera one after another is one, and this is
 * that: the camera stays open, every code it sees is read, and the dialog
 * says what is in and what is still needed until there is enough, then hands
 * everything to the same routing a scanned image takes.
 *
 * What counts as enough is `cameraProgress`'s rule (src/lib/camera-progress.ts).
 *
 * Nothing is decoded here beyond reading the codes' own headers: no share is
 * combined and no key derived. The frames never leave the page (the CSP has
 * `connect-src 'none'`), and the camera is released the moment the dialog
 * closes, however it closes.
 */

/** How often a frame is read. A camera at 30 fps gives far more than jsqr can
 *  use; a few reads a second is responsive and leaves the page usable. */
const FRAME_INTERVAL_MS = 250;

export function CameraScanDialog({
  open,
  onOpenChange,
  onDone,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Everything read, once there is enough or the person stops early. */
  onDone: (codes: string[]) => void;
}) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const codesRef = useRef<string[]>([]);
  const [codes, setCodes] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);

  useEffect(() => {
    if (!open) return;
    let stream: MediaStream | null = null;
    let timer: number | undefined;
    let busy = false;
    let cancelled = false;
    codesRef.current = [];
    setCodes([]);
    setError(null);
    setStarting(true);

    const finish = (all: string[]) => {
      cancelled = true;
      onDone(all);
      onOpenChange(false);
    };

    (async () => {
      if (!navigator.mediaDevices?.getUserMedia) {
        setError("This browser does not offer a camera to web pages. Photograph the codes and choose the pictures instead.");
        setStarting(false);
        return;
      }
      try {
        stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: "environment", width: { ideal: 1280 }, height: { ideal: 720 } },
          audio: false,
        });
      } catch (e) {
        const name = (e as { name?: string }).name;
        setError(
          name === "NotAllowedError"
            ? "The camera was not allowed. Allow it for this page, or photograph the codes and choose the pictures instead."
            : "No camera could be opened. Photograph the codes and choose the pictures instead."
        );
        setStarting(false);
        return;
      }
      if (cancelled) {
        stream.getTracks().forEach((t) => t.stop());
        return;
      }
      const video = videoRef.current;
      if (!video) return;
      video.srcObject = stream;
      await video.play().catch(() => undefined);
      setStarting(false);
      canvasRef.current ??= document.createElement("canvas");

      timer = window.setInterval(async () => {
        if (busy || cancelled) return;
        busy = true;
        try {
          const read = await decodeAllQrInFrame(video, canvasRef.current as HTMLCanvasElement);
          const fresh = read.filter((c) => !codesRef.current.includes(c));
          if (fresh.length > 0 && !cancelled) {
            codesRef.current = [...codesRef.current, ...fresh];
            setCodes(codesRef.current);
            if (cameraProgress(codesRef.current).complete) finish(codesRef.current);
          }
        } catch {
          // A frame that fails to read is the next frame's problem.
        } finally {
          busy = false;
        }
      }, FRAME_INTERVAL_MS);
    })();

    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearInterval(timer);
      stream?.getTracks().forEach((t) => t.stop());
      const video = videoRef.current;
      if (video) video.srcObject = null;
    };
    // onDone and onOpenChange are the parent's; the camera must not restart
    // because a parent re-rendered with a new closure.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const progress = cameraProgress(codes);
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg" data-testid="camera-scan">
        <DialogHeader>
          <DialogTitle>Scan with the camera</DialogTitle>
          <DialogDescription>
            Hold each recovery strip or container symbol up to the camera, one after another. Nothing
            leaves this page, and the camera turns off when this closes.
          </DialogDescription>
        </DialogHeader>
        {error ? (
          <p role="alert" className="rounded-md bg-warning/10 px-3 py-2 text-[13px] text-warning">
            {error}
          </p>
        ) : (
          <div className="overflow-hidden rounded-lg border border-border bg-inset">
            <video
              ref={videoRef}
              muted
              playsInline
              aria-label="Camera preview"
              className="block aspect-video w-full object-cover"
            />
          </div>
        )}
        <div aria-live="polite" data-testid="camera-progress" className="space-y-1 text-[13px] text-foreground">
          {starting ? <p>Opening the camera…</p> : describeCameraProgress(progress).map((l) => <p key={l}>{l}</p>)}
        </div>
        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            disabled={codes.length === 0}
            onClick={() => {
              onDone(codesRef.current);
              onOpenChange(false);
            }}
          >
            <Camera className="h-4 w-4" />
            Use what was read
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
