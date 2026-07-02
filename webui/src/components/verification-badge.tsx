import { ShieldCheck, ShieldAlert } from "lucide-react";
import { cn } from "@/lib/utils";

export const TAG_VERIFIED = "verified";
export const TAG_MANUAL_REVIEW = "needs-manual-verification";

// VerificationBadge shows, at a glance, whether a finding was independently
// reproduced by the Verifier ("Verified") or preserved but still needs a human
// to confirm it ("Manual verification needed"). It reads the machine tags the
// backend attaches, falling back to the boolean `verified` flag.
export function VerificationBadge({
  verified,
  tags,
  className,
}: {
  verified?: boolean;
  tags?: string[];
  className?: string;
}) {
  const isVerified =
    (tags?.includes(TAG_VERIFIED) ?? false) || verified === true;
  const needsReview =
    (tags?.includes(TAG_MANUAL_REVIEW) ?? false) ||
    (verified === false && !isVerified);

  if (isVerified) {
    return (
      <span
        className={cn(
          "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide",
          "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
          className,
        )}
        title="Independently reproduced by the Verifier"
      >
        <ShieldCheck className="h-3 w-3" aria-hidden />
        Verified
      </span>
    );
  }
  if (needsReview) {
    return (
      <span
        className={cn(
          "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide",
          "bg-amber-500/10 text-amber-400 border-amber-500/30",
          className,
        )}
        title="Preserved but not independently confirmed — verify manually before relying on it"
      >
        <ShieldAlert className="h-3 w-3" aria-hidden />
        Manual verification needed
      </span>
    );
  }
  return null;
}
