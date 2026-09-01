import * as React from "react"
import { Slot } from "@radix-ui/react-slot"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

// Pills, always with a 1px border — the filled primary included, which is what
// keeps it reading as ink on paper rather than as a floating block. The primary
// action is the highest-contrast neutral; the only coloured button in the app
// is a destructive confirmation.
//
// Disabled is a named state, not a fraction of the enabled one. This was
// `disabled:opacity-50`, which on the filled primary composites #F5F3F1 over
// the near-black canvas into a mid grey pill — indistinguishable from an
// ordinary button, so the most important control in the app announced itself
// in the treatment reserved for controls you cannot use. It is also the same
// defect the palette forbids in `text-body/60` form, one level up: dimming the
// element instead of choosing a tone, so nobody decides the result.
//
// A disabled control now stops being filled: no background, `line` border,
// `muted` label. Fill, border and text move together, so the difference
// survives greyscale and a glance. See DESIGN-SYSTEM.md § Disabled.
const buttonVariants = cva(
  // `transition-colors` grew two entries: `scale`, so the press state below
  // eases instead of snapping, and nothing else — the press is the one
  // transform a button owns. 0.985 is deliberate: at pill sizes a deeper
  // squash reads as wobble, and this is feedback, not theatre.
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-full border text-sm font-medium ring-offset-background transition-[color,background-color,border-color,scale] active:scale-[0.985] focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:cursor-not-allowed disabled:border-border disabled:bg-transparent disabled:text-subtle-foreground [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        default:
          "border-primary-hover bg-primary text-primary-foreground hover:bg-primary-hover",
        destructive:
          "border-destructive bg-destructive text-destructive-foreground hover:bg-destructive/90",
        outline:
          "border-border bg-transparent text-muted-foreground hover:border-border-strong hover:text-foreground",
        secondary:
          "border-border bg-inset text-muted-foreground hover:border-border-strong hover:text-foreground",
        ghost:
          "border-transparent text-muted-foreground hover:bg-inset hover:text-foreground",
        link: "border-transparent text-foreground underline-offset-4 hover:underline",
      },
      size: {
        default: "h-10 px-4 py-2",
        sm: "h-9 px-3",
        lg: "h-11 px-8",
        icon: "h-10 w-10",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
)

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button"
    return (
      <Comp
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    )
  }
)
Button.displayName = "Button"

export { Button, buttonVariants }
