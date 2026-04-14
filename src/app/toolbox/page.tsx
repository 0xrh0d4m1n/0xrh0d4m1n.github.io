import type { Metadata } from "next";
import { ToolboxLayout } from "@/components/toolbox/toolbox-layout";

export const metadata: Metadata = { title: "Toolbox" };

export default function ToolboxPage() {
  return (
    <div className="mx-auto w-[90vw] max-w-[1600px] px-4 py-8">
      <div className="mb-6">
        <h1 className="mb-1 text-3xl font-bold font-heading">Toolbox</h1>
        <p className="text-muted-foreground">
          Curated collection of cybersecurity tools, resources &amp; references.
        </p>
      </div>

      <ToolboxLayout />
    </div>
  );
}
