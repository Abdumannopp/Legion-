import type { Metadata } from "next";
import { cookies } from "next/headers";
import SiteHeader from "@/components/site/SiteHeader";
import SiteFooter from "@/components/site/SiteFooter";
import { PricingPageContent } from "@/components/site/PricingCard";
import { notFound } from "next/navigation";
import { IS_SAAS } from "@/lib/site";
import { DEFAULT_LOCALE, isLocale, LOCALE_STORAGE_KEY } from "@/lib/i18n/core";
import { pricing } from "@/lib/i18n/ns/pricing";

/** The tab title in the visitor's saved language (same cookie as the root layout). */
export async function generateMetadata(): Promise<Metadata> {
  const saved = (await cookies()).get(LOCALE_STORAGE_KEY)?.value;
  const locale = isLocale(saved) ? saved : DEFAULT_LOCALE;
  return { title: pricing[locale].metaTitle };
}

export default function PricingPage() {
  // A self-hosted installation has nothing to sell.
  if (!IS_SAAS) notFound();
  return (
    <div className="min-h-screen legion-backdrop text-ink">
      <SiteHeader />
      <main className="max-w-6xl mx-auto px-5 pt-16">
        <PricingPageContent />
      </main>
      <SiteFooter />
    </div>
  );
}
