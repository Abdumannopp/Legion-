"use client";

import { useEffect, useState } from "react";
import LegionDashboard from "@/components/LegionDashboard";
import Landing from "@/components/site/Landing";
import { isLoggedIn } from "@/lib/api";
import { IS_SAAS } from "@/lib/site";

/**
 * Hosted service: visitors who are not signed in get the product page (it is
 * what search engines and Paddle's website review see — it is the page's
 * server-rendered HTML). Signed-in users get the dashboard.
 * Self-hosted: always the dashboard, which sends visitors to sign in.
 */
export default function Home() {
  const [signedIn, setSignedIn] = useState(false);
  useEffect(() => setSignedIn(isLoggedIn()), []);
  if (!IS_SAAS || signedIn) return <LegionDashboard />;
  return <Landing />;
}
