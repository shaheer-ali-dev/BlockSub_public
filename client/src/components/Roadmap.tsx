import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { CheckCircle2, Circle } from "lucide-react";

const phases = [
  {
    phase: "🚀 Jan 2026",
    status: "upcoming",
    title: "Mainnet Deployment — Full-scale Release",
    items: [
      "Deploy complete subscription engine on Solana Mainnet",
      "Enable real merchant billing and payments",
      "Finalize HMAC-secured relayer for production",
    ],
  },
  {
    phase: "🌍 After Jan 2026",
    status: "upcoming",
    title: "Global Launch + Merchant SDK + Cross-chain Expansion",
    items: [
      "Launch merchant SDK for simplified integration",
      "Expand to other L1s and L2s (Base, Sui, Avalanche)",
      "Onboard global partners and wallet providers",
    ],
  },
  {
    phase: "🏗️ Feb 2026",
    status: "completed",
    title: "API + Worker + Relayer MVP — Core System on Devnet",
    items: [
      "Deployed Devnet version of core backend and relayer",
      "Introduced subscription vaults and payment workers",
      "Verified stable on-chain billing flows",
    ],
  },
  {
    phase: "⚡ March 2026",
    status: "completed",
    title: "Web Dashboard + Analytics — Merchant Insights Live",
    items: [
      "Merchant analytics dashboard launched",
      "Live tracking for payments and subscriptions",
      "Retention & MRR insights for real-time business metrics",
    ],
  },
  {
    phase: "🪙 June 2026",
    status: "in-progress",
    title: "Tokenomics + Staking System — Reward Model Under Development",
    items: [
      "Designing BlockSub utility token framework",
      "Implementing staking + loyalty incentives for merchants",
      "Testing reward-based relayer participation",
    ],
  },
];

export function Roadmap() {
  const getStatusIcon = (status: string) => {
    if (status === "completed")
      return (
        <CheckCircle2 className="w-6 h-6 text-green-500 bg-white rounded-full shadow-md" />
      );
    if (status === "in-progress")
      return (
        <Circle className="w-6 h-6 text-yellow-500 bg-white rounded-full shadow-md" />
      );
    return (
      <Circle className="w-6 h-6 text-gray-400 bg-white rounded-full shadow-md" />
    );
  };

  const getStatusBadge = (status: string) => {
    if (status === "completed")
      return (
        <Badge className="bg-green-500/20 text-green-600 border-green-400/30">
          ✅ Completed
        </Badge>
      );
    if (status === "in-progress")
      return (
        <Badge className="bg-yellow-500/20 text-yellow-600 border-yellow-400/30">
          ⏳ In Progress
        </Badge>
      );
    return (
      <Badge className="bg-gray-200 text-gray-600 border-gray-300">
        🔜 Upcoming
      </Badge>
    );
  };

  return (
    <section className="py-20 bg-muted/30 relative overflow-hidden" id="roadmap">
      <div className="max-w-5xl mx-auto px-6">
        <div className="text-center mb-16 animate-fade-in-up">
          <h2 className="text-4xl font-bold mb-4">Roadmap</h2>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Our journey to becoming the{" "}
            <span className="font-semibold text-primary">Stripe of Web3</span> 🚀
          </p>
        </div>

        <div className="relative">
          {/* Timeline vertical line */}
          <div className="absolute left-6 top-0 bottom-0 w-1 bg-gradient-to-b from-green-500/70 via-gray-400/40 to-transparent"></div>

          <div className="space-y-12 pl-16">
            {phases.map((phase, index) => (
              <div
                key={index}
                className={`relative group animate-fade-in-up`}
                style={{ animationDelay: `${index * 120}ms` }}
              >
                {/* Timeline dot */}
                <div className="absolute -left-[33px] z-10">
                  {getStatusIcon(phase.status)}
                </div>

                {/* Card */}
                <Card
                  className={`p-8 transition-all duration-300 border-l-4 ${
                    phase.status === "completed"
                      ? "border-green-500 hover:shadow-green-200/50"
                      : phase.status === "in-progress"
                      ? "border-yellow-500 hover:shadow-yellow-200/50"
                      : "border-gray-300"
                  } hover:-translate-y-1 hover:shadow-lg`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="text-xl font-bold">{phase.phase}</h3>
                    {getStatusBadge(phase.status)}
                  </div>

                  <h4 className="text-lg font-semibold mb-4">{phase.title}</h4>

                  <ul className="space-y-2 text-muted-foreground">
                    {phase.items.map((item, i) => (
                      <li key={i} className="flex items-center gap-2">
                        <div className="w-1.5 h-1.5 rounded-full bg-primary"></div>
                        {item}
                      </li>
                    ))}
                  </ul>
                </Card>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
