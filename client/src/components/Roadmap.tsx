import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { CheckCircle2, Circle } from "lucide-react";

const phases = [
  {
    phase: "Phase 1",
    status: "completed",
    title: "Core Infrastructure",
    items: [
      "On-chain subscription vaults",
      "Withdraw logic",
      "Basic smart contracts",
    ],
  },
  {
    phase: "Phase 2",
    status: "completed",
    title: "Developer Tools",
    items: [
      "QR-based wallet checkout",
      "API & SDK release",
      "Code examples & docs",
    ],
  },
  {
    phase: "Phase 3",
    status: "completed",
    title: "Analytics Dashboard",
    items: [
      "Merchant analytics portal",
      "MRR tracking",
      "Retention & churn insights",
    ],
  },
  {
    phase: "Phase 4",
    status: "completed",
    title: "Advanced Features",
    items: [
      "Multiple token support",
      "Pause/resume subscriptions",
      "Relayer incentives",
    ],
  },
  {
    phase: "Phase 5",
    status: "upcoming",
    title: "Partner Ecosystem",
    items: [
      "Integration with major wallets & DEXs",
      "Open partner API",
      "Merchant co-marketing program",
    ],
  },
  {
    phase: "Phase 6",
    status: "upcoming",
    title: "AI-Powered Automation",
    items: [
      "Smart retry & failure prediction",
      "Personalized retention models",
      "Automated billing optimization",
    ],
  },
  {
    phase: "Phase 7",
    status: "upcoming",
    title: "DAO Governance & Token Utility",
    items: [
      "Community-driven decision making",
      "Token staking & rewards",
      "Protocol treasury for growth",
    ],
  },
];

export function Roadmap() {
  const getStatusIcon = (status: string) => {
    return status === "completed" ? (
      <CheckCircle2 className="w-6 h-6 text-green-500 bg-white rounded-full shadow-md" />
    ) : (
      <Circle className="w-6 h-6 text-gray-400 bg-white rounded-full shadow-md" />
    );
  };

  const getStatusBadge = (status: string) => {
    if (status === "completed")
      return (
        <Badge className="bg-green-500/20 text-green-600 border-green-400/30">
          Completed
        </Badge>
      );
    return <Badge variant="secondary">Upcoming</Badge>;
  };

  return (
    <section className="py-20 bg-muted/30 relative overflow-hidden" id="roadmap">
      <div className="max-w-5xl mx-auto px-6">
        <div className="text-center mb-16 animate-fade-in-up">
          <h2 className="text-4xl font-bold mb-4">Roadmap</h2>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Our journey to becoming the <span className="font-semibold text-primary">Stripe of Web3</span> 🚀
          </p>
        </div>

        <div className="relative">
          {/* Vertical timeline line */}
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

                {/* Roadmap Card */}
                <Card
                  className={`p-8 transition-all duration-300 border-l-4 ${
                    phase.status === "completed"
                      ? "border-green-500 hover:shadow-green-200/50"
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
