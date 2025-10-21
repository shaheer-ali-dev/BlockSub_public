import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { CheckCircle2, Circle, Clock } from "lucide-react";

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
    status: "in-progress",
    title: "Developer Tools",
    items: [
      "QR-based wallet checkout",
      "API & SDK release",
      "Code examples & docs",
    ],
  },
  {
    phase: "Phase 3",
    status: "upcoming",
    title: "Analytics Dashboard",
    items: [
      "Merchant analytics portal",
      "MRR tracking",
      "Retention & churn insights",
    ],
  },
  {
    phase: "Phase 4",
    status: "upcoming",
    title: "Advanced Features",
    items: [
      "Multiple token support",
      "Pause/resume subscriptions",
      "Relayer incentives",
    ],
  },
];

export function Roadmap() {
  const getStatusIcon = (status: string) => {
    if (status === "completed") return <CheckCircle2 className="w-5 h-5 text-chart-3" />;
    if (status === "in-progress") return <Clock className="w-5 h-5 text-chart-4" />;
    return <Circle className="w-5 h-5 text-muted-foreground" />;
  };

  const getStatusBadge = (status: string) => {
    if (status === "completed")
      return (
        <Badge className="bg-chart-3/20 text-chart-3 border-chart-3/30">
          Completed
        </Badge>
      );
    if (status === "in-progress")
      return (
        <Badge className="bg-chart-4/20 text-chart-4 border-chart-4/30">
          In Progress
        </Badge>
      );
    return (
      <Badge variant="secondary">Upcoming</Badge>
    );
  };

  return (
    <section className="py-20 bg-muted/30" id="roadmap">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16 animate-fade-in-up">
          <h2 className="text-4xl font-bold mb-4">Roadmap</h2>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Our journey to becoming the Stripe of Web3
          </p>
        </div>

        <div className="max-w-4xl mx-auto">
          <div className="space-y-8">
            {phases.map((phase, index) => (
              <Card
                key={index}
                className="p-8 hover-elevate transition-all duration-300 animate-fade-in-up"
                style={{ animationDelay: `${index * 100}ms` }}
                data-testid={`card-phase-${index}`}
              >
                <div className="flex items-start gap-6">
                  <div className="flex-shrink-0">
                    {getStatusIcon(phase.status)}
                  </div>

                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-3">
                      <h3 className="text-xl font-bold">{phase.phase}</h3>
                      {getStatusBadge(phase.status)}
                    </div>

                    <h4 className="text-lg font-semibold mb-4">{phase.title}</h4>

                    <ul className="space-y-2">
                      {phase.items.map((item, itemIndex) => (
                        <li
                          key={itemIndex}
                          className="flex items-center gap-2 text-muted-foreground"
                        >
                          <div className="w-1.5 h-1.5 rounded-full bg-primary"></div>
                          {item}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
