import { Card } from "@/components/ui/card";
import { ArrowRight, Wallet, Lock, Building2 } from "lucide-react";
import { useState } from "react";

export function ProtocolFlow() {
  const [activeStep, setActiveStep] = useState(0);

  const steps = [
    {
      icon: Wallet,
      title: "User Deposits",
      description: "Subscriber deposits USDC/SPL tokens into subscription vault",
    },
    {
      icon: Lock,
      title: "Vault Auto-Release",
      description: "Funds automatically released per schedule (daily/monthly)",
    },
    {
      icon: Building2,
      title: "Merchant Receives",
      description: "Merchant receives payment directly to their wallet",
    },
  ];

  return (
    <section className="py-20 bg-muted/30" id="how-it-works">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16 animate-fade-in-up">
          <h2 className="text-4xl font-bold mb-4">How It Works</h2>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Simple, secure, and fully automated subscription flow
          </p>
        </div>

        <div className="max-w-5xl mx-auto">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 md:gap-4">
            {steps.map((step, index) => (
              <div key={index} className="relative">
                <Card
                  className={`p-8 text-center cursor-pointer transition-all duration-300 ${
                    activeStep === index
                      ? "scale-105 shadow-xl border-primary"
                      : "hover-elevate"
                  }`}
                  onClick={() => {
                    setActiveStep(index);
                    console.log(`Step ${index + 1} selected`);
                  }}
                  data-testid={`card-step-${index}`}
                >
                  <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-4">
                    <step.icon className="w-8 h-8 text-primary" />
                  </div>
                  <div className="text-sm font-semibold text-primary mb-2">
                    Step {index + 1}
                  </div>
                  <h3 className="text-lg font-bold mb-2">{step.title}</h3>
                  <p className="text-sm text-muted-foreground">
                    {step.description}
                  </p>
                </Card>

                {index < steps.length - 1 && (
                  <div className="hidden md:flex absolute top-1/2 -right-2 transform -translate-y-1/2 translate-x-1/2 z-10">
                    <ArrowRight className="w-6 h-6 text-primary animate-pulse" />
                  </div>
                )}
              </div>
            ))}
          </div>

          <div className="mt-12 p-8 bg-gradient-to-br from-primary/5 to-chart-2/5 rounded-lg border border-primary/20 animate-fade-in">
            <div className="flex items-start gap-4">
              <div className="flex-shrink-0">
                <div className="w-2 h-2 bg-chart-3 rounded-full animate-pulse-slow"></div>
              </div>
              <div>
                <h4 className="font-semibold mb-2">Automated & Secure</h4>
                <p className="text-sm text-muted-foreground leading-relaxed">
                  The entire flow is handled on-chain with Solana's speed and low fees.
                  Users maintain full control with the ability to cancel anytime, while
                  merchants receive reliable, recurring revenue.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
