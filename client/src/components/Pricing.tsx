import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Check } from "lucide-react";
import { Link } from "wouter";

export function Pricing() {
  const plans = [
    {
      name: "Free Trial",
      price: "0",
      period: "2 months",
      badge: "Get Started",
      features: [
        "Full API access",
        "Unlimited subscriptions",
        "USDC support",
        "Basic analytics",
        "Email support",
        "No credit card required",
      ],
    },
    {
      name: "Production",
      price: "30",
      period: "per merchant/month",
      badge: "Most Popular",
      recommended: true,
      features: [
        "Everything in Free Trial",
        "Multi-token support",
        "Advanced analytics",
        "Priority support",
        "Custom integrations",
        "White-label options",
      ],
    },
  ];

  return (
    <section className="py-20" id="pricing">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16 animate-fade-in-up">
          <h2 className="text-4xl font-bold mb-4">Simple, Transparent Pricing</h2>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Start free for 2 months, then just 30$ flat fee per merchant
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 max-w-5xl mx-auto">
          {plans.map((plan, index) => (
            <Card
              key={index}
              className={`p-8 relative overflow-hidden transition-all duration-300 ${
                plan.recommended
                  ? "border-primary shadow-xl scale-105"
                  : "hover-elevate"
              }`}
              data-testid={`card-pricing-${index}`}
            >
              {plan.recommended && (
                <div className="absolute top-0 right-0 bg-primary text-primary-foreground text-xs font-semibold px-3 py-1 rounded-bl-lg">
                  Recommended
                </div>
              )}

              <div className="mb-6">
                <Badge variant="secondary" className="mb-4">
                  {plan.badge}
                </Badge>
                <h3 className="text-2xl font-bold mb-2">{plan.name}</h3>
                <div className="flex items-baseline gap-2">
                  <span className="text-5xl font-bold">{plan.price}$</span>
                  <span className="text-muted-foreground">/ {plan.period}</span>
                </div>
              </div>

              <Link href="/dashboard?tab=api-keys">
                <Button
                  className="w-full mb-8"
                  variant={plan.recommended ? "default" : "outline"}
                  data-testid={`button-pricing-${index}`}
                >
                  {plan.recommended ? "Get Started" : "Start Free Trial"}
                </Button>
              </Link>

              <div className="space-y-4">
                {plan.features.map((feature, fIndex) => (
                  <div key={fIndex} className="flex items-start gap-3">
                    <div className="flex-shrink-0 w-5 h-5 rounded-full bg-chart-3/20 flex items-center justify-center mt-0.5">
                      <Check className="w-3 h-3 text-chart-3" />
                    </div>
                    <span className="text-sm">{feature}</span>
                  </div>
                ))}
              </div>
            </Card>
          ))}
        </div>

        <div className="text-center mt-12">
          <p className="text-sm text-muted-foreground">
            Need custom pricing for enterprise?{" "}
            <a href="#contact" className="text-primary hover:underline">
              Contact us
            </a>
          </p>
        </div>
      </div>
    </section>
  );
}
