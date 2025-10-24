import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Check } from "lucide-react";
import { Link } from "wouter";

export function Pricing() {
  const plans = [
    {
      name: "Starter",
      oldPrice: "30",
      price: "Free",
      period: "for limited time",
      badge: "Launch Offer 🚀",
      features: [
        "3 API tokens",
        "USDC support",
        "Basic analytics",
        "Email support",
        "No credit card required",
      ],
    },
    {
      name: "Growth",
      oldPrice: "59",
      price: "Free",
      period: "for limited time",
      badge: "Most Popular 🌟",
      recommended: true,
      features: [
        "10 API tokens",
        "Multi-token support",
        "Advanced analytics",
        "Priority email support",
        "Custom webhooks",
        "Integration assistance",
      ],
    },
    {
      name: "Enterprise",
      oldPrice: "149",
      price: "Free",
      period: "for limited time",
      badge: "Scale with Us 💼",
      features: [
        "Unlimited API tokens",
        "Dedicated success manager",
        "White-label integration",
        "24/7 support",
        "Custom infrastructure setup",
        "SLA & uptime guarantee",
      ],
    },
  ];

  return (
    <section className="py-20" id="pricing">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16 animate-fade-in-up">
          <h2 className="text-4xl font-bold mb-4">Simple, Transparent Pricing</h2>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            ⚡ All plans are <span className="font-semibold text-primary">Free</span> for a limited time to celebrate our launch!
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-6xl mx-auto">
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
                  <span className="text-muted-foreground line-through text-2xl">
                    ${plan.oldPrice}
                  </span>
                  <span className="text-5xl font-bold text-primary">
                    {plan.price}
                  </span>
                </div>
                <span className="text-muted-foreground">/ {plan.period}</span>
              </div>

              <Link href="/dashboard?tab=api-keys">
                <Button
                  className="w-full mb-8"
                  variant={plan.recommended ? "default" : "outline"}
                  data-testid={`button-pricing-${index}`}
                >
                  {plan.recommended ? "Claim Free Access" : "Start for Free"}
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
