import { Card } from "@/components/ui/card";
import {
  Wallet,
  RefreshCw,
  Clock,
  Shield,
  AlertCircle,
  Code,
} from "lucide-react";
import { motion } from "framer-motion";
import { useState } from "react";

const features = [
  {
    icon: Wallet,
    title: "Subscription Vaults",
    description:
      "Funds locked and auto-released on schedule. Non-custodial, secure, and transparent.",
    color: "from-purple-500 to-pink-500",
  },
  {
    icon: RefreshCw,
    title: "Auto-Renew & Proration",
    description:
      "Programmable schedules: daily, weekly, monthly, or custom intervals with smart proration.",
    color: "from-blue-500 to-cyan-500",
  },
  {
    icon: Clock,
    title: "Retry & Alerts",
    description:
      "Automatic retry logic when balance is low. Real-time notifications keep everyone informed.",
    color: "from-green-500 to-emerald-500",
  },
  {
    icon: Shield,
    title: "Cancel Anytime",
    description:
      "User stays in full control. Cancel subscription at any time with instant refunds.",
    color: "from-orange-500 to-red-500",
  },
  {
    icon: AlertCircle,
    title: "Fraud Protection",
    description:
      "Optional wallet balance verification and suspicious activity detection built-in.",
    color: "from-yellow-500 to-orange-500",
  },
  {
    icon: Code,
    title: "1-Line API Call",
    description:
      "Integration as simple as Stripe Checkout. Production-ready SDK and comprehensive docs.",
    color: "from-indigo-500 to-purple-500",
  },
];

export function Features() {
  const [hoveredCard, setHoveredCard] = useState<number | null>(null);

  return (
    <section className="py-20 relative overflow-hidden" id="features">
      <div className="absolute inset-0 bg-gradient-to-b from-background via-primary/5 to-background pointer-events-none"></div>
      
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        <motion.div 
          className="text-center mb-16"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
        >
          <h2 className="text-4xl font-bold mb-4">Why BlockSub?</h2>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Everything you need to power subscription payments on Solana
          </p>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {features.map((feature, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, y: 50 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: index * 0.1 }}
              onMouseEnter={() => setHoveredCard(index)}
              onMouseLeave={() => setHoveredCard(null)}
            >
              <Card
                className="p-8 h-full transition-all duration-300 hover:shadow-2xl relative overflow-hidden group cursor-pointer"
                data-testid={`card-feature-${index}`}
              >
                <motion.div
                  className={`absolute inset-0 bg-gradient-to-br ${feature.color} opacity-0 group-hover:opacity-10 transition-opacity duration-300`}
                  animate={hoveredCard === index ? { scale: 1.1 } : { scale: 1 }}
                />
                
                <motion.div 
                  className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4 relative z-10"
                  animate={hoveredCard === index ? { 
                    rotate: [0, -10, 10, -10, 0],
                    scale: [1, 1.1, 1.1, 1.1, 1]
                  } : {}}
                  transition={{ duration: 0.5 }}
                >
                  <feature.icon className="w-6 h-6 text-primary" />
                </motion.div>
                
                <h3 className="text-xl font-semibold mb-3 relative z-10">{feature.title}</h3>
                <p className="text-muted-foreground leading-relaxed relative z-10">
                  {feature.description}
                </p>
              </Card>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
