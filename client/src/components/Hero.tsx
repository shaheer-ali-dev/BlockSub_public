import { Button } from "@/components/ui/button";
import { ArrowRight, Code2, Zap, Sparkles } from "lucide-react";
import { motion, AnimatePresence, useScroll, useTransform } from "framer-motion";
import { useRef, useEffect, useMemo } from "react";
import Particles, { initParticlesEngine } from "@tsparticles/react";
import { loadSlim } from "@tsparticles/slim";
import { useState } from "react";
import { Copy, Check } from "lucide-react";
import { Link } from "wouter";

function CopyCodeButton() {
  const [copied, setCopied] = useState(false);

  const codeSnippet = `
  await fetch('http://localhost:3000/api/recurring-subscriptions', {
  method: 'POST',
  headers: { 
    'Content-Type': 'application/json',
    'Authorization': 'Bearer bsk_test_1234567890abcdef1234567890abcdef'
    // Alternatively: 'x-api-key': 'bsk_test_1234567890abcdef1234567890abcdef'
  },
  body: JSON.stringify({
    plan: 'basic',
    priceUsd: 5.00,
    billingInterval: 'monthly',
    webhookUrl: 'https://example.com/webhook',
    metadata: { customer_id: 'cus_123' },
    trialDays: 7
  })
}).then(r => r.json())
`;

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(codeSnippet);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error("Failed to copy!", err);
    }
  };

  return (
    <motion.button
      onClick={handleCopy}
      whileHover={{ scale: 1.1 }}
      whileTap={{ scale: 0.95 }}
      className="absolute -top-2 right-2 p-2 rounded-md bg-primary/10 border border-primary/20 hover:bg-primary/20 transition-colors"
    >
      <AnimatePresence mode="wait" initial={false}>
        {copied ? (
          <motion.div
            key="check"
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.8 }}
            transition={{ duration: 0.2 }}
          >
            <Check className="w-4 h-4 text-green-500" />
          </motion.div>
        ) : (
          <motion.div
            key="copy"
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.8 }}
            transition={{ duration: 0.2 }}
          >
            <Copy className="w-4 h-4 text-primary dark:text-emerald-300" />
          </motion.div>
        )}
      </AnimatePresence>
    </motion.button>
  );
}

export function Hero() {
  const ref = useRef(null);
  const { scrollYProgress } = useScroll({
    target: ref,
    offset: ["start start", "end start"]
  });

  const y = useTransform(scrollYProgress, [0, 1], ["0%", "50%"]);
  const opacity = useTransform(scrollYProgress, [0, 1], [1, 0]);

  // init tsparticles engine once
  useEffect(() => {
    initParticlesEngine(async (engine) => {
      await loadSlim(engine);
    });
  }, []);

  const particlesOptions = useMemo(
    () => ({
      background: { color: "transparent" },
      fullScreen: { enable: false },
      particles: {
        number: { value: 200 }, // more visible
        color: { value: ["#14F195", "#9945FF", "#19FB9B"] },
        shape: { type: ["circle", "polygon"], options: { polygon: { sides: 6 } } }, // circle + hexagons
        links: { enable: true, color: "#14F195", opacity: 0.7, width: 1 },
        move: {
          enable: true,
          speed: 1.2,
          parallax: { enable: true, force: 40, smooth: 15 }
        },
        size: {
          value: { min: 2.5, max: 5 } // some small, some larger
        },
        opacity: {
          value: 0.9,
          animation: {
            enable: true,
            speed: 1.5,
            minimumValue: 0.3,
            sync: false // random pulsing
          }
        }
      },
      detectRetina: true
    }),
    []
  );

  return (
    <section
      ref={ref}
      className="relative min-h-screen flex items-center justify-center overflow-hidden"
    >
      {/* Particle Network Background */}
      <div className="absolute inset-0 z-[1]">
        <Particles id="hero-particles" options={particlesOptions} />
      </div>

      {/* Gradient overlay (lighter to reveal particles) */}
      <motion.div
        style={{ y, opacity }}
        className="absolute inset-0 z-[2] bg-gradient-to-br from-background/70 via-primary/5 to-chart-2/5"
      >
        <div className="absolute inset-0 bg-gradient-to-b from-background/70 via-background/60 to-background/80"></div>
      </motion.div>

      {/* Floating Blur Orbs */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none z-[3]">
        <motion.div
          className="absolute top-20 left-10 w-72 h-72 bg-primary/40 rounded-full blur-3xl"
          animate={{ y: [0, -30, 0], x: [0, 20, 0] }}
          transition={{ duration: 6, repeat: Infinity, ease: "easeInOut" }}
        />
        <motion.div
          className="absolute bottom-20 right-10 w-96 h-96 bg-chart-2/40 rounded-full blur-3xl"
          animate={{ y: [0, 30, 0], x: [0, -20, 0] }}
          transition={{ duration: 8, repeat: Infinity, ease: "easeInOut", delay: 1 }}
        />
        <motion.div
          className="absolute top-1/2 left-1/2 w-64 h-64 bg-purple-500/30 rounded-full blur-3xl"
          animate={{ scale: [1, 1.2, 1], rotate: [0, 180, 360] }}
          transition={{ duration: 10, repeat: Infinity, ease: "linear" }}
        />
      </div>

      {/* Hero Content */}
      <div className="relative z-[10] max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-32">
        <div className="text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 dark:bg-emerald-400/10 dark:border-emerald-400/20 mb-8"
          >
            <motion.div
              animate={{ rotate: [0, 360] }}
              transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
            >
              <Zap className="w-4 h-4 text-primary dark:text-emerald-300" />
            </motion.div>
            <span className="text-sm font-medium text-primary dark:text-emerald-300">
              Everything Stripe does — but Solana-native
            </span>
            <Sparkles className="w-4 h-4 text-primary dark:text-emerald-300" />
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.2 }}
            className="text-5xl sm:text-6xl lg:text-7xl font-bold tracking-tight mb-6"
          >
            <motion.span
              className="bg-gradient-to-r from-primary via-chart-2 to-primary bg-clip-text text-transparent inline-block"
              animate={{ backgroundPosition: ["0% 50%", "100% 50%", "0% 50%"] }}
              transition={{ duration: 5, repeat: Infinity, ease: "linear" }}
              style={{ backgroundSize: "200% 200%" }}
            >
              Smart Subscriptions
            </motion.span>
            <br />
            <span className="text-foreground">on Solana</span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.4 }}
            className="text-xl text-muted-foreground max-w-3xl mx-auto mb-12 leading-relaxed"
          >
            Unlock subscription economies for Web3. BlockSub enables programmable
            recurring payments with auto-renew, subscription vaults, and
            developer-friendly APIs.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.6 }}
            className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-16"
          >
            <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
              <Link href="/dashboard?tab=api-keys">
                <Button size="lg" className="text-lg px-8 group" data-testid="button-hero-start">
                  Get Started Free
                  <ArrowRight className="ml-2 h-5 w-5 group-hover:translate-x-1 transition-transform" />
                </Button>
              </Link>
            </motion.div>
            <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
              <Link href="/dashboard?tab=documentation">
                <Button size="lg" variant="outline" className="text-lg px-8" data-testid="button-hero-docs">
                  <Code2 className="mr-2 h-5 w-5" />
                  View Documentation
                </Button>
              </Link>
            </motion.div>
          </motion.div>

         <motion.div
  initial={{ opacity: 0, scale: 0.9 }}
  animate={{ opacity: 1, scale: 1 }}
  transition={{ duration: 0.8, delay: 0.8 }}
  whileHover={{ scale: 1.02, boxShadow: "0 20px 40px rgba(0,0,0,0.2)" }}
  className="inline-block bg-card border border-card-border rounded-lg p-6 shadow-lg relative"
>
  <div className="flex items-start gap-4">
    <div className="flex-shrink-0">
      <motion.div
        className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center"
        animate={{ rotate: [0, 5, -5, 0] }}
        transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
      >
        <Code2 className="w-5 h-5 text-primary" />
      </motion.div>
    </div>
    <div className="flex-1 text-left relative">
      <p className="text-sm text-muted-foreground mb-2">One-line integration</p>

      {/* Copy Button */}
      <CopyCodeButton />

      <pre className="bg-muted/50 p-4 rounded-md overflow-x-auto relative">
        <code className="text-sm font-mono text-foreground">
{`await fetch('https://blocksub-public-1.onrender.com/api/recurring-subscriptions', {
  method: 'POST',
  headers: { 
    'Content-Type': 'application/json',
    'Authorization': 'Bearer bsk_test_1234567890abcdef1234567890abcdef'
    // Alternatively: 'x-api-key': 'bsk_test_1234567890abcdef1234567890abcdef'
  },
  body: JSON.stringify({
    plan: 'basic',
    priceUsd: 5.00,
    billingInterval: 'monthly',
    webhookUrl: 'https://example.com/webhook',
    metadata: { customer_id: 'cus_123' },
    trialDays: 7
  })
}).then(r => r.json())
`}
        </code>
      </pre>
    </div>
  </div>
</motion.div>
        </div>
      </div>
    </section>
  );
}
