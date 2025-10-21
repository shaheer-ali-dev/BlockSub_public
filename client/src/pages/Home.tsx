import { Navigation } from "@/components/Navigation";
import { Hero } from "@/components/Hero";
import { VideoDemo } from "@/components/VideoDemo";
import { Features } from "@/components/Features";
import { ProtocolFlow } from "@/components/ProtocolFlow";
import { Pricing } from "@/components/Pricing";
import { Roadmap } from "@/components/Roadmap";
import { Footer } from "@/components/Footer";

export default function Home() {
  return (
    <div className="min-h-screen">
      <Navigation />
      <Hero />
      <VideoDemo />
      <section id="features">
        <Features />
      </section>
      <section id="how-it-works">
        <ProtocolFlow />
      </section>
      <section id="pricing">
        <Pricing />
      </section>
      <Roadmap />
      <Footer />
    </div>
  );
}
