import { Card } from "@/components/ui/card";
import { Play } from "lucide-react";
import { useState } from "react";

export function VideoDemo() {
  const [isPlaying, setIsPlaying] = useState(false);

  return (
    <section className="py-20 bg-muted/30" id="demo">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12 animate-fade-in-up">
          <h2 className="text-4xl font-bold mb-4">See It In Action</h2>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Watch how easy it is to integrate recurring payments into your Solana dApp
          </p>
        </div>

        <Card className="max-w-5xl mx-auto overflow-hidden hover-elevate transition-all duration-300 hover:shadow-xl">
          <div className="relative aspect-video bg-gradient-to-br from-primary/20 to-chart-2/20">
            {!isPlaying ? (
              <div className="absolute inset-0 flex items-center justify-center">
                <button
                  onClick={() => {
                    setIsPlaying(true);
                    console.log("Video playback started");
                  }}
                  className="w-20 h-20 rounded-full bg-primary hover:bg-primary/90 flex items-center justify-center transition-all hover:scale-110 active-elevate-2"
                  data-testid="button-play-video"
                >
                  <Play className="w-8 h-8 text-primary-foreground ml-1" fill="currentColor" />
                </button>
              </div>
            ) : (
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="text-center">
                  <div className="w-16 h-16 border-4 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
                  <p className="text-muted-foreground">Video player placeholder</p>
                  <p className="text-sm text-muted-foreground mt-2">
                    Your integration demo video will appear here
                  </p>
                </div>
              </div>
            )}
            <div className="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black/50 to-transparent p-6">
              <h3 className="text-white text-lg font-semibold">
                BlockSub Integration Demo
              </h3>
              <p className="text-white/80 text-sm">3-minute walkthrough</p>
            </div>
          </div>
        </Card>
      </div>
    </section>
  );
}
