import { SiX, SiLinkedin, SiDiscord } from "react-icons/si";
import { Link } from "wouter";

export function Footer() {
  const currentYear = new Date().getFullYear();

  const footerLinks = {
    Product: [
      { label: "Features", href: "/#features", isAnchor: true },
      { label: "Pricing", href: "/#pricing", isAnchor: true },
      { label: "Roadmap", href: "/#roadmap", isAnchor: true },
      { label: "Changelog", href: "#", isAnchor: false },
    ],
    Developers: [
      { label: "Documentation", href: "/docs", isAnchor: false },
      { label: "API Reference", href: "/docs", isAnchor: false },
      { label: "SDK", href: "#", isAnchor: false },
      { label: "Examples", href: "#", isAnchor: false },
    ],
    Company: [
      { label: "About", href: "#" },
      { label: "Blog", href: "#" },
      { label: "Careers", href: "#" },
      { label: "Contact", href: "#" },
    ],
    Legal: [
      { label: "Privacy", href: "#" },
      { label: "Terms", href: "#" },
      { label: "Security", href: "#" },
    ],
  };

  return (
    <footer className="bg-card border-t border-card-border">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-8 mb-12">
          <div className="col-span-2 md:col-span-1">
            <div className="flex items-center gap-2 mb-4">
              {/* Light mode logo */}
              <img
                src="/logo-light.png"
                alt="BlockSub logo"
                className="w-full h-10 rounded-md object-cover block dark:hidden"
                loading="eager"
                decoding="async"
              />
              {/* Dark mode logo */}
              <img
                src="/logo-dark.png"
                alt="BlockSub dark logo"
                className="w-full h-10 rounded-md object-cover hidden dark:block"
                loading="eager"
                decoding="async"
              />
            </div>
            <p className="text-sm text-muted-foreground mb-4">
              Smart subscriptions on Solana. The Web3 alternative to Stripe.
            </p>
            <div className="flex items-center gap-4">
              <a
                href="https://www.linkedin.com/in/shaheer-ali-b13a71360?trk=contact-info"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-foreground transition-colors hover-elevate p-2 rounded-md"
                data-testid="link-linkedin"
                aria-label="LinkedIn"
              >
                <SiLinkedin className="w-5 h-5" />
              </a>
              <a
                href="https://x.com/ray_shaheer_ali"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-foreground transition-colors hover-elevate p-2 rounded-md"
                data-testid="link-x"
                aria-label="X (Twitter)"
              >
                <SiX className="w-5 h-5" />
              </a>
              
           
            </div>
          </div>

          {Object.entries(footerLinks).map(([category, links]) => (
            <div key={category}>
              <h3 className="font-semibold mb-4">{category}</h3>
              <ul className="space-y-2">
                {links.map((link) => (
                  <li key={link.label}>
                    {'isAnchor' in link && link.isAnchor && link.href !== '#' ? (
                      <a
                        href={link.href}
                        className="text-sm text-muted-foreground hover:text-foreground transition-colors hover-elevate px-2 py-1 -mx-2 rounded-md inline-block"
                        data-testid={`link-footer-${link.label.toLowerCase()}`}
                      >
                        {link.label}
                      </a>
                    ) : link.href !== '#' ? (
                      <Link href={link.href}>
                        <span className="text-sm text-muted-foreground hover:text-foreground transition-colors hover-elevate px-2 py-1 -mx-2 rounded-md inline-block cursor-pointer"
                              data-testid={`link-footer-${link.label.toLowerCase()}`}>
                          {link.label}
                        </span>
                      </Link>
                    ) : (
                      <span className="text-sm text-muted-foreground/50 px-2 py-1 -mx-2 rounded-md inline-block cursor-not-allowed"
                            data-testid={`link-footer-${link.label.toLowerCase()}`}>
                        {link.label} <span className="text-xs">(Coming Soon)</span>
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        <div className="border-t border-border pt-8">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <p className="text-sm text-muted-foreground">
              © {currentYear} BlockSub. All rights reserved.
            </p>
            <p className="text-sm text-muted-foreground">
              Built on Solana with ❤️
            </p>
          </div>
        </div>
      </div>
    </footer>
  );
}
