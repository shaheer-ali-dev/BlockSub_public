import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { ThemeToggle } from "./ThemeToggle";
import { Menu, X, User, LogOut, Settings, Key } from "lucide-react";
import { Link, useLocation } from "wouter";
import { useAuth } from "@/contexts/AuthContext";

export function Navigation() {
  const [isScrolled, setIsScrolled] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [location] = useLocation();
  const { user, isAuthenticated, logout, loading } = useAuth();

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 20);
    };
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const navLinks = [
    { href: "/#features", label: "Features" },
    { href: "/#how-it-works", label: "How It Works" },
    { href: "/#pricing", label: "Pricing" },
    { href: "/subscribe", label: "Subscribe" },
    { href: "/dashboard", label: "Docs" },
    { href: "/dashboard", label: "Dashboard" },
  ];

  return (
    <nav
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        isScrolled
          ? "bg-background/80 backdrop-blur-lg border-b border-border"
          : "bg-transparent"
      }`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <Link href="/" className="flex items-center gap-2 hover-elevate px-3 py-2 rounded-md transition-colors" data-testid="link-home">
            {/* Light mode logo */}
            <img
                src="/logo-light.png"
                alt="BlockSub logo"
                className="w-full h-12 rounded-md object-cover block dark:hidden"
                loading="eager"
                decoding="async"
              />
              {/* Dark mode logo */}
              <img
                src="/logo-dark.png"
                alt="BlockSub dark logo"
                className="w-full h-12 rounded-md object-cover hidden dark:block"
                loading="eager"
                decoding="async"
              />
          </Link>

          <div className="hidden md:flex items-center gap-8">
            {navLinks.map((link) => {
              // Handle anchor links, external URLs, and regular routes differently
              if (link.href.startsWith('/#')) {
                return (
                  <a
                    key={link.href}
                    href={link.href}
                    className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors hover-elevate px-3 py-2 rounded-md"
                    data-testid={`link-${link.label.toLowerCase().replace(" ", "-")}`}
                    onClick={(e) => {
                      if (location !== '/') {
                        return; // Let the browser handle the navigation
                      }
                      e.preventDefault();
                      const targetId = link.href.substring(2); // Remove '/#'
                      const element = document.getElementById(targetId);
                      if (element) {
                        element.scrollIntoView({ behavior: 'smooth' });
                      }
                    }}
                  >
                    {link.label}
                  </a>
                );
              } else if (link.href.startsWith('http')) {
                return (
                  <a
                    key={link.href}
                    href={link.href}
                    className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors hover-elevate px-3 py-2 rounded-md"
                    data-testid={`link-${link.label.toLowerCase().replace(" ", "-")}`}
                  >
                    {link.label}
                  </a>
                );
              } else {
                return (
                  <Link
                    key={link.href}
                    href={link.href}
                    className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors hover-elevate px-3 py-2 rounded-md"
                    data-testid={`link-${link.label.toLowerCase().replace(" ", "-")}`}
                  >
                    {link.label}
                  </Link>
                );
              }
            })}
          </div>

          <div className="hidden md:flex items-center gap-4">
            <ThemeToggle />
            {loading ? (
              <div className="h-9 w-20 bg-muted animate-pulse rounded-md" />
            ) : isAuthenticated ? (
              <>
                <Link href="/dashboard">
                  <Button variant="outline" size="sm" data-testid="button-dashboard">
                    <Key className="w-4 h-4 mr-2" />
                    Dashboard
                  </Button>
                </Link>
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" className="relative h-9 w-9 rounded-full">
                      <Avatar className="h-9 w-9">
                        <AvatarFallback className="bg-primary text-primary-foreground">
                          {user?.username.charAt(0).toUpperCase() || 'U'}
                        </AvatarFallback>
                      </Avatar>
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent className="w-56" align="end" forceMount>
                    <div className="flex flex-col space-y-1 p-2">
                      <p className="text-sm font-medium leading-none">{user?.username}</p>
                      <p className="text-xs leading-none text-muted-foreground">
                        Member since {new Date(user?.createdAt || '').toLocaleDateString()}
                      </p>
                    </div>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem asChild>
                      <Link href="/dashboard" className="cursor-pointer">
                        <User className="mr-2 h-4 w-4" />
                        <span>Dashboard</span>
                      </Link>
                    </DropdownMenuItem>
                    <DropdownMenuItem asChild>
                      <Link href="/dashboard?tab=api-keys" className="cursor-pointer">
                        <Key className="mr-2 h-4 w-4" />
                        <span>API Keys</span>
                      </Link>
                    </DropdownMenuItem>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem onClick={logout} className="cursor-pointer text-red-600 focus:text-red-600">
                      <LogOut className="mr-2 h-4 w-4" />
                      <span>Sign out</span>
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </>
            ) : (
              <>
                <Link href="/auth">
                  <Button variant="outline" size="sm" data-testid="button-sign-in">
                    Sign In
                  </Button>
                </Link>
                <Link href="/auth">
                  <Button size="sm" data-testid="button-get-started">
                    Get Started
                  </Button>
                </Link>
              </>
            )}
          </div>

          <div className="md:hidden flex items-center gap-2">
            <ThemeToggle />
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              data-testid="button-mobile-menu"
            >
              {isMobileMenuOpen ? (
                <X className="h-6 w-6" />
              ) : (
                <Menu className="h-6 w-6" />
              )}
            </Button>
          </div>
        </div>
      </div>

      {isMobileMenuOpen && (
        <div className="md:hidden border-t border-border bg-background/95 backdrop-blur-lg animate-fade-in-up">
          <div className="px-4 py-4 space-y-3">
            {navLinks.map((link) => {
              // Handle anchor links, external URLs, and regular routes differently for mobile too
              if (link.href.startsWith('/#')) {
                return (
                  <a
                    key={link.href}
                    href={link.href}
                    className="block px-3 py-2 text-base font-medium text-muted-foreground hover:text-foreground hover-elevate rounded-md transition-colors"
                    onClick={(e) => {
                      setIsMobileMenuOpen(false);
                      if (location !== '/') {
                        return; // Let the browser handle the navigation
                      }
                      e.preventDefault();
                      const targetId = link.href.substring(2); // Remove '/#'
                      const element = document.getElementById(targetId);
                      if (element) {
                        element.scrollIntoView({ behavior: 'smooth' });
                      }
                    }}
                    data-testid={`link-mobile-${link.label.toLowerCase().replace(" ", "-")}`}
                  >
                    {link.label}
                  </a>
                );
              } else if (link.href.startsWith('http')) {
                return (
                  <a
                    key={link.href}
                    href={link.href}
                    className="block px-3 py-2 text-base font-medium text-muted-foreground hover:text-foreground hover-elevate rounded-md transition-colors"
                    onClick={() => setIsMobileMenuOpen(false)}
                    data-testid={`link-mobile-${link.label.toLowerCase().replace(" ", "-")}`}
                  >
                    {link.label}
                  </a>
                );
              } else {
                return (
                  <Link
                    key={link.href}
                    href={link.href}
                    className="block px-3 py-2 text-base font-medium text-muted-foreground hover:text-foreground hover-elevate rounded-md transition-colors"
                    onClick={() => setIsMobileMenuOpen(false)}
                    data-testid={`link-mobile-${link.label.toLowerCase().replace(" ", "-")}`}
                  >
                    {link.label}
                  </Link>
                );
              }
            })}
            <div className="flex flex-col gap-2 pt-4 border-t border-border">
              {loading ? (
                <div className="space-y-2">
                  <div className="h-10 bg-muted animate-pulse rounded-md" />
                  <div className="h-10 bg-muted animate-pulse rounded-md" />
                </div>
              ) : isAuthenticated ? (
                <>
                  <div className="px-3 py-2 text-sm">
                    <p className="font-medium text-foreground">Hi, {user?.username}!</p>
                    <p className="text-muted-foreground">Member since {new Date(user?.createdAt || '').toLocaleDateString()}</p>
                  </div>
                  <Link href="/dashboard">
                    <Button variant="outline" className="w-full" data-testid="button-mobile-dashboard">
                      <Key className="w-4 h-4 mr-2" />
                      Dashboard
                    </Button>
                  </Link>
                  <Link href="/dashboard?tab=api-keys">
                    <Button variant="outline" className="w-full" data-testid="button-mobile-api-keys">
                      <Key className="w-4 h-4 mr-2" />
                      API Keys
                    </Button>
                  </Link>
                  <Button 
                    variant="destructive" 
                    className="w-full" 
                    onClick={() => {
                      setIsMobileMenuOpen(false);
                      logout();
                    }}
                    data-testid="button-mobile-logout"
                  >
                    <LogOut className="w-4 h-4 mr-2" />
                    Sign Out
                  </Button>
                </>
              ) : (
                <>
                  <Link href="/auth">
                    <Button variant="outline" className="w-full" data-testid="button-mobile-sign-in">
                      Sign In
                    </Button>
                  </Link>
                  <Link href="/auth">
                    <Button className="w-full" data-testid="button-mobile-get-started">
                      Get Started
                    </Button>
                  </Link>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </nav>
  );
}
