import type { Express } from "express";
import { createServer, type Server } from "http";

// Note: API key management routes have been moved to auth-routes.ts
// to ensure proper JWT authentication is enforced

export async function registerRoutes(app: Express): Promise<Server> {
  // Add other non-authentication related routes here
  // API key routes are now handled in auth-routes.ts with proper authentication
  
  const httpServer = createServer(app);

  return httpServer;
}
