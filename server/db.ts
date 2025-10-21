// Re-export MongoDB utilities
export { connectToDatabase, disconnectFromDatabase, isConnected, getConnectionStatus } from "@shared/mongodb";

// Initialize connection on server start
import { connectToDatabase } from "@shared/mongodb";

const initializeDatabase = async () => {
  try {
    await connectToDatabase();
  } catch (error) {
    console.error('Failed to initialize database connection:', error);
    process.exit(1);
  }
};

// Initialize connection
initializeDatabase();

export { initializeDatabase };
