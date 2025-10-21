import mongoose from 'mongoose';

// MongoDB connection state
interface MongoConnection {
  isConnected?: number;
}

const connection: MongoConnection = {};

export async function connectToDatabase(): Promise<void> {
  // If already connected, return
  if (connection.isConnected) {
    console.log('Already connected to MongoDB');
    return;
  }

  try {
    const mongoUri = process.env.MONGODB_URI;
    
    if (!mongoUri) {
      throw new Error('MONGODB_URI environment variable is not defined');
    }

    // Connect to MongoDB
    const db = await mongoose.connect(mongoUri, {
      bufferCommands: false,
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Keep trying to send operations for 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
    });

    connection.isConnected = db.connections[0].readyState;
    
    console.log('Connected to MongoDB successfully');

    // Handle connection events
    mongoose.connection.on('error', (error) => {
      console.error('MongoDB connection error:', error);
    });

    mongoose.connection.on('disconnected', () => {
      console.log('MongoDB disconnected');
      connection.isConnected = 0;
    });

    // Graceful shutdown
    process.on('SIGINT', async () => {
      await mongoose.connection.close();
      console.log('MongoDB connection closed due to app termination');
      process.exit(0);
    });

  } catch (error) {
    console.error('Error connecting to MongoDB:', error);
    throw error;
  }
}

export async function disconnectFromDatabase(): Promise<void> {
  try {
    await mongoose.connection.close();
    connection.isConnected = 0;
    console.log('Disconnected from MongoDB');
  } catch (error) {
    console.error('Error disconnecting from MongoDB:', error);
    throw error;
  }
}

// Health check function
export function isConnected(): boolean {
  return connection.isConnected === 1;
}

// Get connection status
export function getConnectionStatus(): string {
  const states = ['disconnected', 'connected', 'connecting', 'disconnecting'];
  return states[mongoose.connection.readyState] || 'unknown';
}