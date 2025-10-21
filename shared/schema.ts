import mongoose, { Schema, Document, Types } from 'mongoose';
import { z } from "zod";

// User Interface
export interface IUser extends Document {
  _id: Types.ObjectId;
  username: string;
  password: string;
  createdAt: Date;
  updatedAt: Date;
}

// API Key Interface
export interface IApiKey extends Document {
  _id: Types.ObjectId;
  userId?: Types.ObjectId;
  name: string;
  key: string;
  createdAt: Date;
  lastUsed?: Date;
  requests: number;
  updatedAt: Date;
}

// User Schema
const userSchema = new Schema<IUser>({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
  },
  password: {
    type: String,
    required: true,
  },
}, {
  timestamps: true,
});

// API Key Schema
const apiKeySchema = new Schema<IApiKey>({
  userId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: false, // For development mode
  },
  name: {
    type: String,
    required: true,
    trim: true,
  },
  key: {
    type: String,
    required: true,
    unique: true,
  },
  lastUsed: {
    type: Date,
    required: false,
  },
  requests: {
    type: Number,
    default: 0,
    min: 0,
  },
}, {
  timestamps: true,
});

// Models
export const User = mongoose.models.User || mongoose.model<IUser>('User', userSchema);
export const ApiKey = mongoose.models.ApiKey || mongoose.model<IApiKey>('ApiKey', apiKeySchema);

// Zod Validation Schemas
export const insertUserSchema = z.object({
  username: z.string().min(3).max(50),
  password: z.string().min(6),
});

export const insertApiKeySchema = z.object({
  userId: z.string().optional(),
  name: z.string().min(1).max(100),
});

// Types for backward compatibility
export type InsertUser = z.infer<typeof insertUserSchema>;
export type InsertApiKey = z.infer<typeof insertApiKeySchema>;
export type User = IUser;
export type ApiKey = IApiKey;
