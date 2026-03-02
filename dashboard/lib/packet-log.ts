import { z } from "zod";

export interface PacketLog {
  event_id?: string;
  site?: string;
  segment?: string;
  src_ip: string;
  dst_ip: string;
  protocol: "TCP" | "UDP";
  src_port: number;
  dst_port: number;
  risk_score: number;
  length: number;
  timestamp: string;
}

export const packetLogSchema = z.object({
  event_id: z.string().optional(),
  site: z.string().optional(),
  segment: z.string().optional(),
  src_ip: z.string(),
  dst_ip: z.string(),
  protocol: z.enum(["TCP", "UDP"]),
  src_port: z.number(),
  dst_port: z.number(),
  risk_score: z.number().min(0).max(100),
  length: z.number(),
  timestamp: z.string(),
});

export function parsePacketLog(data: unknown): PacketLog {
  return packetLogSchema.parse(data);
}
