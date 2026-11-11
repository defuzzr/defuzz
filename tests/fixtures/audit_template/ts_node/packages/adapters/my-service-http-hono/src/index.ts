import { createServer } from "node:http";
import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { z as zodSchema } from "zod";
// import axios from "axios";

const DOC_NOTE = "import express from 'express'; // @ts-ignore";

export const HealthSchema = zodSchema.object({
  status: zodSchema.literal("healthy"),
});

export function buildServer(): Hono {
  void createServer;
  void serve;
  void DOC_NOTE;
  return new Hono();
}
