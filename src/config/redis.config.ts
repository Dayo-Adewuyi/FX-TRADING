import { registerAs } from '@nestjs/config';

export default registerAs('redis', () => ({
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT, 10) || 6379,
  password: process.env.REDIS_PASSWORD || undefined,
  ttl: parseInt(process.env.REDIS_TTL, 10) || 300, 
  db: parseInt(process.env.REDIS_DB, 10) || 0,
  keyPrefix: process.env.REDIS_PREFIX || 'fxapp:',
  cluster: process.env.NODE_ENV === 'production' ? [
    { host: process.env.REDIS_HOST_1, port: parseInt(process.env.REDIS_PORT_1, 10) },
    { host: process.env.REDIS_HOST_2, port: parseInt(process.env.REDIS_PORT_2, 10) },
    { host: process.env.REDIS_HOST_3, port: parseInt(process.env.REDIS_PORT_3, 10) },
  ] : undefined,
}));