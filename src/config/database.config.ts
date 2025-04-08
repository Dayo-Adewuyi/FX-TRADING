import { registerAs } from '@nestjs/config';
import { TypeOrmModuleOptions } from '@nestjs/typeorm';
import { join } from 'path';

export default registerAs('database', (): TypeOrmModuleOptions => ({
  type: 'postgres',
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT, 10) || 5432,
  username: process.env.DB_USERNAME || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres',
  database: process.env.DB_NAME || 'fx_trading',
  entities: [join(__dirname, '../**/*.entity{.ts,.js}')],
  migrations: [join(__dirname, '../database/migrations/*{.ts,.js}')],
  migrationsRun: true,
  synchronize: process.env.NODE_ENV === 'development', 
  ssl: process.env.NODE_ENV === 'production',
  logging: process.env.NODE_ENV === 'development',
  poolSize: 10,
  maxQueryExecutionTime: 1000,
  retryAttempts: 10,
  retryDelay: 3000,
}));

