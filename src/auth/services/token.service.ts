import {
    Injectable,
    Logger,
    InternalServerErrorException,
  } from '@nestjs/common';
  import { InjectRepository } from '@nestjs/typeorm';
  import { Repository, LessThanOrEqual } from 'typeorm';
  import { JwtService } from '@nestjs/jwt';
  import { ConfigService } from '@nestjs/config';
  import { Redis } from 'ioredis';
  import { InjectRedis } from '@nestjs-modules/ioredis';     
  import { TokenBlacklist } from '../entities/token-blacklist.entity';
  
  @Injectable()
  export class TokenService {
    private readonly logger = new Logger(TokenService.name);
    private readonly BLACKLIST_PREFIX = 'token:blacklist:';
    private readonly TOKEN_CLEANUP_INTERVAL = 3600000;
  
    constructor(
      @InjectRepository(TokenBlacklist)
      private readonly tokenBlacklistRepository: Repository<TokenBlacklist>,
      private readonly jwtService: JwtService,
      private readonly configService: ConfigService,
      @InjectRedis() private readonly redis: Redis,
    ) {
      setInterval(() => this.cleanupExpiredTokens(), this.TOKEN_CLEANUP_INTERVAL);
    }
  
    /**
     * Blacklist a token to prevent reuse
     * 
     * @param token JWT token to blacklist
     * @param userId User ID associated with the token
     * @returns Success status
     */
    async blacklistToken(token: string, userId: string): Promise<boolean> {
      try {
        const decoded = this.jwtService.decode(token);
        if (!decoded || !decoded.exp) {
          throw new Error('Invalid token format');
        }
  
        const expiresAt = new Date(decoded.exp * 1000);
  
        const blacklistedToken = new TokenBlacklist();
        blacklistedToken.token = token;
        blacklistedToken.userId = userId;
        blacklistedToken.expiresAt = expiresAt;
        await this.tokenBlacklistRepository.save(blacklistedToken);
  
        const redisKey = `${this.BLACKLIST_PREFIX}${token}`;
        const ttlSeconds = Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1000));
        
        if (ttlSeconds > 0) {
          await this.redis.set(redisKey, '1', 'EX', ttlSeconds);
        }
  
        return true;
      } catch (error) {
        this.logger.error(`Failed to blacklist token: ${error.message}`, error.stack);
        throw new InternalServerErrorException('Failed to process logout request');
      }
    }
  
    /**
     * Check if a token is blacklisted
     * 
     * @param token JWT token to check
     * @returns True if the token is blacklisted
     */
    async isTokenBlacklisted(token: string): Promise<boolean> {
      try {
        const redisKey = `${this.BLACKLIST_PREFIX}${token}`;
        const blacklisted = await this.redis.exists(redisKey);
        
        if (blacklisted) {
          return true;
        }
  
        const blacklistedToken = await this.tokenBlacklistRepository.findOne({
          where: { token },
        });
  
        return !!blacklistedToken;
      } catch (error) {
        this.logger.error(`Failed to check token blacklist: ${error.message}`, error.stack);
        return false;
      }
    }
  
    /**
     * Invalidate all tokens for a user
     * 
     * @param userId User ID whose tokens should be invalidated
     * @returns Success status
     */
    async invalidateAllUserTokens(userId: string): Promise<boolean> {
      try {
     
        const redisKey = `user:tokens:invalidated:${userId}`;
        const expiryTime = 30 * 24 * 60 * 60; 
        await this.redis.set(redisKey, Date.now().toString(), 'EX', expiryTime);
        
        return true;
      } catch (error) {
        this.logger.error(`Failed to invalidate user tokens: ${error.message}`, error.stack);
        throw new InternalServerErrorException('Failed to invalidate user tokens');
      }
    }
  
    /**
     * Check if all of a user's tokens have been invalidated
     * 
     * @param userId User ID to check
     * @param tokenIssuedAt Token issue timestamp to compare against
     * @returns True if the user's tokens were invalidated after token issuance
     */
    async areUserTokensInvalidated(userId: string, tokenIssuedAt: number): Promise<boolean> {
      try {
        const redisKey = `user:tokens:invalidated:${userId}`;
        const invalidatedAtStr = await this.redis.get(redisKey);
        
        if (!invalidatedAtStr) {
          return false;
        }
  
        const invalidatedAt = parseInt(invalidatedAtStr, 10);
        return invalidatedAt > tokenIssuedAt;
      } catch (error) {
        this.logger.error(`Failed to check token invalidation: ${error.message}`, error.stack);
        // Assume token is valid if check fails
        return false;
      }
    }
  
    /**
     * Clean up expired tokens from the database
     */
    private async cleanupExpiredTokens(): Promise<void> {
      try {
        const now = new Date();
        await this.tokenBlacklistRepository.delete({
          expiresAt: LessThanOrEqual(now),
        });
      } catch (error) {
        this.logger.error(`Failed to clean up expired tokens: ${error.message}`, error.stack);
      }
    }
  }