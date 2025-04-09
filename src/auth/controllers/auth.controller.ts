import {
    Body,
    Controller,
    Get,
    HttpCode,
    HttpStatus,
    Param,
    Post,
    Query,
    Req,
    Res,
    UseGuards,
    UseInterceptors,
    ValidationPipe,
  } from '@nestjs/common';
  import { Response } from 'express';
  import {
    ApiBearerAuth,
    ApiOperation,
    ApiResponse,
    ApiTags,
  } from '@nestjs/swagger';
  
  import { AuthService } from '../services/auth.service';
  import { EmailVerificationService } from '../services/email-verification.service';
  import { TokenService } from '../services/token.service';
  import { OtpService } from '../services/otp.service';
  import { LoginDto } from '../dtos/login.dto';
  import { RegisterDto } from '../dtos/register.dto';
  import { RefreshTokenDto } from '../dtos/refresh-token.dto';
  import { ForgotPasswordDto } from '../dtos/forgot-password.dto';
  import { ResetPasswordDto } from '../dtos/reset-password.dto';
  import { ChangePasswordDto } from '../dtos/change-password.dto';
  import { VerifyOtpDto } from '../dtos/verify-otp.dto';
  import { RequestOtpDto } from '../dtos/request-otp.dto';
  import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
  import { CurrentUser } from '../../common/decorators/current-user.decorator';
  import { LoggingInterceptor } from '../../common/interceptors/logging.interceptor';
  import { RateLimit } from '../../common/decorators/rate-limit.decorator';
  import { Public } from '../../common/decorators/public.decorator';
  import { User } from '../../users/entities/user.entity';
  import { CacheInterceptor } from '@nestjs/cache-manager';
  
  @ApiTags('auth')
  @Controller('auth')
  @UseInterceptors(LoggingInterceptor)
  export class AuthController {
    constructor(
      private readonly authService: AuthService,
      private readonly emailVerificationService: EmailVerificationService,
      private readonly tokenService: TokenService,
      private readonly otpService: OtpService,
    ) {}
  
    @Post('register')
    @Public()
    @HttpCode(HttpStatus.CREATED)
    @ApiOperation({ summary: 'Register a new user' })
    @ApiResponse({
      status: HttpStatus.CREATED,
      description: 'User successfully registered',
    })
    @ApiResponse({
      status: HttpStatus.BAD_REQUEST,
      description: 'Invalid input data',
    })
    @RateLimit({ points: 5, duration: 3600 }) 
    async register(@Body(ValidationPipe) registerDto: RegisterDto) {
      return this.authService.register(registerDto);
    }
  
    @Post('login')
    @Public()
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'User login' })
    @ApiResponse({
      status: HttpStatus.OK,
      description: 'User successfully logged in',
    })
    @ApiResponse({
      status: HttpStatus.UNAUTHORIZED,
      description: 'Invalid credentials',
    })
    @RateLimit({ points: 10, duration: 300 }) 
    async login(
      @Body(ValidationPipe) loginDto: LoginDto,
      @Res({ passthrough: true }) response: Response,
    ) {
      const result = await this.authService.login(loginDto);
      
      if (result.refreshToken) {
        response.cookie('refresh_token', result.refreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 7 * 24 * 60 * 60 * 1000,
          path: '/auth/refresh-token',
        });
      }
      
      delete result.refreshToken;
      
      return result;
    }
  
    @Post('refresh-token')
    @Public()
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Refresh access token' })
    @ApiResponse({
      status: HttpStatus.OK,
      description: 'New access token generated',
    })
    @ApiResponse({
      status: HttpStatus.UNAUTHORIZED,
      description: 'Invalid refresh token',
    })
    async refreshToken(
      @Body() refreshTokenDto: RefreshTokenDto,
      @Req() request,
      @Res({ passthrough: true }) response: Response,
    ) {
      const refreshToken = 
        request.cookies?.refresh_token || refreshTokenDto.refreshToken;
      
      if (!refreshToken) {
        return { 
          statusCode: HttpStatus.BAD_REQUEST,
          message: 'Refresh token is required' 
        };
      }
      
      const result = await this.authService.refreshToken(refreshToken);
      
      if (result.refreshToken) {
        response.cookie('refresh_token', result.refreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 7 * 24 * 60 * 60 * 1000, 
          path: '/auth/refresh-token',
        });
      }
      
      delete result.refreshToken;
      
      return result;
    }
  
    @Post('logout')
    @UseGuards(JwtAuthGuard)
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'User logout' })
    @ApiResponse({
      status: HttpStatus.OK,
      description: 'User successfully logged out',
    })
    @ApiBearerAuth()
    async logout(
      @CurrentUser() user: User,
      @Req() request,
      @Res({ passthrough: true }) response: Response,
    ) {
      const token = request.headers.authorization?.split(' ')[1];
      
      if (token) {
        await this.tokenService.blacklistToken(token, user.id);
      }
      
      response.clearCookie('refresh_token', {
        path: '/auth/refresh-token',
      });
      
      return { message: 'Successfully logged out' };
    }
  
    @Get('verify-email')
    @Public()
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Verify user email address' })
    @ApiResponse({
      status: HttpStatus.OK,
      description: 'Email successfully verified',
    })
    @ApiResponse({
      status: HttpStatus.BAD_REQUEST,
      description: 'Invalid verification token',
    })
    async verifyEmail(@Query('token') token: string) {
      return this.emailVerificationService.verifyEmail(token);
    }
  
    @Post('resend-verification')
    @UseGuards(JwtAuthGuard)
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Resend verification email' })
    @ApiResponse({
      status: HttpStatus.OK,
      description: 'Verification email sent',
    })
    @RateLimit({ points: 3, duration: 3600 })
    @ApiBearerAuth()
    async resendVerification(@CurrentUser() user: User) {
      return this.emailVerificationService.sendVerificationEmail(user);
    }
  
    @Post('forgot-password')
    @Public()
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Initiate password reset process' })
    @ApiResponse({
      status: HttpStatus.OK,
      description: 'Password reset email sent',
    })
    @RateLimit({ points: 3, duration: 3600 }) 
    async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
      return this.authService.forgotPassword(forgotPasswordDto.email);
    }
  
    @Post('reset-password')
    @Public()
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Reset password with token' })
    @ApiResponse({
      status: HttpStatus.OK,
      description: 'Password successfully reset',
    })
    @ApiResponse({
      status: HttpStatus.BAD_REQUEST,
      description: 'Invalid reset token',
    })
    async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
      return this.authService.resetPassword(
        resetPasswordDto.token,
        resetPasswordDto.password,
      );
    }
  
    @Post('change-password')
    @UseGuards(JwtAuthGuard)
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Change user password' })
    @ApiResponse({
      status: HttpStatus.OK,
      description: 'Password successfully changed',
    })
    @ApiBearerAuth()
    async changePassword(
      @CurrentUser() user: User,
      @Body() changePasswordDto: ChangePasswordDto,
    ) {
      return this.authService.changePassword(
        user.id,
        changePasswordDto.currentPassword,
        changePasswordDto.newPassword,
      );
    }
  
    @Post('request-otp')
    @UseGuards(JwtAuthGuard)
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Request OTP for two-factor authentication' })
    @ApiResponse({
      status: HttpStatus.OK,
      description: 'OTP sent successfully',
    })
    @RateLimit({ points: 5, duration: 300 }) 
    @ApiBearerAuth()
    async requestOtp(
      @CurrentUser() user: User,
      @Body() requestOtpDto: RequestOtpDto,
    ) {
      return this.otpService.generateAndSendOtp(
        user.id,
        requestOtpDto.action,
        user.email,
      );
    }
  
    @Post('verify-otp')
    @UseGuards(JwtAuthGuard)
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Verify OTP for two-factor authentication' })
    @ApiResponse({
      status: HttpStatus.OK,
      description: 'OTP verified successfully',
    })
    @RateLimit({ points: 5, duration: 300 }) 
    @ApiBearerAuth()
    async verifyOtp(
      @CurrentUser() user: User,
      @Body() verifyOtpDto: VerifyOtpDto,
    ) {
      return this.otpService.verifyOtp(
        user.id,
        verifyOtpDto.action,
        verifyOtpDto.otp,
      );
    }
  
    @Get('me')
    @UseGuards(JwtAuthGuard)
    @UseInterceptors(CacheInterceptor)
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Get current user profile' })
    @ApiResponse({
      status: HttpStatus.OK,
      description: 'User profile retrieved',
    })
    @ApiBearerAuth()
    async getCurrentUser(@CurrentUser() user: User) {
      return this.authService.getUserProfile(user.id);
    }
  }