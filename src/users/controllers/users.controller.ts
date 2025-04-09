import {
    Controller,
    Get,
    Post,
    Patch,
    Body,
    Param,
    UseGuards,
    HttpCode,
    HttpStatus,
    UseInterceptors,
    ClassSerializerInterceptor,
    ParseUUIDPipe,
    BadRequestException,
  } from '@nestjs/common';
  import {
    ApiBearerAuth,
    ApiOperation,
    ApiResponse,
    ApiTags,
  } from '@nestjs/swagger';
  
  import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
  import { RolesGuard } from '../../common/guards/roles.guard';
  import { VerifiedEmailGuard } from '../../common/guards/verified-email.guard';
  import { Roles } from '../../common/decorators/roles.decorator';
  import { CurrentUser } from '../../common/decorators/current-user.decorator';
  import { RateLimit } from '../../common/decorators/rate-limit.decorator';
  
  import { UsersService } from '../services/users.service';
  import { UserProfileService } from '../services/user-profile.service';
  import { User, UserRole } from '../entities/user.entity';
  import { UserProfileDto } from '../dtos/user-profile.dto';
  import { UpdateUserDto } from '../dtos/update-user.dto';
  import { UpdateUserSettingsDto } from '../dtos/user-setting.dto';
  import { UserResponseDto } from '../dtos/user-response.dto';
  
  @ApiTags('users')
  @Controller('users')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @UseInterceptors(ClassSerializerInterceptor)
  @ApiBearerAuth()
  export class UsersController {
    constructor(
      private readonly usersService: UsersService,
      private readonly userProfileService: UserProfileService,
    ) {}
  
    @Get('me')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Get current user profile' })
    @ApiResponse({
      status: HttpStatus.OK,
      description: 'Returns the current user profile',
      type: UserResponseDto,
    })
    async getCurrentUser(@CurrentUser() user: User): Promise<UserResponseDto> {
      return this.usersService.findOneWithRelations(user.id);
    }
  
    @Patch('me')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Update current user profile' })
    @ApiResponse({
      status: HttpStatus.OK,
      description: 'Returns the updated user profile',
      type: UserResponseDto,
    })
    @RateLimit({ points: 5, duration: 60 }) 
    async updateCurrentUser(
      @CurrentUser() user: User,
      @Body() updateUserDto: UpdateUserDto,
    ): Promise<UserResponseDto> {
      if (updateUserDto.role || updateUserDto.status) {
        throw new BadRequestException('Cannot change role or status');
      }
      
      return this.usersService.update(user.id, updateUserDto);
    }
  
    @Patch('me/profile')
    @HttpCode(HttpStatus.OK)
    @UseGuards(VerifiedEmailGuard)
    @ApiOperation({ summary: 'Update current user profile details' })
    @ApiResponse({
      status: HttpStatus.OK,
      description: 'Returns the updated user profile',
      type: UserResponseDto,
    })
    @RateLimit({ points: 5, duration: 60 }) 
    async updateCurrentUserProfile(
      @CurrentUser() user: User,
      @Body() profileDto: UserProfileDto,
    ): Promise<UserResponseDto> {
      await this.userProfileService.updateOrCreate(user.id, profileDto);
      return this.usersService.findOneWithRelations(user.id);
    }
  
   
  
    @Patch('me/settings')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Update user settings' })
    @ApiResponse({
      status: HttpStatus.OK,
      description: 'Returns the updated user settings',
      type: UserResponseDto,
    })
    async updateUserSettings(
      @CurrentUser() user: User,
      @Body() settingsDto: UpdateUserSettingsDto,
    ): Promise<UserResponseDto> {
      await this.usersService.updateSettings(user.id, settingsDto);
      return this.usersService.findOneWithRelations(user.id);
    }
  
    @Get(':id')
    @Roles(UserRole.ADMIN, UserRole.MANAGER)
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Get user by ID (Admin/Manager only)' })
    @ApiResponse({
      status: HttpStatus.OK,
      description: 'Returns the user profile',
      type: UserResponseDto,
    })
    async getUserById(
      @Param('id', new ParseUUIDPipe()) id: string,
    ): Promise<UserResponseDto> {
      return this.usersService.findOneWithRelations(id);
    }
  }