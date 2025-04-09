import {
    Controller,
    Get,
    Post,
    Patch,
    Delete,
    Body,
    Param,
    Query,
    UseGuards,
    HttpCode,
    HttpStatus,
    UseInterceptors,
    ClassSerializerInterceptor,
    ParseUUIDPipe,
  } from '@nestjs/common';
  import {
    ApiBearerAuth,
    ApiOperation,
    ApiResponse,
    ApiTags,
  } from '@nestjs/swagger';
  
  import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
  import { RolesGuard } from '../../common/guards/roles.guard';
  import { Roles } from '../../common/decorators/roles.decorator';
  import { CurrentUser } from '../../common/decorators/current-user.decorator';
  import { UserActivityService } from '../services/user-activity.service';
  
  import { UserAdminService } from '../services/user-admin.service';
  import { User, UserRole } from '../entities/user.entity';
  import { CreateUserDto } from '../dtos/create-user.dto';
  import { AdminUpdateUserDto } from '../dtos/admin-update.dto';
  import { UserFilterDto } from '../dtos/user-filter.dto';
  import { UserResponseDto } from '../dtos/user-response.dto';
  import { PaginatedResponseDto } from '../dtos/paginated-response.dto';
  import { ActivityType } from '../entities/user-activity.entity';
  
  @ApiTags('admin/users')
  @Controller('admin/users')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
  @UseInterceptors(ClassSerializerInterceptor)
  @ApiBearerAuth()
  export class AdminUsersController {
    constructor(
      private readonly userAdminService: UserAdminService,
      private readonly userActivityService: UserActivityService,
    ) {}
  
    @Get()
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Get all users with filtering and pagination (Admin only)' })
    @ApiResponse({
      status: HttpStatus.OK,
      description: 'Returns paginated list of users',
      type: () => PaginatedResponseDto<UserResponseDto>,
    })
    async getAllUsers(
      @Query() filterDto: UserFilterDto,
    ): Promise<PaginatedResponseDto<UserResponseDto>> {
      return this.userAdminService.findAll(filterDto);
    }
  
    @Post()
    @HttpCode(HttpStatus.CREATED)
    @ApiOperation({ summary: 'Create a new user (Admin only)' })
    @ApiResponse({
      status: HttpStatus.CREATED,
      description: 'Returns the created user',
      type: UserResponseDto,
    })
    async createUser(
      @Body() createUserDto: CreateUserDto,
      @CurrentUser() adminUser: User,
    ): Promise<UserResponseDto> {
      const user = await this.userAdminService.create(createUserDto);
      
      await this.userActivityService.logActivity({
        userId: user.id,
        activityType: ActivityType.ACCOUNT_CREATED,
        metadata: {
          createdBy: adminUser.id,
          adminEmail: adminUser.email,
        },
      });
      
      return user;
    }
  
    @Get(':id')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Get user by ID (Admin only)' })
    @ApiResponse({
      status: HttpStatus.OK,
      description: 'Returns the user profile',
      type: UserResponseDto,
    })
    async getUserById(
      @Param('id', new ParseUUIDPipe()) id: string,
    ): Promise<UserResponseDto> {
      return this.userAdminService.findOneWithRelations(id);
    }
  
    @Patch(':id')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Update user by ID (Admin only)' })
    @ApiResponse({
      status: HttpStatus.OK,
      description: 'Returns the updated user',
      type: UserResponseDto,
    })
    async updateUser(
      @Param('id', new ParseUUIDPipe()) id: string,
      @Body() updateUserDto: AdminUpdateUserDto,
      @CurrentUser() adminUser: User,
    ): Promise<UserResponseDto> {
      const user = await this.userAdminService.update(id, updateUserDto);
      
      // Log activity
      await this.userActivityService.logActivity({
        userId: id,
        activityType: ActivityType.PROFILE_UPDATE,
        metadata: {
          updatedBy: adminUser.id,
          adminEmail: adminUser.email,
          fields: Object.keys(updateUserDto),
        },
      });
      
      // If user status was changed to locked or unlocked, log that specifically
      if (updateUserDto.status === 'locked') {
        await this.userActivityService.logActivity({
          userId: id,
          activityType: ActivityType.ACCOUNT_LOCKED,
          metadata: {
            lockedBy: adminUser.id,
            adminEmail: adminUser.email,
          },
        });
      } else if (updateUserDto.unlockAccount) {
        await this.userActivityService.logActivity({
          userId: id,
          activityType: ActivityType.ACCOUNT_UNLOCKED,
          metadata: {
            unlockedBy: adminUser.id,
            adminEmail: adminUser.email,
          },
        });
      }
      
      return user;
    }
  
    @Delete(':id')
    @HttpCode(HttpStatus.NO_CONTENT)
    @ApiOperation({ summary: 'Deactivate user by ID (Admin only)' })
    @ApiResponse({
      status: HttpStatus.NO_CONTENT,
      description: 'User successfully deactivated',
    })
    async deactivateUser(
      @Param('id', new ParseUUIDPipe()) id: string,
      @CurrentUser() adminUser: User,
    ): Promise<void> {
      await this.userAdminService.deactivate(id);
      
      await this.userActivityService.logActivity({
        userId: id,
        activityType: ActivityType.ACCOUNT_DEACTIVATED,
        metadata: {
          deactivatedBy: adminUser.id,
          adminEmail: adminUser.email,
        },
      });
    }
  
    @Get(':id/activities')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Get user activity log (Admin only)' })
    @ApiResponse({
      status: HttpStatus.OK,
      description: 'Returns paginated list of user activities',
    })
    async getUserActivities(
      @Param('id', new ParseUUIDPipe()) id: string,
      @Query('page') page = 1,
      @Query('limit') limit = 20,
    ) {
      return this.userActivityService.findAllByUser(id, {
        page: +page,
        limit: +limit,
      });
    }
  
    @Post(':id/reset-password')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Force reset user password (Admin only)' })
    @ApiResponse({
      status: HttpStatus.OK,
      description: 'Password reset email sent to user',
    })
    async resetUserPassword(
      @Param('id', new ParseUUIDPipe()) id: string,
      @CurrentUser() adminUser: User,
    ) {
      const result = await this.userAdminService.initiatePasswordReset(id);
      
      await this.userActivityService.logActivity({
        userId: id,
        activityType: ActivityType.PASSWORD_RESET_REQUESTED,
        metadata: {
          requestedBy: adminUser.id,
          adminEmail: adminUser.email,
        },
      });
      
      return result;
    }
  }