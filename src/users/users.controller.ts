import {
  Controller,
  Delete,
  Get,
  Patch,
  Request,
  UseGuards,
} from '@nestjs/common';
import { UpdateUserDto } from './dtos/update-user.dto';
import {
  ApiBearerAuth,
  ApiOkResponse,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { RequestWithUser } from 'src/auth/types/request-with-user';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { UsersService } from './users.service';
import { UserSensitiveDto } from './dtos/user-sensitive.dto';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get('me')
  @UseGuards(JwtAuthGuard)
  @ApiUnauthorizedResponse()
  @ApiBearerAuth()
  @ApiOkResponse({
    type: UserSensitiveDto,
  })
  async me(@Request() req: RequestWithUser): Promise<UserSensitiveDto> {
    const { user: payload } = req;
    const user = await this.usersService.findUnique({
      where: {
        id: +payload.sub,
      },
    });
    return this.usersService.getUserSensitiveDto(user);
  }

  @Patch('me')
  @UseGuards(JwtAuthGuard)
  @ApiUnauthorizedResponse()
  @ApiBearerAuth()
  @ApiOkResponse({
    type: UserSensitiveDto,
  })
  async updateMe(
    @Request() req: RequestWithUser,
    updateUserDto: UpdateUserDto,
  ): Promise<UserSensitiveDto> {
    const { user: payload } = req;
    const updatedUser = await this.usersService.update({
      where: {
        id: +payload.sub,
      },
      data: updateUserDto,
    });
    return this.usersService.getUserSensitiveDto(updatedUser);
  }

  @Delete('me')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiUnauthorizedResponse()
  @ApiOkResponse({
    type: UserSensitiveDto,
  })
  async deleteMe(@Request() req: RequestWithUser): Promise<UserSensitiveDto> {
    const { user: payload } = req;
    const deletedUser = await this.usersService.remove({
      where: {
        id: +payload.sub,
      },
    });
    return this.usersService.getUserSensitiveDto(deletedUser);
  }

  // @Put('password')
  // @UseGuards(JwtAuthGuard)
  // @ApiUnauthorizedResponse()
  // @ApiBearerAuth()
  // changePassword(
  //   @Request() req: RequestWithUser,
  //   updatePasswordDto: UpdatePasswordDto,
  // ): void {}
}
