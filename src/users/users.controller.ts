import { Controller, Delete, Get, Patch, Put } from '@nestjs/common';
import { UpdatePasswordDto } from './dtos/update-password.dto';
import { UserDto } from './dtos/user.dto';
import { UpdateUserDto } from './dtos/update-user.dto';

@Controller('users')
export class UsersController {
  @Get('me')
  me(): UserDto {
    return {
      id: 0,
      createdAt: new Date(),
      username: 'mock',
    };
  }

  @Patch('me')
  updateMe(updateUserDto: UpdateUserDto): UserDto {
    return {
      id: 0,
      createdAt: new Date(),
      username: 'mock',
    };
  }

  @Delete('me')
  deleteMe(): UserDto {
    return {
      id: 0,
      createdAt: new Date(),
      username: 'mock',
    };
  }

  @Put('password')
  changePassword(updatePasswordDto: UpdatePasswordDto): void {}
}
