import { ConflictException, Injectable } from '@nestjs/common';
import { Prisma, User } from 'generated/prisma';
import { PrismaService } from 'src/prisma/prisma.service';
import { UserDto } from './dtos/user.dto';
import { UserSensitiveDto } from './dtos/user-sensitive.dto';

@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) {}

  getUserDto(user: User): UserDto {
    return {
      id: user.id,
      isActive: user.isActive,
      isVerified: user.isVerified,
      username: user.username,
      createdAt: user.createdAt,
    };
  }

  getUserSensitiveDto(user: User): UserSensitiveDto {
    return {
      ...this.getUserDto(user),
      email: user.email,
    };
  }

  /**
   * checks if user exists
   * raises `ConflictException` if exists
   */
  async checkUserExistence(args: Prisma.UserFindUniqueArgs): Promise<void> {
    const existingUser = await this.findUnique({
      ...args,
    });

    if (existingUser) {
      throw new ConflictException('User with these credentials already exists');
    }
  }

  async create(args: Prisma.UserCreateArgs) {
    const user = await this.prisma.user.create(args);
    return user;
  }

  async findMany(args?: Prisma.UserFindManyArgs) {
    const users = await this.prisma.user.findMany(args);
    return users;
  }

  async findFirst(args?: Prisma.UserFindFirstArgs) {
    const user = await this.prisma.user.findFirst(args);
    return user;
  }

  async findUnique(args: Prisma.UserFindUniqueArgs) {
    const user = await this.prisma.user.findUnique(args);
    return user;
  }

  async update(args: Prisma.UserUpdateArgs) {
    const user = await this.prisma.user.update(args);
    return user;
  }

  async remove(args: Prisma.UserDeleteArgs) {
    const user = await this.prisma.user.delete(args);
    return user;
  }
}
