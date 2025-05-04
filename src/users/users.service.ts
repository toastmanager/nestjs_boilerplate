import { ConflictException, Injectable } from '@nestjs/common';
import { Prisma } from 'generated/prisma';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) {}

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
}
