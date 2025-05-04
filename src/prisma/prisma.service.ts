import { Injectable, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from 'generated/prisma';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit {
  constructor() {
    super({
      omit: {
        user: {
          passwordHash: true,
        },
      },
    });
  }

  async onModuleInit() {
    await this.$connect();
  }
}
