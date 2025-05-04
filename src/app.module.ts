import { Module } from '@nestjs/common';
import { ConfigifyModule } from '@itgorillaz/configify';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { RefreshTokensModule } from './refresh-tokens/refresh-tokens.module';

@Module({
  imports: [
    ConfigifyModule.forRootAsync(),
    PrismaModule,
    AuthModule,
    UsersModule,
    RefreshTokensModule,
  ],
})
export class AppModule {}
