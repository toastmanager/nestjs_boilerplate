import { Module } from '@nestjs/common';
import { EmailVerificationRepo } from './email-verification.repository';

@Module({
  providers: [EmailVerificationRepo],
  exports: [EmailVerificationRepo],
})
export class EmailVerificationModule {}
