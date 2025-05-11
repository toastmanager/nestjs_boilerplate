import { Logger, Module } from '@nestjs/common';
import { MailerService } from './mailer.service';

@Module({
  providers: [MailerService, Logger],
  exports: [MailerService],
})
export class MailerModule {}
