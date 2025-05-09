import { Injectable, Logger } from '@nestjs/common';
import { MailerConfig } from './mailer.config';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailerService {
  private readonly transporter: nodemailer.Transporter;

  constructor(
    private readonly mailerConfig: MailerConfig,
    readonly logger: Logger,
  ) {
    this.transporter = nodemailer.createTransport({
      host: this.mailerConfig.host,
      port: this.mailerConfig.port,
      secure: this.mailerConfig.port === 465,
      auth: {
        user: this.mailerConfig.user,
        pass: this.mailerConfig.pass,
      },
    });

    try {
      this.transporter
        .verify()
        .then(() => logger.log('SMTP server is ready to take messages'));
    } catch (err) {
      logger.error('SMTP server verification failed', err);
    }
  }

  async sendMail(options: nodemailer.SendMailOptions) {
    return this.transporter.sendMail(options);
  }
}
