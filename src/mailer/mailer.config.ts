import { Configuration, Value } from '@itgorillaz/configify';
import { Transform } from 'class-transformer';
import { IsNotEmpty, IsOptional, IsString } from 'class-validator';

@Configuration()
export class MailerConfig {
  @IsString()
  @IsNotEmpty()
  @Value('SMTP_HOST')
  host: string;

  @Transform(({ value }) => +value)
  @Value('SMTP_PORT')
  port: number;

  @IsString()
  @IsOptional()
  @Value('SMTP_USER')
  user?: string;

  @IsString()
  @IsOptional()
  @Value('SMTP_PASS')
  pass?: string;

  @IsString()
  @IsOptional()
  @Value('SMTP_FROM')
  from: string = '"No Reply" <noreply@example.com>';
}
