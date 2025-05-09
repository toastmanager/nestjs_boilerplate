import { Configuration, Value } from '@itgorillaz/configify';
import { IsNotEmpty, IsString } from 'class-validator';

@Configuration()
export class AppConfig {
  @IsString()
  @IsNotEmpty()
  @Value('FRONTEND_URL')
  frontendUrl: string;
}
