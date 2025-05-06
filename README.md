# NestJS Boilerplate

## Features

- Authentication (JWT)
- S3 storage repository
- Dockerfile
- Docker compose file for dependencies (database & S3 storage)
- Docker compose file for development (server & dependencies)

### Authentication (JWT)

#### Features

- Access token
- Auth guard
- Refresh token
- Refresh token rotation
- Refresh token tree rotation
- Refresh token HttpOnly cookie

#### How to change user

1. Change model in `prisma/models/user.prisma`
1. Change DTO's in `src/auth/dtos/`
1. Change payload types in `src/auth/types/`
1. Change functions in `src/auth/auth.service.ts`

### S3 storage repository

You can create repositories for S3 buckets by extending `StorageRepository` and providing bucketName.

```ts
import { Injectable } from '@nestjs/common';
import { StorageRepository } from 'src/storage/storage';

@Injectable()
export class AvatarsStorage extends StorageRepository {
  protected getBucketName(): string {
    return 'avatars';
  }
}
```

#### Repository functions

- Put
- Update object
- Delete object
- Get object URL
- Get objects URLs
- Ensure bucket existance
- Check object existance
