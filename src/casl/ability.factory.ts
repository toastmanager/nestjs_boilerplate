import {
  AbilityBuilder,
  createMongoAbility,
  ExtractSubjectType,
  PureAbility,
} from '@casl/ability';
import { PrismaQuery, Subjects } from '@casl/prisma';
import { Injectable } from '@nestjs/common';
import { User } from 'generated/prisma';

export enum Action {
  Manage = 'manage',
  Create = 'create',
  Read = 'read',
  Update = 'update',
  Delete = 'delete',
}

export type AppSubjects =
  | 'all'
  | Subjects<{
      User: User;
    }>;

export type AppAbility = PureAbility<[string, AppSubjects], PrismaQuery>;

@Injectable()
export class AbilityFactory {
  defineAbility(user: User) {
    const { can, build } = new AbilityBuilder<AppAbility>(createMongoAbility);

    if (user.isSuperuser) {
      can(Action.Manage, 'all');
    }

    can(Action.Read, 'all');
    can(Action.Update, 'User', { id: user.id });
    can(Action.Delete, 'User', { id: user.id });

    return build({
      detectSubjectType: (item) =>
        item.constructor as unknown as ExtractSubjectType<AppSubjects>,
    });
  }
}
