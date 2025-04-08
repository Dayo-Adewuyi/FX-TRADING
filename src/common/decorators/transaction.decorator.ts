import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { EntityManager } from 'typeorm';


export const InTransaction = createParamDecorator(
  async (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const dataSource = request.dataSource;

    if (!dataSource) {
      throw new Error('DataSource not available in request. Make sure to use the TransactionInterceptor.');
    }

    if (!request.transaction) {
    await dataSource.transaction(async (entityManager: EntityManager) => {
      request.transaction = entityManager;
    });
    }

    return request.transaction;
  },
);