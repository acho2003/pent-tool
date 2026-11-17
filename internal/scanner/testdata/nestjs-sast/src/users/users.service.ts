import { Injectable } from '@nestjs/common';
import { DataSource, Repository } from 'typeorm';

@Injectable()
export class UsersService {
  constructor(private readonly dataSource: DataSource, private readonly repo: Repository<any>, private readonly prisma: any) {}

  async findByName(name: string) {
    // ruleid: nestjs-sql-raw-query-interpolation
    return this.dataSource.query(`SELECT * FROM users WHERE name = '${name}'`);
  }

  async findByRole(role: string) {
    // ruleid: nestjs-sql-raw-query-interpolation
    return this.dataSource.query("SELECT * FROM users WHERE role = '" + role + "'");
  }

  async search(term: string) {
    // ruleid: nestjs-sql-raw-query-interpolation
    return this.repo.createQueryBuilder('u').where(`u.email LIKE '%${term}%'`).getMany();
  }

  async sorted(column: string) {
    // ruleid: nestjs-sql-raw-query-interpolation
    return this.repo.createQueryBuilder('u').orderBy(`u.${column}`).getMany();
  }

  async rawPrisma(id: string) {
    // ruleid: nestjs-prisma-raw-unsafe
    return this.prisma.$queryRawUnsafe('SELECT * FROM t WHERE id = ' + id);
  }

  async safeQuery(name: string) {
    // ok: nestjs-sql-raw-query-interpolation
    return this.dataSource.query('SELECT * FROM users WHERE name = $1', [name]);
  }

  async safeBuilder(term: string) {
    // ok: nestjs-sql-raw-query-interpolation
    return this.repo.createQueryBuilder('u').where('u.email = :term', { term }).getMany();
  }

  async safePrisma() {
    // ok: nestjs-prisma-raw-unsafe
    return this.prisma.$queryRawUnsafe('SELECT 1');
  }
}
